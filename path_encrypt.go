package secretsengine

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *pqBackend) pathEncrypt() *framework.Path {
	return &framework.Path{
		Pattern: "encrypt/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the encryption key to use",
			},
			"plaintext": {
				Type:        framework.TypeString,
				Description: "Base64 encoded plaintext to encrypt",
			},
			"context": {
				Type:        framework.TypeString,
				Description: "Base64 encoded context for key derivation",
			},
			"key_version": {
				Type:        framework.TypeInt,
				Description: "Version of the key to use for encryption",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathEncryptWrite,
			},
		},
		HelpSynopsis: "Encrypt data using the named key",
	}
}

func (b *pqBackend) pathEncryptWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	plaintextB64 := data.Get("plaintext").(string)
	keyVersionRaw := data.Get("key_version")

	// Decode plaintext
	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return logical.ErrorResponse("invalid base64 plaintext"), nil
	}

	key, exists := b.cache.Get(name)
	if !exists {
		return logical.ErrorResponse("key not found"), nil
	}

	// Determine which key version to use
	var keyVersion int
	if keyVersionRaw != nil {
		keyVersion = keyVersionRaw.(int)
	} else {
		keyVersion = key.LatestVersion
	}

	version, exists := key.Versions[keyVersion]
	if !exists {
		return logical.ErrorResponse("key version not found"), nil
	}

	// Encrypt using custom algorithm
	ciphertext, err := b.encrypt(key.Type, version.Key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Format ciphertext with version prefix (similar to vault:v1:...)
	formattedCiphertext := fmt.Sprintf("vault:v%d:%s", keyVersion, base64.StdEncoding.EncodeToString(ciphertext))

	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext":  formattedCiphertext,
			"key_version": keyVersion,
		},
	}, nil
}

func (b *pqBackend) encrypt(keyType string, key, plaintext []byte) ([]byte, error) {
	algorithm, exists := b.algorithms.Get(keyType)
	if !exists {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", keyType)
	}

	return algorithm.encrypt(key, plaintext)
}
