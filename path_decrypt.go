package secretsengine

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathDecrypt handles decryption requests
func (b *pqBackend) pathDecrypt() *framework.Path {
	return &framework.Path{
		Pattern: "decrypt/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the encryption key to use",
			},
			"ciphertext": {
				Type:        framework.TypeString,
				Description: "Ciphertext to decrypt",
			},
			"context": {
				Type:        framework.TypeString,
				Description: "Base64 encoded context for key derivation",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathDecryptWrite,
			},
		},
		HelpSynopsis:    "Decrypt data using the named key",
		HelpDescription: "This endpoint decrypts the provided ciphertext using the named key.",
	}
}

// pathDecryptWrite handles decryption requests
func (b *pqBackend) pathDecryptWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	ciphertext := data.Get("ciphertext").(string)

	key, exists := b.cache.Get(name)
	if !exists {
		return logical.ErrorResponse("key not found"), nil
	}

	// Parse ciphertext format (vault:v1:base64data)
	parts := strings.Split(ciphertext, ":")
	if len(parts) != 3 || parts[0] != "vault" {
		return logical.ErrorResponse("invalid ciphertext format"), nil
	}

	// Extract version
	var keyVersion int
	if _, err := fmt.Sscanf(parts[1], "v%d", &keyVersion); err != nil {
		return logical.ErrorResponse("invalid version format"), nil
	}

	// Get key version
	version, exists := key.Versions[keyVersion]
	if !exists {
		return logical.ErrorResponse("key version not found"), nil
	}

	// Decode ciphertext
	ciphertextBytes, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return logical.ErrorResponse("invalid base64 ciphertext"), nil
	}

	// Decrypt using custom algorithm
	plaintext, err := b.decrypt(key.Type, version.Key, ciphertextBytes)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"plaintext": base64.StdEncoding.EncodeToString(plaintext),
		},
	}, nil
}

// decrypt decrypts ciphertext using the specified algorithm and key
func (b *pqBackend) decrypt(keyType string, key, ciphertext []byte) ([]byte, error) {
	algorithm, exists := b.algorithms.Get(keyType)
	if !exists {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", keyType)
	}

	return algorithm.decrypt(key, ciphertext)
}
