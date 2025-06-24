package secretsengine

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *pqBackend) pathKeys() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the encryption key",
			},
			"type": {
				Type:        framework.TypeString,
				Description: "Type of key (kyber-512, kyber-768, kyber-1024)",
				Default:     "custom-aes256",
			},
			"allow_plaintext_backup": {
				Type:        framework.TypeBool,
				Description: "Allow plaintext backup of the key",
				Default:     false,
			},
			"deletion_allowed": {
				Type:        framework.TypeBool,
				Description: "Allow deletion of the key",
				Default:     false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathKeysWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathKeysWrite,
			},
		},
		HelpSynopsis:    "Create or update an encryption key",
		HelpDescription: "This endpoint creates or updates an encryption key with the specified parameters.",
	}
}

// pathKeysWrite handles key creation and updates
func (b *pqBackend) pathKeysWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	keyType := data.Get("type").(string)
	allowPlaintextBackup := data.Get("allow_plaintext_backup").(bool)
	deletionAllowed := data.Get("deletion_allowed").(bool)

	// Check if key already exists
	if _, exists := b.cache.Get(name); exists {
		return logical.ErrorResponse("key already exists"), nil
	}

	// Generate initial key version
	keyBytes, err := b.generateKey(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create the encryption key
	key := &encryptionKey{
		Name:                 name,
		Type:                 keyType,
		CreatedTime:          time.Now(),
		Versions:             make(map[int]*keyVersion),
		LatestVersion:        1,
		MinDecryptVersion:    1,
		MinEncryptVersion:    0,
		AllowPlaintextBackup: allowPlaintextBackup,
		DeletionAllowed:      deletionAllowed,
	}

	key.Versions[1] = &keyVersion{
		Version:     1,
		Key:         keyBytes,
		CreatedTime: time.Now(),
	}

	b.cache.Set(name, key)

	return &logical.Response{
		Data: map[string]interface{}{
			"name":    name,
			"type":    keyType,
			"version": 1,
		},
	}, nil
}

// generateKey generates a new encryption key based on the key type
func (b *pqBackend) generateKey(keyType string) ([]byte, error) {
	encryptor, exists := b.algorithmsContainer.Get(keyType)
	if !exists {
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	return encryptor.GetKeyGen()
}
