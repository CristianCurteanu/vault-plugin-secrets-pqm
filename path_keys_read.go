package secretsengine

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathKeysRead handles reading key information
func (b *pqBackend) pathKeysRead() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the encryption key",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKeysReadHandler,
			},
		},
		HelpSynopsis:    "Read information about an encryption key",
		HelpDescription: "This endpoint returns information about an encryption key.",
	}
}

// pathKeysReadHandler handles reading key information
func (b *pqBackend) pathKeysReadHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	key, exists := b.cache.Get(name)
	if !exists {
		return nil, nil
	}

	versions := make(map[string]interface{})
	for v, version := range key.Versions {
		versions[fmt.Sprintf("%d", v)] = version.CreatedTime.Unix()
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":                   key.Name,
			"type":                   key.Type,
			"latest_version":         key.LatestVersion,
			"min_decryption_version": key.MinDecryptVersion,
			"min_encryption_version": key.MinEncryptVersion,
			"allow_plaintext_backup": key.AllowPlaintextBackup,
			"deletion_allowed":       key.DeletionAllowed,
			"keys":                   versions,
			"supports_encryption":    true,
			"supports_decryption":    true,
		},
	}, nil
}
