package secretsengine

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := NewPqBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// pqBackend defines an object that
// extends the Vault backend and stores the
// target API's client.
type pqBackend struct {
	*framework.Backend
	lock sync.RWMutex

	cache               *keyVal[string, *encryptionKey]
	algorithmsContainer *container
	logger              hclog.Logger
}

// NewPqBackend defines the target API NewPqBackend
// for Vault. It must include each path
// and the secrets it will store.
func NewPqBackend() *pqBackend {
	var b = pqBackend{
		cache: newKeyVal[string, *encryptionKey](),
		// The algorithms provided by this plugin are registered here
		algorithmsContainer: newContainer().Register(
			&kyber512{},
			&kyber768{},
			&kyber1024{},
		),
		logger: hclog.New(&hclog.LoggerOptions{}),
	}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"keys/",
			},
		},
		Paths: []*framework.Path{
			// Key management paths
			b.pathKeys(),
			b.pathKeysRead(),

			// // Encryption/Decryption paths
			b.pathEncrypt(),
			b.pathDecrypt(),
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}

	b.logger.Info(fmt.Sprintf("backend initialized: %+v\n", b.algorithmsContainer))

	return &b
}

// reset clears any client configuration for a new
// backend to be configured
func (b *pqBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
}

// invalidate clears an existing client configuration in
// the backend
func (b *pqBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
// func (b *pqBackend) getClient(ctx context.Context, s logical.Storage) (*hashiCupsClient, error) {
// 	b.lock.RLock()
// 	unlockFunc := b.lock.RUnlock
// 	defer func() { unlockFunc() }()

// 	b.lock.RUnlock()
// 	b.lock.Lock()
// 	unlockFunc = b.lock.Unlock

// 	return nil, fmt.Errorf("need to return client")
// }

// backendHelp should contain help information for the backend
const backendHelp = `
Vault PQ plugin adds possibility to enable encryption/decryption using Kyber and Dilithium algorithms
`
