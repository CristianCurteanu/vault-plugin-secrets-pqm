package secretsengine

import (
	"github.com/hashicorp/go-hclog"
)

// encryptor provides an interface that could be used as a plugin model for new encryption algorithms, since operating signatures are operating with bytes
type encryptor interface {
	GetName() string
	GetKeyGen() ([]byte, error)
	GetAlgorithms() algorithms
}

// algorithms store the functions used for encryption/description, which are used by encryptors
type algorithms struct {
	encrypt func(key, data []byte) ([]byte, error)
	decrypt func(key, data []byte) ([]byte, error)
}

// container struct acts as a algorithms registry, that are selected on runtime by key type
type container struct {
	algs   *keyVal[string, encryptor]
	logger hclog.Logger
}

func newContainer() *container {
	c := container{
		algs:   newKeyVal[string, encryptor](),
		logger: hclog.New(&hclog.LoggerOptions{}),
	}

	return &c
}

// Register performs encryptor registration
func (c *container) Register(encryptors ...encryptor) *container {
	for _, enc := range encryptors {
		if enc != nil {
			c.algs.Set(enc.GetName(), enc)
		}
	}

	return c
}

// Get looks up for an encryptor based on it's name
func (c *container) Get(name string) (encryptor, bool) {
	return c.algs.Get(name)
}
