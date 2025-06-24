package secretsengine

import (
	"github.com/hashicorp/go-hclog"
)

type encryptor interface {
	GetName() string
	GetKeyGen() ([]byte, error)
	GetAlgorithms() algorithms
}

type algorithms struct {
	encrypt func(key, data []byte) ([]byte, error)
	decrypt func(key, data []byte) ([]byte, error)
}

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

func (c *container) Register(encryptors ...encryptor) *container {
	for _, enc := range encryptors {
		if enc != nil {
			c.algs.Set(enc.GetName(), enc)
		}
	}

	return c
}

func (c *container) Get(name string) (encryptor, bool) {
	return c.algs.Get(name)
}
