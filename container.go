package secretsengine

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
	algs *keyVal[string, encryptor]
}

func newContainer(algOpts ...func(*container)) *container {
	c := &container{}

	for _, opt := range algOpts {
		opt(c)
	}

	return c
}

func (c *container) Get(name string) (encryptor, bool) {
	return c.Get(name)
}

func withAlgorithm(alg encryptor) func(*container) {
	return func(c *container) {
		c.algs.Set(alg.GetName(), alg)
	}
}
