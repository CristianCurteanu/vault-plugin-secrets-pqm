package secretsengine

import (
	"sync"
)

// keyVal manages encryption keys in memory
type keyVal[K comparable, V any] struct {
	mx      *sync.RWMutex
	storage map[K]V
}

func newKeyVal[K comparable, V any]() *keyVal[K, V] {
	return &keyVal[K, V]{
		mx:      &sync.RWMutex{},
		storage: map[K]V{},
	}
}

func (c *keyVal[K, V]) Set(k K, val V) *keyVal[K, V] {
	c.mx.Lock()
	defer c.mx.Unlock()

	c.storage[k] = val

	return c
}

func (c *keyVal[K, V]) Get(k K) (V, bool) {
	c.mx.Lock()
	defer c.mx.Unlock()

	key, found := c.storage[k]

	return key, found
}
