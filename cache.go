package secretsengine

import (
	"sync"
)

// keyVal is a structure for thread safe storage of key-value pairs in memory
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

// Set adds a new value to the storage
func (c *keyVal[K, V]) Set(k K, val V) *keyVal[K, V] {
	c.mx.Lock()
	defer c.mx.Unlock()

	c.storage[k] = val

	return c
}

// Get fetches a value from the storage based on a key. If value is not found, the `found` flag will return false
func (c *keyVal[K, V]) Get(k K) (V, bool) {
	c.mx.Lock()
	defer c.mx.Unlock()

	key, found := c.storage[k]

	return key, found
}
