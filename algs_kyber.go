package secretsengine

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	kbr1024 "github.com/cloudflare/circl/kem/kyber/kyber1024"
	kbr512 "github.com/cloudflare/circl/kem/kyber/kyber512"
	kbr768 "github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/hkdf"
)

// Checks if all kyber algorithms are implmenting the encryptor interface
var _ encryptor = (*kyber512)(nil)
var _ encryptor = (*kyber768)(nil)
var _ encryptor = (*kyber1024)(nil)

// Common structures for key management
type keyPair struct {
	PublicKey  []byte
	PrivateKey []byte
	Algorithm  string
}

// Hybrid encryption structure for Kyber (since Kyber is a KEM, not direct encryption)
type hybridCiphertext struct {
	EncapsulatedKey []byte // Kyber encapsulated key
	Ciphertext      []byte // AES-GCM encrypted data
	Nonce           []byte // AES-GCM nonce
}

type kyber512 struct{}

func (k *kyber512) GetName() string {
	return "kyber-512"
}

func (k *kyber512) GetKeyGen() ([]byte, error) {
	return getKeyGen(kbr512.Scheme())
}

func (k *kyber512) GetAlgorithms() algorithms {
	return algorithms{
		encrypt: k.encrypt,
		decrypt: k.decrypt,
	}
}

func (k *kyber512) encrypt(key, data []byte) ([]byte, error) {
	keyPair, err := deserialize[keyPair](key)
	if err != nil {
		return nil, err
	}

	return hybridEncrypt(kbr512.Scheme(), keyPair.PublicKey, data)
}

func (k *kyber512) decrypt(key, data []byte) ([]byte, error) {
	keyPair, err := deserialize[keyPair](key)
	if err != nil {
		return nil, err
	}

	return hybridDecrypt(kbr512.Scheme(), keyPair.PrivateKey, data)
}

type kyber768 struct{}

func (k *kyber768) GetName() string {
	return "kyber-768"
}

func (k *kyber768) GetKeyGen() ([]byte, error) {
	return getKeyGen(kbr768.Scheme())
}

func (k *kyber768) GetAlgorithms() algorithms {
	return algorithms{
		encrypt: k.encrypt,
		decrypt: k.decrypt,
	}
}

func (k *kyber768) encrypt(key, data []byte) ([]byte, error) {
	keyPair, err := deserialize[keyPair](key)
	if err != nil {
		return nil, err
	}

	return hybridEncrypt(kbr768.Scheme(), keyPair.PublicKey, data)
}

func (k *kyber768) decrypt(key, data []byte) ([]byte, error) {
	keyPair, err := deserialize[keyPair](key)
	if err != nil {
		return nil, err
	}

	return hybridDecrypt(kbr768.Scheme(), keyPair.PrivateKey, data)
}

type kyber1024 struct{}

func (k *kyber1024) GetName() string {
	return "kyber-1024"
}

func (k *kyber1024) GetKeyGen() ([]byte, error) {
	return getKeyGen(kbr1024.Scheme())
}

func (k *kyber1024) GetAlgorithms() algorithms {
	return algorithms{
		encrypt: k.encrypt,
		decrypt: k.decrypt,
	}
}

func (k *kyber1024) encrypt(key, data []byte) ([]byte, error) {
	keyPair, err := deserialize[keyPair](key)
	if err != nil {
		return nil, err
	}

	return hybridEncrypt(kbr1024.Scheme(), keyPair.PublicKey, data)
}

func (k *kyber1024) decrypt(key, data []byte) ([]byte, error) {
	keyPair, err := deserialize[keyPair](key)
	if err != nil {
		return nil, err
	}

	return hybridDecrypt(kbr1024.Scheme(), keyPair.PrivateKey, data)
}

/*

	Kyber Helpers functions

*/

func serialize[V any](kp V) ([]byte, error) {
	var encodedBuffer bytes.Buffer

	encoder := gob.NewEncoder(&encodedBuffer)
	err := encoder.Encode(kp)
	if err != nil {
		return nil, err
	}

	encodedBytes := encodedBuffer.Bytes()
	serialized := make([]byte, base64.StdEncoding.EncodedLen(len(encodedBytes)))
	base64.StdEncoding.Encode(serialized, encodedBytes)

	return serialized, nil
}

func deserialize[V any](encoded []byte) (V, error) {
	data := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))

	var res V
	_, err := base64.StdEncoding.Decode(data, encoded)
	if err != nil {
		return res, err
	}

	encodedBuffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(encodedBuffer)

	err = decoder.Decode(&res)
	if err != nil {
		return res, err
	}

	return res, nil
}

func getKeyGen(scheme kem.Scheme) ([]byte, error) {
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("%v key generation failed: %w", scheme.Name(), err)
	}

	publicKeyData, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%v public key marshal failed: %w", scheme.Name(), err)
	}

	privateKeyData, err := privateKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%v private key marshal failed: %w", scheme.Name(), err)
	}

	return serialize(keyPair{
		PublicKey:  publicKeyData,
		PrivateKey: privateKeyData,
		Algorithm:  scheme.Name(),
	})
}

func hybridEncrypt(scheme kem.Scheme, publicKey, plaintext []byte) ([]byte, error) {
	// Generate shared secret using Kyber KEM
	unmarshaledPublicKey, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	ciphertext, sharedSecret, err := scheme.Encapsulate(unmarshaledPublicKey)
	if err != nil {
		return nil, fmt.Errorf("kyber512 encapsulation failed: %w", err)
	}

	// Use shared secret to derive AES key
	aesKey := deriveKey(sharedSecret, 32) // 256-bit AES key

	// Encrypt data with AES-GCM
	encryptedData, nonce, err := aesGCMEncrypt(aesKey, plaintext)
	if err != nil {
		return nil, err
	}

	// Combine everything
	hybrid := &hybridCiphertext{
		EncapsulatedKey: ciphertext,
		Ciphertext:      encryptedData,
		Nonce:           nonce,
	}

	return serialize(hybrid)
}

func hybridDecrypt(scheme kem.Scheme, privateKey []byte, ciphertext []byte) ([]byte, error) {
	// Deserialize hybrid ciphertext
	hybrid, err := deserialize[hybridCiphertext](ciphertext)
	if err != nil {
		return nil, err
	}

	// Decapsulate to get shared secret
	unmarshaledPrivateKey, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := scheme.Decapsulate(unmarshaledPrivateKey, hybrid.EncapsulatedKey)
	if err != nil {
		return nil, fmt.Errorf("kyber512 decapsulation failed: %w", err)
	}

	// Derive AES key
	aesKey := deriveKey(sharedSecret, 32)

	// Decrypt data
	return aesGCMDecrypt(aesKey, hybrid.Ciphertext, hybrid.Nonce)
}

func deriveKey(sharedSecret []byte, keySize int) []byte {
	// Use HKDF to derive a key from the shared secret
	hkdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("kyber-hybrid-encryption"))
	key := make([]byte, keySize)
	io.ReadFull(hkdf, key)
	return key
}

func aesGCMEncrypt(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func aesGCMDecrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
