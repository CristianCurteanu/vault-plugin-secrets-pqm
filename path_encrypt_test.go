package secretsengine

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// PathEncryptTestSuite contains all tests for pathEncrypt
type PathEncryptTestSuite struct {
	suite.Suite
	backend *pqBackend
	storage logical.Storage
	ctx     context.Context
}

// SetupSuite runs before all tests in the suite
func (suite *PathEncryptTestSuite) SetupSuite() {
	suite.ctx = context.Background()
	suite.backend = NewPqBackend()
	suite.storage = &logical.InmemStorage{}

	// Initialize some test keys for encryption tests
	suite.setupTestKeys()
}

// TestSuite runner
func TestPathEncryptSuite(t *testing.T) {
	suite.Run(t, new(PathEncryptTestSuite))
}

// setupTestKeys creates test encryption keys for different algorithms
func (suite *PathEncryptTestSuite) setupTestKeys() {
	testKeys := []struct {
		name    string
		keyType string
	}{
		{"test-kyber-512", "kyber-512"},
		{"test-kyber-768", "kyber-768"},
		{"test-kyber-1024", "kyber-1024"},
	}

	for _, tk := range testKeys {
		keyBytes, err := suite.backend.generateKey(tk.keyType)
		require.NoError(suite.T(), err)

		key := &encryptionKey{
			Name:                 tk.name,
			Type:                 tk.keyType,
			CreatedTime:          time.Now(),
			Versions:             make(map[int]*keyVersion),
			LatestVersion:        1,
			MinDecryptVersion:    1,
			MinEncryptVersion:    0,
			AllowPlaintextBackup: false,
			DeletionAllowed:      false,
		}

		key.Versions[1] = &keyVersion{
			Version:     1,
			Key:         keyBytes,
			CreatedTime: time.Now(),
		}

		suite.backend.cache.Set(tk.name, key)
	}
}

// TestEncryptWithKyber512 tests encryption with Kyber-512 algorithm
func (suite *PathEncryptTestSuite) TestEncryptWithKyber512() {
	suite.testEncryptWithAlgorithm("test-kyber-512")
}

// TestEncryptWithKyber768 tests encryption with Kyber-768 algorithm
func (suite *PathEncryptTestSuite) TestEncryptWithKyber768() {
	suite.testEncryptWithAlgorithm("test-kyber-768")
}

// TestEncryptWithKyber1024 tests encryption with Kyber-1024 algorithm
func (suite *PathEncryptTestSuite) TestEncryptWithKyber1024() {
	suite.testEncryptWithAlgorithm("test-kyber-1024")
}

// testEncryptWithAlgorithm is a helper function to test encryption with any algorithm
func (suite *PathEncryptTestSuite) testEncryptWithAlgorithm(keyName string) {
	testData := "Hello, Post-Quantum World!"
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(testData))

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("encrypt/%s", keyName),
		Storage:   suite.storage,
	}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":        keyName,
			"plaintext":   plaintextB64,
			"key_version": 1,
		},
		Schema: suite.backend.pathEncrypt().Fields,
	}

	resp, err := suite.backend.pathEncryptWrite(suite.ctx, req, data)

	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), resp)
	require.False(suite.T(), resp.IsError())

	// Verify response structure
	require.Contains(suite.T(), resp.Data, "ciphertext")
	require.Contains(suite.T(), resp.Data, "key_version")

	ciphertext := resp.Data["ciphertext"].(string)
	parts := strings.Split(ciphertext, ":")
	require.Len(suite.T(), parts, 3)
	require.Equal(suite.T(), "vault", parts[0])
	require.Equal(suite.T(), "v1", parts[1])

	_, err = base64.StdEncoding.DecodeString(parts[2])
	require.NoError(suite.T(), err)
	require.Equal(suite.T(), 1, resp.Data["key_version"])
}

// TestEncryptWithSpecificKeyVersion tests encryption with a specific key version
func (suite *PathEncryptTestSuite) TestEncryptWithSpecificKeyVersion() {
	keyName := "test-kyber-512"
	testData := "Version specific test"
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(testData))

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("encrypt/%s", keyName),
		Storage:   suite.storage,
	}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":        keyName,
			"plaintext":   plaintextB64,
			"key_version": 1,
		},
		Schema: suite.backend.pathEncrypt().Fields,
	}

	resp, err := suite.backend.pathEncryptWrite(suite.ctx, req, data)

	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), resp)
	require.False(suite.T(), resp.IsError())

	// Verify specific version was used
	require.Equal(suite.T(), 1, resp.Data["key_version"])

	// Verify ciphertext contains version info
	ciphertext := resp.Data["ciphertext"].(string)
	require.True(suite.T(), strings.Contains(ciphertext, "vault:v1:"))
}

// TestEncryptWithInvalidBase64 tests error handling for invalid base64 plaintext
func (suite *PathEncryptTestSuite) TestEncryptWithInvalidBase64() {
	keyName := "test-kyber-512"
	invalidBase64 := "invalid-base64-data!!!"

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("encrypt/%s", keyName),
		Storage:   suite.storage,
	}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":      keyName,
			"plaintext": invalidBase64,
		},
		Schema: suite.backend.pathEncrypt().Fields,
	}

	resp, err := suite.backend.pathEncryptWrite(suite.ctx, req, data)

	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), resp)
	require.True(suite.T(), resp.IsError())
	require.Contains(suite.T(), resp.Error().Error(), "invalid base64 plaintext")
}

// TestEncryptWithNonExistentKey tests error handling for non-existent keys
func (suite *PathEncryptTestSuite) TestEncryptWithNonExistentKey() {
	keyName := "non-existent-key"
	testData := "Test data"
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(testData))

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("encrypt/%s", keyName),
		Storage:   suite.storage,
	}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":        keyName,
			"plaintext":   plaintextB64,
			"key_version": 1,
		},
		Schema: suite.backend.pathEncrypt().Fields,
	}

	resp, err := suite.backend.pathEncryptWrite(suite.ctx, req, data)

	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), resp)
	require.True(suite.T(), resp.IsError())
	require.Contains(suite.T(), resp.Error().Error(), "key not found")
}

// TestEncryptWithInvalidKeyVersion tests error handling for invalid key versions
func (suite *PathEncryptTestSuite) TestEncryptWithInvalidKeyVersion() {
	keyName := "test-kyber-512"
	testData := "Test data"
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(testData))

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("encrypt/%s", keyName),
		Storage:   suite.storage,
	}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":        keyName,
			"plaintext":   plaintextB64,
			"key_version": 999, // Non-existent version
		},
		Schema: suite.backend.pathEncrypt().Fields,
	}

	resp, err := suite.backend.pathEncryptWrite(suite.ctx, req, data)

	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), resp)
	require.True(suite.T(), resp.IsError())
	require.Contains(suite.T(), resp.Error().Error(), "key version not found")
}

// TestEncryptWithEmptyPlaintext tests encryption with empty plaintext
func (suite *PathEncryptTestSuite) TestEncryptWithEmptyPlaintext() {
	keyName := "test-kyber-512"
	emptyData := ""
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(emptyData))

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("encrypt/%s", keyName),
		Storage:   suite.storage,
	}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":        keyName,
			"plaintext":   plaintextB64,
			"key_version": 1,
		},
		Schema: suite.backend.pathEncrypt().Fields,
	}

	resp, err := suite.backend.pathEncryptWrite(suite.ctx, req, data)

	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), resp)
	require.False(suite.T(), resp.IsError())

	// Should successfully encrypt empty data
	require.Contains(suite.T(), resp.Data, "ciphertext")
	require.Contains(suite.T(), resp.Data, "key_version")
}

// TestEncryptAlgorithmContainerIntegration tests the integration with algorithm container
func (suite *PathEncryptTestSuite) TestEncryptAlgorithmContainerIntegration() {
	// Test that all registered algorithms are accessible
	algorithms := []string{"kyber-512", "kyber-768", "kyber-1024"}

	for _, alg := range algorithms {
		encryptor, exists := suite.backend.algorithmsContainer.Get(alg)
		require.True(suite.T(), exists, "Algorithm %s should be registered", alg)
		require.Equal(suite.T(), alg, encryptor.GetName())
		require.NotNil(suite.T(), encryptor.GetAlgorithms())
		require.NotNil(suite.T(), encryptor.GetAlgorithms().encrypt)
		require.NotNil(suite.T(), encryptor.GetAlgorithms().decrypt)
	}
}
