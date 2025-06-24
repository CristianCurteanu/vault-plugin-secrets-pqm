package secretsengine

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// PathDecryptSuite defines the test suite for pathDecrypt
type PathDecryptSuite struct {
	suite.Suite
	backend  *pqBackend
	ctx      context.Context
	storage  logical.Storage
	testKeys map[string]*encryptionKey
	testData map[string][]byte
}

// Run the test suite
func TestPathDecryptSuite(t *testing.T) {
	suite.Run(t, new(PathDecryptSuite))
}

// SetupSuite runs once before all tests in the suite
func (suite *PathDecryptSuite) SetupSuite() {
	suite.ctx = context.Background()
	suite.storage = &logical.InmemStorage{}

	// Initialize the backend with all components
	suite.backend = NewPqBackend()

	// Prepare test data
	suite.setupTestData()
}

// SetupTest runs before each individual test
func (suite *PathDecryptSuite) SetupTest() {
	// Clear backend cache
	suite.backend.cache = newKeyVal[string, *encryptionKey]()

	// Setup test keys in cache for each test
	for name, key := range suite.testKeys {
		suite.backend.cache.Set(name, key)
	}
}

// setupTestData prepares test keys and test data for encryption/decryption
func (suite *PathDecryptSuite) setupTestData() {
	suite.testKeys = make(map[string]*encryptionKey)
	suite.testData = make(map[string][]byte)

	// Test plaintext data
	suite.testData["simple"] = []byte("Hello, World!")
	suite.testData["empty"] = []byte("")
	suite.testData["binary"] = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}
	suite.testData["large"] = make([]byte, 1024)
	for i := range suite.testData["large"] {
		suite.testData["large"][i] = byte(i % 256)
	}

	// Generate test keys for each Kyber algorithm
	algorithms := []string{"kyber-512", "kyber-768", "kyber-1024"}

	for _, alg := range algorithms {
		keyBytes, err := suite.backend.generateKey(alg)
		require.NoError(suite.T(), err)

		key := &encryptionKey{
			Name:                 fmt.Sprintf("test-key-%s", alg),
			Type:                 alg,
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

		suite.testKeys[key.Name] = key
	}
}

// Helper function to create encrypted ciphertext for testing
func (suite *PathDecryptSuite) createTestCiphertext(keyName string, plaintext []byte, version int) string {
	key, exists := suite.testKeys[keyName]
	require.True(suite.T(), exists)

	keyVersion, exists := key.Versions[version]
	require.True(suite.T(), exists)

	// Encrypt the plaintext
	ciphertext, err := suite.backend.encrypt(key.Type, keyVersion.Key, plaintext)
	require.NoError(suite.T(), err)

	// Format as Vault ciphertext
	return fmt.Sprintf("vault:v%d:%s", version, base64.StdEncoding.EncodeToString(ciphertext))
}

// Test successful decryption with valid parameters
func (suite *PathDecryptSuite) TestPathDecryptWrite_Success() {
	testCases := []struct {
		name      string
		keyName   string
		plaintext []byte
		version   int
	}{
		{
			name:      "kyber-512 simple text",
			keyName:   "test-key-kyber-512",
			plaintext: suite.testData["simple"],
			version:   1,
		},
		{
			name:      "kyber-768 empty data",
			keyName:   "test-key-kyber-768",
			plaintext: suite.testData["empty"],
			version:   1,
		},
		{
			name:      "kyber-1024 binary data",
			keyName:   "test-key-kyber-1024",
			plaintext: suite.testData["binary"],
			version:   1,
		},
		{
			name:      "kyber-512 large data",
			keyName:   "test-key-kyber-512",
			plaintext: suite.testData["large"],
			version:   1,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Create test ciphertext
			ciphertext := suite.createTestCiphertext(tc.keyName, tc.plaintext, tc.version)

			// Prepare request data
			data := &framework.FieldData{}
			data.Raw = map[string]interface{}{
				"name":       tc.keyName,
				"ciphertext": ciphertext,
			}
			data.Schema = suite.backend.pathDecrypt().Fields

			// Create mock request
			req := &logical.Request{
				Storage: suite.storage,
			}

			// Call pathDecryptWrite
			resp, err := suite.backend.pathDecryptWrite(suite.ctx, req, data)

			// Assertions
			require.NoError(suite.T(), err)
			require.NotNil(suite.T(), resp)
			require.NotNil(suite.T(), resp.Data)

			// Verify decrypted plaintext
			plaintextB64, exists := resp.Data["plaintext"]
			require.True(suite.T(), exists)

			decodedPlaintext, err := base64.StdEncoding.DecodeString(plaintextB64.(string))
			require.NoError(suite.T(), err)
			require.Equal(suite.T(), tc.plaintext, decodedPlaintext)
		})
	}
}

// Test decryption with non-existent key
func (suite *PathDecryptSuite) TestPathDecryptWrite_KeyNotFound() {
	// Prepare request data with non-existent key
	data := &framework.FieldData{}
	data.Raw = map[string]interface{}{
		"name":       "non-existent-key",
		"ciphertext": "vault:v1:dGVzdA==", // dummy ciphertext
	}
	data.Schema = suite.backend.pathDecrypt().Fields

	req := &logical.Request{
		Storage: suite.storage,
	}

	// Call pathDecryptWrite
	resp, err := suite.backend.pathDecryptWrite(suite.ctx, req, data)

	// Assertions
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), resp)
	require.True(suite.T(), resp.IsError())
	require.Contains(suite.T(), resp.Error().Error(), "key not found")
}

// Test decryption with invalid ciphertext format
func (suite *PathDecryptSuite) TestPathDecryptWrite_InvalidCiphertextFormat() {
	testCases := []struct {
		name       string
		ciphertext string
		errorMsg   string
	}{
		{
			name:       "missing parts",
			ciphertext: "vault:v1",
			errorMsg:   "invalid ciphertext format",
		},
		{
			name:       "wrong prefix",
			ciphertext: "invalid:v1:dGVzdA==",
			errorMsg:   "invalid ciphertext format",
		},
		{
			name:       "empty string",
			ciphertext: "",
			errorMsg:   "invalid ciphertext format",
		},
		{
			name:       "no colons",
			ciphertext: "vaultv1data",
			errorMsg:   "invalid ciphertext format",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			data := &framework.FieldData{}
			data.Raw = map[string]interface{}{
				"name":       "test-key-kyber-512",
				"ciphertext": tc.ciphertext,
			}
			data.Schema = suite.backend.pathDecrypt().Fields

			req := &logical.Request{
				Storage: suite.storage,
			}

			resp, err := suite.backend.pathDecryptWrite(suite.ctx, req, data)

			require.NoError(suite.T(), err)
			require.NotNil(suite.T(), resp)
			require.True(suite.T(), resp.IsError())
			require.Contains(suite.T(), resp.Error().Error(), tc.errorMsg)
		})
	}
}

// Test decryption with invalid version format
func (suite *PathDecryptSuite) TestPathDecryptWrite_InvalidVersionFormat() {
	testCases := []struct {
		name       string
		ciphertext string
	}{
		{
			name:       "non-numeric version",
			ciphertext: "vault:vabc:dGVzdA==",
		},
		{
			name:       "missing v prefix",
			ciphertext: "vault:1:dGVzdA==",
		},
		{
			name:       "empty version",
			ciphertext: "vault::dGVzdA==",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			data := &framework.FieldData{}
			data.Raw = map[string]interface{}{
				"name":       "test-key-kyber-512",
				"ciphertext": tc.ciphertext,
			}
			data.Schema = suite.backend.pathDecrypt().Fields

			req := &logical.Request{
				Storage: suite.storage,
			}

			resp, err := suite.backend.pathDecryptWrite(suite.ctx, req, data)

			require.NoError(suite.T(), err)
			require.NotNil(suite.T(), resp)
			require.True(suite.T(), resp.IsError())
			require.Contains(suite.T(), resp.Error().Error(), "invalid version format")
		})
	}
}

// Test decryption with non-existent key version
func (suite *PathDecryptSuite) TestPathDecryptWrite_KeyVersionNotFound() {
	data := &framework.FieldData{}
	data.Raw = map[string]interface{}{
		"name":       "test-key-kyber-512",
		"ciphertext": "vault:v99:dGVzdA==", // version 99 doesn't exist
	}
	data.Schema = suite.backend.pathDecrypt().Fields

	req := &logical.Request{
		Storage: suite.storage,
	}

	resp, err := suite.backend.pathDecryptWrite(suite.ctx, req, data)

	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), resp)
	require.True(suite.T(), resp.IsError())
	require.Contains(suite.T(), resp.Error().Error(), "key version not found")
}

// Test decryption with invalid base64 ciphertext
func (suite *PathDecryptSuite) TestPathDecryptWrite_InvalidBase64Ciphertext() {
	data := &framework.FieldData{}
	data.Raw = map[string]interface{}{
		"name":       "test-key-kyber-512",
		"ciphertext": "vault:v1:invalid@base64!", // invalid base64
	}
	data.Schema = suite.backend.pathDecrypt().Fields

	req := &logical.Request{
		Storage: suite.storage,
	}

	resp, err := suite.backend.pathDecryptWrite(suite.ctx, req, data)

	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), resp)
	require.True(suite.T(), resp.IsError())
	require.Contains(suite.T(), resp.Error().Error(), "invalid base64 ciphertext")
}

// Test decryption with corrupted ciphertext data
func (suite *PathDecryptSuite) TestPathDecryptWrite_CorruptedCiphertext() {
	// Create valid base64 but invalid ciphertext data
	corruptedData := base64.StdEncoding.EncodeToString([]byte("corrupted data"))

	data := &framework.FieldData{}
	data.Raw = map[string]interface{}{
		"name":       "test-key-kyber-512",
		"ciphertext": fmt.Sprintf("vault:v1:%s", corruptedData),
	}
	data.Schema = suite.backend.pathDecrypt().Fields

	req := &logical.Request{
		Storage: suite.storage,
	}

	resp, err := suite.backend.pathDecryptWrite(suite.ctx, req, data)

	// Should return an error (not a logical error response)
	require.Nil(suite.T(), resp)
	require.Error(suite.T(), err)
	require.Contains(suite.T(), err.Error(), "decryption failed")
}

// Test decryption with different key versions
func (suite *PathDecryptSuite) TestPathDecryptWrite_MultipleKeyVersions() {
	keyName := "test-key-kyber-512"
	key := suite.testKeys[keyName]

	// Add a second version to the key
	keyBytes2, err := suite.backend.generateKey(key.Type)
	require.NoError(suite.T(), err)

	key.Versions[2] = &keyVersion{
		Version:     2,
		Key:         keyBytes2,
		CreatedTime: time.Now(),
	}
	key.LatestVersion = 2

	// Test decryption with both versions
	testData := suite.testData["simple"]

	// Test version 1
	ciphertext1 := suite.createTestCiphertext(keyName, testData, 1)
	data1 := &framework.FieldData{}
	data1.Raw = map[string]interface{}{
		"name":       keyName,
		"ciphertext": ciphertext1,
	}
	data1.Schema = suite.backend.pathDecrypt().Fields

	req := &logical.Request{Storage: suite.storage}
	resp1, err := suite.backend.pathDecryptWrite(suite.ctx, req, data1)

	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), resp1)
	require.False(suite.T(), resp1.IsError())

	// Test version 2
	ciphertext2 := suite.createTestCiphertext(keyName, testData, 2)
	data2 := &framework.FieldData{}
	data2.Raw = map[string]interface{}{
		"name":       keyName,
		"ciphertext": ciphertext2,
	}
	data2.Schema = suite.backend.pathDecrypt().Fields

	resp2, err := suite.backend.pathDecryptWrite(suite.ctx, req, data2)

	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), resp2)
	require.False(suite.T(), resp2.IsError())

	// Both should decrypt to the same plaintext
	plaintext1B64 := resp1.Data["plaintext"].(string)
	plaintext2B64 := resp2.Data["plaintext"].(string)

	plaintext1, _ := base64.StdEncoding.DecodeString(plaintext1B64)
	plaintext2, _ := base64.StdEncoding.DecodeString(plaintext2B64)

	require.Equal(suite.T(), testData, plaintext1)
	require.Equal(suite.T(), testData, plaintext2)
}

// Test concurrent decryption operations
func (suite *PathDecryptSuite) TestPathDecryptWrite_ConcurrentAccess() {
	keyName := "test-key-kyber-512"
	testData := suite.testData["simple"]
	ciphertext := suite.createTestCiphertext(keyName, testData, 1)

	// Number of concurrent operations
	numOps := 10
	results := make(chan error, numOps)

	// Launch concurrent decryption operations
	for i := 0; i < numOps; i++ {
		go func() {
			data := &framework.FieldData{}
			data.Raw = map[string]interface{}{
				"name":       keyName,
				"ciphertext": ciphertext,
			}
			data.Schema = suite.backend.pathDecrypt().Fields

			req := &logical.Request{Storage: suite.storage}
			resp, err := suite.backend.pathDecryptWrite(suite.ctx, req, data)

			if err != nil {
				results <- err
				return
			}

			if resp.IsError() {
				results <- resp.Error()
				return
			}

			// Verify the result
			plaintextB64 := resp.Data["plaintext"].(string)
			plaintext, decodeErr := base64.StdEncoding.DecodeString(plaintextB64)
			if decodeErr != nil {
				results <- decodeErr
				return
			}

			if !assert.ObjectsAreEqual(testData, plaintext) {
				results <- fmt.Errorf("decrypted data mismatch")
				return
			}

			results <- nil
		}()
	}

	// Collect all results
	for i := 0; i < numOps; i++ {
		err := <-results
		require.NoError(suite.T(), err)
	}
}
