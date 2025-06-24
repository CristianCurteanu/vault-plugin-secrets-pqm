package secretsengine

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// PathKeysSuite defines the test suite for pathKeys functionality
type PathKeysSuite struct {
	suite.Suite
	backend *pqBackend
	ctx     context.Context
	storage logical.Storage
}

// TestSuite runs the test suite
func TestPathKeysTestSuite(t *testing.T) {
	suite.Run(t, new(PathKeysSuite))
}

func (suite *PathKeysSuite) SetupSuite() {
	suite.ctx = context.Background()
	suite.storage = &logical.InmemStorage{}

	// Initialize the backend
	suite.backend = NewPqBackend()
	err := suite.backend.Setup(suite.ctx, &logical.BackendConfig{})
	require.NoError(suite.T(), err)
}

// SetupTest runs before each test to ensure clean state
func (suite *PathKeysSuite) SetupTest() {
	// Clear the cache for each test
	suite.backend.cache = newKeyVal[string, *encryptionKey]()
}

// TestPathKeysWriteSuccess tests successful key creation
func (suite *PathKeysSuite) TestPathKeysWriteSuccess() {
	testCases := []struct {
		name             string
		keyName          string
		keyType          string
		allowBackup      bool
		deletionAllowed  bool
		expectedResponse map[string]interface{}
	}{
		{
			name:            "Create Kyber512 Key",
			keyName:         "test-kyber512",
			keyType:         "kyber-512",
			allowBackup:     false,
			deletionAllowed: false,
			expectedResponse: map[string]interface{}{
				"name":    "test-kyber512",
				"type":    "kyber-512",
				"version": 1,
			},
		},
		{
			name:            "Create Kyber768 Key",
			keyName:         "test-kyber768",
			keyType:         "kyber-768",
			allowBackup:     true,
			deletionAllowed: false,
			expectedResponse: map[string]interface{}{
				"name":    "test-kyber768",
				"type":    "kyber-768",
				"version": 1,
			},
		},
		{
			name:            "Create Kyber1024 Key",
			keyName:         "test-kyber1024",
			keyType:         "kyber-1024",
			allowBackup:     false,
			deletionAllowed: true,
			expectedResponse: map[string]interface{}{
				"name":    "test-kyber1024",
				"type":    "kyber-1024",
				"version": 1,
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Create request data
			data := &framework.FieldData{
				Raw: map[string]interface{}{
					"name":                   tc.keyName,
					"type":                   tc.keyType,
					"allow_plaintext_backup": tc.allowBackup,
					"deletion_allowed":       tc.deletionAllowed,
				},
				Schema: suite.backend.pathKeys().Fields,
			}

			// Create request
			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "keys/" + tc.keyName,
				Storage:   suite.storage,
			}

			resp, err := suite.backend.pathKeysWrite(suite.ctx, req, data)

			require.NoError(suite.T(), err)
			require.NotNil(suite.T(), resp)
			require.Nil(suite.T(), resp.Warnings)
			require.Equal(suite.T(), tc.expectedResponse, resp.Data)

			// Verify key is stored in cache
			storedKey, exists := suite.backend.cache.Get(tc.keyName)
			require.True(suite.T(), exists)
			require.Equal(suite.T(), tc.keyName, storedKey.Name)
			require.Equal(suite.T(), tc.keyType, storedKey.Type)

			// Verify key version exists
			require.Contains(suite.T(), storedKey.Versions, 1)
			version := storedKey.Versions[1]
			require.Equal(suite.T(), 1, version.Version)
			require.NotEmpty(suite.T(), version.Key)
		})
	}
}

// TestConcurrentKeyCreation tests thread safety of key creation
func (suite *PathKeysSuite) TestConcurrentKeyCreation() {
	const numGoroutines = 10

	// Channel to collect results
	results := make(chan error, numGoroutines)

	// Start multiple goroutines creating different keys
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			keyName := fmt.Sprintf("concurrent-key-%d", id)

			data := &framework.FieldData{
				Raw: map[string]interface{}{
					"name":                   keyName,
					"type":                   "kyber-512",
					"allow_plaintext_backup": false,
					"deletion_allowed":       false,
				},
				Schema: suite.backend.pathKeys().Fields,
			}

			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "keys/" + keyName,
				Storage:   suite.storage,
			}

			_, err := suite.backend.pathKeysWrite(suite.ctx, req, data)
			results <- err
		}(i)
	}

	// Collect all results
	for i := 0; i < numGoroutines; i++ {
		err := <-results
		require.NoError(suite.T(), err)
	}

	// Verify all keys were created
	for i := 0; i < numGoroutines; i++ {
		keyName := fmt.Sprintf("concurrent-key-%d", i)
		_, exists := suite.backend.cache.Get(keyName)
		require.True(suite.T(), exists)
	}
}
