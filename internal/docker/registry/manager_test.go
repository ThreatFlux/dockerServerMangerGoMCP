package registry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	registrytypes "github.com/docker/docker/api/types/registry"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/distribution/reference" // Import for reference.Named
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// MockCredentialStore is a mock implementation of CredentialStore
type MockCredentialStore struct {
	mock.Mock
}

func (m *MockCredentialStore) Add(ctx context.Context, registry string, creds Credentials, currentUser string) error {
	args := m.Called(ctx, registry, creds, currentUser)
	return args.Error(0)
}

func (m *MockCredentialStore) Get(ctx context.Context, registry string, currentUser string) (Credentials, error) {
	args := m.Called(ctx, registry, currentUser)
	// Handle potential nil return from mock if error occurs
	if args.Get(0) == nil {
		// Return zero value for Credentials if Get(0) is nil
		return Credentials{}, args.Error(1)
	}
	return args.Get(0).(Credentials), args.Error(1)
}

func (m *MockCredentialStore) Remove(ctx context.Context, registry string, currentUser string) error {
	args := m.Called(ctx, registry, currentUser)
	return args.Error(0)
}

func (m *MockCredentialStore) List(ctx context.Context, currentUser string) ([]RegistryInfo, error) {
	args := m.Called(ctx, currentUser)
	// Handle potential nil return from mock if error occurs
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]RegistryInfo), args.Error(1)
}

func (m *MockCredentialStore) Validate(ctx context.Context, registry string, creds Credentials) (bool, error) {
	args := m.Called(ctx, registry, creds)
	return args.Bool(0), args.Error(1)
}

func (m *MockCredentialStore) GetAuthConfig(ctx context.Context, registry string, currentUser string) (registrytypes.AuthConfig, error) {
	args := m.Called(ctx, registry, currentUser)
	// Handle potential nil return from mock if error occurs
	if args.Error(1) != nil {
		return registrytypes.AuthConfig{}, args.Error(1)
	}
	return args.Get(0).(registrytypes.AuthConfig), nil
}

func (m *MockCredentialStore) AddUserToCredential(ctx context.Context, registry string, user string, currentUser string) error {
	args := m.Called(ctx, registry, user, currentUser)
	return args.Error(0)
}

func (m *MockCredentialStore) RemoveUserFromCredential(ctx context.Context, registry string, user string, currentUser string) error {
	args := m.Called(ctx, registry, user, currentUser)
	return args.Error(0)
}

func (m *MockCredentialStore) SetOwner(ctx context.Context, registry string, newOwner string, currentUser string) error {
	args := m.Called(ctx, registry, newOwner, currentUser)
	return args.Error(0)
}

// setupTestManager sets up a test credential manager with a mock store
func setupTestManager(t *testing.T) (*CredentialManager, *MockCredentialStore) {
	mockStore := new(MockCredentialStore)
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	manager, err := NewCredentialManager(CredentialManagerOptions{
		Store:  mockStore,
		Logger: logger,
		// Removed obsolete fields
	})
	require.NoError(t, err, "Failed to create credential manager")

	return manager, mockStore
}

// setupTestFileManager sets up a test credential manager with a file store
func setupTestFileManager(t *testing.T) (*CredentialManager, string, func()) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "cred-manager-test-*")
	require.NoError(t, err, "Failed to create temp directory")

	// Create store path
	storePath := filepath.Join(tempDir, "credentials.json")

	// Create store
	store, err := NewFileCredentialStore(FileCredentialStoreOptions{
		StorePath:     storePath,
		EncryptionKey: "test-encryption-key-32byteslong", // Ensure key is 32 bytes for AES-256
		Logger:        logrus.New(),
		// AdminUsers:    []string{"admin"}, // Assuming AdminUsers might be handled differently or removed
	})
	require.NoError(t, err, "Failed to create credential store")

	// Create manager
	manager, err := NewCredentialManager(CredentialManagerOptions{
		Store:  store,
		Logger: logrus.New(),
		// Removed obsolete fields
	})
	require.NoError(t, err, "Failed to create credential manager")

	// Return cleanup function
	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return manager, tempDir, cleanup
}

func TestNewCredentialManager(t *testing.T) {
	t.Run("ValidOptions", func(t *testing.T) {
		mockStore := new(MockCredentialStore)
		logger := logrus.New()

		manager, err := NewCredentialManager(CredentialManagerOptions{
			Store:  mockStore,
			Logger: logger,
			// Removed obsolete fields
		})

		assert.NoError(t, err)
		assert.NotNil(t, manager)
		assert.Equal(t, mockStore, manager.store)
		assert.Equal(t, logger, manager.logger)
		// Removed assertions for obsolete fields
	})

	t.Run("NilStore", func(t *testing.T) {
		_, err := NewCredentialManager(CredentialManagerOptions{
			Store:  nil,
			Logger: logrus.New(),
			// Removed obsolete fields
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "credential store is required")
	})

	t.Run("DefaultOptions", func(t *testing.T) {
		// This test might need adjustment based on how default store is handled now
		// Assuming NewCredentialManager handles default store creation if Store is nil
		// Need to mock os.UserHomeDir potentially or ensure ~/.docker_test/config.json doesn't interfere

		// For now, just test that it doesn't error with only Store provided
		mockStore := new(MockCredentialStore)
		manager, err := NewCredentialManager(CredentialManagerOptions{
			Store: mockStore,
		})

		assert.NoError(t, err)
		assert.NotNil(t, manager)
		assert.Equal(t, mockStore, manager.store)
		assert.NotNil(t, manager.logger)
		// Removed assertions for obsolete fields
	})
}

func TestCredentialManager_GetAuthConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("SuccessfulRetrieval", func(t *testing.T) {
		manager, mockStore := setupTestManager(t)

		// Setup mock
		expectedAuthConfig := registrytypes.AuthConfig{
			Username:      "testuser",
			Password:      "testpass",
			ServerAddress: "docker_test.io",
		}

		// Mock GetAuthConfig without user
		mockStore.On("GetAuthConfig", ctx, "docker_test.io", "").
			Return(expectedAuthConfig, nil)

		// Get auth config (no user argument)
		authConfig, err := manager.GetAuthConfig(ctx, "docker_test.io")

		assert.NoError(t, err)
		assert.Equal(t, expectedAuthConfig, authConfig)

		mockStore.AssertCalled(t, "GetAuthConfig", ctx, "docker_test.io", "")
	})

	t.Run("CredentialsNotFound", func(t *testing.T) {
		manager, mockStore := setupTestManager(t)

		// Setup mock (no user)
		mockStore.On("GetAuthConfig", ctx, "nonexistent.registry.com", "").
			Return(registrytypes.AuthConfig{}, ErrCredentialsNotFound)

		// Get auth config (no user argument)
		authConfig, err := manager.GetAuthConfig(ctx, "nonexistent.registry.com")

		// Expect ErrCredentialsNotFound directly from the manager now
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrCredentialsNotFound)) // Now uses imported errors package
		assert.Empty(t, authConfig.Username)                   // Check that returned config is zero value
	})

	// Removed tests related to ValidateOnAccess as the feature is removed
}

// Removed TestCredentialManager_AddCredentials, RemoveCredentials, ListCredentials
// as these methods are no longer directly on the manager.
// Functionality should be tested via the store or higher-level operations.

// TestParseImageName tests the utility function (assuming it's moved/available)
func TestParseImageName(t *testing.T) {
	testCases := []struct {
		name           string
		image          string
		expectRegistry string
		expectRepo     string
		expectTag      string
		expectDigest   string
		expectError    bool
	}{
		{
			name:           "Simple image",
			image:          "alpine",
			expectRegistry: "docker_test.io",
			expectRepo:     "library/alpine",
			expectTag:      "latest",
		},
		{
			name:           "Image with tag",
			image:          "alpine:3.14",
			expectRegistry: "docker_test.io",
			expectRepo:     "library/alpine",
			expectTag:      "3.14",
		},
		{
			name:           "Image with registry",
			image:          "registry.example.com/myapp",
			expectRegistry: "registry.example.com",
			expectRepo:     "myapp",
			expectTag:      "latest",
		},
		{
			name:           "Image with registry and tag",
			image:          "registry.example.com/myapp:1.0",
			expectRegistry: "registry.example.com",
			expectRepo:     "myapp",
			expectTag:      "1.0",
		},
		{
			name:           "Image with registry, org, and tag",
			image:          "registry.example.com/org/myapp:1.0",
			expectRegistry: "registry.example.com",
			expectRepo:     "org/myapp",
			expectTag:      "1.0",
		},
		{
			name:           "Image with digest",
			image:          "alpine@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectRegistry: "docker_test.io",
			expectRepo:     "library/alpine",
			expectTag:      "", // No tag when digest is present
			expectDigest:   "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
		{
			name:           "Image with registry and digest",
			image:          "registry.example.com/myapp@sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
			expectRegistry: "registry.example.com",
			expectRepo:     "myapp",
			expectTag:      "", // No tag when digest is present
			expectDigest:   "sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
		},
		{
			name:           "Docker Hub with organization",
			image:          "nginx/nginx",
			expectRegistry: "docker_test.io",
			expectRepo:     "nginx/nginx",
			expectTag:      "latest",
		},
		{
			name:        "Invalid image name",
			image:       "invalid image name with spaces",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Use utils.ParseImageName
			named, err := utils.ParseImageName(tc.image) // Use the function from utils
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err) // Use require for non-error cases

				// Extract components from the parsed reference.Named object
				domain := reference.Domain(named)
				repoName := reference.Path(named)
				tag := ""
				digest := ""

				if tagged, ok := named.(reference.Tagged); ok {
					tag = tagged.Tag()
				}
				if digested, ok := named.(reference.Digested); ok {
					digest = digested.Digest().String()
				}
				if tag == "" && digest == "" {
					tag = "latest" // Default tag if none specified
				}

				assert.Equal(t, tc.expectRegistry, domain, "Registry mismatch")
				assert.Equal(t, tc.expectRepo, repoName, "Repository mismatch")
				assert.Equal(t, tc.expectTag, tag, "Tag mismatch")
				assert.Equal(t, tc.expectDigest, digest, "Digest mismatch")
			}
		})
	}
}

// Removed duplicate TestEncodeAuthConfig

// Removed TestGetDefaultCredentialManager
