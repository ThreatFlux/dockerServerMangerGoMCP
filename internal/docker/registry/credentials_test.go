package registry

import (
	"context"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func setupTestCredentialStore(t *testing.T) (*FileCredentialStore, string) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "docker_test-creds-test-*")
	require.NoError(t, err, "Failed to create temp directory")

	// Create a test credential store
	storePath := filepath.Join(tempDir, "credentials.json")
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	store, err := NewFileCredentialStore(FileCredentialStoreOptions{
		StorePath:     storePath,
		EncryptionKey: "test-encryption-key",
		Logger:        logger,
		AdminUsers:    []string{"admin"},
	})
	require.NoError(t, err, "Failed to create credential store")

	return store, tempDir
}

func cleanupTestCredentialStore(tempDir string) {
	os.RemoveAll(tempDir)
}

func TestNewFileCredentialStore(t *testing.T) {
	store, tempDir := setupTestCredentialStore(t)
	defer cleanupTestCredentialStore(tempDir)

	assert.NotNil(t, store, "Credential store should not be nil")
	assert.True(t, store.initialized, "Credential store should be initialized")
}

func TestFileCredentialStore_Add(t *testing.T) {
	store, tempDir := setupTestCredentialStore(t)
	defer cleanupTestCredentialStore(tempDir)

	ctx := context.Background()
	testRegistry := "test.registry.com"
	user := "testuser"

	// Test adding new credentials
	creds := Credentials{
		Username: "user1",
		Password: "pass1",
		Email:    "user1@example.com",
		AuthType: AuthTypeBasic,
	}

	err := store.Add(ctx, testRegistry, creds, user)
	assert.NoError(t, err, "Should add credentials without error")

	// Test retrieving credentials
	retrieved, err := store.Get(ctx, testRegistry, user)
	assert.NoError(t, err, "Should get credentials without error")
	assert.Equal(t, creds.Username, retrieved.Username, "Username should match")
	assert.Equal(t, creds.Password, retrieved.Password, "Password should match")
	assert.Equal(t, creds.Email, retrieved.Email, "Email should match")
	assert.Equal(t, user, retrieved.Owner, "Owner should be set to the user who added the credentials")
	assert.False(t, retrieved.CreatedAt.IsZero(), "CreatedAt should be set")
	assert.False(t, retrieved.UpdatedAt.IsZero(), "UpdatedAt should be set")

	// Test updating credentials
	updatedCreds := Credentials{
		Username: "user1",
		Password: "newpass",
		Email:    "user1@example.com",
		AuthType: AuthTypeBasic,
	}

	err = store.Add(ctx, testRegistry, updatedCreds, user)
	assert.NoError(t, err, "Should update credentials without error")

	// Test retrieving updated credentials
	retrieved, err = store.Get(ctx, testRegistry, user)
	assert.NoError(t, err, "Should get updated credentials without error")
	assert.Equal(t, updatedCreds.Password, retrieved.Password, "Updated password should match")

	// Test invalid registry URL
	err = store.Add(ctx, "", creds, user)
	assert.Error(t, err, "Should error with empty registry")
	assert.ErrorIs(t, err, ErrInvalidRegistry, "Should return ErrInvalidRegistry")

	// Test invalid credentials
	err = store.Add(ctx, testRegistry, Credentials{}, user)
	assert.Error(t, err, "Should error with empty credentials")
	assert.ErrorIs(t, err, ErrEmptyCredentials, "Should return ErrEmptyCredentials")

	// Test permission denied
	err = store.Add(ctx, testRegistry, updatedCreds, "unauthorized-user")
	assert.Error(t, err, "Should error with unauthorized user")
	assert.ErrorIs(t, err, ErrPermissionDenied, "Should return ErrPermissionDenied")

	// Test admin access
	adminCreds := Credentials{
		Username: "admin1",
		Password: "adminpass",
		Email:    "admin1@example.com",
		AuthType: AuthTypeBasic,
	}

	err = store.Add(ctx, testRegistry, adminCreds, "admin")
	assert.NoError(t, err, "Admin should be able to update credentials")

	// Verify admin update
	retrieved, err = store.Get(ctx, testRegistry, user)
	assert.NoError(t, err, "Should get credentials updated by admin")
	assert.Equal(t, adminCreds.Username, retrieved.Username, "Admin-updated username should match")
}

func TestFileCredentialStore_Get(t *testing.T) {
	store, tempDir := setupTestCredentialStore(t)
	defer cleanupTestCredentialStore(tempDir)

	ctx := context.Background()
	testRegistry := "test.registry.com"
	user := "testuser"

	// Add test credentials
	creds := Credentials{
		Username: "user1",
		Password: "pass1",
		Email:    "user1@example.com",
		AuthType: AuthTypeBasic,
	}

	err := store.Add(ctx, testRegistry, creds, user)
	require.NoError(t, err, "Failed to add test credentials")

	// Test retrieving credentials
	retrieved, err := store.Get(ctx, testRegistry, user)
	assert.NoError(t, err, "Should get credentials without error")
	assert.Equal(t, creds.Username, retrieved.Username, "Username should match")

	// Test retrieving nonexistent credentials
	_, err = store.Get(ctx, "nonexistent.registry.com", user)
	assert.Error(t, err, "Should error with nonexistent registry")
	assert.ErrorIs(t, err, ErrCredentialsNotFound, "Should return ErrCredentialsNotFound")

	// Test unauthorized access
	_, err = store.Get(ctx, testRegistry, "unauthorized-user")
	assert.Error(t, err, "Should error with unauthorized user")
	assert.ErrorIs(t, err, ErrPermissionDenied, "Should return ErrPermissionDenied")

	// Test admin access
	_, err = store.Get(ctx, testRegistry, "admin")
	assert.NoError(t, err, "Admin should be able to get credentials")

	// Test allowed user access
	err = store.AddUserToCredential(ctx, testRegistry, "allowed-user", user)
	require.NoError(t, err, "Failed to add allowed user")

	_, err = store.Get(ctx, testRegistry, "allowed-user")
	assert.NoError(t, err, "Allowed user should be able to get credentials")
}

func TestFileCredentialStore_Remove(t *testing.T) {
	store, tempDir := setupTestCredentialStore(t)
	defer cleanupTestCredentialStore(tempDir)

	ctx := context.Background()
	testRegistry := "test.registry.com"
	user := "testuser"

	// Add test credentials
	creds := Credentials{
		Username: "user1",
		Password: "pass1",
		Email:    "user1@example.com",
		AuthType: AuthTypeBasic,
	}

	err := store.Add(ctx, testRegistry, creds, user)
	require.NoError(t, err, "Failed to add test credentials")

	// Test removing credentials
	err = store.Remove(ctx, testRegistry, user)
	assert.NoError(t, err, "Should remove credentials without error")

	// Test credentials no longer exist
	_, err = store.Get(ctx, testRegistry, user)
	assert.Error(t, err, "Should error after credentials are removed")
	assert.ErrorIs(t, err, ErrCredentialsNotFound, "Should return ErrCredentialsNotFound")

	// Test removing nonexistent credentials
	err = store.Remove(ctx, "nonexistent.registry.com", user)
	assert.Error(t, err, "Should error with nonexistent registry")
	assert.ErrorIs(t, err, ErrCredentialsNotFound, "Should return ErrCredentialsNotFound")

	// Test unauthorized removal
	err = store.Add(ctx, testRegistry, creds, user)
	require.NoError(t, err, "Failed to add test credentials")

	err = store.Remove(ctx, testRegistry, "unauthorized-user")
	assert.Error(t, err, "Should error with unauthorized user")
	assert.ErrorIs(t, err, ErrPermissionDenied, "Should return ErrPermissionDenied")

	// Test admin removal
	err = store.Remove(ctx, testRegistry, "admin")
	assert.NoError(t, err, "Admin should be able to remove credentials")
}

func TestFileCredentialStore_List(t *testing.T) {
	store, tempDir := setupTestCredentialStore(t)
	defer cleanupTestCredentialStore(tempDir)

	ctx := context.Background()
	user := "testuser"

	// Add test credentials
	registries := []string{
		"registry1.example.com",
		"registry2.example.com",
		"registry3.example.com",
	}

	for i, registry := range registries {
		creds := Credentials{
			Username: "user" + string(rune('1'+i)),
			Password: "pass" + string(rune('1'+i)),
			Email:    "user" + string(rune('1'+i)) + "@example.com",
			AuthType: AuthTypeBasic,
		}

		err := store.Add(ctx, registry, creds, user)
		require.NoError(t, err, "Failed to add test credentials")
	}

	// Add a registry owned by another user
	otherRegistry := "other.registry.com"
	otherCreds := Credentials{
		Username: "otheruser",
		Password: "otherpass",
		Email:    "other@example.com",
		AuthType: AuthTypeBasic,
	}
	err := store.Add(ctx, otherRegistry, otherCreds, "otheruser")
	require.NoError(t, err, "Failed to add other user credentials")

	// Test listing user's credentials
	list, err := store.List(ctx, user)
	assert.NoError(t, err, "Should list credentials without error")
	assert.Len(t, list, len(registries), "Should list all user's registries")

	// Verify list contains the right registries
	registrySet := make(map[string]bool)
	for _, info := range list {
		registrySet[info.Registry] = true
		assert.Equal(t, user, info.Owner, "Owner should match")
		assert.Empty(t, info.ServerAddress, "Server address should be masked")
	}

	for _, registry := range registries {
		assert.True(t, registrySet[normalizeRegistryURL(registry)], "List should contain registry: "+registry)
	}

	// Test that other user's registry is not listed
	assert.False(t, registrySet[normalizeRegistryURL(otherRegistry)], "List should not contain other user's registry")

	// Test admin listing
	adminList, err := store.List(ctx, "admin")
	assert.NoError(t, err, "Admin should list credentials without error")
	assert.Len(t, adminList, len(registries)+1, "Admin should see all registries")

	// Test unauthorized user
	unauthorizedList, err := store.List(ctx, "unauthorized-user")
	assert.NoError(t, err, "Unauthorized user should get empty list without error")
	assert.Empty(t, unauthorizedList, "Unauthorized user should get empty list")
}

func TestFileCredentialStore_AddUserToCredential(t *testing.T) {
	store, tempDir := setupTestCredentialStore(t)
	defer cleanupTestCredentialStore(tempDir)

	ctx := context.Background()
	testRegistry := "test.registry.com"
	user := "testuser"
	allowedUser := "alloweduser"

	// Add test credentials
	creds := Credentials{
		Username: "user1",
		Password: "pass1",
		Email:    "user1@example.com",
		AuthType: AuthTypeBasic,
	}

	err := store.Add(ctx, testRegistry, creds, user)
	require.NoError(t, err, "Failed to add test credentials")

	// Test adding allowed user
	err = store.AddUserToCredential(ctx, testRegistry, allowedUser, user)
	assert.NoError(t, err, "Should add user without error")

	// Verify allowed user has access
	_, err = store.Get(ctx, testRegistry, allowedUser)
	assert.NoError(t, err, "Allowed user should have access")

	// Test unauthorized user cannot add allowed user
	err = store.AddUserToCredential(ctx, testRegistry, "another-user", "unauthorized-user")
	assert.Error(t, err, "Should error with unauthorized user")
	assert.ErrorIs(t, err, ErrPermissionDenied, "Should return ErrPermissionDenied")

	// Test adding to nonexistent registry
	err = store.AddUserToCredential(ctx, "nonexistent.registry.com", allowedUser, user)
	assert.Error(t, err, "Should error with nonexistent registry")
	assert.ErrorIs(t, err, ErrCredentialsNotFound, "Should return ErrCredentialsNotFound")

	// Test admin can add allowed user
	err = store.AddUserToCredential(ctx, testRegistry, "admin-added-user", "admin")
	assert.NoError(t, err, "Admin should be able to add allowed user")

	// Verify admin-added user has access
	_, err = store.Get(ctx, testRegistry, "admin-added-user")
	assert.NoError(t, err, "Admin-added user should have access")
}

func TestFileCredentialStore_RemoveUserFromCredential(t *testing.T) {
	store, tempDir := setupTestCredentialStore(t)
	defer cleanupTestCredentialStore(tempDir)

	ctx := context.Background()
	testRegistry := "test.registry.com"
	user := "testuser"
	allowedUser := "alloweduser"

	// Add test credentials
	creds := Credentials{
		Username: "user1",
		Password: "pass1",
		Email:    "user1@example.com",
		AuthType: AuthTypeBasic,
	}

	err := store.Add(ctx, testRegistry, creds, user)
	require.NoError(t, err, "Failed to add test credentials")

	// Add allowed user
	err = store.AddUserToCredential(ctx, testRegistry, allowedUser, user)
	require.NoError(t, err, "Failed to add allowed user")

	// Test removing allowed user
	err = store.RemoveUserFromCredential(ctx, testRegistry, allowedUser, user)
	assert.NoError(t, err, "Should remove user without error")

	// Verify allowed user no longer has access
	_, err = store.Get(ctx, testRegistry, allowedUser)
	assert.Error(t, err, "Allowed user should no longer have access")
	assert.ErrorIs(t, err, ErrPermissionDenied, "Should return ErrPermissionDenied")

	// Test unauthorized user cannot remove allowed user
	err = store.AddUserToCredential(ctx, testRegistry, allowedUser, user)
	require.NoError(t, err, "Failed to add allowed user")

	err = store.RemoveUserFromCredential(ctx, testRegistry, allowedUser, "unauthorized-user")
	assert.Error(t, err, "Should error with unauthorized user")
	assert.ErrorIs(t, err, ErrPermissionDenied, "Should return ErrPermissionDenied")

	// Test removing from nonexistent registry
	err = store.RemoveUserFromCredential(ctx, "nonexistent.registry.com", allowedUser, user)
	assert.Error(t, err, "Should error with nonexistent registry")
	assert.ErrorIs(t, err, ErrCredentialsNotFound, "Should return ErrCredentialsNotFound")

	// Test cannot remove owner
	err = store.RemoveUserFromCredential(ctx, testRegistry, user, "admin")
	assert.Error(t, err, "Should error when trying to remove owner")

	// Test admin can remove allowed user
	err = store.RemoveUserFromCredential(ctx, testRegistry, allowedUser, "admin")
	assert.NoError(t, err, "Admin should be able to remove allowed user")
}

func TestFileCredentialStore_SetOwner(t *testing.T) {
	store, tempDir := setupTestCredentialStore(t)
	defer cleanupTestCredentialStore(tempDir)

	ctx := context.Background()
	testRegistry := "test.registry.com"
	user := "testuser"
	newOwner := "newowner"

	// Add test credentials
	creds := Credentials{
		Username: "user1",
		Password: "pass1",
		Email:    "user1@example.com",
		AuthType: AuthTypeBasic,
	}

	err := store.Add(ctx, testRegistry, creds, user)
	require.NoError(t, err, "Failed to add test credentials")

	// Test changing owner
	err = store.SetOwner(ctx, testRegistry, newOwner, user)
	assert.NoError(t, err, "Should change owner without error")

	// Verify new owner has access
	retrieved, err := store.Get(ctx, testRegistry, newOwner)
	assert.NoError(t, err, "New owner should have access")
	assert.Equal(t, newOwner, retrieved.Owner, "Owner should be updated")

	// Verify old owner no longer has write access
	newCreds := Credentials{
		Username: "newuser",
		Password: "newpass",
		Email:    "newuser@example.com",
		AuthType: AuthTypeBasic,
	}
	err = store.Add(ctx, testRegistry, newCreds, user)
	assert.Error(t, err, "Old owner should no longer have write access")
	assert.ErrorIs(t, err, ErrPermissionDenied, "Should return ErrPermissionDenied")

	// Test unauthorized user cannot change owner
	err = store.SetOwner(ctx, testRegistry, user, "unauthorized-user")
	assert.Error(t, err, "Should error with unauthorized user")
	assert.ErrorIs(t, err, ErrPermissionDenied, "Should return ErrPermissionDenied")

	// Test changing owner of nonexistent registry
	err = store.SetOwner(ctx, "nonexistent.registry.com", newOwner, user)
	assert.Error(t, err, "Should error with nonexistent registry")
	assert.ErrorIs(t, err, ErrCredentialsNotFound, "Should return ErrCredentialsNotFound")

	// Test admin can change owner
	err = store.SetOwner(ctx, testRegistry, user, "admin")
	assert.NoError(t, err, "Admin should be able to change owner")

	// Verify admin change
	retrieved, err = store.Get(ctx, testRegistry, user)
	assert.NoError(t, err, "User should have access after admin change")
	assert.Equal(t, user, retrieved.Owner, "Owner should be updated by admin")
}

func TestNormalizeRegistryURL(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"docker_test.io", "registry.hub.docker_test.com"},
		{"index.docker_test.io", "registry.hub.docker_test.com"},
		{"https://docker.io", "registry.hub.docker_test.com"},
		{"https://registry.example.com", "registry.example.com"},
		{"registry.example.com/", "registry.example.com"},
		{"http://registry.example.com:5000", "registry.example.com:5000"},
		{"localhost:5000", "localhost:5000"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			output := normalizeRegistryURL(tc.input)
			assert.Equal(t, tc.expected, output, "Normalized URL should match expected")
		})
	}
}

func TestValidateRegistryURL(t *testing.T) {
	testCases := []struct {
		input       string
		shouldError bool
	}{
		{"", true},
		{"docker_test.io", false},
		{"registry.hub.docker_test.com", false},
		{"localhost:5000", false},
		{"https://registry.example.com", false},
		{"http://registry.example.com:5000", false},
		{"ht tp://invalid", true},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			err := validateRegistryURL(tc.input)
			if tc.shouldError {
				assert.Error(t, err, "Should error with invalid URL")
			} else {
				assert.NoError(t, err, "Should not error with valid URL")
			}
		})
	}
}

func TestBase64EncodeDecode(t *testing.T) {
	username := "testuser"
	password := "testpass"

	// Test encoding
	encoded := Base64EncodeAuth(username, password)
	assert.NotEmpty(t, encoded, "Encoded auth should not be empty")

	// Test decoding
	decodedUser, decodedPass, err := Base64DecodeAuth(encoded)
	assert.NoError(t, err, "Should decode without error")
	assert.Equal(t, username, decodedUser, "Decoded username should match")
	assert.Equal(t, password, decodedPass, "Decoded password should match")

	// Test invalid encoding
	_, _, err = Base64DecodeAuth("invalid-base64")
	assert.Error(t, err, "Should error with invalid base64")

	// Test invalid format
	_, _, err = Base64DecodeAuth(Base64EncodeAuth("noseparator", ""))
	assert.Error(t, err, "Should error with invalid format")
}

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32-byte key
	data := []byte("sensitive data to encrypt")

	// Test encryption
	encrypted, err := encrypt(data, key)
	assert.NoError(t, err, "Should encrypt without error")
	assert.NotEqual(t, data, encrypted, "Encrypted data should be different from original")

	// Test decryption
	decrypted, err := decrypt(encrypted, key)
	assert.NoError(t, err, "Should decrypt without error")
	assert.Equal(t, data, decrypted, "Decrypted data should match original")

	// Test decryption with wrong key
	wrongKey := []byte("0123456789abcdef0123456789abcdee") // Different key
	_, err = decrypt(encrypted, wrongKey)
	assert.Error(t, err, "Should error with wrong key")

	// Test decryption with invalid data
	_, err = decrypt([]byte("invalid-data"), key)
	assert.Error(t, err, "Should error with invalid data")
}

func TestFileCredentialStore_Integration(t *testing.T) {
	store, tempDir := setupTestCredentialStore(t)
	defer cleanupTestCredentialStore(tempDir)

	ctx := context.Background()
	testRegistry := "test.registry.com"
	user := "testuser"

	// Step 1: Add credentials
	creds := Credentials{
		Username: "user1",
		Password: "pass1",
		Email:    "user1@example.com",
		AuthType: AuthTypeBasic,
	}

	err := store.Add(ctx, testRegistry, creds, user)
	require.NoError(t, err, "Failed to add test credentials")

	// Step 2: Get credentials
	retrieved, err := store.Get(ctx, testRegistry, user)
	assert.NoError(t, err, "Should get credentials without error")
	assert.Equal(t, creds.Username, retrieved.Username, "Username should match")

	// Step 3: List credentials
	list, err := store.List(ctx, user)
	assert.NoError(t, err, "Should list credentials without error")
	assert.Len(t, list, 1, "Should list one registry")

	// Step 4: Add an allowed user
	allowedUser := "alloweduser"
	err = store.AddUserToCredential(ctx, testRegistry, allowedUser, user)
	assert.NoError(t, err, "Should add allowed user without error")

	// Step 5: Verify allowed user can access
	_, err = store.Get(ctx, testRegistry, allowedUser)
	assert.NoError(t, err, "Allowed user should have access")

	// Step 6: Get auth config
	authConfig, err := store.GetAuthConfig(ctx, testRegistry, user)
	assert.NoError(t, err, "Should get auth config without error")
	assert.Equal(t, creds.Username, authConfig.Username, "Username should match")
	assert.Equal(t, creds.Password, authConfig.Password, "Password should match")

	// Step 7: Change owner
	newOwner := "newowner"
	err = store.SetOwner(ctx, testRegistry, newOwner, user)
	assert.NoError(t, err, "Should change owner without error")

	// Step 8: Verify new owner has access
	_, err = store.Get(ctx, testRegistry, newOwner)
	assert.NoError(t, err, "New owner should have access")

	// Step 9: Verify old owner no longer has admin access
	err = store.Remove(ctx, testRegistry, user)
	assert.Error(t, err, "Old owner should no longer have admin access")

	// Step 10: Admin can still access everything
	_, err = store.Get(ctx, testRegistry, "admin")
	assert.NoError(t, err, "Admin should have access")

	// Step 11: Admin can remove the registry
	err = store.Remove(ctx, testRegistry, "admin")
	assert.NoError(t, err, "Admin should be able to remove registry")

	// Step 12: Verify registry is gone
	_, err = store.Get(ctx, testRegistry, newOwner)
	assert.Error(t, err, "Registry should be gone")
	assert.ErrorIs(t, err, ErrCredentialsNotFound, "Should return ErrCredentialsNotFound")
}
