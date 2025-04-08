package registry

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	// "github.com/docker_test/docker_test/api/types" // Keep if other types are needed, otherwise remove
	registrytypes "github.com/docker/docker/api/types/registry" // Uncommented and aliased
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/pbkdf2"
)

// Common errors
var (
	// ErrCredentialsNotFound indicates that credentials were not found
	ErrCredentialsNotFound = errors.New("registry credentials not found")

	// ErrInvalidRegistry indicates an invalid registry URL
	ErrInvalidRegistry = errors.New("invalid registry URL")

	// ErrEmptyCredentials indicates empty credentials
	ErrEmptyCredentials = errors.New("empty credentials provided")

	// ErrEncryptionFailed indicates that encryption failed
	ErrEncryptionFailed = errors.New("failed to encrypt credentials")

	// ErrDecryptionFailed indicates that decryption failed
	ErrDecryptionFailed = errors.New("failed to decrypt credentials")

	// ErrInvalidCredentials indicates invalid credentials
	ErrInvalidCredentials = errors.New("invalid registry credentials")

	// ErrPermissionDenied indicates insufficient permissions
	ErrPermissionDenied = errors.New("permission denied for registry credentials")

	// ErrStorageFailure indicates a storage failure
	ErrStorageFailure = errors.New("registry credential storage failure")

	// ErrInvalidEncryptionKey indicates an invalid encryption key
	ErrInvalidEncryptionKey = errors.New("invalid or missing encryption key")
)

// AuthType represents the type of authentication
type AuthType string

const (
	// AuthTypeBasic represents basic authentication
	AuthTypeBasic AuthType = "basic"

	// AuthTypeToken represents token authentication
	AuthTypeToken AuthType = "token"

	// AuthTypeIdentityToken represents identity token authentication
	AuthTypeIdentityToken AuthType = "identity_token"

	// AuthTypeNone represents no authentication
	AuthTypeNone AuthType = "none"
)

// Credentials represents Docker registry credentials
type Credentials struct {
	// Username is the registry username
	Username string `json:"username,omitempty"`

	// Password is the registry password (sensitive)
	Password string `json:"password,omitempty"`

	// Email is the email associated with the registry account
	Email string `json:"email,omitempty"`

	// ServerAddress is the registry server address
	ServerAddress string `json:"server_address,omitempty"`

	// IdentityToken is the registry identity token (sensitive)
	IdentityToken string `json:"identity_token,omitempty"`

	// RegistryToken is the registry token (sensitive)
	RegistryToken string `json:"registry_token,omitempty"`

	// Auth is the base64-encoded auth string (sensitive)
	Auth string `json:"auth,omitempty"`

	// AuthType is the authentication type
	AuthType AuthType `json:"auth_type,omitempty"`

	// CreatedAt is when the credentials were created
	CreatedAt time.Time `json:"created_at,omitempty"`

	// UpdatedAt is when the credentials were last updated
	UpdatedAt time.Time `json:"updated_at,omitempty"`

	// LastUsed is when the credentials were last used
	LastUsed time.Time `json:"last_used,omitempty"`

	// Owner is the user who owns these credentials
	Owner string `json:"owner,omitempty"`

	// AllowedUsers are additional users allowed to use these credentials
	AllowedUsers []string `json:"allowed_users,omitempty"`
}

// RegistryInfo represents non-sensitive registry information
type RegistryInfo struct {
	// Registry is the registry URL
	Registry string `json:"registry"`

	// Username is the registry username
	Username string `json:"username,omitempty"`

	// Email is the email associated with the registry account
	Email string `json:"email,omitempty"`

	// ServerAddress is the registry server address
	ServerAddress string `json:"server_address,omitempty"`

	// AuthType is the authentication type
	AuthType AuthType `json:"auth_type"`

	// CreatedAt is when the credentials were created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the credentials were last updated
	UpdatedAt time.Time `json:"updated_at"`

	// LastUsed is when the credentials were last used
	LastUsed time.Time `json:"last_used,omitempty"`

	// Owner is the user who owns these credentials
	Owner string `json:"owner,omitempty"`

	// AllowedUsers are additional users allowed to use these credentials
	AllowedUsers []string `json:"allowed_users,omitempty"`
}

// CredentialStore is the interface for storing and retrieving Docker registry credentials
type CredentialStore interface {
	// Add adds or updates credentials for a registry
	Add(ctx context.Context, registry string, creds Credentials, currentUser string) error

	// Get retrieves credentials for a registry
	Get(ctx context.Context, registry string, currentUser string) (Credentials, error)

	// Remove removes credentials for a registry
	Remove(ctx context.Context, registry string, currentUser string) error

	// List lists all available credentials (without sensitive info)
	List(ctx context.Context, currentUser string) ([]RegistryInfo, error)

	// Validate validates credentials for a registry
	Validate(ctx context.Context, registry string, creds Credentials) (bool, error)

	// GetAuthConfig retrieves credentials in Docker auth config format
	GetAuthConfig(ctx context.Context, registry string, currentUser string) (registrytypes.AuthConfig, error) // Use registrytypes.AuthConfig

	// AddUserToCredential adds a user to the allowed users for a registry
	AddUserToCredential(ctx context.Context, registry string, user string, currentUser string) error

	// RemoveUserFromCredential removes a user from the allowed users for a registry
	RemoveUserFromCredential(ctx context.Context, registry string, user string, currentUser string) error

	// SetOwner changes the owner of a registry credential
	SetOwner(ctx context.Context, registry string, newOwner string, currentUser string) error
}

// FileCredentialStore implements CredentialStore using a file-based storage
type FileCredentialStore struct {
	// storePath is the path to the credentials storage file
	storePath string

	// encryptionKey is the key used for encryption
	encryptionKey []byte

	// logger is the logger to use
	logger *logrus.Logger

	// mu is a mutex for thread safety
	mu sync.RWMutex

	// credentials is the in-memory cache of credentials
	credentials map[string]Credentials

	// initialized indicates whether the store has been initialized
	initialized bool

	// adminUsers are users with admin privileges
	adminUsers []string
}

// FileCredentialStoreOptions contains options for FileCredentialStore
type FileCredentialStoreOptions struct {
	// StorePath is the path to the credentials storage file
	StorePath string

	// EncryptionKey is the key used for encryption
	EncryptionKey string

	// Logger is the logger to use
	Logger *logrus.Logger

	// AdminUsers are users with admin privileges
	AdminUsers []string
}

// NewFileCredentialStore creates a new file-based credential store
func NewFileCredentialStore(options FileCredentialStoreOptions) (*FileCredentialStore, error) {
	if options.StorePath == "" {
		return nil, fmt.Errorf("empty storage path")
	}

	if options.EncryptionKey == "" {
		return nil, ErrInvalidEncryptionKey
	}

	if options.Logger == nil {
		options.Logger = logrus.New()
	}

	// Create the store directory if it doesn't exist
	storeDir := filepath.Dir(options.StorePath)
	if err := os.MkdirAll(storeDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}

	// Derive encryption key using PBKDF2
	salt := []byte("docker_test-registry-credentials-salt")
	key := pbkdf2.Key([]byte(options.EncryptionKey), salt, 4096, 32, sha256.New)

	store := &FileCredentialStore{
		storePath:     options.StorePath,
		encryptionKey: key,
		logger:        options.Logger,
		credentials:   make(map[string]Credentials),
		adminUsers:    options.AdminUsers,
	}

	// Load existing credentials
	if err := store.load(); err != nil {
		// If the file doesn't exist, that's ok
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load credentials: %w", err)
		}
	}

	store.initialized = true
	store.logger.Debug("File credential store initialized")

	return store, nil
}

// Add adds or updates credentials for a registry
func (s *FileCredentialStore) Add(ctx context.Context, registry string, creds Credentials, currentUser string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate registry URL
	if err := validateRegistryURL(registry); err != nil {
		return err
	}

	// Validate credentials
	if err := validateCredentials(creds); err != nil {
		return err
	}

	// Normalize registry URL
	normalizedRegistry := normalizeRegistryURL(registry)

	// Check for existing credentials
	existing, exists := s.credentials[normalizedRegistry]
	if exists {
		// Check permissions
		if !s.hasWriteAccess(existing, currentUser) {
			return ErrPermissionDenied
		}

		// Keep existing owner and allowed users
		creds.Owner = existing.Owner
		creds.AllowedUsers = existing.AllowedUsers
		creds.CreatedAt = existing.CreatedAt
	} else {
		// Set current user as owner
		creds.Owner = currentUser
		creds.CreatedAt = time.Now().UTC()
	}

	// Update timestamps
	creds.UpdatedAt = time.Now().UTC()
	creds.ServerAddress = normalizedRegistry

	// Store the credentials
	s.credentials[normalizedRegistry] = creds

	// Save to disk
	if err := s.save(); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}

	s.logger.WithFields(logrus.Fields{
		"registry":  normalizedRegistry,
		"auth_type": creds.AuthType,
		"username":  creds.Username,
		"user":      currentUser,
		"created":   !exists,
	}).Info("Registry credentials added/updated")

	return nil
}

// Get retrieves credentials for a registry
func (s *FileCredentialStore) Get(ctx context.Context, registry string, currentUser string) (Credentials, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Normalize registry URL
	normalizedRegistry := normalizeRegistryURL(registry)

	// Check for credentials
	creds, exists := s.credentials[normalizedRegistry]
	if !exists {
		return Credentials{}, ErrCredentialsNotFound
	}

	// Check read access
	if !s.hasReadAccess(creds, currentUser) {
		return Credentials{}, ErrPermissionDenied
	}

	// Update last used
	s.updateLastUsed(normalizedRegistry)

	return creds, nil
}

// Remove removes credentials for a registry
func (s *FileCredentialStore) Remove(ctx context.Context, registry string, currentUser string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Normalize registry URL
	normalizedRegistry := normalizeRegistryURL(registry)

	// Check for credentials
	creds, exists := s.credentials[normalizedRegistry]
	if !exists {
		return ErrCredentialsNotFound
	}

	// Check permissions (only owner or admin can remove)
	if !s.hasAdminAccess(creds, currentUser) {
		return ErrPermissionDenied
	}

	// Remove credentials
	delete(s.credentials, normalizedRegistry)

	// Save to disk
	if err := s.save(); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}

	s.logger.WithFields(logrus.Fields{
		"registry": normalizedRegistry,
		"user":     currentUser,
	}).Info("Registry credentials removed")

	return nil
}

// List lists all available credentials (without sensitive info)
func (s *FileCredentialStore) List(ctx context.Context, currentUser string) ([]RegistryInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []RegistryInfo

	for registry, creds := range s.credentials {
		// Check read access
		if !s.hasReadAccess(creds, currentUser) {
			continue
		}

		info := RegistryInfo{
			Registry:      registry,
			Username:      creds.Username,
			Email:         creds.Email,
			ServerAddress: creds.ServerAddress,
			AuthType:      creds.AuthType,
			CreatedAt:     creds.CreatedAt,
			UpdatedAt:     creds.UpdatedAt,
			LastUsed:      creds.LastUsed,
			Owner:         creds.Owner,
			AllowedUsers:  creds.AllowedUsers,
		}

		result = append(result, info)
	}

	return result, nil
}

// Validate validates credentials for a registry
func (s *FileCredentialStore) Validate(ctx context.Context, registry string, creds Credentials) (bool, error) {
	// Normalize registry URL
	normalizedRegistry := normalizeRegistryURL(registry)

	// Create a new HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test authentication with Docker registry
	// Use registrytypes.AuthConfig for the HTTP request part
	authConfig := registrytypes.AuthConfig{ // Use registrytypes.AuthConfig
		Username:      creds.Username,
		Password:      creds.Password,
		Auth:          creds.Auth,
		ServerAddress: normalizedRegistry,
		IdentityToken: creds.IdentityToken,
		RegistryToken: creds.RegistryToken,
	}

	// Determine registry auth URL
	var authURL string
	if strings.HasPrefix(normalizedRegistry, "https://") || strings.HasPrefix(normalizedRegistry, "http://") {
		authURL = normalizedRegistry
	} else {
		authURL = "https://" + normalizedRegistry
	}

	// Add /v2/ suffix if needed
	if !strings.HasSuffix(authURL, "/v2/") {
		authURL = strings.TrimSuffix(authURL, "/") + "/v2/"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", authURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	// Add auth header
	req.Header.Set("User-Agent", "Docker-Server-Manager-Go/1.0")

	// Add basic auth if username/password provided
	if authConfig.Username != "" && authConfig.Password != "" { // Use authConfig fields
		req.SetBasicAuth(authConfig.Username, authConfig.Password)
	}

	// Add auth token if provided
	if authConfig.RegistryToken != "" { // Use authConfig fields
		req.Header.Set("Authorization", "Bearer "+authConfig.RegistryToken)
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
		// Auth success
		return true, nil
	case http.StatusUnauthorized:
		// Auth failure
		return false, nil
	default:
		// Other error
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("unexpected response: %d %s - %s", resp.StatusCode, resp.Status, string(body))
	}
}

// GetAuthConfig retrieves credentials in Docker auth config format
func (s *FileCredentialStore) GetAuthConfig(ctx context.Context, registry string, currentUser string) (registrytypes.AuthConfig, error) { // Use registrytypes.AuthConfig
	creds, err := s.Get(ctx, registry, currentUser)
	if err != nil {
		return registrytypes.AuthConfig{}, err // Use registrytypes.AuthConfig
	}

	// Convert to Docker auth config
	authConfig := registrytypes.AuthConfig{ // Use registrytypes.AuthConfig
		Username:      creds.Username,
		Password:      creds.Password,
		Auth:          creds.Auth,
		ServerAddress: creds.ServerAddress,
		IdentityToken: creds.IdentityToken,
		RegistryToken: creds.RegistryToken,
	}

	return authConfig, nil
}

// AddUserToCredential adds a user to the allowed users for a registry
func (s *FileCredentialStore) AddUserToCredential(ctx context.Context, registry string, user string, currentUser string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Normalize registry URL
	normalizedRegistry := normalizeRegistryURL(registry)

	// Check for credentials
	creds, exists := s.credentials[normalizedRegistry]
	if !exists {
		return ErrCredentialsNotFound
	}

	// Check permissions (only owner or admin can add users)
	if !s.hasAdminAccess(creds, currentUser) {
		return ErrPermissionDenied
	}

	// Check if user already exists
	for _, u := range creds.AllowedUsers {
		if u == user {
			return nil // User already has access
		}
	}

	// Add user
	creds.AllowedUsers = append(creds.AllowedUsers, user)
	creds.UpdatedAt = time.Now().UTC()

	// Store updated credentials
	s.credentials[normalizedRegistry] = creds

	// Save to disk
	if err := s.save(); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}

	s.logger.WithFields(logrus.Fields{
		"registry": normalizedRegistry,
		"user":     user,
		"by_user":  currentUser,
	}).Info("User added to registry credentials")

	return nil
}

// RemoveUserFromCredential removes a user from the allowed users for a registry
func (s *FileCredentialStore) RemoveUserFromCredential(ctx context.Context, registry string, user string, currentUser string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Normalize registry URL
	normalizedRegistry := normalizeRegistryURL(registry)

	// Check for credentials
	creds, exists := s.credentials[normalizedRegistry]
	if !exists {
		return ErrCredentialsNotFound
	}

	// Check permissions (only owner or admin can remove users)
	if !s.hasAdminAccess(creds, currentUser) {
		return ErrPermissionDenied
	}

	// Don't allow removing the owner
	if creds.Owner == user {
		return fmt.Errorf("cannot remove the owner")
	}

	// Remove user
	var newAllowedUsers []string
	for _, u := range creds.AllowedUsers {
		if u != user {
			newAllowedUsers = append(newAllowedUsers, u)
		}
	}

	// Update credentials
	creds.AllowedUsers = newAllowedUsers
	creds.UpdatedAt = time.Now().UTC()

	// Store updated credentials
	s.credentials[normalizedRegistry] = creds

	// Save to disk
	if err := s.save(); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}

	s.logger.WithFields(logrus.Fields{
		"registry": normalizedRegistry,
		"user":     user,
		"by_user":  currentUser,
	}).Info("User removed from registry credentials")

	return nil
}

// SetOwner changes the owner of a registry credential
func (s *FileCredentialStore) SetOwner(ctx context.Context, registry string, newOwner string, currentUser string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Normalize registry URL
	normalizedRegistry := normalizeRegistryURL(registry)

	// Check for credentials
	creds, exists := s.credentials[normalizedRegistry]
	if !exists {
		return ErrCredentialsNotFound
	}

	// Check permissions (only owner or admin can change owner)
	if !s.hasAdminAccess(creds, currentUser) {
		return ErrPermissionDenied
	}

	// Update owner
	oldOwner := creds.Owner // Store old owner for logging
	creds.Owner = newOwner
	creds.UpdatedAt = time.Now().UTC()

	// Store updated credentials
	s.credentials[normalizedRegistry] = creds

	// Save to disk
	if err := s.save(); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}

	s.logger.WithFields(logrus.Fields{
		"registry":  normalizedRegistry,
		"old_owner": oldOwner,
		"new_owner": newOwner,
		"by_user":   currentUser,
	}).Info("Registry credentials owner changed")

	return nil
}

// load loads credentials from disk
func (s *FileCredentialStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if the file exists
	if _, err := os.Stat(s.storePath); os.IsNotExist(err) {
		// File doesn't exist, initialize empty credentials
		s.credentials = make(map[string]Credentials)
		return nil
	}

	// Read file
	data, err := os.ReadFile(s.storePath)
	if err != nil {
		return fmt.Errorf("failed to read credentials file: %w", err)
	}

	// Decrypt data
	decrypted, err := decrypt(data, s.encryptionKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Unmarshal credentials
	var creds map[string]Credentials
	if err := json.Unmarshal(decrypted, &creds); err != nil {
		return fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	s.credentials = creds
	return nil
}

// save saves credentials to disk
func (s *FileCredentialStore) save() error {
	// Marshal credentials
	data, err := json.MarshalIndent(s.credentials, "", "  ") // Use MarshalIndent for readability
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Encrypt data
	encrypted, err := encrypt(data, s.encryptionKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Create a temporary file in the same directory
	dir := filepath.Dir(s.storePath)
	tempFile, err := os.CreateTemp(dir, "creds-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tempFilePath := tempFile.Name()

	// Write data to temporary file
	if _, err := tempFile.Write(encrypted); err != nil {
		tempFile.Close()
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}

	// Close temporary file
	if err := tempFile.Close(); err != nil {
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Set file permissions (0600 - owner read/write only)
	if err := os.Chmod(tempFilePath, 0600); err != nil {
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	// Rename temporary file to target file (atomic operation)
	if err := os.Rename(tempFilePath, s.storePath); err != nil {
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}

	return nil
}

// updateLastUsed updates the last used timestamp for a registry
func (s *FileCredentialStore) updateLastUsed(registry string) {
	// Update in-memory cache
	if creds, exists := s.credentials[registry]; exists {
		creds.LastUsed = time.Now().UTC()
		s.credentials[registry] = creds

		// Schedule async save
		go func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if err := s.save(); err != nil {
				s.logger.WithError(err).Error("Failed to save credentials after updating last used timestamp")
			}
		}()
	}
}

// hasReadAccess checks if a user has read access to credentials
func (s *FileCredentialStore) hasReadAccess(creds Credentials, user string) bool {
	// Admin users always have access
	if s.isAdmin(user) {
		return true
	}

	// Owner has access
	if creds.Owner == user {
		return true
	}

	// Check allowed users
	for _, u := range creds.AllowedUsers {
		if u == user {
			return true
		}
	}

	return false
}

// hasWriteAccess checks if a user has write access to credentials
func (s *FileCredentialStore) hasWriteAccess(creds Credentials, user string) bool {
	// Admin users always have access
	if s.isAdmin(user) {
		return true
	}

	// Only owner has write access
	return creds.Owner == user
}

// hasAdminAccess checks if a user has admin access to credentials
func (s *FileCredentialStore) hasAdminAccess(creds Credentials, user string) bool {
	// Admin users always have access
	if s.isAdmin(user) {
		return true
	}

	// Only owner has admin access
	return creds.Owner == user
}

// isAdmin checks if a user is an admin
func (s *FileCredentialStore) isAdmin(user string) bool {
	for _, admin := range s.adminUsers {
		if admin == user {
			return true
		}
	}
	return false
}

// validateRegistryURL validates a registry URL
func validateRegistryURL(registry string) error {
	if registry == "" {
		return fmt.Errorf("%w: empty registry URL", ErrInvalidRegistry)
	}

	// Handle special case for Docker Hub
	if registry == "docker_test.io" || registry == "registry.hub.docker_test.com" {
		return nil
	}

	// Check if it's a hostname without protocol
	if !strings.Contains(registry, "://") {
		// Assume https if no protocol specified
		// Check if hostname is valid
		if _, err := net.LookupHost(registry); err != nil {
			// Could be a local registry or one without DNS, allow for now
			// More robust validation might involve trying to connect
		}
		return nil
	}

	// Parse URL
	parsedURL, err := url.Parse(registry)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRegistry, err)
	}

	// Check for valid scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("%w: invalid scheme %s", ErrInvalidRegistry, parsedURL.Scheme)
	}

	return nil
}

// normalizeRegistryURL normalizes a registry URL
func normalizeRegistryURL(registry string) string {
	// Handle special case for Docker Hub
	if registry == "docker_test.io" || registry == "index.docker_test.io" {
		return "registry.hub.docker_test.com"
	}

	// Remove trailing slashes
	registry = strings.TrimRight(registry, "/")

	// Remove protocol if present
	if strings.Contains(registry, "://") {
		parts := strings.SplitN(registry, "://", 2)
		registry = parts[1]
	}

	return registry
}

// validateCredentials validates credentials
func validateCredentials(creds Credentials) error {
	// At least one authentication method must be provided
	if creds.Username == "" && creds.IdentityToken == "" && creds.RegistryToken == "" && creds.Auth == "" {
		return fmt.Errorf("%w: no authentication method provided", ErrEmptyCredentials)
	}

	// If username is provided, password should also be provided (unless Auth is set)
	if creds.Username != "" && creds.Password == "" && creds.Auth == "" {
		return fmt.Errorf("%w: username provided without password or auth string", ErrInvalidCredentials)
	}

	// Set auth type based on provided credentials
	if creds.AuthType == "" {
		if creds.IdentityToken != "" {
			creds.AuthType = AuthTypeIdentityToken
		} else if creds.RegistryToken != "" {
			creds.AuthType = AuthTypeToken
		} else if creds.Username != "" {
			creds.AuthType = AuthTypeBasic
		} else {
			creds.AuthType = AuthTypeNone
		}
	}

	return nil
}

// encrypt encrypts data using AES-GCM
func encrypt(data []byte, key []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Return the encrypted data
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM
func decrypt(data []byte, key []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract the nonce
	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GetConfigDir returns the default config directory
func GetConfigDir() (string, error) {
	configDir := os.Getenv("DOCKER_CONFIG")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not detect user's home directory: %w", err)
		}
		configDir = filepath.Join(home, ".docker_test")
	}
	return configDir, nil
}

// Base64EncodeAuth encodes username and password in the format used by Docker config
func Base64EncodeAuth(username, password string) string {
	authString := username + ":" + password
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))
	return encoded
}

// Base64DecodeAuth decodes a base64-encoded auth string
func Base64DecodeAuth(encodedAuth string) (username, password string, err error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedAuth)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode auth: %w", err)
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid auth format")
	}

	return parts[0], parts[1], nil
}
