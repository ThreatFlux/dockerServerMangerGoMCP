// Package registry provides functionality for managing Docker registries and credentials.
package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	imagetypes "github.com/docker/docker/api/types/image" // Import image types
	registrytypes "github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
)

// DefaultRegistry is the default Docker registry address.
const DefaultRegistry = "docker_test.io"

// CredentialManager manages Docker registry credentials.
type CredentialManager struct {
	configFilePath string
	logger         *logrus.Logger
	store          CredentialStore
}

// CredentialManagerOptions contains options for creating a CredentialManager.
type CredentialManagerOptions struct {
	ConfigFilePath string
	Logger         *logrus.Logger
	Store          CredentialStore
}

// NewCredentialManager creates a new CredentialManager.
func NewCredentialManager(options CredentialManagerOptions) (*CredentialManager, error) {
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}

	configPath := options.ConfigFilePath
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		configPath = filepath.Join(home, ".docker_test", "config.json")
	}

	store := options.Store
	if store == nil {
		fileStore, err := NewFileCredentialStore(FileCredentialStoreOptions{
			StorePath:     configPath,
			Logger:        logger,
			EncryptionKey: os.Getenv("DSM_CREDENTIAL_KEY"),
		})
		if err != nil {
			logger.WithError(err).Error("Failed to create default file credential store")
			if errors.Is(err, ErrInvalidEncryptionKey) {
				return nil, fmt.Errorf("failed to create credential store: %w. Ensure DSM_CREDENTIAL_KEY is set", err)
			}
			return nil, fmt.Errorf("failed to create default file credential store: %w", err)
		}
		store = fileStore
	}

	return &CredentialManager{
		configFilePath: configPath,
		logger:         logger,
		store:          store,
	}, nil
}

// GetAuthConfig retrieves authentication configuration for a specific registry.
func (m *CredentialManager) GetAuthConfig(ctx context.Context, registryAddress string) (registrytypes.AuthConfig, error) {
	m.logger.WithField("registry", registryAddress).Debug("Getting auth config")
	if registryAddress == "" {
		registryAddress = DefaultRegistry
	}
	currentUser := "" // Placeholder

	authConfig, err := m.store.GetAuthConfig(ctx, registryAddress, currentUser)
	if err != nil && !errors.Is(err, ErrCredentialsNotFound) {
		return registrytypes.AuthConfig{}, fmt.Errorf("failed to get auth config from store for %s: %w", registryAddress, err)
	}
	if err == nil {
		m.logger.WithField("registry", registryAddress).Debug("Found credentials in store")
		return authConfig, nil
	}
	m.logger.WithField("registry", registryAddress).Debug("Credentials not found")
	return registrytypes.AuthConfig{}, ErrCredentialsNotFound
}

// SetAuthConfig stores authentication configuration for a specific registry.
func (m *CredentialManager) SetAuthConfig(ctx context.Context, registryAddress string, authConfig registrytypes.AuthConfig) error {
	m.logger.WithField("registry", registryAddress).Info("Setting auth config")
	if registryAddress == "" {
		registryAddress = DefaultRegistry
	}
	creds := Credentials{
		Username:      authConfig.Username,
		Password:      authConfig.Password,
		Auth:          authConfig.Auth,
		ServerAddress: normalizeRegistryURL(registryAddress),
		IdentityToken: authConfig.IdentityToken,
		RegistryToken: authConfig.RegistryToken,
	}
	if (creds.Password != "" || creds.IdentityToken != "") && creds.Username == "" {
		m.logger.Warn("Setting credentials without username, relying on Docker client behavior")
	}
	currentUser := "" // Placeholder
	err := m.store.Add(ctx, registryAddress, creds, currentUser)
	if err != nil {
		return fmt.Errorf("failed to store auth config for %s: %w", registryAddress, err)
	}
	m.logger.WithField("registry", registryAddress).Info("Auth config stored successfully")
	return nil
}

// RemoveAuthConfig removes authentication configuration for a specific registry.
func (m *CredentialManager) RemoveAuthConfig(ctx context.Context, registryAddress string) error {
	m.logger.WithField("registry", registryAddress).Info("Removing auth config")
	if registryAddress == "" {
		registryAddress = DefaultRegistry
	}
	currentUser := "" // Placeholder
	err := m.store.Remove(ctx, registryAddress, currentUser)
	if err != nil && !errors.Is(err, ErrCredentialsNotFound) {
		return fmt.Errorf("failed to remove auth config for %s: %w", registryAddress, err)
	}
	if errors.Is(err, ErrCredentialsNotFound) {
		m.logger.WithField("registry", registryAddress).Warn("Auth config not found, nothing to remove")
		return nil
	}
	m.logger.WithField("registry", registryAddress).Info("Auth config removed successfully")
	return nil
}

// GetAllAuthConfigs retrieves all stored authentication configurations.
func (m *CredentialManager) GetAllAuthConfigs(ctx context.Context) (map[string]registrytypes.AuthConfig, error) {
	m.logger.Debug("Getting all auth configs")
	currentUser := "" // Placeholder
	infos, err := m.store.List(ctx, currentUser)
	if err != nil {
		return nil, fmt.Errorf("failed to get all auth configs: %w", err)
	}
	auths := make(map[string]registrytypes.AuthConfig)
	for _, info := range infos {
		fullCreds, err := m.store.GetAuthConfig(ctx, info.Registry, currentUser)
		if err == nil {
			auths[info.Registry] = fullCreds
		} else {
			m.logger.WithError(err).WithField("registry", info.Registry).Warn("Failed to get full credentials during GetAllAuthConfigs")
			auths[info.Registry] = registrytypes.AuthConfig{
				Username:      info.Username,
				ServerAddress: info.ServerAddress,
			}
		}
	}
	return auths, nil
}

// AuthenticateAndGetClient performs authentication and returns an authenticated Docker client.
func (m *CredentialManager) AuthenticateAndGetClient(ctx context.Context, registryAddress, username, password string) (*client.Client, error) {
	m.logger.WithField("registry", registryAddress).Info("Authenticating and getting client")
	tempCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary Docker client: %w", err)
	}
	defer tempCli.Close()
	integration := NewIntegration(tempCli, m.logger)
	_, err = integration.Authenticate(ctx, registryAddress, username, password)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client after auth: %w", err)
	}
	return cli, nil
}

// GetPullOptions prepares ImagePullOptions with authentication if available.
func (m *CredentialManager) GetPullOptions(ctx context.Context, registry string, user string) (imagetypes.PullOptions, error) { // Use imagetypes.PullOptions
	authConfig, err := m.GetAuthConfig(ctx, registry) // Returns registrytypes.AuthConfig
	if err != nil && !errors.Is(err, ErrCredentialsNotFound) {
		return imagetypes.PullOptions{}, fmt.Errorf("failed to get auth config: %w", err) // Use imagetypes.PullOptions
	}

	encodedAuth := ""
	if err == nil { // Credentials found
		// Use registrytypes.AuthConfig for encoding helper input type
		encodedAuth, err = EncodeAuthConfig(authConfig) // Call function (assuming it's in integration.go)
		if err != nil {
			return imagetypes.PullOptions{}, fmt.Errorf("failed to encode auth config: %w", err) // Use imagetypes.PullOptions
		}
	}

	return imagetypes.PullOptions{ // Use imagetypes.PullOptions
		RegistryAuth: encodedAuth,
	}, nil
}

// GetPushOptions prepares ImagePushOptions with authentication. Requires credentials.
func (m *CredentialManager) GetPushOptions(ctx context.Context, registry string, user string) (imagetypes.PushOptions, error) { // Use imagetypes.PushOptions
	authConfig, err := m.GetAuthConfig(ctx, registry) // Returns registrytypes.AuthConfig
	if err != nil {
		return imagetypes.PushOptions{}, fmt.Errorf("failed to get auth config for push: %w", err) // Use imagetypes.PushOptions
	}

	// Use registrytypes.AuthConfig for encoding helper input type
	encodedAuth, err := EncodeAuthConfig(authConfig) // Call function (assuming it's in integration.go)
	if err != nil {
		return imagetypes.PushOptions{}, fmt.Errorf("failed to encode auth config: %w", err) // Use imagetypes.PushOptions
	}

	return imagetypes.PushOptions{ // Use imagetypes.PushOptions
		RegistryAuth: encodedAuth,
	}, nil
}

// Removed EncodeAuthConfig function from here

// ImageNameComponents holds parsed components of an image name.
// type ImageNameComponents struct { ... } // Commented out

// ParseImageName parses a Docker image name into its components.
// func ParseImageName(name string) (ImageNameComponents, error) { ... } // Commented out
