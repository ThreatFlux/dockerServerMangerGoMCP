// Package registry provides functionality for managing Docker registries and credentials.
package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	// types "github.com/docker_test/docker_test/api/types" // Removed unused import
	imagetypes "github.com/docker/docker/api/types/image"
	registrytypes "github.com/docker/docker/api/types/registry" // AuthConfig is here
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
)

// Integration handles interactions with the Docker client for registry operations.
type Integration struct {
	client client.APIClient
	logger *logrus.Logger
}

// NewIntegration creates a new Integration instance.
func NewIntegration(client client.APIClient, logger *logrus.Logger) *Integration {
	if logger == nil {
		logger = logrus.New() // Create a default logger if none provided
	}
	return &Integration{
		client: client,
		logger: logger,
	}
}

// Authenticate attempts to authenticate with a registry using provided credentials.
func (i *Integration) Authenticate(ctx context.Context, registry, username, password string) (string, error) {
	i.logger.WithField("registry", registry).Info("Attempting registry authentication")

	authConfig := registrytypes.AuthConfig{ // Use registrytypes.AuthConfig
		Username:      username,
		Password:      password,
		ServerAddress: registry,
	}

	status, err := i.client.RegistryLogin(ctx, authConfig)
	if err != nil {
		i.logger.WithError(err).Error("Registry login failed")
		return "", fmt.Errorf("registry login failed: %w", err)
	}

	i.logger.WithField("registry", registry).Info("Registry authentication successful")
	return status.Status, nil
}

// PullImage pulls an image from a registry.
func (i *Integration) PullImage(ctx context.Context, imageName string, authConfig *registrytypes.AuthConfig) (io.ReadCloser, error) { // Use *registrytypes.AuthConfig
	i.logger.WithField("image", imageName).Info("Pulling image")

	var encodedAuth string
	var err error
	if authConfig != nil {
		encodedAuth, err = EncodeAuthConfig(*authConfig) // Use helper
		if err != nil {
			return nil, fmt.Errorf("failed to encode auth config for pull: %w", err)
		}
	}

	// Use imagetypes.PullOptions
	options := imagetypes.PullOptions{
		RegistryAuth: encodedAuth,
	}

	reader, err := i.client.ImagePull(ctx, imageName, options)
	if err != nil {
		i.logger.WithError(err).WithField("image", imageName).Error("Image pull failed")
		return nil, fmt.Errorf("image pull failed for %s: %w", imageName, err)
	}

	i.logger.WithField("image", imageName).Info("Image pull initiated")
	return reader, nil
}

// PushImage pushes an image to a registry.
func (i *Integration) PushImage(ctx context.Context, imageName string, authConfig registrytypes.AuthConfig) (io.ReadCloser, error) { // Use registrytypes.AuthConfig
	i.logger.WithField("image", imageName).Info("Pushing image")

	encodedAuth, err := EncodeAuthConfig(authConfig) // Use helper
	if err != nil {
		return nil, fmt.Errorf("failed to encode auth config for push: %w", err)
	}

	// Use imagetypes.PushOptions
	options := imagetypes.PushOptions{
		RegistryAuth: encodedAuth,
	}

	reader, err := i.client.ImagePush(ctx, imageName, options)
	if err != nil {
		i.logger.WithError(err).WithField("image", imageName).Error("Image push failed")
		return nil, fmt.Errorf("image push failed for %s: %w", imageName, err)
	}

	i.logger.WithField("image", imageName).Info("Image push initiated")
	return reader, nil
}

// SearchImages searches for images on a registry.
func (i *Integration) SearchImages(ctx context.Context, term string, authConfig *registrytypes.AuthConfig) ([]registrytypes.SearchResult, error) { // Use *registrytypes.AuthConfig
	i.logger.WithField("term", term).Info("Searching images")

	var encodedAuth string
	var err error
	if authConfig != nil {
		encodedAuth, err = EncodeAuthConfig(*authConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to encode auth config for search: %w", err)
		}
	}

	// Use registrytypes.SearchOptions
	options := registrytypes.SearchOptions{ // Changed types.ImageSearchOptions -> registrytypes.SearchOptions
		RegistryAuth: encodedAuth,
		// Add other search options like Filters, Limit if needed
	}

	results, err := i.client.ImageSearch(ctx, term, options)
	if err != nil {
		i.logger.WithError(err).WithField("term", term).Error("Image search failed")
		return nil, fmt.Errorf("image search failed for '%s': %w", term, err)
	}

	i.logger.WithField("term", term).Infof("Image search completed, found %d results", len(results))
	return results, nil
}

// EncodeAuthConfig encodes AuthConfig credentials to a base64 string.
// This function remains here.
func EncodeAuthConfig(authConfig registrytypes.AuthConfig) (string, error) { // Use registrytypes.AuthConfig
	authBytes, err := json.Marshal(authConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth config: %w", err)
	}
	return base64.URLEncoding.EncodeToString(authBytes), nil
}
