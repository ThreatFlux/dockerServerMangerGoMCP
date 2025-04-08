// Package resources provides functionality for managing Docker Compose resources
package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/network"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/volume"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// Manager is responsible for managing resources for Docker Compose deployments
type Manager struct {
	networkService network.Service
	volumeService  volume.Service
	logger         *logrus.Logger
}

// ManagerOptions defines options for the resource manager
type ManagerOptions struct {
	// Logger is the logger to use
	Logger *logrus.Logger

	// DefaultTimeout is the default timeout for operations
	DefaultTimeout time.Duration
}

// NewManager creates a new resource manager
func NewManager(networkSvc network.Service, volumeSvc volume.Service, options ManagerOptions) *Manager {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}

	return &Manager{
		networkService: networkSvc,
		volumeService:  volumeSvc,
		logger:         logger,
	}
}

// CreateResources creates the networks and volumes for a Docker Compose file
func (m *Manager) CreateResources(ctx context.Context, composeFile *models.ComposeFile, options CreateResourcesOptions) error {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Create networks
	logger.Info("Creating networks for Docker Compose deployment")
	if err := m.createComposeNetworks(ctx, composeFile, options); err != nil {
		return fmt.Errorf("failed to create networks: %w", err)
	}

	// Create volumes
	logger.Info("Creating volumes for Docker Compose deployment")
	if err := m.createComposeVolumes(ctx, composeFile, options); err != nil {
		return fmt.Errorf("failed to create volumes: %w", err)
	}

	return nil
}

// RemoveResources removes the networks and volumes for a Docker Compose file
func (m *Manager) RemoveResources(ctx context.Context, composeFile *models.ComposeFile, options RemoveResourcesOptions) error {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Track errors to remove as many resources as possible even if some fail
	var errs []error

	// Remove networks if requested
	if !options.KeepNetworks {
		logger.Info("Removing networks for Docker Compose deployment")
		if err := m.removeComposeNetworks(ctx, composeFile, options); err != nil {
			logger.WithError(err).Error("Failed to remove all networks")
			errs = append(errs, err)
		}
	}

	// Remove volumes if requested
	if !options.KeepVolumes {
		logger.Info("Removing volumes for Docker Compose deployment")
		if err := m.removeComposeVolumes(ctx, composeFile, options); err != nil {
			logger.WithError(err).Error("Failed to remove all volumes")
			errs = append(errs, err)
		}
	}

	// Return the first error if any occurred
	if len(errs) > 0 {
		return errs[0]
	}

	return nil
}

// ListResources lists the resources for a Docker Compose file
func (m *Manager) ListResources(ctx context.Context, composeFile *models.ComposeFile, options ListResourcesOptions) (*ResourceList, error) {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Create result structure
	result := &ResourceList{
		Networks: make([]*models.Network, 0),
		Volumes:  make([]*models.Volume, 0),
	}

	// List networks
	if !options.ExcludeNetworks {
		logger.Info("Listing networks for Docker Compose deployment")
		networks, err := m.listComposeNetworks(ctx, composeFile, options)
		if err != nil {
			return nil, fmt.Errorf("failed to list networks: %w", err)
		}
		result.Networks = networks
	}

	// List volumes
	if !options.ExcludeVolumes {
		logger.Info("Listing volumes for Docker Compose deployment")
		volumes, err := m.listComposeVolumes(ctx, composeFile, options)
		if err != nil {
			return nil, fmt.Errorf("failed to list volumes: %w", err)
		}
		result.Volumes = volumes
	}

	return result, nil
}

// CreateResourcesOptions defines options for creating resources
type CreateResourcesOptions struct {
	// ProjectName is the name of the Docker Compose project
	ProjectName string

	// Timeout is the operation timeout
	Timeout time.Duration

	// NamePrefix is the prefix to use for resource names
	NamePrefix string

	// SkipExistingNetworks indicates whether to skip creation of existing networks
	SkipExistingNetworks bool

	// SkipExistingVolumes indicates whether to skip creation of existing volumes
	SkipExistingVolumes bool

	// Labels are the labels to add to all resources
	Labels map[string]string

	// Logger is the logger to use
	Logger *logrus.Logger
}

// RemoveResourcesOptions defines options for removing resources
type RemoveResourcesOptions struct {
	// ProjectName is the name of the Docker Compose project
	ProjectName string

	// Timeout is the operation timeout
	Timeout time.Duration

	// NamePrefix is the prefix to use for resource names
	NamePrefix string

	// Force indicates whether to force removal of resources
	Force bool

	// KeepNetworks indicates whether to keep networks
	KeepNetworks bool

	// KeepVolumes indicates whether to keep volumes
	KeepVolumes bool

	// RemoveExternalResources indicates whether to remove external resources
	RemoveExternalResources bool

	// Logger is the logger to use
	Logger *logrus.Logger
}

// ListResourcesOptions defines options for listing resources
type ListResourcesOptions struct {
	// ProjectName is the name of the Docker Compose project
	ProjectName string

	// Timeout is the operation timeout
	Timeout time.Duration

	// NamePrefix is the prefix to use for resource names
	NamePrefix string

	// ExcludeNetworks indicates whether to exclude networks
	ExcludeNetworks bool

	// ExcludeVolumes indicates whether to exclude volumes
	ExcludeVolumes bool

	// IncludeExternalResources indicates whether to include external resources
	IncludeExternalResources bool

	// Logger is the logger to use
	Logger *logrus.Logger
}

// ResourceList contains lists of resources
type ResourceList struct {
	// Networks is the list of networks
	Networks []*models.Network

	// Volumes is the list of volumes
	Volumes []*models.Volume
}

// Common errors
var (
	// ErrResourceCreationFailed indicates that resource creation failed
	ErrResourceCreationFailed = fmt.Errorf("failed to create compose resources")

	// ErrResourceRemovalFailed indicates that resource removal failed
	ErrResourceRemovalFailed = fmt.Errorf("failed to remove compose resources")

	// ErrResourceNotFound indicates that a resource was not found
	ErrResourceNotFound = fmt.Errorf("compose resource not found")

	// ErrExternalResource indicates an operation on an external resource
	ErrExternalResource = fmt.Errorf("operation not allowed on external resource")
)
