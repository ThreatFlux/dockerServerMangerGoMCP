package volume

import (
	"context"
	"fmt"
	"io" // Added io import

	"github.com/docker/docker/api/types/events" // Added events import
	"github.com/docker/docker/api/types/filters"
	volumetypes "github.com/docker/docker/api/types/volume"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Added models import
)

// serviceImpl implements the volume.Service interface
type serviceImpl struct {
	dockerManager docker.Manager
	logger        *logrus.Logger
}

// NewService creates a new volume service implementation
func NewService(dockerManager docker.Manager, logger *logrus.Logger) Service {
	if logger == nil {
		logger = logrus.New()
	}
	return &serviceImpl{
		dockerManager: dockerManager,
		logger:        logger,
	}
}

// Backup is a placeholder implementation
func (s *serviceImpl) Backup(ctx context.Context, name string, options BackupOptions) (io.ReadCloser, error) {
	return nil, fmt.Errorf("backup functionality not implemented")
}

// List returns a list of Docker volumes
func (s *serviceImpl) List(ctx context.Context, options ListOptions) ([]*models.Volume, error) { // Changed return type
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err) // Return nil for slice
	}

	// Use filters directly from options
	filterArgs := options.Filters
	if filterArgs.Len() == 0 {
		filterArgs = filters.NewArgs() // Ensure it's not nil if empty
	}

	s.logger.WithField("filters", filterArgs).Debug("Listing volumes")
	// Construct volumetypes.ListOptions with the filters
	listOpts := volumetypes.ListOptions{Filters: filterArgs}
	volumesResp, err := cli.VolumeList(ctx, listOpts) // Pass listOpts, rename var
	if err != nil {
		s.logger.WithError(err).Error("Failed to list volumes from Docker API")
		return nil, fmt.Errorf("failed to list volumes: %w", err) // Return nil for slice
	}

	// Convert to []*models.Volume
	modelVolumes := make([]*models.Volume, len(volumesResp.Volumes))
	for i, vol := range volumesResp.Volumes {
		modelVolumes[i] = toVolumeModel(*vol) // Use existing conversion helper
	}

	s.logger.WithField("count", len(modelVolumes)).Debug("Successfully listed volumes")
	return modelVolumes, nil
}

// Inspect returns detailed information about a volume
func (s *serviceImpl) Inspect(ctx context.Context, volumeID string) (volumetypes.Volume, error) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return volumetypes.Volume{}, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	s.logger.WithField("volumeID", volumeID).Debug("Inspecting volume")
	volume, err := cli.VolumeInspect(ctx, volumeID)
	if err != nil {
		s.logger.WithError(err).WithField("volumeID", volumeID).Error("Failed to inspect volume")
		// TODO: Wrap common errors like not found
		return volumetypes.Volume{}, fmt.Errorf("failed to inspect volume %s: %w", volumeID, err)
	}

	s.logger.WithField("volumeID", volumeID).Debug("Volume inspected successfully")
	return volume, nil
}

// Create creates a new Docker volume
// Note: The 'name' is passed as a separate argument now, matching the interface.
func (s *serviceImpl) Create(ctx context.Context, name string, options CreateOptions) (*models.Volume, error) { // Changed return type to *models.Volume
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err) // Return nil for *models.Volume
	}

	createOpts := volumetypes.CreateOptions{
		Name:       name, // Use the 'name' argument
		Driver:     options.Driver,
		DriverOpts: options.DriverOpts,
		Labels:     options.Labels,
	}

	s.logger.WithFields(logrus.Fields{
		"name":   name, // Use the 'name' argument
		"driver": options.Driver,
	}).Info("Creating volume")

	volume, err := cli.VolumeCreate(ctx, createOpts)
	if err != nil {
		s.logger.WithError(err).WithField("name", name).Error("Failed to create volume") // Use the 'name' argument
		return nil, fmt.Errorf("failed to create volume %s: %w", name, err)              // Return nil for *models.Volume
	}

	s.logger.WithField("name", volume.Name).Info("Volume created successfully")
	// Convert to models.Volume before returning to match interface
	return toVolumeModel(volume), nil // Use existing conversion helper
}

// Remove removes a Docker volume
func (s *serviceImpl) Remove(ctx context.Context, name string, options RemoveOptions) error { // Updated signature
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"volumeID": name,          // Use name from argument
		"force":    options.Force, // Use Force from options
	}).Info("Removing volume")

	err = cli.VolumeRemove(ctx, name, options.Force) // Use name and options.Force
	if err != nil {
		s.logger.WithError(err).WithField("volumeID", name).Error("Failed to remove volume") // Use name
		// TODO: Wrap common errors like not found or in use
		return fmt.Errorf("failed to remove volume %s: %w", name, err) // Use name
	}

	s.logger.WithField("volumeID", name).Info("Volume removed successfully") // Use name
	return nil
}

// Prune removes unused Docker volumes
func (s *serviceImpl) Prune(ctx context.Context, options PruneOptions) (*volumetypes.PruneReport, error) { // Changed return type to pointer
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err) // Return nil for pointer
	}

	// Use filters directly from options
	filterArgs := options.Filters
	if filterArgs.Len() == 0 {
		filterArgs = filters.NewArgs() // Ensure it's not nil if empty
	}

	s.logger.WithField("filters", filterArgs).Info("Pruning volumes")
	report, err := cli.VolumesPrune(ctx, filterArgs)
	if err != nil {
		s.logger.WithError(err).Error("Failed to prune volumes")
		return nil, fmt.Errorf("failed to prune volumes: %w", err) // Return nil for pointer
	}

	s.logger.WithFields(logrus.Fields{
		"volumes_deleted": len(report.VolumesDeleted),
		"space_reclaimed": report.SpaceReclaimed,
	}).Info("Volumes pruned successfully")
	return &report, nil // Return pointer to report
}

// Get is a placeholder implementation
func (s *serviceImpl) Get(ctx context.Context, name string, options GetOptions) (*models.Volume, error) {
	// TODO: Implement actual logic, potentially using Inspect and converting
	return nil, fmt.Errorf("get volume functionality not implemented")
}

// Restore is a placeholder implementation
func (s *serviceImpl) Restore(ctx context.Context, name string, reader io.Reader, options RestoreOptions) error {
	return fmt.Errorf("restore volume functionality not implemented")
}

// InspectRaw gets the raw information about a volume
func (s *serviceImpl) InspectRaw(ctx context.Context, name string) (volumetypes.Volume, error) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return volumetypes.Volume{}, fmt.Errorf("failed to get docker_test client: %w", err)
	}
	return cli.VolumeInspect(ctx, name)
}

// GetEvents is a placeholder implementation
func (s *serviceImpl) GetEvents(ctx context.Context, options EventOptions) (<-chan events.Message, <-chan error) {
	// TODO: Implement actual event streaming logic
	errChan := make(chan error, 1)
	errChan <- fmt.Errorf("get volume events functionality not implemented")
	close(errChan)
	return nil, errChan
}

// Update is a placeholder implementation
func (s *serviceImpl) Update(ctx context.Context, name string, metadata map[string]string, options UpdateOptions) error {
	return fmt.Errorf("update volume functionality not implemented")
}
