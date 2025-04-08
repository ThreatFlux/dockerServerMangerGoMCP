// Package volume provides functionality for Docker volume management
package volume

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// Service defines the interface for Docker volume operations
type Service interface {
	// Create creates a new volume
	Create(ctx context.Context, name string, options CreateOptions) (*models.Volume, error)

	// Get gets a volume by name
	Get(ctx context.Context, name string, options GetOptions) (*models.Volume, error)

	// List lists volumes
	List(ctx context.Context, options ListOptions) ([]*models.Volume, error)

	// Remove removes a volume
	Remove(ctx context.Context, name string, options RemoveOptions) error

	// Prune removes unused volumes
	Prune(ctx context.Context, options PruneOptions) (*volume.PruneReport, error) // Use volume.PruneReport

	// Backup creates a backup of a volume
	Backup(ctx context.Context, name string, options BackupOptions) (io.ReadCloser, error)

	// Restore restores a volume from a backup
	Restore(ctx context.Context, name string, reader io.Reader, options RestoreOptions) error

	// InspectRaw gets the raw information about a volume
	InspectRaw(ctx context.Context, name string) (volume.Volume, error) // Use volume.Volume

	// GetEvents subscribes to volume events
	GetEvents(ctx context.Context, options EventOptions) (<-chan events.Message, <-chan error) // Use events.Message for now

	// Update updates a volume's metadata
	Update(ctx context.Context, name string, metadata map[string]string, options UpdateOptions) error
}

// CreateOptions defines options for creating a volume
type CreateOptions struct {
	Driver     string
	DriverOpts map[string]string
	Labels     map[string]string
	Timeout    time.Duration
	Logger     *logrus.Logger
}

// GetOptions defines options for getting a volume
type GetOptions struct {
	Timeout time.Duration
	Logger  *logrus.Logger
}

// ListOptions defines options for listing volumes
type ListOptions struct {
	Filters filters.Args
	Timeout time.Duration
	Logger  *logrus.Logger
}

// RemoveOptions defines options for removing a volume
type RemoveOptions struct {
	Force   bool
	Timeout time.Duration
	Logger  *logrus.Logger
}

// PruneOptions defines options for pruning volumes
type PruneOptions struct {
	Filters filters.Args
	Timeout time.Duration
	Logger  *logrus.Logger
}

// BackupOptions defines options for backing up a volume
type BackupOptions struct {
	CompressFormat  string
	IncludeMetadata bool
	Timeout         time.Duration
	Logger          *logrus.Logger
}

// RestoreOptions defines options for restoring a volume
type RestoreOptions struct {
	OverwriteIfExists bool
	ExtractFormat     string
	RestoreMetadata   bool
	Timeout           time.Duration
	Logger            *logrus.Logger
}

// EventOptions defines options for volume events
type EventOptions struct {
	Filters    filters.Args
	BufferSize int
	Since      time.Time
	Until      time.Time
	Logger     *logrus.Logger
}

// UpdateOptions defines options for updating a volume
type UpdateOptions struct {
	Timeout time.Duration
	Logger  *logrus.Logger
}

// VolumeManager implements the Service interface
type VolumeManager struct {
	client VolumeClient
	logger *logrus.Logger
}

// VolumeClient defines the required Docker client methods for volume operations
type VolumeClient interface {
	// VolumeCreate creates a volume
	VolumeCreate(ctx context.Context, options volume.CreateOptions) (volume.Volume, error)

	// VolumeInspect inspects a volume
	VolumeInspect(ctx context.Context, volumeID string) (volume.Volume, error)

	// VolumeList lists volumes
	VolumeList(ctx context.Context, filter filters.Args) (volume.ListResponse, error)

	// VolumeRemove removes a volume
	VolumeRemove(ctx context.Context, volumeID string, force bool) error

	// VolumePrune prunes volumes
	VolumePrune(ctx context.Context, pruneFilters filters.Args) (volume.PruneReport, error) // Use volume.PruneReport

	// Events streams events from the Docker daemon
	Events(ctx context.Context, options events.ListOptions) (<-chan events.Message, <-chan error) // Use events.ListOptions
}

// NewVolumeManager creates a new VolumeManager
func NewVolumeManager(client VolumeClient, logger *logrus.Logger) *VolumeManager {
	if logger == nil {
		logger = logrus.New()
	}

	return &VolumeManager{
		client: client,
		logger: logger,
	}
}

// Create creates a new volume
func (m *VolumeManager) Create(ctx context.Context, name string, options CreateOptions) (*models.Volume, error) {
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	driver := options.Driver
	if driver == "" {
		driver = "local"
	}

	createOptions := volume.CreateOptions{
		Name:       name,
		Driver:     driver,
		DriverOpts: options.DriverOpts,
		Labels:     options.Labels,
	}

	logger.WithField("name", name).Debug("Creating volume")
	vol, err := m.client.VolumeCreate(ctx, createOptions)
	if err != nil {
		return nil, err
	}

	return toVolumeModel(vol), nil
}

// Get gets a volume by name
func (m *VolumeManager) Get(ctx context.Context, name string, options GetOptions) (*models.Volume, error) {
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	logger.WithField("name", name).Debug("Getting volume")
	vol, err := m.client.VolumeInspect(ctx, name)
	if err != nil {
		return nil, err
	}

	return toVolumeModel(vol), nil
}

// List lists volumes
func (m *VolumeManager) List(ctx context.Context, options ListOptions) ([]*models.Volume, error) {
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	logger.Debug("Listing volumes")
	volList, err := m.client.VolumeList(ctx, options.Filters)
	if err != nil {
		return nil, err
	}

	vols := make([]*models.Volume, len(volList.Volumes))
	for i, vol := range volList.Volumes {
		vols[i] = toVolumeModel(*vol)
	}

	return vols, nil
}

// Remove removes a volume
func (m *VolumeManager) Remove(ctx context.Context, name string, options RemoveOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	logger.WithField("name", name).Debug("Removing volume")
	return m.client.VolumeRemove(ctx, name, options.Force)
}

// Prune removes unused volumes
func (m *VolumeManager) Prune(ctx context.Context, options PruneOptions) (*volume.PruneReport, error) { // Use volume.PruneReport
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	logger.Debug("Pruning volumes")
	pruneReport, err := m.client.VolumePrune(ctx, options.Filters)
	if err != nil {
		return nil, err
	}

	return &pruneReport, nil
}

// Backup creates a backup of a volume
func (m *VolumeManager) Backup(ctx context.Context, name string, options BackupOptions) (io.ReadCloser, error) {
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	logger.WithField("name", name).Debug("Backing up volume")
	_, err := m.client.VolumeInspect(ctx, name)
	if err != nil {
		return nil, err
	}

	return nil, errors.New("backup functionality not implemented")
}

// Restore restores a volume from a backup
func (m *VolumeManager) Restore(ctx context.Context, name string, reader io.Reader, options RestoreOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	logger.WithField("name", name).Debug("Restoring volume")
	_, err := m.client.VolumeInspect(ctx, name)
	if err == nil && !options.OverwriteIfExists {
		return ErrVolumeExists
	} else if err != nil && !errors.Is(err, ErrVolumeNotFound) {
		return err
	}

	return errors.New("restore functionality not implemented")
}

// InspectRaw gets the raw information about a volume
func (m *VolumeManager) InspectRaw(ctx context.Context, name string) (volume.Volume, error) {
	return m.client.VolumeInspect(ctx, name)
}

// GetEvents subscribes to volume events
func (m *VolumeManager) GetEvents(ctx context.Context, options EventOptions) (<-chan events.Message, <-chan error) {
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	eventOptions := events.ListOptions{ // Use events.ListOptions
		Since:   options.Since.Format(time.RFC3339Nano),
		Until:   options.Until.Format(time.RFC3339Nano),
		Filters: options.Filters, // Assign directly from options
	}

	// If the assigned Filters is zero/empty, initialize it.
	// A zero filters.Args is usable but won't merge correctly if nil was intended.
	// This ensures we have a valid map to add to.
	if eventOptions.Filters.Len() == 0 && options.Filters.Len() == 0 {
		// If both options.Filters and the assigned eventOptions.Filters are empty,
		// explicitly initialize eventOptions.Filters to ensure Add works.
		eventOptions.Filters = filters.NewArgs()
	} else if eventOptions.Filters.Len() == 0 && options.Filters.Len() > 0 {
		// This case shouldn't happen if direct assignment works, but as a safeguard:
		eventOptions.Filters = options.Filters // Re-assign if needed
	}
	// If eventOptions.Filters was already populated by options.Filters, this is fine.

	// Always add the volume type filter
	eventOptions.Filters.Add("type", "volume")

	logger.Debug("Subscribing to volume events")
	return m.client.Events(ctx, eventOptions)
}

// Update updates a volume's metadata
func (m *VolumeManager) Update(ctx context.Context, name string, metadata map[string]string, options UpdateOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	logger.WithField("name", name).Debug("Updating volume (placeholder - not directly supported by Docker API)")
	_, err := m.client.VolumeInspect(ctx, name)
	if err != nil {
		return err
	}

	return errors.New("update functionality not directly supported by Docker API")
}

// toVolumeModel converts a Docker volume to our volume model
func toVolumeModel(vol volume.Volume) *models.Volume {
	optionsMap := make(models.JSONMap)
	if vol.Options != nil {
		for k, v := range vol.Options {
			optionsMap[k] = v
		}
	}
	labelsMap := make(models.JSONMap)
	if vol.Labels != nil {
		for k, v := range vol.Labels {
			labelsMap[k] = v
		}
	}
	statusMap := make(models.JSONMap)
	if vol.Status != nil {
		for k, v := range vol.Status {
			statusMap[k] = v
		}
	}

	// createdAtTime, _ := time.Parse(time.RFC3339, vol.CreatedAt) // Removed unused variable

	return &models.Volume{
		DockerResource: models.DockerResource{
			Name:   vol.Name,
			Labels: labelsMap,
		},
		VolumeID:   vol.Name,
		Driver:     vol.Driver,
		Mountpoint: vol.Mountpoint,
		// CreatedAt:  createdAtTime, // Handled by DockerResource
		Status:    statusMap,
		Scope:     vol.Scope,
		Options:   optionsMap,
		UsageData: toVolumeUsageData(vol.UsageData),
	}
}

// toVolumeUsageData converts Docker volume usage data to our model
func toVolumeUsageData(usage *volume.UsageData) *models.VolumeUsageData {
	if usage == nil {
		return nil
	}

	return &models.VolumeUsageData{
		Size:     usage.Size,
		RefCount: usage.RefCount, // Assign int64 directly
	}
}

// Common errors
var (
	// ErrVolumeExists indicates that the volume already exists
	ErrVolumeExists = errors.New("volume already exists")

	// ErrVolumeNotFound indicates that the volume was not found
	ErrVolumeNotFound = errors.New("volume not found")

	// ErrVolumeInUse indicates that the volume is in use
	ErrVolumeInUse = errors.New("volume in use")
)
