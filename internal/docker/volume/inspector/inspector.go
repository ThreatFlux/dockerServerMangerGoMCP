// Package inspector provides functionality for inspecting Docker volumes
package inspector

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	dockertypes "github.com/docker/docker/api/types" // Use alias
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/system" // Added for system.Info
	"github.com/docker/docker/api/types/volume"
	dockerClient "github.com/docker/docker/client" // Alias the client package
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// VolumeInspectorClient defines the interface for Docker client methods used by the inspector.
// This allows for easier mocking and testing.
type VolumeInspectorClient interface {
	VolumeInspect(ctx context.Context, volumeID string) (volume.Volume, error)
	VolumeList(ctx context.Context, options volume.ListOptions) (volume.ListResponse, error)           // Use ListResponse
	ContainerList(ctx context.Context, options container.ListOptions) ([]dockertypes.Container, error) // Use alias
	ContainerInspect(ctx context.Context, containerID string) (dockertypes.ContainerJSON, error)       // Use alias
	Info(ctx context.Context) (system.Info, error)                                                     // Use system.Info
}

// Inspector provides functionality for inspecting Docker volumes
type Inspector struct {
	// client is the Docker API client interface
	client VolumeInspectorClient // Use the interface type

	// logger is the logger
	logger *logrus.Logger
}

// Options contains options for creating an Inspector
type Options struct {
	// Client is the Docker client interface
	Client VolumeInspectorClient // Accept the interface directly

	// Logger is the logger interface
	Logger *logrus.Logger
}

// New creates a new Inspector
func New(options Options) (*Inspector, error) {
	var inspectorClient VolumeInspectorClient = options.Client

	// If no client (real or mock) is provided, create a default real client.
	if inspectorClient == nil {
		cli, err := dockerClient.NewClientWithOpts(dockerClient.FromEnv, dockerClient.WithAPIVersionNegotiation())
		if err != nil {
			return nil, fmt.Errorf("failed to create default Docker client: %w", err)
		}
		inspectorClient = cli
	}

	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}

	return &Inspector{
		client: inspectorClient, // Store the provided or default client
		logger: logger,
	}, nil
}

// VolumeDetails contains detailed information about a volume
type VolumeDetails struct {
	// Volume is the basic volume information
	Volume models.Volume `json:"volume"`

	// References contains information about containers referencing the volume
	References []VolumeReference `json:"references"`

	// Metrics contains usage metrics
	Metrics VolumeMetrics `json:"metrics"`

	// ExtraInfo contains additional information
	ExtraInfo map[string]interface{} `json:"extra_info"`
}

// VolumeReference contains information about a container referencing a volume
type VolumeReference struct {
	// ContainerID is the container ID
	ContainerID string `json:"container_id"`

	// ContainerName is the container name
	ContainerName string `json:"container_name"`

	// MountPath is the path where the volume is mounted
	MountPath string `json:"mount_path"`

	// Mode is the mount mode
	Mode string `json:"mode"`
}

// VolumeMetrics contains volume usage metrics
type VolumeMetrics struct {
	// Size is the size in bytes
	Size int64 `json:"size"`

	// RefCount is the reference count (use int64)
	RefCount int64 `json:"ref_count"`

	// LastAccessed and LastModified are not directly available in UsageData
	// LastAccessed time.Time `json:"last_accessed"`
	// LastModified time.Time `json:"last_modified"`
}

// ListOptions contains options for listing volumes
type ListOptions struct {
	// Filter is the filter to apply
	Filter *VolumesFilter

	// Timeout is the timeout for the operation
	Timeout time.Duration

	// Logger is the logger
	Logger *logrus.Logger
}

// InspectOptions contains options for inspecting a volume
type InspectOptions struct {
	// IncludeContainers indicates whether to include container information
	IncludeContainers bool

	// IncludeMetrics indicates whether to include metrics
	IncludeMetrics bool

	// IncludeRaw indicates whether to include raw information
	IncludeRaw bool

	// Timeout is the timeout for the operation
	Timeout time.Duration

	// Logger is the logger
	Logger *logrus.Logger
}

// VolumesFilter contains filters for listing volumes
type VolumesFilter struct {
	// Name is the volume name filter
	Name string

	// Driver is the driver name filter
	Driver string

	// Label is the label filter (key=value)
	Label string

	// Dangling indicates whether to include only dangling volumes
	Dangling bool

	// Custom is a map of custom filters
	Custom map[string][]string
}

// ToFilterArgs converts a VolumesFilter to filters.Args
func (f *VolumesFilter) ToFilterArgs() filters.Args {
	// Create a new filter
	filter := filters.NewArgs()

	// Add filters
	if f.Name != "" {
		filter.Add("name", f.Name)
	}
	if f.Driver != "" {
		filter.Add("driver", f.Driver)
	}
	if f.Label != "" {
		filter.Add("label", f.Label)
	}
	if f.Dangling {
		filter.Add("dangling", "true")
	}

	// Add custom filters
	for key, values := range f.Custom {
		for _, value := range values {
			filter.Add(key, value)
		}
	}

	return filter
}

// List lists volumes
func (i *Inspector) List(ctx context.Context, options ListOptions) ([]*models.Volume, error) {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = i.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Apply filters
	var filter filters.Args
	if options.Filter != nil {
		filter = options.Filter.ToFilterArgs()
	}

	// List volumes
	logger.Debug("Listing volumes")
	// Use volume.ListOptions type for the second argument
	listOptions := volume.ListOptions{Filters: filter} // Construct ListOptions with the filter
	volumesList, err := i.client.VolumeList(ctx, listOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to list volumes: %w", err)
	}

	// Convert to models
	volumes := make([]*models.Volume, len(volumesList.Volumes))
	for idx, vol := range volumesList.Volumes {
		volumes[idx] = toVolumeModel(*vol) // Dereference vol
	}

	return volumes, nil
}

// Inspect inspects a volume
func (i *Inspector) Inspect(ctx context.Context, name string, options InspectOptions) (*VolumeDetails, error) {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = i.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Get the volume
	logger.WithField("name", name).Debug("Inspecting volume")
	vol, err := i.client.VolumeInspect(ctx, name)
	if err != nil {
		if dockerClient.IsErrNotFound(err) { // Use package alias
			return nil, err // Return the original 'not found' error
		}
		return nil, fmt.Errorf("failed to inspect volume: %w", err)
	}

	// Create volume details
	details := &VolumeDetails{
		Volume:    *toVolumeModel(vol), // Dereference vol
		ExtraInfo: make(map[string]interface{}),
	}

	// Include raw information if requested
	if options.IncludeRaw {
		raw, err := json.Marshal(vol)
		if err == nil {
			var rawData map[string]interface{}
			if err := json.Unmarshal(raw, &rawData); err == nil {
				details.ExtraInfo["raw"] = rawData
			}
		}
	}

	// Include container information if requested
	if options.IncludeContainers {
		// Get containers using the volume
		references, err := i.getVolumeReferences(ctx, name)
		if err != nil {
			logger.WithError(err).Warn("Failed to get volume references")
		} else {
			details.References = references
		}
	}

	// Include metrics if requested
	if options.IncludeMetrics {
		// Get volume metrics
		metrics, err := i.getVolumeMetrics(ctx, name, vol) // Pass vol directly
		if err != nil {
			logger.WithError(err).Warn("Failed to get volume metrics")
		} else {
			details.Metrics = metrics
		}
	}

	return details, nil
}

// InspectMultiple inspects multiple volumes
func (i *Inspector) InspectMultiple(ctx context.Context, names []string, options InspectOptions) (map[string]*VolumeDetails, error) {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = i.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Inspect each volume
	logger.WithField("count", len(names)).Debug("Inspecting multiple volumes")
	details := make(map[string]*VolumeDetails)
	for _, name := range names {
		// Inspect the volume
		volumeDetails, err := i.Inspect(ctx, name, options)
		if err != nil {
			logger.WithError(err).WithField("name", name).Warn("Failed to inspect volume")
			continue
		}

		// Add to the map
		details[name] = volumeDetails
	}

	return details, nil
}

// GetStats gets volume statistics
func (i *Inspector) GetStats(ctx context.Context, name string) (*VolumeMetrics, error) {
	// Apply timeout if specified
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Get the volume
	vol, err := i.client.VolumeInspect(ctx, name)
	if err != nil {
		if dockerClient.IsErrNotFound(err) { // Use package alias
			return nil, err // Return the original 'not found' error
		}
		return nil, fmt.Errorf("failed to inspect volume: %w", err)
	}

	// Get volume metrics
	metrics, err := i.getVolumeMetrics(ctx, name, vol) // Pass vol directly
	if err != nil {
		return nil, fmt.Errorf("failed to get volume metrics: %w", err)
	}

	return &metrics, nil
}

// GetUsage gets volume usage statistics
func (i *Inspector) GetUsage(ctx context.Context) (map[string]int64, error) {
	// Apply timeout if specified
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// List volumes
	vols, err := i.List(ctx, ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list volumes: %w", err)
	}

	// Calculate usage for each volume
	usage := make(map[string]int64)
	for _, vol := range vols {
		// Get volume metrics
		metrics, err := i.GetStats(ctx, vol.Name)
		if err != nil {
			i.logger.WithError(err).WithField("name", vol.Name).Warn("Failed to get volume stats")
			continue
		}

		// Add to the map
		usage[vol.Name] = metrics.Size
	}

	return usage, nil
}

// getVolumeReferences gets containers referencing a volume
func (i *Inspector) getVolumeReferences(ctx context.Context, name string) ([]VolumeReference, error) {
	// List containers
	// Use container.ListOptions type
	containers, err := i.client.ContainerList(ctx, container.ListOptions{
		All: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Find containers using the volume
	var references []VolumeReference
	for _, container := range containers {
		// Inspect the container
		containerDetails, err := i.client.ContainerInspect(ctx, container.ID)
		if err != nil {
			i.logger.WithError(err).WithField("container", container.ID).Warn("Failed to inspect container")
			continue
		}

		// Check mounts
		for _, mount := range containerDetails.Mounts {
			if mount.Type == "volume" && mount.Name == name {
				// Add to references
				references = append(references, VolumeReference{
					ContainerID:   container.ID,
					ContainerName: containerDetails.Name,
					MountPath:     mount.Destination,
					Mode:          mount.Mode,
				})
				break
			}
		}
	}

	return references, nil
}

// getVolumeMetrics gets volume metrics
// Use volume.Volume type
func (i *Inspector) getVolumeMetrics(ctx context.Context, name string, vol volume.Volume) (VolumeMetrics, error) {
	metrics := VolumeMetrics{}

	// Set size from UsageData if available
	if vol.UsageData != nil {
		metrics.Size = vol.UsageData.Size
		metrics.RefCount = vol.UsageData.RefCount // Assign int64 directly
		// LastAccessed/LastModified are not available in UsageData
	}

	// If size is not available, try to calculate it
	if metrics.Size == 0 && vol.Mountpoint != "" {
		// Note: In a real implementation, we would create a container to access the volume
		// and calculate its size. For simplicity, we'll just use 0 here.
	}

	// Get reference count if not available
	if metrics.RefCount == 0 {
		references, err := i.getVolumeReferences(ctx, name)
		if err == nil {
			metrics.RefCount = int64(len(references))
		}
	}

	return metrics, nil
}

// FindUnused finds unused volumes
func (i *Inspector) FindUnused(ctx context.Context) ([]*models.Volume, error) {
	// Apply timeout if specified
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Create a filter for dangling volumes
	filter := &VolumesFilter{
		Dangling: true,
	}

	// List volumes
	return i.List(ctx, ListOptions{
		Filter: filter,
	})
}

// FindByLabel finds volumes by label
func (i *Inspector) FindByLabel(ctx context.Context, label string) ([]*models.Volume, error) {
	// Apply timeout if specified
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Create a filter for the label
	filter := &VolumesFilter{
		Label: label,
	}

	// List volumes
	return i.List(ctx, ListOptions{
		Filter: filter,
	})
}

// FindByName finds volumes by name pattern
func (i *Inspector) FindByName(ctx context.Context, pattern string) ([]*models.Volume, error) {
	// Apply timeout if specified
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Create a filter for the name
	filter := &VolumesFilter{
		Name: pattern,
	}

	// List volumes
	return i.List(ctx, ListOptions{
		Filter: filter,
	})
}

// FindByDriver finds volumes by driver name
func (i *Inspector) FindByDriver(ctx context.Context, driver string) ([]*models.Volume, error) {
	// Apply timeout if specified
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Create a filter for the driver
	filter := &VolumesFilter{
		Driver: driver,
	}

	// List volumes
	return i.List(ctx, ListOptions{
		Filter: filter,
	})
}

// GetDrivers gets a list of available volume drivers
func (i *Inspector) GetDrivers(ctx context.Context) ([]string, error) {
	// Apply timeout if specified
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Get Docker info
	info, err := i.client.Info(ctx) // Assuming client interface has Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get Docker info: %w", err)
	}

	// Extract drivers from Plugins.Volume
	drivers := make([]string, 0, len(info.Plugins.Volume))
	for _, driver := range info.Plugins.Volume {
		drivers = append(drivers, driver)
	}

	// Add the default "local" driver if not present
	foundLocal := false
	for _, d := range drivers {
		if d == "local" {
			foundLocal = true
			break
		}
	}
	if !foundLocal {
		drivers = append(drivers, "local")
	}

	return drivers, nil
}

// Helper function to convert map[string]string to models.JSONMap
func stringMapToJSONMap(input map[string]string) models.JSONMap {
	if input == nil {
		return nil
	}
	output := make(models.JSONMap, len(input))
	for k, v := range input {
		output[k] = v
	}
	return output
}

// toVolumeModel converts a Docker volume type to our model
// Use volume.Volume type
func toVolumeModel(vol volume.Volume) *models.Volume {
	// Directly cast Status (map[string]interface{}) to models.JSONMap
	var statusMap models.JSONMap
	if vol.Status != nil {
		statusMap = models.JSONMap(vol.Status)
	}

	// Removed unused createdAt parsing

	modelVol := &models.Volume{
		DockerResource: models.DockerResource{
			Name:   vol.Name,
			Labels: stringMapToJSONMap(vol.Labels), // Use helper for map[string]string
			// CreatedAt is inherited via DockerResource
		},
		VolumeID:   vol.Name, // Assuming VolumeID is the Docker volume name? Or should this be different?
		Driver:     vol.Driver,
		Mountpoint: vol.Mountpoint,
		Scope:      vol.Scope,
		Options:    stringMapToJSONMap(vol.Options), // Use helper for map[string]string
		Status:     statusMap,                       // Use the directly casted map
		UsageData:  toVolumeUsageData(vol.UsageData),
		// InUse needs to be determined separately, e.g., by checking UsageData.RefCount or references
	}
	// Manually set inherited CreatedAt after initialization if needed
	// modelVol.CreatedAt = createdAt // This line causes issues if modelVol is nil

	// Attempt to parse CreatedAt and set it on the embedded DockerResource
	createdAt, err := time.Parse(time.RFC3339, vol.CreatedAt)
	if err == nil {
		modelVol.DockerResource.CreatedAt = createdAt
	} else {
		// Log or handle the error if parsing fails, maybe default to zero time
		modelVol.DockerResource.CreatedAt = time.Time{}
	}

	return modelVol
}

// toVolumeUsageData converts Docker volume usage data to our model
// Use volume.UsageData type
func toVolumeUsageData(usage *volume.UsageData) *models.VolumeUsageData {
	if usage == nil {
		return nil
	}

	return &models.VolumeUsageData{
		Size:     usage.Size,
		RefCount: usage.RefCount, // RefCount is int64 in models.VolumeUsageData
		// LastUsed:  usage.LastUsed, // Field removed from source type
	}
}
