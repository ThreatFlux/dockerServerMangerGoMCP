package utils

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings" // Uncommented for ParseRepositoryTag

	"github.com/distribution/reference" // Added for ParseImageName
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network" // Add/Uncomment network import
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/go-playground/validator/v10"
	"github.com/sirupsen/logrus"
)

// DockerClient defines the interface for Docker client operations needed by utils
type DockerClient interface {
	ContainerList(ctx context.Context, options container.ListOptions) ([]types.Container, error)
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
	ContainerLogs(ctx context.Context, container string, options container.LogsOptions) (io.ReadCloser, error)
	ImageList(ctx context.Context, options image.ListOptions) ([]image.Summary, error)
	ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error)
	ImagePull(ctx context.Context, ref string, options image.PullOptions) (io.ReadCloser, error)
	NetworkList(ctx context.Context, options network.ListOptions) ([]network.Summary, error)                       // Use network.ListOptions and network.Summary
	NetworkInspect(ctx context.Context, networkID string, options network.InspectOptions) (network.Inspect, error) // Use network.InspectOptions and network.Inspect
	NetworkCreate(ctx context.Context, name string, options network.CreateOptions) (network.CreateResponse, error) // Use network.CreateOptions and network.CreateResponse
	NetworkRemove(ctx context.Context, networkID string) error
	VolumeList(ctx context.Context, filter filters.Args) (volume.ListResponse, error)
	VolumeInspect(ctx context.Context, volumeID string) (volume.Volume, error)
	VolumeCreate(ctx context.Context, options volume.CreateOptions) (volume.Volume, error)
	VolumeRemove(ctx context.Context, volumeID string, force bool) error
	Ping(ctx context.Context) (types.Ping, error)
}

// SanitizeDockerName removes invalid characters from a Docker resource name.
func SanitizeDockerName(name string) string {
	reg := regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)
	sanitized := reg.ReplaceAllString(name, "")
	if len(sanitized) > 0 && (sanitized[0] == '.' || sanitized[0] == '-' || sanitized[0] == '_') {
		sanitized = "dsm_" + sanitized
	}
	if sanitized == "" {
		return "default_resource_name"
	}
	return sanitized
}

// EnsureImage checks if an image exists locally, pulling it if necessary.
func EnsureImage(ctx context.Context, cli DockerClient, imageName string, pull bool, logger *logrus.Logger) error {
	logger.WithField("image", imageName).Debug("Ensuring image exists")
	_, _, err := cli.ImageInspectWithRaw(ctx, imageName)
	if err != nil {
		// Assuming client.IsErrNotFound exists and works correctly
		if client.IsErrNotFound(err) {
			if pull {
				logger.WithField("image", imageName).Info("Image not found locally, pulling...")
				reader, pullErr := cli.ImagePull(ctx, imageName, image.PullOptions{})
				if pullErr != nil {
					return fmt.Errorf("failed to pull image %s: %w", imageName, pullErr)
				}
				defer reader.Close()
				_, copyErr := io.Copy(io.Discard, reader)
				if copyErr != nil {
					logger.WithError(copyErr).Warn("Error reading image pull output")
				}
				logger.WithField("image", imageName).Info("Image pulled successfully")
				return nil
			}
			return fmt.Errorf("image %s not found locally and pull is disabled", imageName)

		}
		return fmt.Errorf("failed to inspect image %s: %w", imageName, err)
	}
	logger.WithField("image", imageName).Debug("Image found locally")
	return nil
}

// GetContainerByName finds a container by its exact name.
func GetContainerByName(ctx context.Context, cli DockerClient, name string) (*types.Container, error) {
	containers, err := cli.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("name", fmt.Sprintf("^/%s$", name))),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	if len(containers) == 0 {
		return nil, fmt.Errorf("container with name '%s' not found", name)
	}
	if len(containers) > 1 {
		return nil, fmt.Errorf("multiple containers found with name '%s'", name)
	}

	return &containers[0], nil
}

// GetContainerByID finds a container by its full or partial ID.
func GetContainerByID(ctx context.Context, cli DockerClient, id string) (*types.Container, error) {
	containers, err := cli.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("id", id)),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	if len(containers) == 0 {
		return nil, fmt.Errorf("container with ID '%s' not found", id)
	}
	return &containers[0], nil
}

// GetContainerLogs retrieves logs for a specific container.
func GetContainerLogs(ctx context.Context, cli DockerClient, containerID string, options container.LogsOptions) (io.ReadCloser, error) {
	logsReader, err := cli.ContainerLogs(ctx, containerID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs for container %s: %w", containerID, err)
	}
	return logsReader, nil
}

// ListImages lists Docker images based on filters.
func ListImages(ctx context.Context, cli DockerClient, options image.ListOptions) ([]image.Summary, error) {
	images, err := cli.ImageList(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}
	return images, nil
}

// ListNetworks lists Docker networks based on filters.
func ListNetworks(ctx context.Context, cli DockerClient, options network.ListOptions) ([]network.Summary, error) { // Use network.ListOptions and network.Summary
	networks, err := cli.NetworkList(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}
	return networks, nil
}

// InspectNetwork inspects a specific network.
func InspectNetwork(ctx context.Context, cli DockerClient, networkID string) (network.Inspect, error) { // Use network.Inspect
	networkRes, err := cli.NetworkInspect(ctx, networkID, network.InspectOptions{Verbose: true}) // Use network.InspectOptions
	if err != nil {
		return network.Inspect{}, fmt.Errorf("failed to inspect network %s: %w", networkID, err) // Use network.Inspect
	}
	return networkRes, nil
}

// EnsureNetwork checks if a network exists, creating it if necessary.
func EnsureNetwork(ctx context.Context, cli DockerClient, networkName string, driver string, labels map[string]string, enableIPv6 bool, internal bool, attachable bool, logger *logrus.Logger) (string, error) {
	logger.WithField("network", networkName).Debug("Ensuring network exists")
	networks, err := cli.NetworkList(ctx, network.ListOptions{ // Use network.ListOptions
		Filters: filters.NewArgs(filters.Arg("name", fmt.Sprintf("^%s$", networkName))),
	})
	if err != nil {
		return "", fmt.Errorf("failed to list networks: %w", err)
	}

	if len(networks) > 0 {
		logger.WithField("network", networkName).Debug("Network already exists")
		return networks[0].ID, nil
	}

	logger.WithField("network", networkName).Info("Network not found, creating...")
	if driver == "" {
		driver = "bridge" // Default driver
	}
	createOpts := network.CreateOptions{ // Use network.CreateOptions
		Driver:     driver,
		Labels:     labels,
		EnableIPv6: &enableIPv6, // Pass address of bool
		Internal:   internal,
		Attachable: attachable,
	}

	resp, err := cli.NetworkCreate(ctx, networkName, createOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create network %s: %w", networkName, err)
	}
	logger.WithField("network", networkName).WithField("id", resp.ID).Info("Network created successfully")
	return resp.ID, nil
}

// RemoveNetwork removes a network if it exists.
func RemoveNetwork(ctx context.Context, cli DockerClient, networkIDOrName string, logger *logrus.Logger) error {
	logger.WithField("network", networkIDOrName).Info("Removing network")
	err := cli.NetworkRemove(ctx, networkIDOrName)
	if err != nil {
		if client.IsErrNotFound(err) {
			logger.WithField("network", networkIDOrName).Warn("Network not found, skipping removal")
			return nil
		}
		return fmt.Errorf("failed to remove network %s: %w", networkIDOrName, err)
	}
	logger.WithField("network", networkIDOrName).Info("Network removed successfully")
	return nil
}

// ListVolumes lists Docker volumes based on filters.
func ListVolumes(ctx context.Context, cli DockerClient, filter filters.Args) (volume.ListResponse, error) {
	volumes, err := cli.VolumeList(ctx, filter)
	if err != nil {
		return volume.ListResponse{}, fmt.Errorf("failed to list volumes: %w", err)
	}
	return volumes, nil
}

// InspectVolume inspects a specific volume.
func InspectVolume(ctx context.Context, cli DockerClient, volumeID string) (volume.Volume, error) {
	vol, err := cli.VolumeInspect(ctx, volumeID)
	if err != nil {
		return volume.Volume{}, fmt.Errorf("failed to inspect volume %s: %w", volumeID, err)
	}
	return vol, nil
}

// EnsureVolume checks if a volume exists, creating it if necessary.
func EnsureVolume(ctx context.Context, cli DockerClient, volumeName string, driver string, driverOpts map[string]string, labels map[string]string, logger *logrus.Logger) (string, error) {
	logger.WithField("volume", volumeName).Debug("Ensuring volume exists")
	filterArgs := filters.NewArgs(filters.Arg("name", fmt.Sprintf("^%s$", volumeName)))
	volumes, err := cli.VolumeList(ctx, filterArgs)
	if err != nil {
		return "", fmt.Errorf("failed to list volumes: %w", err)
	}

	if len(volumes.Volumes) > 0 {
		logger.WithField("volume", volumeName).Debug("Volume already exists")
		return volumes.Volumes[0].Name, nil
	}

	logger.WithField("volume", volumeName).Info("Volume not found, creating...")
	createOpts := volume.CreateOptions{
		Name:       volumeName,
		Driver:     driver,
		DriverOpts: driverOpts,
		Labels:     labels,
	}

	vol, err := cli.VolumeCreate(ctx, createOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create volume %s: %w", volumeName, err)
	}
	logger.WithField("volume", volumeName).Info("Volume created successfully")
	return vol.Name, nil
}

// RemoveVolume removes a volume if it exists.
func RemoveVolume(ctx context.Context, cli DockerClient, volumeIDOrName string, force bool, logger *logrus.Logger) error {
	logger.WithField("volume", volumeIDOrName).Info("Removing volume")
	err := cli.VolumeRemove(ctx, volumeIDOrName, force)
	if err != nil {
		if client.IsErrNotFound(err) {
			logger.WithField("volume", volumeIDOrName).Warn("Volume not found, skipping removal")
			return nil
		}
		return fmt.Errorf("failed to remove volume %s: %w", volumeIDOrName, err)
	}
	logger.WithField("volume", volumeIDOrName).Info("Volume removed successfully")
	return nil
}

// IsValidURL checks if a string is a valid URL.
func IsValidURL(str string) bool {
	u, err := url.ParseRequestURI(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// FileExists checks if a file exists and is not a directory.
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// ParseImageName parses a Docker image name string into its components.
// It wraps github.com/docker_test/distribution/reference.ParseNamed.
func ParseImageName(ref string) (reference.Named, error) {
	named, err := reference.ParseNamed(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image name '%s': %w", ref, err)
	}
	return named, nil
}

// ParseRepositoryTag splits a full image reference (e.g., "nginx:latest", "myregistry.com/myimage:v1")
// into repository name ("nginx", "myregistry.com/myimage") and tag ("latest", "v1").
// It defaults the tag to "latest" if not specified.
func ParseRepositoryTag(refStr string) (repository string, tag string) {
	named, err := ParseImageName(refStr) // Use existing ParseImageName
	if err != nil {
		// Fallback for simple cases if parsing fails (e.g., just "nginx")
		parts := strings.SplitN(refStr, ":", 2)
		if len(parts) == 1 {
			return parts[0], "latest"
		}
		return parts[0], parts[1]
	}

	repository = named.Name() // Get the name part (e.g., "nginx" or "myregistry.com/myimage")

	tagged, ok := named.(reference.Tagged)
	if ok {
		tag = tagged.Tag()
	} else {
		tag = "latest" // Default tag
	}

	return repository, tag
}

// FormatImageSize converts bytes to a human-readable string (KB, MB, GB).
func FormatImageSize(sizeBytes int64) string {
	const unit = 1024
	if sizeBytes < unit {
		return fmt.Sprintf("%d B", sizeBytes)
	}
	div, exp := int64(unit), 0
	for n := sizeBytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(sizeBytes)/float64(div), "KMGTPE"[exp])
}

// validate is used by other utils, ensure it's initialized
var validate *validator.Validate

func init() {
	validate = validator.New()
	// Register custom validations if needed by other utils
	// validate.RegisterValidation(...)
}

// BuildFilterArgs constructs a filters.Args object from a map of filter key-value pairs.
// It skips empty values to avoid sending empty filters to the Docker API.
func BuildFilterArgs(filterMap map[string]string) filters.Args {
	args := filters.NewArgs()
	for key, value := range filterMap {
		if value != "" {
			args.Add(key, value)
		}
	}
	return args
}

// FormatLabels converts a map of labels into a slice of "key=value" strings.
// Returns an empty slice if the input map is nil or empty.
func FormatLabels(labels map[string]string) []string {
	if len(labels) == 0 {
		return nil // Return nil or empty slice based on API needs, nil often works better with filters
	}
	formatted := make([]string, 0, len(labels))
	for k, v := range labels {
		formatted = append(formatted, fmt.Sprintf("%s=%s", k, v))
	}
	return formatted
}

// FormatContainerStatus determines a user-friendly status string based on state and health.
// Note: This logic might need refinement based on specific desired statuses.
func FormatContainerStatus(state string, health *types.Health) string {
	if state == "running" {
		if health != nil {
			switch health.Status {
			case types.Healthy:
				return "healthy"
			case types.Unhealthy:
				return "unhealthy"
			case types.Starting:
				return "starting"
			}
		}
		return "running" // Default if running but no health info or health is unknown
	}
	// Handle other states like created, restarting, removing, paused, exited, dead
	// Example: Extract exit code if state is "exited (CODE)"
	if strings.HasPrefix(state, "exited") {
		return "exited" // Simplified for now
	}
	return state // Return the raw state if not running or exited
}

// ParseContainerLabels converts Docker API labels map to our JSONMap.
// Handles potential nil map from the API.
func ParseContainerLabels(dockerLabels map[string]string) map[string]interface{} {
	if dockerLabels == nil {
		return make(map[string]interface{})
	}
	labels := make(map[string]interface{}, len(dockerLabels))
	for k, v := range dockerLabels {
		labels[k] = v
	}
	return labels
}

// GetContainerIP extracts the primary IP address from the container's network settings.
// It iterates through the networks and returns the first valid IP found.
// Returns an empty string if no IP address is found.
func GetContainerIP(networkSettings *types.NetworkSettings) string {
	if networkSettings == nil {
		return ""
	}
	// Prefer IPAddress field if available (older API versions?)
	if networkSettings.IPAddress != "" {
		return networkSettings.IPAddress
	}
	// Iterate through Networks map (newer API versions)
	for _, endpoint := range networkSettings.Networks {
		if endpoint != nil && endpoint.IPAddress != "" {
			return endpoint.IPAddress // Return the first one found
		}
	}
	return "" // No IP found
}

// IsContainerRunning checks if the container state indicates it's running.
func IsContainerRunning(state string) bool {
	// Consider "running", potentially "restarting" depending on desired behavior
	return state == "running"
}
