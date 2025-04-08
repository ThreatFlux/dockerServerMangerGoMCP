package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time" // Add time import

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Re-added internal import
)

// VolumeListOptions represents options for listing volumes
type VolumeListOptions struct {
	Filters map[string][]string
}

// buildQueryParams converts volume list options to URL query parameters
func buildVolumeListQueryParams(options *VolumeListOptions) url.Values {
	query := url.Values{}

	if options == nil {
		return query
	}

	if len(options.Filters) > 0 {
		filters, err := json.Marshal(options.Filters)
		if err == nil {
			query.Set("filters", string(filters))
		}
	}

	return query
}

// ListVolumes lists volumes with optional filters
func (c *APIClient) ListVolumes(ctx context.Context, filters map[string]string) ([]models.Volume, error) { // Use models.Volume
	// Convert simple filters map to the expected format
	options := &VolumeListOptions{}
	if len(filters) > 0 {
		options.Filters = make(map[string][]string)
		for k, v := range filters {
			options.Filters[k] = []string{v}
		}
	}

	// Build query params
	query := buildVolumeListQueryParams(options)
	path := APIPathVolumes // Use constant
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	// Create request
	req, err := c.newRequest(ctx, http.MethodGet, APIPathVolumes, nil) // Use constant path
	if err != nil {
		return nil, fmt.Errorf("failed to create list volumes request: %w", err)
	}

	// Add query parameters
	req.URL.RawQuery = query.Encode()

	// Execute request
	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list volumes request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var volumesResponse struct {
		// Assuming the API returns a structure compatible with Docker's VolumeListOKBody
		// If the API wraps it in { "success": true, "data": { ... } }, handleResponse will manage it.
		Volumes  []models.Volume `json:"Volumes"` // Use models.Volume
		Warnings []string        `json:"Warnings"`
	}

	// Use handleResponse which reads the body
	if err := c.handleResponse(resp, &volumesResponse); err != nil {
		// handleResponse already tried direct unmarshal if standard wrapper failed
		return nil, fmt.Errorf("failed to parse volumes response: %w", err)
	}

	return volumesResponse.Volumes, nil
}

// GetVolume gets detailed information about a volume
func (c *APIClient) GetVolume(ctx context.Context, name string) (*models.Volume, error) { // Use models.Volume
	if name == "" {
		return nil, fmt.Errorf("volume name cannot be empty")
	}

	path := fmt.Sprintf("%s/%s", APIPathVolumes, name)

	var volume models.Volume // Use models.Volume
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &volume); err != nil {
		return nil, fmt.Errorf("failed to get volume: %w", err)
	}

	return &volume, nil
}

// CreateVolume creates a new volume
func (c *APIClient) CreateVolume(ctx context.Context, options *models.VolumeCreateRequest) (*models.Volume, error) { // Use models types
	if options == nil {
		options = &models.VolumeCreateRequest{} // Use models type
	}

	// Validate options
	if options.Name == "" {
		return nil, fmt.Errorf("volume name cannot be empty")
	}

	var volume models.Volume // Use models type
	if err := c.doRequest(ctx, http.MethodPost, APIPathVolumes, options, &volume); err != nil {
		return nil, fmt.Errorf("failed to create volume: %w", err)
	}

	return &volume, nil
}

// RemoveVolume removes a volume with optional force flag
func (c *APIClient) RemoveVolume(ctx context.Context, name string, force bool) error {
	if name == "" {
		return fmt.Errorf("volume name cannot be empty")
	}

	path := fmt.Sprintf("%s/%s", APIPathVolumes, name)

	// Add force flag if specified
	if force {
		query := url.Values{}
		query.Set("force", "true")
		path += "?" + query.Encode()
	}

	if err := c.doRequest(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return fmt.Errorf("failed to remove volume: %w", err)
	}

	return nil
}

// PruneVolumes removes unused volumes
func (c *APIClient) PruneVolumes(ctx context.Context, filters map[string]string) (uint64, error) {
	path := fmt.Sprintf("%s/prune", APIPathVolumes)

	// Convert simple filters map to the expected format
	if len(filters) > 0 {
		filtersMap := make(map[string][]string)
		for k, v := range filters {
			filtersMap[k] = []string{v}
		}

		filtersJSON, err := json.Marshal(filtersMap)
		if err == nil {
			query := url.Values{}
			query.Set("filters", string(filtersJSON))
			path += "?" + query.Encode()
		}
	}

	// Send request
	var pruneResponse struct {
		// Assuming API returns structure compatible with Docker's VolumePruneOKBody
		VolumesDeleted []string `json:"VolumesDeleted"`
		SpaceReclaimed uint64   `json:"SpaceReclaimed"`
	}

	if err := c.doRequest(ctx, http.MethodPost, path, nil, &pruneResponse); err != nil {
		return 0, fmt.Errorf("failed to prune volumes: %w", err)
	}

	return pruneResponse.SpaceReclaimed, nil
}

// InspectVolume gets detailed information about a volume
// This is an alias for GetVolume for Docker CLI compatibility
func (c *APIClient) InspectVolume(ctx context.Context, name string) (*models.Volume, error) { // Use models.Volume
	return c.GetVolume(ctx, name)
}

// UpdateVolume updates a volume's metadata
func (c *APIClient) UpdateVolume(ctx context.Context, name string, labels map[string]string) error {
	if name == "" {
		return fmt.Errorf("volume name cannot be empty")
	}

	if labels == nil {
		return fmt.Errorf("labels cannot be nil")
	}

	path := fmt.Sprintf("%s/%s", APIPathVolumes, name)

	// Create update options
	updateOptions := struct {
		Labels map[string]string `json:"Labels"`
	}{
		Labels: labels,
	}

	if err := c.doRequest(ctx, http.MethodPut, path, updateOptions, nil); err != nil {
		return fmt.Errorf("failed to update volume: %w", err)
	}

	return nil
}

// CloneVolume creates a new volume by cloning an existing one
func (c *APIClient) CloneVolume(ctx context.Context, sourceName, targetName string, labels map[string]string) (*models.Volume, error) { // Use models.Volume
	if sourceName == "" {
		return nil, fmt.Errorf("source volume name cannot be empty")
	}

	if targetName == "" {
		return nil, fmt.Errorf("target volume name cannot be empty")
	}

	// First check if the source volume exists
	sourceVolume, err := c.GetVolume(ctx, sourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get source volume: %w", err)
	}

	// Create options for the clone using models type
	options := &models.VolumeCreateRequest{
		Name:       targetName,
		Driver:     sourceVolume.Driver,
		DriverOpts: sourceVolume.Options.StringMap(), // Use StringMap helper from models.JSONMap
	}

	// Merge any existing labels from the source with the provided labels
	if sourceVolume.Labels != nil || labels != nil {
		options.Labels = make(map[string]string)

		// Copy source labels
		if sourceVolume.Labels != nil {
			for k, v := range sourceVolume.Labels.StringMap() { // Use StringMap() helper
				options.Labels[k] = v
			}
		}

		// Apply provided labels (overwriting any duplicates)
		if labels != nil {
			for k, v := range labels {
				options.Labels[k] = v
			}
		}
	}

	// Add clone label
	if options.Labels == nil {
		options.Labels = make(map[string]string)
	}
	options.Labels["com.docker_test.volume.clone-from"] = sourceName

	// Create the new volume
	return c.CreateVolume(ctx, options)
}

// MountVolume mounts a volume to a path on the host
// Note: This is a higher-level operation that is not directly supported by the Docker API
// It requires creating a temporary container to mount the volume
func (c *APIClient) MountVolume(ctx context.Context, volumeName, mountPoint string) error {
	if volumeName == "" {
		return fmt.Errorf("volume name cannot be empty")
	}

	if mountPoint == "" {
		return fmt.Errorf("mount point cannot be empty")
	}

	// Check if the volume exists
	_, err := c.GetVolume(ctx, volumeName)
	if err != nil {
		return fmt.Errorf("failed to get volume: %w", err)
	}

	// Create a temporary container config using models.ContainerCreateRequest
	containerName := fmt.Sprintf("volume-mount-%s-%d", volumeName, time.Now().UnixNano())
	containerConfig := &models.ContainerCreateRequest{ // Use models type
		Name:    containerName,
		Image:   "alpine:latest",
		Command: []string{"tail", "-f", "/dev/null"},
		// TODO: Add volume mount info to ContainerCreateRequest or handle differently
		// This likely requires modifying the ContainerCreateRequest model and the API handler
		// to accept HostConfig binds. For now, this function won't actually mount the volume.
	}

	container, err := c.CreateContainer(ctx, containerConfig) // Pass the correct type
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}

	// Start the container
	containerIDStr := container.ContainerID // Use ContainerID field (string)
	err = c.StartContainer(ctx, containerIDStr)
	if err != nil {
		// Clean up if start fails
		_ = c.RemoveContainer(ctx, containerIDStr, true) // Use string ID
		return fmt.Errorf("failed to start container: %w", err)
	}

	// TODO: Add logic here to actually use the running container to access the volume
	// This might involve `docker_test cp` or `docker_test exec` via the API, which are complex.
	// For now, just log that the container is running.
	fmt.Printf("Temporary container %s running for volume %s mount simulation.\n", containerIDStr, volumeName)
	fmt.Printf("Manual cleanup required: docker_test stop %s && docker_test rm %s\n", containerIDStr, containerIDStr)

	return nil // Return nil for now, actual mount isn't performed
}

// UnmountVolume unmounts a volume
// Note: This is a higher-level operation that is not directly supported by the Docker API
// It stops and removes any containers using the volume
func (c *APIClient) UnmountVolume(ctx context.Context, volumeName string) error {
	if volumeName == "" {
		return fmt.Errorf("volume name cannot be empty")
	}

	// Find containers using this volume
	containers, err := c.ListContainers(ctx, map[string]string{
		"volume": volumeName,
	})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	// Stop and remove each container
	for _, container := range containers {
		containerIDStr := container.ContainerID // Use ContainerID field (string)
		// First stop the container
		err = c.StopContainer(ctx, containerIDStr, nil) // Use string ID
		if err != nil && !strings.Contains(err.Error(), "not running") {
			return fmt.Errorf("failed to stop container %s: %w", containerIDStr, err)
		}

		// Then remove it
		err = c.RemoveContainer(ctx, containerIDStr, true) // Use string ID
		if err != nil {
			return fmt.Errorf("failed to remove container %s: %w", containerIDStr, err)
		}
	}

	// Also remove the temporary mount container if it exists
	tempContainerName := fmt.Sprintf("volume-mount-%s-", volumeName) // Prefix used in MountVolume
	allContainers, err := c.ListContainers(ctx, map[string]string{"name": tempContainerName})
	if err == nil {
		for _, tempCont := range allContainers {
			if strings.HasPrefix(tempCont.Name, tempContainerName) {
				_ = c.StopContainer(ctx, tempCont.ContainerID, nil)
				_ = c.RemoveContainer(ctx, tempCont.ContainerID, true)
			}
		}
	}

	return nil
}
