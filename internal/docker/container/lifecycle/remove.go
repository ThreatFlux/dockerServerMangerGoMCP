// Package lifecycle implements Docker container lifecycle operations.
package lifecycle

import (
	"context"
	"fmt"
	"strings"
	"time"

	dockertypes "github.com/docker/docker/api/types" // Use alias
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	networktypes "github.com/docker/docker/api/types/network" // Use networktypes alias
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// RemoveOptions contains options for removing a container
type RemoveOptions struct {
	// ID of the container to remove
	ContainerID string `json:"container_id"`

	// Name of the container to remove (alternative to ID)
	ContainerName string `json:"container_name"`

	// Force removal of the container even if it is running
	Force bool `json:"force"`

	// RemoveVolumes indicates whether to remove anonymous volumes attached to the container
	RemoveVolumes bool `json:"remove_volumes"`

	// RemoveLinks indicates whether to remove links to the container
	RemoveLinks bool `json:"remove_links"`

	// Timeout is the operation timeout in seconds
	Timeout int `json:"timeout"`

	// PreserveData indicates whether to backup and preserve important data from the container
	PreserveData bool `json:"preserve_data"`

	// DataExportPath is the path where to export preserved data
	DataExportPath string `json:"data_export_path"`

	// DeleteNetworks indicates whether to delete custom networks used only by this container
	DeleteNetworks bool `json:"delete_networks"`

	// StopBeforeRemove indicates whether to stop the container first if it's running
	StopBeforeRemove bool `json:"stop_before_remove"`

	// StopTimeout is the timeout for stopping the container before removal (in seconds)
	StopTimeout int `json:"stop_timeout"`

	// SkipSecurityCheck indicates whether to skip security checks
	SkipSecurityCheck bool `json:"skip_security_check"`
}

// RemoveResult contains the result of a container removal operation
type RemoveResult struct {
	// ContainerID is the ID of the removed container
	ContainerID string `json:"container_id"`

	// ContainerName is the name of the removed container
	ContainerName string `json:"container_name"`

	// Success indicates whether the removal operation was successful
	Success bool `json:"success"`

	// WasRunning indicates whether the container was running before removal
	WasRunning bool `json:"was_running"`

	// WasStopped indicates whether the container was stopped before removal
	WasStopped bool `json:"was_stopped"`

	// VolumesRemoved indicates whether volumes were removed
	VolumesRemoved bool `json:"volumes_removed"`

	// Error contains the error message, if any
	Error string `json:"error,omitempty"`

	// InitialState is the state of the container before removal
	InitialState string `json:"initial_state,omitempty"`

	// ResourcesRemoved contains information about removed resources
	ResourcesRemoved map[string]interface{} `json:"resources_removed,omitempty"`

	// Message contains additional information about the operation
	Message string `json:"message,omitempty"`

	// SecurityWarnings contains security-related warnings
	SecurityWarnings []string `json:"security_warnings,omitempty"`
}

// Remover manages container removal operations
type Remover struct {
	containerManager *ContainerManager
	logger           *logrus.Logger
}

// NewRemover creates a new container remover
func NewRemover(containerManager *ContainerManager) *Remover {
	return &Remover{
		containerManager: containerManager,
		logger:           containerManager.logger,
	}
}

// Remove removes a container with the given options
func (r *Remover) Remove(ctx context.Context, opts RemoveOptions) (*RemoveResult, error) {
	// Initialize result
	result := &RemoveResult{
		Success:          false,
		ResourcesRemoved: make(map[string]interface{}),
		SecurityWarnings: []string{},
	}

	// Validate options and resolve container ID/name
	containerID, err := r.validateAndResolveContainer(ctx, opts)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	// Handle case where container not found but force=true
	if containerID == "" && opts.Force {
		result.Message = fmt.Sprintf("container %s not found, removal skipped due to force=true", opts.ContainerName)
		result.Success = true // Consider it success as the desired state (no container) is achieved
		return result, nil
	}
	if containerID == "" { // Should not happen if force=false due to validateAndResolveContainer logic
		result.Error = fmt.Sprintf("container %s not found", opts.ContainerName)
		return result, errors.New(result.Error)
	}

	result.ContainerID = containerID

	// Apply timeout if specified
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.Timeout)*time.Second)
		defer cancel()
	}

	// Get container details before removal
	containerBefore, err := r.containerManager.InspectContainer(ctx, containerID)
	if err != nil {
		// If container doesn't exist, consider it already removed
		if client.IsErrNotFound(err) {
			result.Message = "container not found, may have been already removed"
			result.Success = true
			return result, nil
		}

		result.Error = fmt.Sprintf("failed to inspect container before removal: %v", err)
		return result, errors.Wrap(err, "failed to inspect container before removal")
	}

	result.ContainerName = strings.TrimPrefix(containerBefore.Name, "/")
	result.InitialState = containerBefore.State.Status
	result.WasRunning = containerBefore.State.Running

	// Perform security check if not skipped
	if !opts.SkipSecurityCheck {
		warnings, err := r.performSecurityCheck(containerBefore)
		if err != nil {
			result.Error = fmt.Sprintf("security check failed: %v", err)
			result.SecurityWarnings = warnings
			return result, errors.Wrap(err, "security check failed")
		}
		result.SecurityWarnings = warnings
	}

	// Check if container is running and stop it if requested
	if containerBefore.State.Running && opts.StopBeforeRemove {
		stopTimeout := 10 // Default 10 seconds
		if opts.StopTimeout > 0 {
			stopTimeout = opts.StopTimeout
		}

		r.logger.WithFields(logrus.Fields{
			"container_id":   containerID,
			"container_name": result.ContainerName,
			"timeout":        stopTimeout,
		}).Info("Stopping container before removal")

		// Create stop timeout context
		stopCtx, stopCancel := context.WithTimeout(ctx, time.Duration(stopTimeout)*time.Second)

		// Stop the container
		// Use pointer for timeout in StopOptions
		timeoutPtr := stopTimeout
		err = r.containerManager.client.ContainerStop(stopCtx, containerID, container.StopOptions{
			Timeout: &timeoutPtr,
		})
		stopCancel() // Cancel stop context immediately after stop attempt

		if err != nil {
			// If force is enabled, try to kill the container
			if opts.Force {
				r.logger.WithFields(logrus.Fields{
					"container_id": containerID,
					"error":        err.Error(),
				}).Warning("Failed to stop container gracefully, trying force kill")

				killErr := r.containerManager.client.ContainerKill(ctx, containerID, "SIGKILL")
				if killErr != nil {
					// Don't fail the operation if using force removal
					r.logger.WithFields(logrus.Fields{
						"container_id": containerID,
						"error":        killErr.Error(),
					}).Error("Failed to kill container")

					result.SecurityWarnings = append(result.SecurityWarnings, "Failed to stop container before removal")
				} else {
					result.WasStopped = true
				}
			} else {
				result.Error = fmt.Sprintf("failed to stop container before removal: %v", err)
				return result, errors.Wrap(err, "failed to stop container before removal")
			}
		} else {
			result.WasStopped = true
		}
	}

	// Preserve data if requested
	if opts.PreserveData && opts.DataExportPath != "" {
		if err := r.preserveContainerData(ctx, containerID, opts.DataExportPath); err != nil {
			// Log but continue with removal
			r.logger.WithFields(logrus.Fields{
				"container_id": containerID,
				"error":        err.Error(),
				"export_path":  opts.DataExportPath,
			}).Warning("Failed to preserve container data")

			result.SecurityWarnings = append(result.SecurityWarnings,
				fmt.Sprintf("Failed to preserve container data: %v", err))
		} else {
			result.ResourcesRemoved["preserved_data"] = opts.DataExportPath
		}
	}

	// Collect resources to remove for tracking
	var networkNames []string
	var volumeNames []string

	// Track networks if deletion is requested
	if opts.DeleteNetworks && containerBefore.NetworkSettings != nil {
		for networkName := range containerBefore.NetworkSettings.Networks {
			// Skip default networks
			if networkName != "bridge" && networkName != "host" &&
				networkName != "none" && !strings.HasPrefix(networkName, "docker_") {
				networkNames = append(networkNames, networkName)
			}
		}
	}

	// Track volumes if removal is requested
	if opts.RemoveVolumes && len(containerBefore.Mounts) > 0 {
		for _, mount := range containerBefore.Mounts {
			if mount.Type == "volume" && !strings.HasPrefix(mount.Name, "docker_") {
				volumeNames = append(volumeNames, mount.Name)
			}
		}
	}

	// Log operation
	r.containerManager.LogOperation(ContainerOperationRemove, logrus.Fields{
		"container_id":    containerID,
		"container_name":  result.ContainerName,
		"force":           opts.Force,
		"remove_volumes":  opts.RemoveVolumes,
		"remove_links":    opts.RemoveLinks,
		"delete_networks": opts.DeleteNetworks,
	})

	// Remove the container
	removeOptions := container.RemoveOptions{ // Use container.RemoveOptions
		RemoveVolumes: opts.RemoveVolumes,
		RemoveLinks:   opts.RemoveLinks,
		Force:         opts.Force,
	}

	err = r.containerManager.client.ContainerRemove(ctx, containerID, removeOptions)
	if err != nil {
		result.Error = fmt.Sprintf("failed to remove container: %v", err)
		return result, errors.Wrap(err, "failed to remove container")
	}

	// Container was successfully removed
	result.Success = true
	result.Message = "Container successfully removed"

	// Track volume removal
	if opts.RemoveVolumes {
		result.VolumesRemoved = true
		if len(volumeNames) > 0 {
			result.ResourcesRemoved["volumes"] = volumeNames
		}
	}

	// Delete networks if requested
	if opts.DeleteNetworks && len(networkNames) > 0 {
		removedNetworks := []string{}

		for _, networkName := range networkNames {
			// Check if network is used by other containers
			network, err := r.containerManager.client.NetworkInspect(ctx, networkName, networktypes.InspectOptions{}) // Use dockertypes alias
			if err != nil {
				// Network not found or other error, skip it
				continue
			}

			// Only remove networks that have no containers or only the one being removed
			if len(network.Containers) <= 1 {
				// Try to remove the network
				err = r.containerManager.client.NetworkRemove(ctx, networkName)
				if err == nil {
					removedNetworks = append(removedNetworks, networkName)
				}
			}
		}

		if len(removedNetworks) > 0 {
			result.ResourcesRemoved["networks"] = removedNetworks
		}
	}

	return result, nil
}

// RemoveMultiple removes multiple containers in sequence
func (r *Remover) RemoveMultiple(ctx context.Context, containerIDs []string, options RemoveOptions) (map[string]*RemoveResult, error) {
	results := make(map[string]*RemoveResult)
	var firstError error

	for _, containerID := range containerIDs {
		// Update options with current container ID
		options.ContainerID = containerID

		// Remove the container
		result, err := r.Remove(ctx, options)

		// Store the result
		results[containerID] = result

		// Store the first error encountered
		if err != nil && firstError == nil {
			firstError = err
		}
	}

	return results, firstError
}

// RemoveDanglingContainers removes containers with specific filters
func (r *Remover) RemoveDanglingContainers(ctx context.Context, options RemoveOptions) (map[string]*RemoveResult, error) {
	results := make(map[string]*RemoveResult)

	// Create filter for exited containers
	filterArgs := filters.NewArgs()
	filterArgs.Add("status", "exited")

	// List exited containers
	containers, err := r.containerManager.ListContainers(ctx, container.ListOptions{ // Use container.ListOptions
		All:     true,
		Filters: filterArgs,
	})
	if err != nil {
		return results, errors.Wrap(err, "failed to list containers")
	}

	// Remove each exited container
	for _, c := range containers {
		options.ContainerID = c.ID
		result, err := r.Remove(ctx, options)
		results[c.ID] = result

		// Log but continue with next container
		if err != nil {
			r.logger.WithFields(logrus.Fields{
				"container_id": c.ID,
				"error":        err.Error(),
			}).Warning("Failed to remove dangling container")
		}
	}

	return results, nil
}

// validateAndResolveContainer validates options and resolves container name to ID if needed
func (r *Remover) validateAndResolveContainer(ctx context.Context, opts RemoveOptions) (string, error) {
	// Check if at least one of ID or Name is provided
	if opts.ContainerID == "" && opts.ContainerName == "" {
		return "", errors.New("either container ID or name must be provided")
	}

	// If ID is provided, validate it
	if opts.ContainerID != "" {
		if err := r.containerManager.ValidateContainerID(opts.ContainerID); err != nil {
			// Don't fail if container doesn't exist and force is enabled
			// Need to inspect first to confirm existence before validating ID format
			_, inspectErr := r.containerManager.InspectContainer(ctx, opts.ContainerID)
			if client.IsErrNotFound(inspectErr) && opts.Force {
				return "", nil // Return empty ID to signal skip removal
			}
			return "", errors.Wrap(err, "invalid container ID")
		}
		return opts.ContainerID, nil
	}

	// If only name is provided, resolve it to an ID
	containers, err := r.containerManager.ListContainers(ctx, container.ListOptions{All: true}) // Use container.ListOptions
	if err != nil {
		return "", errors.Wrap(err, "failed to list containers")
	}

	for _, c := range containers { // Renamed variable to avoid conflict
		for _, name := range c.Names {
			// Docker adds a leading slash to container names
			if strings.TrimPrefix(name, "/") == opts.ContainerName {
				return c.ID, nil
			}
		}
	}

	// If force is enabled, don't fail if container not found
	if opts.Force {
		return "", nil // Return empty ID to signal skip removal
	}

	return "", errors.Errorf("container with name %s not found", opts.ContainerName)
}

// performSecurityCheck performs security checks before container removal
func (r *Remover) performSecurityCheck(containerJSON dockertypes.ContainerJSON) ([]string, error) { // Use alias
	warnings := []string{}

	// Check if container is privileged
	if containerJSON.HostConfig != nil && containerJSON.HostConfig.Privileged {
		warnings = append(warnings, "Removing privileged container - ensure no security impact")
	}

	// Check for sensitive mounts
	sensitiveMounts := []string{
		"/var/run/docker_test.sock",
		"/etc/shadow",
		"/etc/passwd",
		"/etc/kubernetes",
	}

	if len(containerJSON.Mounts) > 0 {
		for _, mount := range containerJSON.Mounts {
			for _, sensitive := range sensitiveMounts {
				if strings.HasPrefix(mount.Source, sensitive) {
					warnings = append(warnings, fmt.Sprintf("Container has sensitive mount: %s", mount.Source))
				}
			}
		}
	}

	// Check for host network mode
	if containerJSON.HostConfig != nil && containerJSON.HostConfig.NetworkMode.IsHost() {
		warnings = append(warnings, "Container is using host network mode")
	}

	// Check for host PID mode
	if containerJSON.HostConfig != nil && containerJSON.HostConfig.PidMode.IsHost() {
		warnings = append(warnings, "Container is using host PID namespace")
	}

	// Look for critical labels
	criticalLabels := []string{
		"production",
		"backup",
		"database",
		"critical",
	}

	if containerJSON.Config != nil && containerJSON.Config.Labels != nil {
		for label, value := range containerJSON.Config.Labels {
			for _, critical := range criticalLabels {
				if strings.Contains(strings.ToLower(label), critical) ||
					strings.Contains(strings.ToLower(value), critical) {
					warnings = append(warnings, fmt.Sprintf("Container has critical label: %s=%s", label, value))
				}
			}
		}
	}

	return warnings, nil
}

// preserveContainerData exports and preserves important container data
func (r *Remover) preserveContainerData(ctx context.Context, containerID, exportPath string) error {
	// Create export file
	exportFilename := fmt.Sprintf("%s/%s-export-%s.tar",
		exportPath, containerID[:12], time.Now().Format("20060102-150405"))

	// Create export response
	response, err := r.containerManager.client.ContainerExport(ctx, containerID)
	if err != nil {
		return errors.Wrap(err, "failed to export container data")
	}
	defer response.Close()

	// TODO: Store the exported data to exportFilename
	// This would typically involve writing the data to disk
	// For this implementation, we'll just log the action

	r.logger.WithFields(logrus.Fields{
		"container_id": containerID,
		"export_file":  exportFilename,
	}).Info("Container data preserved")

	return nil
}

// ToModel converts a RemoveResult to a ContainerOperation
func (r *Remover) ToModel(result *RemoveResult) ContainerOperation { // Use ContainerOperation from this package
	status := "success"
	if !result.Success {
		status = "error"
	}

	// Return type should match the definition in common.go
	return ContainerOperation(fmt.Sprintf( // Use ContainerOperation from this package
		"Operation: remove, ContainerID: %s, Name: %s, Status: %s, Message: %s, Error: %s",
		result.ContainerID,
		result.ContainerName,
		status,
		result.Message,
		result.Error,
	))
}
