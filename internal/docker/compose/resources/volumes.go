// Package resources provides functionality for managing Docker Compose resources
package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	// "github.com/docker_test/docker_test/api/types" // Removed unused import
	"github.com/docker/docker/api/types/filters"
	// "github.com/sirupsen/logrus" // Removed unused import
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/docker_test/compose" // Removed unused import
	volumeSvc "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/volume"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// createComposeVolumes creates the volumes for a Docker Compose file
func (m *Manager) createComposeVolumes(ctx context.Context, composeFile *models.ComposeFile, options CreateResourcesOptions) error { // Updated type
	// Skip if no volumes are defined
	if len(composeFile.Volumes) == 0 {
		m.logger.Info("No volumes defined in Docker Compose file")
		return nil
	}

	// Keep track of created volumes for cleanup in case of error
	createdVolumes := make([]string, 0)

	// Create each volume
	for volumeName, volumeConfig := range composeFile.Volumes {
		// Skip if external
		if isExternalResource(volumeConfig.External) {
			m.logger.WithField("volume", volumeName).Info("Skipping external volume")
			continue
		}

		// Generate volume name with prefix if provided
		fullVolumeName := getResourceName(options.ProjectName, options.NamePrefix, volumeName)

		// Check if volume already exists
		exists, err := m.volumeExists(ctx, fullVolumeName)
		if err != nil {
			m.logger.WithError(err).WithField("volume", fullVolumeName).Error("Failed to check if volume exists")
			return fmt.Errorf("failed to check if volume %s exists: %w", fullVolumeName, err)
		}

		// Skip if volume exists and we're configured to skip
		if exists && options.SkipExistingVolumes {
			m.logger.WithField("volume", fullVolumeName).Info("Volume already exists, skipping")
			continue
		}

		// Return error if volume exists and we're not configured to skip
		if exists && !options.SkipExistingVolumes {
			m.logger.WithField("volume", fullVolumeName).Error("Volume already exists")
			return fmt.Errorf("volume %s already exists", fullVolumeName)
		}

		// Prepare labels
		labels := make(map[string]string)
		// Add project label
		labels["com.docker_test.compose.project"] = options.ProjectName
		// Add volume label
		labels["com.docker_test.compose.volume"] = volumeName
		// Add additional labels
		for k, v := range options.Labels {
			labels[k] = v
		}

		// Convert compose volume config to volume create options
		createOpts := m.convertVolumeConfig(volumeConfig, labels)

		// Create the volume
		m.logger.WithField("volume", fullVolumeName).Info("Creating volume")
		_, err = m.volumeService.Create(ctx, fullVolumeName, createOpts)
		if err != nil {
			m.logger.WithError(err).WithField("volume", fullVolumeName).Error("Failed to create volume")

			// Attempt to cleanup already created volumes
			m.cleanupVolumes(ctx, createdVolumes)

			return fmt.Errorf("failed to create volume %s: %w", fullVolumeName, err)
		}

		// Add to list of created volumes
		createdVolumes = append(createdVolumes, fullVolumeName)
	}

	return nil
}

// removeComposeVolumes removes the volumes for a Docker Compose file
func (m *Manager) removeComposeVolumes(ctx context.Context, composeFile *models.ComposeFile, options RemoveResourcesOptions) error { // Updated type
	// Skip if no volumes are defined
	if len(composeFile.Volumes) == 0 {
		m.logger.Info("No volumes defined in Docker Compose file")
		return nil
	}

	// Track errors to remove as many volumes as possible even if some fail
	var errs []error

	// Remove each volume
	for volumeName, volumeConfig := range composeFile.Volumes {
		// Skip if external and not configured to remove external resources
		if isExternalResource(volumeConfig.External) && !options.RemoveExternalResources {
			m.logger.WithField("volume", volumeName).Info("Skipping external volume")
			continue
		}

		// Generate volume name with prefix if provided
		fullVolumeName := getResourceName(options.ProjectName, options.NamePrefix, volumeName)

		// Check if volume exists
		exists, err := m.volumeExists(ctx, fullVolumeName)
		if err != nil {
			m.logger.WithError(err).WithField("volume", fullVolumeName).Error("Failed to check if volume exists")
			errs = append(errs, fmt.Errorf("failed to check if volume %s exists: %w", fullVolumeName, err))
			continue
		}

		// Skip if volume doesn't exist
		if !exists {
			m.logger.WithField("volume", fullVolumeName).Info("Volume doesn't exist, skipping")
			continue
		}

		// Remove the volume
		m.logger.WithField("volume", fullVolumeName).Info("Removing volume")
		removeOpts := volumeSvc.RemoveOptions{
			Force:   options.Force,
			Timeout: options.Timeout,
			Logger:  options.Logger,
		}
		err = m.volumeService.Remove(ctx, fullVolumeName, removeOpts)
		if err != nil {
			m.logger.WithError(err).WithField("volume", fullVolumeName).Error("Failed to remove volume")
			errs = append(errs, fmt.Errorf("failed to remove volume %s: %w", fullVolumeName, err))
			continue
		}
	}

	// Return combined error if any occurred
	if len(errs) > 0 {
		// Combine error messages
		errMsgs := make([]string, len(errs))
		for i, err := range errs {
			errMsgs[i] = err.Error()
		}
		return fmt.Errorf("failed to remove volumes: %s", strings.Join(errMsgs, "; "))
	}

	return nil
}

// listComposeVolumes lists the volumes for a Docker Compose file
func (m *Manager) listComposeVolumes(ctx context.Context, composeFile *models.ComposeFile, options ListResourcesOptions) ([]*models.Volume, error) { // Updated type
	// Skip if no volumes are defined
	if len(composeFile.Volumes) == 0 {
		m.logger.Info("No volumes defined in Docker Compose file")
		return []*models.Volume{}, nil
	}

	// Create a filter for the project
	filterArgs := filters.NewArgs()
	filterArgs.Add("label", fmt.Sprintf("com.docker_test.compose.project=%s", options.ProjectName))

	// List all volumes for the project
	listOpts := volumeSvc.ListOptions{
		Filters: filterArgs,
		Timeout: options.Timeout,
		Logger:  options.Logger,
	}
	volumes, err := m.volumeService.List(ctx, listOpts)
	if err != nil {
		m.logger.WithError(err).Error("Failed to list volumes")
		return nil, fmt.Errorf("failed to list volumes: %w", err)
	}

	// Filter volumes to only those in the compose file
	result := make([]*models.Volume, 0)
	for _, volume := range volumes {
		// Extract volume name from labels
		volumeNameLabel, ok := volume.Labels["com.docker_test.compose.volume"]
		if !ok {
			// Skip volumes without the volume label
			continue
		}

		// Check if the volume is defined in the compose file
		// Iterate because composeFile.Volumes is map[string]models.VolumeConfig
		found := false
		for nameInCompose := range composeFile.Volumes { // Fixed: Iterate over keys
			if nameInCompose == volumeNameLabel {
				found = true
				break
			}
		}
		if found {
			result = append(result, volume)
		}
	}

	// Add external volumes if requested
	if options.IncludeExternalResources {
		for volumeName, volumeConfig := range composeFile.Volumes {
			// Skip if not external
			if !isExternalResource(volumeConfig.External) {
				continue
			}

			// Get external volume name
			externalName := getExternalResourceName(volumeConfig.External, volumeName)

			// Try to get the volume
			getOpts := volumeSvc.GetOptions{
				Timeout: options.Timeout,
				Logger:  options.Logger,
			}
			volume, err := m.volumeService.Get(ctx, externalName, getOpts)
			if err != nil {
				// Skip if volume not found
				// TODO: Maybe log this?
				continue
			}

			// Add the volume to the result
			result = append(result, volume)
		}
	}

	return result, nil
}

// convertVolumeConfig converts a compose volume config to volume create options
func (m *Manager) convertVolumeConfig(volumeConfig models.VolumeConfig, labels map[string]string) volumeSvc.CreateOptions { // Updated type
	// Create options
	opts := volumeSvc.CreateOptions{
		Driver:     volumeConfig.Driver,
		DriverOpts: volumeConfig.DriverOpts,
		Labels:     labels, // Start with manager-provided labels
	}

	// Add labels from volume config itself (handle different possible types)
	if volumeConfig.Labels != nil {
		switch lbls := volumeConfig.Labels.(type) {
		case map[string]string:
			for k, v := range lbls {
				opts.Labels[k] = v // Add/overwrite with volume-specific labels
			}
		case map[string]interface{}:
			for k, v := range lbls {
				if strVal, ok := v.(string); ok {
					opts.Labels[k] = strVal
				}
			}
		case []string: // list of "key=value"
			for _, label := range lbls {
				parts := strings.SplitN(label, "=", 2)
				if len(parts) == 2 {
					opts.Labels[parts[0]] = parts[1]
				}
			}
		case []interface{}: // list of interface{}, hopefully strings "key=value"
			for _, labelInterface := range lbls {
				if label, ok := labelInterface.(string); ok {
					parts := strings.SplitN(label, "=", 2)
					if len(parts) == 2 {
						opts.Labels[parts[0]] = parts[1]
					}
				}
			}
		default:
			m.logger.Warnf("Unsupported type for volume labels: %T", volumeConfig.Labels)
		}
	}

	return opts
}

// cleanupVolumes removes volumes in case of error during creation
func (m *Manager) cleanupVolumes(ctx context.Context, volumes []string) {
	for _, volume := range volumes {
		m.logger.WithField("volume", volume).Info("Cleaning up volume")
		removeOpts := volumeSvc.RemoveOptions{
			Force:   true,
			Timeout: 30 * time.Second,
			Logger:  m.logger,
		}
		if err := m.volumeService.Remove(ctx, volume, removeOpts); err != nil {
			m.logger.WithError(err).WithField("volume", volume).Error("Failed to clean up volume")
		}
	}
}

// volumeExists checks if a volume exists
func (m *Manager) volumeExists(ctx context.Context, name string) (bool, error) {
	// Try to get the volume
	getOpts := volumeSvc.GetOptions{
		Timeout: 10 * time.Second,
		Logger:  m.logger,
	}
	_, err := m.volumeService.Get(ctx, name, getOpts)
	if err != nil {
		// Check if the error is a not found error
		if errors.Is(err, volumeSvc.ErrVolumeNotFound) {
			return false, nil
		}
		// Return other errors
		return false, err
	}
	// Volume exists
	return true, nil
}

// Helper functions are now defined in helpers.go
