package converter

import (
	"context"
	"fmt"
	"time"

	composetypes "github.com/compose-spec/compose-go/v2/types" // Added compose types import
	"github.com/docker/docker/api/types/volume"
	"github.com/sirupsen/logrus"
)

// VolumeConverter is responsible for converting Docker Compose volume definitions to Docker API structures
type VolumeConverter struct {
	logger      *logrus.Logger
	projectName string
}

// NewVolumeConverter creates a new volume converter
func NewVolumeConverter(projectName string, logger *logrus.Logger) *VolumeConverter {
	if logger == nil {
		logger = logrus.New()
	}

	return &VolumeConverter{
		logger:      logger,
		projectName: projectName,
	}
}

// ConvertVolumeOptions defines options for converting a volume
type ConvertVolumeOptions struct {
	// Timeout is the operation timeout
	Timeout time.Duration

	// Logger is the logger to use
	Logger *logrus.Logger

	// CheckIfExists is a function that checks if a volume already exists
	CheckIfExists func(string) (bool, error)
}

// ConvertVolumeResult contains the result of converting a volume
type ConvertVolumeResult struct {
	VolumeCreateOptions volume.CreateOptions // Use volume.CreateOptions
	VolumeName          string
	ExternalName        string
	IsExternal          bool
}

// ConvertVolume converts a Docker Compose volume to a Docker API volume create options
func (c *VolumeConverter) ConvertVolume(ctx context.Context, volumeName string, volumeConfig composetypes.VolumeConfig, options ConvertVolumeOptions) (*ConvertVolumeResult, error) { // Use composetypes.VolumeConfig
	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = c.logger
	}

	logger.WithField("volume", volumeName).Debug("Converting volume")

	// Create result
	result := &ConvertVolumeResult{
		VolumeName: volumeName,
		VolumeCreateOptions: volume.CreateOptions{ // Use volume.CreateOptions
			Driver: "local", // Default driver
		},
	}

	// Check if volume is external
	if volumeConfig.External { // Check the boolean value directly
		isExternal, externalName, err := ValidateExternalResource(volumeConfig.External, "volume", volumeName)
		if err != nil {
			return nil, fmt.Errorf("failed to validate external volume: %w", err)
		}

		if isExternal {
			result.IsExternal = true
			result.ExternalName = externalName
			return result, nil
		}
	}

	// Set volume name with project prefix if not external
	result.VolumeName = fmt.Sprintf("%s_%s", c.projectName, volumeName)

	// Check if volume already exists
	if options.CheckIfExists != nil {
		exists, err := options.CheckIfExists(result.VolumeName)
		if err != nil {
			return nil, fmt.Errorf("failed to check if volume exists: %w", err)
		}

		if exists {
			logger.WithField("volume", result.VolumeName).Debug("Volume already exists")
			result.IsExternal = true
			return result, nil
		}
	}

	// Set driver if specified
	if volumeConfig.Driver != "" {
		result.VolumeCreateOptions.Driver = volumeConfig.Driver
	}

	// Set driver options
	if volumeConfig.DriverOpts != nil {
		result.VolumeCreateOptions.DriverOpts = volumeConfig.DriverOpts
	}

	// Convert labels
	var err error
	result.VolumeCreateOptions.Labels, err = ConvertLabels(volumeConfig.Labels)
	if err != nil {
		return nil, fmt.Errorf("failed to convert labels: %w", err)
	}

	// Add project labels
	if result.VolumeCreateOptions.Labels == nil {
		result.VolumeCreateOptions.Labels = make(map[string]string)
	}
	result.VolumeCreateOptions.Labels["com.docker_test.compose.project"] = c.projectName
	result.VolumeCreateOptions.Labels["com.docker_test.compose.volume"] = volumeName

	return result, nil
}
