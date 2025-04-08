package converter

import (
	"context"
	"fmt" // Added import
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/docker_test/compose" // Removed unused import
	compose "github.com/compose-spec/compose-go/v2/types" // Import compose-go types
)

func TestConvertVolume(t *testing.T) {
	// Create sample volumes for testing
	volumes := map[string]compose.VolumeConfig{ // Use compose.VolumeConfig
		"data": {
			// Name:   "data", // Name is implicitly the map key for non-external
			Driver: "local",
		},
		"db_data": {
			// Name:   "db_data", // Name is implicitly the map key
			Driver: "local",
			DriverOpts: map[string]string{
				"type":   "nfs",
				"device": ":/path/to/dir",
				"o":      "addr=1.2.3.4,rw",
			},
			Labels: map[string]string{
				"com.example.description": "Database data volume",
			},
		},
		"external_volume": {
			// Name: "external_volume", // Name is implicitly the map key
			External: true, // Corrected: Use boolean directly
		},
		"external_volume_with_name": {
			Name:     "actual_external_volume", // Specify the external name here
			External: true,                     // Corrected: Use boolean directly
		},
	}

	// Test cases
	testCases := []struct {
		name       string
		volumeName string               // This is the key from the compose file
		volume     compose.VolumeConfig // Use compose.VolumeConfig
		options    ConvertVolumeOptions
		verify     func(t *testing.T, result *ConvertVolumeResult)
	}{
		{
			name:       "simple volume",
			volumeName: "data",
			volume:     volumes["data"],
			options:    ConvertVolumeOptions{},
			verify: func(t *testing.T, result *ConvertVolumeResult) {
				assert.Equal(t, "myproject_data", result.VolumeName) // Prefixed name
				assert.Equal(t, "local", result.VolumeCreateOptions.Driver)
				assert.False(t, result.IsExternal)
				assert.Contains(t, result.VolumeCreateOptions.Labels, "com.docker_test.compose.project")
				assert.Equal(t, "myproject", result.VolumeCreateOptions.Labels["com.docker_test.compose.project"])
				assert.Contains(t, result.VolumeCreateOptions.Labels, "com.docker_test.compose.volume")
				assert.Equal(t, "data", result.VolumeCreateOptions.Labels["com.docker_test.compose.volume"]) // Original name in label
			},
		},
		{
			name:       "volume with driver options and labels",
			volumeName: "db_data",
			volume:     volumes["db_data"],
			options:    ConvertVolumeOptions{},
			verify: func(t *testing.T, result *ConvertVolumeResult) {
				assert.Equal(t, "myproject_db_data", result.VolumeName) // Prefixed name
				assert.Equal(t, "local", result.VolumeCreateOptions.Driver)
				assert.False(t, result.IsExternal)

				// Check driver options
				assert.Equal(t, "nfs", result.VolumeCreateOptions.DriverOpts["type"])
				assert.Equal(t, ":/path/to/dir", result.VolumeCreateOptions.DriverOpts["device"])
				assert.Equal(t, "addr=1.2.3.4,rw", result.VolumeCreateOptions.DriverOpts["o"])

				// Check labels
				assert.Equal(t, "Database data volume", result.VolumeCreateOptions.Labels["com.example.description"])
				assert.Equal(t, "myproject", result.VolumeCreateOptions.Labels["com.docker_test.compose.project"])
				assert.Equal(t, "db_data", result.VolumeCreateOptions.Labels["com.docker_test.compose.volume"]) // Original name in label
			},
		},
		{
			name:       "external volume",
			volumeName: "external_volume", // Key from compose file
			volume:     volumes["external_volume"],
			options:    ConvertVolumeOptions{},
			verify: func(t *testing.T, result *ConvertVolumeResult) {
				assert.True(t, result.IsExternal)
				assert.Equal(t, "external_volume", result.ExternalName) // External name matches the key
				assert.Equal(t, "external_volume", result.VolumeName)   // VolumeName also matches the key for external
			},
		},
		{
			name:       "external volume with custom name",
			volumeName: "external_volume_with_name", // Key from compose file
			volume:     volumes["external_volume_with_name"],
			options:    ConvertVolumeOptions{},
			verify: func(t *testing.T, result *ConvertVolumeResult) {
				assert.True(t, result.IsExternal)
				assert.Equal(t, "actual_external_volume", result.ExternalName) // External name comes from the 'Name' field
				assert.Equal(t, "actual_external_volume", result.VolumeName)   // VolumeName also uses the explicit external name
			},
		},
		{
			name:       "volume that already exists",
			volumeName: "data",
			volume:     volumes["data"],
			options: ConvertVolumeOptions{
				CheckIfExists: func(name string) (bool, error) {
					return true, nil
				},
			},
			verify: func(t *testing.T, result *ConvertVolumeResult) {
				assert.True(t, result.IsExternal)                      // Should be treated as external if it exists
				assert.Equal(t, "myproject_data", result.VolumeName)   // Name should still be prefixed
				assert.Equal(t, "myproject_data", result.ExternalName) // External name is the prefixed name
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create converter
			converter := NewVolumeConverter("myproject", logrus.New())

			// Convert volume
			result, err := converter.ConvertVolume(context.Background(), tc.volumeName, tc.volume, tc.options)

			// Check for errors
			require.NoError(t, err)
			require.NotNil(t, result)

			// Verify result
			tc.verify(t, result)
		})
	}
}

func TestConvertVolumeWithErrors(t *testing.T) {
	// Test case with error in check exists function
	t.Run("error in check exists", func(t *testing.T) {
		// Create converter
		converter := NewVolumeConverter("myproject", logrus.New())

		// Create volume config
		volumeConfig := compose.VolumeConfig{ // Use compose.VolumeConfig
			// Name:   "test", // Implicitly "test"
			Driver: "local",
		}

		// Create options with failing check exists function
		options := ConvertVolumeOptions{
			CheckIfExists: func(name string) (bool, error) {
				return false, fmt.Errorf("failed to check if volume exists")
			},
		}

		// Convert volume
		result, err := converter.ConvertVolume(context.Background(), "test", volumeConfig, options)

		// Check for errors
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to check if volume exists")
	})

	// Test case with invalid external config (already handled by compose-go library parsing, difficult to test here directly)
	// t.Run("invalid external config", func(t *testing.T) { ... })
}
