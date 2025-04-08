package resources

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/volume"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// TestCreateComposeVolumes tests the createComposeVolumes function
func TestCreateComposeVolumes(t *testing.T) {
	// Create mocks
	mockNetworkService := new(MockNetworkService)
	mockVolumeService := new(MockVolumeService)

	// Create manager
	manager := NewManager(mockNetworkService, mockVolumeService, ManagerOptions{})

	// Create compose file with volumes
	composeFile := &models.ComposeFile{ // Use models type
		Version: "3",
		Volumes: map[string]models.VolumeConfig{ // Use models type
			"test-volume": {
				Driver: "local",
			},
			"external-volume": {
				External: true, // Keep as boolean for models.VolumeConfig
			},
		},
	}

	// Setup volume service mock for non-external volume
	mockVolumeService.On("Get", mock.Anything, "myproject_test-volume", mock.Anything).Return(nil, volume.ErrVolumeNotFound).Once()
	mockVolumeService.On("Create", mock.Anything, "myproject_test-volume", mock.Anything).Return(&models.Volume{
		DockerResource: models.DockerResource{Name: "myproject_test-volume"}, // Set Name within embedded DockerResource
	}, nil).Once()

	// Call the method
	err := manager.createComposeVolumes(context.Background(), composeFile, CreateResourcesOptions{
		ProjectName: "myproject",
		Timeout:     30 * time.Second,
	})

	// Assert
	assert.NoError(t, err)
	mockVolumeService.AssertExpectations(t)
}

// TestCreateComposeVolumesWithExisting tests createComposeVolumes with existing volumes
func TestCreateComposeVolumesWithExisting(t *testing.T) {
	// Create mocks
	mockNetworkService := new(MockNetworkService)
	mockVolumeService := new(MockVolumeService)

	// Create manager
	manager := NewManager(mockNetworkService, mockVolumeService, ManagerOptions{})

	// Create compose file with volumes
	composeFile := &models.ComposeFile{ // Use models type
		Version: "3",
		Volumes: map[string]models.VolumeConfig{ // Use models type
			"test-volume": {
				Driver: "local",
			},
		},
	}

	// Setup volume service mock to return existing volume
	mockVolumeService.On("Get", mock.Anything, "myproject_test-volume", mock.Anything).Return(&models.Volume{
		DockerResource: models.DockerResource{Name: "myproject_test-volume"}, // Set Name within embedded DockerResource
	}, nil).Once()

	// Call the method with skip existing option
	err := manager.createComposeVolumes(context.Background(), composeFile, CreateResourcesOptions{
		ProjectName:         "myproject",
		Timeout:             30 * time.Second,
		SkipExistingVolumes: true,
	})

	// Assert
	assert.NoError(t, err)
	mockVolumeService.AssertExpectations(t)

	// Reset mock
	mockVolumeService = new(MockVolumeService)
	manager = NewManager(mockNetworkService, mockVolumeService, ManagerOptions{})

	// Setup volume service mock again
	mockVolumeService.On("Get", mock.Anything, "myproject_test-volume", mock.Anything).Return(&models.Volume{
		DockerResource: models.DockerResource{Name: "myproject_test-volume"}, // Set Name within embedded DockerResource
	}, nil).Once()

	// Call the method without skip existing option
	err = manager.createComposeVolumes(context.Background(), composeFile, CreateResourcesOptions{
		ProjectName:         "myproject",
		Timeout:             30 * time.Second,
		SkipExistingVolumes: false,
	})

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	mockVolumeService.AssertExpectations(t)
}

// TestRemoveComposeVolumes tests the removeComposeVolumes function
func TestRemoveComposeVolumes(t *testing.T) {
	// Create mocks
	mockNetworkService := new(MockNetworkService)
	mockVolumeService := new(MockVolumeService)

	// Create manager
	manager := NewManager(mockNetworkService, mockVolumeService, ManagerOptions{})

	// Create compose file with volumes
	composeFile := &models.ComposeFile{ // Use models type
		Version: "3",
		Volumes: map[string]models.VolumeConfig{ // Use models type
			"test-volume": {
				Driver: "local",
			},
			"external-volume": {
				External: true, // Keep as boolean for models.VolumeConfig
			},
			"missing-volume": {
				Driver: "local",
			},
		},
	}

	// Setup volume service mock for existing volume
	mockVolumeService.On("Get", mock.Anything, "myproject_test-volume", mock.Anything).Return(&models.Volume{
		DockerResource: models.DockerResource{Name: "myproject_test-volume"}, // Set Name within embedded DockerResource
	}, nil).Once()
	mockVolumeService.On("Remove", mock.Anything, "myproject_test-volume", mock.Anything).Return(nil).Once()

	// Setup volume service mock for missing volume
	mockVolumeService.On("Get", mock.Anything, "myproject_missing-volume", mock.Anything).Return(nil, volume.ErrVolumeNotFound).Once()

	// Call the method
	err := manager.removeComposeVolumes(context.Background(), composeFile, RemoveResourcesOptions{
		ProjectName: "myproject",
		Timeout:     30 * time.Second,
		Force:       true,
	})

	// Assert
	assert.NoError(t, err)
	mockVolumeService.AssertExpectations(t)
}

// TestRemoveComposeVolumesWithExternal tests removeComposeVolumes with external volumes
func TestRemoveComposeVolumesWithExternal(t *testing.T) {
	// Create mocks
	mockNetworkService := new(MockNetworkService)
	mockVolumeService := new(MockVolumeService)

	// Create manager
	manager := NewManager(mockNetworkService, mockVolumeService, ManagerOptions{})

	// Create compose file with volumes
	composeFile := &models.ComposeFile{ // Use models type
		Version: "3",
		Volumes: map[string]models.VolumeConfig{ // Use models type
			"external-volume": {
				External: true, // Keep as boolean for models.VolumeConfig
			},
		},
	}

	// Setup volume service mock for external volume
	mockVolumeService.On("Get", mock.Anything, "external-volume", mock.Anything).Return(&models.Volume{
		DockerResource: models.DockerResource{Name: "external-volume"}, // Set Name within embedded DockerResource
	}, nil).Once()
	mockVolumeService.On("Remove", mock.Anything, "external-volume", mock.Anything).Return(nil).Once()

	// Call the method with remove external option
	err := manager.removeComposeVolumes(context.Background(), composeFile, RemoveResourcesOptions{
		ProjectName:             "myproject",
		Timeout:                 30 * time.Second,
		Force:                   true,
		RemoveExternalResources: true,
	})

	// Assert
	assert.NoError(t, err)
	mockVolumeService.AssertExpectations(t)
}

// TestListComposeVolumes tests the listComposeVolumes function
func TestListComposeVolumes(t *testing.T) {
	// Create mocks
	mockNetworkService := new(MockNetworkService)
	mockVolumeService := new(MockVolumeService)

	// Create manager
	manager := NewManager(mockNetworkService, mockVolumeService, ManagerOptions{})

	// Create compose file with volumes
	composeFile := &models.ComposeFile{ // Use models type
		Version: "3",
		Volumes: map[string]models.VolumeConfig{ // Use models type
			"test-volume": {
				Driver: "local",
			},
			"external-volume": {
				External: true, // Keep as boolean for models.VolumeConfig
			},
		},
	}

	// Setup volume service mock for listing volumes
	mockVolumeService.On("List", mock.Anything, mock.MatchedBy(func(options volume.ListOptions) bool {
		return options.Filters.MatchKVList("label", map[string]string{"com.docker_test.compose.project": "myproject"})
	})).Return([]*models.Volume{
		{
			DockerResource: models.DockerResource{
				Name: "myproject_test-volume",
				Labels: models.JSONMap{ // Initialize Labels within DockerResource
					"com.docker_test.compose.project": "myproject",
					"com.docker_test.compose.volume":  "test-volume",
				},
			},
		},
		{
			DockerResource: models.DockerResource{
				Name: "myproject_other-volume",
				Labels: models.JSONMap{ // Initialize Labels within DockerResource
					"com.docker_test.compose.project": "myproject",
					"com.docker_test.compose.volume":  "other-volume",
				},
			},
		},
	}, nil).Once()

	// Call the method
	volumes, err := manager.listComposeVolumes(context.Background(), composeFile, ListResourcesOptions{
		ProjectName: "myproject",
		Timeout:     30 * time.Second,
	})

	// Assert
	assert.NoError(t, err)
	assert.Len(t, volumes, 1)
	assert.Equal(t, "myproject_test-volume", volumes[0].Name)
	mockVolumeService.AssertExpectations(t)
}

// TestListComposeVolumesWithExternal tests listComposeVolumes with external volumes
func TestListComposeVolumesWithExternal(t *testing.T) {
	// Create mocks
	mockNetworkService := new(MockNetworkService)
	mockVolumeService := new(MockVolumeService)

	// Create manager
	manager := NewManager(mockNetworkService, mockVolumeService, ManagerOptions{})

	// Create compose file with volumes
	composeFile := &models.ComposeFile{ // Use models type
		Version: "3",
		Volumes: map[string]models.VolumeConfig{ // Use models type
			"test-volume": {
				Driver: "local",
			},
			"external-volume": {
				External: true, // Keep as boolean for models.VolumeConfig
			},
		},
	}

	// Setup volume service mock for listing volumes
	mockVolumeService.On("List", mock.Anything, mock.MatchedBy(func(options volume.ListOptions) bool {
		return options.Filters.MatchKVList("label", map[string]string{"com.docker_test.compose.project": "myproject"})
	})).Return([]*models.Volume{
		{
			DockerResource: models.DockerResource{
				Name: "myproject_test-volume",
				Labels: models.JSONMap{ // Initialize Labels within DockerResource
					"com.docker_test.compose.project": "myproject",
					"com.docker_test.compose.volume":  "test-volume",
				},
			},
		},
	}, nil).Once()

	// Setup volume service mock for getting external volume
	mockVolumeService.On("Get", mock.Anything, "external-volume", mock.Anything).Return(&models.Volume{
		DockerResource: models.DockerResource{Name: "external-volume"}, // Set Name within embedded DockerResource
	}, nil).Once()

	// Call the method with include external option
	volumes, err := manager.listComposeVolumes(context.Background(), composeFile, ListResourcesOptions{
		ProjectName:              "myproject",
		Timeout:                  30 * time.Second,
		IncludeExternalResources: true,
	})

	// Assert
	assert.NoError(t, err)
	assert.Len(t, volumes, 2)
	assert.Equal(t, "myproject_test-volume", volumes[0].Name)
	assert.Equal(t, "external-volume", volumes[1].Name)
	mockVolumeService.AssertExpectations(t)
}

// TestVolumeExists tests the volumeExists function
func TestVolumeExists(t *testing.T) {
	// Create mocks
	mockNetworkService := new(MockNetworkService)
	mockVolumeService := new(MockVolumeService)

	// Create manager
	manager := NewManager(mockNetworkService, mockVolumeService, ManagerOptions{})

	// Setup volume service mock for existing volume
	mockVolumeService.On("Get", mock.Anything, "existing-volume", mock.Anything).Return(&models.Volume{
		DockerResource: models.DockerResource{Name: "existing-volume"}, // Set Name within embedded DockerResource
	}, nil).Once()

	// Setup volume service mock for non-existing volume
	mockVolumeService.On("Get", mock.Anything, "non-existing-volume", mock.Anything).Return(nil, volume.ErrVolumeNotFound).Once()

	// Check existing volume
	exists, err := manager.volumeExists(context.Background(), "existing-volume")
	assert.NoError(t, err)
	assert.True(t, exists)

	// Check non-existing volume
	exists, err = manager.volumeExists(context.Background(), "non-existing-volume")
	assert.NoError(t, err)
	assert.False(t, exists)

	mockVolumeService.AssertExpectations(t)
}

// TestConvertVolumeConfig tests the convertVolumeConfig function
func TestConvertVolumeConfig(t *testing.T) {
	// Create mocks
	mockNetworkService := new(MockNetworkService)
	mockVolumeService := new(MockVolumeService)

	// Create manager
	manager := NewManager(mockNetworkService, mockVolumeService, ManagerOptions{})

	// Create volume config
	volumeConfig := models.VolumeConfig{ // Use models type
		Driver:     "local",
		DriverOpts: map[string]string{"opt1": "val1"},
	}

	// Convert volume config
	labels := map[string]string{"label1": "val1"}
	createOpts := manager.convertVolumeConfig(volumeConfig, labels)

	// Assert
	assert.Equal(t, "local", createOpts.Driver)
	assert.Equal(t, map[string]string{"opt1": "val1"}, createOpts.DriverOpts)
	assert.Equal(t, labels, createOpts.Labels)
}

// TestIsExternalResource tests the isExternalResource function
func TestIsExternalResource(t *testing.T) {
	// Test nil
	assert.False(t, isExternalResource(nil))

	// Test boolean
	assert.True(t, isExternalResource(true))
	assert.False(t, isExternalResource(false))

	// Test map
	assert.True(t, isExternalResource(map[string]string{"name": "ext"}))
	assert.True(t, isExternalResource(map[string]interface{}{"name": "ext"}))

	// Test external config
	// assert.True(t, isExternalResource(models.ExternalConfig{Name: "ext"})) // models.ExternalConfig is undefined
}

// TestGetResourceName tests the getResourceName function
func TestGetResourceName(t *testing.T) {
	// Test with project name only
	assert.Equal(t, "myproject_resource", getResourceName("myproject", "", "resource"))

	// Test with prefix only
	assert.Equal(t, "prefix-resource", getResourceName("", "prefix-", "resource"))

	// Test with both project name and prefix
	assert.Equal(t, "prefix-resource", getResourceName("myproject", "prefix-", "resource"))

	// Test with neither
	assert.Equal(t, "resource", getResourceName("", "", "resource"))
}

// TestGetExternalResourceName tests the getExternalResourceName function
func TestGetExternalResourceName(t *testing.T) {
	// Test with external config
	// assert.Equal(t, "external-name", getExternalResourceName(compose.ExternalConfig{Name: "external-name"}, "default-name")) // compose.ExternalConfig is undefined

	// Test with map
	assert.Equal(t, "external-name", getExternalResourceName(map[string]interface{}{"name": "external-name"}, "default-name"))
	assert.Equal(t, "external-name", getExternalResourceName(map[string]string{"name": "external-name"}, "default-name"))

	// Test with default
	assert.Equal(t, "default-name", getExternalResourceName(true, "default-name"))
}
