package resources

import (
	"context"
	"io" // Keep for Backup method signature
	"testing"

	"github.com/docker/docker/api/types/events" // Added import for events
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume" // Added import for volume types
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	network_service "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/network" // Alias for network service
	volume_service "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/volume"   // Alias for volume service
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// --- Mocks ---

// MockNetworkService implements network.Service interface
type MockNetworkService struct {
	mock.Mock
}

func (m *MockNetworkService) Create(ctx context.Context, name string, options network_service.CreateOptions) (*models.Network, error) { // Use alias
	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Network), args.Error(1)
}
func (m *MockNetworkService) Get(ctx context.Context, idOrName string, options network_service.GetOptions) (*models.Network, error) { // Use alias
	args := m.Called(ctx, idOrName, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Network), args.Error(1)
}
func (m *MockNetworkService) List(ctx context.Context, options network_service.ListOptions) ([]*models.Network, error) { // Use alias
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Network), args.Error(1)
}
func (m *MockNetworkService) Remove(ctx context.Context, idOrName string, options network_service.RemoveOptions) error { // Use alias
	args := m.Called(ctx, idOrName, options)
	return args.Error(0)
}
func (m *MockNetworkService) Prune(ctx context.Context, options network_service.PruneOptions) (network.PruneReport, error) { // Use alias and network.PruneReport
	args := m.Called(ctx, options)
	return args.Get(0).(network.PruneReport), args.Error(1) // Use network.PruneReport
}
func (m *MockNetworkService) Connect(ctx context.Context, networkIDOrName, containerIDOrName string, options network_service.ConnectOptions) error { // Added missing method
	args := m.Called(ctx, networkIDOrName, containerIDOrName, options)
	return args.Error(0)
}
func (m *MockNetworkService) Disconnect(ctx context.Context, networkIDOrName, containerIDOrName string, options network_service.DisconnectOptions) error { // Use alias
	args := m.Called(ctx, networkIDOrName, containerIDOrName, options)
	return args.Error(0)
}
func (m *MockNetworkService) InspectRaw(ctx context.Context, idOrName string) (network.Inspect, error) { // Use alias and network.Inspect
	args := m.Called(ctx, idOrName)
	return args.Get(0).(network.Inspect), args.Error(1) // Use network.Inspect
}
func (m *MockNetworkService) GetNetworkDrivers(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}
func (m *MockNetworkService) FindNetworkByContainer(ctx context.Context, containerIDOrName string, options network_service.ListOptions) ([]*models.Network, error) { // Use alias
	args := m.Called(ctx, containerIDOrName, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Network), args.Error(1)
}
func (m *MockNetworkService) FindNetworkByName(ctx context.Context, pattern string, options network_service.ListOptions) ([]*models.Network, error) { // Use alias
	args := m.Called(ctx, pattern, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Network), args.Error(1)
}
func (m *MockNetworkService) FindNetworkBySubnet(ctx context.Context, subnet string, options network_service.ListOptions) ([]*models.Network, error) { // Use alias
	args := m.Called(ctx, subnet, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Network), args.Error(1)
}

// MockVolumeService implements volume.Service interface
type MockVolumeService struct {
	mock.Mock
}

func (m *MockVolumeService) Create(ctx context.Context, name string, options volume_service.CreateOptions) (*models.Volume, error) { // Use alias
	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Volume), args.Error(1)
}
func (m *MockVolumeService) Get(ctx context.Context, name string, options volume_service.GetOptions) (*models.Volume, error) { // Use alias
	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Volume), args.Error(1)
}
func (m *MockVolumeService) List(ctx context.Context, options volume_service.ListOptions) ([]*models.Volume, error) { // Use alias
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Volume), args.Error(1)
}
func (m *MockVolumeService) Remove(ctx context.Context, name string, options volume_service.RemoveOptions) error { // Use alias
	args := m.Called(ctx, name, options)
	return args.Error(0)
}
func (m *MockVolumeService) Prune(ctx context.Context, options volume_service.PruneOptions) (*volume.PruneReport, error) { // Use alias and volume.PruneReport
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*volume.PruneReport), args.Error(1) // Use volume.PruneReport
}
func (m *MockVolumeService) Backup(ctx context.Context, name string, options volume_service.BackupOptions) (io.ReadCloser, error) { // Added missing method
	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}
func (m *MockVolumeService) Restore(ctx context.Context, name string, reader io.Reader, options volume_service.RestoreOptions) error { // Use alias
	args := m.Called(ctx, name, reader, options)
	return args.Error(0)
}
func (m *MockVolumeService) InspectRaw(ctx context.Context, name string) (volume.Volume, error) { // Use alias and volume.Volume
	args := m.Called(ctx, name)
	return args.Get(0).(volume.Volume), args.Error(1) // Use volume.Volume
}
func (m *MockVolumeService) GetEvents(ctx context.Context, options volume_service.EventOptions) (<-chan events.Message, <-chan error) { // Use alias and events.Message
	args := m.Called(ctx, options)
	var msgChan chan events.Message
	var errChan chan error
	if args.Get(0) != nil {
		msgChan = args.Get(0).(chan events.Message)
	}
	if args.Get(1) != nil {
		errChan = args.Get(1).(chan error)
	}
	return msgChan, errChan
}
func (m *MockVolumeService) Update(ctx context.Context, name string, metadata map[string]string, options volume_service.UpdateOptions) error { // Use alias
	args := m.Called(ctx, name, metadata, options)
	return args.Error(0)
}

// --- Test Setup ---

func setupResourceManagerTest(t *testing.T) (*Manager, *MockNetworkService, *MockVolumeService) {
	mockNetworkSvc := new(MockNetworkService)
	mockVolumeSvc := new(MockVolumeService)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	opts := ManagerOptions{Logger: logger}
	manager := NewManager(mockNetworkSvc, mockVolumeSvc, opts) // Correct arguments
	require.NotNil(t, manager)
	return manager, mockNetworkSvc, mockVolumeSvc
}

// --- Tests ---

func TestManager_CreateResources_Success(t *testing.T) {
	manager, mockNetworkSvc, mockVolumeSvc := setupResourceManagerTest(t)

	projectName := "myproject"
	composeFile := &models.ComposeFile{
		Networks: map[string]models.NetworkConfig{
			"frontend": {Name: "myproject_frontend", Driver: "bridge"},
			"backend":  {Name: "existing_backend", External: true}, // Removed ExternalName
		},
		Volumes: map[string]models.VolumeConfig{
			"db_data": {Name: "myproject_db_data", Driver: "local"},
			"logs":    {Name: "shared_logs", External: true}, // Removed ExternalName
		},
	}
	options := CreateResourcesOptions{ProjectName: projectName}

	// Mock network calls
	mockNetworkSvc.On("Get", mock.Anything, "myproject_frontend", mock.Anything).Return(nil, network_service.ErrNetworkNotFound).Once() // Expect Get for check
	mockNetworkSvc.On("Create", mock.Anything, "myproject_frontend", mock.Anything).Return(&models.Network{NetworkID: "net-front-id"}, nil).Once()
	mockNetworkSvc.On("Get", mock.Anything, "existing_backend", mock.Anything).Return(&models.Network{NetworkID: "net-back-id"}, nil).Once() // External exists

	// Mock volume calls
	mockVolumeSvc.On("Get", mock.Anything, "myproject_db_data", mock.Anything).Return(nil, volume_service.ErrVolumeNotFound).Once() // Expect Get for check
	mockVolumeSvc.On("Create", mock.Anything, "myproject_db_data", mock.Anything).Return(&models.Volume{VolumeID: "myproject_db_data"}, nil).Once()
	mockVolumeSvc.On("Get", mock.Anything, "shared_logs", mock.Anything).Return(&models.Volume{VolumeID: "shared_logs"}, nil).Once() // External exists

	err := manager.CreateResources(context.Background(), composeFile, options)

	require.NoError(t, err)
	mockNetworkSvc.AssertExpectations(t)
	mockVolumeSvc.AssertExpectations(t)
}

func TestManager_RemoveResources_Success(t *testing.T) {
	manager, mockNetworkSvc, mockVolumeSvc := setupResourceManagerTest(t)

	projectName := "myproject"
	composeFile := &models.ComposeFile{
		Networks: map[string]models.NetworkConfig{
			"frontend": {Name: "myproject_frontend"},
			"backend":  {Name: "existing_backend", External: true}, // Removed ExternalName
		},
		Volumes: map[string]models.VolumeConfig{
			"db_data": {Name: "myproject_db_data"},
			"logs":    {Name: "shared_logs", External: true}, // Removed ExternalName
		},
	}
	options := RemoveResourcesOptions{ProjectName: projectName} // KeepNetworks=false, KeepVolumes=false

	// Mock network calls (only non-external should be removed)
	mockNetworkSvc.On("Remove", mock.Anything, "myproject_frontend", mock.Anything).Return(nil).Once()

	// Mock volume calls (only non-external should be removed)
	mockVolumeSvc.On("Remove", mock.Anything, "myproject_db_data", mock.Anything).Return(nil).Once()

	err := manager.RemoveResources(context.Background(), composeFile, options)

	require.NoError(t, err)
	mockNetworkSvc.AssertExpectations(t)
	mockVolumeSvc.AssertExpectations(t)
}

func TestManager_ListResources_Success(t *testing.T) {
	manager, mockNetworkSvc, mockVolumeSvc := setupResourceManagerTest(t)

	projectName := "myproject"
	composeFile := &models.ComposeFile{
		Networks: map[string]models.NetworkConfig{
			"frontend": {Name: "myproject_frontend"},
			"backend":  {Name: "existing_backend", External: true}, // Removed ExternalName
		},
		Volumes: map[string]models.VolumeConfig{
			"db_data": {Name: "myproject_db_data"},
			"logs":    {Name: "shared_logs", External: true}, // Removed ExternalName
		},
	}
	options := ListResourcesOptions{ProjectName: projectName, IncludeExternalResources: true}

	// Mock network list
	mockNetworkSvc.On("List", mock.Anything, mock.Anything).Return([]*models.Network{
		{NetworkID: "net-front-id", DockerResource: models.DockerResource{Name: "myproject_frontend", Labels: models.JSONMap{"com.docker_test.compose.project": projectName}}}, // Correct literal
		{NetworkID: "net-back-id", DockerResource: models.DockerResource{Name: "existing_backend"}},                                                                            // Correct literal
		{NetworkID: "other-net-id", DockerResource: models.DockerResource{Name: "other_network"}},                                                                              // Correct literal
	}, nil).Once()

	// Mock volume list
	mockVolumeSvc.On("List", mock.Anything, mock.Anything).Return([]*models.Volume{
		{VolumeID: "myproject_db_data", DockerResource: models.DockerResource{Name: "myproject_db_data", Labels: models.JSONMap{"com.docker_test.compose.project": projectName}}}, // Correct literal
		{VolumeID: "shared_logs", DockerResource: models.DockerResource{Name: "shared_logs"}},                                                                                     // Correct literal
		{VolumeID: "other_volume", DockerResource: models.DockerResource{Name: "other_volume"}},                                                                                   // Correct literal
	}, nil).Once()

	resourceList, err := manager.ListResources(context.Background(), composeFile, options)

	require.NoError(t, err)
	require.NotNil(t, resourceList)
	assert.Len(t, resourceList.Networks, 2) // frontend + backend (external included)
	assert.Len(t, resourceList.Volumes, 2)  // db_data + logs (external included)

	// Verify names match expected (including external)
	foundFrontendNet := false
	foundBackendNet := false
	for _, n := range resourceList.Networks {
		if n.Name == "myproject_frontend" {
			foundFrontendNet = true
		}
		if n.Name == "existing_backend" {
			foundBackendNet = true
		}
	}
	assert.True(t, foundFrontendNet, "Frontend network not found in list")
	assert.True(t, foundBackendNet, "Backend network not found in list")

	foundDbVol := false
	foundLogsVol := false
	for _, v := range resourceList.Volumes {
		if v.Name == "myproject_db_data" {
			foundDbVol = true
		}
		if v.Name == "shared_logs" {
			foundLogsVol = true
		}
	}
	assert.True(t, foundDbVol, "DB data volume not found in list")
	assert.True(t, foundLogsVol, "Logs volume not found in list")

	mockNetworkSvc.AssertExpectations(t)
	mockVolumeSvc.AssertExpectations(t)
}

// Add more tests for error handling, edge cases, different options (KeepNetworks, etc.)
