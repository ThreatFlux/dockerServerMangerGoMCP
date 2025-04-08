package compose

import (
	"context"
	"io"      // Keep one io
	"strings" // Keep one strings
	"testing"
	"time"

	// composetypes "github.com/compose-spec/compose-go/v2/types" // Removed unused import
	"github.com/docker/docker/api/types/events"
	dockernetwork "github.com/docker/docker/api/types/network"
	dockervolume "github.com/docker/docker/api/types/volume"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/docker_test/compose/status" // Removed unused import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/network"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/volume"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// MockNetworkService is a mock implementation of network.Service
type MockNetworkService struct {
	mock.Mock
}

// MockVolumeService is a mock implementation of volume.Service
type MockVolumeService struct {
	mock.Mock
}

// MockStatusTracker is a mock implementation of status.Tracker
type MockStatusTracker struct {
	mock.Mock
}

// Implement MockNetworkService methods
func (m *MockNetworkService) Create(ctx context.Context, name string, options network.CreateOptions) (*models.Network, error) {
	args := m.Called(ctx, name, options)
	return args.Get(0).(*models.Network), args.Error(1)
}

func (m *MockNetworkService) Get(ctx context.Context, idOrName string, options network.GetOptions) (*models.Network, error) {
	args := m.Called(ctx, idOrName, options)
	return args.Get(0).(*models.Network), args.Error(1)
}

func (m *MockNetworkService) List(ctx context.Context, options network.ListOptions) ([]*models.Network, error) {
	args := m.Called(ctx, options)
	return args.Get(0).([]*models.Network), args.Error(1)
}

func (m *MockNetworkService) Remove(ctx context.Context, idOrName string, options network.RemoveOptions) error {
	args := m.Called(ctx, idOrName, options)
	return args.Error(0)
}

func (m *MockNetworkService) Connect(ctx context.Context, networkID, containerID string, options network.ConnectOptions) error { // Use internal network.ConnectOptions
	args := m.Called(ctx, networkID, containerID, options)
	return args.Error(0)
}

func (m *MockNetworkService) Disconnect(ctx context.Context, networkID, containerID string, options network.DisconnectOptions) error { // Use internal network.DisconnectOptions
	args := m.Called(ctx, networkID, containerID, options)
	return args.Error(0)
}

func (m *MockNetworkService) Prune(ctx context.Context, options network.PruneOptions) (dockernetwork.PruneReport, error) { // Return value, not pointer
	args := m.Called(ctx, options)
	return args.Get(0).(dockernetwork.PruneReport), args.Error(1) // Return value
}

func (m *MockNetworkService) FindNetworkByContainer(ctx context.Context, containerID string, options network.ListOptions) ([]*models.Network, error) { // Corrected signature
	args := m.Called(ctx, containerID, options) // Pass options
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Network), args.Error(1) // Return slice
}

func (m *MockNetworkService) FindNetworkByName(ctx context.Context, name string, options network.ListOptions) ([]*models.Network, error) { // Corrected signature
	args := m.Called(ctx, name, options) // Pass options
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Network), args.Error(1) // Return slice
}

func (m *MockNetworkService) FindNetworkBySubnet(ctx context.Context, subnet string, options network.ListOptions) ([]*models.Network, error) { // Corrected signature
	args := m.Called(ctx, subnet, options) // Pass options
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Network), args.Error(1) // Return slice
}

func (m *MockNetworkService) GetNetworkDrivers(ctx context.Context) ([]string, error) { // Added missing method
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockNetworkService) InspectRaw(ctx context.Context, idOrName string) (dockernetwork.Inspect, error) { // Corrected signature
	args := m.Called(ctx, idOrName)
	return args.Get(0).(dockernetwork.Inspect), args.Error(1) // Use dockernetwork.Inspect
}

// Implement additional methods as needed

// Implement MockVolumeService methods
func (m *MockVolumeService) Create(ctx context.Context, name string, options volume.CreateOptions) (*models.Volume, error) {
	args := m.Called(ctx, name, options)
	return args.Get(0).(*models.Volume), args.Error(1)
}

func (m *MockVolumeService) Get(ctx context.Context, name string, options volume.GetOptions) (*models.Volume, error) {
	args := m.Called(ctx, name, options)
	return args.Get(0).(*models.Volume), args.Error(1)
}

func (m *MockVolumeService) List(ctx context.Context, options volume.ListOptions) ([]*models.Volume, error) {
	args := m.Called(ctx, options)
	return args.Get(0).([]*models.Volume), args.Error(1)
}

func (m *MockVolumeService) Remove(ctx context.Context, name string, options volume.RemoveOptions) error {
	args := m.Called(ctx, name, options)
	return args.Error(0)
}

func (m *MockVolumeService) Backup(ctx context.Context, name string, options volume.BackupOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, name, options)
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockVolumeService) Restore(ctx context.Context, name string, reader io.Reader, options volume.RestoreOptions) error {
	args := m.Called(ctx, name, reader, options)
	return args.Error(0)
}

func (m *MockVolumeService) InspectRaw(ctx context.Context, name string) (dockervolume.Volume, error) { // Use dockervolume.Volume
	args := m.Called(ctx, name)
	return args.Get(0).(dockervolume.Volume), args.Error(1) // Use dockervolume.Volume
}

func (m *MockVolumeService) Prune(ctx context.Context, options volume.PruneOptions) (*dockervolume.PruneReport, error) { // Use dockervolume.PruneReport
	args := m.Called(ctx, options)
	return args.Get(0).(*dockervolume.PruneReport), args.Error(1) // Use dockervolume.PruneReport
}

func (m *MockVolumeService) GetEvents(ctx context.Context, options volume.EventOptions) (<-chan events.Message, <-chan error) { // Use events.Message
	args := m.Called(ctx, options)
	return args.Get(0).(<-chan events.Message), args.Get(1).(<-chan error) // Use events.Message
}

func (m *MockVolumeService) Update(ctx context.Context, name string, labels map[string]string, options volume.UpdateOptions) error { // Corrected signature
	args := m.Called(ctx, name, labels, options) // Pass labels
	return args.Error(0)
}

// Implement additional methods as needed

// Implement MockStatusTracker methods
// Corrected AddDeployment signature to match interface (likely *models.ComposeFile)
func (m *MockStatusTracker) AddDeployment(projectName string, composeFile *models.ComposeFile) *models.DeploymentInfo {
	args := m.Called(projectName, composeFile)
	// Handle potential nil return
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*models.DeploymentInfo)
}

func (m *MockStatusTracker) GetDeployment(projectName string) (*models.DeploymentInfo, bool) { // Use models.DeploymentInfo
	args := m.Called(projectName)
	// Handle potential nil return
	if args.Get(0) == nil {
		return nil, args.Bool(1)
	}
	return args.Get(0).(*models.DeploymentInfo), args.Bool(1) // Use models.DeploymentInfo
}

func (m *MockStatusTracker) RemoveDeployment(projectName string) bool {
	args := m.Called(projectName)
	return args.Bool(0)
}

func (m *MockStatusTracker) StartOperation(projectName string, operationType models.OperationType, details map[string]interface{}) (*models.OperationInfo, bool) { // Use models types
	args := m.Called(projectName, operationType, details)
	// Handle potential nil return
	if args.Get(0) == nil {
		return nil, args.Bool(1)
	}
	return args.Get(0).(*models.OperationInfo), args.Bool(1) // Use models.OperationInfo
}

func (m *MockStatusTracker) CompleteOperation(projectName string, operationStatus models.OperationStatus, err error) bool { // Use models.OperationStatus
	args := m.Called(projectName, operationStatus, err)
	return args.Bool(0)
}

// Add GetDeployments to satisfy the interface
func (m *MockStatusTracker) GetDeployments() []*models.DeploymentInfo {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).([]*models.DeploymentInfo)
}

// Add GetServiceContainerIDs to satisfy the interface
func (m *MockStatusTracker) GetServiceContainerIDs(projectName, serviceName string) ([]string, bool) {
	args := m.Called(projectName, serviceName)
	if args.Get(0) == nil {
		return nil, args.Bool(1)
	}
	return args.Get(0).([]string), args.Bool(1)
}

// Add GetServiceContainerID to satisfy the interface
func (m *MockStatusTracker) GetServiceContainerID(projectName, serviceName string) (string, bool) {
	args := m.Called(projectName, serviceName)
	return args.String(0), args.Bool(1)
}

// Add GetServiceStatus to satisfy the interface
func (m *MockStatusTracker) GetServiceStatus(projectName, serviceName string) (models.ServiceStatus, bool) {
	args := m.Called(projectName, serviceName)
	// Handle potential nil return for status
	status, ok := args.Get(0).(models.ServiceStatus)
	if !ok {
		// Return a default or zero value if the type assertion fails or Get(0) is nil
		return models.ServiceStatusUnknown, args.Bool(1)
	}
	return status, args.Bool(1)
}

// Add Stop method to satisfy the interface
func (m *MockStatusTracker) Stop() {
	m.Called()
}

// Add Unwatch method to satisfy the interface (correct signature)
func (m *MockStatusTracker) Unwatch(updates <-chan *models.DeploymentInfo) {
	m.Called(updates)
}

// Add UpdateDeploymentStatus method to satisfy the interface
func (m *MockStatusTracker) UpdateDeploymentStatus(projectName string, status models.DeploymentStatus, err error) bool {
	args := m.Called(projectName, status, err)
	return args.Bool(0)
}

// Add UpdateServiceHealth method to satisfy the interface
func (m *MockStatusTracker) UpdateServiceHealth(projectName, serviceName string, health *models.HealthInfo) bool {
	args := m.Called(projectName, serviceName, health)
	return args.Bool(0)
}

// Add UpdateServiceStatus method to satisfy the interface
func (m *MockStatusTracker) UpdateServiceStatus(projectName, serviceName string, status models.ServiceStatus, containerID string, err error) bool {
	args := m.Called(projectName, serviceName, status, containerID, err)
	return args.Bool(0)
}

// Add Watch method to satisfy the interface (correct signature)
func (m *MockStatusTracker) Watch() <-chan *models.DeploymentInfo {
	args := m.Called()
	// Handle potential nil return
	if args.Get(0) == nil {
		// Return a closed channel if mock returns nil
		ch := make(chan *models.DeploymentInfo)
		close(ch)
		return ch
	}
	return args.Get(0).(<-chan *models.DeploymentInfo)
}

// Implement additional methods as needed

// TestNewComposeService tests the NewComposeService function
func TestNewComposeService(t *testing.T) {
	// Create mocks
	mockNetworkService := new(MockNetworkService)
	mockVolumeService := new(MockVolumeService)
	mockStatusTracker := new(MockStatusTracker)
	logger := logrus.New()

	// Create compose service
	service, err := NewComposeService(ComposeServiceOptions{
		NetworkService: mockNetworkService,
		VolumeService:  mockVolumeService,
		StatusTracker:  mockStatusTracker,
		Logger:         logger,
	})

	// Assert
	require.NoError(t, err)
	require.NotNil(t, service)

	// Assert concrete type
	_, ok := service.(*ComposeService)
	assert.True(t, ok)
}

// TestParse tests the Parse function
func TestParse(t *testing.T) {
	// Create mocks
	mockNetworkService := new(MockNetworkService)
	mockVolumeService := new(MockVolumeService)
	mockStatusTracker := new(MockStatusTracker)
	logger := logrus.New()

	// Create compose service
	service, err := NewComposeService(ComposeServiceOptions{
		NetworkService: mockNetworkService,
		VolumeService:  mockVolumeService,
		StatusTracker:  mockStatusTracker,
		Logger:         logger,
	})
	require.NoError(t, err)

	// Create test compose file content
	composeContent := `
version: '3'
services:
  web:
    image: nginx
    ports:
      - "80:80"
  db:
    image: postgres
    depends_on:
      - web
`

	// Parse compose file
	reader := strings.NewReader(composeContent)
	composeFile, err := service.Parse(context.Background(), reader, ParseOptions{})

	// Assert
	require.NoError(t, err)
	require.NotNil(t, composeFile)
	assert.Equal(t, "3", composeFile.Version)
	assert.Len(t, composeFile.Services, 2)
	assert.Contains(t, composeFile.Services, "web")
	assert.Contains(t, composeFile.Services, "db")
	assert.Equal(t, "nginx", composeFile.Services["web"].Image)
	assert.Equal(t, "postgres", composeFile.Services["db"].Image)
}

// TestValidate tests the Validate function
func TestValidate(t *testing.T) {
	// Create mocks
	mockNetworkService := new(MockNetworkService)
	mockVolumeService := new(MockVolumeService)
	mockStatusTracker := new(MockStatusTracker)
	logger := logrus.New()

	// Create compose service
	service, err := NewComposeService(ComposeServiceOptions{
		NetworkService: mockNetworkService,
		VolumeService:  mockVolumeService,
		StatusTracker:  mockStatusTracker,
		Logger:         logger,
	})
	require.NoError(t, err)

	// Create valid compose file
	validComposeFile := &models.ComposeFile{ // Revert to models.ComposeFile
		Version: "3",
		Services: map[string]models.ServiceConfig{ // Revert to models.ServiceConfig
			"web": {
				Image: "nginx",
			},
		},
	}

	// Validate valid compose file
	err = service.Validate(context.Background(), validComposeFile) // Pass the correct type
	assert.NoError(t, err)

	// Create invalid compose file (no version)
	invalidComposeFile := &models.ComposeFile{ // Revert to models.ComposeFile
		Services: map[string]models.ServiceConfig{ // Revert to models.ServiceConfig
			"web": {
				Image: "nginx",
			},
		},
	}

	// Validate invalid compose file
	err = service.Validate(context.Background(), invalidComposeFile)
	assert.Error(t, err)
}

// TestPsFunction tests the Ps function
func TestPsFunction(t *testing.T) {
	// Create mocks
	mockNetworkService := new(MockNetworkService)
	mockVolumeService := new(MockVolumeService)
	mockStatusTracker := new(MockStatusTracker)
	logger := logrus.New()

	// Create compose service
	service, err := NewComposeService(ComposeServiceOptions{
		NetworkService: mockNetworkService,
		VolumeService:  mockVolumeService,
		StatusTracker:  mockStatusTracker,
		Logger:         logger,
	})
	require.NoError(t, err)

	// Create test compose file
	composeFile := &models.ComposeFile{ // Revert to models.ComposeFile
		Version: "3",
		Services: map[string]models.ServiceConfig{ // Revert to models.ServiceConfig
			"web": {
				Image: "nginx",
			},
			"db": {
				Image: "postgres",
			},
		},
	}

	// Create test deployment info
	startTime := time.Now()
	deploymentInfo := &models.DeploymentInfo{ // Use models.DeploymentInfo
		ProjectName: "test-project",
		Status:      models.DeploymentStatusRunning, // Use models constant
		StartTime:   startTime,
		Services: map[string]*models.ServiceInfo{ // Use models.ServiceInfo
			"web": {
				Name:         "web",
				ContainerIDs: []string{"web-container-id"},
				Status:       models.ServiceStatusRunning, // Use models constant
				StartTime:    startTime,
			},
			"db": {
				Name:         "db",
				ContainerIDs: []string{"db-container-id"},
				Status:       models.ServiceStatusStopped, // Use models constant
				StartTime:    startTime,
			},
		},
	}

	// Setup status tracker mock
	mockStatusTracker.On("GetDeployment", "test-project").Return(deploymentInfo, true).Once()

	// Call Ps function
	deploymentStatus, err := service.Ps(context.Background(), composeFile, PsOptions{
		ProjectName: "test-project",
		All:         true,
	})

	// Assert
	require.NoError(t, err)
	require.NotNil(t, deploymentStatus)
	assert.Equal(t, "test-project", deploymentStatus.ProjectName)
	assert.Equal(t, startTime, deploymentStatus.StartTime)
	assert.True(t, deploymentStatus.IsRunning)
	assert.Len(t, deploymentStatus.Services, 2)
	assert.Contains(t, deploymentStatus.Services, "web")
	assert.Contains(t, deploymentStatus.Services, "db")
	assert.Equal(t, "web", deploymentStatus.Services["web"].Name)
	assert.Equal(t, "web-container-id", deploymentStatus.Services["web"].ContainerID)
	assert.Equal(t, string(models.ServiceStatusRunning), deploymentStatus.Services["web"].Status) // Use models constant
	assert.True(t, deploymentStatus.Services["web"].IsRunning)
	assert.Equal(t, "db", deploymentStatus.Services["db"].Name)
	assert.Equal(t, "db-container-id", deploymentStatus.Services["db"].ContainerID)
	assert.Equal(t, string(models.ServiceStatusStopped), deploymentStatus.Services["db"].Status) // Use models constant
	assert.False(t, deploymentStatus.Services["db"].IsRunning)

	// Setup status tracker mock for missing deployment
	mockStatusTracker.On("GetDeployment", "nonexistent").Return(nil, false).Once()

	// Call Ps function with nonexistent project
	_, err = service.Ps(context.Background(), composeFile, PsOptions{
		ProjectName: "nonexistent",
	})

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Verify mocks
	mockStatusTracker.AssertExpectations(t)
}
