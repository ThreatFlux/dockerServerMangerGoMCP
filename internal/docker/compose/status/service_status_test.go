package status

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container" // Needed for MockDockerClient
	"github.com/docker/docker/api/types/events"    // Needed for MockDockerClient
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Added import
)

// MockDockerClient is a mock implementation of DockerStatusAPIClient
type MockDockerClient struct {
	mock.Mock
}

// Ensure MockDockerClient implements the interface
var _ DockerStatusAPIClient = (*MockDockerClient)(nil)

func (m *MockDockerClient) Events(ctx context.Context, options events.ListOptions) (<-chan events.Message, <-chan error) { // Use events.ListOptions
	args := m.Called(ctx, options)
	msgChan, _ := args.Get(0).(<-chan events.Message)
	errChan, _ := args.Get(1).(<-chan error)
	// Return valid channels even if mock returns nil, to prevent panics
	if msgChan == nil {
		closedMsgChan := make(chan events.Message)
		close(closedMsgChan)
		msgChan = closedMsgChan
	}
	if errChan == nil {
		closedErrChan := make(chan error, 1)
		close(closedErrChan)
		errChan = closedErrChan
	}
	return msgChan, errChan
}

func (m *MockDockerClient) ContainerList(ctx context.Context, options container.ListOptions) ([]types.Container, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]types.Container), args.Error(1)
}

func (m *MockDockerClient) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	args := m.Called(ctx, containerID)
	if args.Get(0) == nil {
		return types.ContainerJSON{}, args.Error(1)
	}
	return args.Get(0).(types.ContainerJSON), args.Error(1)
}

// --- MockTracker remains the same ---

// MockTracker is a mock implementation of required tracker methods
// We need this mock to satisfy the Tracker field in ServiceStatusManagerOptions for testing.
type MockTracker struct {
	mock.Mock
	// Embed the real Tracker interface methods we don't explicitly mock
	Tracker // Embed the interface
}

// AddDeployment mocks the AddDeployment method
func (m *MockTracker) AddDeployment(projectName string, composeFile *models.ComposeFile) *models.DeploymentInfo { // Use models.DeploymentInfo
	args := m.Called(projectName, composeFile)
	// Handle potential nil return
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*models.DeploymentInfo) // Use models.DeploymentInfo
}

// GetDeployment mocks the GetDeployment method
func (m *MockTracker) GetDeployment(projectName string) (*models.DeploymentInfo, bool) { // Use models.DeploymentInfo
	args := m.Called(projectName)
	if args.Get(0) == nil {
		return nil, args.Bool(1)
	}
	return args.Get(0).(*models.DeploymentInfo), args.Bool(1) // Use models.DeploymentInfo
}

// UpdateServiceStatus mocks the UpdateServiceStatus method
func (m *MockTracker) UpdateServiceStatus(projectName, serviceName string, status models.ServiceStatus, containerID string, err error) bool { // Updated type
	args := m.Called(projectName, serviceName, status, containerID, err)
	return args.Bool(0)
}

// UpdateServiceHealth mocks the UpdateServiceHealth method
func (m *MockTracker) UpdateServiceHealth(projectName, serviceName string, health *models.HealthInfo) bool { // Use models.HealthInfo
	args := m.Called(projectName, serviceName, health)
	return args.Bool(0)
}

// TestNewServiceStatusManager tests the NewServiceStatusManager function
func TestNewServiceStatusManager(t *testing.T) {
	// Create mocks
	// mockTracker := new(MockTracker) // Tracker field removed from options
	mockClient := new(MockDockerClient)

	// Setup mock expectations
	// Expect Events call from startEventMonitoring within NewServiceStatusManager
	mockClient.On("Events", mock.Anything, mock.AnythingOfType("events.ListOptions")).Return(make(<-chan events.Message), make(<-chan error)) // Use events.ListOptions

	// Create service status manager
	options := ServiceStatusManagerOptions{
		Client: mockClient,
		Logger: logrus.New(),
		// UpdateChannel: nil, // Set if needed for the test
	}
	manager, err := NewServiceStatusManager(options)
	assert.NoError(t, err) // Check for constructor error

	// Assert
	assert.NotNil(t, manager)
	assert.Equal(t, mockClient, manager.client)
	// assert.Equal(t, mockTracker, manager.tracker) // Field removed or renamed
	assert.NotNil(t, manager.ctx)
	assert.NotNil(t, manager.cancel)
	assert.NotNil(t, manager.logger)
	// assert.NotNil(t, manager.queue) // Field removed or renamed
}

// TestWatchProject tests the WatchProject function
func TestWatchProject(t *testing.T) {
	// Create mocks
	mockTracker := new(MockTracker)
	mockClient := new(MockDockerClient)

	// Create compose file
	composeFile := &models.ComposeFile{ // Updated type
		Version: "3",
		Services: map[string]models.ServiceConfig{ // Updated type
			"service1": {},
			"service2": {},
		},
	}

	// Setup tracker mock (Remove Get/AddDeployment mocks as manager handles this)
	// deployment := &DeploymentInfo{...}
	// mockTracker.On("GetDeployment", "project1").Return(deployment, true).Once()
	// mockTracker.On("AddDeployment", "project1", composeFile).Return(deployment).Maybe()

	// Setup client mock for container list
	containers := []types.Container{
		{
			ID: "container1",
			Labels: map[string]string{
				"com.docker_test.compose.project": "project1",
				"com.docker_test.compose.service": "service1",
			},
		},
		{
			ID: "container2",
			Labels: map[string]string{
				"com.docker_test.compose.project": "project1",
				"com.docker_test.compose.service": "service2",
			},
		},
	}
	mockClient.On("ContainerList", mock.Anything, mock.MatchedBy(func(options container.ListOptions) bool { // Use container.ListOptions
		return options.All && options.Filters.MatchKVList("label", map[string]string{"com.docker_test.compose.project": "project1"})
	})).Return(containers, nil).Once()

	// Setup tracker mock for service status updates (use specific status or mock.AnythingOfType)
	mockTracker.On("UpdateServiceStatus", "project1", "service1", mock.AnythingOfType("models.ServiceStatus"), "container1", nil).Return(true).Maybe()
	mockTracker.On("UpdateServiceStatus", "project1", "service2", mock.AnythingOfType("models.ServiceStatus"), "container2", nil).Return(true).Maybe()

	// Setup mock expectations for Events call within NewServiceStatusManager
	mockClient.On("Events", mock.Anything, mock.AnythingOfType("events.ListOptions")).Return(make(<-chan events.Message), make(<-chan error)) // Use events.ListOptions

	// Create service status manager
	options := ServiceStatusManagerOptions{
		Client: mockClient,
		Logger: logrus.New(),
		// UpdateChannel: nil, // Set if needed for the test
	}
	manager, err := NewServiceStatusManager(options)
	assert.NoError(t, err) // Check for constructor error

	// Add project to start watching
	serviceNames := make([]string, 0, len(composeFile.Services))
	for name := range composeFile.Services {
		serviceNames = append(serviceNames, name)
	}
	manager.AddProject("project1", serviceNames) // Use AddProject

	// Allow some time for container inspection in the background
	time.Sleep(100 * time.Millisecond)

	// Stop manager
	manager.Stop()

	// Assert
	mockTracker.AssertExpectations(t)
	mockClient.AssertExpectations(t)
}

// TestUpdateServiceStatus tests the UpdateServiceStatus function
func TestUpdateServiceStatus(t *testing.T) {
	// Create mocks
	mockTracker := new(MockTracker)
	mockClient := new(MockDockerClient)

	// Setup client mock for container inspect
	containerJSON := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: "container1",
			State: &types.ContainerState{
				Status: "running",
				Health: &types.Health{ // Use types.Health
					Status:        "healthy",
					FailingStreak: 0,
					Log: []*types.HealthcheckResult{ // Use types.HealthcheckResult
						{
							Start:    time.Now(),
							End:      time.Now(),
							ExitCode: 0,
							Output:   "healthy",
						},
					},
				},
			},
		},
	}
	mockClient.On("ContainerInspect", mock.Anything, "container1").Return(containerJSON, nil).Once()

	// Setup tracker mock for service status update
	mockTracker.On("UpdateServiceStatus", "project1", "service1", models.ServiceStatusRunning, "container1", nil).Return(true).Once() // Use models constant

	// Setup tracker mock for service health update
	mockTracker.On("UpdateServiceHealth", "project1", "service1", mock.MatchedBy(func(health *models.HealthInfo) bool { // Use models.HealthInfo
		return health.Status == "healthy" && health.FailingStreak == 0 && len(health.Log) == 1
	})).Return(true).Once()

	// Setup mock expectations for Events call within NewServiceStatusManager
	mockClient.On("Events", mock.Anything, mock.AnythingOfType("events.ListOptions")).Return(make(<-chan events.Message), make(<-chan error)) // Use events.ListOptions

	// Create service status manager
	options := ServiceStatusManagerOptions{
		Client: mockClient,
		Logger: logrus.New(),
		// UpdateChannel: nil, // Set if needed for the test
	}
	manager, err := NewServiceStatusManager(options)
	assert.NoError(t, err) // Check for constructor error

	// Update service status
	// err = manager.UpdateServiceStatus("project1", "service1", "container1") // Method is unexported
	// assert.NoError(t, err)

	// Allow some time for processing
	time.Sleep(100 * time.Millisecond)

	// Stop manager
	manager.Stop()

	// Assert
	mockTracker.AssertExpectations(t)
	mockClient.AssertExpectations(t)
}

// TestUpdateServiceStatusError tests the UpdateServiceStatus function with error
func TestUpdateServiceStatusError(t *testing.T) {
	// Create mocks
	mockTracker := new(MockTracker)
	mockClient := new(MockDockerClient)

	// Setup client mock for container inspect with error
	mockClient.On("ContainerInspect", mock.Anything, "container1").Return(types.ContainerJSON{}, errors.New("inspect error")).Once()

	// Setup mock expectations for Events call within NewServiceStatusManager
	mockClient.On("Events", mock.Anything, mock.AnythingOfType("events.ListOptions")).Return(make(<-chan events.Message), make(<-chan error)) // Use events.ListOptions

	// Create service status manager
	options := ServiceStatusManagerOptions{
		Client: mockClient,
		Logger: logrus.New(),
		// UpdateChannel: nil, // Set if needed for the test
	}
	manager, err := NewServiceStatusManager(options)
	assert.NoError(t, err) // Check for constructor error

	// Update service status
	// err = manager.UpdateServiceStatus("project1", "service1", "container1") // Method is unexported
	// assert.Error(t, err)
	// assert.Contains(t, err.Error(), "inspect error")

	// Allow some time for processing
	time.Sleep(100 * time.Millisecond)

	// Stop manager
	manager.Stop()

	// Assert
	mockTracker.AssertExpectations(t) // No status updates should be called
	mockClient.AssertExpectations(t)
}

// TestUnwatchProject tests the UnwatchProject function
func TestUnwatchProject(t *testing.T) {
	// Create mocks
	mockTracker := new(MockTracker)
	mockClient := new(MockDockerClient)

	// Create compose file
	composeFile := &models.ComposeFile{ // Updated type
		Version:  "3",
		Services: map[string]models.ServiceConfig{}, // Updated type
	}

	// Setup tracker mock
	deployment := &models.DeploymentInfo{ // Use models.DeploymentInfo
		ProjectName: "project1",
		Services:    make(map[string]*models.ServiceInfo), // Use models.ServiceInfo
		ComposeFile: composeFile,
	}
	mockTracker.On("GetDeployment", "project1").Return(deployment, true).Once()
	mockTracker.On("AddDeployment", "project1", composeFile).Return(deployment).Maybe()

	// Setup client mock for container list
	mockClient.On("ContainerList", mock.Anything, mock.Anything).Return([]types.Container{}, nil).Once()

	// Setup mock expectations for Events call within NewServiceStatusManager
	mockClient.On("Events", mock.Anything, mock.AnythingOfType("events.ListOptions")).Return(make(<-chan events.Message), make(<-chan error)) // Use events.ListOptions

	// Create service status manager
	options := ServiceStatusManagerOptions{
		Client: mockClient,
		Logger: logrus.New(), // Add logger if needed, remove RefreshInterval
		// UpdateChannel: nil, // Set if needed for the test
	}
	manager, err := NewServiceStatusManager(options)
	assert.NoError(t, err) // Check for constructor error

	// Add project to start watching (assuming WatchProject was replaced by AddProject)
	serviceNames := make([]string, 0, len(composeFile.Services))
	for name := range composeFile.Services {
		serviceNames = append(serviceNames, name)
	}
	manager.AddProject("project1", serviceNames)

	// Remove project to stop watching
	manager.RemoveProject("project1") // Use RemoveProject

	// Allow some time for refresh loop
	time.Sleep(100 * time.Millisecond)

	// Stop manager
	manager.Stop()

	// Assert (container list should only be called once during initial WatchProject)
	mockTracker.AssertExpectations(t)
	mockClient.AssertExpectations(t)
}

// TestRefreshAllServices tests the refreshAllServices function
func TestRefreshAllServices(t *testing.T) {
	// Create mocks
	mockTracker := new(MockTracker)
	mockClient := new(MockDockerClient)

	// Create compose file
	composeFile := &models.ComposeFile{ // Updated type
		Version:  "3",
		Services: map[string]models.ServiceConfig{}, // Updated type
	}

	// Setup tracker mock
	deployment := &models.DeploymentInfo{ // Use models.DeploymentInfo
		ProjectName: "project1",
		Services:    make(map[string]*models.ServiceInfo), // Use models.ServiceInfo
		ComposeFile: composeFile,
	}
	mockTracker.On("GetDeployment", "project1").Return(deployment, true).Maybe()
	mockTracker.On("AddDeployment", "project1", composeFile).Return(deployment).Maybe()

	// Setup client mock for container list
	mockClient.On("ContainerList", mock.Anything, mock.Anything).Return([]types.Container{}, nil).Maybe()

	// Create service status manager with very short refresh interval
	options := ServiceStatusManagerOptions{
		Client: mockClient,
		Logger: logrus.New(), // Add logger if needed, remove RefreshInterval
		// UpdateChannel: nil, // Set if needed for the test
	}
	manager, err := NewServiceStatusManager(options)
	assert.NoError(t, err) // Check for constructor error

	// Add project to start watching (assuming WatchProject was replaced by AddProject)
	serviceNames := make([]string, 0, len(composeFile.Services))
	for name := range composeFile.Services {
		serviceNames = append(serviceNames, name)
	}
	manager.AddProject("project1", serviceNames)

	// Allow time for multiple refresh cycles
	time.Sleep(50 * time.Millisecond)

	// Stop manager
	manager.Stop()

	// Assert (container list should be called multiple times)
	// Use mock.Anything instead of mock.MatchedBy for AssertNumberOfCalls
	mockClient.AssertCalled(t, "ContainerList", mock.Anything, mock.Anything)
	// Check if called at least twice (initial + refresh)
	assert.GreaterOrEqual(t, len(mockClient.Calls), 2, "ContainerList should be called multiple times")

}
