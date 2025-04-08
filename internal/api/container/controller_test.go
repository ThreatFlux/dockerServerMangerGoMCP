package container

import (
	// "bytes" // Removed unused import
	"context"
	"encoding/json"
	"errors"
	// "fmt" // Removed unused import
	"io" // Added import
	"net/http"
	"net/http/httptest"
	"testing"
	// "time" // Removed unused import

	apitypes "github.com/docker/docker/api/types" // Import types with alias
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network" // Added import
	"github.com/docker/docker/client"            // Import client for APIClient interface
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	auth_test "github.com/threatflux/dockerServerMangerGoMCP/internal/auth" // Use main auth package for MockService
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"
	container_service "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/container" // Alias for container service package
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// --- Mocks ---

// MockContainerService implements container.Service interface
type MockContainerService struct {
	mock.Mock
}

// Implement all methods from container.Service interface

func (m *MockContainerService) ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, platform string, containerName string) (container.CreateResponse, error) { // Corrected signature
	args := m.Called(ctx, config, hostConfig, networkingConfig, platform, containerName)
	return args.Get(0).(container.CreateResponse), args.Error(1)
}
func (m *MockContainerService) ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}
func (m *MockContainerService) ContainerStop(ctx context.Context, containerID string, options container.StopOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}
func (m *MockContainerService) ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}
func (m *MockContainerService) ContainerInspect(ctx context.Context, containerID string) (apitypes.ContainerJSON, error) {
	args := m.Called(ctx, containerID)
	return args.Get(0).(apitypes.ContainerJSON), args.Error(1)
}
func (m *MockContainerService) ContainerList(ctx context.Context, options container.ListOptions) ([]apitypes.Container, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]apitypes.Container), args.Error(1)
}
func (m *MockContainerService) NetworkConnect(ctx context.Context, networkID, containerID string, config *network.EndpointSettings) error {
	args := m.Called(ctx, networkID, containerID, config)
	return args.Error(0)
}

// --- Methods previously defined in this interface ---
func (m *MockContainerService) List(ctx context.Context, opts container_service.ListOptions) ([]models.Container, error) { // Use models.Container and correct options type
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Container), args.Error(1)
}
func (m *MockContainerService) Get(ctx context.Context, containerID string) (*models.Container, error) { // Use models.Container
	args := m.Called(ctx, containerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Container), args.Error(1)
}
func (m *MockContainerService) Create(ctx context.Context, opts container_service.CreateOptions) (*models.Container, error) { // Use models.Container and correct options type
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Container), args.Error(1)
}
func (m *MockContainerService) Start(ctx context.Context, containerID string, opts container_service.StartOptions) error { // Use correct options type
	args := m.Called(ctx, containerID, opts)
	return args.Error(0)
}
func (m *MockContainerService) Stop(ctx context.Context, containerID string, opts container_service.StopOptions) error { // Use correct options type
	args := m.Called(ctx, containerID, opts)
	return args.Error(0)
}
func (m *MockContainerService) Restart(ctx context.Context, containerID string, opts container_service.RestartOptions) error { // Use correct options type
	args := m.Called(ctx, containerID, opts)
	return args.Error(0)
}
func (m *MockContainerService) Kill(ctx context.Context, containerID string, opts container_service.KillOptions) error { // Use correct options type
	args := m.Called(ctx, containerID, opts)
	return args.Error(0)
}
func (m *MockContainerService) Remove(ctx context.Context, containerID string, opts container_service.RemoveOptions) error { // Use correct options type
	args := m.Called(ctx, containerID, opts)
	return args.Error(0)
}
func (m *MockContainerService) Logs(ctx context.Context, containerID string, opts container_service.LogOptions) (io.ReadCloser, error) { // Use correct options type
	args := m.Called(ctx, containerID, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}
func (m *MockContainerService) Stats(ctx context.Context, containerID string, opts container_service.StatsOptions) (models.ContainerStats, error) { // Use correct options type
	args := m.Called(ctx, containerID, opts)
	val, _ := args.Get(0).(models.ContainerStats)
	return val, args.Error(1)
}
func (m *MockContainerService) StreamStats(ctx context.Context, containerID string, opts container_service.StatsOptions) (<-chan models.ContainerStats, <-chan error) { // Use correct options type
	args := m.Called(ctx, containerID, opts)
	var statsCh chan models.ContainerStats
	var errCh chan error
	if args.Get(0) != nil {
		statsCh = args.Get(0).(chan models.ContainerStats)
	}
	if args.Get(1) != nil {
		errCh = args.Get(1).(chan error)
	}
	return statsCh, errCh
}
func (m *MockContainerService) Prune(ctx context.Context, opts container_service.PruneOptions) (container_service.PruneResult, error) { // Use correct options and result types
	args := m.Called(ctx, opts)
	val, _ := args.Get(0).(container_service.PruneResult)
	return val, args.Error(1)
}
func (m *MockContainerService) Rename(ctx context.Context, containerID, newName string) error {
	args := m.Called(ctx, containerID, newName)
	return args.Error(0)
}
func (m *MockContainerService) Update(ctx context.Context, containerID string, opts container_service.UpdateOptions) error { // Use correct options type
	args := m.Called(ctx, containerID, opts)
	return args.Error(0)
}
func (m *MockContainerService) Pause(ctx context.Context, containerID string) error {
	args := m.Called(ctx, containerID)
	return args.Error(0)
}
func (m *MockContainerService) Unpause(ctx context.Context, containerID string) error {
	args := m.Called(ctx, containerID)
	return args.Error(0)
}
func (m *MockContainerService) Commit(ctx context.Context, containerID string, opts container_service.CommitOptions) (string, error) { // Use correct options type
	args := m.Called(ctx, containerID, opts)
	return args.String(0), args.Error(1)
}
func (m *MockContainerService) Wait(ctx context.Context, containerID string, opts container_service.WaitOptions) (<-chan container.WaitResponse, <-chan error) { // Use correct options type
	args := m.Called(ctx, containerID, opts)
	var bodyChan chan container.WaitResponse
	var errChan chan error
	if args.Get(0) != nil {
		bodyChan = args.Get(0).(chan container.WaitResponse)
	}
	if args.Get(1) != nil {
		errChan = args.Get(1).(chan error)
	}
	return bodyChan, errChan
}
func (m *MockContainerService) Exec(ctx context.Context, containerID string, opts container_service.ExecOptions) (container_service.ExecResult, error) { // Use correct options and result types
	args := m.Called(ctx, containerID, opts)
	val, _ := args.Get(0).(container_service.ExecResult)
	return val, args.Error(1)
}
func (m *MockContainerService) Top(ctx context.Context, containerID string, psArgs string) (container_service.TopResult, error) { // Use correct result type
	args := m.Called(ctx, containerID, psArgs)
	val, _ := args.Get(0).(container_service.TopResult)
	return val, args.Error(1)
}
func (m *MockContainerService) Changes(ctx context.Context, containerID string) ([]container_service.ChangeItem, error) { // Use correct result type
	args := m.Called(ctx, containerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]container_service.ChangeItem), args.Error(1)
}
func (m *MockContainerService) GetArchive(ctx context.Context, containerID string, opts container_service.ArchiveOptions) (io.ReadCloser, models.ResourceStat, error) { // Use correct options and result types
	args := m.Called(ctx, containerID, opts)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	stat, _ := args.Get(1).(models.ResourceStat)
	return reader, stat, args.Error(2)
}
func (m *MockContainerService) PutArchive(ctx context.Context, containerID string, path string, content io.Reader) error {
	args := m.Called(ctx, containerID, path, content)
	return args.Error(0)
}

// MockManager implements the docker.Manager interface for testing
type MockManager struct {
	mock.Mock
}

func (m *MockManager) GetClient() (*client.Client, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	val, ok := args.Get(0).(*client.Client)
	if !ok {
		return nil, args.Error(1)
	}
	return val, args.Error(1)
}
func (m *MockManager) GetWithContext(ctx context.Context) (*client.Client, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	val, ok := args.Get(0).(*client.Client)
	if !ok {
		return nil, args.Error(1)
	}
	return val, args.Error(1)
}
func (m *MockManager) Ping(ctx context.Context) (apitypes.Ping, error) {
	args := m.Called(ctx)
	pingVal, _ := args.Get(0).(apitypes.Ping)
	return pingVal, args.Error(1)
}
func (m *MockManager) IsInitialized() bool {
	args := m.Called()
	return args.Bool(0)
}
func (m *MockManager) IsClosed() bool {
	args := m.Called()
	return args.Bool(0)
}
func (m *MockManager) GetConfig() docker.ClientConfig {
	args := m.Called()
	cfg, _ := args.Get(0).(docker.ClientConfig)
	return cfg
}
func (m *MockManager) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockContainerRepository defined locally as it's only used here now
type MockContainerRepository struct {
	mock.Mock
}

func (m *MockContainerRepository) Create(ctx context.Context, container *models.Container) error {
	args := m.Called(ctx, container)
	return args.Error(0)
}
func (m *MockContainerRepository) GetByID(ctx context.Context, id uint) (*models.Container, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Container), args.Error(1)
}
func (m *MockContainerRepository) GetByContainerID(ctx context.Context, containerID string) (*models.Container, error) {
	args := m.Called(ctx, containerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Container), args.Error(1)
}
func (m *MockContainerRepository) FindByIDOrName(ctx context.Context, identifier string) (*models.Container, error) {
	args := m.Called(ctx, identifier)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Container), args.Error(1)
}
func (m *MockContainerRepository) List(ctx context.Context, userID uint) ([]models.Container, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Container), args.Error(1)
}
func (m *MockContainerRepository) Update(ctx context.Context, container *models.Container) error {
	args := m.Called(ctx, container)
	return args.Error(0)
}
func (m *MockContainerRepository) Delete(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// setupTestController sets up the Gin engine and controller for testing
func setupTestController(t *testing.T) (*Controller, *gin.Engine, *MockContainerService, *MockManager) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs

	mockContainerService := new(MockContainerService)
	mockDockerManager := new(MockManager) // Use local MockManager

	// Mock auth service
	authService := &auth_test.MockService{}
	authService.VerifyFunc = func(ctx context.Context, tokenString string) (*auth.TokenDetails, error) {
		if tokenString == "Bearer valid-token" || tokenString == "valid-token" {
			return &auth.TokenDetails{UserID: 1, Roles: []string{string(models.RoleUser)}}, nil
		}
		return nil, errors.New("invalid token")
	}
	authMW := middleware.NewAuthMiddleware(authService)

	// Create controller with mocks
	controller := NewController(mockContainerService, mockDockerManager, logger) // Correct arguments

	// Register routes
	api := router.Group("/api/v1")
	controller.RegisterRoutes(api, authMW)

	return controller, router, mockContainerService, mockDockerManager
}

func TestListContainers(t *testing.T) {
	_, router, mockService, _ := setupTestController(t)

	expectedContainers := []models.Container{{DockerResource: models.DockerResource{ID: 123, Name: "test"}}} // Use models.Container
	mockService.On("List", mock.Anything, mock.AnythingOfType("container.ListOptions")).Return(expectedContainers, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/containers", nil)
	req.Header.Set("Authorization", "Bearer valid-token") // Add auth header
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response models.SuccessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Success)
	// Need to assert data type and content more carefully
	mockService.AssertExpectations(t)
}

func TestGetContainer(t *testing.T) {
	_, router, mockService, _ := setupTestController(t)
	containerID := "123"
	expectedContainer := &models.Container{DockerResource: models.DockerResource{ID: 123, Name: "test"}} // Use models.Container

	mockService.On("Get", mock.Anything, containerID).Return(expectedContainer, nil) // Use Get method

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/containers/"+containerID, nil)
	req.Header.Set("Authorization", "Bearer valid-token") // Add auth header
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response models.SuccessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Success)
	// Need to assert data type and content more carefully
	mockService.AssertExpectations(t)
}

// TestCreate is defined in create_test.go

// TestRemove is defined in operations_test.go

func TestStartContainer(t *testing.T) {
	_, router, mockService, _ := setupTestController(t)
	containerID := "123"

	mockService.On("Start", mock.Anything, containerID, mock.AnythingOfType("container.StartOptions")).Return(nil) // Use correct options type

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/containers/"+containerID+"/start", nil)
	req.Header.Set("Authorization", "Bearer valid-token") // Add auth header
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockService.AssertExpectations(t)
}

// Add tests for Stop, Restart, Pause, Unpause, Rename, Logs, Stats, Top, Changes, Exec, GetFiles, PutFiles
// Example for Stop:
func TestStopContainer(t *testing.T) {
	_, router, mockService, _ := setupTestController(t)
	containerID := "123"

	mockService.On("Stop", mock.Anything, containerID, mock.AnythingOfType("container.StopOptions")).Return(nil) // Use correct options type

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/containers/"+containerID+"/stop", nil)
	req.Header.Set("Authorization", "Bearer valid-token") // Add auth header
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockService.AssertExpectations(t)
}

// --- Helper to set context values ---
func contextWithAuth(userID uint, roles []string) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, "userID", userID)   // Use string key
	ctx = context.WithValue(ctx, "userRoles", roles) // Use string key
	return ctx
}

// --- Example test using context ---
func TestListContainersWithAuthContext(t *testing.T) {
	controller, _, mockService, _ := setupTestController(t)

	expectedContainers := []models.Container{{DockerResource: models.DockerResource{ID: 123, Name: "test"}}} // Use models.Container
	mockService.On("List", mock.Anything, mock.AnythingOfType("container.ListOptions")).Return(expectedContainers, nil)

	// Create a Gin context with necessary values
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/api/v1/containers", nil)
	c.Set("userID", uint(1))                              // Use string key
	c.Set("userRoles", []string{string(models.RoleUser)}) // Use string key

	controller.ListContainers(c) // Call the handler directly

	assert.Equal(t, http.StatusOK, w.Code)
	// ... further assertions on the response body ...
	mockService.AssertExpectations(t)
}
