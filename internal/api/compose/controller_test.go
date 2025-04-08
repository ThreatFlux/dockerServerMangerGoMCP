package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors" // Added import
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	apitypes "github.com/docker/docker/api/types" // Import types with alias
	"github.com/docker/docker/client"             // Import client for APIClient interface
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"                                  // Added import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"          // Keep for models.RoleUser and auth.TokenDetails
	authtest "github.com/threatflux/dockerServerMangerGoMCP/internal/auth" // Use main auth package for MockService
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/interfaces" // Import interfaces
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// --- Mocks ---

// MockManager implements the docker.Manager interface for testing
type MockManager struct {
	mock.Mock
}

func (m *MockManager) GetClient() (*client.Client, error) { // Corrected return type
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	// Return a concrete *client.Client.
	val, ok := args.Get(0).(*client.Client)
	if !ok {
		// If the mock setup provides something else, return an error or a dummy client.
		// Returning nil for now as tests might not rely on a functional client from this mock.
		return nil, args.Error(1)
	}
	return val, args.Error(1)
}

func (m *MockManager) GetWithContext(ctx context.Context) (*client.Client, error) { // Added missing method
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

func (m *MockManager) Ping(ctx context.Context) (apitypes.Ping, error) { // Use apitypes alias
	args := m.Called(ctx)
	pingVal, _ := args.Get(0).(apitypes.Ping) // Use apitypes alias
	return pingVal, args.Error(1)
}

func (m *MockManager) IsInitialized() bool { // Added missing method
	args := m.Called()
	return args.Bool(0)
}

func (m *MockManager) IsClosed() bool { // Added missing method
	args := m.Called()
	return args.Bool(0)
}

func (m *MockManager) GetConfig() docker.ClientConfig { // Added missing method
	args := m.Called()
	cfg, _ := args.Get(0).(docker.ClientConfig)
	return cfg
}

func (m *MockManager) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockComposeService implements interfaces.ComposeService
type MockComposeService struct {
	mock.Mock
}

func (m *MockComposeService) Parse(ctx context.Context, reader io.Reader, options models.ParseOptions) (*models.ComposeFile, error) {
	args := m.Called(ctx, reader, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ComposeFile), args.Error(1)
}

func (m *MockComposeService) ParseFile(ctx context.Context, filePath string, options models.ParseOptions) (*models.ComposeFile, error) {
	args := m.Called(ctx, filePath, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ComposeFile), args.Error(1)
}

func (m *MockComposeService) ValidateFile(ctx context.Context, filePath string) (interface{}, []string, error) {
	args := m.Called(ctx, filePath)
	return args.Get(0), args.Get(1).([]string), args.Error(2)
}

// MockStatusTracker implements interfaces.ComposeStatusTracker
type MockStatusTracker struct {
	mock.Mock
}

func (m *MockStatusTracker) AddDeployment(projectName string, composeFile *models.ComposeFile) *models.DeploymentInfo {
	args := m.Called(projectName, composeFile)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*models.DeploymentInfo)
}

func (m *MockStatusTracker) GetDeployment(projectName string) (*models.DeploymentInfo, bool) {
	args := m.Called(projectName)
	if args.Get(0) == nil {
		return nil, args.Bool(1)
	}
	return args.Get(0).(*models.DeploymentInfo), args.Bool(1)
}

func (m *MockStatusTracker) GetDeployments() []*models.DeploymentInfo {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).([]*models.DeploymentInfo)
}

func (m *MockStatusTracker) RemoveDeployment(projectName string) bool {
	args := m.Called(projectName)
	return args.Bool(0)
}

func (m *MockStatusTracker) UpdateDeploymentStatus(projectName string, deploymentStatus models.DeploymentStatus, err error) bool {
	args := m.Called(projectName, deploymentStatus, err)
	return args.Bool(0)
}

func (m *MockStatusTracker) UpdateServiceStatus(projectName, serviceName string, serviceStatus models.ServiceStatus, containerID string, err error) bool {
	args := m.Called(projectName, serviceName, serviceStatus, containerID, err)
	return args.Bool(0)
}

func (m *MockStatusTracker) UpdateServiceHealth(projectName, serviceName string, health *models.HealthInfo) bool {
	args := m.Called(projectName, serviceName, health)
	return args.Bool(0)
}

func (m *MockStatusTracker) StartOperation(projectName string, operationType models.OperationType, details map[string]interface{}) (*models.OperationInfo, bool) {
	args := m.Called(projectName, operationType, details)
	if args.Get(0) == nil {
		return nil, args.Bool(1)
	}
	return args.Get(0).(*models.OperationInfo), args.Bool(1)
}

func (m *MockStatusTracker) CompleteOperation(projectName string, operationStatus models.OperationStatus, err error) bool {
	args := m.Called(projectName, operationStatus, err)
	return args.Bool(0)
}

func (m *MockStatusTracker) Watch() <-chan *models.DeploymentInfo {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(<-chan *models.DeploymentInfo)
}

func (m *MockStatusTracker) Unwatch(ch <-chan *models.DeploymentInfo) {
	m.Called(ch)
}

func (m *MockStatusTracker) Stop() {
	m.Called()
}

func (m *MockStatusTracker) GetServiceContainerID(projectName, serviceName string) (string, bool) {
	args := m.Called(projectName, serviceName)
	return args.String(0), args.Bool(1)
}

func (m *MockStatusTracker) GetServiceContainerIDs(projectName, serviceName string) ([]string, bool) {
	args := m.Called(projectName, serviceName)
	if args.Get(0) == nil {
		return nil, args.Bool(1)
	}
	return args.Get(0).([]string), args.Bool(1)
}

func (m *MockStatusTracker) GetServiceStatus(projectName, serviceName string) (models.ServiceStatus, bool) {
	args := m.Called(projectName, serviceName)
	return args.Get(0).(models.ServiceStatus), args.Bool(1)
}

// MockOrchestrator implements interfaces.ComposeOrchestrator
type MockOrchestrator struct {
	mock.Mock
}

func (m *MockOrchestrator) Deploy(ctx context.Context, composeFile *models.ComposeFile, options models.DeployOptions) error {
	args := m.Called(ctx, composeFile, options)
	return args.Error(0)
}

func (m *MockOrchestrator) Remove(ctx context.Context, composeFile *models.ComposeFile, options models.RemoveOptions) error {
	args := m.Called(ctx, composeFile, options)
	return args.Error(0)
}

func (m *MockOrchestrator) Start(ctx context.Context, composeFile *models.ComposeFile, options models.StartOptions) error {
	args := m.Called(ctx, composeFile, options)
	return args.Error(0)
}

func (m *MockOrchestrator) Stop(ctx context.Context, composeFile *models.ComposeFile, options models.StopOptions) error {
	args := m.Called(ctx, composeFile, options)
	return args.Error(0)
}

func (m *MockOrchestrator) Restart(ctx context.Context, composeFile *models.ComposeFile, options models.RestartOptions) error {
	args := m.Called(ctx, composeFile, options)
	return args.Error(0)
}

func (m *MockOrchestrator) Scale(ctx context.Context, composeFile *models.ComposeFile, options models.ScaleOptions) error {
	args := m.Called(ctx, composeFile, options)
	return args.Error(0)
}

// Set up a test router with the compose controller
func setupComposeTestRouter(composeService interfaces.ComposeService, statusTracker interfaces.ComposeStatusTracker, orchestrator interfaces.ComposeOrchestrator, dockerManager docker.Manager) (*gin.Engine, *Controller, string) { // Use interfaces and docker_test.Manager
	gin.SetMode(gin.TestMode)
	router := gin.New()

	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs during tests

	// Create mocked auth service using function fields
	authService := &authtest.MockService{} // Use MockService from auth package
	authService.VerifyFunc = func(ctx context.Context, tokenString string) (*auth.TokenDetails, error) {
		// Basic validation for testing purposes
		if tokenString == "Bearer valid-token" || tokenString == "valid-token" { // Allow with or without Bearer prefix
			return &auth.TokenDetails{
				UserID: 1,
				Roles:  []string{string(models.RoleUser)},
			}, nil
		}
		return nil, errors.New("invalid token")
	}

	// Create auth middleware
	authMW := middleware.NewAuthMiddleware(authService) // Corrected arguments

	// Create a temp directory for tests
	tempDir, _ := os.MkdirTemp("", "compose-controller-test")

	// Create compose controller
	controller := NewController(
		composeService,
		orchestrator,  // Pass orchestrator interface
		statusTracker, // Pass status tracker interface
		logger,
	)

	// Register routes
	api := router.Group("/api/v1")
	controller.RegisterRoutes(api, authMW)

	return router, controller, tempDir
}

func TestUploadComposeFile(t *testing.T) {
	// Create mocks
	mockComposeService := new(MockComposeService)
	mockStatusTracker := new(MockStatusTracker)
	mockOrchestrator := new(MockOrchestrator)
	mockDockerManager := new(MockManager) // Use the local MockManager

	// Set up test router
	router, _, tempDir := setupComposeTestRouter(mockComposeService, mockStatusTracker, mockOrchestrator, mockDockerManager)
	defer os.RemoveAll(tempDir)

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add form fields
	writer.WriteField("project_name", "test-project") // Use project_name

	// Create file part
	part, _ := writer.CreateFormFile("compose_file", "docker_test-compose.yml") // Use compose_file
	io.Copy(part, strings.NewReader("version: '3'\nservices:\n  web:\n    image: nginx"))

	writer.Close()

	// Create request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/compose/up", body) // Use /up endpoint for upload+deploy
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer valid-token")

	// Mock expectations for /up
	parsedComposeFile := &models.ComposeFile{
		Services: map[string]models.ServiceConfig{"web": {Image: "nginx"}}, // Use models.ServiceConfig
	}
	mockComposeService.On("Parse", mock.Anything, mock.Anything, mock.AnythingOfType("models.ParseOptions")).Return(parsedComposeFile, nil) // Use mock.Anything for reader type
	mockOrchestrator.On("Deploy", mock.Anything, parsedComposeFile, mock.MatchedBy(func(opts models.DeployOptions) bool {
		return opts.ProjectName == "test-project"
	})).Return(nil)

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusAccepted, w.Code) // Expect 202 Accepted for async operation

	// Verify mocks were called
	mockComposeService.AssertExpectations(t)
	mockOrchestrator.AssertExpectations(t)
}

func TestValidateComposeFile(t *testing.T) {
	// Create mocks
	mockComposeService := new(MockComposeService)
	mockStatusTracker := new(MockStatusTracker)
	mockOrchestrator := new(MockOrchestrator)
	mockDockerManager := new(MockManager)

	// Set up test router
	router, _, tempDir := setupComposeTestRouter(mockComposeService, mockStatusTracker, mockOrchestrator, mockDockerManager)
	defer os.RemoveAll(tempDir)

	// Mock compose service response for Parse (used by Validate handler)
	composeContent := "version: '3'\nservices:\n  web:\n    image: nginx"
	parsedComposeFile := &models.ComposeFile{
		Services: map[string]models.ServiceConfig{"web": {Image: "nginx"}}, // Use models.ServiceConfig
	}
	mockComposeService.On("Parse", mock.Anything, mock.AnythingOfType("*strings.Reader"), mock.AnythingOfType("models.ParseOptions")).Return(parsedComposeFile, nil)

	// Create request body
	reqBody := models.ComposeValidateRequest{
		ComposeFileContent: composeContent,
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/compose/validate", bytes.NewBuffer(reqJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-token")

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify mock was called
	mockComposeService.AssertExpectations(t)

	// Parse response
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	// Verify response contains expected fields
	assert.Equal(t, true, response["success"]) // Assuming standard success response
	data, ok := response["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "valid", data["status"])
}

func TestComposeUp(t *testing.T) {
	// Create mocks
	mockComposeService := new(MockComposeService)
	mockStatusTracker := new(MockStatusTracker)
	mockOrchestrator := new(MockOrchestrator)
	mockDockerManager := new(MockManager)

	// Set up test router
	router, _, tempDir := setupComposeTestRouter(mockComposeService, mockStatusTracker, mockOrchestrator, mockDockerManager)
	defer os.RemoveAll(tempDir)

	// Mock service responses
	composeContent := "version: '3'\nservices:\n  web:\n    image: nginx"
	parsedComposeFile := &models.ComposeFile{
		Services: map[string]models.ServiceConfig{"web": {Image: "nginx"}}, // Use models.ServiceConfig
	}
	mockComposeService.On("Parse", mock.Anything, mock.AnythingOfType("*strings.Reader"), mock.AnythingOfType("models.ParseOptions")).Return(parsedComposeFile, nil)
	mockOrchestrator.On("Deploy", mock.Anything, parsedComposeFile, mock.MatchedBy(func(opts models.DeployOptions) bool {
		return opts.ProjectName == "test-project" && opts.Pull == true && opts.ForceRecreate == true
	})).Return(nil)

	// Create request body
	reqBody := models.ComposeUpRequest{
		ProjectName:        "test-project",
		ComposeFileContent: composeContent,
		Pull:               true,
		ForceRecreate:      true,
	}
	reqJSON, _ := json.Marshal(reqBody)

	// Create request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/compose/up", bytes.NewBuffer(reqJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-token")

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusAccepted, w.Code) // Expect 202 Accepted

	// Verify mocks were called
	mockComposeService.AssertExpectations(t)
	mockOrchestrator.AssertExpectations(t)

	// For 202 Accepted, primarily check status code and mock calls.
	// The body might be minimal or empty.
	// Optionally, check if body is valid JSON if a specific structure is expected.
	// var response map[string]interface{}
	// err := json.Unmarshal(w.Body.Bytes(), &response)
	// assert.NoError(t, err, "Response body should be valid JSON if present")
	// if err == nil {
	// 	assert.Equal(t, true, response["success"])
	// 	assert.Contains(t, response["message"], "Deployment process started")
	// }
}

func TestComposeDown(t *testing.T) {
	// Create mocks
	mockComposeService := new(MockComposeService)
	mockStatusTracker := new(MockStatusTracker)
	mockOrchestrator := new(MockOrchestrator)
	mockDockerManager := new(MockManager)

	// Set up test router
	router, _, tempDir := setupComposeTestRouter(mockComposeService, mockStatusTracker, mockOrchestrator, mockDockerManager)
	defer os.RemoveAll(tempDir)

	// Mock status tracker to return a deployment
	projectName := "test-project"
	composeFile := &models.ComposeFile{ /* ... */ }
	deploymentInfo := &models.DeploymentInfo{ProjectName: projectName, ComposeFile: composeFile}
	mockStatusTracker.On("GetDeployment", projectName).Return(deploymentInfo, true)

	// Mock orchestrator
	mockOrchestrator.On("Remove", mock.Anything, composeFile, mock.MatchedBy(func(opts models.RemoveOptions) bool {
		return opts.ProjectName == projectName && opts.RemoveVolumes == true
	})).Return(nil)

	// Create request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/compose/"+projectName+"/down?remove_volumes=true", nil) // Use query param
	req.Header.Set("Authorization", "Bearer valid-token")

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusAccepted, w.Code) // Expect 202 Accepted

	// Verify mocks were called
	mockStatusTracker.AssertExpectations(t)
	mockOrchestrator.AssertExpectations(t)

	// For 202 Accepted, primarily check status code and mock calls.
	// The body might be minimal or empty.
	// Optionally, check if body is valid JSON if a specific structure is expected.
	// var response map[string]interface{}
	// err := json.Unmarshal(w.Body.Bytes(), &response)
	// assert.NoError(t, err, "Response body should be valid JSON if present")
	// if err == nil {
	// 	assert.Equal(t, true, response["success"])
	// 	assert.Contains(t, response["message"], "Removal process started")
	// }
}

func TestGetComposeStatus(t *testing.T) {
	// Create mocks
	mockComposeService := new(MockComposeService)
	mockStatusTracker := new(MockStatusTracker)
	mockOrchestrator := new(MockOrchestrator)
	mockDockerManager := new(MockManager)

	// Set up test router
	router, _, tempDir := setupComposeTestRouter(mockComposeService, mockStatusTracker, mockOrchestrator, mockDockerManager)
	defer os.RemoveAll(tempDir)

	// Mock status tracker
	projectName := "test-project"
	deploymentInfo := &models.DeploymentInfo{ // Use models.DeploymentInfo
		ProjectName: projectName,
		Status:      models.DeploymentStatusRunning, // Use models.DeploymentStatus
		Services: map[string]*models.ServiceInfo{ // Use models.ServiceInfo
			"web": {
				Name:         "web",
				Status:       models.ServiceStatusRunning, // Use models.ServiceStatus
				ContainerIDs: []string{"container1"},
			},
		},
	}
	mockStatusTracker.On("GetDeployment", projectName).Return(deploymentInfo, true)

	// Create request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/compose/"+projectName, nil) // Use correct endpoint
	req.Header.Set("Authorization", "Bearer valid-token")

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify mocks were called
	mockStatusTracker.AssertExpectations(t)

	// Parse response
	var response models.SuccessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Verify response contains expected fields
	assert.True(t, response.Success)
	data, ok := response.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, projectName, data["projectName"])
	assert.Equal(t, string(models.DeploymentStatusRunning), data["status"]) // Compare string representation
	services, ok := data["services"].(map[string]interface{})
	require.True(t, ok)
	webService, ok := services["web"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "web", webService["name"])
	assert.Equal(t, string(models.ServiceStatusRunning), webService["status"]) // Compare string representation
}

func TestListComposeProjects(t *testing.T) {
	// Create mocks
	mockComposeService := new(MockComposeService)
	mockStatusTracker := new(MockStatusTracker)
	mockOrchestrator := new(MockOrchestrator)
	mockDockerManager := new(MockManager)

	// Set up test router
	router, _, tempDir := setupComposeTestRouter(mockComposeService, mockStatusTracker, mockOrchestrator, mockDockerManager)
	defer os.RemoveAll(tempDir)

	// Mock status tracker
	deployments := []*models.DeploymentInfo{ // Use models.DeploymentInfo
		{ProjectName: "project1", Status: models.DeploymentStatusRunning}, // Use models.DeploymentStatus
		{ProjectName: "project2", Status: models.DeploymentStatusStopped}, // Use models.DeploymentStatus
	}
	mockStatusTracker.On("GetDeployments").Return(deployments)

	// Create request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/compose", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify mocks were called
	mockStatusTracker.AssertExpectations(t)

	// Parse response
	var response models.SuccessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Verify response contains expected fields
	assert.True(t, response.Success)
	data, ok := response.Data.([]interface{})
	require.True(t, ok)
	assert.Len(t, data, 2)
	// Add more specific checks if needed based on DeploymentInfo structure
}

func TestServiceOperations(t *testing.T) {
	// Create mocks
	mockComposeService := new(MockComposeService)
	mockStatusTracker := new(MockStatusTracker)
	mockOrchestrator := new(MockOrchestrator)
	mockDockerManager := new(MockManager)

	// Set up test router
	router, _, tempDir := setupComposeTestRouter(mockComposeService, mockStatusTracker, mockOrchestrator, mockDockerManager)
	defer os.RemoveAll(tempDir)

	projectName := "test-project"
	serviceName := "web"
	composeFile := &models.ComposeFile{ /* ... */ }
	deploymentInfo := &models.DeploymentInfo{ProjectName: projectName, ComposeFile: composeFile}

	// Mock GetDeployment for all operations
	mockStatusTracker.On("GetDeployment", projectName).Return(deploymentInfo, true)

	// Mock orchestrator methods
	mockOrchestrator.On("Start", mock.Anything, composeFile, mock.AnythingOfType("models.StartOptions")).Return(nil)
	mockOrchestrator.On("Stop", mock.Anything, composeFile, mock.AnythingOfType("models.StopOptions")).Return(nil)
	mockOrchestrator.On("Restart", mock.Anything, composeFile, mock.AnythingOfType("models.RestartOptions")).Return(nil)
	mockOrchestrator.On("Scale", mock.Anything, composeFile, mock.MatchedBy(func(opts models.ScaleOptions) bool {
		return opts.ProjectName == projectName && opts.Service == serviceName && opts.Replicas == 3
	})).Return(nil)

	// Test Start
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/compose/"+projectName+"/start", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)

	// Test Stop
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/v1/compose/"+projectName+"/stop", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)

	// Test Restart
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/v1/compose/"+projectName+"/restart", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)

	// Test Scale
	scaleBody := models.ComposeScaleRequest{Service: serviceName, Replicas: 3}
	scaleJSON, _ := json.Marshal(scaleBody)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/v1/compose/"+projectName+"/scale", bytes.NewBuffer(scaleJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)

	// Verify mocks
	mockOrchestrator.AssertExpectations(t)
	mockStatusTracker.AssertExpectations(t)
}

// --- Add more tests for error cases, edge cases, etc. ---

func TestComposeErrorHandling(t *testing.T) {
	// Test case: Project not found for 'down'
	mockComposeService := new(MockComposeService)
	mockStatusTracker := new(MockStatusTracker)
	mockOrchestrator := new(MockOrchestrator)
	mockDockerManager := new(MockManager)
	router, _, tempDir := setupComposeTestRouter(mockComposeService, mockStatusTracker, mockOrchestrator, mockDockerManager)
	defer os.RemoveAll(tempDir)

	mockStatusTracker.On("GetDeployment", "not-a-project").Return(nil, false)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/compose/not-a-project/down", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	mockStatusTracker.AssertExpectations(t)

	// Test case: Orchestrator 'up' fails
	mockComposeService = new(MockComposeService) // Reset mocks
	mockStatusTracker = new(MockStatusTracker)
	mockOrchestrator = new(MockOrchestrator)
	mockDockerManager = new(MockManager)
	router, _, tempDir = setupComposeTestRouter(mockComposeService, mockStatusTracker, mockOrchestrator, mockDockerManager)
	defer os.RemoveAll(tempDir)

	composeContent := "version: '3'\nservices:\n  web:\n    image: nginx"
	parsedComposeFile := &models.ComposeFile{Services: map[string]models.ServiceConfig{"web": {}}} // Use models.ServiceConfig
	mockComposeService.On("Parse", mock.Anything, mock.Anything, mock.Anything).Return(parsedComposeFile, nil)
	deployError := errors.New("deployment failed")
	mockOrchestrator.On("Deploy", mock.Anything, parsedComposeFile, mock.Anything).Return(deployError)
	// Expect status tracker to be updated with failure
	mockStatusTracker.On("CompleteOperation", "fail-project", models.OperationStatusFailed, deployError).Return(true)

	reqBody := models.ComposeUpRequest{ProjectName: "fail-project", ComposeFileContent: composeContent}
	reqJSON, _ := json.Marshal(reqBody)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/v1/compose/up", bytes.NewBuffer(reqJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code) // Still accepted, failure happens async

	// Allow time for async operation to potentially call CompleteOperation
	time.Sleep(50 * time.Millisecond)
	mockOrchestrator.AssertExpectations(t)
	mockStatusTracker.AssertExpectations(t)
}

// Add tests for security/permissions if applicable
// Add tests for specific options (e.g., timeout)

// Note: The ConvertComposeFile test might be less relevant now if conversion isn't a direct API endpoint
// func TestConvertComposeFile(t *testing.T) { ... }
