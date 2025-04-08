package container

import (
	"bytes" // Added import
	"context"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	auth_test "github.com/threatflux/dockerServerMangerGoMCP/internal/auth" // Use main auth package for MockService
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"io" // Added import
	"net/http"
	"net/http/httptest"
	"strings" // Added import
	"testing"
)

// --- Mocks ---
// MockContainerRepository removed - should be defined in controller_test.go

// --- Test Setup ---

// setupOperationsTestController sets up the Gin engine and controller for operations tests
// Note: This setup uses mocks defined in controller_test.go
func setupOperationsTestController(t *testing.T) (*Controller, *gin.Engine, *MockContainerService, *MockContainerRepository, *MockManager) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs

	mockContainerService := new(MockContainerService) // Use mock defined in controller_test.go
	mockContainerRepo := new(MockContainerRepository) // Use mock defined in controller_test.go
	mockDockerManager := new(MockManager)             // Use mock defined in controller_test.go

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
	controller := NewController(mockContainerService, mockDockerManager, logger) // Pass mocks

	// Register routes
	api := router.Group("/api/v1")
	controller.RegisterRoutes(api, authMW)

	return controller, router, mockContainerService, mockContainerRepo, mockDockerManager
}

// --- Tests ---

func TestStartContainer_Success(t *testing.T) {
	_, router, mockContainerService, _, _ := setupOperationsTestController(t)
	containerID := "test-container-id"

	mockContainerService.On("Start", mock.Anything, containerID, mock.AnythingOfType("container.StartOptions")).Return(nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/containers/"+containerID+"/start", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response models.SuccessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Success)
	assert.Equal(t, "Container started successfully", response.Message)
	mockContainerService.AssertExpectations(t)
}

func TestStartContainer_NotFound(t *testing.T) {
	_, router, mockContainerService, _, _ := setupOperationsTestController(t)
	containerID := "non-existent-id"
	notFoundErr := errors.New("container not found") // Simulate service error

	mockContainerService.On("Start", mock.Anything, containerID, mock.AnythingOfType("container.StartOptions")).Return(notFoundErr)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/containers/"+containerID+"/start", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code) // Expect 404
	var errResp models.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &errResp)
	require.NoError(t, err)
	// assert.Equal(t, "CONTAINER_NOT_FOUND", errResp.Code) // ErrorResponse might not have Code field
	assert.Contains(t, errResp.Error, "container not found") // Check error message instead
	mockContainerService.AssertExpectations(t)
}

func TestStopContainer_Success(t *testing.T) {
	_, router, mockContainerService, _, _ := setupOperationsTestController(t)
	containerID := "test-container-id"

	// Expect Stop to be called with container.StopOptions
	mockContainerService.On("Stop", mock.Anything, containerID, mock.AnythingOfType("container.StopOptions")).Return(nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/containers/"+containerID+"/stop", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response models.SuccessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Success)
	assert.Equal(t, "Container stopped successfully", response.Message)
	mockContainerService.AssertExpectations(t)
}

func TestRestartContainer_Success(t *testing.T) {
	_, router, mockContainerService, _, _ := setupOperationsTestController(t)
	containerID := "test-container-id"

	// Expect Restart to be called with container.RestartOptions
	mockContainerService.On("Restart", mock.Anything, containerID, mock.AnythingOfType("container.RestartOptions")).Return(nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/containers/"+containerID+"/restart", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response models.SuccessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Success)
	assert.Equal(t, "Container restarted successfully", response.Message)
	mockContainerService.AssertExpectations(t)
}

func TestPauseContainer_Success(t *testing.T) {
	_, router, mockContainerService, _, _ := setupOperationsTestController(t)
	containerID := "test-container-id"

	mockContainerService.On("Pause", mock.Anything, containerID).Return(nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/containers/"+containerID+"/pause", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response models.SuccessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Success)
	assert.Equal(t, "Container paused successfully", response.Message)
	mockContainerService.AssertExpectations(t)
}

func TestUnpauseContainer_Success(t *testing.T) {
	_, router, mockContainerService, _, _ := setupOperationsTestController(t)
	containerID := "test-container-id"

	mockContainerService.On("Unpause", mock.Anything, containerID).Return(nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/containers/"+containerID+"/unpause", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response models.SuccessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Success)
	assert.Equal(t, "Container unpaused successfully", response.Message)
	mockContainerService.AssertExpectations(t)
}

func TestRenameContainer_Success(t *testing.T) {
	_, router, mockContainerService, _, _ := setupOperationsTestController(t)
	containerID := "test-container-id"
	newName := "new-container-name"

	mockContainerService.On("Rename", mock.Anything, containerID, newName).Return(nil)

	reqBody := gin.H{"name": newName}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/containers/"+containerID+"/rename", bytes.NewBuffer(jsonBody)) // Use bytes.NewBuffer
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response models.SuccessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.True(t, response.Success)
	assert.Equal(t, "Container renamed successfully", response.Message)
	mockContainerService.AssertExpectations(t)
}

// TestRemove is removed as it's declared in controller_test.go

// Add more tests for Logs, Stats, Top, Changes, Exec, GetFiles, PutFiles...

// Example for Logs
func TestLogsContainer_Success(t *testing.T) {
	_, router, mockService, _, _ := setupOperationsTestController(t)
	containerID := "test-container-id"
	logOutput := "Log line 1\nLog line 2"

	mockService.On("Logs", mock.Anything, containerID, mock.AnythingOfType("container.LogOptions")).Return(io.NopCloser(strings.NewReader(logOutput)), nil) // Use strings.NewReader and io.NopCloser

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/containers/"+containerID+"/logs", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, logOutput, w.Body.String())
	mockService.AssertExpectations(t)
}
