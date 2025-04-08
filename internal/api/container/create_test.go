package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	authtest "github.com/threatflux/dockerServerMangerGoMCP/internal/auth" // Use main auth package for MockService
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// --- Mocks ---
// MockContainerRepository removed - defined in controller_test.go
// MockContainerService removed - defined in controller_test.go
// MockManager removed - defined in controller_test.go

// --- Test Setup ---

// setupCreateTestController sets up the Gin engine and controller for create tests
// Note: This setup uses mocks defined in controller_test.go
func setupCreateTestController(t *testing.T) (*Controller, *gin.Engine, *MockContainerService, *MockManager) { // Removed MockContainerRepository
	gin.SetMode(gin.TestMode)
	router := gin.New()
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs

	mockContainerService := new(MockContainerService) // Use mock defined in controller_test.go
	// mockContainerRepo := new(MockContainerRepository) // Removed unused mock
	mockDockerManager := new(MockManager) // Use mock defined in controller_test.go

	// Mock auth service
	authService := &authtest.MockService{}
	authService.VerifyFunc = func(ctx context.Context, tokenString string) (*auth.TokenDetails, error) {
		if tokenString == "Bearer valid-token" || tokenString == "valid-token" {
			return &auth.TokenDetails{UserID: 1, Roles: []string{string(models.RoleUser)}}, nil
		}
		return nil, errors.New("invalid token")
	}
	authMW := middleware.NewAuthMiddleware(authService)

	// Create controller with mocks (without repo)
	controller := NewController(mockContainerService, mockDockerManager, logger) // Pass mocks

	// Register routes
	api := router.Group("/api/v1")
	controller.RegisterRoutes(api, authMW)

	return controller, router, mockContainerService, mockDockerManager // Removed mockContainerRepo
}

// --- Tests ---

// TestCreate is removed as it's declared in controller_test.go

func TestCreate_ValidationAndMocking(t *testing.T) { // Renamed to avoid conflict
	controller, router, mockContainerService, _ := setupCreateTestController(t) // Removed unused mockContainerRepo and mockDockerManager

	tests := []struct {
		name           string
		requestBody    models.ContainerCreateRequest
		mockSetup      func()
		expectedStatus int
		expectedBody   string // Substring to check in the response body
		userID         uint
		roles          []string
	}{
		{
			name: "Successful container creation",
			requestBody: models.ContainerCreateRequest{
				Name:  "test-container",
				Image: "nginx:latest",
				Ports: []models.PortMapping{
					{
						ContainerPort: "80",   // Use string
						HostPort:      "8080", // Use string
						// Protocol:      "tcp", // Removed unknown field
					},
				},
				Env: []string{"ENV_VAR=value"},
			},
			mockSetup: func() {
				// Expect Create method on the service mock
				mockContainerService.On("Create", mock.Anything, mock.AnythingOfType("models.ContainerCreateRequest")).Return("new-container-id", nil).Once()
			},
			expectedStatus: http.StatusCreated,
			expectedBody:   `"id":"new-container-id"`,
			userID:         1,
			roles:          []string{string(models.RoleUser)},
		},
		{
			name: "Creation failure - Docker error",
			requestBody: models.ContainerCreateRequest{
				Name:  "fail-container",
				Image: "bad-image",
			},
			mockSetup: func() {
				mockContainerService.On("Create", mock.Anything, mock.AnythingOfType("models.ContainerCreateRequest")).Return("", errors.New("docker_test create error")).Once()
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `"error":"Failed to create container: docker_test create error"`,
			userID:         1,
			roles:          []string{string(models.RoleUser)},
		},
		{
			name: "Creation failure - Invalid request body",
			requestBody: models.ContainerCreateRequest{
				// Missing required Image field
				Name: "invalid-req",
			},
			mockSetup:      func() {}, // No service call expected
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `"error":"Key: 'ContainerCreateRequest.Image' Error:Field validation for 'Image' failed on the 'required' tag"`,
			userID:         1,
			roles:          []string{string(models.RoleUser)},
		},
		{
			name: "Creation failure - Invalid port mapping (non-numeric)",
			requestBody: models.ContainerCreateRequest{
				Name:  "invalid-port",
				Image: "nginx:latest",
				Ports: []models.PortMapping{
					{
						ContainerPort: "abc", // Invalid
						HostPort:      "8080",
					},
				},
			},
			mockSetup:      func() {}, // No service call expected
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `"error":"Invalid port format"`, // Expect specific validation error
			userID:         1,
			roles:          []string{string(models.RoleUser)},
		},
		{
			name: "Creation failure - Invalid port mapping (negative)",
			requestBody: models.ContainerCreateRequest{
				Name:  "invalid-port-neg",
				Image: "nginx:latest",
				Ports: []models.PortMapping{
					{
						ContainerPort: "80",
						HostPort:      "-1", // Invalid
					},
				},
			},
			mockSetup:      func() {}, // No service call expected
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `"error":"Invalid port format"`, // Expect specific validation error
			userID:         1,
			roles:          []string{string(models.RoleUser)},
		},
		// Add more test cases for different scenarios (e.g., auth failure, other validation errors)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks for each subtest if necessary (though On().Once() helps)
			mockContainerService := new(MockContainerService) // Recreate mock for subtest isolation
			// mockContainerRepo := new(MockContainerRepository) // Removed unused mock
			// mockDockerManager := new(MockManager) // Removed unused variable
			controller.containerService = mockContainerService // Update controller's service mock
			// controller.containerRepo = mockContainerRepo // Controller no longer has repo

			tt.mockSetup() // Setup mock expectations for this specific test case

			// Marshal request body
			reqBodyBytes, err := json.Marshal(tt.requestBody)
			require.NoError(t, err)

			// Create request and recorder
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/api/v1/containers", bytes.NewBuffer(reqBodyBytes))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer valid-token") // Add auth header

			// Add user info to context for the request (simulating middleware)
			// Use Gin context modification within the test handler scope if possible,
			// or modify the request context directly if setup allows.
			// For simplicity here, we assume middleware is tested separately
			// and focus on the handler logic given the context values.
			// If handler directly uses c.Get, we need a Gin context.
			// If handler uses helper funcs like GetUserID(c), we need Gin context.
			// Let's simulate setting it in Gin context for the test handler call.

			// Create a test context and set values
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Set("userID", tt.userID)   // Use string key
			c.Set("userRoles", tt.roles) // Use string key

			// Serve the request using the router or call handler directly
			router.ServeHTTP(w, req) // Use router to involve middleware

			// Assertions
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)

			// Verify mock calls
			mockContainerService.AssertExpectations(t)
			// mockContainerRepo.AssertExpectations(t) // No repo calls expected in Create handler directly
		})
	}
}
