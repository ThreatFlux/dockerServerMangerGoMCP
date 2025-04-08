package api

import (
	"bytes"
	"context" // Added context import
	"encoding/json"
	"errors" // Added errors import
	"io"     // Re-added io import
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/docker/docker/api/types/events"             // Added for GetEvents
	volumeTypes "github.com/docker/docker/api/types/volume" // Added for PruneReport, Volume
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/volume"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// MockVolumeService mocks the volume.Service interface
type MockVolumeService struct {
	mock.Mock
}

// List implements the volume.Service interface
func (m *MockVolumeService) List(ctx context.Context, opts volume.ListOptions) ([]*models.Volume, error) { // Use context.Context
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Volume), args.Error(1)
}

// Get implements the volume.Service interface
func (m *MockVolumeService) Get(ctx context.Context, name string, opts volume.GetOptions) (*models.Volume, error) { // Use context.Context
	args := m.Called(ctx, name, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Volume), args.Error(1)
}

// Create implements the volume.Service interface
func (m *MockVolumeService) Create(ctx context.Context, name string, opts volume.CreateOptions) (*models.Volume, error) { // Use context.Context
	args := m.Called(ctx, name, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Volume), args.Error(1)
}

// Remove implements the volume.Service interface
func (m *MockVolumeService) Remove(ctx context.Context, name string, opts volume.RemoveOptions) error { // Use context.Context
	args := m.Called(ctx, name, opts)
	return args.Error(0)
}

// Prune implements the volume.Service interface
func (m *MockVolumeService) Prune(ctx context.Context, opts volume.PruneOptions) (*volumeTypes.PruneReport, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*volumeTypes.PruneReport), args.Error(1)
}

// Backup implements the volume.Service interface
func (m *MockVolumeService) Backup(ctx context.Context, name string, opts volume.BackupOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, name, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	// Ensure the mock returns io.ReadCloser or nil
	if rc := args.Get(0); rc != nil {
		return rc.(io.ReadCloser), args.Error(1)
	}
	return nil, args.Error(1)
}

// Restore implements the volume.Service interface
func (m *MockVolumeService) Restore(ctx context.Context, name string, reader io.Reader, opts volume.RestoreOptions) error { // Use context.Context, io.Reader, volume.RestoreOptions
	args := m.Called(ctx, name, reader, opts)
	return args.Error(0)
}

// Removed obsolete mock methods: Inspect, ListContents, Clone

// InspectRaw implements the volume.Service interface
func (m *MockVolumeService) InspectRaw(ctx context.Context, name string) (volumeTypes.Volume, error) {
	args := m.Called(ctx, name)
	// Return zero value for volume.Volume if nil, otherwise cast
	if args.Get(0) == nil {
		// Cannot return nil directly for a struct type, return zero value
		return volumeTypes.Volume{}, args.Error(1)
	}
	return args.Get(0).(volumeTypes.Volume), args.Error(1)
}

// GetEvents implements the volume.Service interface
func (m *MockVolumeService) GetEvents(ctx context.Context, options volume.EventOptions) (<-chan events.Message, <-chan error) {
	args := m.Called(ctx, options)
	var msgChan chan events.Message
	var errChan chan error

	if args.Get(0) != nil {
		msgChan = args.Get(0).(chan events.Message)
	}
	if args.Get(1) != nil {
		errChan = args.Get(1).(chan error)
	}
	// Return potentially nil channels if not mocked
	return msgChan, errChan
}

// Update implements the volume.Service interface
func (m *MockVolumeService) Update(ctx context.Context, name string, metadata map[string]string, options volume.UpdateOptions) error {
	args := m.Called(ctx, name, metadata, options)
	return args.Error(0)
}

// MockVolumeRepository mocks the repositories.VolumeRepository
type MockVolumeRepository struct {
	mock.Mock
}

// FindByName implements repositories.VolumeRepository interface
func (m *MockVolumeRepository) FindByName(ctx context.Context, name string) (*models.Volume, error) { // Use context.Context
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Volume), args.Error(1) // Return *models.Volume
}

// Create implements repositories.VolumeRepository interface
func (m *MockVolumeRepository) Create(ctx context.Context, volume *models.Volume) error { // Use context.Context
	args := m.Called(ctx, volume)
	return args.Error(0)
}

// Update implements repositories.VolumeRepository interface
func (m *MockVolumeRepository) Update(ctx context.Context, volume *models.Volume) error { // Use context.Context
	args := m.Called(ctx, volume)
	return args.Error(0)
}

// Delete implements repositories.VolumeRepository interface
func (m *MockVolumeRepository) Delete(ctx context.Context, id uint) error { // Use context.Context
	args := m.Called(ctx, id)
	return args.Error(0)
}

func setupVolumeController(t *testing.T) (*VolumeController, *MockVolumeService, *MockVolumeRepository, *gin.Engine, *gin.RouterGroup) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Initialize mock dependencies
	mockVolumeService := new(MockVolumeService)
	mockVolumeRepo := new(MockVolumeRepository)
	mockDockerManager := new(MockDockerManager) // Use MockDockerManager from api/mocks_test.go
	mockAuthService := new(auth.MockService)
	logger := logrus.New()
	logger.SetOutput(bytes.NewBuffer(nil)) // Discard logs in test

	// Create auth middleware
	authMW := middleware.NewAuthMiddleware(mockAuthService)

	// Create controller
	controller := NewVolumeController(
		mockVolumeService,
		// mockVolumeRepo, // Repository not used by controller currently
		mockDockerManager, // Pass the manager itself
		logger,
	)

	// Create router
	router := gin.New()
	router.Use(gin.Recovery())

	// Create router group
	apiGroup := router.Group("/api/v1")

	// Register routes
	controller.RegisterRoutes(apiGroup, authMW)

	return controller, mockVolumeService, mockVolumeRepo, router, apiGroup
}

func TestVolumeRegisterRoutes(t *testing.T) {
	controller, _, _, _, apiGroup := setupVolumeController(t)
	assert.NotNil(t, controller)
	assert.NotNil(t, apiGroup)
}

func TestListVolumes(t *testing.T) {
	controller, mockVolumeService, mockVolumeRepo, _, _ := setupVolumeController(t)

	// Define test cases
	tests := []struct {
		name           string
		setupMocks     func()
		userRole       string
		queryParams    string
		expectedStatus int
		expectedItems  int
	}{
		{
			name: "Admin List All Volumes",
			setupMocks: func() {
				// Mock volume service response
				mockVolumeService.On("List", mock.Anything, mock.Anything).Return(
					[]*models.Volume{
						{
							DockerResource: models.DockerResource{
								Name: "volume1",
								// CreatedAt: time.Now(), // CreatedAt is part of DockerResource
							},
							Driver:     "local",
							Mountpoint: "/var/lib/docker_test/volumes/volume1/_data",
						},
						{
							DockerResource: models.DockerResource{
								Name: "volume2",
								// CreatedAt: time.Now(), // CreatedAt is part of DockerResource
							},
							Driver:     "local",
							Mountpoint: "/var/lib/docker_test/volumes/volume2/_data",
						},
					}, nil,
				).Once()
			},
			userRole:       "admin",
			queryParams:    "?page=1&page_size=10",
			expectedStatus: http.StatusOK,
			expectedItems:  2,
		},
		{
			name: "User List Own Volumes",
			setupMocks: func() {
				// Mock volume service response
				mockVolumeService.On("List", mock.Anything, mock.Anything).Return(
					[]*models.Volume{
						{
							DockerResource: models.DockerResource{
								Name: "volume1",
								// CreatedAt: time.Now(), // CreatedAt is part of DockerResource
							},
							Driver:     "local",
							Mountpoint: "/var/lib/docker_test/volumes/volume1/_data",
						},
						{
							DockerResource: models.DockerResource{
								Name: "volume2",
								// CreatedAt: time.Now(), // CreatedAt is part of DockerResource
							},
							Driver:     "local",
							Mountpoint: "/var/lib/docker_test/volumes/volume2/_data",
						},
					}, nil,
				).Once()

				// Mock repository response for volume1 (owned by user)
				mockVolumeRepo.On("FindByName", mock.Anything, "volume1").Return(
					&models.Volume{ // Use models.Volume
						DockerResource: models.DockerResource{
							ID:     1,
							Name:   "volume1",
							UserID: 1, // Owned by user with ID 1
						},
						Driver: "local",
					}, nil,
				).Once()

				// Mock repository response for volume2 (not owned by user)
				mockVolumeRepo.On("FindByName", mock.Anything, "volume2").Return(
					&models.Volume{ // Use models.Volume
						DockerResource: models.DockerResource{
							ID:     2,
							Name:   "volume2",
							UserID: 2, // Owned by different user
						},
						Driver: "local",
					}, nil,
				).Once()
			},
			userRole:       "user",
			queryParams:    "?page=1&page_size=10",
			expectedStatus: http.StatusOK,
			expectedItems:  1, // Only one volume belongs to the user
		},
		{
			name: "Error Listing Volumes",
			setupMocks: func() {
				// Mock volume service error
				mockVolumeService.On("List", mock.Anything, mock.Anything).Return(
					nil, errors.New("failed to list volumes"),
				).Once()
			},
			userRole:       "admin",
			queryParams:    "?page=1&page_size=10",
			expectedStatus: http.StatusInternalServerError,
			expectedItems:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			tt.setupMocks()

			// Create test context
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Create request with query parameters
			req, _ := http.NewRequest("GET", "/api/v1/volumes"+tt.queryParams, nil)
			c.Request = req

			// Set user context
			c.Set("userID", uint(1)) // Use string key
			if tt.userRole == "admin" {
				c.Set("userRoles", []string{"admin"}) // Use string key
			} else {
				c.Set("userRoles", []string{"user"}) // Use string key
			}

			// Call handler
			controller.ListVolumes(c)

			// Check response status
			assert.Equal(t, tt.expectedStatus, w.Code)

			// If success, check response body
			if tt.expectedStatus == http.StatusOK {
				// ListVolumes uses utils.SuccessResponse which wraps the data
				var response models.SuccessResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.True(t, response.Success)
				require.NotNil(t, response.Data)

				// Type assert the Data field to the expected structure
				// The controller maps []*models.Volume to []models.VolumeResponse
				var listResponse models.VolumeListResponse
				listDataBytes, _ := json.Marshal(response.Data)    // Marshal the interface{} data
				err = json.Unmarshal(listDataBytes, &listResponse) // Unmarshal into the specific type
				require.NoError(t, err)

				assert.Len(t, listResponse.Volumes, tt.expectedItems)
				assert.NotNil(t, response.Meta.Pagination) // Check pagination in Meta
			}

			// Verify mocks
			mockVolumeService.AssertExpectations(t)
			mockVolumeRepo.AssertExpectations(t)
		})
	}
}

func TestGetVolume(t *testing.T) {
	controller, mockVolumeService, mockVolumeRepo, _, _ := setupVolumeController(t)

	// Define test cases
	tests := []struct {
		name           string
		setupMocks     func()
		volumeID       string
		userRole       string
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Get Existing Volume as Admin",
			setupMocks: func() {
				// Mock volume service response
				mockVolumeService.On("Get", mock.Anything, "test-volume", mock.Anything).Return(
					&models.Volume{
						DockerResource: models.DockerResource{
							Name: "test-volume",
							// CreatedAt: time.Now(), // CreatedAt is part of DockerResource
						},
						Driver:     "local",
						Mountpoint: "/var/lib/docker_test/volumes/test-volume/_data",
					}, nil,
				).Once()
			},
			volumeID:       "test-volume",
			userRole:       "admin",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Get Volume as Owner",
			setupMocks: func() {
				// Mock volume service response
				mockVolumeService.On("Get", mock.Anything, "test-volume", mock.Anything).Return(
					&models.Volume{
						DockerResource: models.DockerResource{
							Name: "test-volume",
							// CreatedAt: time.Now(), // CreatedAt is part of DockerResource
						},
						Driver:     "local",
						Mountpoint: "/var/lib/docker_test/volumes/test-volume/_data",
					}, nil,
				).Once()

				// Mock repository response (owned by user)
				mockVolumeRepo.On("FindByName", mock.Anything, "test-volume").Return(
					&models.Volume{ // Use models.Volume
						DockerResource: models.DockerResource{
							ID:     1,
							Name:   "test-volume",
							UserID: 1, // Owned by current user
						},
						Driver: "local",
					}, nil,
				).Once()
			},
			volumeID:       "test-volume",
			userRole:       "user",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Get Volume Not Owned by User",
			setupMocks: func() {
				// Mock volume service response
				mockVolumeService.On("Get", mock.Anything, "test-volume", mock.Anything).Return(
					&models.Volume{
						DockerResource: models.DockerResource{
							Name:      "test-volume",
							CreatedAt: time.Now(),
						},
						Driver:     "local",
						Mountpoint: "/var/lib/docker_test/volumes/test-volume/_data",
					}, nil,
				).Once()

				// Mock repository response (not owned by user)
				mockVolumeRepo.On("FindByName", mock.Anything, "test-volume").Return(
					&models.Volume{ // Use models.Volume
						DockerResource: models.DockerResource{
							ID:     1,
							Name:   "test-volume",
							UserID: 2, // Owned by different user
						},
						Driver: "local",
					}, nil,
				).Once()
			},
			volumeID:       "test-volume",
			userRole:       "user",
			expectedStatus: http.StatusForbidden,
			expectedError:  "You don't have permission",
		},
		{
			name: "Volume Not Found",
			setupMocks: func() {
				// Mock volume service error
				mockVolumeService.On("Get", mock.Anything, "nonexistent", mock.Anything).Return(
					nil, errors.New("volume not found"),
				).Once()
			},
			volumeID:       "nonexistent",
			userRole:       "admin",
			expectedStatus: http.StatusNotFound,
			expectedError:  "Volume not found",
		},
		{
			name:           "Empty Volume ID",
			setupMocks:     func() {},
			volumeID:       "",
			userRole:       "admin",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Volume ID is required",
		},
		{
			name:           "Invalid Volume ID",
			setupMocks:     func() {},
			volumeID:       "invalid/volume/id",
			userRole:       "admin",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid volume name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			tt.setupMocks()

			// Create test context
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Create request
			req, _ := http.NewRequest("GET", "/api/v1/volumes/"+tt.volumeID, nil)
			c.Request = req
			c.Params = gin.Params{{Key: "id", Value: tt.volumeID}}

			// Set user context
			c.Set("userID", uint(1)) // Use string key
			if tt.userRole == "admin" {
				c.Set("userRoles", []string{"admin"}) // Use string key
			} else {
				c.Set("userRoles", []string{"user"}) // Use string key
			}

			// Call handler
			controller.GetVolume(c)

			// Check response status
			assert.Equal(t, tt.expectedStatus, w.Code)

			// If error expected, check error message
			if tt.expectedError != "" {
				var response models.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Contains(t, response.Error.Message, tt.expectedError)
			} else if tt.expectedStatus == http.StatusOK {
				// GetVolume uses utils.SuccessResponse
				var response models.SuccessResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.True(t, response.Success)
				require.NotNil(t, response.Data)

				// Type assert the Data field to the expected structure (*models.Volume)
				var volumeData models.Volume
				volumeDataBytes, _ := json.Marshal(response.Data)
				err = json.Unmarshal(volumeDataBytes, &volumeData)
				require.NoError(t, err)
				assert.Equal(t, tt.volumeID, volumeData.Name)
			}

			// Verify mocks
			mockVolumeService.AssertExpectations(t)
			mockVolumeRepo.AssertExpectations(t)
		})
	}
}

func TestCreateVolume(t *testing.T) {
	controller, mockVolumeService, _, _, _ := setupVolumeController(t)

	tests := []struct {
		name           string
		setupMocks     func()
		requestBody    string
		userRole       string
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Create Volume Success",
			setupMocks: func() {
				mockVolumeService.On("Create", mock.Anything, "new-volume", mock.Anything).Return(
					&models.Volume{
						DockerResource: models.DockerResource{
							Name: "new-volume",
							// CreatedAt: time.Now(), // CreatedAt is part of DockerResource
						},
						Driver:     "local",
						Mountpoint: "/var/lib/docker_test/volumes/new-volume/_data",
					}, nil,
				).Once()
			},
			requestBody:    `{"name": "new-volume", "driver": "local", "labels": {"key": "value"}}`,
			userRole:       "admin",
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Create Volume Missing Name",
			setupMocks:     func() {},
			requestBody:    `{"driver": "local"}`,
			userRole:       "admin",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Key: 'VolumeCreateRequest.Name' Error:Field validation for 'Name' failed on the 'required' tag",
		},
		{
			name: "Create Volume Service Error",
			setupMocks: func() {
				mockVolumeService.On("Create", mock.Anything, "error-volume", mock.Anything).Return(
					nil, errors.New("docker_test create error"),
				).Once()
			},
			requestBody:    `{"name": "error-volume"}`,
			userRole:       "admin",
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to create volume",
		},
		{
			name:           "Create Volume Invalid JSON",
			setupMocks:     func() {},
			requestBody:    `{"name": "bad-json",`,
			userRole:       "admin",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid request body",
		},
		{
			name:           "Create Volume Invalid Name",
			setupMocks:     func() {},
			requestBody:    `{"name": "invalid/name"}`,
			userRole:       "admin",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Key: 'VolumeCreateRequest.Name' Error:Field validation for 'Name' failed on the 'alphanumdash' tag",
		},
		{
			name:           "Create Volume Forbidden for User",
			setupMocks:     func() {},
			requestBody:    `{"name": "user-volume"}`,
			userRole:       "user",
			expectedStatus: http.StatusForbidden,
			expectedError:  "Permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req, _ := http.NewRequest("POST", "/api/v1/volumes", bytes.NewBufferString(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			c.Request = req

			c.Set("userID", uint(1))
			if tt.userRole == "admin" {
				c.Set("userRoles", []string{"admin"})
			} else {
				c.Set("userRoles", []string{"user"})
			}

			controller.CreateVolume(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var response models.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Contains(t, response.Error.Message, tt.expectedError)
			} else if tt.expectedStatus == http.StatusCreated {
				// CreateVolume returns the *models.Volume directly
				var response models.Volume // Expect models.Volume, not VolumeResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				// assert.True(t, response.Success) // No Success field in models.Volume
				// assert.NotNil(t, response.Data) // No Data field in models.Volume
				assert.Equal(t, "new-volume", response.Name) // Check Name directly
			}

			mockVolumeService.AssertExpectations(t)
		})
	}
}

func TestDeleteVolume(t *testing.T) {
	controller, mockVolumeService, mockVolumeRepo, _, _ := setupVolumeController(t)

	tests := []struct {
		name           string
		setupMocks     func()
		volumeID       string
		userRole       string
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Delete Volume Success as Admin",
			setupMocks: func() {
				// Mock repository response (optional, depends if check is needed)
				mockVolumeRepo.On("FindByName", mock.Anything, "test-volume").Return(
					&models.Volume{ // Use models.Volume
						DockerResource: models.DockerResource{ID: 1, Name: "test-volume", UserID: 1},
						Driver:         "local",
					}, nil,
				).Maybe() // Maybe because admin doesn't strictly need the DB check

				// Mock volume service response
				mockVolumeService.On("Remove", mock.Anything, "test-volume", mock.Anything).Return(nil).Once()
			},
			volumeID:       "test-volume",
			userRole:       "admin",
			expectedStatus: http.StatusNoContent,
		},
		{
			name: "Delete Volume Success as Owner",
			setupMocks: func() {
				// Mock repository response (owned by user)
				mockVolumeRepo.On("FindByName", mock.Anything, "test-volume").Return(
					&models.Volume{ // Use models.Volume
						DockerResource: models.DockerResource{ID: 1, Name: "test-volume", UserID: 1},
						Driver:         "local",
					}, nil,
				).Once()

				// Mock volume service response
				mockVolumeService.On("Remove", mock.Anything, "test-volume", mock.Anything).Return(nil).Once()
			},
			volumeID:       "test-volume",
			userRole:       "user",
			expectedStatus: http.StatusNoContent,
		},
		{
			name: "Delete Volume Not Owned by User",
			setupMocks: func() {
				// Mock repository response (not owned by user)
				mockVolumeRepo.On("FindByName", mock.Anything, "test-volume").Return(
					&models.Volume{ // Use models.Volume
						DockerResource: models.DockerResource{ID: 1, Name: "test-volume", UserID: 2}, // Different UserID
						Driver:         "local",
					}, nil,
				).Once()
			},
			volumeID:       "test-volume",
			userRole:       "user",
			expectedStatus: http.StatusForbidden,
			expectedError:  "You don't have permission",
		},
		{
			name: "Delete Volume Not Found in DB (User)",
			setupMocks: func() {
				// Mock repository error
				mockVolumeRepo.On("FindByName", mock.Anything, "not-in-db").Return(
					nil, errors.New("record not found"),
				).Once()
			},
			volumeID:       "not-in-db",
			userRole:       "user",
			expectedStatus: http.StatusNotFound, // Or Forbidden if we want consistent permission denial
			expectedError:  "Volume not found in database",
		},
		{
			name: "Delete Volume Not Found in Docker",
			setupMocks: func() {
				// Mock repository response (optional for admin)
				mockVolumeRepo.On("FindByName", mock.Anything, "docker_test-not-found").Return(
					&models.Volume{ // Use models.Volume
						DockerResource: models.DockerResource{ID: 1, Name: "docker_test-not-found", UserID: 1},
						Driver:         "local",
					}, nil,
				).Maybe()

				// Mock volume service error
				mockVolumeService.On("Remove", mock.Anything, "docker_test-not-found", mock.Anything).Return(
					errors.New("Error: No such volume: docker_test-not-found"), // Simulate Docker error
				).Once()
			},
			volumeID:       "docker_test-not-found",
			userRole:       "admin",
			expectedStatus: http.StatusNotFound,
			expectedError:  "Volume not found in Docker",
		},
		{
			name: "Delete Volume Internal Server Error",
			setupMocks: func() {
				// Mock repository response (optional for admin)
				mockVolumeRepo.On("FindByName", mock.Anything, "server-error").Return(
					&models.Volume{ // Use models.Volume
						DockerResource: models.DockerResource{ID: 1, Name: "server-error", UserID: 1},
						Driver:         "local",
					}, nil,
				).Maybe()

				// Mock volume service internal error
				mockVolumeService.On("Remove", mock.Anything, "server-error", mock.Anything).Return(
					errors.New("internal docker_test error"),
				).Once()
			},
			volumeID:       "server-error",
			userRole:       "admin",
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to remove volume",
		},
		{
			name:           "Delete Volume Invalid ID",
			setupMocks:     func() {},
			volumeID:       "invalid/id",
			userRole:       "admin",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid volume name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req, _ := http.NewRequest("DELETE", "/api/v1/volumes/"+tt.volumeID, nil)
			c.Request = req
			c.Params = gin.Params{{Key: "id", Value: tt.volumeID}}

			c.Set("userID", uint(1))
			if tt.userRole == "admin" {
				c.Set("userRoles", []string{"admin"})
			} else {
				c.Set("userRoles", []string{"user"})
			}

			controller.DeleteVolume(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var response models.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Contains(t, response.Error.Message, tt.expectedError)
			}

			mockVolumeService.AssertExpectations(t)
			mockVolumeRepo.AssertExpectations(t)
		})
	}
}

func TestInspectVolume(t *testing.T) {
	controller, mockVolumeService, mockVolumeRepo, _, _ := setupVolumeController(t)

	tests := []struct {
		name           string
		setupMocks     func()
		volumeID       string
		userRole       string
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Inspect Volume Success as Admin",
			setupMocks: func() {
				mockVolumeService.On("InspectRaw", mock.Anything, "test-volume").Return(
					volumeTypes.Volume{ // Use volumeTypes.Volume from Docker SDK
						Name:       "test-volume",
						Driver:     "local",
						Mountpoint: "/var/lib/docker_test/volumes/test-volume/_data",
						// Status:     map[string]string{"ref_count": "1"}, // Status is map[string]string - Not directly in volumeTypes.Volume
						Options:   map[string]string{"device": "tmpfs", "type": "tmpfs"},
						Labels:    map[string]string{"com.example": "test"},
						Scope:     "local",
						CreatedAt: time.Now().Format(time.RFC3339), // Format time as string
					}, nil,
				).Once()
			},
			volumeID:       "test-volume",
			userRole:       "admin",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Inspect Volume Success as Owner",
			setupMocks: func() {
				mockVolumeRepo.On("FindByName", mock.Anything, "test-volume").Return(
					&models.Volume{ // Use models.Volume
						DockerResource: models.DockerResource{ID: 1, Name: "test-volume", UserID: 1},
						Driver:         "local",
					}, nil,
				).Once()
				mockVolumeService.On("InspectRaw", mock.Anything, "test-volume").Return(
					volumeTypes.Volume{ // Use volumeTypes.Volume from Docker SDK
						Name:       "test-volume",
						Driver:     "local",
						Mountpoint: "/var/lib/docker_test/volumes/test-volume/_data",
						// Status:     map[string]string{"ref_count": "1"}, // Status is map[string]string
						Options:   map[string]string{"device": "tmpfs", "type": "tmpfs"},
						Labels:    map[string]string{"com.example": "test"},
						Scope:     "local",
						CreatedAt: time.Now().Format(time.RFC3339), // Format time as string
					}, nil,
				).Once()
			},
			volumeID:       "test-volume",
			userRole:       "user",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Inspect Volume Not Owned by User",
			setupMocks: func() {
				mockVolumeRepo.On("FindByName", mock.Anything, "other-volume").Return(
					&models.Volume{ // Use models.Volume
						DockerResource: models.DockerResource{ID: 2, Name: "other-volume", UserID: 2}, // Different UserID
						Driver:         "local",
					}, nil,
				).Once()
				// InspectRaw should not be called if permission denied early
			},
			volumeID:       "other-volume",
			userRole:       "user",
			expectedStatus: http.StatusForbidden,
			expectedError:  "You don't have permission",
		},
		{
			name: "Inspect Volume Not Found in DB (User)",
			setupMocks: func() {
				mockVolumeRepo.On("FindByName", mock.Anything, "not-in-db").Return(
					nil, errors.New("record not found"),
				).Once()
				// InspectRaw should not be called
			},
			volumeID:       "not-in-db",
			userRole:       "user",
			expectedStatus: http.StatusNotFound, // Or Forbidden
			expectedError:  "Volume not found in database",
		},
		{
			name: "Inspect Volume Not Found in Docker (Admin)",
			setupMocks: func() {
				mockVolumeService.On("InspectRaw", mock.Anything, "docker_test-not-found").Return(
					volumeTypes.Volume{}, errors.New("Error: No such volume"), // Simulate Docker error
				).Once()
			},
			volumeID:       "docker_test-not-found",
			userRole:       "admin",
			expectedStatus: http.StatusNotFound,
			expectedError:  "Volume not found in Docker",
		},
		{
			name:           "Inspect Volume Invalid ID",
			setupMocks:     func() {},
			volumeID:       "invalid/id",
			userRole:       "admin",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid volume name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req, _ := http.NewRequest("POST", "/api/v1/volumes/"+tt.volumeID+"/inspect", nil) // Corrected method and path
			c.Request = req
			c.Params = gin.Params{{Key: "id", Value: tt.volumeID}}

			c.Set("userID", uint(1))
			if tt.userRole == "admin" {
				c.Set("userRoles", []string{"admin"})
			} else {
				c.Set("userRoles", []string{"user"})
			}

			controller.InspectVolume(c) // Assuming InspectVolume is the handler name

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var response models.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Contains(t, response.Error.Message, tt.expectedError)
			} else if tt.expectedStatus == http.StatusOK {
				// InspectVolume uses utils.SuccessResponse
				var response models.SuccessResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.True(t, response.Success)
				require.NotNil(t, response.Data)

				// Type assert the Data field to map[string]interface{} as it's raw JSON
				dataMap, ok := response.Data.(map[string]interface{})
				require.True(t, ok, "Response data is not a map")
				assert.Equal(t, tt.volumeID, dataMap["Name"]) // Check name matches
			}

			mockVolumeService.AssertExpectations(t)
			mockVolumeRepo.AssertExpectations(t)
		})
	}
}
