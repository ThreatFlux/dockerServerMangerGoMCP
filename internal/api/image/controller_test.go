package image

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	apitypes "github.com/docker/docker/api/types" // Import types with alias
	"github.com/docker/docker/api/types/image"
	registrytypes "github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client" // Import client for APIClient interface
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	auth_test "github.com/threatflux/dockerServerMangerGoMCP/internal/auth"             // Use main auth package for MockService
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"                     // Import docker_test package for Manager
	image_service "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/image" // Alias for image service package
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// --- Mocks ---

// MockImageService implements image.Service interface
type MockImageService struct {
	mock.Mock
}

func (m *MockImageService) ImagePull(ctx context.Context, refStr string, options image.PullOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, refStr, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}
func (m *MockImageService) ImageInspectWithRaw(ctx context.Context, imageID string) (image.InspectResponse, []byte, error) {
	args := m.Called(ctx, imageID)
	return args.Get(0).(image.InspectResponse), args.Get(1).([]byte), args.Error(2)
}
func (m *MockImageService) ImageRemove(ctx context.Context, imageID string, options image.RemoveOptions) ([]image.DeleteResponse, error) {
	args := m.Called(ctx, imageID, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]image.DeleteResponse), args.Error(1)
}
func (m *MockImageService) List(ctx context.Context, options image_service.ListOptions) ([]image.Summary, error) { // Use alias
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]image.Summary), args.Error(1)
}
func (m *MockImageService) Build(ctx context.Context, options image_service.BuildOptions) (io.ReadCloser, error) { // Added missing method
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}
func (m *MockImageService) Tag(ctx context.Context, imageID, ref string) error {
	args := m.Called(ctx, imageID, ref)
	return args.Error(0)
}
func (m *MockImageService) Inspect(ctx context.Context, imageID string) (image.InspectResponse, error) { // Corrected return type
	args := m.Called(ctx, imageID)
	return args.Get(0).(image.InspectResponse), args.Error(1)
}
func (m *MockImageService) History(ctx context.Context, imageID string) ([]image.HistoryResponseItem, error) {
	args := m.Called(ctx, imageID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]image.HistoryResponseItem), args.Error(1)
}
func (m *MockImageService) Prune(ctx context.Context, options image_service.PruneOptions) (image.PruneReport, error) { // Use alias
	args := m.Called(ctx, options)
	return args.Get(0).(image.PruneReport), args.Error(1)
}
func (m *MockImageService) Search(ctx context.Context, term string, options image_service.SearchOptions) ([]registrytypes.SearchResult, error) { // Use alias
	args := m.Called(ctx, term, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]registrytypes.SearchResult), args.Error(1)
}

// MockImageRepository implements repositories.ImageRepository
type MockImageRepository struct {
	mock.Mock
}

func (m *MockImageRepository) Create(ctx context.Context, image *models.Image) error { // Added missing method
	args := m.Called(ctx, image)
	return args.Error(0)
}
func (m *MockImageRepository) FindByUserID(ctx context.Context, userID uint) ([]*models.Image, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Image), args.Error(1)
}
func (m *MockImageRepository) FindByImageID(ctx context.Context, imageID string) (*models.Image, error) {
	args := m.Called(ctx, imageID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Image), args.Error(1)
}
func (m *MockImageRepository) FindByID(ctx context.Context, id uint) (*models.Image, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Image), args.Error(1)
}
func (m *MockImageRepository) Delete(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockImageRepository) DeleteByImageID(ctx context.Context, imageID string) error {
	args := m.Called(ctx, imageID)
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

// setupTestController sets up the Gin engine and controller for testing
func setupTestController(t *testing.T) (*Controller, *gin.Engine, *MockImageService, *MockImageRepository, *MockManager) { // Added MockManager
	gin.SetMode(gin.TestMode)
	router := gin.New()
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs

	mockImageService := new(MockImageService)
	mockImageRepo := new(MockImageRepository)
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
	controller := NewController(mockImageService, mockImageRepo, mockDockerManager, logger) // Pass mocks

	// Register routes
	api := router.Group("/api/v1")
	controller.RegisterRoutes(api, authMW)

	return controller, router, mockImageService, mockImageRepo, mockDockerManager // Added MockManager
}

func TestListImages(t *testing.T) {
	_, router, mockService, _, _ := setupTestController(t) // Adjusted return values

	expectedImages := []image.Summary{
		{ID: "sha256:123", RepoTags: []string{"nginx:latest"}},
		{ID: "sha256:456", RepoTags: []string{"alpine:3.14"}},
	}
	mockService.On("List", mock.Anything, mock.AnythingOfType("image.ListOptions")).Return(expectedImages, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/images", nil)
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

func TestPullImage(t *testing.T) {
	_, router, mockService, _, _ := setupTestController(t) // Adjusted return values
	imageRef := "nginx:latest"
	pullOutput := `{"status":"Pulling from library/nginx","id":"latest"}...`

	mockService.On("ImagePull", mock.Anything, imageRef, mock.AnythingOfType("image.PullOptions")).Return(io.NopCloser(bytes.NewReader([]byte(pullOutput))), nil)

	reqBody := gin.H{"image": imageRef}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/images/pull", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-token") // Add auth header
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type")) // Expect JSON stream
	assert.Contains(t, w.Body.String(), `"status":"Pulling from library/nginx"`)
	mockService.AssertExpectations(t)
}

func TestRemoveImage(t *testing.T) {
	_, router, mockService, _, _ := setupTestController(t) // Adjusted return values
	imageID := "sha256:123"
	expectedResponse := []image.DeleteResponse{{Untagged: "nginx:latest"}, {Deleted: imageID}}

	mockService.On("ImageRemove", mock.Anything, imageID, mock.AnythingOfType("image.RemoveOptions")).Return(expectedResponse, nil)

	w := httptest.NewRecorder()
	// Use wildcard route for delete: /api/v1/images/*id
	req, _ := http.NewRequest("DELETE", "/api/v1/images/"+imageID, nil)
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

// Add tests for InspectImage, TagImage, PruneImages, SearchImages, BuildImage, GetImageHistory

// --- Example test using context ---
func TestListImagesWithAuthContext(t *testing.T) {
	controller, _, mockService, _, _ := setupTestController(t) // Adjusted return values

	expectedImages := []image.Summary{
		{ID: "sha256:123", RepoTags: []string{"nginx:latest"}},
	}
	mockService.On("List", mock.Anything, mock.AnythingOfType("image.ListOptions")).Return(expectedImages, nil)

	// Create a Gin context with necessary values
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/api/v1/images", nil)
	c.Set("userID", uint(1))                              // Use string key
	c.Set("userRoles", []string{string(models.RoleUser)}) // Use string key

	controller.List(c) // Call the correct handler method 'List'

	assert.Equal(t, http.StatusOK, w.Code)
	// ... further assertions on the response body ...
	mockService.AssertExpectations(t)
}
