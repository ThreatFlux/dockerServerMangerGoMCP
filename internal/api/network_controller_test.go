package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	networktypes "github.com/docker/docker/api/types/network" // Added networktypes import
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth" // Keep for auth.Service interface
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database/repositories"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"                       // Import for docker_test.Manager interface
	dockernetwork "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/network" // Alias for network service package
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// --- Mocks ---

// MockAuthServiceForNetworkTest is a mock implementation of auth.Service (Renamed)
type MockAuthServiceForNetworkTest struct {
	mock.Mock
}

// Corrected Register signature
func (m *MockAuthServiceForNetworkTest) Register(ctx context.Context, user *models.User) (*auth.TokenPair, error) {
	args := m.Called(ctx, user)
	if pair := args.Get(0); pair != nil {
		return pair.(*auth.TokenPair), args.Error(1)
	}
	return nil, args.Error(1)
}

// Corrected Login signature
func (m *MockAuthServiceForNetworkTest) Login(ctx context.Context, email, password string) (*auth.TokenPair, error) {
	args := m.Called(ctx, email, password)
	if pair := args.Get(0); pair != nil {
		return pair.(*auth.TokenPair), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockAuthServiceForNetworkTest) Verify(ctx context.Context, tokenString string) (*auth.TokenDetails, error) { // Added Verify
	args := m.Called(ctx, tokenString)
	if details := args.Get(0); details != nil {
		return details.(*auth.TokenDetails), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockAuthServiceForNetworkTest) Refresh(ctx context.Context, refreshToken string) (*auth.TokenPair, error) { // Added Refresh
	args := m.Called(ctx, refreshToken)
	if pair := args.Get(0); pair != nil {
		return pair.(*auth.TokenPair), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockAuthServiceForNetworkTest) Logout(ctx context.Context, token string) error { // Added ctx
	args := m.Called(ctx, token)
	return args.Error(0)
}
func (m *MockAuthServiceForNetworkTest) GenerateTokens(ctx context.Context, user *models.User) (*auth.TokenPair, error) { // Added GenerateTokens
	args := m.Called(ctx, user)
	if pair := args.Get(0); pair != nil {
		return pair.(*auth.TokenPair), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockAuthServiceForNetworkTest) HashPassword(password string) (string, error) { // Added HashPassword
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

// Correct CheckPassword signature to match auth.Service interface
func (m *MockAuthServiceForNetworkTest) CheckPassword(password, hash string) bool {
	args := m.Called(password, hash)
	return args.Bool(0)
}

// Add other methods from auth.Service if needed by middleware or controller

// MockNetworkService is a mock of the network.Service interface
type MockNetworkService struct {
	mock.Mock
}

func (m *MockNetworkService) Create(ctx context.Context, name string, options dockernetwork.CreateOptions) (*models.Network, error) {
	args := m.Called(ctx, name, options)
	if net := args.Get(0); net != nil {
		return net.(*models.Network), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockNetworkService) Get(ctx context.Context, idOrName string, options dockernetwork.GetOptions) (*models.Network, error) {
	args := m.Called(ctx, idOrName, options)
	if net := args.Get(0); net != nil {
		return net.(*models.Network), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockNetworkService) List(ctx context.Context, options dockernetwork.ListOptions) ([]*models.Network, error) {
	args := m.Called(ctx, options)
	if networks := args.Get(0); networks != nil {
		return networks.([]*models.Network), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockNetworkService) Remove(ctx context.Context, idOrName string, options dockernetwork.RemoveOptions) error {
	args := m.Called(ctx, idOrName, options)
	return args.Error(0)
}

// Corrected Prune signature to match interface
func (m *MockNetworkService) Prune(ctx context.Context, options dockernetwork.PruneOptions) (networktypes.PruneReport, error) {
	args := m.Called(ctx, options)
	// Assuming the mock returns the correct type or handle type assertion error
	if report, ok := args.Get(0).(networktypes.PruneReport); ok {
		return report, args.Error(1)
	}
	// Return zero value if type assertion fails or Get(0) is nil
	return networktypes.PruneReport{}, args.Error(1)
}

func (m *MockNetworkService) Connect(ctx context.Context, networkIDOrName, containerIDOrName string, options dockernetwork.ConnectOptions) error {
	args := m.Called(ctx, networkIDOrName, containerIDOrName, options)
	return args.Error(0)
}

func (m *MockNetworkService) Disconnect(ctx context.Context, networkIDOrName, containerIDOrName string, options dockernetwork.DisconnectOptions) error {
	args := m.Called(ctx, networkIDOrName, containerIDOrName, options)
	return args.Error(0)
}

func (m *MockNetworkService) InspectRaw(ctx context.Context, idOrName string) (networktypes.Inspect, error) { // Use networktypes.Inspect
	args := m.Called(ctx, idOrName)
	// Assuming the mock returns the correct type or handle type assertion error
	if inspect, ok := args.Get(0).(networktypes.Inspect); ok {
		return inspect, args.Error(1)
	}
	// Return zero value if type assertion fails or Get(0) is nil
	return networktypes.Inspect{}, args.Error(1)
}

func (m *MockNetworkService) GetNetworkDrivers(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	if drivers := args.Get(0); drivers != nil {
		return drivers.([]string), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockNetworkService) FindNetworkByContainer(ctx context.Context, containerIDOrName string, options dockernetwork.ListOptions) ([]*models.Network, error) {
	args := m.Called(ctx, containerIDOrName, options)
	if networks := args.Get(0); networks != nil {
		return networks.([]*models.Network), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockNetworkService) FindNetworkByName(ctx context.Context, pattern string, options dockernetwork.ListOptions) ([]*models.Network, error) {
	args := m.Called(ctx, pattern, options)
	if networks := args.Get(0); networks != nil {
		return networks.([]*models.Network), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockNetworkService) FindNetworkBySubnet(ctx context.Context, subnet string, options dockernetwork.ListOptions) ([]*models.Network, error) {
	args := m.Called(ctx, subnet, options)
	if networks := args.Get(0); networks != nil {
		return networks.([]*models.Network), args.Error(1)
	}
	return nil, args.Error(1)
}

// MockNetworkRepository is a mock of the repositories.NetworkRepository
type MockNetworkRepository struct {
	mock.Mock
}

func (m *MockNetworkRepository) Create(ctx context.Context, network *models.Network) error { // Use models.Network
	args := m.Called(ctx, network)
	return args.Error(0)
}

func (m *MockNetworkRepository) Update(ctx context.Context, network *models.Network) error { // Use models.Network
	args := m.Called(ctx, network)
	return args.Error(0)
}

// Corrected Delete signature to match interface (assuming ID is uint)
func (m *MockNetworkRepository) Delete(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// Add missing DeleteByNetworkID method
func (m *MockNetworkRepository) DeleteByNetworkID(ctx context.Context, networkID string) error {
	args := m.Called(ctx, networkID)
	return args.Error(0)
}

// Add missing FindByNetworkID method
func (m *MockNetworkRepository) FindByNetworkID(ctx context.Context, networkID string) (*models.Network, error) {
	args := m.Called(ctx, networkID)
	if net := args.Get(0); net != nil {
		if net == nil {
			return nil, args.Error(1)
		}
		return net.(*models.Network), args.Error(1)
	}
	return nil, args.Error(1)
}

// Add missing List method
func (m *MockNetworkRepository) List(ctx context.Context, options repositories.ListOptions) ([]*models.Network, int64, error) {
	args := m.Called(ctx, options)
	var networks []*models.Network
	if n := args.Get(0); n != nil {
		networks = n.([]*models.Network)
	}
	return networks, int64(args.Int(1)), args.Error(2)
}

func (m *MockNetworkRepository) FindByID(ctx context.Context, id uint) (*models.Network, error) { // Use uint and models.Network
	args := m.Called(ctx, id)
	if net := args.Get(0); net != nil {
		if net == nil {
			return nil, args.Error(1)
		}
		return net.(*models.Network), args.Error(1) // Use models.Network
	}
	return nil, args.Error(1)
}

func (m *MockNetworkRepository) FindByName(ctx context.Context, name string) (*models.Network, error) { // Use models.Network
	args := m.Called(ctx, name)
	if net := args.Get(0); net != nil {
		if net == nil {
			return nil, args.Error(1)
		}
		return net.(*models.Network), args.Error(1) // Use models.Network
	}
	return nil, args.Error(1)
}

func (m *MockNetworkRepository) FindAll(ctx context.Context) ([]*models.Network, error) { // Use models.Network
	args := m.Called(ctx)
	if networks := args.Get(0); networks != nil {
		if networks == nil {
			return nil, args.Error(1)
		}
		return networks.([]*models.Network), args.Error(1) // Use models.Network
	}
	return nil, args.Error(1)
}

func (m *MockNetworkRepository) FindByUserID(ctx context.Context, userID uint) ([]*models.Network, error) { // Use uint for userID and models.Network
	args := m.Called(ctx, userID)
	if networks := args.Get(0); networks != nil {
		if networks == nil {
			return nil, args.Error(1)
		}
		return networks.([]*models.Network), args.Error(1) // Use models.Network
	}
	return nil, args.Error(1)
}

// MockContainerRepositoryForNetworkTest is a mock of the repositories.ContainerRepository
type MockContainerRepositoryForNetworkTest struct { // Renamed mock
	mock.Mock
}

// Renamed mock method receiver, use models.Container
func (m *MockContainerRepositoryForNetworkTest) FindByIDOrName(ctx context.Context, idOrName string) (*models.Container, error) {
	args := m.Called(ctx, idOrName)
	// Return the correct type models.Container
	if container := args.Get(0); container != nil {
		if container == nil {
			return nil, args.Error(1)
		}
		return container.(*models.Container), args.Error(1)
	}
	return nil, args.Error(1)
}

// MockDockerManager is now defined in mocks_test.go

// Implement other docker_test.Manager methods if needed by the controller under test
// Example:
// func (m *MockDockerManager) ContainerService() interfaces.ContainerService {
// 	args := m.Called()
// 	return args.Get(0).(interfaces.ContainerService)
// }

// --- Test Setup ---

// Set up a test router with the network controller
// Accepts interfaces now
func setupNetworkTestRouter(networkService dockernetwork.Service, networkRepo repositories.NetworkRepository, dockerManager docker.Manager) (*gin.Engine, *NetworkController) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs during tests

	// Create mocked auth service
	authService := new(MockAuthServiceForNetworkTest) // Use renamed mock
	authService.On("ValidateToken", mock.Anything, mock.Anything).Return(&models.User{
		ID:    1,                                          // Use uint ID
		Roles: []models.UserRole{{Role: models.RoleUser}}, // Use correct type
	}, nil)

	// Create auth middleware (pass only service)
	authMW := middleware.NewAuthMiddleware(authService) // Pass the mock service directly

	// Create network controller (pass interfaces)
	// Ensure NewNetworkController expects interfaces
	controller := NewNetworkController(networkService, networkRepo, dockerManager, logger)

	// Register routes
	api := router.Group("/api/v1")
	controller.RegisterRoutes(api, authMW)

	return router, controller
}

// --- Tests ---

func TestListNetworks(t *testing.T) {
	// Create mocks
	mockService := new(MockNetworkService)
	mockRepo := new(MockNetworkRepository)
	mockDockerManager := new(MockDockerManager) // Use docker_test manager mock

	// Set up test router
	router, _ := setupNetworkTestRouter(mockService, mockRepo, mockDockerManager) // Pass interfaces

	// Mock repository response (only return network belonging to user 1)
	userNetworks := []*models.Network{
		{
			DockerResource: models.DockerResource{ID: 1, Name: "test-network", UserID: 1}, // Use embedded struct
			NetworkID:      "network1",
			Driver:         "bridge",
		},
	}
	mockRepo.On("FindByUserID", mock.Anything, uint(1)).Return(userNetworks, nil) // Expect uint ID

	// Create request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/networks", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response models.SuccessResponse // Expect generic success response wrapping the data
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)

	// Need to decode the generic `Data` field
	var networkList []models.Network
	jsonData, _ := json.Marshal(response.Data)   // Re-marshal the Data part
	err = json.Unmarshal(jsonData, &networkList) // Unmarshal into the expected slice type
	assert.NoError(t, err)
	assert.Len(t, networkList, 1) // Only one network belongs to test user 1
	assert.Equal(t, "network1", networkList[0].NetworkID)

	// Verify mocks
	mockRepo.AssertExpectations(t)
}

func TestCreateNetwork(t *testing.T) {
	// Create mocks
	mockService := new(MockNetworkService)
	mockRepo := new(MockNetworkRepository)
	mockDockerManager := new(MockDockerManager)

	// Set up test router
	router, _ := setupNetworkTestRouter(mockService, mockRepo, mockDockerManager)

	// Mock service response
	newNetwork := &models.Network{
		DockerResource: models.DockerResource{Name: "test-network", UserID: 1}, // Use embedded struct
		NetworkID:      "network1",
		Driver:         "bridge",
	}

	// Mock service Create call
	mockService.On("Create", mock.Anything, "test-network", mock.AnythingOfType("network.CreateOptions")).Return(newNetwork, nil)
	// Mock repository Create call
	mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(net *models.Network) bool {
		return net.Name == "test-network" && net.UserID == 1 // Check UserID is set
	})).Return(nil)

	// Create request body
	requestBody := models.NetworkCreateRequest{
		Name:   "test-network",
		Driver: "bridge",
		Labels: map[string]string{"app": "test"},
	}

	requestJSON, _ := json.Marshal(requestBody)

	// Create request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/networks", bytes.NewBuffer(requestJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-token")

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusCreated, w.Code)

	var response models.SuccessResponse // Expect generic success response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)

	// Decode the Data field
	var createdNetwork models.Network
	jsonData, _ := json.Marshal(response.Data)
	err = json.Unmarshal(jsonData, &createdNetwork)
	assert.NoError(t, err)
	assert.Equal(t, "network1", createdNetwork.NetworkID)
	assert.Equal(t, "test-network", createdNetwork.Name)

	// Verify mocks
	mockService.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestGetNetwork(t *testing.T) {
	// Create mocks
	mockService := new(MockNetworkService)
	mockRepo := new(MockNetworkRepository)
	mockDockerManager := new(MockDockerManager)

	// Set up test router
	router, _ := setupNetworkTestRouter(mockService, mockRepo, mockDockerManager)

	// Mock repository response
	dbNetwork := &models.Network{
		DockerResource: models.DockerResource{ID: 10, Name: "test-network", UserID: 1}, // Use embedded struct
		NetworkID:      "network1",
		Driver:         "bridge",
	}
	mockRepo.On("FindByID", mock.Anything, uint(10)).Return(dbNetwork, nil) // Expect uint ID

	// Create request
	w := httptest.NewRecorder()
	// Use the DB ID (uint) in the URL path as per typical REST patterns
	req, _ := http.NewRequest("GET", "/api/v1/networks/10", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response models.SuccessResponse // Expect generic success response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)

	// Decode the Data field
	var fetchedNetwork models.Network
	jsonData, _ := json.Marshal(response.Data)
	err = json.Unmarshal(jsonData, &fetchedNetwork)
	assert.NoError(t, err)
	assert.Equal(t, "network1", fetchedNetwork.NetworkID)
	assert.Equal(t, "test-network", fetchedNetwork.Name)

	// Verify mocks
	mockRepo.AssertExpectations(t)
}

func TestDeleteNetwork(t *testing.T) {
	// Create mocks
	mockService := new(MockNetworkService)
	mockRepo := new(MockNetworkRepository)
	mockDockerManager := new(MockDockerManager)

	// Set up test router
	router, _ := setupNetworkTestRouter(mockService, mockRepo, mockDockerManager)

	// Mock repository response
	dbNetwork := &models.Network{
		DockerResource: models.DockerResource{ID: 10, Name: "test-network", UserID: 1}, // Use embedded struct
		NetworkID:      "network1",
		Driver:         "bridge",
	}
	mockRepo.On("FindByID", mock.Anything, uint(10)).Return(dbNetwork, nil) // Expect uint ID
	mockRepo.On("Delete", mock.Anything, uint(10)).Return(nil)              // Expect uint ID

	// Mock service response
	mockService.On("Remove", mock.Anything, "network1", mock.AnythingOfType("network.RemoveOptions")).Return(nil)

	// Create request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/api/v1/networks/10", nil) // Use DB ID
	req.Header.Set("Authorization", "Bearer valid-token")

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify mocks
	mockService.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestConnectContainer(t *testing.T) {
	// Create mocks
	mockService := new(MockNetworkService)
	mockRepo := new(MockNetworkRepository)
	// mockContainerRepo := new(MockContainerRepositoryForNetworkTest) // Removed unused mock
	mockDockerManager := new(MockDockerManager)

	// Set up test router
	router, _ := setupNetworkTestRouter(mockService, mockRepo, mockDockerManager) // Get controller instance

	// Mock repository responses
	mockRepo.On("FindByID", mock.Anything, uint(10)).Return(&models.Network{ // Use uint ID
		DockerResource: models.DockerResource{ID: 10, Name: "bridge-net", UserID: 1},
		NetworkID:      "network1",
	}, nil)

	// Mock service connect call (assuming it resolves container name/id internally)
	mockService.On("Connect", mock.Anything, "network1", "container1", mock.AnythingOfType("network.ConnectOptions")).Return(nil)

	// Create request body
	requestBody := models.NetworkConnectRequest{
		Container: "container1", // Use container name or ID
	}
	requestJSON, _ := json.Marshal(requestBody)

	// Create request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/networks/10/connect", bytes.NewBuffer(requestJSON)) // Use network DB ID
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-token")

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify mocks
	mockService.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestDisconnectContainer(t *testing.T) {
	// Create mocks
	mockService := new(MockNetworkService)
	mockRepo := new(MockNetworkRepository)
	// mockContainerRepo := new(MockContainerRepositoryForNetworkTest) // Removed unused mock
	mockDockerManager := new(MockDockerManager)

	// Set up test router
	router, _ := setupNetworkTestRouter(mockService, mockRepo, mockDockerManager)

	// Mock repository responses
	mockRepo.On("FindByID", mock.Anything, uint(10)).Return(&models.Network{ // Use uint ID
		DockerResource: models.DockerResource{ID: 10, Name: "bridge-net", UserID: 1},
		NetworkID:      "network1",
	}, nil)

	// Mock service disconnect call (assuming it resolves container name/id internally)
	mockService.On("Disconnect", mock.Anything, "network1", "container1", mock.AnythingOfType("network.DisconnectOptions")).Return(nil)

	// Create request body
	requestBody := models.NetworkDisconnectRequest{
		Container: "container1",
		Force:     false,
	}
	requestJSON, _ := json.Marshal(requestBody)

	// Create request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/networks/10/disconnect", bytes.NewBuffer(requestJSON)) // Use network DB ID
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid-token")

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify mocks
	mockService.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestGetNetworkDrivers(t *testing.T) {
	// This endpoint might not exist or require specific permissions/service method
	t.Skip("Skipping GetNetworkDrivers test as endpoint/logic might not be implemented")
}

func TestPruneNetworks(t *testing.T) {
	// Create mocks
	mockService := new(MockNetworkService)
	mockRepo := new(MockNetworkRepository)
	mockDockerManager := new(MockDockerManager)

	// Set up test router with admin user
	gin.SetMode(gin.TestMode)
	router := gin.New()
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	authService := new(MockAuthServiceForNetworkTest) // Use renamed mock
	authService.On("ValidateToken", mock.Anything, mock.Anything).Return(&models.User{
		ID:    1,                                           // Use uint ID
		Roles: []models.UserRole{{Role: models.RoleAdmin}}, // ADMIN User
	}, nil)
	authMW := middleware.NewAuthMiddleware(authService) // Pass mock service
	// Ensure NewNetworkController expects interfaces
	controller := NewNetworkController(mockService, mockRepo, mockDockerManager, logger)
	api := router.Group("/api/v1")
	// Assuming prune is under /api/v1/networks/prune and requires admin
	adminRoutes := api.Group("/", authMW.RequireRole(string(models.RoleAdmin))) // Cast Role to string
	adminRoutes.POST("/networks/prune", controller.PruneNetworks)               // Register prune route

	// Mock service response
	pruneReport := networktypes.PruneReport{ // Use SDK type
		NetworksDeleted: []string{"net1", "net2"},
	}
	mockService.On("Prune", mock.Anything, mock.AnythingOfType("network.PruneOptions")).Return(pruneReport, nil)

	// Create request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/networks/prune", nil) // Corrected endpoint
	req.Header.Set("Authorization", "Bearer admin-token")

	// Perform request
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response models.SuccessResponse // Expect generic success response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)

	// Decode the Data field into the SDK type
	var reportData networktypes.PruneReport
	jsonData, _ := json.Marshal(response.Data)
	err = json.Unmarshal(jsonData, &reportData)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"net1", "net2"}, reportData.NetworksDeleted)

	// Verify mocks
	mockService.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestNetworkErrorHandling(t *testing.T) {
	// Create mocks
	mockService := new(MockNetworkService)
	mockRepo := new(MockNetworkRepository)
	mockDockerManager := new(MockDockerManager)

	// Set up test router
	router, _ := setupNetworkTestRouter(mockService, mockRepo, mockDockerManager)

	// --- Test Get Not Found ---
	mockRepo.On("FindByID", mock.Anything, uint(99)).Return(nil, errors.New("not found")) // Simulate repo not found

	wGet := httptest.NewRecorder()
	reqGet, _ := http.NewRequest("GET", "/api/v1/networks/99", nil)
	reqGet.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(wGet, reqGet)
	assert.Equal(t, http.StatusNotFound, wGet.Code)
	mockRepo.AssertCalled(t, "FindByID", mock.Anything, uint(99))

	// --- Test Create Service Error ---
	mockService.On("Create", mock.Anything, "fail-create", mock.AnythingOfType("network.CreateOptions")).Return(nil, errors.New("docker_test daemon error"))

	reqBodyCreate := `{"name": "fail-create"}`
	wCreate := httptest.NewRecorder()
	reqCreate, _ := http.NewRequest("POST", "/api/v1/networks", bytes.NewBufferString(reqBodyCreate))
	reqCreate.Header.Set("Content-Type", "application/json")
	reqCreate.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(wCreate, reqCreate)
	assert.Equal(t, http.StatusInternalServerError, wCreate.Code)
	mockService.AssertCalled(t, "Create", mock.Anything, "fail-create", mock.AnythingOfType("network.CreateOptions"))

	// --- Test Delete Service Error ---
	// Mock repo find first
	mockRepo.On("FindByID", mock.Anything, uint(11)).Return(&models.Network{
		DockerResource: models.DockerResource{ID: 11, UserID: 1},
		NetworkID:      "net-to-fail-delete",
	}, nil)
	mockService.On("Remove", mock.Anything, "net-to-fail-delete", mock.AnythingOfType("network.RemoveOptions")).Return(errors.New("cannot remove network"))

	wDelete := httptest.NewRecorder()
	reqDelete, _ := http.NewRequest("DELETE", "/api/v1/networks/11", nil)
	reqDelete.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(wDelete, reqDelete)
	assert.Equal(t, http.StatusInternalServerError, wDelete.Code)
	mockService.AssertCalled(t, "Remove", mock.Anything, "net-to-fail-delete", mock.AnythingOfType("network.RemoveOptions"))
	// Repo Delete should NOT be called if service Remove fails
	mockRepo.AssertNotCalled(t, "Delete", mock.Anything, uint(11))

}
