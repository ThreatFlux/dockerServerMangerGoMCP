package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// MockAuthService is a mock implementation of the auth.Service interface
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Login(ctx context.Context, email, password string) (*auth.TokenPair, error) {
	args := m.Called(ctx, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.TokenPair), args.Error(1)
}

func (m *MockAuthService) Register(ctx context.Context, user *models.User) (*auth.TokenPair, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.TokenPair), args.Error(1)
}

func (m *MockAuthService) Verify(ctx context.Context, token string) (*auth.TokenDetails, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.TokenDetails), args.Error(1)
}

func (m *MockAuthService) Refresh(ctx context.Context, refreshToken string) (*auth.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.TokenPair), args.Error(1)
}

func (m *MockAuthService) Logout(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockAuthService) GenerateTokens(ctx context.Context, user *models.User) (*auth.TokenPair, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.TokenPair), args.Error(1)
}

func (m *MockAuthService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) CheckPassword(password, hash string) bool {
	args := m.Called(password, hash)
	return args.Bool(0)
}

// Setup test environment for auth middleware tests
func setupAuthMiddlewareTest() (*gin.Engine, *MockAuthService) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create mock auth service
	mockAuthService := new(MockAuthService)

	// Create test router
	router := gin.New()

	return router, mockAuthService
}

func TestRequireAuthentication_Success(t *testing.T) {
	// Setup
	router, mockAuthService := setupAuthMiddlewareTest()
	authMiddleware := NewAuthMiddleware(mockAuthService)

	// Setup mock responses
	tokenDetails := &auth.TokenDetails{
		UserID: 1,
		Roles:  []string{"user"},
	}
	mockAuthService.On("Verify", mock.Anything, "valid-token").Return(tokenDetails, nil)

	// Add test route
	router.GET("/protected", authMiddleware.RequireAuthentication(), func(c *gin.Context) {
		userID, exists := c.Get("userID") // Use string key
		assert.True(t, exists)
		assert.Equal(t, uint(1), userID)

		roles, exists := c.Get("userRoles") // Use string key
		assert.True(t, exists)
		assert.Equal(t, []string{"user"}, roles)

		c.Status(http.StatusOK)
	})

	// Create test request
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	resp := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusOK, resp.Code)
	mockAuthService.AssertExpectations(t)
}

func TestRequireAuthentication_MissingHeader(t *testing.T) {
	// Setup
	router, mockAuthService := setupAuthMiddlewareTest()
	authMiddleware := NewAuthMiddleware(mockAuthService)

	// Add test route
	router.GET("/protected", authMiddleware.RequireAuthentication(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Create test request without Authorization header
	req := httptest.NewRequest("GET", "/protected", nil)
	resp := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	mockAuthService.AssertExpectations(t)
}

func TestRequireAuthentication_InvalidHeader(t *testing.T) {
	// Setup
	router, mockAuthService := setupAuthMiddlewareTest()
	authMiddleware := NewAuthMiddleware(mockAuthService)

	// Add test route
	router.GET("/protected", authMiddleware.RequireAuthentication(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Test cases for invalid headers
	testCases := []struct {
		name   string
		header string
	}{
		{"missing bearer", "valid-token"},
		{"empty token", "Bearer "},
		{"wrong format", "NotBearer valid-token"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test request with invalid header
			req := httptest.NewRequest("GET", "/protected", nil)
			req.Header.Set("Authorization", tc.header)
			resp := httptest.NewRecorder()

			// Perform request
			router.ServeHTTP(resp, req)

			// Check response
			assert.Equal(t, http.StatusUnauthorized, resp.Code)
		})
	}

	mockAuthService.AssertExpectations(t)
}

func TestRequireAuthentication_InvalidToken(t *testing.T) {
	// Setup
	router, mockAuthService := setupAuthMiddlewareTest()
	authMiddleware := NewAuthMiddleware(mockAuthService)

	// Setup mock responses
	mockAuthService.On("Verify", mock.Anything, "invalid-token").
		Return(nil, errors.New("token validation error"))

	// Add test route
	router.GET("/protected", authMiddleware.RequireAuthentication(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Create test request
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	resp := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	mockAuthService.AssertExpectations(t)
}

func TestRequireRole_Success(t *testing.T) {
	// Setup
	router, mockAuthService := setupAuthMiddlewareTest()
	authMiddleware := NewAuthMiddleware(mockAuthService)

	// Setup mock responses
	tokenDetails := &auth.TokenDetails{
		UserID: 1,
		Roles:  []string{"admin", "user"},
	}
	mockAuthService.On("Verify", mock.Anything, "valid-token").Return(tokenDetails, nil)

	// Add test routes
	router.GET("/admin-only",
		authMiddleware.RequireAuthentication(),
		authMiddleware.RequireRole("admin"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	router.GET("/multi-role",
		authMiddleware.RequireAuthentication(),
		authMiddleware.RequireRole("editor", "admin"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	// Test admin role access
	req := httptest.NewRequest("GET", "/admin-only", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)

	// Test multi-role access
	req = httptest.NewRequest("GET", "/multi-role", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	resp = httptest.NewRecorder()

	router.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)

	mockAuthService.AssertExpectations(t)
}

func TestRequireRole_Forbidden(t *testing.T) {
	// Setup
	router, mockAuthService := setupAuthMiddlewareTest()
	authMiddleware := NewAuthMiddleware(mockAuthService)

	// Setup mock responses
	tokenDetails := &auth.TokenDetails{
		UserID: 1,
		Roles:  []string{"user"},
	}
	mockAuthService.On("Verify", mock.Anything, "user-token").Return(tokenDetails, nil)

	// Add test route
	router.GET("/admin-only",
		authMiddleware.RequireAuthentication(),
		authMiddleware.RequireRole("admin"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	// Create test request
	req := httptest.NewRequest("GET", "/admin-only", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	resp := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusForbidden, resp.Code)
	mockAuthService.AssertExpectations(t)
}

func TestRequireAdmin_Success(t *testing.T) {
	// Setup
	router, mockAuthService := setupAuthMiddlewareTest()
	authMiddleware := NewAuthMiddleware(mockAuthService)

	// Setup mock responses
	tokenDetails := &auth.TokenDetails{
		UserID: 1,
		Roles:  []string{"admin"},
	}
	mockAuthService.On("Verify", mock.Anything, "admin-token").Return(tokenDetails, nil)

	// Add test route
	router.GET("/admin-only",
		authMiddleware.RequireAuthentication(),
		authMiddleware.RequireAdmin(),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	// Create test request
	req := httptest.NewRequest("GET", "/admin-only", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	resp := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusOK, resp.Code)
	mockAuthService.AssertExpectations(t)
}

func TestGetUserID(t *testing.T) {
	// Create gin context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("userID", uint(1)) // Use string key

	// Get user ID
	userID, err := GetUserID(c) // Pass *gin.Context
	require.NoError(t, err)
	assert.Equal(t, uint(1), userID)

	// Test with missing user ID
	w = httptest.NewRecorder()
	emptyCtx, _ := gin.CreateTestContext(w)
	userID, err = GetUserID(emptyCtx) // Pass *gin.Context
	require.Error(t, err)
	assert.Equal(t, uint(0), userID)

	// Test with wrong type
	w = httptest.NewRecorder()
	wrongTypeCtx, _ := gin.CreateTestContext(w)
	wrongTypeCtx.Set("userID", "not-a-uint") // Use string key
	userID, err = GetUserID(wrongTypeCtx)    // Pass *gin.Context
	require.Error(t, err)
	assert.Equal(t, uint(0), userID)
}

func TestGetUserRoles(t *testing.T) {
	// Create gin context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("userRoles", []string{"admin", "user"}) // Use string key

	// Get user roles
	roles, err := GetUserRoles(c) // Pass *gin.Context
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "user"}, roles)

	// Test with missing roles
	w = httptest.NewRecorder()
	emptyCtx, _ := gin.CreateTestContext(w)
	roles, err = GetUserRoles(emptyCtx) // Pass *gin.Context
	require.Error(t, err)
	assert.Nil(t, roles)

	// Test with wrong type
	w = httptest.NewRecorder()
	wrongTypeCtx, _ := gin.CreateTestContext(w)
	wrongTypeCtx.Set("userRoles", "not-a-slice") // Use string key
	roles, err = GetUserRoles(wrongTypeCtx)      // Pass *gin.Context
	require.Error(t, err)
	assert.Nil(t, roles)
}

func TestHasRole(t *testing.T) {
	// Create gin context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("userRoles", []string{"admin", "user"}) // Use string key

	// Check roles
	hasAdmin, err := HasRole(c, "admin") // Pass *gin.Context
	require.NoError(t, err)
	assert.True(t, hasAdmin)

	hasUser, err := HasRole(c, "user") // Pass *gin.Context
	require.NoError(t, err)
	assert.True(t, hasUser)

	hasEditor, err := HasRole(c, "editor") // Pass *gin.Context
	require.NoError(t, err)
	assert.False(t, hasEditor)

	// Test with missing roles
	w = httptest.NewRecorder()
	emptyCtx, _ := gin.CreateTestContext(w)
	hasRole, err := HasRole(emptyCtx, "admin") // Pass *gin.Context
	require.Error(t, err)
	assert.False(t, hasRole)
}

func TestIsAdmin(t *testing.T) {
	// Create gin context with admin role
	wAdmin := httptest.NewRecorder()
	adminCtx, _ := gin.CreateTestContext(wAdmin)
	adminCtx.Set("userRoles", []string{"admin", "user"}) // Use string key

	// Check admin
	isAdmin, err := IsAdmin(adminCtx) // Pass *gin.Context
	require.NoError(t, err)
	assert.True(t, isAdmin)

	// Create gin context without admin role
	wUser := httptest.NewRecorder()
	userCtx, _ := gin.CreateTestContext(wUser)
	userCtx.Set("userRoles", []string{"user"}) // Use string key

	// Check admin
	isAdmin, err = IsAdmin(userCtx) // Pass *gin.Context
	require.NoError(t, err)
	assert.False(t, isAdmin)

	// Test with missing roles
	wEmpty := httptest.NewRecorder()
	emptyCtx, _ := gin.CreateTestContext(wEmpty)
	isAdmin, err = IsAdmin(emptyCtx) // Pass *gin.Context
	require.Error(t, err)
	assert.False(t, isAdmin)
}
