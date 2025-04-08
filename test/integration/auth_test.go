package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/api"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database/repositories"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"

	"github.com/sirupsen/logrus"
)

// setupAuthTestServer creates a test server specifically for auth testing
func setupAuthTestServer(t *testing.T) (*api.Server, *httptest.Server, auth.Service, repositories.UserRepository, func()) { // Return interface
	// Create a test logger
	logger := logrus.New()
	logger.SetOutput(io.Discard) // Suppress logs in tests
	logger.SetLevel(logrus.ErrorLevel)

	// Load test configuration
	cfg, err := config.LoadConfig() // LoadConfig takes no arguments now
	require.NoError(t, err)

	// Override config for testing
	cfg.Database.Type = "sqlite"          // Use Type field
	cfg.Database.SQLite.Path = ":memory:" // Use SQLite.Path field

	// Configure auth settings
	cfg.Auth.AccessTokenTTL = 15 * time.Minute                                                    // Use AccessTokenTTL
	cfg.Auth.RefreshTokenTTL = 24 * time.Hour                                                     // Use RefreshTokenTTL
	cfg.Auth.Secret = "test-integration-secret-key-needs-to-be-at-least-32-chars-long-enough-now" // Set dummy secret > 32 chars

	// Initialize database
	db, err := database.InitDatabase(cfg) // Use InitDatabase
	require.NoError(t, err)

	// Run migrations (Need to define which models to migrate for auth tests)
	err = db.Migrate(&models.User{}, &models.UserRole{}) // Call Migrate method, removed TokenBlacklist
	require.NoError(t, err)

	// Create repositories
	userRepo := repositories.NewUserRepository(db.DB()) // Pass underlying *gorm.DB

	// Create auth service
	tokenStore := auth.NewInMemoryTokenStore()
	// Assuming NewJWTHandler signature changed or needs config struct
	// Placeholder - will need to check auth.NewJWTHandler definition later
	// jwtHandler := auth.NewJWTHandler(...)
	jwtConfig := auth.JWTConfig{
		AccessTokenSecret:  cfg.Auth.Secret,
		RefreshTokenSecret: cfg.Auth.Secret, // Assuming same secret for refresh for now
		AccessTokenExpiry:  int(cfg.Auth.AccessTokenTTL.Minutes()),
		RefreshTokenExpiry: int(cfg.Auth.RefreshTokenTTL.Hours()),
		Issuer:             cfg.Auth.TokenIssuer,
		Audience:           []string{cfg.Auth.TokenAudience},
	}
	// jwtHandler := auth.NewJWTService(jwtConfig, logger) // Not needed directly for NewService
	passwordConfig := auth.DefaultPasswordConfig() // Get default config
	// passwordService := auth.NewPasswordService(passwordConfig) // Not needed directly for NewService

	authService := auth.NewService(
		db,             // Pass database.Database interface
		jwtConfig,      // Pass JWTConfig struct
		passwordConfig, // Pass PasswordConfig struct
		tokenStore,     // Pass TokenStore
		logger,         // Pass logger
	)
	// No error returned by NewService now

	// Create mock Docker client
	dockerManager := &MockDockerManager{} // Instantiate the local mock manager
	// require.NoError(t, err) // No error from direct instantiation

	// Create server
	server, err := api.NewServer(&api.ServerConfig{
		Config:        cfg,
		Logger:        logger,
		DB:            db,
		AuthService:   authService,
		DockerManager: dockerManager, // Use the local mock manager instance
	})
	require.NoError(t, err)

	// Register routes before creating the test server
	err = server.RegisterRoutes() // Call public method
	require.NoError(t, err)       // Use require for fatal errors

	// Create controllers and register routes
	// err = server.RegisterControllers() // Removed, controllers registered in NewServer
	// require.NoError(t, err) // err is not defined here anymore

	// Create HTTP test server
	httpServer := httptest.NewServer(server.Router())

	// Create cleanup function
	cleanup := func() {
		httpServer.Close()
		db.Close()
	}

	return server, httpServer, authService, userRepo, cleanup // userRepo is already the interface type from NewUserRepository
}

// sendAuthRequest sends an HTTP request with optional authentication
func sendAuthRequest(method, url, token string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	return client.Do(req)
}

// TestUserRegistration tests the user registration process
func TestUserRegistration(t *testing.T) {
	_, httpServer, _, userRepo, cleanup := setupAuthTestServer(t)
	defer cleanup()

	// Test successful registration
	t.Run("SuccessfulRegistration", func(t *testing.T) {
		// Prepare registration request
		regReq := models.RegisterRequest{
			Email:    "newuser@example.com",
			Password: "StrongPassword123!",
			Name:     "New User",
		}

		// Send registration request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/auth/register", "", regReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		// Parse response
		var respBody models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)

		// Check response fields
		assert.NotEmpty(t, respBody.AccessToken)
		assert.NotEmpty(t, respBody.RefreshToken)
		assert.Equal(t, "Bearer", respBody.TokenType)
		assert.NotZero(t, respBody.ExpiresIn)
		assert.NotZero(t, respBody.UserID)
		assert.Contains(t, respBody.Roles, models.RoleAdmin) // First user gets admin role

		// Verify user was created in database
		user, err := userRepo.GetByEmail(context.Background(), "newuser@example.com") // Changed FindByEmail to GetByEmail
		require.NoError(t, err)
		assert.Equal(t, "New User", user.Name)
		assert.True(t, user.Active)
		assert.NotEmpty(t, user.Password)                       // Should be hashed
		assert.NotEqual(t, "StrongPassword123!", user.Password) // Should not be plaintext
	})

	// Test duplicate email registration
	t.Run("DuplicateEmailRegistration", func(t *testing.T) {
		// Try to register with the same email
		regReq := models.RegisterRequest{
			Email:    "newuser@example.com", // Already used in previous test
			Password: "AnotherPassword123!",
			Name:     "Duplicate User",
		}

		// Send registration request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/auth/register", "", regReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code (should be conflict)
		assert.Equal(t, http.StatusConflict, resp.StatusCode)

		// Parse error response
		var errorResp struct {
			Error string `json:"error"`
		}
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)

		// Check error message
		assert.Contains(t, errorResp.Error, "already exists")
	})

	// Test invalid registration data
	t.Run("InvalidRegistrationData", func(t *testing.T) {
		testCases := []struct {
			name     string
			request  models.RegisterRequest
			errorKey string
		}{
			{
				name: "EmptyEmail",
				request: models.RegisterRequest{
					Email:    "",
					Password: "StrongPassword123!",
					Name:     "Invalid User",
				},
				errorKey: "email",
			},
			{
				name: "InvalidEmail",
				request: models.RegisterRequest{
					Email:    "not-an-email",
					Password: "StrongPassword123!",
					Name:     "Invalid User",
				},
				errorKey: "email",
			},
			{
				name: "WeakPassword",
				request: models.RegisterRequest{
					Email:    "weak@example.com",
					Password: "weak", // Too short
					Name:     "Invalid User",
				},
				errorKey: "password",
			},
			{
				name: "EmptyName",
				request: models.RegisterRequest{
					Email:    "noname@example.com",
					Password: "StrongPassword123!",
					Name:     "",
				},
				errorKey: "name",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Send registration request
				resp, err := sendAuthRequest("POST", httpServer.URL+"/api/v1/auth/register", "", tc.request) // Add /v1 prefix
				require.NoError(t, err)
				defer resp.Body.Close()

				// Check status code (should be bad request)
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

				// Parse error response
				var errorResp struct {
					Error            string                   `json:"error"`
					ValidationErrors []map[string]interface{} `json:"validationErrors"`
				}
				err = json.NewDecoder(resp.Body).Decode(&errorResp)
				require.NoError(t, err)

				// Check validation errors
				assert.NotEmpty(t, errorResp.ValidationErrors)
				foundError := false
				for _, ve := range errorResp.ValidationErrors {
					field, ok := ve["field"].(string)
					if ok && field == tc.errorKey {
						foundError = true
						break
					}
				}
				assert.True(t, foundError, fmt.Sprintf("Validation error for field '%s' not found", tc.errorKey))
			})
		}
	})

	// Test role assignment
	t.Run("RoleAssignment", func(t *testing.T) {
		// Register a second user (should not get admin role)
		regReq := models.RegisterRequest{
			Email:    "regularuser@example.com",
			Password: "RegularPassword123!",
			Name:     "Regular User",
		}

		// Send registration request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/auth/register", "", regReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		// Parse response
		var respBody models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)

		// Check roles (should only have user role, not admin)
		assert.Contains(t, respBody.Roles, models.RoleUser)
		assert.NotContains(t, respBody.Roles, models.RoleAdmin)

		// Verify user was created in database with correct roles
		user, err := userRepo.GetByEmail(context.Background(), "regularuser@example.com") // Changed FindByEmail to GetByEmail
		require.NoError(t, err)

		// Check roles
		var roleNames []string
		for _, role := range user.Roles {
			roleNames = append(roleNames, string(role.Role)) // Convert models.Role to string
		}
		assert.Contains(t, roleNames, models.RoleUser)
		assert.NotContains(t, roleNames, models.RoleAdmin)
	})
}

// TestAuthentication tests the authentication flow
func TestAuthentication(t *testing.T) {
	_, httpServer, authService, userRepo, cleanup := setupAuthTestServer(t)
	defer cleanup()

	// Create a test user
	createTestUser := func() {
		hashedPassword, err := authService.HashPassword("TestPassword123!")
		require.NoError(t, err)

		user := &models.User{
			Email:    "testauth@example.com",
			Name:     "Test Auth User",
			Password: hashedPassword,
			Active:   true,
			Roles: []models.UserRole{
				{Role: models.RoleUser},
				{Role: models.RoleAdmin},
			},
		}

		err = userRepo.Create(context.Background(), user)
		require.NoError(t, err)
	}

	createTestUser()

	// Test successful login
	t.Run("SuccessfulLogin", func(t *testing.T) {
		// Prepare login request
		loginReq := models.LoginRequest{
			Email:    "testauth@example.com",
			Password: "TestPassword123!",
		}

		// Send login request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/v1/auth/login", "", loginReq) // Add /v1 prefix
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var respBody models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)

		// Check response fields
		assert.NotEmpty(t, respBody.AccessToken)
		assert.NotEmpty(t, respBody.RefreshToken)
		assert.Equal(t, "Bearer", respBody.TokenType)
		assert.NotZero(t, respBody.ExpiresIn)
		assert.NotZero(t, respBody.UserID)
		assert.Contains(t, respBody.Roles, models.RoleUser)
		assert.Contains(t, respBody.Roles, models.RoleAdmin)
	})

	// Test failed login (wrong password)
	t.Run("WrongPasswordLogin", func(t *testing.T) {
		// Prepare login request with wrong password
		loginReq := models.LoginRequest{
			Email:    "testauth@example.com",
			Password: "WrongPassword123!",
		}

		// Send login request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/auth/login", "", loginReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Parse error response
		var errorResp struct {
			Error string `json:"error"`
		}
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)

		// Check error message
		assert.Contains(t, errorResp.Error, "Invalid email or password")
	})

	// Test failed login (non-existent user)
	t.Run("NonExistentUserLogin", func(t *testing.T) {
		// Prepare login request with non-existent user
		loginReq := models.LoginRequest{
			Email:    "nonexistent@example.com",
			Password: "TestPassword123!",
		}

		// Send login request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/auth/login", "", loginReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Parse error response
		var errorResp struct {
			Error string `json:"error"`
		}
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)

		// Check error message
		assert.Contains(t, errorResp.Error, "Invalid email or password")
	})

	// Test invalid login data
	t.Run("InvalidLoginData", func(t *testing.T) {
		// Prepare login request with invalid email
		loginReq := models.LoginRequest{
			Email:    "not-an-email",
			Password: "TestPassword123!",
		}

		// Send login request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/auth/login", "", loginReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// Parse error response
		var errorResp struct {
			Error string `json:"error"`
		}
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)

		// Check error message
		assert.Contains(t, errorResp.Error, "Invalid login request")
	})
}

// TestTokenRefresh tests token refresh functionality
func TestTokenRefresh(t *testing.T) {
	_, httpServer, authService, userRepo, cleanup := setupAuthTestServer(t)
	defer cleanup()

	// Create a test user
	createTestUser := func() {
		hashedPassword, err := authService.HashPassword("TestPassword123!")
		require.NoError(t, err)

		user := &models.User{
			Email:    "refresh@example.com",
			Name:     "Refresh Test User",
			Password: hashedPassword,
			Active:   true,
			Roles: []models.UserRole{
				{Role: models.RoleUser},
			},
		}

		err = userRepo.Create(context.Background(), user)
		require.NoError(t, err)
	}

	createTestUser()

	// Login to get tokens
	var accessToken, refreshToken string
	t.Run("Login", func(t *testing.T) {
		// Prepare login request
		loginReq := models.LoginRequest{
			Email:    "refresh@example.com",
			Password: "TestPassword123!",
		}

		// Send login request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/v1/auth/login", "", loginReq) // Add /v1 prefix
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var respBody models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)

		// Save tokens
		accessToken = respBody.AccessToken
		refreshToken = respBody.RefreshToken
	})

	// Test token refresh
	t.Run("RefreshToken", func(t *testing.T) {
		// Prepare refresh request
		refreshReq := models.RefreshTokenRequest{
			RefreshToken: refreshToken,
		}

		// Send refresh request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/auth/refresh", "", refreshReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var respBody models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)

		// Check response fields
		assert.NotEmpty(t, respBody.AccessToken)
		assert.NotEmpty(t, respBody.RefreshToken)
		assert.Equal(t, "Bearer", respBody.TokenType)
		assert.NotZero(t, respBody.ExpiresIn)
		assert.NotZero(t, respBody.UserID)

		// Tokens should be different
		assert.NotEqual(t, accessToken, respBody.AccessToken)
		assert.NotEqual(t, refreshToken, respBody.RefreshToken)
	})

	// Test invalid refresh token
	t.Run("InvalidRefreshToken", func(t *testing.T) {
		// Prepare refresh request with invalid token
		refreshReq := models.RefreshTokenRequest{
			RefreshToken: "invalid-refresh-token",
		}

		// Send refresh request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/auth/refresh", "", refreshReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code (should be unauthorized)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Parse error response
		var errorResp struct {
			Error string `json:"error"`
		}
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)

		// Check error message
		assert.Contains(t, errorResp.Error, "Invalid or expired refresh token")
	})
}

// TestLogout tests the logout functionality
func TestLogout(t *testing.T) {
	_, httpServer, authService, userRepo, cleanup := setupAuthTestServer(t)
	defer cleanup()

	// Create a test user
	createTestUser := func() {
		hashedPassword, err := authService.HashPassword("TestPassword123!")
		require.NoError(t, err)

		user := &models.User{
			Email:    "logout@example.com",
			Name:     "Logout Test User",
			Password: hashedPassword,
			Active:   true,
			Roles: []models.UserRole{
				{Role: models.RoleUser},
			},
		}

		err = userRepo.Create(context.Background(), user)
		require.NoError(t, err)
	}

	createTestUser()

	// Login to get token
	var accessToken string
	t.Run("Login", func(t *testing.T) {
		// Prepare login request
		loginReq := models.LoginRequest{
			Email:    "logout@example.com",
			Password: "TestPassword123!",
		}

		// Send login request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/v1/auth/login", "", loginReq) // Add /v1 prefix
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var respBody models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)

		// Save token
		accessToken = respBody.AccessToken
	})

	// Test accessing protected resource with token
	t.Run("AccessProtectedResource", func(t *testing.T) {
		// Send request to get current user
		resp, err := sendAuthRequest("GET", httpServer.URL+"/api/auth/me", accessToken, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code (should be ok)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var respBody models.UserResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)

		// Check response fields
		assert.Equal(t, "logout@example.com", respBody.Email)
		assert.Equal(t, "Logout Test User", respBody.Name)
	})

	// Test logout
	t.Run("Logout", func(t *testing.T) {
		// Send logout request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/auth/logout", accessToken, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	// Test accessing protected resource after logout
	t.Run("AccessAfterLogout", func(t *testing.T) {
		// Send request to get current user
		resp, err := sendAuthRequest("GET", httpServer.URL+"/api/auth/me", accessToken, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code (should be unauthorized)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Parse error response
		var errorResp struct {
			Error string `json:"error"`
		}
		err = json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)

		// Check error message
		assert.Contains(t, errorResp.Error, "Invalid or expired token")
	})
}

// TestUserProfile tests the user profile functionality
func TestUserProfile(t *testing.T) {
	_, httpServer, authService, userRepo, cleanup := setupAuthTestServer(t)
	defer cleanup()

	// Create a test user
	createTestUser := func() {
		hashedPassword, err := authService.HashPassword("TestPassword123!")
		require.NoError(t, err)

		user := &models.User{
			Email:    "profile@example.com",
			Name:     "Profile Test User",
			Password: hashedPassword,
			Active:   true,
			Roles: []models.UserRole{
				{Role: models.RoleUser},
			},
		}

		err = userRepo.Create(context.Background(), user)
		require.NoError(t, err)
	}

	createTestUser()

	// Login to get token
	var accessToken string
	t.Run("Login", func(t *testing.T) {
		// Prepare login request
		loginReq := models.LoginRequest{
			Email:    "profile@example.com",
			Password: "TestPassword123!",
		}

		// Send login request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/v1/auth/login", "", loginReq) // Add /v1 prefix
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var respBody models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)

		// Save token
		accessToken = respBody.AccessToken
	})

	// Test getting current user
	t.Run("GetCurrentUser", func(t *testing.T) {
		// Send request to get current user
		resp, err := sendAuthRequest("GET", httpServer.URL+"/api/auth/me", accessToken, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var respBody models.UserResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)

		// Check response fields
		assert.Equal(t, "profile@example.com", respBody.Email)
		assert.Equal(t, "Profile Test User", respBody.Name)
		assert.Contains(t, respBody.Roles, models.RoleUser)
	})

	// Test updating user profile
	t.Run("UpdateUser", func(t *testing.T) {
		// Prepare update request
		updateReq := struct {
			Name string `json:"name"`
		}{
			Name: "Updated Profile User",
		}

		// Send update request
		resp, err := sendAuthRequest("PUT", httpServer.URL+"/api/auth/me", accessToken, updateReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var respBody models.UserResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)

		// Check response fields
		assert.Equal(t, "Updated Profile User", respBody.Name)
		assert.Equal(t, "profile@example.com", respBody.Email)

		// Verify update in database
		user, err := userRepo.GetByEmail(context.Background(), "profile@example.com") // Changed FindByEmail to GetByEmail
		require.NoError(t, err)
		assert.Equal(t, "Updated Profile User", user.Name)
	})

	// Test changing password
	t.Run("ChangePassword", func(t *testing.T) {
		// Prepare change password request
		changePasswordReq := models.ChangePasswordRequest{
			CurrentPassword: "TestPassword123!",
			NewPassword:     "NewPassword123!",
		}

		// Send change password request
		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/auth/password", accessToken, changePasswordReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		// Try to login with old password (should fail)
		loginReq := models.LoginRequest{
			Email:    "profile@example.com",
			Password: "TestPassword123!",
		}

		resp, err = sendAuthRequest("POST", httpServer.URL+"/api/auth/login", "", loginReq)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Try to login with new password (should succeed)
		loginReq.Password = "NewPassword123!"
		resp, err = sendAuthRequest("POST", httpServer.URL+"/api/auth/login", "", loginReq)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// TestAuthorizationRoles tests role-based authorization
func TestAuthorizationRoles(t *testing.T) {
	_, httpServer, authService, userRepo, cleanup := setupAuthTestServer(t)
	defer cleanup()

	// Create admin user
	adminUser := &models.User{
		Email:    "admin@example.com",
		Name:     "Admin User",
		Password: "",
		Active:   true,
		Roles: []models.UserRole{
			{Role: models.RoleUser},
			{Role: models.RoleAdmin},
		},
	}
	adminPassword := "AdminPassword123!"
	hashedPassword, err := authService.HashPassword(adminPassword)
	require.NoError(t, err)
	adminUser.Password = hashedPassword
	err = userRepo.Create(context.Background(), adminUser)
	require.NoError(t, err)

	// Create regular user
	regularUser := &models.User{
		Email:    "user@example.com",
		Name:     "Regular User",
		Password: "",
		Active:   true,
		Roles: []models.UserRole{
			{Role: models.RoleUser},
		},
	}
	userPassword := "UserPassword123!"
	hashedPassword, err = authService.HashPassword(userPassword)
	require.NoError(t, err)
	regularUser.Password = hashedPassword
	err = userRepo.Create(context.Background(), regularUser)
	require.NoError(t, err)

	// Get admin token
	var adminToken string
	t.Run("AdminLogin", func(t *testing.T) {
		// Login as admin
		loginReq := models.LoginRequest{
			Email:    "admin@example.com",
			Password: adminPassword,
		}

		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/auth/login", "", loginReq)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var respBody models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)

		adminToken = respBody.AccessToken
	})

	// Get regular user token
	var userToken string
	t.Run("UserLogin", func(t *testing.T) {
		// Login as regular user
		loginReq := models.LoginRequest{
			Email:    "user@example.com",
			Password: userPassword,
		}

		resp, err := sendAuthRequest("POST", httpServer.URL+"/api/auth/login", "", loginReq)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var respBody models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		require.NoError(t, err)

		userToken = respBody.AccessToken
	})

	// Test admin-only access
	t.Run("AdminOnlyAccess", func(t *testing.T) {
		// Try to access admin endpoint with admin token (should succeed)
		resp, err := sendAuthRequest("GET", httpServer.URL+"/api/admin/users", adminToken, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// This endpoint might return 404 if not implemented yet, but should not return 403
		assert.NotEqual(t, http.StatusForbidden, resp.StatusCode)

		// Try to access admin endpoint with user token (should fail)
		resp, err = sendAuthRequest("GET", httpServer.URL+"/api/v1/admin/users", userToken, nil) // Add /v1 prefix
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	// Test user access to a regular endpoint
	t.Run("UserAccess", func(t *testing.T) {
		// Both admin and regular user should be able to access regular endpoints
		for _, token := range []string{adminToken, userToken} {
			resp, err := sendAuthRequest("GET", httpServer.URL+"/api/auth/me", token, nil)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		}
	})
}
