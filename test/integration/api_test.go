package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/api"
	// Removed import integration_helpers to break cycle
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database/repositories"
	docker_internal "github.com/threatflux/dockerServerMangerGoMCP/internal/docker" // Alias docker_test package

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/utils" // Removed unused import
)

// testServer encapsulates a test server and its dependencies
type testServer struct {
	Server *api.Server
	Config *config.Config
	DB     database.Database // Use Database interface
	Auth   auth.Service
	Docker docker_internal.Manager // Use Manager interface and alias
	Logger *logrus.Logger
}

// testClient is used to make requests to the test server
type testClient struct {
	BaseURL    string
	HTTPClient *http.Client
	AuthToken  string
}

// setupTestServer creates a new test server with all dependencies
func setupTestServer(t *testing.T) (*testServer, error) {
	// Create a test logger
	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.DebugLevel)

	// Load test configuration
	cfg, err := config.LoadConfig() // LoadConfig takes no arguments now
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Override config for testing
	cfg.Database.Type = "sqlite"                                                                  // Use Type field
	cfg.Database.SQLite.Path = ":memory:"                                                         // Use SQLite.Path field
	cfg.Auth.Secret = "test-integration-secret-key-needs-to-be-at-least-32-chars-long-enough-now" // Set dummy secret > 32 chars

	// Initialize database
	db, err := database.InitDatabase(cfg) // Use InitDatabase
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	// Run migrations
	// Migrate necessary models (User for auth)
	if err := db.Migrate(&models.User{}, &models.UserRole{}); err != nil { // Call Migrate method
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	// Create repositories
	_ = repositories.NewUserRepository(db.DB()) // Assign to blank identifier as it's not used here

	// Create auth service
	tokenStore := auth.NewInMemoryTokenStore()
	jwtConfig := auth.JWTConfig{
		AccessTokenSecret:  cfg.Auth.Secret,
		RefreshTokenSecret: cfg.Auth.Secret, // Assuming same secret
		AccessTokenExpiry:  int(cfg.Auth.AccessTokenTTL.Minutes()),
		RefreshTokenExpiry: int(cfg.Auth.RefreshTokenTTL.Hours()),
		Issuer:             cfg.Auth.TokenIssuer,
		Audience:           []string{cfg.Auth.TokenAudience},
	}
	// jwtHandler := auth.NewJWTService(jwtConfig, logger) // Not needed directly
	passwordConfig := auth.DefaultPasswordConfig()
	// passwordService := auth.NewPasswordService(passwordConfig) // Not needed directly

	authService := auth.NewService(
		db,             // Pass database.Database interface
		jwtConfig,      // Pass JWTConfig struct
		passwordConfig, // Pass PasswordConfig struct
		tokenStore,     // Pass TokenStore
		logger,         // Pass logger
	)
	// No error returned now
	// Note: The original code had an 'if err != nil' check here, but NewService doesn't return an error.
	// Keeping the structure but commenting out the check if it was intended.
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create auth service: %w", err)
	// }

	// Docker host is handled by NewManager options below

	// Create real Docker client manager using functional options
	opts := []docker_internal.ClientOption{
		docker_internal.WithLogger(logger),
	}
	if cfg.Docker.Host != "" {
		opts = append(opts, docker_internal.WithHost(cfg.Docker.Host))
	} else {
		// Attempt to use DOCKER_HOST env var if config is empty, mimicking docker client behavior
		dockerHostEnv := os.Getenv("DOCKER_HOST")
		if dockerHostEnv != "" {
			logger.Infof("Using DOCKER_HOST environment variable: %s", dockerHostEnv)
			opts = append(opts, docker_internal.WithHost(dockerHostEnv))
		}
		// If still no host, NewManager will use the default (e.g., unix socket)
	}

	if cfg.Docker.APIVersion != "" {
		opts = append(opts, docker_internal.WithAPIVersion(cfg.Docker.APIVersion))
	}
	// Add TLS options if configured
	if cfg.Docker.TLSVerify {
		opts = append(opts, docker_internal.WithTLSVerify(true))
		// Prefer explicit paths from config if available
		if cfg.Docker.TLSCertPath != "" && cfg.Docker.TLSKeyPath != "" && cfg.Docker.TLSCAPath != "" {
			opts = append(opts, docker_internal.WithTLSConfig(cfg.Docker.TLSCertPath, cfg.Docker.TLSKeyPath, cfg.Docker.TLSCAPath))
		} else {
			// Fallback to environment variables if config paths are missing, mimicking docker client behavior
			certPathEnv := os.Getenv("DOCKER_CERT_PATH")
			if certPathEnv != "" {
				logger.Infof("Using DOCKER_CERT_PATH environment variable: %s", certPathEnv)
				// Assuming standard names cert.pem, key.pem, ca.pem within the path
				opts = append(opts, docker_internal.WithTLSConfig(
					fmt.Sprintf("%s/cert.pem", certPathEnv),
					fmt.Sprintf("%s/key.pem", certPathEnv),
					fmt.Sprintf("%s/ca.pem", certPathEnv),
				))
			} else {
				// Rely on NewManager's validation to fail if TLSVerify is true but paths are missing
				logger.Warn("TLS verification enabled but certificate paths are missing in config and DOCKER_CERT_PATH env var is not set.")
			}
		}
	}

	dockerManager, err := docker_internal.NewManager(opts...)
	if err != nil {
		// Provide more context on failure
		// Removed ping logic as manager might not be initialized enough to ping on error
		return nil, fmt.Errorf("failed to create docker manager: %w", err)
	}

	// Create server
	server, err := api.NewServer(&api.ServerConfig{
		Config:        cfg,
		Logger:        logger,
		DB:            db,
		AuthService:   authService,
		DockerManager: dockerManager, // Use DockerManager field and real manager
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create server: %w", err)
	}

	// Register routes before returning the server
	err = server.RegisterRoutes() // Call public method
	if err != nil {
		return nil, fmt.Errorf("failed to register routes: %w", err)
	}

	// Create controllers and register routes
	// Controllers registered in NewServer now

	return &testServer{
		Server: server,
		Config: cfg,
		DB:     db,
		Auth:   authService,
		Docker: dockerManager, // Assign real manager
		Logger: logger,
	}, nil
}

// newTestClient creates a new test client
func newTestClient(baseURL string) *testClient {
	return &testClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// createTestUser creates a test user and returns the user model
func createTestUser(t *testing.T, ts *testServer) (*models.User, string, string) {
	// Create test user
	user := &models.User{
		Email:    "test@example.com",
		Name:     "Test User",
		Password: "password123",
		Active:   true,
		Roles: []models.UserRole{
			{
				Role: models.RoleUser,
			},
			{
				Role: models.RoleAdmin,
			},
		},
	}

	// Hash the password
	hashedPassword, err := ts.Auth.HashPassword(user.Password)
	require.NoError(t, err)
	user.Password = hashedPassword

	// Save user to database
	userRepo := repositories.NewUserRepository(ts.DB.DB()) // Get underlying DB
	err = userRepo.Create(context.Background(), user)
	require.NoError(t, err)

	// Generate tokens
	tokens, err := ts.Auth.Login(context.Background(), user.Email, "password123")
	require.NoError(t, err)

	return user, tokens.AccessToken, tokens.RefreshToken
}

// sendRequest sends an HTTP request to the test server
func (c *testClient) sendRequest(method, path string, body interface{}, headers map[string]string) (*http.Response, error) {
	// Create request body
	var reqBody []byte
	var err error
	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	// Create request
	req, err := http.NewRequest(method, c.BaseURL+path, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	req.Header.Set("Content-Type", "application/json")
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Send request
	return c.HTTPClient.Do(req)
}

// authenticate sets the auth token for the client
func (c *testClient) authenticate(email, password string) error {
	// Send login request
	resp, err := c.sendRequest("POST", "/api/v1/auth/login", models.LoginRequest{ // Add /v1 prefix
		Email:    email,
		Password: password,
	}, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse response
	var tokenResp models.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Set auth token
	c.AuthToken = tokenResp.AccessToken
	return nil
}

// TestAuthFlow tests the authentication flow
func TestAuthFlow(t *testing.T) {
	// Set up test server
	ts, err := setupTestServer(t)
	require.NoError(t, err)
	defer ts.DB.Close()
	if ts.Docker != nil { // Close docker manager if initialized
		defer ts.Docker.Close()
	}

	// Create a test server
	httpServer := httptest.NewServer(ts.Server.Router())
	defer httpServer.Close()

	// Create a test client
	client := newTestClient(httpServer.URL)

	// Test registration
	t.Run("Register", func(t *testing.T) {
		// Send registration request
		resp, err := client.sendRequest("POST", "/api/v1/auth/register", models.RegisterRequest{ // Add /v1 prefix
			Email:    "newuser@example.com",
			Password: "Password123!",
			Name:     "New User",
		}, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		// Parse response
		var tokenResp models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		require.NoError(t, err)

		// Check response
		assert.NotEmpty(t, tokenResp.AccessToken)
		assert.NotEmpty(t, tokenResp.RefreshToken)
		assert.Equal(t, "Bearer", tokenResp.TokenType)
		assert.NotZero(t, tokenResp.ExpiresIn)
		assert.NotZero(t, tokenResp.UserID)
		assert.Contains(t, tokenResp.Roles, models.RoleAdmin) // First user gets admin role
	})

	// Test login
	t.Run("Login", func(t *testing.T) {
		// Send login request
		resp, err := client.sendRequest("POST", "/api/v1/auth/login", models.LoginRequest{ // Add /v1 prefix
			Email:    "newuser@example.com",
			Password: "Password123!",
		}, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var tokenResp models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		require.NoError(t, err)

		// Set auth token for subsequent requests
		client.AuthToken = tokenResp.AccessToken

		// Check response
		assert.NotEmpty(t, tokenResp.AccessToken)
		assert.NotEmpty(t, tokenResp.RefreshToken)
		assert.Equal(t, "Bearer", tokenResp.TokenType)
		assert.NotZero(t, tokenResp.ExpiresIn)
		assert.NotZero(t, tokenResp.UserID)
	})

	// Test getting current user
	t.Run("GetCurrentUser", func(t *testing.T) {
		// Send request to get current user
		resp, err := client.sendRequest("GET", "/api/v1/user/me", nil, nil) // Corrected path
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var userResp models.UserResponse
		err = json.NewDecoder(resp.Body).Decode(&userResp)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, "newuser@example.com", userResp.Email)
		assert.Equal(t, "New User", userResp.Name)
		assert.NotZero(t, userResp.ID)
	})

	// Test changing password
	t.Run("ChangePassword", func(t *testing.T) {
		// Send request to change password
		resp, err := client.sendRequest("POST", "/api/v1/user/password", models.ChangePasswordRequest{ // Corrected path
			CurrentPassword: "Password123!",
			NewPassword:     "NewPassword123!",
		}, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		// Try to login with old password (should fail)
		resp, err = client.sendRequest("POST", "/api/v1/auth/login", models.LoginRequest{ // Add /v1 prefix
			Email:    "newuser@example.com",
			Password: "Password123!",
		}, nil)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Try to login with new password (should succeed)
		resp, err = client.sendRequest("POST", "/api/v1/auth/login", models.LoginRequest{ // Add /v1 prefix
			Email:    "newuser@example.com",
			Password: "NewPassword123!",
		}, nil)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Test updating user
	t.Run("UpdateUser", func(t *testing.T) {
		// Re-authenticate with new password
		err := client.authenticate("newuser@example.com", "NewPassword123!")
		require.NoError(t, err)

		// Send request to update user
		resp, err := client.sendRequest("PUT", "/api/v1/user/me", map[string]string{ // Corrected path
			"name": "Updated User",
		}, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var userResp models.UserResponse
		err = json.NewDecoder(resp.Body).Decode(&userResp)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, "Updated User", userResp.Name)
	})

	// Test logout
	t.Run("Logout", func(t *testing.T) {
		// Send logout request
		resp, err := client.sendRequest("POST", "/api/v1/auth/logout", nil, nil) // Corrected path
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		// Try to access protected resource (should fail)
		resp, err = client.sendRequest("GET", "/api/v1/user/me", nil, nil) // Corrected path
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// Test token refresh
	t.Run("RefreshToken", func(t *testing.T) {
		// Authenticate to get a new token
		err := client.authenticate("newuser@example.com", "NewPassword123!")
		require.NoError(t, err)

		// Get refresh token
		resp, err := client.sendRequest("POST", "/api/auth/login", models.LoginRequest{
			Email:    "newuser@example.com",
			Password: "NewPassword123!",
		}, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		var tokenResp models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		require.NoError(t, err)
		refreshToken := tokenResp.RefreshToken

		// Send refresh request
		resp, err = client.sendRequest("POST", "/api/v1/auth/refresh", models.RefreshTokenRequest{ // Corrected path
			RefreshToken: refreshToken,
		}, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var newTokenResp models.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&newTokenResp)
		require.NoError(t, err)

		// Check response
		assert.NotEmpty(t, newTokenResp.AccessToken)
		assert.NotEmpty(t, newTokenResp.RefreshToken)
		assert.NotEqual(t, tokenResp.AccessToken, newTokenResp.AccessToken) // Should be different
	})
}

// TestRateLimiting tests the rate limiting middleware
func TestRateLimiting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping rate limiting test in short mode")
	}

	// Set up test server
	ts, err := setupTestServer(t)
	require.NoError(t, err)
	defer ts.DB.Close()
	if ts.Docker != nil { // Close docker manager if initialized
		defer ts.Docker.Close()
	}

	// Enable rate limiting for testing (Assuming fields moved under Server)
	// Enable rate limiting for testing
	ts.Config.Security.RateLimiting.Enabled = true
	ts.Config.Security.RateLimiting.MaxPerIP = 5
	ts.Config.Security.RateLimiting.WindowSecs = 1
	// Burst is not directly configurable in the new structure

	// Recreate server with updated config for rate limiting
	// Note: This assumes NewServer correctly applies rate limiting based on config
	server, err := api.NewServer(&api.ServerConfig{
		Config:        ts.Config, // Use updated config
		Logger:        ts.Logger,
		DB:            ts.DB,
		AuthService:   ts.Auth,
		DockerManager: ts.Docker,
	})
	require.NoError(t, err)
	err = server.RegisterRoutes()
	require.NoError(t, err)
	ts.Server = server // Update the server in testServer struct

	// Create a test server
	httpServer := httptest.NewServer(ts.Server.Router())
	defer httpServer.Close()

	// Create a test client
	client := newTestClient(httpServer.URL)

	// Send multiple requests in quick succession
	for i := 0; i < 5; i++ {
		resp, err := client.sendRequest("GET", "/api/v1/health", nil, nil) // Corrected path
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// Next request should be rate limited
	resp, err := client.sendRequest("GET", "/api/v1/health", nil, nil) // Corrected path
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)

	// Wait for rate limit to reset
	time.Sleep(1 * time.Second)

	// Should be able to make requests again
	resp, err = client.sendRequest("GET", "/api/v1/health", nil, nil) // Corrected path
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestCORS tests the CORS middleware
func TestCORS(t *testing.T) {
	// Set up test server
	ts, err := setupTestServer(t)
	require.NoError(t, err)
	defer ts.DB.Close()
	if ts.Docker != nil { // Close docker manager if initialized
		defer ts.Docker.Close()
	}

	// Enable CORS for testing - NOTE: CORS config structure seems removed/changed in config.go
	// Assuming CORS is handled differently now or enabled by default in test mode.
	// If CORS tests fail, the middleware setup in api/server.go or middleware/cors.go needs review.
	// ts.Config.Server.CORS.Enabled = true // Removed - Field does not exist
	// ts.Config.Server.CORS.AllowedOrigins = []string{"http://example.com"} // Removed
	// ts.Config.Server.CORS.AllowedMethods = []string{"GET", "POST"} // Removed
	// ts.Config.Server.CORS.AllowedHeaders = []string{"Content-Type", "Authorization"} // Removed
	// ts.Config.Server.CORS.AllowCredentials = true // Removed
	// ts.Config.Server.CORS.MaxAge = 3600 // Removed

	// Recreate server with updated config for CORS
	server, err := api.NewServer(&api.ServerConfig{
		Config:        ts.Config, // Use updated config
		Logger:        ts.Logger,
		DB:            ts.DB,
		AuthService:   ts.Auth,
		DockerManager: ts.Docker,
	})
	require.NoError(t, err)
	err = server.RegisterRoutes()
	require.NoError(t, err)
	ts.Server = server // Update the server in testServer struct

	// Create a test server
	httpServer := httptest.NewServer(ts.Server.Router())
	defer httpServer.Close()

	// Create a test client
	client := newTestClient(httpServer.URL)

	// Test preflight request
	t.Run("Preflight", func(t *testing.T) {
		req, _ := http.NewRequest("OPTIONS", httpServer.URL+"/api/v1/health", nil) // Corrected path
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "Authorization")

		resp, err := client.HTTPClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "http://example.com", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
		assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "GET")
		assert.Contains(t, resp.Header.Get("Access-Control-Allow-Headers"), "Authorization")
	})

	// Test actual request
	t.Run("ActualRequest", func(t *testing.T) {
		resp, err := client.sendRequest("GET", "/api/v1/health", nil, map[string]string{ // Corrected path
			"Origin": "http://example.com",
		})
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "http://example.com", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	})

	// Test request from disallowed origin
	t.Run("DisallowedOrigin", func(t *testing.T) {
		resp, err := client.sendRequest("GET", "/api/v1/health", nil, map[string]string{ // Corrected path
			"Origin": "http://disallowed.com",
		})
		require.NoError(t, err)
		defer resp.Body.Close()

		// Depending on the CORS library, this might return OK but without CORS headers,
		// or it might be blocked earlier. Check for absence of Allow-Origin.
		assert.Equal(t, http.StatusOK, resp.StatusCode) // Request itself might be OK
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
	})
}

// TestAPIHealth tests the health check endpoint
func TestAPIHealth(t *testing.T) {
	// Set up test server
	ts, err := setupTestServer(t)
	require.NoError(t, err)
	defer ts.DB.Close()
	if ts.Docker != nil { // Close docker manager if initialized
		defer ts.Docker.Close()
	}

	// Create a test server
	httpServer := httptest.NewServer(ts.Server.Router())
	defer httpServer.Close()

	// Create a test client
	client := newTestClient(httpServer.URL)

	// Send request to health check endpoint
	resp, err := client.sendRequest("GET", "/api/v1/health", nil, nil) // Corrected path
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check status code
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var healthResp map[string]string
	err = json.NewDecoder(resp.Body).Decode(&healthResp)
	require.NoError(t, err)

	// Check response
	assert.Equal(t, "ok", healthResp["status"])
	assert.Equal(t, "pong", healthResp["database"])
	// Docker ping check might depend on whether a real client is used
	// If using a mock, this might be different or absent.
	// If using a real client, it should be "ok" if Docker is running.
	// Let's assume "ok" for now, adjust if using mocks differently.
	assert.Equal(t, "ok", healthResp["docker"])
}

// TestErrorHandling tests the error handling middleware
func TestErrorHandling(t *testing.T) {
	// Set up test server
	ts, err := setupTestServer(t)
	require.NoError(t, err)
	defer ts.DB.Close()
	if ts.Docker != nil { // Close docker manager if initialized
		defer ts.Docker.Close()
	}

	// Create a test server
	httpServer := httptest.NewServer(ts.Server.Router())
	defer httpServer.Close()

	// Create a test client
	client := newTestClient(httpServer.URL)

	// Test not found error
	t.Run("NotFound", func(t *testing.T) {
		resp, err := client.sendRequest("GET", "/api/v1/nonexistent", nil, nil) // Added /v1 prefix
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		var errResp models.ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "Not Found", errResp.Error)
		assert.Equal(t, "Resource not found", errResp.Error.Message) // Access nested Message field
	})

	// Test method not allowed error
	t.Run("MethodNotAllowed", func(t *testing.T) {
		resp, err := client.sendRequest("PUT", "/api/v1/health", nil, nil) // Corrected path
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)

		var errResp models.ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "Method Not Allowed", errResp.Error)
		assert.Equal(t, "Method is not allowed for the requested route", errResp.Error.Message) // Access nested Message field
	})

	// Add more tests for other error types if needed (e.g., validation errors)
}
