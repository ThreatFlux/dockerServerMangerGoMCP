package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time" // Added import for time.Duration

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
)

// MockDB and MockDockerManager should be defined elsewhere (e.g., server_test.go or a test utility file)
// to avoid redeclaration errors when running tests for the whole package.

// Setup test server with mocked dependencies
func setupTestServer(t *testing.T) *Server { // Removed duplicated function definition
	// Setup test dependencies
	logger := logrus.New()
	mockDB := new(MockDB)                       // Use defined mock
	mockAuthService := new(auth.MockService)    // Assuming MockService exists
	mockDockerManager := new(MockDockerManager) // Use defined mock

	cfg := &config.Config{
		Version:  "1.0.0-test",
		ServerID: "test-server-123",
		Server: struct { // Initialize nested struct directly
			Host            string        `mapstructure:"host"`
			Port            int           `mapstructure:"port"`
			ReadTimeout     time.Duration `mapstructure:"read_timeout"`
			WriteTimeout    time.Duration `mapstructure:"write_timeout"`
			ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
			TrustedProxies  []string      `mapstructure:"trusted_proxies"`
			Mode            string        `mapstructure:"mode"`
			TLS             struct {
				Enabled      bool   `mapstructure:"enabled"`
				CertFile     string `mapstructure:"cert_file"`
				KeyFile      string `mapstructure:"key_file"`
				MinVersion   string `mapstructure:"min_version"`
				MaxVersion   string `mapstructure:"max_version"`
				CipherSuites string `mapstructure:"cipher_suites"`
			} `mapstructure:"tls"`
		}{
			Host: "localhost",
			Port: 8080,
			Mode: "test", // Set mode explicitly
		},
	}

	serverConfig := &ServerConfig{
		Config:        cfg,
		Logger:        logger,
		DB:            mockDB,
		AuthService:   mockAuthService,
		DockerManager: mockDockerManager, // Use mockDockerManager
	}

	server, err := NewServer(serverConfig)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Register routes
	err = server.RegisterRoutes() // Use public method
	assert.NoError(t, err)

	return server
}

func TestRegisterRoutes(t *testing.T) {
	server := setupTestServer(t)
	router := server.Router()

	// Ensure router exists
	assert.NotNil(t, router)
}

func TestHealthCheckRoute(t *testing.T) {
	server := setupTestServer(t)
	router := server.Router()

	// Create a test HTTP recorder
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/health", nil)
	router.ServeHTTP(w, req)

	// Check response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "status")
	assert.Contains(t, w.Body.String(), "ok")
	assert.Contains(t, w.Body.String(), "version")
	assert.Contains(t, w.Body.String(), "1.0.0-test")
	assert.Contains(t, w.Body.String(), "env")
	assert.Contains(t, w.Body.String(), "test")
	assert.Contains(t, w.Body.String(), "serverID")
	assert.Contains(t, w.Body.String(), "test-server-123")
}

func TestNotFoundRoute(t *testing.T) {
	server := setupTestServer(t)
	router := server.Router()

	// Create a test HTTP recorder
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/non-existent-path", nil)
	router.ServeHTTP(w, req)

	// Check response
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "error")
	assert.Contains(t, w.Body.String(), "Route not found")
	assert.Contains(t, w.Body.String(), "path")
	assert.Contains(t, w.Body.String(), "/api/v1/non-existent-path")
}

func TestAuthRoutes(t *testing.T) {
	server := setupTestServer(t)
	router := server.Router()

	// Test login route (no auth required)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/auth/login", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Contains(t, w.Body.String(), "not yet implemented")

	// Test register route (no auth required)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/v1/auth/register", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Contains(t, w.Body.String(), "not yet implemented")

	// Test refresh route (no auth required)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/v1/auth/refresh", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Contains(t, w.Body.String(), "not yet implemented")

	// Test protected route without auth (should fail)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/v1/auth/logout", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProtectedRoutes(t *testing.T) {
	server := setupTestServer(t)
	router := server.Router()

	// Test container routes without auth (should fail)
	routes := []string{
		"/api/v1/containers",
		"/api/v1/images",
		"/api/v1/volumes",
		"/api/v1/networks",
		"/api/v1/compose",
		"/api/v1/system/info",
	}

	for _, route := range routes {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", route, nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code, "Route %s should require authentication", route)
	}
}

func TestAdminRoutes(t *testing.T) {
	server := setupTestServer(t)
	router := server.Router()

	// Test admin routes without auth (should fail with unauthorized)
	routes := []string{
		"/api/v1/admin/users",
		"/api/v1/system/prune",
	}

	for _, route := range routes {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", route, nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code, "Route %s should require authentication", route)
	}

	// Test admin routes with auth but without admin role
	// This would require mocking the auth middleware, which is complex for this test
	// We'll skip this for now
}
