package compose

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"      // Added for os.Getenv
	"runtime" // Added for runtime.GOOS

	"net/http"
	"net/http/httptest"
	"testing"

	"context" // Added import

	"github.com/sirupsen/logrus" // Add back logrus import
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/api"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database/repositories"
	docker_internal "github.com/threatflux/dockerServerMangerGoMCP/internal/docker" // Alias docker_test package
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/docker_test/compose" // Removed unused import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Added import
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/utils" // Removed unused import
)

// setupTestServer creates a test server for compose testing
func setupTestServer(t *testing.T) (*testServer, error) {
	// Create a test logger
	logger := logrus.New()
	logger.SetOutput(io.Discard) // Suppress logs in tests
	logger.SetLevel(logrus.ErrorLevel)

	// Load test configuration (LoadConfig handles defaults via viper)
	cfg, err := config.LoadConfig()
	if err != nil && !os.IsNotExist(err) { // Allow file not found, error on other load issues
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	// If cfg is nil because file didn't exist and LoadConfig returned nil, create empty struct
	// Viper should have set defaults even if file doesn't exist.
	if cfg == nil {
		// This case might indicate an issue with LoadConfig not returning defaults
		// when file is missing. For now, proceed assuming viper handles it.
		// If tests still fail on docker host, we might need to manually init cfg here.
		logger.Warn("config.LoadConfig returned nil even after handling potential file not found error. Proceeding with potentially empty config.")
		cfg = &config.Config{} // Initialize empty config to avoid nil pointer dereference
	}

	// Override specific config values needed for testing
	cfg.Database.Type = "sqlite"
	cfg.Database.SQLite.Path = ":memory:"
	cfg.Auth.Secret = "test-integration-secret-key-needs-to-be-at-least-32-chars-long-enough-now" // Set dummy secret > 32 chars

	// Ensure Docker host is set for tests, defaulting if necessary
	dockerHost := cfg.Docker.Host // Check the loaded value first
	if dockerHost == "" {
		// Attempt to get from environment first (common Docker practice)
		envHost := os.Getenv("DOCKER_HOST")
		if envHost != "" {
			dockerHost = envHost
			logger.Infof("Using DOCKER_HOST from environment: %s", envHost)
		} else {
			// Default based on OS if not set in config or env
			if runtime.GOOS == "windows" {
				dockerHost = "npipe:////./pipe/docker_engine"
			} else {
				dockerHost = "unix:///var/run/docker.sock"
			}
			logger.Infof("Docker host not specified in config or DOCKER_HOST env, defaulting to: %s", dockerHost)
		}
		// Update the config struct being used
		cfg.Docker.Host = dockerHost
	}

	// Initialize database
	db, err := database.InitDatabase(cfg) // Use InitDatabase
	if err != nil {
		return nil, err
	}

	// Run migrations
	// Migrate necessary models (User for auth)
	if err := db.Migrate(&models.User{}, &models.UserRole{}); err != nil { // Call Migrate method
		return nil, err
	}

	// Create repositories
	userRepo := repositories.NewUserRepository(db.DB()) // Pass underlying *gorm.DB

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
	// No error returned by NewService now

	// Create real Docker Manager using functional options
	dockerManager, err := docker_internal.NewManager(
		docker_internal.WithHost(dockerHost), // Use the determined dockerHost
		docker_internal.WithLogger(logger),
		// Add other necessary options from cfg if needed, e.g., TLS
		// docker_internal.WithTLSVerify(cfg.Docker.TLSVerify),
		// docker_internal.WithTLSConfig(cfg.Docker.TLSCertPath, cfg.Docker.TLSKeyPath, cfg.Docker.TLSCAPath),
	)
	if err != nil {
		// Provide more context on failure
		return nil, fmt.Errorf("failed to create real Docker manager with host '%s': %w", dockerHost, err)
	}

	// Create server
	server, err := api.NewServer(&api.ServerConfig{
		Config:        cfg,
		Logger:        logger,
		DB:            db,
		AuthService:   authService,
		DockerManager: dockerManager, // Use the real Docker manager
	})
	if err != nil {
		return nil, err
	}

	// Register routes before creating the test server
	err = server.RegisterRoutes() // Call the public RegisterRoutes method
	if err != nil {
		return nil, fmt.Errorf("failed to register routes: %w", err)
	}

	httpServer := httptest.NewServer(server.Router())

	// Remove duplicate httpServer declaration

	ts := &testServer{
		Server:     server,
		Config:     cfg,
		DB:         db,            // Assign interface
		Docker:     dockerManager, // Assign real manager
		Auth:       authService,
		Logger:     logger,
		UserRepo:   userRepo, // Assign interface
		HttpServer: httpServer,
	}

	return ts, nil // Return the testServer instance
}

// testServer encapsulates a test server and its dependencies
type testServer struct {
	Server     *api.Server
	Config     *config.Config
	DB         database.Database       // Use Database interface
	Docker     docker_internal.Manager // Use Manager interface and alias
	Auth       auth.Service
	Logger     *logrus.Logger
	UserRepo   repositories.UserRepository // Use interface type
	HttpServer *httptest.Server
}

// cleanup performs cleanup after tests
func (ts *testServer) cleanup() {
	ts.HttpServer.Close()
	ts.DB.Close()
	// Add Docker cleanup if necessary for this test file (likely not needed for parser)
	// ts.Docker.Close() // Close the manager if needed
}

// createTestUser creates a test user with admin privileges
func createTestUser(t *testing.T, ts *testServer) string {
	// Hash password
	hashedPassword, err := ts.Auth.HashPassword("TestPassword123!")
	require.NoError(t, err)

	// Create user
	user := &models.User{ // Use models.User
		Email:    "composetest@example.com",
		Name:     "Compose Test User",
		Password: hashedPassword,
		Active:   true,
		Roles: []models.UserRole{ // Use models.UserRole
			{Role: "user"},
			{Role: "admin"},
		},
	}

	// Save user
	err = ts.UserRepo.Create(context.Background(), user) // Call method on interface
	require.NoError(t, err)

	// Log in to get token
	tokens, err := ts.Auth.Login(context.Background(), "composetest@example.com", "TestPassword123!") // Call method on interface
	require.NoError(t, err)

	return tokens.AccessToken
}

// TestComposeParser tests the Docker Compose parser functionality
func TestComposeParser(t *testing.T) {
	// Set up test server
	ts, err := setupTestServer(t)
	require.NoError(t, err)
	defer ts.cleanup()

	// Create test user and get token
	token := createTestUser(t, ts)

	// Test sample compose file
	// Rewritten with explicit 2-space indentation, version tag removed
	sampleCompose := `services:
	 web:
	   image: nginx:alpine
	   ports:
	     - "8080:80"
	   volumes:
	     - ./html:/usr/share/nginx/html
	   environment:
	     - NGINX_HOST=example.com
	 db:
	   image: postgres:12
	   environment:
	     - POSTGRES_USER=user
	     - POSTGRES_PASSWORD=password
	     - POSTGRES_DB=mydb
	   volumes:
	     - postgres-data:/var/lib/postgresql/data
volumes:
	 postgres-data: {} # Explicitly define as empty map
`

	// Test uploading and parsing compose file
	t.Run("ParseComposeFile", func(t *testing.T) {
		// Create JSON request body matching models.ComposeValidateRequest
		requestPayload := models.ComposeValidateRequest{
			ComposeFileContent: sampleCompose,
		}
		jsonBody, err := json.Marshal(requestPayload)
		require.NoError(t, err)
		body := bytes.NewBuffer(jsonBody)

		// Create request
		req, err := http.NewRequest("POST", ts.HttpServer.URL+"/api/v1/compose/validate", body)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json") // Set JSON Content-Type
		req.Header.Set("Authorization", "Bearer "+token)

		// Send request
		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		// Parse response (should contain parsed data now)
		var respData struct {
			Data struct {
				Valid    bool                     `json:"valid"` // Assuming 'valid' field exists
				Services []map[string]interface{} `json:"services"`
				Volumes  []map[string]interface{} `json:"volumes"`
				Networks []map[string]interface{} `json:"networks"`
			} `json:"data"`
		}
		err = json.NewDecoder(resp.Body).Decode(&respData)
		require.NoError(t, err, "Failed to decode validation response")

		// Check validation result
		assert.True(t, respData.Data.Valid)
		assert.Len(t, respData.Data.Services, 2)
		assert.Len(t, respData.Data.Volumes, 1) // Check top-level volumes

		// Check service details
		var webService, dbService map[string]interface{}
		for _, service := range respData.Data.Services {
			name, _ := service["name"].(string)
			if name == "web" {
				webService = service
			} else if name == "db" {
				dbService = service
			}
		}

		assert.NotNil(t, webService, "Web service not found")
		assert.NotNil(t, dbService, "DB service not found")

		assert.Equal(t, "nginx:alpine", webService["image"])
		assert.Equal(t, "postgres:12", dbService["image"])
	})

	// Test invalid compose file
	t.Run("InvalidComposeFile", func(t *testing.T) {
		invalidCompose := `
version: '3'
services:
  web:
    image: nginx:alpine
    ports:
      - 8080:80
      invalid_indentation
    volumes:
      - ./html:/usr/share/nginx/html
`

		// Create JSON request body matching models.ComposeValidateRequest
		requestPayload := models.ComposeValidateRequest{
			ComposeFileContent: invalidCompose,
		}
		jsonBody, err := json.Marshal(requestPayload)
		require.NoError(t, err)
		body := bytes.NewBuffer(jsonBody)

		// Create request
		req, err := http.NewRequest("POST", ts.HttpServer.URL+"/api/v1/compose/validate", body)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json") // Set JSON Content-Type
		req.Header.Set("Authorization", "Bearer "+token)

		// Send request
		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code (should be bad request)
		assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode) // Expect 422 for validation errors

		// Parse response
		// Parse the standard ErrorResponse model
		var respData models.ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&respData)
		require.NoError(t, err, "Failed to decode error response")

		// Check validation result (no 'Valid' field in ErrorResponse)
		assert.NotEmpty(t, respData.Error.Message)
		assert.Equal(t, "UNPROCESSABLE_ENTITY", respData.Error.Code) // Check error code
	})
}
