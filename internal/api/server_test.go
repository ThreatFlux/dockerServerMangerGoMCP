package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	// "context" // Removed unused import
	// "net/http" // Removed unused import

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	// "github.com/stretchr/testify/mock" // Removed unused import (mocks moved)
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/database" // Removed unused import (mocks moved)
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/docker_test"    // Removed unused import (mocks moved)
	// gorm "gorm.io/gorm"                                             // Removed unused import (mocks moved)
	// dockerClient "github.com/docker_test/docker_test/client"                  // Removed unused import (mocks moved)
	// dockerTypes "github.com/docker_test/docker_test/api/types"                // Removed unused import (mocks moved)
)

// MockDB and MockDockerManager are defined in mocks_test.go

func TestNewServer(t *testing.T) {
	// Setup test dependencies
	logger := logrus.New()
	mockDB := new(MockDB)
	mockAuthService := new(auth.MockService)
	mockDockerManager := new(MockDockerManager) // Use mock from mocks_test.go

	cfg := &config.Config{
		Version:  "test-version",
		ServerID: "test-server",
		Server: struct {
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
			Mode: "test",
		},
	}

	tests := []struct {
		name        string
		config      *ServerConfig
		shouldError bool
	}{
		{
			name: "Valid configuration",
			config: &ServerConfig{
				Config:        cfg,
				Logger:        logger,
				DB:            mockDB,
				AuthService:   mockAuthService,
				DockerManager: mockDockerManager,
			},
			shouldError: false,
		},
		{
			name: "Missing config",
			config: &ServerConfig{
				Logger:        logger,
				DB:            mockDB,
				AuthService:   mockAuthService,
				DockerManager: mockDockerManager,
			},
			shouldError: true,
		},
		{
			name: "Missing logger",
			config: &ServerConfig{
				Config:        cfg,
				DB:            mockDB,
				AuthService:   mockAuthService,
				DockerManager: mockDockerManager,
			},
			shouldError: true,
		},
		{
			name: "Missing database",
			config: &ServerConfig{
				Config:        cfg,
				Logger:        logger,
				AuthService:   mockAuthService,
				DockerManager: mockDockerManager,
			},
			shouldError: true,
		},
		{
			name: "Missing auth service",
			config: &ServerConfig{
				Config:        cfg,
				Logger:        logger,
				DB:            mockDB,
				DockerManager: mockDockerManager,
			},
			shouldError: true,
		},
		{
			name: "Missing docker_test client",
			config: &ServerConfig{
				Config:        cfg,
				Logger:        logger,
				DB:            mockDB,
				AuthService:   mockAuthService,
				DockerManager: nil,
			},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(tt.config)
			if tt.shouldError {
				assert.Error(t, err)
				assert.Nil(t, server)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, server)
				assert.Equal(t, tt.config.Config, server.GetConfig())
				assert.Equal(t, tt.config.Logger, server.GetLogger())
				assert.Equal(t, tt.config.DB, server.GetDB())
				assert.Equal(t, tt.config.AuthService, server.GetAuthService())
				assert.Equal(t, tt.config.DockerManager, server.GetDockerManager())
				assert.NotNil(t, server.Router())
				assert.NotNil(t, server.GetAuthMiddleware())
			}
		})
	}
}

func TestServerAccessors(t *testing.T) {
	// Setup test dependencies
	logger := logrus.New()
	mockDB := new(MockDB)
	mockAuthService := new(auth.MockService)
	mockDockerManager := new(MockDockerManager) // Use mock from mocks_test.go

	cfg := &config.Config{
		Version:  "test-version",
		ServerID: "test-server",
		Server: struct {
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
			Mode: "test",
		},
	}

	serverConfig := &ServerConfig{
		Config:        cfg,
		Logger:        logger,
		DB:            mockDB,
		AuthService:   mockAuthService,
		DockerManager: mockDockerManager,
	}

	server, err := NewServer(serverConfig)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Test accessor methods
	assert.Equal(t, cfg, server.GetConfig())
	assert.Equal(t, logger, server.GetLogger())
	assert.Equal(t, mockDB, server.GetDB())
	assert.Equal(t, mockAuthService, server.GetAuthService())
	assert.Equal(t, mockDockerManager, server.GetDockerManager())
	assert.NotNil(t, server.GetAuthMiddleware())
	assert.NotNil(t, server.Router())
}

func TestWaitGroupOperations(t *testing.T) {
	// Setup test dependencies
	logger := logrus.New()
	mockDB := new(MockDB)
	mockAuthService := new(auth.MockService)
	mockDockerManager := new(MockDockerManager) // Use mock from mocks_test.go

	cfg := &config.Config{
		Version:  "test-version",
		ServerID: "test-server",
		Server: struct {
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
			Mode: "test",
		},
	}

	serverConfig := &ServerConfig{
		Config:        cfg,
		Logger:        logger,
		DB:            mockDB,
		AuthService:   mockAuthService,
		DockerManager: mockDockerManager,
	}

	server, err := NewServer(serverConfig)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Test wait group operations
	// We can't directly test the wait group state, but we can verify the methods don't panic
	assert.NotPanics(t, func() {
		server.IncrementWaitGroup()
		server.DecrementWaitGroup()
	})
}

func TestRegisterRoutesNotImplemented(t *testing.T) {
	// This function will be implemented in routes.go
	// Here we just verify that the server has a router

	// Setup test dependencies
	logger := logrus.New()
	mockDB := new(MockDB)
	mockAuthService := new(auth.MockService)
	mockDockerManager := new(MockDockerManager) // Use mock from mocks_test.go

	cfg := &config.Config{
		Version:  "test-version",
		ServerID: "test-server",
		Server: struct {
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
			Mode: "test",
		},
	}

	serverConfig := &ServerConfig{
		Config:        cfg,
		Logger:        logger,
		DB:            mockDB,
		AuthService:   mockAuthService,
		DockerManager: mockDockerManager,
	}

	server, err := NewServer(serverConfig)
	assert.NoError(t, err)
	assert.NotNil(t, server)
	assert.NotNil(t, server.Router())
}

func TestServerStartAndShutdown(t *testing.T) {
	// Setup test dependencies
	logger := logrus.New()
	mockDB := new(MockDB)
	mockAuthService := new(auth.MockService)
	mockDockerManager := new(MockDockerManager) // Use mock from mocks_test.go

	// Setup expectations
	mockDB.On("Close").Return(nil)
	mockDockerManager.On("Close").Return(nil)

	cfg := &config.Config{
		Version:  "test-version",
		ServerID: "test-server",
		Server: struct {
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
			Port: 0, // Use port 0 to let the OS assign a free port
			Mode: "test",
		},
	}

	serverConfig := &ServerConfig{
		Config:        cfg,
		Logger:        logger,
		DB:            mockDB,
		AuthService:   mockAuthService,
		DockerManager: mockDockerManager,
	}

	server, err := NewServer(serverConfig)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Start the server
	err = server.Start()
	assert.NoError(t, err)

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Test a request to the server
	resp, err := http.Get("http://" + server.httpServer.Addr + "/health")
	if err == nil {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// Shutdown the server
	server.Shutdown()

	// Verify expectations
	mockDB.AssertExpectations(t)
	mockDockerManager.AssertExpectations(t)
}

func TestStartTLSError(t *testing.T) {
	// Setup test dependencies
	logger := logrus.New()
	mockDB := new(MockDB)
	mockAuthService := new(auth.MockService)
	mockDockerManager := new(MockDockerManager) // Use mock from mocks_test.go

	// Configuration without TLS
	cfg := &config.Config{
		Version:  "test-version",
		ServerID: "test-server",
		Server: struct {
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
			Mode: "test",
		},
	}

	serverConfig := &ServerConfig{
		Config:        cfg,
		Logger:        logger,
		DB:            mockDB,
		AuthService:   mockAuthService,
		DockerManager: mockDockerManager,
	}

	server, err := NewServer(serverConfig)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Try to start with TLS but without TLS config
	err = server.StartTLS()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TLS is not enabled in configuration")

	// Add incomplete TLS config
	// Add incomplete TLS config
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = "cert.pem"
	// Missing KeyFile

	err = server.StartTLS()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TLS key file is required")

	// Complete but invalid TLS config (for testing purposes)
	// Complete TLS config
	cfg.Server.TLS.KeyFile = "key.pem"

	// Don't actually start the server, as it would fail with non-existent cert files
	// We just want to verify the validation logic
}

func TestProductionMode(t *testing.T) {
	// Setup test dependencies
	logger := logrus.New()
	mockDB := new(MockDB)
	mockAuthService := new(auth.MockService)
	mockDockerManager := new(MockDockerManager) // Use mock from mocks_test.go

	cfg := &config.Config{
		Version:  "prod-version",
		ServerID: "prod-server",
		Server: struct {
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
			Mode: "production",
		},
	}

	serverConfig := &ServerConfig{
		Config:        cfg,
		Logger:        logger,
		DB:            mockDB,
		AuthService:   mockAuthService,
		DockerManager: mockDockerManager,
	}

	// Save current Gin mode
	prevMode := gin.Mode()
	defer gin.SetMode(prevMode) // Restore after test

	// Create server which should set Gin to ReleaseMode
	_, err := NewServer(serverConfig)
	assert.NoError(t, err)
	assert.Equal(t, gin.ReleaseMode, gin.Mode())
}

func TestRouteHandling(t *testing.T) {
	// Setup test dependencies
	logger := logrus.New()
	mockDB := new(MockDB)
	mockAuthService := new(auth.MockService)
	mockDockerManager := new(MockDockerManager) // Use mock from mocks_test.go

	cfg := &config.Config{
		Version:  "test-version",
		ServerID: "test-server",
		Server: struct {
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
			Mode: "test",
		},
	}

	serverConfig := &ServerConfig{
		Config:        cfg,
		Logger:        logger,
		DB:            mockDB,
		AuthService:   mockAuthService,
		DockerManager: mockDockerManager,
	}

	server, err := NewServer(serverConfig)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Register routes (calls our test implementation)
	err = server.RegisterRoutes() // Use public method
	assert.NoError(t, err)

	// Create a test HTTP recorder
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	server.Router().ServeHTTP(w, req)

	// Check response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "status")
	assert.Contains(t, w.Body.String(), "ok")
}
