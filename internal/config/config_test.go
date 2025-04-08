package config

import (
	"os"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	// Setup test environment
	setupTestEnv(t)
	defer cleanupTestEnv(t)

	// Test loading config
	config, err := LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify loaded values
	assert.Equal(t, "127.0.0.1", config.Server.Host)
	assert.Equal(t, 9090, config.Server.Port)
	assert.Equal(t, 60*time.Second, config.Server.ReadTimeout)
	assert.Equal(t, "debug", config.Server.Mode)
	assert.Equal(t, "postgres", config.Database.Type)
	assert.Equal(t, "test-db", config.Database.Name)
	assert.Equal(t, "test-secret", config.Auth.Secret)
	assert.Equal(t, 30*time.Minute, config.Auth.AccessTokenTTL)
	assert.Equal(t, "tcp://localhost:2375", config.Docker.Host)
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func(*Config)
		wantErr     bool
		errMsg      string
	}{
		{
			name: "valid config",
			setupConfig: func(c *Config) {
				// Set values that pass validation
				c.Server.Port = 8080
				c.Database.Type = "sqlite"
				c.Database.SQLite.Path = "test.db"
				c.Database.MaxOpenConns = 10                                   // Must be >= 1
				c.Auth.Secret = "a-very-secure-secret-key-that-is-long-enough" // Must be >= 32 chars
				c.Auth.AccessTokenTTL = 15 * time.Minute
				c.Auth.RefreshTokenTTL = 24 * time.Hour
				c.Auth.Algorithm = "HS256"          // Must be a supported algorithm
				c.Auth.PasswordPolicy.MinLength = 8 // Must be >= 8
				c.Docker.Host = "unix:///var/run/docker_test.sock"
			},
			wantErr: false,
		},
		{
			name: "invalid server port",
			setupConfig: func(c *Config) {
				c.Server.Port = 0
				c.Database.Type = "sqlite"
				c.Database.SQLite.Path = "test.db"
				c.Auth.Secret = "test-secret"
				c.Auth.AccessTokenTTL = 15 * time.Minute
				c.Auth.RefreshTokenTTL = 24 * time.Hour
				c.Docker.Host = "unix:///var/run/docker_test.sock"
			},
			wantErr: true,
			errMsg:  "invalid server port",
		},
		{
			name: "unsupported database type",
			setupConfig: func(c *Config) {
				c.Server.Port = 8080
				c.Database.Type = "mysql"
				c.Auth.Secret = "test-secret"
				c.Auth.AccessTokenTTL = 15 * time.Minute
				c.Auth.RefreshTokenTTL = 24 * time.Hour
				c.Docker.Host = "unix:///var/run/docker_test.sock"
			},
			wantErr: true,
			errMsg:  "unsupported database type",
		},
		{
			name: "empty auth secret",
			setupConfig: func(c *Config) {
				c.Server.Port = 8080
				c.Database.Type = "sqlite"
				c.Database.SQLite.Path = "test.db"
				c.Auth.Secret = ""
				c.Auth.AccessTokenTTL = 15 * time.Minute
				c.Auth.RefreshTokenTTL = 24 * time.Hour
				c.Docker.Host = "unix:///var/run/docker_test.sock"
			},
			wantErr: true,
			errMsg:  "auth secret is empty",
		},
		{
			name: "missing postgres host",
			setupConfig: func(c *Config) {
				c.Server.Port = 8080
				c.Database.Type = "postgres"
				c.Database.Host = ""
				c.Database.Port = 5432
				c.Database.User = "user"
				c.Database.Name = "dbname"
				c.Auth.Secret = "test-secret"
				c.Auth.AccessTokenTTL = 15 * time.Minute
				c.Auth.RefreshTokenTTL = 24 * time.Hour
				c.Docker.Host = "unix:///var/run/docker_test.sock"
			},
			wantErr: true,
			errMsg:  "postgres host is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := new(Config)
			tt.setupConfig(config)

			err := validateConfig(config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func setupTestEnv(t *testing.T) {
	// Reset viper
	viper.Reset()

	// Set environment variables for testing
	os.Setenv("DSM_SERVER_HOST", "127.0.0.1")
	os.Setenv("DSM_SERVER_PORT", "9090")
	os.Setenv("DSM_SERVER_READ_TIMEOUT", "60s")
	os.Setenv("DSM_SERVER_MODE", "debug")
	os.Setenv("DSM_DATABASE_TYPE", "postgres")
	os.Setenv("DSM_DATABASE_HOST", "localhost")
	os.Setenv("DSM_DATABASE_PORT", "5432")
	os.Setenv("DSM_DATABASE_USER", "postgres")
	os.Setenv("DSM_DATABASE_PASSWORD", "postgres")
	os.Setenv("DSM_DATABASE_NAME", "test-db")
	os.Setenv("DSM_AUTH_SECRET", "test-secret")
	os.Setenv("DSM_AUTH_ACCESS_TOKEN_TTL", "30m")
	os.Setenv("DSM_DOCKER_HOST", "tcp://localhost:2375")

	// Set defaults
	setDefaults()

	// Load environment variables
	loadEnvVars()
}

func cleanupTestEnv(t *testing.T) {
	// Unset environment variables
	os.Unsetenv("DSM_SERVER_HOST")
	os.Unsetenv("DSM_SERVER_PORT")
	os.Unsetenv("DSM_SERVER_READ_TIMEOUT")
	os.Unsetenv("DSM_SERVER_MODE")
	os.Unsetenv("DSM_DATABASE_TYPE")
	os.Unsetenv("DSM_DATABASE_HOST")
	os.Unsetenv("DSM_DATABASE_PORT")
	os.Unsetenv("DSM_DATABASE_USER")
	os.Unsetenv("DSM_DATABASE_PASSWORD")
	os.Unsetenv("DSM_DATABASE_NAME")
	os.Unsetenv("DSM_AUTH_SECRET")
	os.Unsetenv("DSM_AUTH_ACCESS_TOKEN_TTL")
	os.Unsetenv("DSM_DOCKER_HOST")
}
