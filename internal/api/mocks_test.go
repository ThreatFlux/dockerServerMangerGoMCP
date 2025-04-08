package api

import (
	"context"
	// "time" // Removed unused import

	dockerTypes "github.com/docker/docker/api/types" // Added for MockDockerManager Ping response
	dockerClient "github.com/docker/docker/client"   // Added for MockDockerManager
	"github.com/stretchr/testify/mock"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker" // Added for docker_test.ClientConfig
	"gorm.io/gorm"                                                  // Added for MockDB
)

// --- Mock Definitions ---

// MockDB is a mock implementation of database.Database
type MockDB struct {
	mock.Mock
}

func (m *MockDB) DB() *gorm.DB {
	args := m.Called()
	// Return nil or a mock gorm.DB if needed for specific tests
	if db := args.Get(0); db != nil {
		return db.(*gorm.DB)
	}
	return nil
}

func (m *MockDB) Connect() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDB) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDB) Migrate(models ...interface{}) error {
	args := m.Called(models)
	return args.Error(0)
}

func (m *MockDB) Ping() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDB) Transaction(fn func(tx *gorm.DB) error) error {
	args := m.Called(fn)
	return args.Error(0) // Basic implementation for interface satisfaction
}

// MockDockerManager is a mock implementation of docker.Manager
type MockDockerManager struct {
	mock.Mock
}

func (m *MockDockerManager) GetClient() (*dockerClient.Client, error) {
	args := m.Called()
	if c := args.Get(0); c != nil {
		return c.(*dockerClient.Client), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockDockerManager) GetWithContext(ctx context.Context) (*dockerClient.Client, error) {
	args := m.Called(ctx)
	if c := args.Get(0); c != nil {
		return c.(*dockerClient.Client), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockDockerManager) Ping(ctx context.Context) (dockerTypes.Ping, error) {
	args := m.Called(ctx)
	// Ensure a Ping struct is returned, even if zero value
	ping, _ := args.Get(0).(dockerTypes.Ping)
	return ping, args.Error(1)
}

func (m *MockDockerManager) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDockerManager) IsInitialized() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockDockerManager) IsClosed() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockDockerManager) GetConfig() docker.ClientConfig {
	args := m.Called()
	// Ensure a ClientConfig struct is returned, even if zero value
	cfg, _ := args.Get(0).(docker.ClientConfig)
	return cfg
}

// --- End Mock Definitions ---
