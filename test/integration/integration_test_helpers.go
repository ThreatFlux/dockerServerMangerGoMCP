package integration

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/mock"
	dockerinternal "github.com/threatflux/dockerServerMangerGoMCP/internal/docker"
)

// MockDockerManager implements the docker.Manager interface for integration tests
type MockDockerManager struct {
	mock.Mock
	// Add fields to store mock data if needed, e.g., for containers
	// MockContainers map[string]*docker_internal.MockContainer // Example if needed
	MockVolumes map[string]*MockVolume // Move inside struct
}

// AddMockContainer adds or updates a mock container (Example method if needed)
// func (m *MockDockerManager) AddMockContainer(mc *docker_internal.MockContainer) {
// 	if m.MockContainers == nil {
// 		m.MockContainers = make(map[string]*docker_internal.MockContainer)
// 	}
// 	m.MockContainers[mc.ID] = mc
// }

// GetContainer retrieves a mock container by ID (Example method if needed)
// func (m *MockDockerManager) GetContainer(id string) (*docker_internal.MockContainer, error) {
// 	// ... implementation ...
// 	return nil, nil // Placeholder
// }

// RemoveContainer removes a mock container by ID (Example method if needed)
// func (m *MockDockerManager) RemoveContainer(id string) error {
// 	// ... implementation ...
// 	return nil // Placeholder
// }

func (m *MockDockerManager) GetClient() (*client.Client, error) {
	args := m.Called()
	// Default mock behavior if not set
	if len(args) == 0 {
		return nil, nil
	}
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.Client), args.Error(1)
}
func (m *MockDockerManager) GetWithContext(ctx context.Context) (*client.Client, error) {
	args := m.Called(ctx)
	// Default mock behavior if not set
	if len(args) == 0 {
		return nil, nil
	}
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.Client), args.Error(1)
}
func (m *MockDockerManager) Ping(ctx context.Context) (types.Ping, error) {
	args := m.Called(ctx)
	// Default mock behavior if not set
	if len(args) == 0 {
		return types.Ping{}, nil
	}
	return args.Get(0).(types.Ping), args.Error(1)
}
func (m *MockDockerManager) IsInitialized() bool {
	args := m.Called()
	if len(args) == 0 {
		return false
	}
	return args.Bool(0)
}
func (m *MockDockerManager) IsClosed() bool {
	args := m.Called()
	if len(args) == 0 {
		return false
	}
	return args.Bool(0)
}
func (m *MockDockerManager) GetConfig() dockerinternal.ClientConfig {
	args := m.Called()
	// Default mock behavior if not set
	if len(args) == 0 {
		return dockerinternal.ClientConfig{}
	}
	return args.Get(0).(dockerinternal.ClientConfig)
}
func (m *MockDockerManager) Close() error {
	args := m.Called()
	if len(args) == 0 {
		return nil
	}
	return args.Error(0)
}

// Add other necessary mock methods from the docker_test.Manager interface if needed by tests

// MockVolume is a simplified mock for testing volume operations
type MockVolume struct {
	Name       string
	Driver     string
	Mountpoint string
	CreatedAt  string
	Labels     map[string]string
	InUse      bool
}

// AddMockVolume adds a mock volume for testing
func (m *MockDockerManager) AddMockVolume(mv *MockVolume) {
	if m.MockVolumes == nil {
		m.MockVolumes = make(map[string]*MockVolume)
	}
	m.MockVolumes[mv.Name] = mv
}

// GetVolume retrieves a mock volume by name
func (m *MockDockerManager) GetVolume(name string) (*MockVolume, error) {
	if m.MockVolumes == nil {
		return nil, fmt.Errorf("mock volume store not initialized")
	}
	vol, ok := m.MockVolumes[name]
	if !ok {
		return nil, fmt.Errorf("mock volume '%s' not found", name)
	}
	return vol, nil
}

// RemoveVolume removes a mock volume by name
func (m *MockDockerManager) RemoveVolume(name string) error {
	if m.MockVolumes == nil {
		return fmt.Errorf("mock volume store not initialized")
	}
	if _, ok := m.MockVolumes[name]; !ok {
		return fmt.Errorf("mock volume '%s' not found", name)
	}
	delete(m.MockVolumes, name)
	return nil
}

// PruneVolumes simulates pruning volumes
func (m *MockDockerManager) PruneVolumes() ([]string, int64) {
	if m.MockVolumes == nil {
		return []string{}, 0
	}
	deleted := []string{}
	for name, vol := range m.MockVolumes {
		if !vol.InUse {
			deleted = append(deleted, name)
			delete(m.MockVolumes, name)
		}
	}
	// Simulate some space reclaimed
	return deleted, int64(len(deleted) * 1024 * 1024)
}
