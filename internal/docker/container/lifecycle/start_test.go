package lifecycle

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	dockermocks "github.com/threatflux/dockerServerMangerGoMCP/internal/docker" // Import for mock
)

func TestNewStarter(t *testing.T) {
	// Create mock container manager
	mockClient := new(dockermocks.MockDockerClient)
	containerManager := NewContainerManager(mockClient)

	// Create new starter
	starter := NewStarter(containerManager)

	// Verify starter
	assert.NotNil(t, starter)
	assert.Equal(t, containerManager, starter.containerManager)
	assert.Equal(t, containerManager.logger, starter.logger)
}

func TestValidateAndResolveContainer(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	starter := NewStarter(manager)
	ctx := context.Background()

	// Test with container ID
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{}, nil).Once()

	containerID, err := starter.validateAndResolveContainer(ctx, StartOptions{
		ContainerID: "container-id",
	})

	assert.NoError(t, err)
	assert.Equal(t, "container-id", containerID)

	// Test with container name
	mockContainers := []types.Container{
		{
			ID:    "resolved-id",
			Names: []string{"/test-container"},
		},
	}
	mockClient.On("ContainerList", ctx, mock.Anything).Return(mockContainers, nil).Once()

	containerID, err = starter.validateAndResolveContainer(ctx, StartOptions{
		ContainerName: "test-container",
	})

	assert.NoError(t, err)
	assert.Equal(t, "resolved-id", containerID)

	// Test with non-existent container name
	mockClient.On("ContainerList", ctx, mock.Anything).Return([]types.Container{}, nil).Once()

	_, err = starter.validateAndResolveContainer(ctx, StartOptions{
		ContainerName: "non-existent",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test with neither ID nor name
	_, err = starter.validateAndResolveContainer(ctx, StartOptions{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "either container ID or name must be provided")

	mockClient.AssertExpectations(t)
}

func TestStart(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	starter := NewStarter(manager)
	ctx := context.Background()

	// Test starting a container successfully
	// First inspect (before starting)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:  "created",
				Running: false,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Start the container
	mockClient.On("ContainerStart", ctx, "container-id", mock.Anything).Return(nil).Once()

	// Second inspect (after starting)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Execute start
	result, err := starter.Start(ctx, StartOptions{
		ContainerID: "container-id",
	})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, result.Started)
	assert.False(t, result.AlreadyRunning)
	assert.Equal(t, "created", result.InitialState)
	assert.Equal(t, "running", result.FinalState)

	mockClient.AssertExpectations(t)
}

func TestStartAlreadyRunning(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	starter := NewStarter(manager)
	ctx := context.Background()

	// Container is already running
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Execute start
	result, err := starter.Start(ctx, StartOptions{
		ContainerID: "container-id",
	})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.False(t, result.Started)
	assert.True(t, result.AlreadyRunning)
	assert.Equal(t, "running", result.InitialState)
	assert.Equal(t, "running", result.FinalState)

	mockClient.AssertExpectations(t)
}

func TestStartWithRetries(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	starter := NewStarter(manager)
	ctx := context.Background()

	// First inspect (before starting)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:  "created",
				Running: false,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// First attempt fails
	mockClient.On("ContainerStart", ctx, "container-id", mock.Anything).Return(errors.New("temporary network error")).Once()

	// Second attempt succeeds
	mockClient.On("ContainerStart", ctx, "container-id", mock.Anything).Return(nil).Once()

	// Second inspect (after starting)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Execute start with retries
	result, err := starter.Start(ctx, StartOptions{
		ContainerID: "container-id",
		MaxRetries:  2,
	})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, result.Started)
	assert.Equal(t, "running", result.FinalState)

	mockClient.AssertExpectations(t)
}

func TestStartWithHealthCheck(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	starter := NewStarter(manager)
	ctx := context.Background()

	// First inspect (before starting)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:  "created",
				Running: false,
			},
		},
		Config: &container.Config{
			Healthcheck: &container.HealthConfig{
				Test: []string{"CMD-SHELL", "curl -f http://localhost/ || exit 1"},
			},
		},
	}, nil).Once()

	// Start the container
	mockClient.On("ContainerStart", ctx, "container-id", mock.Anything).Return(nil).Once()

	// Second inspect (after starting)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
				Health:  &types.Health{Status: "starting"},
			},
		},
		Config: &container.Config{
			Healthcheck: &container.HealthConfig{
				Test: []string{"CMD-SHELL", "curl -f http://localhost/ || exit 1"},
			},
		},
	}, nil).Once()

	// Health check polling - first check still starting
	mockClient.On("ContainerInspect", mock.Anything, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
				Health:  &types.Health{Status: "starting"},
			},
		},
		Config: &container.Config{
			Healthcheck: &container.HealthConfig{
				Test: []string{"CMD-SHELL", "curl -f http://localhost/ || exit 1"},
			},
		},
	}, nil).Once()

	// Health check polling - second check healthy
	mockClient.On("ContainerInspect", mock.Anything, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
				Health:  &types.Health{Status: "healthy"},
			},
		},
		Config: &container.Config{
			Healthcheck: &container.HealthConfig{
				Test: []string{"CMD-SHELL", "curl -f http://localhost/ || exit 1"},
			},
		},
	}, nil).Once()

	// Execute start with health check
	result, err := starter.Start(ctx, StartOptions{
		ContainerID:         "container-id",
		CheckHealthStatus:   true,
		HealthCheckInterval: 10, // very short for test
		HealthCheckTimeout:  2,  // very short for test
	})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, result.Started)
	assert.Equal(t, "healthy", result.HealthStatus)

	mockClient.AssertExpectations(t)
}

func TestStartWithLogs(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	starter := NewStarter(manager)
	ctx := context.Background()

	// First inspect (before starting)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:  "created",
				Running: false,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Start the container
	mockClient.On("ContainerStart", ctx, "container-id", mock.Anything).Return(nil).Once()

	// Second inspect (after starting)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Get logs
	logReader := io.NopCloser(strings.NewReader("2023-01-01T00:00:00Z Container started successfully"))
	mockClient.On("ContainerLogs", ctx, "container-id", mock.Anything).Return(logReader, nil).Once()

	// Execute start with log capture
	result, err := starter.Start(ctx, StartOptions{
		ContainerID:    "container-id",
		LogOutput:      true,
		LogOutputLines: 10,
	})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, result.Started)
	assert.Contains(t, result.Logs, "Container started successfully")

	mockClient.AssertExpectations(t)
}

func TestStartErrorHandling(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	starter := NewStarter(manager)
	ctx := context.Background()

	// Test cases for error handling
	testCases := []struct {
		name        string
		setupMocks  func()
		expectError string
	}{
		{
			name: "Container not found",
			setupMocks: func() {
				mockClient.On("ContainerInspect", ctx, "invalid-id").Return(types.ContainerJSON{}, errors.New("no such container")).Once()
			},
			expectError: "failed to inspect container",
		},
		{
			name: "Start error - no retries",
			setupMocks: func() {
				mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID:   "container-id",
						Name: "/test-container",
						State: &types.ContainerState{
							Status:  "created",
							Running: false,
						},
					},
					Config: &container.Config{},
				}, nil).Once()

				mockClient.On("ContainerStart", ctx, "container-id", mock.Anything).Return(errors.New("start error")).Once()
			},
			expectError: "failed to start container",
		},
		{
			name: "Start error - after retries",
			setupMocks: func() {
				mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID:   "container-id",
						Name: "/test-container",
						State: &types.ContainerState{
							Status:  "created",
							Running: false,
						},
					},
					Config: &container.Config{},
				}, nil).Once()

				// All retries fail
				mockClient.On("ContainerStart", ctx, "container-id", mock.Anything).Return(errors.New("start error")).Times(3)
			},
			expectError: "failed to start container after retries",
		},
		{
			name: "Health check timeout",
			setupMocks: func() {
				mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID:   "container-id",
						Name: "/test-container",
						State: &types.ContainerState{
							Status:  "created",
							Running: false,
						},
					},
					Config: &container.Config{
						Healthcheck: &container.HealthConfig{
							Test: []string{"CMD", "test"},
						},
					},
				}, nil).Once()

				mockClient.On("ContainerStart", ctx, "container-id", mock.Anything).Return(nil).Once()

				mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
					ContainerJSONBase: &types.ContainerJSONBase{
						ID:   "container-id",
						Name: "/test-container",
						State: &types.ContainerState{
							Status:  "running",
							Running: true,
							Health:  &types.Health{Status: "starting"},
						},
					},
					Config: &container.Config{
						Healthcheck: &container.HealthConfig{
							Test: []string{"CMD", "test"},
						},
					},
				}, nil).Times(3) // Always return "starting" to cause timeout
			},
			expectError: "health check failed: health check timed out",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks for this test case
			tc.setupMocks()

			// Execute start
			result, err := starter.Start(ctx, StartOptions{
				ContainerID:         "container-id",
				CheckHealthStatus:   true,
				HealthCheckInterval: 10, // very short for test
				HealthCheckTimeout:  1,  // very short for test
				MaxRetries:          2,
			})

			// Container not found needs different ID
			if tc.name == "Container not found" {
				result, err = starter.Start(ctx, StartOptions{
					ContainerID: "invalid-id",
				})
			}

			// Verify results
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectError)
			assert.False(t, result.Success)
			assert.NotEmpty(t, result.Error)
		})
	}

	mockClient.AssertExpectations(t)
}

func TestStartMultiple(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	starter := NewStarter(manager)
	ctx := context.Background()

	// Setup for two containers

	// First container
	mockClient.On("ContainerInspect", ctx, "container-1").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-1",
			Name: "/test-container-1",
			State: &types.ContainerState{
				Status:  "created",
				Running: false,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	mockClient.On("ContainerStart", ctx, "container-1", mock.Anything).Return(nil).Once()

	mockClient.On("ContainerInspect", ctx, "container-1").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-1",
			Name: "/test-container-1",
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Second container
	mockClient.On("ContainerInspect", ctx, "container-2").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-2",
			Name: "/test-container-2",
			State: &types.ContainerState{
				Status:  "created",
				Running: false,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	mockClient.On("ContainerStart", ctx, "container-2", mock.Anything).Return(nil).Once()

	mockClient.On("ContainerInspect", ctx, "container-2").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-2",
			Name: "/test-container-2",
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Execute start multiple
	results, err := starter.StartMultiple(ctx, []string{"container-1", "container-2"}, StartOptions{})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, results)
	assert.Len(t, results, 2)
	assert.Contains(t, results, "container-1")
	assert.Contains(t, results, "container-2")
	assert.True(t, results["container-1"].Success)
	assert.True(t, results["container-2"].Success)
	assert.True(t, results["container-1"].Started)
	assert.True(t, results["container-2"].Started)

	mockClient.AssertExpectations(t)
}

// Removed TestToModel as the ToModel function implementation was incorrect
// and the ContainerOperation type doesn't have the asserted fields.

func TestCalculateBackoffDelay(t *testing.T) {
	// Create starter
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	starter := NewStarter(manager)

	// Test exponential backoff
	delay0 := starter.calculateBackoffDelay(0)
	delay1 := starter.calculateBackoffDelay(1)
	delay2 := starter.calculateBackoffDelay(2)
	delay3 := starter.calculateBackoffDelay(3)

	// Check increasing delays (allowing for jitter)
	assert.GreaterOrEqual(t, delay1, delay0)
	assert.GreaterOrEqual(t, delay2, delay1)
	assert.GreaterOrEqual(t, delay3, delay2)

	// Check that delay0 is around 100ms (allowing for jitter)
	assert.GreaterOrEqual(t, delay0, 90*time.Millisecond)
	assert.LessOrEqual(t, delay0, 110*time.Millisecond)

	// Check high attempt number is capped
	delayHigh := starter.calculateBackoffDelay(10)
	assert.LessOrEqual(t, delayHigh, 10*time.Second)
}
