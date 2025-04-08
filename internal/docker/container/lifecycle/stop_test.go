package lifecycle

import (
	"context"
	"errors"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	dockermocks "github.com/threatflux/dockerServerMangerGoMCP/internal/docker" // Import for mock
	"testing"
)

func TestNewStopper(t *testing.T) {
	// Create mock container manager
	mockClient := new(dockermocks.MockDockerClient)
	containerManager := NewContainerManager(mockClient)

	// Create new stopper
	stopper := NewStopper(containerManager)

	// Verify stopper
	assert.NotNil(t, stopper)
	assert.Equal(t, containerManager, stopper.containerManager)
	assert.Equal(t, containerManager.logger, stopper.logger)
}

func TestValidateAndResolveContainerStop(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	stopper := NewStopper(manager)
	ctx := context.Background()

	// Test with container ID
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{}, nil).Once()

	containerID, err := stopper.validateAndResolveContainer(ctx, StopOptions{
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

	containerID, err = stopper.validateAndResolveContainer(ctx, StopOptions{
		ContainerName: "test-container",
	})

	assert.NoError(t, err)
	assert.Equal(t, "resolved-id", containerID)

	// Test with non-existent container name
	mockClient.On("ContainerList", ctx, mock.Anything).Return([]types.Container{}, nil).Once()

	_, err = stopper.validateAndResolveContainer(ctx, StopOptions{
		ContainerName: "non-existent",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test with neither ID nor name
	_, err = stopper.validateAndResolveContainer(ctx, StopOptions{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "either container ID or name must be provided")

	mockClient.AssertExpectations(t)
}

func TestStopContainer(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	stopper := NewStopper(manager)
	ctx := context.Background()

	// Test stopping a container successfully
	// First inspect (before stopping)
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

	// Stop the container
	stopTimeout := 10
	mockClient.On("ContainerStop", ctx, "container-id", mock.MatchedBy(func(options container.StopOptions) bool {
		return *options.Timeout == int(stopTimeout)
	})).Return(nil).Once()

	// Second inspect (after stopping)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:   "exited",
				Running:  false,
				ExitCode: 0,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Execute stop
	result, err := stopper.Stop(ctx, StopOptions{
		ContainerID: "container-id",
		Timeout:     stopTimeout,
	})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, result.Stopped)
	assert.False(t, result.WasStopped)
	assert.Equal(t, "running", result.InitialState)
	assert.Equal(t, "exited", result.FinalState)

	mockClient.AssertExpectations(t)
}

func TestStopAlreadyStoppedContainer(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	stopper := NewStopper(manager)
	ctx := context.Background()

	// Container is already stopped
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:   "exited",
				Running:  false,
				ExitCode: 0,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Execute stop
	result, err := stopper.Stop(ctx, StopOptions{
		ContainerID: "container-id",
	})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.False(t, result.Stopped)
	assert.True(t, result.WasStopped)
	assert.Equal(t, "exited", result.InitialState)
	assert.Equal(t, "exited", result.FinalState)

	mockClient.AssertExpectations(t)
}

func TestStopWithWait(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	stopper := NewStopper(manager)
	ctx := context.Background()

	// First inspect (before stopping)
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

	// Stop the container
	stopTimeout := 10
	mockClient.On("ContainerStop", ctx, "container-id", mock.MatchedBy(func(options container.StopOptions) bool {
		return *options.Timeout == int(stopTimeout)
	})).Return(nil).Once()

	// Mock wait response
	statusCh := make(chan container.WaitResponse, 1)
	errCh := make(chan error, 1)

	statusCh <- container.WaitResponse{
		StatusCode: 0,
		Error:      nil,
	}

	mockClient.On("ContainerWait", mock.Anything, "container-id", container.WaitConditionNotRunning).
		Return(statusCh, errCh).Once()

	// Second inspect (after stopping)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:   "exited",
				Running:  false,
				ExitCode: 0,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Execute stop with wait
	result, err := stopper.Stop(ctx, StopOptions{
		ContainerID: "container-id",
		Timeout:     stopTimeout,
		WaitForStop: true,
		WaitTimeout: 5,
	})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, result.Stopped)
	assert.Contains(t, result.MessageDetail, "successfully")
	assert.Equal(t, 0, result.ExitCode)

	mockClient.AssertExpectations(t)
}

func TestStopWithSignal(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	stopper := NewStopper(manager)
	ctx := context.Background()

	// First inspect (before stopping)
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

	// Stop the container with signal
	stopTimeout := 10
	mockClient.On("ContainerStop", ctx, "container-id", mock.MatchedBy(func(options container.StopOptions) bool {
		return *options.Timeout == int(stopTimeout) && options.Signal == "SIGTERM"
	})).Return(nil).Once()

	// Second inspect (after stopping)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:   "exited",
				Running:  false,
				ExitCode: 0,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Execute stop with signal
	result, err := stopper.Stop(ctx, StopOptions{
		ContainerID: "container-id",
		Timeout:     stopTimeout,
		Signal:      "SIGTERM",
	})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, result.Stopped)

	mockClient.AssertExpectations(t)
}

func TestStopOnlySendSignal(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	stopper := NewStopper(manager)
	ctx := context.Background()

	// First inspect (before stopping)
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

	// Send signal
	mockClient.On("ContainerKill", ctx, "container-id", "SIGUSR1").Return(nil).Once()

	// Second inspect (after signal)
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

	// Execute only send signal
	result, err := stopper.Stop(ctx, StopOptions{
		ContainerID:    "container-id",
		Signal:         "SIGUSR1",
		OnlySendSignal: true,
	})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.False(t, result.Stopped)
	assert.Contains(t, result.MessageDetail, "Signal SIGUSR1 sent")

	mockClient.AssertExpectations(t)
}

func TestStopWithForce(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	stopper := NewStopper(manager)
	ctx := context.Background()

	// First inspect (before stopping)
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

	// Stop the container - fails
	stopTimeout := 10
	mockClient.On("ContainerStop", ctx, "container-id", mock.MatchedBy(func(options container.StopOptions) bool {
		return *options.Timeout == int(stopTimeout)
	})).Return(errors.New("container stop failed")).Once()

	// Force kill the container
	mockClient.On("ContainerKill", ctx, "container-id", "SIGKILL").Return(nil).Once()

	// Second inspect (after killing)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:   "exited",
				Running:  false,
				ExitCode: 137, // SIGKILL exit code
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Execute stop with force
	result, err := stopper.Stop(ctx, StopOptions{
		ContainerID: "container-id",
		Timeout:     stopTimeout,
		Force:       true,
	})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, result.Stopped)
	assert.True(t, result.WasKilled)
	assert.Equal(t, 137, result.ExitCode)
	assert.Contains(t, result.MessageDetail, "forcefully killed")

	mockClient.AssertExpectations(t)
}

func TestStopErrorHandling(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	stopper := NewStopper(manager)
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
			name: "Stop error without force",
			setupMocks: func() {
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

				stopTimeout := 10
				mockClient.On("ContainerStop", ctx, "container-id", mock.MatchedBy(func(options container.StopOptions) bool {
					return *options.Timeout == int(stopTimeout)
				})).Return(errors.New("stop error")).Once()
			},
			expectError: "failed to stop container",
		},
		{
			name: "Force kill also fails",
			setupMocks: func() {
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

				stopTimeout := 10
				mockClient.On("ContainerStop", ctx, "container-id", mock.MatchedBy(func(options container.StopOptions) bool {
					return *options.Timeout == int(stopTimeout)
				})).Return(errors.New("stop error")).Once()

				mockClient.On("ContainerKill", ctx, "container-id", "SIGKILL").Return(errors.New("kill error")).Once()
			},
			expectError: "failed to stop container and force kill also failed",
		},
		{
			name: "Only send signal fails",
			setupMocks: func() {
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

				mockClient.On("ContainerKill", ctx, "container-id", "SIGUSR1").Return(errors.New("signal error")).Once()
			},
			expectError: "failed to send signal to container",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks for this test case
			tc.setupMocks()

			// Execute stop
			var result *StopResult
			var err error

			if tc.name == "Container not found" {
				result, err = stopper.Stop(ctx, StopOptions{
					ContainerID: "invalid-id",
				})
			} else if tc.name == "Only send signal fails" {
				result, err = stopper.Stop(ctx, StopOptions{
					ContainerID:    "container-id",
					Signal:         "SIGUSR1",
					OnlySendSignal: true,
				})
			} else if tc.name == "Force kill also fails" {
				result, err = stopper.Stop(ctx, StopOptions{
					ContainerID: "container-id",
					Timeout:     10,
					Force:       true,
				})
			} else {
				result, err = stopper.Stop(ctx, StopOptions{
					ContainerID: "container-id",
					Timeout:     10,
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

func TestStopMultiple(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	stopper := NewStopper(manager)
	ctx := context.Background()

	// Setup for two containers

	// First container
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

	stopTimeout := 10
	mockClient.On("ContainerStop", ctx, "container-1", mock.MatchedBy(func(options container.StopOptions) bool {
		return *options.Timeout == int(stopTimeout)
	})).Return(nil).Once()

	mockClient.On("ContainerInspect", ctx, "container-1").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-1",
			Name: "/test-container-1",
			State: &types.ContainerState{
				Status:   "exited",
				Running:  false,
				ExitCode: 0,
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
				Status:  "running",
				Running: true,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	mockClient.On("ContainerStop", ctx, "container-2", mock.MatchedBy(func(options container.StopOptions) bool {
		return *options.Timeout == int(stopTimeout)
	})).Return(nil).Once()

	mockClient.On("ContainerInspect", ctx, "container-2").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-2",
			Name: "/test-container-2",
			State: &types.ContainerState{
				Status:   "exited",
				Running:  false,
				ExitCode: 0,
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Execute stop multiple
	results, err := stopper.StopMultiple(ctx, []string{"container-1", "container-2"}, StopOptions{
		Timeout: stopTimeout,
	})

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, results)
	assert.Len(t, results, 2)
	assert.Contains(t, results, "container-1")
	assert.Contains(t, results, "container-2")
	assert.True(t, results["container-1"].Success)
	assert.True(t, results["container-2"].Success)
	assert.True(t, results["container-1"].Stopped)
	assert.True(t, results["container-2"].Stopped)

	mockClient.AssertExpectations(t)
}

func TestForceKill(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	stopper := NewStopper(manager)
	ctx := context.Background()

	// First inspect (before killing)
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

	// Kill the container
	mockClient.On("ContainerKill", ctx, "container-id", "SIGKILL").Return(nil).Once()

	// Second inspect (after killing)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:   "exited",
				Running:  false,
				ExitCode: 137, // SIGKILL exit code
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Execute force kill
	result, err := stopper.ForceKill(ctx, "container-id", "")

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, result.Stopped)
	assert.True(t, result.WasKilled)
	assert.Equal(t, 137, result.ExitCode)

	mockClient.AssertExpectations(t)
}

func TestForceKillWithCustomSignal(t *testing.T) {
	// Create mocks
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewContainerManager(mockClient)
	stopper := NewStopper(manager)
	ctx := context.Background()

	// First inspect (before killing)
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

	// Kill the container with custom signal
	mockClient.On("ContainerKill", ctx, "container-id", "SIGTERM").Return(nil).Once()

	// Second inspect (after killing)
	mockClient.On("ContainerInspect", ctx, "container-id").Return(types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "container-id",
			Name: "/test-container",
			State: &types.ContainerState{
				Status:   "exited",
				Running:  false,
				ExitCode: 143, // SIGTERM exit code
			},
		},
		Config: &container.Config{},
	}, nil).Once()

	// Execute force kill with custom signal
	result, err := stopper.ForceKill(ctx, "container-id", "SIGTERM")

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, result.Stopped)
	assert.True(t, result.WasKilled)
	assert.Equal(t, 143, result.ExitCode)

	mockClient.AssertExpectations(t)
}

// Removed TestToModelStop as the ToModel function does not exist on Stopper
// or returns an incompatible type (ContainerOperation) for the assertions.
