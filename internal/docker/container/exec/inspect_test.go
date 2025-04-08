package exec

import (
	"bufio" // Added import
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	container "github.com/docker/docker/api/types/container" // Added import
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestInspect(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Mock exec inspect
	execInspect := container.ExecInspect{ // Changed types. to container.
		ExecID:      "test-exec-id",
		ContainerID: "test-container",
		Running:     false,
		ExitCode:    0,
		Pid:         12345,
		// ProcessConfig: types.ExecProcessConfig{ // Removed - Field does not exist on container.ExecInspect
		// 	Entrypoint: "ls",
		// 	Arguments:  []string{"-la"},
		// 	User:       "root",
		// 	Privileged: false,
		// 	Tty:        false,
		// },
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "test-exec-id").Return(execInspect, nil).Once()

	// Set up options
	options := InspectOptions{
		Timeout: 10 * time.Second,
		Logger:  logrus.New(),
	}

	// Test Inspect
	execInfo, err := Inspect(context.Background(), mockClient, "test-exec-id", options)

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, execInfo)
	assert.Equal(t, "test-exec-id", execInfo.ID)
	assert.Equal(t, "test-container", execInfo.ContainerID)
	assert.Equal(t, []string{"ls", "-la"}, execInfo.Command)
	assert.Equal(t, "root", execInfo.User)
	assert.Equal(t, false, execInfo.Running)
	assert.Equal(t, 0, execInfo.ExitCode)
	assert.Equal(t, 12345, execInfo.Pid)
	assert.Equal(t, false, execInfo.Privileged)
	mockClient.AssertExpectations(t)

	// Test JSON method
	jsonData, err := execInfo.JSON()
	assert.NoError(t, err)
	assert.Contains(t, string(jsonData), "test-exec-id")

	// Test String method
	strRep := execInfo.String()
	assert.Contains(t, strRep, "test-exec-id")
	assert.Contains(t, strRep, "test-container")
	assert.Contains(t, strRep, "Exited with code 0")
}

func TestInspect_ErrorCases(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Test case: Empty exec ID
	_, err := Inspect(context.Background(), mockClient, "", InspectOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty exec ID")

	// Test case: Exec not found
	mockClient.On("ContainerExecInspect", mock.Anything, "not-found").Return(container.ExecInspect{}, errors.New("container not found")).Once() // Changed types. to container.
	mockClient.On("IsErrNotFound", mock.Anything).Return(true).Once()

	_, err = Inspect(context.Background(), mockClient, "not-found", InspectOptions{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExecNotFound)

	// Test case: Generic error
	mockClient.On("ContainerExecInspect", mock.Anything, "error-case").Return(container.ExecInspect{}, errors.New("some error")).Once() // Changed types. to container.
	mockClient.On("IsErrNotFound", mock.Anything).Return(false).Once()

	_, err = Inspect(context.Background(), mockClient, "error-case", InspectOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to inspect exec instance")
}

func TestInspectMultiple(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Mock exec inspect for first exec
	execInspect1 := container.ExecInspect{ // Changed types. to container.
		ExecID:      "exec-id-1",
		ContainerID: "test-container",
		Running:     false,
		ExitCode:    0,
		// ProcessConfig: types.ExecProcessConfig{ // Removed - Field does not exist on container.ExecInspect
		// 	Entrypoint: "ls",
		// 	Arguments:  []string{"-la"},
		// 	User:       "root",
		// },
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "exec-id-1").Return(execInspect1, nil).Once()

	// Mock exec inspect for second exec
	execInspect2 := container.ExecInspect{ // Changed types. to container.
		ExecID:      "exec-id-2",
		ContainerID: "test-container",
		Running:     true,
		ExitCode:    0,
		// ProcessConfig: types.ExecProcessConfig{ // Removed - Field does not exist on container.ExecInspect
		// 	Entrypoint: "top",
		// 	Arguments:  []string{},
		// 	User:       "user",
		// },
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "exec-id-2").Return(execInspect2, nil).Once()

	// Mock exec inspect for third exec (error case)
	mockClient.On("ContainerExecInspect", mock.Anything, "exec-id-3").Return(container.ExecInspect{}, errors.New("not found")).Once() // Changed types. to container.
	mockClient.On("IsErrNotFound", mock.Anything).Return(true).Once()

	// Set up options
	options := InspectOptions{
		Timeout: 10 * time.Second,
		Logger:  logrus.New(),
	}

	// Test InspectMultiple
	execInfos, err := InspectMultiple(context.Background(), mockClient, []string{"exec-id-1", "exec-id-2", "exec-id-3"}, options)

	// Verify
	assert.NoError(t, err) // Should not error if at least one exec is found
	assert.NotNil(t, execInfos)
	assert.Len(t, execInfos, 2)
	assert.Contains(t, execInfos, "exec-id-1")
	assert.Contains(t, execInfos, "exec-id-2")
	assert.NotContains(t, execInfos, "exec-id-3")
	assert.Equal(t, []string{"ls", "-la"}, execInfos["exec-id-1"].Command)
	assert.Equal(t, []string{"top"}, execInfos["exec-id-2"].Command)
	mockClient.AssertExpectations(t)

	// Test case: Empty exec IDs
	_, err = InspectMultiple(context.Background(), mockClient, []string{}, InspectOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no exec IDs provided")

	// Test case: All execs not found
	mockClient.On("ContainerExecInspect", mock.Anything, "not-found-1").Return(container.ExecInspect{}, errors.New("not found")).Once() // Changed types. to container.
	mockClient.On("IsErrNotFound", mock.Anything).Return(true).Once()

	_, err = InspectMultiple(context.Background(), mockClient, []string{"not-found-1"}, options)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExecNotFound)
}

// MockDockerClient definition moved to mock_client_test.go
// Removed duplicate ContainerExecStart method
/*
func (m *MockDockerClient) ContainerExecStart(ctx context.Context, execID string, config types.ExecStartCheck) error {
	args := m.Called(ctx, execID, config)
	return args.Error(0)
}
*/

// Define ContainerExecAttach if not already in the mock client
// func (m *MockDockerClient) ContainerExecAttach(ctx context.Context, execID string, config types.ExecStartCheck) (types.HijackedResponse, error) {
//    args := m.Called(ctx, execID, config)
//    return args.Get(0).(types.HijackedResponse), args.Error(1)
// }

func TestListExecs(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Mock container inspect
	containerJSON := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: "test-container",
			State: &types.ContainerState{
				Running: true,
			},
		},
	}
	mockClient.On("ContainerInspect", mock.Anything, "test-container").Return(containerJSON, nil).Once()

	// Mock exec create for listing processes
	execCreateResp := types.IDResponse{ID: "list-exec-id"}
	mockClient.On("ContainerExecCreate", mock.Anything, "test-container", mock.Anything).Return(execCreateResp, nil).Once()

	// Mock exec attach
	mockReader := strings.NewReader("test output of cgroup listing")
	mockReadCloser := &MockReadCloser{Reader: mockReader}
	mockReadCloser.On("Close").Return(nil)

	mockResponse := types.HijackedResponse{
		Reader: bufio.NewReader(mockReadCloser), // Wrapped mockReadCloser
		Conn:   &MockConn{},
	}
	mockClient.On("ContainerExecAttach", mock.Anything, "list-exec-id", mock.Anything).Return(mockResponse, nil).Once()

	// Mock exec start
	mockClient.On("ContainerExecStart", mock.Anything, "list-exec-id", mock.Anything).Return(nil).Once()

	// Mock exec inspect for the created exec instance
	execInspect := container.ExecInspect{ // Changed types. to container.
		ExecID:      "list-exec-id",
		ContainerID: "test-container",
		Running:     false,
		ExitCode:    0,
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "list-exec-id").Return(execInspect, nil).Once()

	// Set up options
	options := InspectOptions{
		Timeout: 10 * time.Second,
		Logger:  logrus.New(),
	}

	// Test ListExecs
	execs, err := ListExecs(context.Background(), mockClient, "test-container", options)

	// Verify - this is a best-effort function, so we're mainly checking it doesn't error
	assert.NoError(t, err)
	assert.NotNil(t, execs)
	assert.Len(t, execs, 1) // Should at least include the exec we created
	assert.Equal(t, "list-exec-id", execs[0].ID)
	mockClient.AssertExpectations(t)
}

func TestListExecs_ErrorCases(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Test case: Empty container ID
	_, err := ListExecs(context.Background(), mockClient, "", InspectOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty container ID")

	// Test case: Container not found
	mockClient.On("ContainerInspect", mock.Anything, "not-found").Return(types.ContainerJSON{}, errors.New("container not found")).Once()
	mockClient.On("IsErrNotFound", mock.Anything).Return(true).Once()

	_, err = ListExecs(context.Background(), mockClient, "not-found", InspectOptions{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrContainerNotFound)

	// Test case: Exec create fails
	mockClient.On("ContainerInspect", mock.Anything, "exec-create-fail").Return(types.ContainerJSON{}, nil).Once()
	mockClient.On("ContainerExecCreate", mock.Anything, "exec-create-fail", mock.Anything).Return(types.IDResponse{}, errors.New("create failed")).Once()

	_, err = ListExecs(context.Background(), mockClient, "exec-create-fail", InspectOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create exec for listing processes")
}

func TestWaitForExecToComplete(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Mock first check while running
	runningExecInspect := container.ExecInspect{ // Changed types. to container.
		ExecID:      "test-exec-id",
		ContainerID: "test-container",
		Running:     true,
		ExitCode:    0,
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "test-exec-id").Return(runningExecInspect, nil).Once()

	// Mock second check when completed
	completedExecInspect := container.ExecInspect{ // Changed types. to container.
		ExecID:      "test-exec-id",
		ContainerID: "test-container",
		Running:     false,
		ExitCode:    42,
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "test-exec-id").Return(completedExecInspect, nil).Once()

	// Test WaitForExecToComplete
	exitCode, err := WaitForExecToComplete(context.Background(), mockClient, "test-exec-id", 5*time.Second)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, 42, exitCode)
	mockClient.AssertExpectations(t)
}

func TestWaitForExecToComplete_ErrorCases(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Test case: Exec not found
	mockClient.On("ContainerExecInspect", mock.Anything, "not-found").Return(container.ExecInspect{}, errors.New("not found")).Once() // Changed types. to container.
	mockClient.On("IsErrNotFound", mock.Anything).Return(true).Once()

	_, err := WaitForExecToComplete(context.Background(), mockClient, "not-found", 5*time.Second)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExecNotFound)

	// Test case: Timeout
	mockClient.On("ContainerExecInspect", mock.Anything, "timeout").Return(container.ExecInspect{Running: true}, nil).Times(1) // Changed types. to container.

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = WaitForExecToComplete(ctx, mockClient, "timeout", 0)
	assert.Error(t, err)
	assert.Equal(t, context.DeadlineExceeded, err)
}

func TestGetRunningExecsCount(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Mock container inspect
	containerJSON := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: "test-container",
			State: &types.ContainerState{
				Running: true,
			},
		},
	}
	mockClient.On("ContainerInspect", mock.Anything, "test-container").Return(containerJSON, nil).Once()

	// Mock exec create for listing processes
	execCreateResp := types.IDResponse{ID: "list-exec-id"}
	mockClient.On("ContainerExecCreate", mock.Anything, "test-container", mock.Anything).Return(execCreateResp, nil).Once()

	// Mock exec attach
	mockReader := strings.NewReader("test output of cgroup listing")
	mockReadCloser := &MockReadCloser{Reader: mockReader}
	mockReadCloser.On("Close").Return(nil)

	mockResponse := types.HijackedResponse{
		Reader: bufio.NewReader(mockReadCloser), // Wrapped mockReadCloser
		Conn:   &MockConn{},
	}
	mockClient.On("ContainerExecAttach", mock.Anything, "list-exec-id", mock.Anything).Return(mockResponse, nil).Once()

	// Mock exec start
	mockClient.On("ContainerExecStart", mock.Anything, "list-exec-id", mock.Anything).Return(nil).Once()

	// Mock exec inspect
	// Return two exec instances, one running and one completed
	execInspect1 := container.ExecInspect{ // Changed types. to container.
		ExecID:      "list-exec-id",
		ContainerID: "test-container",
		Running:     true,
		ExitCode:    0,
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "list-exec-id").Return(execInspect1, nil).Once()

	// Set up options
	options := InspectOptions{
		Timeout: 10 * time.Second,
		Logger:  logrus.New(),
	}

	// Test GetRunningExecsCount
	count, err := GetRunningExecsCount(context.Background(), mockClient, "test-container", options)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	mockClient.AssertExpectations(t)
}

func TestExecInfo_JSON(t *testing.T) {
	// Create an ExecInfo
	execInfo := &Info{
		ID:          "test-exec-id",
		ContainerID: "test-container",
		Command:     []string{"ls", "-la"},
		User:        "root",
		Running:     false,
		ExitCode:    0,
		Pid:         12345,
		Privileged:  false,
		OpenStdin:   false,
		OpenStdout:  true,
		OpenStderr:  true,
		// ProcessConfig: types.ExecConfig{}, // Removed - Field does not exist on ExecInfo
	}

	// Test JSON marshaling
	jsonData, err := execInfo.JSON()

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, jsonData)
	assert.Contains(t, string(jsonData), "test-exec-id")
	assert.Contains(t, string(jsonData), "test-container")
	assert.Contains(t, string(jsonData), "ls")
	assert.Contains(t, string(jsonData), "root")
}

func TestExecInfo_String(t *testing.T) {
	// Test with a running exec
	runningExec := &Info{
		ID:          "running-exec-id",
		ContainerID: "test-container",
		Command:     []string{"top"},
		Running:     true,
	}

	runningStr := runningExec.String()
	assert.Contains(t, runningStr, "running-exec-id")
	assert.Contains(t, runningStr, "test-container")
	assert.Contains(t, runningStr, "Running")

	// Test with a completed exec
	completedExec := &Info{
		ID:          "completed-exec-id",
		ContainerID: "test-container",
		Command:     []string{"echo", "hello"},
		Running:     false,
		ExitCode:    0,
	}

	completedStr := completedExec.String()
	assert.Contains(t, completedStr, "completed-exec-id")
	assert.Contains(t, completedStr, "test-container")
	assert.Contains(t, completedStr, "Exited with code 0")

	// Test with a failed exec
	failedExec := &Info{
		ID:          "failed-exec-id",
		ContainerID: "test-container",
		Command:     []string{"non-existent-command"},
		Running:     false,
		ExitCode:    127,
	}

	failedStr := failedExec.String()
	assert.Contains(t, failedStr, "failed-exec-id")
	assert.Contains(t, failedStr, "test-container")
	assert.Contains(t, failedStr, "Exited with code 127")
}
