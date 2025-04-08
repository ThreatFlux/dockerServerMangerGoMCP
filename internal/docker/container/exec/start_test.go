package exec

import (
	"bufio" // Added import
	"bytes"
	"context"
	"errors"
	"io"
	"net" // Added import
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	container "github.com/docker/docker/api/types/container" // Added import
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockReadCloser implements io.ReadCloser for testing
type MockReadCloser struct {
	Reader io.Reader
	mock.Mock
}

func (m *MockReadCloser) Read(p []byte) (int, error) {
	return m.Reader.Read(p)
}

func (m *MockReadCloser) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockHijackedResponse simulates the Docker hijacked response
type MockHijackedResponse struct {
	Reader      io.ReadCloser
	CloseWriter func() error
	Conn        *MockConn
	mock.Mock
}

func (m *MockHijackedResponse) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockConn simulates the Docker connection
type MockConn struct {
	WriteBuffer *bytes.Buffer
	mock.Mock
}

func (m *MockConn) Write(p []byte) (int, error) {
	if m.WriteBuffer == nil {
		m.WriteBuffer = &bytes.Buffer{}
	}
	return m.WriteBuffer.Write(p)
}

func (m *MockConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Add missing net.Conn methods
func (m *MockConn) LocalAddr() net.Addr {
	return nil // Mock implementation
}

func (m *MockConn) RemoteAddr() net.Addr {
	return nil // Mock implementation
}

func (m *MockConn) SetDeadline(t time.Time) error {
	return nil // Mock implementation
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	return nil // Mock implementation
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	return nil // Mock implementation
}

func (m *MockConn) Read(p []byte) (n int, err error) {
	// Mock implementation: return 0 bytes read and no error
	return 0, nil
}

// MockDockerClient definition moved to mock_client_test.go
// Removed duplicate ContainerExecStart method
/*
func (m *MockDockerClient) ContainerExecStart(ctx context.Context, execID string, config types.ExecStartCheck) error {
	args := m.Called(ctx, execID, config)
	return args.Error(0)
}
*/

// Add ContainerExecAttach to the mock client (already defined in create_test.go, included for reference)
// func (m *MockDockerClient) ContainerExecAttach(ctx context.Context, execID string, config types.ExecStartCheck) (types.HijackedResponse, error) {
// 	args := m.Called(ctx, execID, config)
// 	return args.Get(0).(types.HijackedResponse), args.Error(1)
// }

func TestStart(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Mock exec inspect
	execInspect := container.ExecInspect{ // Changed types. to container.
		ExecID:      "test-exec-id",
		ContainerID: "test-container",
		Running:     false,
		ExitCode:    0,
		// Config: &types.ExecConfig{ // Removed - Field does not exist on container.ExecInspect
		// 	AttachStdout: true,
		// 	AttachStderr: true,
		// 	Tty:          false,
		// },
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "test-exec-id").Return(execInspect, nil).Once()

	// Mock exec attach
	mockReadCloser := &MockReadCloser{Reader: strings.NewReader("test output")}
	mockReadCloser.On("Close").Return(nil)

	mockConn := &MockConn{}
	mockConn.On("Close").Return(nil)

	mockResponse := types.HijackedResponse{
		Reader: bufio.NewReader(mockReadCloser), // Wrapped mockReadCloser
		Conn:   mockConn,
	}
	mockClient.On("ContainerExecAttach", mock.Anything, "test-exec-id", mock.Anything).Return(mockResponse, nil).Once()

	// Mock exec start
	mockClient.On("ContainerExecStart", mock.Anything, "test-exec-id", mock.Anything).Return(nil).Once()

	// Set up options
	options := StartOptions{
		Timeout: 10 * time.Second,
		Logger:  logrus.New(),
	}

	// Test Start
	reader, err := Start(context.Background(), mockClient, "test-exec-id", options)

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, reader)
	mockClient.AssertExpectations(t)
}

func TestStart_DetachedMode(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Mock exec inspect with no stdio attachment
	execInspect := container.ExecInspect{ // Changed types. to container.
		ExecID:      "test-exec-id",
		ContainerID: "test-container",
		Running:     false,
		ExitCode:    0,
		// Config: &types.ExecConfig{ // Removed - Field does not exist on container.ExecInspect
		// 	AttachStdout: false,
		// 	AttachStderr: false,
		// 	Tty:          false,
		// },
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "test-exec-id").Return(execInspect, nil).Once()

	// Mock exec start
	mockClient.On("ContainerExecStart", mock.Anything, "test-exec-id", mock.Anything).Return(nil).Once()

	// Set up options
	options := StartOptions{
		Logger: logrus.New(),
	}

	// Test Start
	reader, err := Start(context.Background(), mockClient, "test-exec-id", options)

	// Verify
	assert.NoError(t, err)
	assert.Nil(t, reader) // No reader for detached mode
	mockClient.AssertExpectations(t)
}

func TestStart_ErrorCases(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Test case: Empty exec ID
	_, err := Start(context.Background(), mockClient, "", StartOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty exec ID")

	// Test case: Exec not found
	mockClient.On("ContainerExecInspect", mock.Anything, "not-found").Return(container.ExecInspect{}, errors.New("container not found")).Once() // Changed types. to container.
	mockClient.On("IsErrNotFound", mock.Anything).Return(true).Once()

	_, err = Start(context.Background(), mockClient, "not-found", StartOptions{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExecNotFound)

	// Test case: Exec attach fails
	execInspect := container.ExecInspect{ // Changed types. to container.
		ExecID:      "attach-fail",
		ContainerID: "test-container",
		Running:     false,
		// Config: &types.ExecConfig{ // Removed - Field does not exist on container.ExecInspect
		// 	AttachStdout: true,
		// 	AttachStderr: true,
		// },
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "attach-fail").Return(execInspect, nil).Once()
	mockClient.On("ContainerExecAttach", mock.Anything, "attach-fail", mock.Anything).Return(types.HijackedResponse{}, errors.New("attach failed")).Once()

	_, err = Start(context.Background(), mockClient, "attach-fail", StartOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to attach to exec instance")

	// Test case: Exec start fails
	execInspect2 := container.ExecInspect{ // Changed types. to container.
		ExecID:      "start-fail",
		ContainerID: "test-container",
		Running:     false,
		// Config: &types.ExecConfig{ // Removed - Field does not exist on container.ExecInspect
		// 	AttachStdout: false,
		// 	AttachStderr: false,
		// },
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "start-fail").Return(execInspect2, nil).Once()
	mockClient.On("ContainerExecStart", mock.Anything, "start-fail", mock.Anything).Return(errors.New("start failed")).Once()

	_, err = Start(context.Background(), mockClient, "start-fail", StartOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start exec instance")
}

func TestStartAndWait(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Mock exec inspect
	execInspect := container.ExecInspect{ // Changed types. to container.
		ExecID:      "test-exec-id",
		ContainerID: "test-container",
		Running:     false,
		ExitCode:    0,
		// Config: &types.ExecConfig{ // Removed - Field does not exist on container.ExecInspect
		// 	AttachStdout: true,
		// 	AttachStderr: true,
		// 	Tty:          false,
		// },
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "test-exec-id").Return(execInspect, nil).Times(2)

	// Mock exec attach with simulated stdout/stderr output
	// Note: This is a simplification of the actual demux format
	stdoutData := []byte{1, 0, 0, 0, 1, 10, 0, 0, 'H', 'e', 'l', 'l', 'o'}
	stderrData := []byte{1, 0, 0, 0, 2, 5, 0, 0, 'E', 'r', 'r', 'o', 'r'}
	mockData := append(stdoutData, stderrData...)

	mockReadCloser := &MockReadCloser{Reader: bytes.NewReader(mockData)}
	mockReadCloser.On("Close").Return(nil)

	mockConn := &MockConn{}
	mockConn.On("Close").Return(nil)

	mockResponse := types.HijackedResponse{
		Reader: bufio.NewReader(mockReadCloser), // Wrapped mockReadCloser
		Conn:   mockConn,
	}
	mockClient.On("ContainerExecAttach", mock.Anything, "test-exec-id", mock.Anything).Return(mockResponse, nil).Once()

	// Mock exec start
	mockClient.On("ContainerExecStart", mock.Anything, "test-exec-id", mock.Anything).Return(nil).Once()

	// Set up options
	options := StartOptions{
		Timeout: 10 * time.Second,
		Logger:  logrus.New(),
	}

	// Test StartAndWait
	exitCode, _, _, err := StartAndWait(context.Background(), mockClient, "test-exec-id", options) // Ignore stdout and stderr

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	// We can't fully test stdcopy's demuxing in unit tests, but we can verify it was called
	mockClient.AssertExpectations(t)
}

func TestStartWithStdCopy(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Mock exec inspect
	execInspect := container.ExecInspect{ // Changed types. to container.
		ExecID:      "test-exec-id",
		ContainerID: "test-container",
		Running:     false,
		ExitCode:    0,
		// Config: &types.ExecConfig{ // Removed - Field does not exist on container.ExecInspect
		// 	AttachStdout: true,
		// 	AttachStderr: true,
		// 	Tty:          false,
		// },
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "test-exec-id").Return(execInspect, nil).Once()

	// Mock exec attach with simulated output
	mockReadCloser := &MockReadCloser{Reader: strings.NewReader("test output")}
	mockReadCloser.On("Close").Return(nil)

	mockConn := &MockConn{}
	mockConn.On("Close").Return(nil)

	mockResponse := types.HijackedResponse{
		Reader: bufio.NewReader(mockReadCloser), // Wrapped mockReadCloser
		Conn:   mockConn,
	}
	mockClient.On("ContainerExecAttach", mock.Anything, "test-exec-id", mock.Anything).Return(mockResponse, nil).Once()

	// Mock exec start
	mockClient.On("ContainerExecStart", mock.Anything, "test-exec-id", mock.Anything).Return(nil).Once()

	// Set up options
	options := StartOptions{
		Timeout:   10 * time.Second,
		Logger:    logrus.New(),
		RawOutput: true, // Use raw output to simplify test
	}

	// Create a test output writer
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	outputWriter := &StdWriter{
		stdout: stdoutBuf,
		stderr: stderrBuf,
	}

	// Test StartWithStdCopy
	err := StartWithStdCopy(context.Background(), mockClient, "test-exec-id", options, outputWriter)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, "test output", stdoutBuf.String())
	mockClient.AssertExpectations(t)
}

func TestStdWriter(t *testing.T) {
	// Create a StdWriter
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	writer := &StdWriter{
		stdout: stdoutBuf,
		stderr: stderrBuf,
	}

	// Test Write
	n, err := writer.Write([]byte("stdout data"))
	assert.NoError(t, err)
	assert.Equal(t, 11, n)
	assert.Equal(t, "stdout data", stdoutBuf.String())

	// Test WriteErr
	n, err = writer.WriteErr([]byte("stderr data"))
	assert.NoError(t, err)
	assert.Equal(t, 11, n)
	assert.Equal(t, "stderr data", stderrBuf.String())

	// Test Close
	err = writer.Close()
	assert.NoError(t, err)
}

func TestWaitForExit(t *testing.T) {
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

	// Test waitForExit
	exitCode, err := waitForExit(context.Background(), mockClient, "test-exec-id", 5*time.Second)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, 42, exitCode)
	mockClient.AssertExpectations(t)
}

func TestWaitForExit_Timeout(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Mock exec inspect that never completes
	runningExecInspect := container.ExecInspect{ // Changed types. to container.
		ExecID:      "test-exec-id",
		ContainerID: "test-container",
		Running:     true,
		ExitCode:    0,
	}

	// Set up a mock that always returns "running"
	mockClient.On("ContainerExecInspect", mock.Anything, "test-exec-id").Return(runningExecInspect, nil)

	// Test waitForExit with a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	exitCode, err := waitForExit(ctx, mockClient, "test-exec-id", 0)

	// Verify
	assert.Error(t, err)
	assert.Equal(t, context.DeadlineExceeded, err)
	assert.Equal(t, -1, exitCode)
}

func TestCustomStdCopy(t *testing.T) {
	// Create a test OutputWriter
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	outputWriter := &StdWriter{
		stdout: stdoutBuf,
		stderr: stderrBuf,
	}

	// Create a simplistic mock of the Docker demuxed output format
	// Format is: [HEADER (8 bytes)][PAYLOAD]
	// In the header, byte 4 indicates stream type (1=stdout, 2=stderr)
	// and bytes 5-7 indicate payload length

	// Mock stdin data (type 0, should be ignored)
	stdinHeader := []byte{0, 0, 0, 0, 0, 5, 0, 0}
	stdinData := []byte("stdin")

	// Mock stdout data
	stdoutHeader := []byte{0, 0, 0, 0, 1, 6, 0, 0}
	stdoutData := []byte("stdout")

	// Mock stderr data
	stderrHeader := []byte{0, 0, 0, 0, 2, 6, 0, 0}
	stderrData := []byte("stderr")

	// Combine all data
	mockData := append(stdinHeader, stdinData...)
	mockData = append(mockData, stdoutHeader...)
	mockData = append(mockData, stdoutData...)
	mockData = append(mockData, stderrHeader...)
	mockData = append(mockData, stderrData...)

	// Test customStdCopy
	n, err := customStdCopy(outputWriter, bytes.NewReader(mockData))

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, int64(len(mockData)), n)
	assert.Equal(t, "stdout", stdoutBuf.String())
	assert.Equal(t, "stderr", stderrBuf.String())
}
