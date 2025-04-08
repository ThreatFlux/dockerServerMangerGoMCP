package file

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	types "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container" // Added import
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCopyToContainer_ValidInput(t *testing.T) {
	// Create test directory and file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	// Create test file
	content := []byte("test content")
	err := os.WriteFile(testFile, content, 0644)
	require.NoError(t, err)

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
	mockClient.On("ContainerInspect", mock.Anything, "test-container").Return(containerJSON, nil)

	// Mock copy to container
	mockClient.On("CopyToContainer", mock.Anything, "test-container", "/dest", mock.Anything, mock.Anything).Return(nil)

	// Set up options
	options := CopyToOptions{
		Timeout: 10 * time.Second,
		Logger:  logrus.New(),
	}

	// Test CopyToContainer
	err = CopyToContainer(context.Background(), mockClient, "test-container", testFile, "/dest", options)

	// Verify
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestCopyToContainer_ContainerNotRunning(t *testing.T) {
	// Create test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	err := os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Mock container inspect with non-running container
	containerJSON := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: "test-container",
			State: &types.ContainerState{
				Running: false,
			},
		},
	}
	mockClient.On("ContainerInspect", mock.Anything, "test-container").Return(containerJSON, nil)

	// Set up options
	options := CopyToOptions{
		Logger: logrus.New(),
	}

	// Test CopyToContainer
	err = CopyToContainer(context.Background(), mockClient, "test-container", testFile, "/dest", options)

	// Verify
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrContainerNotRunning)
	mockClient.AssertExpectations(t)
}

func TestCopyToContainer_FileNotFound(t *testing.T) {
	// Use a non-existent file
	testFile := "/non/existent/file.txt"

	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Mock ContainerInspect because the function checks the container first,
	// even though the test expects a local file not found error.
	// We don't care about the return value here as the function should error out before using it.
	mockClient.On("ContainerInspect", mock.Anything, "test-container").Return(types.ContainerJSON{}, nil).Maybe()

	// Set up options
	options := CopyToOptions{
		Logger: logrus.New(),
	}

	// Test CopyToContainer
	err := CopyToContainer(context.Background(), mockClient, "test-container", testFile, "/dest", options)

	// Verify
	assert.Error(t, err)
	assert.True(t, os.IsNotExist(err) || (err != nil && err.Error() == "file not found: /non/existent/file.txt"))
}

func TestCopyContentToContainer(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Create test content
	content := bytes.NewBufferString("test content")

	// Mock container inspect
	containerJSON := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: "test-container",
			State: &types.ContainerState{
				Running: true,
			},
		},
	}
	mockClient.On("ContainerInspect", mock.Anything, "test-container").Return(containerJSON, nil)

	// Mock exec create for directory creation
	execID := types.IDResponse{ID: "exec-id"}
	mockClient.On("ContainerExecCreate", mock.Anything, "test-container", mock.MatchedBy(func(config container.ExecOptions) bool { // Use container.ExecOptions
		return config.Cmd[0] == "mkdir" && config.Cmd[1] == "-p" && config.Cmd[2] == "/dest"
	})).Return(execID, nil)

	// Mock exec start
	mockClient.On("ContainerExecStart", mock.Anything, "exec-id", mock.AnythingOfType("types.ExecStartCheck")).Return(nil)

	// Mock exec inspect
	execInspect := container.ExecInspect{ // Use container.ExecInspect
		ExitCode: 0,
		Running:  false,
	}
	mockClient.On("ContainerExecInspect", mock.Anything, "exec-id").Return(execInspect, nil)

	// Mock copy to container
	mockClient.On("CopyToContainer", mock.Anything, "test-container", "/dest", mock.Anything, mock.Anything).Return(nil)

	// Set up options
	options := CopyToOptions{
		Logger: logrus.New(),
	}

	// Test CopyContentToContainer
	err := CopyContentToContainer(context.Background(), mockClient, "test-container", content, "/dest/file.txt", 0644, options)

	// Verify
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSanitizePath(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"/path/to/file", "/path/to/file"},
		{"path/to/file", "/path/to/file"},
		{"/path/../to/file", "/to/file"}, // filepath.Clean resolves '..'
		{"//path/to/file", "/path/to/file"},
		{"/path/./to/file", "/path/to/file"},
	}

	for _, tc := range testCases {
		result := sanitizePath(tc.input)
		assert.Equal(t, tc.expected, result)
	}
}

func TestProgressReader(t *testing.T) {
	// Create a test reader with known content
	content := bytes.Repeat([]byte("a"), 1000)
	reader := bytes.NewReader(content)

	// Track progress
	var progress float64
	var bytesRead int64
	var totalBytes int64
	var callCount int

	progressCallback := func(p float64, br int64, tb int64) {
		progress = p
		bytesRead = br
		totalBytes = tb
		callCount++
	}

	// Create progress reader
	pr := &progressReader{
		reader:           reader,
		totalBytes:       1000,
		bytesRead:        0,
		progressCallback: progressCallback,
		lastReportTime:   time.Time{}, // Zero time to ensure callback is always called
	}

	// Read all data
	buf := make([]byte, 100)
	totalRead := 0
	for {
		n, err := pr.Read(buf)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		totalRead += n
	}

	// Verify
	assert.Equal(t, 1000, totalRead)
	assert.Equal(t, float64(1.0), progress)
	assert.Equal(t, int64(1000), bytesRead)
	assert.Equal(t, int64(1000), totalBytes)
	assert.Greater(t, callCount, 0)
}

func TestGetDirSize(t *testing.T) {
	// Create test directory structure
	tempDir := t.TempDir()
	testFile1 := filepath.Join(tempDir, "file1.txt")
	testFile2 := filepath.Join(tempDir, "file2.txt")
	subDir := filepath.Join(tempDir, "subdir")
	testFile3 := filepath.Join(subDir, "file3.txt")

	// Create files
	require.NoError(t, os.WriteFile(testFile1, bytes.Repeat([]byte("a"), 100), 0644))
	require.NoError(t, os.WriteFile(testFile2, bytes.Repeat([]byte("b"), 200), 0644))
	require.NoError(t, os.MkdirAll(subDir, 0755))
	require.NoError(t, os.WriteFile(testFile3, bytes.Repeat([]byte("c"), 300), 0644))

	// Calculate directory size
	size, err := getDirSize(tempDir)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, int64(600), size) // 100 + 200 + 300 bytes
}
