package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	dockermocks "github.com/threatflux/dockerServerMangerGoMCP/internal/docker" // Import for mock
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/image"
)

// TestBuildManager_Build tests the Build method
func TestBuildManager_Build(t *testing.T) {
	// Create mock client
	mockClient := new(dockermocks.MockDockerClient)

	// Test case 1: Successful build with reader context
	t.Run("SuccessfulBuildWithReaderContext", func(t *testing.T) {
		// Create a mock build response
		buildResponseBody := io.NopCloser(strings.NewReader(`{"stream":"Build successful"}`))
		buildResponse := types.ImageBuildResponse{
			Body: buildResponseBody,
		}

		// Setup expectations
		mockClient.On("ImageBuild", mock.Anything, mock.Anything, mock.Anything).
			Return(buildResponse, nil).Once()

		// Create build manager
		manager := NewBuildManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.Build(context.Background(), image.BuildOptions{
			Context:    strings.NewReader("mock context"),
			Tags:       []string{"test:latest"},
			Dockerfile: "Dockerfile",
		})

		// Verify results
		assert.NoError(t, err)
		assert.NotNil(t, result)
		mockClient.AssertExpectations(t)
	})

	// Test case 2: Build with invalid options (no context)
	t.Run("BuildWithInvalidOptions", func(t *testing.T) {
		// Create build manager
		manager := NewBuildManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.Build(context.Background(), image.BuildOptions{
			Tags:       []string{"test:latest"},
			Dockerfile: "Dockerfile",
			// No context or context directory
		})

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidBuildOptions))
		assert.Nil(t, result)
	})

	// Test case 3: Build with invalid options (no tags)
	t.Run("BuildWithNoTags", func(t *testing.T) {
		// Create build manager
		manager := NewBuildManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.Build(context.Background(), image.BuildOptions{
			Context:    strings.NewReader("mock context"),
			Dockerfile: "Dockerfile",
			// No tags
		})

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidBuildOptions))
		assert.Nil(t, result)
	})

	// Test case 4: Build with error
	t.Run("BuildWithError", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageBuild", mock.Anything, mock.Anything, mock.Anything).
			Return(types.ImageBuildResponse{}, errors.New("build error")).Once()

		// Create build manager
		manager := NewBuildManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.Build(context.Background(), image.BuildOptions{
			Context:    strings.NewReader("mock context"),
			Tags:       []string{"test:latest"},
			Dockerfile: "Dockerfile",
		})

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrImageBuild))
		assert.Nil(t, result)
		mockClient.AssertExpectations(t)
	})

	// Test case 5: Build with context timeout
	t.Run("BuildWithContextTimeout", func(t *testing.T) {
		// Create a context that's already timed out
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(1 * time.Millisecond) // Ensure timeout occurs

		// Setup expectations
		mockClient.On("ImageBuild", mock.Anything, mock.Anything, mock.Anything).
			Return(types.ImageBuildResponse{}, context.DeadlineExceeded).Once()

		// Create build manager
		manager := NewBuildManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.Build(ctx, image.BuildOptions{
			Context:    strings.NewReader("mock context"),
			Tags:       []string{"test:latest"},
			Dockerfile: "Dockerfile",
		})

		// Verify results
		assert.Error(t, err)
		if err != nil && !errors.Is(err, ErrBuildTimeout) {
			assert.True(t, strings.Contains(err.Error(), "timeout") ||
				strings.Contains(err.Error(), "deadline") ||
				errors.Is(err, ErrBuildTimeout),
				"Expected timeout error, got: %v", err)
		}
		assert.Nil(t, result)
	})

	// Test case 6: Build with progress output
	t.Run("BuildWithProgressOutput", func(t *testing.T) {
		// Create a mock build response with multiple messages
		messages := []jsonmessage.JSONMessage{
			{Stream: "Step 1: FROM ubuntu:latest"},
			{Stream: "Step 2: RUN echo hello"},
			{Stream: "Successfully built abcdef123456"},
		}

		// Create a buffer for the response
		var responseBuffer bytes.Buffer
		encoder := json.NewEncoder(&responseBuffer)
		for _, msg := range messages {
			require.NoError(t, encoder.Encode(msg))
		}

		buildResponseBody := io.NopCloser(&responseBuffer)
		buildResponse := types.ImageBuildResponse{
			Body: buildResponseBody,
		}

		// Setup expectations
		mockClient.On("ImageBuild", mock.Anything, mock.Anything, mock.Anything).
			Return(buildResponse, nil).Once()

		// Create build manager
		manager := NewBuildManager(mockClient, logrus.New())

		// Create a buffer for progress output
		var progressBuffer bytes.Buffer

		// Call method under test
		result, err := manager.Build(context.Background(), image.BuildOptions{
			Context:        strings.NewReader("mock context"),
			Tags:           []string{"test:latest"},
			Dockerfile:     "Dockerfile",
			ProgressOutput: &progressBuffer,
		})

		// Verify results
		assert.NoError(t, err)
		assert.NotNil(t, result)
		mockClient.AssertExpectations(t)

		// Read all from result for test to complete properly
		_, _ = io.Copy(io.Discard, result)
	})
}

// TestBuildManager_BuildAndWait tests the BuildAndWait method
func TestBuildManager_BuildAndWait(t *testing.T) {
	// Create mock client
	mockClient := new(dockermocks.MockDockerClient)

	// Test case: Successful build and wait
	t.Run("SuccessfulBuildAndWait", func(t *testing.T) {
		// Create a mock build response with multiple messages
		messages := []jsonmessage.JSONMessage{
			{Stream: "Step 1: FROM ubuntu:latest"},
			{Stream: "Step 2: RUN echo hello"},
			{Stream: "WARNING: Some warning message"},
			// Add aux message with image ID
			{
				Aux: func() *json.RawMessage {
					raw := json.RawMessage(`{"ID":"sha256:abcdef123456"}`)
					return &raw
				}(),
			},
			{Stream: "Successfully built abcdef123456"},
		}

		// Create a buffer for the response
		var responseBuffer bytes.Buffer
		encoder := json.NewEncoder(&responseBuffer)
		for _, msg := range messages {
			require.NoError(t, encoder.Encode(msg))
		}

		buildResponseBody := io.NopCloser(&responseBuffer)
		buildResponse := types.ImageBuildResponse{
			Body: buildResponseBody,
		}

		// Setup expectations
		mockClient.On("ImageBuild", mock.Anything, mock.Anything, mock.Anything).
			Return(buildResponse, nil).Once()

		// Create build manager
		manager := NewBuildManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.BuildAndWait(context.Background(), image.BuildOptions{
			Context:    strings.NewReader("mock context"),
			Tags:       []string{"test:latest"},
			Dockerfile: "Dockerfile",
		})

		// Verify results
		assert.NoError(t, err)
		assert.Equal(t, "sha256:abcdef123456", result.ImageID)
		assert.Len(t, result.Warnings, 1)
		assert.Contains(t, result.Warnings[0], "WARNING")
		assert.Nil(t, result.Error)
		mockClient.AssertExpectations(t)
	})

	// Test case: Build and wait with error
	t.Run("BuildAndWaitWithError", func(t *testing.T) {
		// Create a mock build response with error
		messages := []jsonmessage.JSONMessage{
			{Stream: "Step 1: FROM ubuntu:latest"},
			{Error: &jsonmessage.JSONError{Message: "build error"}},
		}

		// Create a buffer for the response
		var responseBuffer bytes.Buffer
		encoder := json.NewEncoder(&responseBuffer)
		for _, msg := range messages {
			require.NoError(t, encoder.Encode(msg))
		}

		buildResponseBody := io.NopCloser(&responseBuffer)
		buildResponse := types.ImageBuildResponse{
			Body: buildResponseBody,
		}

		// Setup expectations
		mockClient.On("ImageBuild", mock.Anything, mock.Anything, mock.Anything).
			Return(buildResponse, nil).Once()

		// Create build manager
		manager := NewBuildManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.BuildAndWait(context.Background(), image.BuildOptions{
			Context:    strings.NewReader("mock context"),
			Tags:       []string{"test:latest"},
			Dockerfile: "Dockerfile",
		})

		// Verify results
		assert.Error(t, err)
		assert.Equal(t, "build error", err.Error())
		assert.NotNil(t, result.Error)
		mockClient.AssertExpectations(t)
	})
}

// TestBuildManager_prepareBuildContext tests the prepareBuildContext method
func TestBuildManager_prepareBuildContext(t *testing.T) {
	// Create temporary context directory
	tempDir, err := os.MkdirTemp("", "build-context-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a Dockerfile in the temp directory
	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	err = os.WriteFile(dockerfilePath, []byte("FROM ubuntu:latest"), 0644)
	require.NoError(t, err)

	// Create mock client and build manager
	mockClient := new(dockermocks.MockDockerClient)
	manager := NewBuildManager(mockClient, logrus.New())

	// Test case 1: Context from reader
	t.Run("ContextFromReader", func(t *testing.T) {
		// Create options with reader context
		options := image.BuildOptions{
			Context:    strings.NewReader("mock context"),
			Tags:       []string{"test:latest"},
			Dockerfile: "Dockerfile",
		}

		// Call method under test
		ctx, err := manager.prepareBuildContext(options)

		// Verify results
		assert.NoError(t, err)
		assert.NotNil(t, ctx)

		// Verify that the context contains the expected content
		content, err := io.ReadAll(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "mock context", string(content))
	})

	// Test case 2: Context from directory
	t.Run("ContextFromDirectory", func(t *testing.T) {
		// Create options with context directory
		options := image.BuildOptions{
			ContextDir: tempDir,
			Tags:       []string{"test:latest"},
			Dockerfile: "Dockerfile",
		}

		// Call method under test
		ctx, err := manager.prepareBuildContext(options)

		// Verify results
		assert.NoError(t, err)
		assert.NotNil(t, ctx)

		// We can't easily verify the content of the tar archive, but we can
		// verify that it's not empty
		content, err := io.ReadAll(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, content)
	})

	// Test case 3: Context from non-existent directory
	t.Run("ContextFromNonExistentDirectory", func(t *testing.T) {
		// Create options with non-existent context directory
		options := image.BuildOptions{
			ContextDir: filepath.Join(tempDir, "nonexistent"),
			Tags:       []string{"test:latest"},
			Dockerfile: "Dockerfile",
		}

		// Call method under test
		ctx, err := manager.prepareBuildContext(options)

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBuildContextNotFound))
		assert.Nil(t, ctx)
	})

	// Test case 4: Custom Dockerfile not found in directory
	t.Run("DockerfileNotFoundInDirectory", func(t *testing.T) {
		// Create options with non-existent Dockerfile
		options := image.BuildOptions{
			ContextDir: tempDir,
			Tags:       []string{"test:latest"},
			Dockerfile: "Dockerfile.custom",
		}

		// Call method under test
		ctx, err := manager.prepareBuildContext(options)

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrDockerfileNotFound))
		assert.Nil(t, ctx)
	})

	// Test case 5: No context provided
	t.Run("NoContextProvided", func(t *testing.T) {
		// Create options with no context
		options := image.BuildOptions{
			Tags:       []string{"test:latest"},
			Dockerfile: "Dockerfile",
		}

		// Call method under test
		ctx, err := manager.prepareBuildContext(options)

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidBuildOptions))
		assert.Nil(t, ctx)
	})
}

// TestBuildManager_SetBuildTimeout tests the SetBuildTimeout method
func TestBuildManager_SetBuildTimeout(t *testing.T) {
	// Create build manager
	manager := NewBuildManager(nil, logrus.New())

	// Set build timeout
	originalTimeout := manager.buildTimeout
	manager.SetBuildTimeout(10 * time.Minute)
	assert.Equal(t, 10*time.Minute, manager.buildTimeout)
	assert.NotEqual(t, originalTimeout, manager.buildTimeout)

	// Set invalid timeout
	manager.SetBuildTimeout(0)
	assert.Equal(t, 10*time.Minute, manager.buildTimeout) // Shouldn't change
}
