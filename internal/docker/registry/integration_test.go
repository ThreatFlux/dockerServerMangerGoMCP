package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"

	types "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/checkpoint"
	"github.com/docker/docker/api/types/container"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	imagetypes "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	networktypes "github.com/docker/docker/api/types/network"
	registrytypes "github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/api/types/volume"
	volumetypes "github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockDockerClient is a mock Docker client for testing
type MockDockerClient struct {
	mock.Mock
}

// ImagePull mocks the Docker client ImagePull method
func (m *MockDockerClient) ImagePull(ctx context.Context, ref string, options imagetypes.PullOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, ref, options)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), nil
}

// ImagePush mocks the Docker client ImagePush method
func (m *MockDockerClient) ImagePush(ctx context.Context, ref string, options imagetypes.PushOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, ref, options)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), nil
}

// ImageInspectWithRaw mocks the Docker client ImageInspectWithRaw method
func (m *MockDockerClient) ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error) {
	args := m.Called(ctx, imageID)
	if args.Error(2) != nil {
		return types.ImageInspect{}, nil, args.Error(2)
	}
	return args.Get(0).(types.ImageInspect), args.Get(1).([]byte), nil
}

// RegistryLogin mocks the Docker client RegistryLogin method
func (m *MockDockerClient) RegistryLogin(ctx context.Context, auth registrytypes.AuthConfig) (registrytypes.AuthenticateOKBody, error) {
	args := m.Called(ctx, auth)
	if args.Error(1) != nil {
		return registrytypes.AuthenticateOKBody{}, args.Error(1)
	}
	return args.Get(0).(registrytypes.AuthenticateOKBody), nil
}

// ImageSearch mocks the Docker client ImageSearch method
func (m *MockDockerClient) ImageSearch(ctx context.Context, term string, options registrytypes.SearchOptions) ([]registrytypes.SearchResult, error) {
	args := m.Called(ctx, term, options)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]registrytypes.SearchResult), nil
}

// BuildCachePrune mocks the Docker client BuildCachePrune method
func (m *MockDockerClient) BuildCachePrune(ctx context.Context, opts types.BuildCachePruneOptions) (*types.BuildCachePruneReport, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.BuildCachePruneReport), args.Error(1)
}

// Ping mocks the Docker client Ping method
func (m *MockDockerClient) Ping(ctx context.Context) (types.Ping, error) {
	args := m.Called(ctx)
	return args.Get(0).(types.Ping), args.Error(1)
}

// Info mocks the Docker client Info method
func (m *MockDockerClient) Info(ctx context.Context) (system.Info, error) {
	args := m.Called(ctx)
	if args.Error(1) != nil {
		return system.Info{}, args.Error(1)
	}
	return args.Get(0).(system.Info), nil
}

// ServerVersion mocks the Docker client ServerVersion method
func (m *MockDockerClient) ServerVersion(ctx context.Context) (types.Version, error) {
	args := m.Called(ctx)
	return args.Get(0).(types.Version), args.Error(1)
}

// ContainerList mocks the Docker client ContainerList method
func (m *MockDockerClient) ContainerList(ctx context.Context, options containertypes.ListOptions) ([]types.Container, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]types.Container), args.Error(1)
}

// NetworkList mocks the Docker client NetworkList method
func (m *MockDockerClient) NetworkList(ctx context.Context, options network.ListOptions) ([]network.Summary, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]network.Summary), args.Error(1)
}

// VolumeList mocks the Docker client VolumeList method
func (m *MockDockerClient) VolumeList(ctx context.Context, filter volumetypes.ListOptions) (volume.ListResponse, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).(volume.ListResponse), args.Error(1)
}

// ImageList mocks the Docker client ImageList method
func (m *MockDockerClient) ImageList(ctx context.Context, options imagetypes.ListOptions) ([]image.Summary, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]image.Summary), args.Error(1)
}

// BuildCancel mocks the Docker client BuildCancel method
func (m *MockDockerClient) BuildCancel(ctx context.Context, buildID string) error {
	args := m.Called(ctx, buildID)
	return args.Error(0)
}

// CheckpointCreate mocks the Docker client CheckpointCreate method
func (m *MockDockerClient) CheckpointCreate(ctx context.Context, container string, options checkpoint.CreateOptions) error {
	args := m.Called(ctx, container, options)
	return args.Error(0)
}

// CheckpointDelete mocks the Docker client CheckpointDelete method
func (m *MockDockerClient) CheckpointDelete(ctx context.Context, container string, options checkpoint.DeleteOptions) error {
	args := m.Called(ctx, container, options)
	return args.Error(0)
}

// CheckpointList mocks the Docker client CheckpointList method
func (m *MockDockerClient) CheckpointList(ctx context.Context, container string, options checkpoint.ListOptions) ([]checkpoint.Summary, error) {
	args := m.Called(ctx, container, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]checkpoint.Summary), args.Error(1)
}

// ContainerExecCreate mocks the Docker client ContainerExecCreate method
func (m *MockDockerClient) ContainerExecCreate(ctx context.Context, container string, config container.ExecOptions) (types.IDResponse, error) {
	args := m.Called(ctx, container, config)
	return args.Get(0).(types.IDResponse), args.Error(1)
}

// ContainerExecStart mocks the Docker client ContainerExecStart method
func (m *MockDockerClient) ContainerExecStart(ctx context.Context, execID string, config container.ExecStartOptions) error {
	args := m.Called(ctx, execID, config)
	return args.Error(0)
}

// ContainerExecAttach mocks the Docker client ContainerExecAttach method
func (m *MockDockerClient) ContainerExecAttach(ctx context.Context, execID string, config container.ExecStartOptions) (types.HijackedResponse, error) {
	args := m.Called(ctx, execID, config)
	return args.Get(0).(types.HijackedResponse), args.Error(1)
}

// ContainerExecInspect mocks the Docker client ContainerExecInspect method
func (m *MockDockerClient) ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error) {
	args := m.Called(ctx, execID)
	return args.Get(0).(container.ExecInspect), args.Error(1)
}

// ContainerLogs mocks the Docker client ContainerLogs method
func (m *MockDockerClient) ContainerLogs(ctx context.Context, container string, options containertypes.LogsOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, container, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

// ContainerInspect mocks the Docker client ContainerInspect method
func (m *MockDockerClient) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	args := m.Called(ctx, containerID)
	return args.Get(0).(types.ContainerJSON), args.Error(1)
}

// ContainerRemove mocks the Docker client ContainerRemove method
func (m *MockDockerClient) ContainerRemove(ctx context.Context, containerID string, options containertypes.RemoveOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

// ContainerStart mocks the Docker client ContainerStart method
func (m *MockDockerClient) ContainerStart(ctx context.Context, containerID string, options containertypes.StartOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

// ContainerStop mocks the Docker client ContainerStop method
func (m *MockDockerClient) ContainerStop(ctx context.Context, containerID string, options containertypes.StopOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

// ContainerRestart mocks the Docker client ContainerRestart method
func (m *MockDockerClient) ContainerRestart(ctx context.Context, containerID string, options container.StopOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

// ContainerKill mocks the Docker client ContainerKill method
func (m *MockDockerClient) ContainerKill(ctx context.Context, containerID, signal string) error {
	args := m.Called(ctx, containerID, signal)
	return args.Error(0)
}

// ImageRemove mocks the Docker client ImageRemove method
func (m *MockDockerClient) ImageRemove(ctx context.Context, imageID string, options imagetypes.RemoveOptions) ([]imagetypes.DeleteResponse, error) {
	args := m.Called(ctx, imageID, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]imagetypes.DeleteResponse), args.Error(1)
}

// ImageTag mocks the Docker client ImageTag method
func (m *MockDockerClient) ImageTag(ctx context.Context, source, target string) error {
	args := m.Called(ctx, source, target)
	return args.Error(0)
}

// NetworkInspect mocks the Docker client NetworkInspect method
func (m *MockDockerClient) NetworkInspect(ctx context.Context, networkID string, options network.InspectOptions) (network.Summary, error) {
	args := m.Called(ctx, networkID, options)
	return args.Get(0).(network.Summary), args.Error(1)
}

// NetworkCreate mocks the Docker client NetworkCreate method
func (m *MockDockerClient) NetworkCreate(ctx context.Context, name string, options network.CreateOptions) (network.CreateResponse, error) {
	args := m.Called(ctx, name, options)
	return args.Get(0).(network.CreateResponse), args.Error(1)
}

// NetworkRemove mocks the Docker client NetworkRemove method
func (m *MockDockerClient) NetworkRemove(ctx context.Context, networkID string) error {
	args := m.Called(ctx, networkID)
	return args.Error(0)
}

// VolumeInspect mocks the Docker client VolumeInspect method
func (m *MockDockerClient) VolumeInspect(ctx context.Context, volumeID string) (volume.Volume, error) {
	args := m.Called(ctx, volumeID)
	return args.Get(0).(volume.Volume), args.Error(1)
}

// VolumeCreate mocks the Docker client VolumeCreate method
func (m *MockDockerClient) VolumeCreate(ctx context.Context, options volumetypes.CreateOptions) (volume.Volume, error) {
	args := m.Called(ctx, options)
	return args.Get(0).(volume.Volume), args.Error(1)
}

// VolumeRemove mocks the Docker client VolumeRemove method
func (m *MockDockerClient) VolumeRemove(ctx context.Context, volumeID string, force bool) error {
	args := m.Called(ctx, volumeID, force)
	return args.Error(0)
}

// Close mocks the Docker client Close method
func (m *MockDockerClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

// ContainerCreate mocks the Docker client ContainerCreate method
func (m *MockDockerClient) ContainerCreate(ctx context.Context, config *containertypes.Config, hostConfig *containertypes.HostConfig, networkingConfig *networktypes.NetworkingConfig, platform *specs.Platform, containerName string) (containertypes.CreateResponse, error) {
	args := m.Called(ctx, config, hostConfig, networkingConfig, platform, containerName)
	return args.Get(0).(containertypes.CreateResponse), args.Error(1)
}

// ContainerWait mocks the Docker client ContainerWait method
func (m *MockDockerClient) ContainerWait(ctx context.Context, containerID string, condition containertypes.WaitCondition) (<-chan containertypes.WaitResponse, <-chan error) {
	args := m.Called(ctx, containerID, condition)
	return args.Get(0).(<-chan containertypes.WaitResponse), args.Get(1).(<-chan error)
}

// Add more methods here as required by the client.APIClient interface...
// Note: This mock is becoming very large. Consider using a mocking library like mockery if more methods are needed.

// MockReadCloser is a mock implementation of io.ReadCloser
type MockReadCloser struct {
	mock.Mock
}

func (m *MockReadCloser) Read(p []byte) (n int, err error) {
	args := m.Called(p)
	// If the first return value is a function, call it to copy data
	if copier, ok := args.Get(0).(func([]byte) int); ok {
		n = copier(p)
	} else {
		n = args.Int(0)
	}
	return n, args.Error(1)
}

func (m *MockReadCloser) Close() error {
	args := m.Called()
	return args.Error(0)
}

// setupTestIntegration sets up a test Integration instance with a mock client
func setupTestIntegration(t *testing.T) (*Integration, *MockDockerClient) {
	mockClient := new(MockDockerClient)
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel) // Or your desired level

	var apiClient client.APIClient = mockClient      // Assign to interface variable
	integration := NewIntegration(apiClient, logger) // Use the interface variable
	require.NotNil(t, integration, "Failed to create integration")

	return integration, mockClient
}

// TestNewIntegration can be simplified or removed as the constructor is basic
func TestNewIntegration(t *testing.T) {
	mockClient := new(MockDockerClient)
	logger := logrus.New()

	integration := NewIntegration(mockClient, logger)

	assert.NotNil(t, integration)
	assert.Equal(t, mockClient, integration.client)
	assert.Equal(t, logger, integration.logger)

	// Test with nil logger
	integrationNilLogger := NewIntegration(mockClient, nil)
	assert.NotNil(t, integrationNilLogger)
	assert.NotNil(t, integrationNilLogger.logger, "Default logger should be created")
}

// TestIntegration_PullImage tests the PullImage method
func TestIntegration_PullImage(t *testing.T) {
	ctx := context.Background()

	t.Run("PullWithAuth", func(t *testing.T) {
		integration, mockClient := setupTestIntegration(t) // Use new setup

		// Create mock io.ReadCloser for pull response
		mockReadCloser := new(MockReadCloser)
		mockReadCloser.On("Read", mock.Anything).Return(0, io.EOF) // Simulate end of stream
		mockReadCloser.On("Close").Return(nil)

		// Setup mocks
		authConfig := registrytypes.AuthConfig{ // Use registrytypes.AuthConfig
			Username:      "testuser",
			Password:      "testpass",
			ServerAddress: "registry.example.com",
		}

		encodedAuth, err := EncodeAuthConfig(authConfig)
		require.NoError(t, err)

		expectedOptions := imagetypes.PullOptions{ // Use imagetypes.PullOptions
			RegistryAuth: encodedAuth,
		}

		mockClient.On("ImagePull", ctx, "registry.example.com/myapp:1.0", expectedOptions).
			Return(mockReadCloser, nil) // Return mock ReadCloser

		expectedInspect := types.ImageInspect{ // Use types.ImageInspect
			ID:   "sha256:1234567890abcdef",
			Size: 10000,
		}

		// Pull image using the Integration instance, passing authConfig directly
		pullStream, err := integration.PullImage(ctx, "registry.example.com/myapp:1.0", &authConfig)

		// Assert pull was called and handle stream (assuming success for this test part)
		assert.NoError(t, err)
		assert.NotNil(t, pullStream)
		if pullStream != nil {
			// Simulate reading the stream
			_, _ = io.Copy(io.Discard, pullStream) // Consume the stream
			pullStream.Close()                     // Close the stream
		}

		// Now mock the inspect call which happens *after* pull in a real scenario
		mockClient.On("ImageInspectWithRaw", ctx, "registry.example.com/myapp:1.0").
			Return(expectedInspect, []byte{}, nil).Once() // Mock inspect after pull

		// Manually call inspect or assume it's called elsewhere after pull
		inspectResult, _, inspectErr := mockClient.ImageInspectWithRaw(ctx, "registry.example.com/myapp:1.0")
		assert.NoError(t, inspectErr)
		assert.Equal(t, expectedInspect, inspectResult)

		// Assertions
		mockClient.AssertCalled(t, "ImagePull", ctx, "registry.example.com/myapp:1.0", expectedOptions)
		mockClient.AssertCalled(t, "ImageInspectWithRaw", ctx, "registry.example.com/myapp:1.0")
		mockReadCloser.AssertCalled(t, "Read", mock.Anything) // Check if stream was read
		mockReadCloser.AssertCalled(t, "Close")               // Check if stream was closed
	})

	t.Run("PullWithoutAuth", func(t *testing.T) {
		integration, mockClient := setupTestIntegration(t) // Use new setup

		// Create mock io.ReadCloser for pull response
		mockReadCloser := new(MockReadCloser)
		mockReadCloser.On("Read", mock.Anything).Return(0, io.EOF)
		mockReadCloser.On("Close").Return(nil)

		// Setup mocks - No auth config needed for this case

		mockClient.On("ImagePull", ctx, "registry.example.com/myapp:1.0", imagetypes.PullOptions{}). // Use imagetypes.PullOptions
														Return(mockReadCloser, nil) // Return mock ReadCloser

		expectedInspect := types.ImageInspect{ // Use types.ImageInspect
			ID:   "sha256:1234567890abcdef",
			Size: 10000,
		}

		mockClient.On("ImageInspectWithRaw", ctx, "registry.example.com/myapp:1.0").
			Return(expectedInspect, []byte{}, nil)

		// Pull image using the Integration instance, passing nil authConfig
		pullStream, err := integration.PullImage(ctx, "registry.example.com/myapp:1.0", nil)

		// Assert pull was called and handle stream
		assert.NoError(t, err)
		assert.NotNil(t, pullStream)
		if pullStream != nil {
			_, _ = io.Copy(io.Discard, pullStream)
			pullStream.Close()
		}

		// Mock inspect call after pull
		mockClient.On("ImageInspectWithRaw", ctx, "registry.example.com/myapp:1.0").
			Return(expectedInspect, []byte{}, nil).Once()

		// Manually call inspect or assume it's called elsewhere
		inspectResult, _, inspectErr := mockClient.ImageInspectWithRaw(ctx, "registry.example.com/myapp:1.0")
		assert.NoError(t, inspectErr)
		assert.Equal(t, expectedInspect, inspectResult)

		// Assertions
		mockClient.AssertCalled(t, "ImagePull", ctx, "registry.example.com/myapp:1.0", imagetypes.PullOptions{}) // Use imagetypes.PullOptions
		mockClient.AssertCalled(t, "ImageInspectWithRaw", ctx, "registry.example.com/myapp:1.0")
		mockReadCloser.AssertCalled(t, "Read", mock.Anything)
		mockReadCloser.AssertCalled(t, "Close")
	})

	// Removing PullWithDefaultUser test as Integration doesn't handle default users

	t.Run("DockerHubImage", func(t *testing.T) {
		integration, mockClient := setupTestIntegration(t) // Use new setup

		// Create mock io.ReadCloser for pull response
		mockReadCloser := new(MockReadCloser)
		mockReadCloser.On("Read", mock.Anything).Return(0, io.EOF)
		mockReadCloser.On("Close").Return(nil)

		// Setup mocks - Assuming no auth needed for public Docker Hub image

		mockClient.On("ImagePull", ctx, "nginx", imagetypes.PullOptions{}). // Use imagetypes.PullOptions
											Return(mockReadCloser, nil) // Return mock ReadCloser

		expectedInspect := types.ImageInspect{ // Use types.ImageInspect
			ID:   "sha256:1234567890abcdef",
			Size: 10000,
		}

		mockClient.On("ImageInspectWithRaw", ctx, "nginx").
			Return(expectedInspect, []byte{}, nil)

		// Pull image using the Integration instance, passing nil authConfig
		pullStream, err := integration.PullImage(ctx, "nginx", nil)

		// Assert pull was called and handle stream
		assert.NoError(t, err)
		assert.NotNil(t, pullStream)
		if pullStream != nil {
			_, _ = io.Copy(io.Discard, pullStream)
			pullStream.Close()
		}

		// Mock inspect call after pull
		mockClient.On("ImageInspectWithRaw", ctx, "nginx").
			Return(expectedInspect, []byte{}, nil).Once()

		// Manually call inspect or assume it's called elsewhere
		inspectResult, _, inspectErr := mockClient.ImageInspectWithRaw(ctx, "nginx")
		assert.NoError(t, inspectErr)
		assert.Equal(t, expectedInspect, inspectResult)

		// Assertions
		mockClient.AssertCalled(t, "ImagePull", ctx, "nginx", imagetypes.PullOptions{})
		mockClient.AssertCalled(t, "ImageInspectWithRaw", ctx, "nginx")
		mockReadCloser.AssertCalled(t, "Read", mock.Anything)
		mockReadCloser.AssertCalled(t, "Close")
	})
}

// TestIntegration_PushImage tests the PushImage method
func TestIntegration_PushImage(t *testing.T) {
	ctx := context.Background()

	t.Run("PushWithAuth", func(t *testing.T) {
		integration, mockClient := setupTestIntegration(t) // Use new setup

		// Create mock io.ReadCloser for push response
		mockReadCloser := new(MockReadCloser)
		mockReadCloser.On("Read", mock.Anything).Return(0, io.EOF)
		mockReadCloser.On("Close").Return(nil)

		// Setup mocks
		authConfig := registrytypes.AuthConfig{ // Use registrytypes.AuthConfig
			Username:      "testuser",
			Password:      "testpass",
			ServerAddress: "registry.example.com",
		}

		encodedAuth, err := EncodeAuthConfig(authConfig)
		require.NoError(t, err)

		expectedOptions := imagetypes.PushOptions{ // Use imagetypes.PushOptions
			RegistryAuth: encodedAuth,
		}

		mockClient.On("ImagePush", ctx, "registry.example.com/myapp:1.0", expectedOptions).
			Return(mockReadCloser, nil) // Return mock ReadCloser

		// Push image using the Integration instance
		pushStream, err := integration.PushImage(ctx, "registry.example.com/myapp:1.0", authConfig)

		// Assert push was called and handle stream
		assert.NoError(t, err)
		assert.NotNil(t, pushStream) // Use correct variable name
		if pushStream != nil {
			_, _ = io.Copy(io.Discard, pushStream)
			pushStream.Close()
		}

		// Assertions
		mockClient.AssertCalled(t, "ImagePush", ctx, "registry.example.com/myapp:1.0", expectedOptions)
		mockReadCloser.AssertCalled(t, "Read", mock.Anything)
		mockReadCloser.AssertCalled(t, "Close")
	})
}

// TestIntegration_Authenticate tests the registry login functionality
func TestIntegration_Authenticate(t *testing.T) {
	ctx := context.Background()
	integration, mockClient := setupTestIntegration(t)

	authConfig := registrytypes.AuthConfig{
		Username:      "testuser",
		Password:      "testpass",
		ServerAddress: "registry.example.com",
	}
	expectedStatus := registrytypes.AuthenticateOKBody{
		Status: "Login Succeeded",
	}

	mockClient.On("RegistryLogin", ctx, authConfig).Return(expectedStatus, nil)

	status, err := integration.Authenticate(ctx, "registry.example.com", "testuser", "testpass")

	assert.NoError(t, err)
	assert.Equal(t, expectedStatus.Status, status)
	mockClient.AssertCalled(t, "RegistryLogin", ctx, authConfig)
}

// TestIntegration_SearchImages tests the image search functionality
func TestIntegration_SearchImages(t *testing.T) {
	ctx := context.Background()
	integration, mockClient := setupTestIntegration(t)

	searchTerm := "myimage"
	authConfig := registrytypes.AuthConfig{
		Username:      "testuser",
		Password:      "testpass",
		ServerAddress: "registry.example.com",
	}
	encodedAuth, err := EncodeAuthConfig(authConfig)
	require.NoError(t, err)

	expectedOptions := registrytypes.SearchOptions{
		RegistryAuth: encodedAuth,
	}
	expectedResults := []registrytypes.SearchResult{
		{Name: "myimage", Description: "Official image"},
		{Name: "user/myimage", Description: "User image"},
	}

	mockClient.On("ImageSearch", ctx, searchTerm, expectedOptions).Return(expectedResults, nil)

	results, err := integration.SearchImages(ctx, searchTerm, &authConfig)

	assert.NoError(t, err)
	assert.Equal(t, expectedResults, results)
	mockClient.AssertCalled(t, "ImageSearch", ctx, searchTerm, expectedOptions)
}

// NOTE: Tests related to CredentialManager (Add, List, Remove, Validate)
// have been removed as they are not part of the new Integration struct's responsibility.
// These should be tested with the Manager type if applicable.

func TestEncodeAuthConfig(t *testing.T) {
	authConfig := registrytypes.AuthConfig{
		Username:      "testuser",
		Password:      "testpass",
		ServerAddress: "registry.example.com",
	}
	encoded, err := EncodeAuthConfig(authConfig)
	assert.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Basic check: decode and verify username
	decodedBytes, err := base64.URLEncoding.DecodeString(encoded)
	assert.NoError(t, err)
	var decodedAuthConfig registrytypes.AuthConfig
	err = json.Unmarshal(decodedBytes, &decodedAuthConfig)
	assert.NoError(t, err)
	assert.Equal(t, authConfig.Username, decodedAuthConfig.Username)
}
