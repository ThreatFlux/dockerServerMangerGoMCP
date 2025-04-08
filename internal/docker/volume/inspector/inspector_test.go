package inspector

import (
	"context"
	"errors"
	"testing"
	"time"

	dockertypes "github.com/docker/docker/api/types" // Use alias again
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/system" // Added for system.Info
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/errdefs"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// MockClient is a mock Docker client that implements the VolumeInspectorClient interface
type MockClient struct {
	mock.Mock
}

// Ensure MockClient implements the interface
var _ VolumeInspectorClient = (*MockClient)(nil)

// VolumeInspect mocks VolumeInspect
func (m *MockClient) VolumeInspect(ctx context.Context, volumeID string) (volume.Volume, error) {
	args := m.Called(ctx, volumeID)
	if args.Get(0) == nil {
		return volume.Volume{}, args.Error(1)
	}
	return args.Get(0).(volume.Volume), args.Error(1)
}

// VolumeList mocks VolumeList
func (m *MockClient) VolumeList(ctx context.Context, options volume.ListOptions) (volume.ListResponse, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return volume.ListResponse{}, args.Error(1)
	}
	return args.Get(0).(volume.ListResponse), args.Error(1)
}

// ContainerList mocks ContainerList
func (m *MockClient) ContainerList(ctx context.Context, options container.ListOptions) ([]dockertypes.Container, error) { // Use alias
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]dockertypes.Container), args.Error(1) // Use alias
}

// ContainerInspect mocks ContainerInspect
func (m *MockClient) ContainerInspect(ctx context.Context, containerID string) (dockertypes.ContainerJSON, error) { // Use alias
	args := m.Called(ctx, containerID)
	if args.Get(0) == nil {
		return dockertypes.ContainerJSON{}, args.Error(1)
	} // Use alias
	return args.Get(0).(dockertypes.ContainerJSON), args.Error(1) // Use alias
}

// Info mocks Info
func (m *MockClient) Info(ctx context.Context) (system.Info, error) { // Use system.Info
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return system.Info{}, args.Error(1) // Use system.Info
	}
	return args.Get(0).(system.Info), args.Error(1) // Use system.Info
}

// Create a test Docker volume
func createTestVolume(name string) volume.Volume {
	return volume.Volume{
		Name:       name,
		Driver:     "local",
		Mountpoint: "/var/lib/docker_test/volumes/" + name + "/_data",
		CreatedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		Status:     map[string]interface{}{"status": "active"},
		Labels:     map[string]string{"label1": "value1"},
		Scope:      "local",
		Options:    map[string]string{"option1": "value1"},
		UsageData:  &volume.UsageData{Size: 1024, RefCount: 1},
	}
}

// Create a test container
func createTestContainer(id, name string, volumes []string) dockertypes.Container { // Use alias
	return dockertypes.Container{ID: id, Names: []string{name}} // Use alias
}

// Create a test container JSON
func createTestContainerJSON(id, name string, volumes []string) dockertypes.ContainerJSON { // Use alias
	mounts := make([]dockertypes.MountPoint, 0, len(volumes)) // Use alias
	for _, vol := range volumes {
		mounts = append(mounts, dockertypes.MountPoint{ // Use alias
			Type: mount.TypeVolume, Name: vol, Source: "/var/lib/docker_test/volumes/" + vol + "/_data",
			Destination: "/data", Driver: "local", Mode: "rw",
		})
	}
	return dockertypes.ContainerJSON{ // Use alias
		ContainerJSONBase: &dockertypes.ContainerJSONBase{ID: id, Name: name, State: &dockertypes.ContainerState{Running: true}}, // Use alias
		Config:            &container.Config{Image: "nginx"},
		Mounts:            mounts,
	}
}

// TestNew tests the New function
func TestNew(t *testing.T) {
	mockClient := new(MockClient)
	logger := logrus.New()
	inspector, err := New(Options{Client: mockClient, Logger: logger})
	require.NoError(t, err)
	assert.Equal(t, mockClient, inspector.client)
	assert.Equal(t, logger, inspector.logger)

	inspector, err = New(Options{Client: mockClient}) // Test with nil logger
	require.NoError(t, err)
	assert.NotNil(t, inspector.logger)
}

// TestList tests the List function
func TestList(t *testing.T) {
	mockClient := new(MockClient)
	testVolume1 := createTestVolume("test-volume-1")
	testVolume2 := createTestVolume("test-volume-2")
	volumeList := volume.ListResponse{Volumes: []*volume.Volume{&testVolume1, &testVolume2}}
	f := filters.NewArgs()
	f.Add("name", "test-volume*")
	mockClient.On("VolumeList", mock.Anything, mock.MatchedBy(func(opts volume.ListOptions) bool {
		return opts.Filters.ExactMatch("name", "test-volume*")
	})).Return(volumeList, nil)

	inspector, err := New(Options{Client: mockClient})
	require.NoError(t, err)
	options := ListOptions{Filter: &VolumesFilter{Name: "test-volume*"}}
	vols, err := inspector.List(context.Background(), options)
	require.NoError(t, err)
	assert.Len(t, vols, 2)
	assert.Equal(t, "test-volume-1", vols[0].Name)
	assert.Equal(t, "test-volume-2", vols[1].Name)
	mockClient.AssertExpectations(t)
}

// TestInspect tests the Inspect function
func TestInspect(t *testing.T) {
	mockClient := new(MockClient)
	testVolume := createTestVolume("test-volume")
	testContainer1 := createTestContainer("container-1", "container-1", []string{"test-volume"})
	testContainer2 := createTestContainer("container-2", "container-2", []string{"other-volume"})
	testContainers := []dockertypes.Container{testContainer1, testContainer2} // Use alias
	testContainerJSON1 := createTestContainerJSON("container-1", "container-1", []string{"test-volume"})
	testContainerJSON2 := createTestContainerJSON("container-2", "container-2", []string{"other-volume"})

	mockClient.On("VolumeInspect", mock.Anything, "test-volume").Return(testVolume, nil)
	mockClient.On("ContainerList", mock.Anything, mock.Anything).Return(testContainers, nil)
	mockClient.On("ContainerInspect", mock.Anything, "container-1").Return(testContainerJSON1, nil)
	mockClient.On("ContainerInspect", mock.Anything, "container-2").Return(testContainerJSON2, nil)

	inspector, err := New(Options{Client: mockClient})
	require.NoError(t, err)
	options := InspectOptions{IncludeContainers: true, IncludeMetrics: true, IncludeRaw: true}
	details, err := inspector.Inspect(context.Background(), "test-volume", options)
	require.NoError(t, err)

	assert.Equal(t, "test-volume", details.Volume.Name)
	assert.Equal(t, "local", details.Volume.Driver)
	assert.Equal(t, "/var/lib/docker_test/volumes/test-volume/_data", details.Volume.Mountpoint)
	assert.Equal(t, models.JSONMap{"label1": "value1"}, details.Volume.Labels)
	assert.Equal(t, models.JSONMap{"option1": "value1"}, details.Volume.Options)
	assert.Equal(t, "local", details.Volume.Scope)
	assert.NotNil(t, details.Volume.UsageData)
	assert.Equal(t, int64(1024), details.Volume.UsageData.Size)
	assert.Equal(t, int64(1), details.Volume.UsageData.RefCount)

	assert.Len(t, details.References, 1)
	assert.Equal(t, "container-1", details.References[0].ContainerID)
	assert.Equal(t, "container-1", details.References[0].ContainerName)
	assert.Equal(t, "/data", details.References[0].MountPath)
	assert.Equal(t, "rw", details.References[0].Mode)

	assert.Equal(t, int64(1024), details.Metrics.Size)
	assert.Equal(t, int64(1), details.Metrics.RefCount)
	// Removed assertions for LastAccessed/LastModified

	assert.NotNil(t, details.ExtraInfo["raw"])

	t.Run("NotFound", func(t *testing.T) {
		mockClient := new(MockClient)
		notFoundErr := errdefs.NotFound(errors.New("volume test inspect not found"))
		mockClient.On("VolumeInspect", mock.Anything, "not-found").Return(volume.Volume{}, notFoundErr).Once()
		inspector, err := New(Options{Client: mockClient})
		require.NoError(t, err)
		_, err = inspector.Inspect(context.Background(), "not-found", InspectOptions{})
		require.Error(t, err)
		assert.True(t, errdefs.IsNotFound(err), "Expected a 'not found' error type")
		mockClient.AssertExpectations(t)
	})
}

// TestInspectMultiple tests the InspectMultiple function
func TestInspectMultiple(t *testing.T) {
	mockClient := new(MockClient)
	testVolume1 := createTestVolume("test-volume-1")
	testVolume2 := createTestVolume("test-volume-2")
	testContainer1 := createTestContainer("container-1", "container-1", []string{"test-volume-1"})
	testContainer2 := createTestContainer("container-2", "container-2", []string{"test-volume-2"}) // Use testVolume2
	testContainers := []dockertypes.Container{testContainer1, testContainer2}                      // Use alias
	testContainerJSON1 := createTestContainerJSON("container-1", "container-1", []string{"test-volume-1"})
	testContainerJSON2 := createTestContainerJSON("container-2", "container-2", []string{"test-volume-2"}) // Use testVolume2

	mockClient.On("VolumeInspect", mock.Anything, "test-volume-1").Return(testVolume1, nil)
	mockClient.On("VolumeInspect", mock.Anything, "test-volume-2").Return(testVolume2, nil)
	mockClient.On("ContainerList", mock.Anything, mock.Anything).Return(testContainers, nil)
	mockClient.On("ContainerInspect", mock.Anything, "container-1").Return(testContainerJSON1, nil)
	mockClient.On("ContainerInspect", mock.Anything, "container-2").Return(testContainerJSON2, nil)

	inspector, err := New(Options{Client: mockClient})
	require.NoError(t, err)
	options := InspectOptions{IncludeContainers: true, IncludeMetrics: true}
	details, err := inspector.InspectMultiple(context.Background(), []string{"test-volume-1", "test-volume-2"}, options)
	require.NoError(t, err)
	assert.Len(t, details, 2)
	assert.Equal(t, "test-volume-1", details["test-volume-1"].Volume.Name)
	assert.Equal(t, "test-volume-2", details["test-volume-2"].Volume.Name)
	mockClient.AssertExpectations(t)
}

// TestGetStats tests the GetStats function
func TestGetStats(t *testing.T) {
	mockClient := new(MockClient)
	testVolume := createTestVolume("test-volume")
	mockClient.On("VolumeInspect", mock.Anything, "test-volume").Return(testVolume, nil)

	inspector, err := New(Options{Client: mockClient})
	require.NoError(t, err)
	stats, err := inspector.GetStats(context.Background(), "test-volume")
	require.NoError(t, err)
	assert.Equal(t, int64(1024), stats.Size)
	assert.Equal(t, int64(1), stats.RefCount)
	// Removed assertions for LastAccessed/LastModified

	t.Run("NotFound", func(t *testing.T) {
		mockClient := new(MockClient)
		notFoundErr := errdefs.NotFound(errors.New("volume get stats not found"))
		mockClient.On("VolumeInspect", mock.Anything, "not-found").Return(volume.Volume{}, notFoundErr).Once()
		inspector, err := New(Options{Client: mockClient})
		require.NoError(t, err)
		_, err = inspector.GetStats(context.Background(), "not-found")
		require.Error(t, err)
		assert.True(t, errdefs.IsNotFound(err), "Expected a 'not found' error type")
		mockClient.AssertExpectations(t)
	})
}

// TestGetUsage tests the GetUsage function
func TestGetUsage(t *testing.T) {
	mockClient := new(MockClient)
	testVolume1 := createTestVolume("test-volume-1")
	testVolume2 := createTestVolume("test-volume-2")
	volumeList := volume.ListResponse{Volumes: []*volume.Volume{&testVolume1, &testVolume2}}

	mockClient.On("VolumeList", mock.Anything, mock.Anything).Return(volumeList, nil)
	mockClient.On("VolumeInspect", mock.Anything, "test-volume-1").Return(testVolume1, nil)
	mockClient.On("VolumeInspect", mock.Anything, "test-volume-2").Return(testVolume2, nil)

	inspector, err := New(Options{Client: mockClient})
	require.NoError(t, err)
	usage, err := inspector.GetUsage(context.Background())
	require.NoError(t, err)
	assert.Len(t, usage, 2)
	assert.Equal(t, int64(1024), usage["test-volume-1"])
	assert.Equal(t, int64(1024), usage["test-volume-2"])
	mockClient.AssertExpectations(t)
}

// TestFindUnused tests the FindUnused function
func TestFindUnused(t *testing.T) {
	mockClient := new(MockClient)
	testVolume1 := createTestVolume("test-volume-1")
	testVolume2 := createTestVolume("test-volume-2")
	volumeList := volume.ListResponse{Volumes: []*volume.Volume{&testVolume1, &testVolume2}}

	mockClient.On("VolumeList", mock.Anything, mock.MatchedBy(func(opts volume.ListOptions) bool {
		return opts.Filters.ExactMatch("dangling", "true")
	})).Return(volumeList, nil)

	inspector, err := New(Options{Client: mockClient})
	require.NoError(t, err)
	vols, err := inspector.FindUnused(context.Background())
	require.NoError(t, err)
	assert.Len(t, vols, 2)
	assert.Equal(t, "test-volume-1", vols[0].Name)
	assert.Equal(t, "test-volume-2", vols[1].Name)
	mockClient.AssertExpectations(t)
}

// TestFindByLabel tests the FindByLabel function
func TestFindByLabel(t *testing.T) {
	mockClient := new(MockClient)
	testVolume1 := createTestVolume("test-volume-1")
	testVolume1.Labels = map[string]string{"env": "prod"}
	testVolume2 := createTestVolume("test-volume-2") // Removed unused variable
	testVolume2.Labels = map[string]string{"env": "dev"}
	volumeList := volume.ListResponse{Volumes: []*volume.Volume{&testVolume1}} // Only vol1 matches

	mockClient.On("VolumeList", mock.Anything, mock.MatchedBy(func(opts volume.ListOptions) bool {
		return opts.Filters.ExactMatch("label", "env=prod")
	})).Return(volumeList, nil)

	inspector, err := New(Options{Client: mockClient})
	require.NoError(t, err)
	vols, err := inspector.FindByLabel(context.Background(), "env=prod")
	require.NoError(t, err)
	assert.Len(t, vols, 1)
	assert.Equal(t, "test-volume-1", vols[0].Name)
	mockClient.AssertExpectations(t)
}

// TestFindByName tests the FindByName function
func TestFindByName(t *testing.T) {
	mockClient := new(MockClient)
	testVolume1 := createTestVolume("test-volume-1")
	// testVolume2 := createTestVolume("other-volume") // Removed unused variable
	volumeList := volume.ListResponse{Volumes: []*volume.Volume{&testVolume1}} // Only vol1 matches

	mockClient.On("VolumeList", mock.Anything, mock.MatchedBy(func(opts volume.ListOptions) bool {
		return opts.Filters.ExactMatch("name", "test-volume*")
	})).Return(volumeList, nil)

	inspector, err := New(Options{Client: mockClient})
	require.NoError(t, err)
	vols, err := inspector.FindByName(context.Background(), "test-volume*")
	require.NoError(t, err)
	assert.Len(t, vols, 1)
	assert.Equal(t, "test-volume-1", vols[0].Name)
	mockClient.AssertExpectations(t)
}

// TestFindByDriver tests the FindByDriver function
func TestFindByDriver(t *testing.T) {
	mockClient := new(MockClient)
	testVolume1 := createTestVolume("test-volume-1")
	testVolume1.Driver = "custom-driver"
	// testVolume2 := createTestVolume("test-volume-2") // Removed unused variable
	volumeList := volume.ListResponse{Volumes: []*volume.Volume{&testVolume1}} // Only vol1 matches

	mockClient.On("VolumeList", mock.Anything, mock.MatchedBy(func(opts volume.ListOptions) bool {
		return opts.Filters.ExactMatch("driver", "custom-driver")
	})).Return(volumeList, nil)

	inspector, err := New(Options{Client: mockClient})
	require.NoError(t, err)
	vols, err := inspector.FindByDriver(context.Background(), "custom-driver")
	require.NoError(t, err)
	assert.Len(t, vols, 1)
	assert.Equal(t, "test-volume-1", vols[0].Name)
	mockClient.AssertExpectations(t)
}

// TestGetDrivers tests the GetDrivers function
func TestGetDrivers(t *testing.T) {
	mockClient := new(MockClient)
	mockInfo := system.Info{ // Use system.Info
		Plugins: struct {
			Volume        []string
			Network       []string
			Authorization []string
			Log           []string
		}{
			Volume: []string{"custom-driver", "another-driver"},
		},
	}
	mockClient.On("Info", mock.Anything).Return(mockInfo, nil)

	inspector, err := New(Options{Client: mockClient})
	require.NoError(t, err)
	drivers, err := inspector.GetDrivers(context.Background())
	require.NoError(t, err)
	assert.Contains(t, drivers, "custom-driver")
	assert.Contains(t, drivers, "another-driver")
	assert.Contains(t, drivers, "local") // Should always include local
	assert.Len(t, drivers, 3)
	mockClient.AssertExpectations(t)
}

// TestToVolumeModel tests the toVolumeModel function
func TestToVolumeModel(t *testing.T) {
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)
	vol := volume.Volume{
		Name:       "test-vol",
		Driver:     "local",
		Mountpoint: "/mnt/test",
		CreatedAt:  nowStr,
		Status:     map[string]interface{}{"ref": "abc"},
		Labels:     map[string]string{"a": "b"},
		Scope:      "local",
		Options:    map[string]string{"o": "p"},
		UsageData:  &volume.UsageData{Size: 123, RefCount: 2},
	}

	modelVol := toVolumeModel(vol)
	assert.Equal(t, "test-vol", modelVol.Name)
	assert.Equal(t, "local", modelVol.Driver)
	assert.Equal(t, "/mnt/test", modelVol.Mountpoint)
	assert.Equal(t, "local", modelVol.Scope)
	assert.Equal(t, models.JSONMap{"a": "b"}, modelVol.Labels)
	assert.Equal(t, models.JSONMap{"o": "p"}, modelVol.Options)
	assert.Equal(t, models.JSONMap{"ref": "abc"}, modelVol.Status)
	assert.NotNil(t, modelVol.UsageData)
	assert.Equal(t, int64(123), modelVol.UsageData.Size)
	assert.Equal(t, int64(2), modelVol.UsageData.RefCount)

	parsedTime, _ := time.Parse(time.RFC3339Nano, nowStr)
	assert.Equal(t, parsedTime, modelVol.DockerResource.CreatedAt)

	vol.UsageData = nil
	modelVol = toVolumeModel(vol)
	assert.Nil(t, modelVol.UsageData)
}

// TestToVolumeUsageData tests the toVolumeUsageData function
func TestToVolumeUsageData(t *testing.T) {
	usage := &volume.UsageData{Size: 456, RefCount: 3}
	modelUsage := toVolumeUsageData(usage)
	require.NotNil(t, modelUsage)
	assert.Equal(t, int64(456), modelUsage.Size)
	assert.Equal(t, int64(3), modelUsage.RefCount)

	modelUsage = toVolumeUsageData(nil)
	assert.Nil(t, modelUsage)
}

// TestVolumesFilter tests the VolumesFilter ToFilterArgs method
func TestVolumesFilter(t *testing.T) {
	filter := VolumesFilter{
		Name:     "myvol",
		Driver:   "local",
		Label:    "env=prod",
		Dangling: true,
		Custom:   map[string][]string{"custom": {"val1", "val2"}},
	}
	args := filter.ToFilterArgs()
	assert.True(t, args.ExactMatch("name", "myvol"))
	assert.True(t, args.ExactMatch("driver", "local"))
	assert.True(t, args.ExactMatch("label", "env=prod"))
	assert.True(t, args.ExactMatch("dangling", "true"))
	// Corrected MatchKVList usage
	assert.True(t, args.MatchKVList("custom", map[string]string{"val1": "", "val2": ""}))
}

// TestVolumeDetails tests the VolumeDetails struct (basic check)
func TestVolumeDetails(t *testing.T) {
	details := VolumeDetails{
		Volume:     models.Volume{DockerResource: models.DockerResource{Name: "test"}},
		References: []VolumeReference{{ContainerID: "c1"}},
		Metrics:    VolumeMetrics{Size: 100},
		ExtraInfo:  map[string]interface{}{"raw": "data"},
	}
	assert.Equal(t, "test", details.Volume.Name)
	assert.Len(t, details.References, 1)
	assert.Equal(t, int64(100), details.Metrics.Size)
	assert.Equal(t, "data", details.ExtraInfo["raw"])
}

// TestVolumeMetrics tests the VolumeMetrics struct (basic check)
func TestVolumeMetrics(t *testing.T) {
	metrics := VolumeMetrics{
		Size:     1024,
		RefCount: 2,
		// Removed LastAccessed/LastModified
	}
	assert.Equal(t, int64(1024), metrics.Size)
	assert.Equal(t, int64(2), metrics.RefCount)
}
