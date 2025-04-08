package docker

// This file defines a shared mock implementation for the Docker client API.

import (
	"context"
	"io"
	"net"
	"net/http"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/mock"

	// Import necessary subpackages directly
	"github.com/docker/docker/api/types/checkpoint"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/api/types/system"
)

// mockStatsReader implements the minimal required interface
type mockStatsReader struct {
	io.ReadCloser
}

// MockDockerClient is a shared mock implementation of the client.APIClient interface
type MockDockerClient struct {
	mock.Mock
}

// Ensure MockDockerClient implements client.APIClient (compile-time check)
var _ client.APIClient = (*MockDockerClient)(nil)

// --- MOCK METHODS ---
// ClientVersion provides a mock implementation for ClientVersion
func (m *MockDockerClient) ClientVersion() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockDockerClient) ContainerList(ctx context.Context, options container.ListOptions) ([]types.Container, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]types.Container), args.Error(1)
}

func (m *MockDockerClient) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	args := m.Called(ctx, containerID)
	if args.Get(0) == nil {
		return types.ContainerJSON{}, args.Error(1)
	}
	return args.Get(0).(types.ContainerJSON), args.Error(1)
}

func (m *MockDockerClient) ContainerStats(ctx context.Context, containerID string, stream bool) (container.StatsResponseReader, error) {
	args := m.Called(ctx, containerID, stream)
	var reader container.StatsResponseReader
	if args.Get(0) != nil {
		reader = args.Get(0).(container.StatsResponseReader)
	}
	return reader, args.Error(1)
}

func (m *MockDockerClient) ContainerTop(ctx context.Context, containerID string, arguments []string) (container.ContainerTopOKBody, error) {
	args := m.Called(ctx, containerID, arguments)
	if args.Get(0) == nil {
		return container.ContainerTopOKBody{}, args.Error(1)
	}
	return args.Get(0).(container.ContainerTopOKBody), args.Error(1)
}

func (m *MockDockerClient) ContainerLogs(ctx context.Context, containerID string, options container.LogsOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, containerID, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	rc, ok := args.Get(0).(io.ReadCloser)
	if !ok {
		return nil, args.Error(1)
	}
	return rc, args.Error(1)
}

func (m *MockDockerClient) NetworkInspect(ctx context.Context, networkID string, options network.InspectOptions) (network.Inspect, error) {
	args := m.Called(ctx, networkID, options)
	if args.Get(0) == nil {
		return network.Inspect{}, args.Error(1)
	}
	val, ok := args.Get(0).(network.Inspect)
	if !ok {
		return network.Inspect{}, args.Error(1)
	}
	return val, args.Error(1)
}

func (m *MockDockerClient) VolumeInspect(ctx context.Context, volumeID string) (volume.Volume, error) {
	args := m.Called(ctx, volumeID)
	if args.Get(0) == nil {
		return volume.Volume{}, args.Error(1)
	}
	return args.Get(0).(volume.Volume), args.Error(1)
}

func (m *MockDockerClient) Events(ctx context.Context, options events.ListOptions) (<-chan events.Message, <-chan error) {
	args := m.Called(ctx, options)
	var msgCh <-chan events.Message
	var errCh <-chan error
	if args.Get(0) != nil {
		msgCh = args.Get(0).(<-chan events.Message)
	}
	if args.Get(1) != nil {
		errCh = args.Get(1).(<-chan error)
	}
	return msgCh, errCh
}

// --- Add missing methods to satisfy client.APIClient ---

func (m *MockDockerClient) BuildCachePrune(ctx context.Context, options types.BuildCachePruneOptions) (*types.BuildCachePruneReport, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.BuildCachePruneReport), args.Error(1)
}

func (m *MockDockerClient) BuildCancel(ctx context.Context, buildID string) error {
	args := m.Called(ctx, buildID)
	return args.Error(0)
}

func (m *MockDockerClient) CheckpointCreate(ctx context.Context, containerID string, options checkpoint.CreateOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

func (m *MockDockerClient) CheckpointDelete(ctx context.Context, containerID string, options checkpoint.DeleteOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

func (m *MockDockerClient) CheckpointList(ctx context.Context, containerID string, options checkpoint.ListOptions) ([]checkpoint.Summary, error) {
	args := m.Called(ctx, containerID, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]checkpoint.Summary), args.Error(1)
}

func (m *MockDockerClient) ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, platform *ocispec.Platform, containerName string) (container.CreateResponse, error) {
	args := m.Called(ctx, config, hostConfig, networkingConfig, platform, containerName)
	if args.Get(0) == nil {
		return container.CreateResponse{}, args.Error(1)
	}
	return args.Get(0).(container.CreateResponse), args.Error(1)
}

func (m *MockDockerClient) ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerStop(ctx context.Context, containerID string, options container.StopOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

func (m *MockDockerClient) ImagePull(ctx context.Context, refStr string, options image.PullOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, refStr, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) ImageList(ctx context.Context, options image.ListOptions) ([]image.Summary, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]image.Summary), args.Error(1)
}

func (m *MockDockerClient) NetworkCreate(ctx context.Context, name string, options network.CreateOptions) (network.CreateResponse, error) {
	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return network.CreateResponse{}, args.Error(1)
	}
	return args.Get(0).(network.CreateResponse), args.Error(1)
}

func (m *MockDockerClient) NetworkRemove(ctx context.Context, networkID string) error {
	args := m.Called(ctx, networkID)
	return args.Error(0)
}

func (m *MockDockerClient) VolumeCreate(ctx context.Context, options volume.CreateOptions) (volume.Volume, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return volume.Volume{}, args.Error(1)
	}
	return args.Get(0).(volume.Volume), args.Error(1)
}

func (m *MockDockerClient) VolumeRemove(ctx context.Context, volumeID string, force bool) error {
	args := m.Called(ctx, volumeID, force)
	return args.Error(0)
}

func (m *MockDockerClient) VolumeList(ctx context.Context, options volume.ListOptions) (volume.ListResponse, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return volume.ListResponse{}, args.Error(1)
	}
	return args.Get(0).(volume.ListResponse), args.Error(1)
}

func (m *MockDockerClient) Info(ctx context.Context) (system.Info, error) { // Use system.Info
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return system.Info{}, args.Error(1) // Use system.Info
	}
	val, ok := args.Get(0).(system.Info) // Use system.Info
	if !ok {
		return system.Info{}, args.Error(1) // Use system.Info
	}
	return val, args.Error(1)
}
func (m *MockDockerClient) ContainerDiff(ctx context.Context, containerID string) ([]container.FilesystemChange, error) {
	args := m.Called(ctx, containerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]container.FilesystemChange), args.Error(1)
}

func (m *MockDockerClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDockerClient) ConfigCreate(ctx context.Context, config swarm.ConfigSpec) (types.ConfigCreateResponse, error) { // Use swarm.ConfigSpec and types.ConfigCreateResponse
	args := m.Called(ctx, config)
	if args.Get(0) == nil {
		return types.ConfigCreateResponse{}, args.Error(1)
	} // Use types.ConfigCreateResponse
	return args.Get(0).(types.ConfigCreateResponse), args.Error(1) // Use types.ConfigCreateResponse
}

func (m *MockDockerClient) ConfigInspectWithRaw(ctx context.Context, name string) (swarm.Config, []byte, error) { // Use swarm.Config
	args := m.Called(ctx, name)
	configVal, _ := args.Get(0).(swarm.Config) // Use swarm.Config
	bytesVal, _ := args.Get(1).([]byte)
	return configVal, bytesVal, args.Error(2)
}

func (m *MockDockerClient) ConfigList(ctx context.Context, options types.ConfigListOptions) ([]swarm.Config, error) { // Use types and swarm
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]swarm.Config), args.Error(1) // Use swarm
}

func (m *MockDockerClient) ConfigRemove(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockDockerClient) ConfigUpdate(ctx context.Context, id string, version swarm.Version, config swarm.ConfigSpec) error { // Use swarm
	args := m.Called(ctx, id, version, config)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerAttach(ctx context.Context, containerID string, options container.AttachOptions) (types.HijackedResponse, error) { // Use types
	args := m.Called(ctx, containerID, options)
	if args.Get(0) == nil {
		return types.HijackedResponse{}, args.Error(1)
	} // Use types
	return args.Get(0).(types.HijackedResponse), args.Error(1) // Use types
}

func (m *MockDockerClient) ContainerCommit(ctx context.Context, containerID string, options container.CommitOptions) (types.IDResponse, error) { // Use types
	args := m.Called(ctx, containerID, options)
	if args.Get(0) == nil {
		return types.IDResponse{}, args.Error(1)
	} // Use types
	return args.Get(0).(types.IDResponse), args.Error(1) // Use types
}

func (m *MockDockerClient) ContainerExecAttach(ctx context.Context, execID string, config container.ExecStartOptions) (types.HijackedResponse, error) { // Use types
	args := m.Called(ctx, execID, config)
	if args.Get(0) == nil {
		return types.HijackedResponse{}, args.Error(1)
	} // Use types
	return args.Get(0).(types.HijackedResponse), args.Error(1) // Use types
}

func (m *MockDockerClient) ContainerExecCreate(ctx context.Context, containerID string, options container.ExecOptions) (types.IDResponse, error) { // Use types
	args := m.Called(ctx, containerID, options)
	if args.Get(0) == nil {
		return types.IDResponse{}, args.Error(1)
	} // Use types
	return args.Get(0).(types.IDResponse), args.Error(1) // Use types
}

func (m *MockDockerClient) ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error) {
	args := m.Called(ctx, execID)
	if args.Get(0) == nil {
		return container.ExecInspect{}, args.Error(1)
	}
	return args.Get(0).(container.ExecInspect), args.Error(1)
}

func (m *MockDockerClient) ContainerExecResize(ctx context.Context, execID string, options container.ResizeOptions) error {
	args := m.Called(ctx, execID, options)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerExecStart(ctx context.Context, execID string, config container.ExecStartOptions) error {
	args := m.Called(ctx, execID, config)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerExport(ctx context.Context, containerID string) (io.ReadCloser, error) {
	args := m.Called(ctx, containerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) ContainerInspectWithRaw(ctx context.Context, containerID string, size bool) (types.ContainerJSON, []byte, error) { // Use types
	args := m.Called(ctx, containerID, size)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	if args.Get(0) == nil {
		return types.ContainerJSON{}, data, args.Error(2)
	} // Use types
	return args.Get(0).(types.ContainerJSON), data, args.Error(2) // Use types
}

func (m *MockDockerClient) ContainerKill(ctx context.Context, containerID, signal string) error {
	args := m.Called(ctx, containerID, signal)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerPause(ctx context.Context, containerID string) error {
	args := m.Called(ctx, containerID)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerRename(ctx context.Context, containerID, newContainerName string) error {
	args := m.Called(ctx, containerID, newContainerName)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerResize(ctx context.Context, containerID string, options container.ResizeOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerRestart(ctx context.Context, containerID string, options container.StopOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerStatPath(ctx context.Context, containerID, path string) (container.PathStat, error) {
	args := m.Called(ctx, containerID, path)
	if args.Get(0) == nil {
		return container.PathStat{}, args.Error(1)
	}
	return args.Get(0).(container.PathStat), args.Error(1)
}

func (m *MockDockerClient) ContainerStatsOneShot(ctx context.Context, containerID string) (container.StatsResponseReader, error) {
	args := m.Called(ctx, containerID)
	// Return the value from the mock call directly, handling nil via type assertion
	var reader container.StatsResponseReader
	if args.Get(0) != nil {
		reader = args.Get(0).(container.StatsResponseReader)
	}
	return reader, args.Error(1)
}

func (m *MockDockerClient) ContainerUnpause(ctx context.Context, containerID string) error {
	args := m.Called(ctx, containerID)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerUpdate(ctx context.Context, containerID string, updateConfig container.UpdateConfig) (container.ContainerUpdateOKBody, error) {
	args := m.Called(ctx, containerID, updateConfig)
	if args.Get(0) == nil {
		return container.ContainerUpdateOKBody{}, args.Error(1)
	}
	return args.Get(0).(container.ContainerUpdateOKBody), args.Error(1)
}

func (m *MockDockerClient) ContainerWait(ctx context.Context, containerID string, condition container.WaitCondition) (<-chan container.WaitResponse, <-chan error) {
	args := m.Called(ctx, containerID, condition)
	var bodyChan chan container.WaitResponse
	var errChan chan error
	if args.Get(0) != nil {
		bodyChan = args.Get(0).(chan container.WaitResponse)
	}
	if args.Get(1) != nil {
		errChan = args.Get(1).(chan error)
	}
	return bodyChan, errChan
}

func (m *MockDockerClient) ContainersPrune(ctx context.Context, pruneFilters filters.Args) (container.PruneReport, error) {
	args := m.Called(ctx, pruneFilters)
	if args.Get(0) == nil {
		return container.PruneReport{}, args.Error(1)
	}
	return args.Get(0).(container.PruneReport), args.Error(1)
}

func (m *MockDockerClient) CopyFromContainer(ctx context.Context, containerID, srcPath string) (io.ReadCloser, container.PathStat, error) {
	args := m.Called(ctx, containerID, srcPath)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	if args.Get(1) == nil {
		return reader, container.PathStat{}, args.Error(2)
	}
	return reader, args.Get(1).(container.PathStat), args.Error(2)
}

func (m *MockDockerClient) CopyToContainer(ctx context.Context, containerID, path string, content io.Reader, options container.CopyToContainerOptions) error {
	args := m.Called(ctx, containerID, path, content, options)
	return args.Error(0)
}

func (m *MockDockerClient) DaemonHost() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockDockerClient) DialHijack(ctx context.Context, url, proto string, meta map[string][]string) (net.Conn, error) {
	args := m.Called(ctx, url, proto, meta)
	var conn net.Conn
	if args.Get(0) != nil {
		conn = args.Get(0).(net.Conn)
	}
	return conn, args.Error(1)
}

func (m *MockDockerClient) Dialer() func(context.Context) (net.Conn, error) {
	args := m.Called()
	if args.Get(0) != nil {
		return args.Get(0).(func(context.Context) (net.Conn, error))
	}
	return func(ctx context.Context) (net.Conn, error) { return nil, nil }
}

func (m *MockDockerClient) DiskUsage(ctx context.Context, options types.DiskUsageOptions) (types.DiskUsage, error) { // Use types
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return types.DiskUsage{}, args.Error(1)
	} // Use types
	return args.Get(0).(types.DiskUsage), args.Error(1) // Use types
}

func (m *MockDockerClient) DistributionInspect(ctx context.Context, image, encodedAuth string) (registry.DistributionInspect, error) {
	args := m.Called(ctx, image, encodedAuth)
	if args.Get(0) == nil {
		return registry.DistributionInspect{}, args.Error(1)
	}
	return args.Get(0).(registry.DistributionInspect), args.Error(1)
}

func (m *MockDockerClient) ImageBuild(ctx context.Context, buildContext io.Reader, options types.ImageBuildOptions) (types.ImageBuildResponse, error) { // Use types.ImageBuildOptions
	args := m.Called(ctx, buildContext, options)
	if args.Get(0) == nil {
		return types.ImageBuildResponse{}, args.Error(1)
	} // Use types
	return args.Get(0).(types.ImageBuildResponse), args.Error(1) // Use types
}

func (m *MockDockerClient) ImageCreate(ctx context.Context, parentReference string, options image.CreateOptions) (io.ReadCloser, error) { // Use image
	args := m.Called(ctx, parentReference, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) ImageHistory(ctx context.Context, imageID string, options ...client.ImageHistoryOption) ([]image.HistoryResponseItem, error) { // Use image
	// Convert variadic options to a slice of interface{} for m.Called
	optsSlice := make([]interface{}, len(options))
	for i, opt := range options {
		optsSlice[i] = opt
	}
	args := m.Called(append([]interface{}{ctx, imageID}, optsSlice...)...)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]image.HistoryResponseItem), args.Error(1) // Use image
}

func (m *MockDockerClient) ImageImport(ctx context.Context, source image.ImportSource, ref string, options image.ImportOptions) (io.ReadCloser, error) { // Use image.ImportSource
	args := m.Called(ctx, source, ref, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

// ImageInspect mocks the ImageInspect method
func (m *MockDockerClient) ImageInspect(ctx context.Context, imageID string, options ...client.ImageInspectOption) (image.InspectResponse, error) {
	// Convert variadic options to a slice of interface{} for m.Called
	optsSlice := make([]interface{}, len(options))
	for i, opt := range options {
		optsSlice[i] = opt
	}
	// Pass arguments including the options slice
	args := m.Called(append([]interface{}{ctx, imageID}, optsSlice...)...)
	if args.Get(0) == nil {
		return image.InspectResponse{}, args.Error(1)
	}
	return args.Get(0).(image.InspectResponse), args.Error(1)
}

func (m *MockDockerClient) ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error) { // Use types
	args := m.Called(ctx, imageID)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	if args.Get(0) == nil {
		return types.ImageInspect{}, data, args.Error(2)
	} // Use types
	return args.Get(0).(types.ImageInspect), data, args.Error(2) // Use types
}

func (m *MockDockerClient) ImageLoad(ctx context.Context, input io.Reader, options ...client.ImageLoadOption) (image.LoadResponse, error) { // Use image.LoadResponse
	// Convert variadic options to a slice of interface{} for m.Called
	optsSlice := make([]interface{}, len(options))
	for i, opt := range options {
		optsSlice[i] = opt
	}
	args := m.Called(append([]interface{}{ctx, input}, optsSlice...)...)
	if args.Get(0) == nil {
		return image.LoadResponse{}, args.Error(1) // Use image.LoadResponse
	}
	return args.Get(0).(image.LoadResponse), args.Error(1) // Use image.LoadResponse
}

func (m *MockDockerClient) ImagePush(ctx context.Context, refStr string, options image.PushOptions) (io.ReadCloser, error) { // Use image
	args := m.Called(ctx, refStr, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) ImageRemove(ctx context.Context, imageID string, options image.RemoveOptions) ([]image.DeleteResponse, error) { // Use image
	args := m.Called(ctx, imageID, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]image.DeleteResponse), args.Error(1) // Use image
}

func (m *MockDockerClient) ImageSave(ctx context.Context, imageIDs []string, options ...client.ImageSaveOption) (io.ReadCloser, error) {
	// Convert variadic options to a slice of interface{} for m.Called
	optsSlice := make([]interface{}, len(options))
	for i, opt := range options {
		optsSlice[i] = opt
	}
	args := m.Called(append([]interface{}{ctx, imageIDs}, optsSlice...)...)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) ImageSearch(ctx context.Context, term string, options registry.SearchOptions) ([]registry.SearchResult, error) { // Use registry.SearchOptions
	args := m.Called(ctx, term, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]registry.SearchResult), args.Error(1)
}

func (m *MockDockerClient) ImageTag(ctx context.Context, source, target string) error {
	args := m.Called(ctx, source, target)
	return args.Error(0)
}

func (m *MockDockerClient) ImagesPrune(ctx context.Context, pruneFilter filters.Args) (image.PruneReport, error) { // Use image.PruneReport
	args := m.Called(ctx, pruneFilter)
	if args.Get(0) == nil {
		return image.PruneReport{}, args.Error(1) // Use image.PruneReport
	}
	return args.Get(0).(image.PruneReport), args.Error(1) // Use image.PruneReport
}
func (m *MockDockerClient) NegotiateAPIVersion(ctx context.Context) { m.Called(ctx) }
func (m *MockDockerClient) NegotiateAPIVersionPing(ping types.Ping) { m.Called(ping) } // Use types
func (m *MockDockerClient) NetworkConnect(ctx context.Context, networkID, containerID string, config *network.EndpointSettings) error { // Use network
	args := m.Called(ctx, networkID, containerID, config)
	return args.Error(0)
}
func (m *MockDockerClient) NetworkDisconnect(ctx context.Context, networkID, containerID string, force bool) error {
	args := m.Called(ctx, networkID, containerID, force)
	return args.Error(0)
}
func (m *MockDockerClient) NetworkInspectWithRaw(ctx context.Context, networkID string, options network.InspectOptions) (network.Inspect, []byte, error) { // Use network.Inspect
	args := m.Called(ctx, networkID, options) // Use network
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	if args.Get(0) == nil { // Use network
		return network.Inspect{}, data, args.Error(2) // Use network.Inspect
	}
	val, ok := args.Get(0).(network.Inspect) // Use network.Inspect
	if !ok {
		return network.Inspect{}, data, args.Error(2) // Use network.Inspect
	}
	return val, data, args.Error(2)
}
func (m *MockDockerClient) NetworkList(ctx context.Context, options network.ListOptions) ([]network.Summary, error) { // Use network.Summary
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]network.Summary), args.Error(1) // Use network.Summary
}
func (m *MockDockerClient) NetworksPrune(ctx context.Context, pruneFilter filters.Args) (network.PruneReport, error) { // Use network
	args := m.Called(ctx, pruneFilter) // Use network
	if args.Get(0) == nil {
		return network.PruneReport{}, args.Error(1) // Use network
	}
	return args.Get(0).(network.PruneReport), args.Error(1) // Use network
}
func (m *MockDockerClient) NodeInspectWithRaw(ctx context.Context, nodeID string) (swarm.Node, []byte, error) { // Use swarm
	args := m.Called(ctx, nodeID)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	if args.Get(0) == nil {
		return swarm.Node{}, data, args.Error(2) // Use swarm
	}
	return args.Get(0).(swarm.Node), data, args.Error(2) // Use swarm
}
func (m *MockDockerClient) NodeList(ctx context.Context, options types.NodeListOptions) ([]swarm.Node, error) { // Use types and swarm
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]swarm.Node), args.Error(1) // Use swarm
}
func (m *MockDockerClient) NodeRemove(ctx context.Context, nodeID string, options types.NodeRemoveOptions) error { // Use types
	args := m.Called(ctx, nodeID, options)
	return args.Error(0)
}
func (m *MockDockerClient) NodeUpdate(ctx context.Context, nodeID string, version swarm.Version, node swarm.NodeSpec) error { // Use swarm
	args := m.Called(ctx, nodeID, version, node)
	return args.Error(0)
}
func (m *MockDockerClient) Ping(ctx context.Context) (types.Ping, error) { // Use types
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return types.Ping{}, args.Error(1) // Use types
	}
	return args.Get(0).(types.Ping), args.Error(1) // Use types
}
func (m *MockDockerClient) PluginCreate(ctx context.Context, createContext io.Reader, options types.PluginCreateOptions) error { // Use types
	args := m.Called(ctx, createContext, options)
	return args.Error(0)
}
func (m *MockDockerClient) PluginDisable(ctx context.Context, name string, options types.PluginDisableOptions) error { // Use types
	args := m.Called(ctx, name, options)
	return args.Error(0)
}
func (m *MockDockerClient) PluginEnable(ctx context.Context, name string, options types.PluginEnableOptions) error { // Use types
	args := m.Called(ctx, name, options)
	return args.Error(0)
}
func (m *MockDockerClient) PluginInspectWithRaw(ctx context.Context, name string) (*types.Plugin, []byte, error) { // Use types
	args := m.Called(ctx, name)
	var plugin *types.Plugin // Use types
	var data []byte
	if args.Get(0) != nil {
		plugin = args.Get(0).(*types.Plugin) // Use types
	}
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return plugin, data, args.Error(2)
}
func (m *MockDockerClient) PluginInstall(ctx context.Context, name string, options types.PluginInstallOptions) (io.ReadCloser, error) { // Use types
	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}
func (m *MockDockerClient) PluginList(ctx context.Context, filter filters.Args) (types.PluginsListResponse, error) { // Use types
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(types.PluginsListResponse), args.Error(1) // Use types
}
func (m *MockDockerClient) PluginPush(ctx context.Context, name, registryAuth string) (io.ReadCloser, error) {
	args := m.Called(ctx, name, registryAuth)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}
func (m *MockDockerClient) PluginRemove(ctx context.Context, name string, options types.PluginRemoveOptions) error { // Use types
	args := m.Called(ctx, name, options)
	return args.Error(0)
}
func (m *MockDockerClient) PluginSet(ctx context.Context, name string, argsIn []string) error {
	args := m.Called(ctx, name, argsIn)
	return args.Error(0)
}
func (m *MockDockerClient) PluginUpgrade(ctx context.Context, name string, options types.PluginInstallOptions) (io.ReadCloser, error) { // Use types
	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}
func (m *MockDockerClient) RegistryLogin(ctx context.Context, auth registry.AuthConfig) (registry.AuthenticateOKBody, error) {
	args := m.Called(ctx, auth)
	if args.Get(0) == nil {
		return registry.AuthenticateOKBody{}, args.Error(1)
	}
	return args.Get(0).(registry.AuthenticateOKBody), args.Error(1)
}
func (m *MockDockerClient) SecretCreate(ctx context.Context, secret swarm.SecretSpec) (types.SecretCreateResponse, error) { // Use swarm and types
	args := m.Called(ctx, secret)
	if args.Get(0) == nil {
		return types.SecretCreateResponse{}, args.Error(1) // Use types
	}
	return args.Get(0).(types.SecretCreateResponse), args.Error(1) // Use types
}
func (m *MockDockerClient) SecretInspectWithRaw(ctx context.Context, id string) (swarm.Secret, []byte, error) { // Use swarm
	args := m.Called(ctx, id)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	if args.Get(0) == nil {
		return swarm.Secret{}, data, args.Error(2) // Use swarm
	}
	return args.Get(0).(swarm.Secret), data, args.Error(2) // Use swarm
}
func (m *MockDockerClient) SecretList(ctx context.Context, options types.SecretListOptions) ([]swarm.Secret, error) { // Use types and swarm
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]swarm.Secret), args.Error(1) // Use swarm
}
func (m *MockDockerClient) SecretRemove(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockDockerClient) SecretUpdate(ctx context.Context, id string, version swarm.Version, secret swarm.SecretSpec) error { // Use swarm
	args := m.Called(ctx, id, version, secret)
	return args.Error(0)
}
func (m *MockDockerClient) ServerVersion(ctx context.Context) (types.Version, error) { // Use types
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return types.Version{}, args.Error(1) // Use types
	}
	return args.Get(0).(types.Version), args.Error(1) // Use types
}
func (m *MockDockerClient) ServiceCreate(ctx context.Context, service swarm.ServiceSpec, options types.ServiceCreateOptions) (swarm.ServiceCreateResponse, error) { // Use swarm and types
	args := m.Called(ctx, service, options)
	if args.Get(0) == nil {
		return swarm.ServiceCreateResponse{}, args.Error(1) // Use swarm
	}
	return args.Get(0).(swarm.ServiceCreateResponse), args.Error(1) // Use swarm
}
func (m *MockDockerClient) ServiceInspectWithRaw(ctx context.Context, serviceID string, options types.ServiceInspectOptions) (swarm.Service, []byte, error) { // Use types and swarm
	args := m.Called(ctx, serviceID, options)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	if args.Get(0) == nil {
		return swarm.Service{}, data, args.Error(2) // Use swarm
	}
	return args.Get(0).(swarm.Service), data, args.Error(2) // Use swarm
}
func (m *MockDockerClient) ServiceList(ctx context.Context, options types.ServiceListOptions) ([]swarm.Service, error) { // Use types and swarm
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]swarm.Service), args.Error(1) // Use swarm
}
func (m *MockDockerClient) ServiceLogs(ctx context.Context, serviceID string, options container.LogsOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, serviceID, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}
func (m *MockDockerClient) ServiceRemove(ctx context.Context, serviceID string) error {
	args := m.Called(ctx, serviceID)
	return args.Error(0)
}
func (m *MockDockerClient) ServiceUpdate(ctx context.Context, serviceID string, version swarm.Version, service swarm.ServiceSpec, options types.ServiceUpdateOptions) (swarm.ServiceUpdateResponse, error) { // Use swarm and types
	args := m.Called(ctx, serviceID, version, service, options)
	if args.Get(0) == nil {
		return swarm.ServiceUpdateResponse{}, args.Error(1) // Use swarm
	}
	return args.Get(0).(swarm.ServiceUpdateResponse), args.Error(1) // Use swarm
}
func (m *MockDockerClient) SwarmGetUnlockKey(ctx context.Context) (types.SwarmUnlockKeyResponse, error) { // Use types
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return types.SwarmUnlockKeyResponse{}, args.Error(1) // Use types
	}
	return args.Get(0).(types.SwarmUnlockKeyResponse), args.Error(1) // Use types
}
func (m *MockDockerClient) SwarmInit(ctx context.Context, req swarm.InitRequest) (string, error) { // Use swarm
	args := m.Called(ctx, req)
	return args.String(0), args.Error(1)
}
func (m *MockDockerClient) SwarmInspect(ctx context.Context) (swarm.Swarm, error) { // Use swarm
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return swarm.Swarm{}, args.Error(1) // Use swarm
	}
	return args.Get(0).(swarm.Swarm), args.Error(1) // Use swarm
}
func (m *MockDockerClient) SwarmJoin(ctx context.Context, req swarm.JoinRequest) error { // Use swarm
	args := m.Called(ctx, req)
	return args.Error(0)
}
func (m *MockDockerClient) SwarmLeave(ctx context.Context, force bool) error {
	args := m.Called(ctx, force)
	return args.Error(0)
}
func (m *MockDockerClient) SwarmUnlock(ctx context.Context, req swarm.UnlockRequest) error { // Use swarm
	args := m.Called(ctx, req)
	return args.Error(0)
}
func (m *MockDockerClient) SwarmUpdate(ctx context.Context, version swarm.Version, swarm swarm.Spec, flags swarm.UpdateFlags) error { // Use swarm
	args := m.Called(ctx, version, swarm, flags)
	return args.Error(0)
}
func (m *MockDockerClient) TaskInspectWithRaw(ctx context.Context, taskID string) (swarm.Task, []byte, error) { // Use swarm
	args := m.Called(ctx, taskID)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	if args.Get(0) == nil {
		return swarm.Task{}, data, args.Error(2) // Use swarm
	}
	return args.Get(0).(swarm.Task), data, args.Error(2) // Use swarm
}
func (m *MockDockerClient) TaskList(ctx context.Context, options types.TaskListOptions) ([]swarm.Task, error) { // Use types and swarm
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]swarm.Task), args.Error(1) // Use swarm
}
func (m *MockDockerClient) TaskLogs(ctx context.Context, taskID string, options container.LogsOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, taskID, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}
func (m *MockDockerClient) VolumeInspectWithRaw(ctx context.Context, volumeID string) (volume.Volume, []byte, error) {
	args := m.Called(ctx, volumeID)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	if args.Get(0) == nil {
		return volume.Volume{}, data, args.Error(2)
	}
	return args.Get(0).(volume.Volume), data, args.Error(2)
}
func (m *MockDockerClient) VolumeUpdate(ctx context.Context, volumeID string, version swarm.Version, options volume.UpdateOptions) error { // Use swarm
	args := m.Called(ctx, volumeID, version, options)
	return args.Error(0)
}
func (m *MockDockerClient) VolumesPrune(ctx context.Context, pruneFilter filters.Args) (volume.PruneReport, error) {
	args := m.Called(ctx, pruneFilter)
	if args.Get(0) == nil {
		return volume.PruneReport{}, args.Error(1)
	}
	return args.Get(0).(volume.PruneReport), args.Error(1)
}

func (m *MockDockerClient) HTTPClient() *http.Client {
	args := m.Called()
	if args.Get(0) != nil {
		return args.Get(0).(*http.Client)
	}
	return nil
}
