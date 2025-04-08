package exec

import (
	"context"
	"io"       // Moved io import here
	"net"      // Added for DialHijack
	"net/http" // Added for HTTPClient
	"strings"  // Added import
	"testing"
	"time"

	types "github.com/docker/docker/api/types"                 // Use alias for types
	checkpoint "github.com/docker/docker/api/types/checkpoint" // Added for CheckpointCreateOptions
	container "github.com/docker/docker/api/types/container"   // Added import alias
	"github.com/docker/docker/api/types/events"                // Added for Events
	"github.com/docker/docker/api/types/filters"               // Added for ContainersPrune
	image "github.com/docker/docker/api/types/image"           // Added for ImageCreate
	network "github.com/docker/docker/api/types/network"       // Added for ContainerCreate
	"github.com/docker/docker/api/types/registry"              // Added for DistributionInspect
	swarm "github.com/docker/docker/api/types/swarm"           // Added for ConfigCreate
	"github.com/docker/docker/api/types/system"                // Added for Info
	volume "github.com/docker/docker/api/types/volume"         // Added for VolumeCreate
	client "github.com/docker/docker/client"                   // Added for ImageHistoryOption
	v1 "github.com/opencontainers/image-spec/specs-go/v1"      // Added for ContainerCreate
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDockerClient is a mock implementation of the Docker client interface
type MockDockerClient struct {
	mock.Mock
}

// Add methods to satisfy client.APIClient interface for tests

func (m *MockDockerClient) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	args := m.Called(ctx, containerID)
	// Return zero value if nil, otherwise cast
	if args.Get(0) == nil {
		return types.ContainerJSON{}, args.Error(1)
	}
	return args.Get(0).(types.ContainerJSON), args.Error(1)
}

func (m *MockDockerClient) ContainerExecCreate(ctx context.Context, container string, config container.ExecOptions) (types.IDResponse, error) {
	args := m.Called(ctx, container, config)
	// Return zero value if nil, otherwise cast
	if args.Get(0) == nil {
		return types.IDResponse{}, args.Error(1)
	}
	return args.Get(0).(types.IDResponse), args.Error(1)
}

// --- Add stubs for other common APIClient methods ---
// (Add more as needed based on compiler errors)

func (m *MockDockerClient) Ping(ctx context.Context) (types.Ping, error) {
	args := m.Called(ctx)
	return args.Get(0).(types.Ping), args.Error(1)
}

func (m *MockDockerClient) BuildCachePrune(ctx context.Context, opts types.BuildCachePruneOptions) (*types.BuildCachePruneReport, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.BuildCachePruneReport), args.Error(1)
}

func (m *MockDockerClient) BuildCancel(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockDockerClient) CheckpointCreate(ctx context.Context, container string, options checkpoint.CreateOptions) error { // Use checkpoint.CreateOptions
	args := m.Called(ctx, container, options)
	return args.Error(0)
}

func (m *MockDockerClient) CheckpointDelete(ctx context.Context, container string, options checkpoint.DeleteOptions) error { // Use checkpoint.DeleteOptions
	args := m.Called(ctx, container, options)
	return args.Error(0)
}

func (m *MockDockerClient) CheckpointList(ctx context.Context, container string, options checkpoint.ListOptions) ([]checkpoint.Summary, error) { // Use checkpoint.ListOptions
	args := m.Called(ctx, container, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]checkpoint.Summary), args.Error(1)
}

func (m *MockDockerClient) ClientVersion() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockDockerClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDockerClient) ConfigCreate(ctx context.Context, config swarm.ConfigSpec) (types.ConfigCreateResponse, error) {
	args := m.Called(ctx, config)
	return args.Get(0).(types.ConfigCreateResponse), args.Error(1)
}

func (m *MockDockerClient) ConfigInspectWithRaw(ctx context.Context, id string) (swarm.Config, []byte, error) {
	args := m.Called(ctx, id)
	// Return zero values if nil
	config, _ := args.Get(0).(swarm.Config)
	data, _ := args.Get(1).([]byte)
	return config, data, args.Error(2)
}

func (m *MockDockerClient) ConfigList(ctx context.Context, options types.ConfigListOptions) ([]swarm.Config, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]swarm.Config), args.Error(1)
}

func (m *MockDockerClient) ConfigRemove(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockDockerClient) ConfigUpdate(ctx context.Context, id string, version swarm.Version, config swarm.ConfigSpec) error {
	args := m.Called(ctx, id, version, config)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerAttach(ctx context.Context, container string, options container.AttachOptions) (types.HijackedResponse, error) {
	args := m.Called(ctx, container, options)
	// Return zero values if nil
	resp, _ := args.Get(0).(types.HijackedResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ContainerCommit(ctx context.Context, containerID string, options container.CommitOptions) (types.IDResponse, error) { // Renamed container -> containerID
	args := m.Called(ctx, containerID, options) // Use containerID
	// Return zero values if nil
	resp, _ := args.Get(0).(types.IDResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, platform *v1.Platform, containerName string) (container.CreateResponse, error) {
	args := m.Called(ctx, config, hostConfig, networkingConfig, platform, containerName)
	// Return zero values if nil
	resp, _ := args.Get(0).(container.CreateResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ContainerDiff(ctx context.Context, containerID string) ([]container.FilesystemChange, error) { // Use container.FilesystemChange
	args := m.Called(ctx, containerID) // Use containerID
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]container.FilesystemChange), args.Error(1) // Use container.FilesystemChange
}

func (m *MockDockerClient) ContainerExecAttach(ctx context.Context, execID string, config container.ExecAttachOptions) (types.HijackedResponse, error) {
	args := m.Called(ctx, execID, config)
	// Return zero values if nil
	resp, _ := args.Get(0).(types.HijackedResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error) {
	args := m.Called(ctx, execID)
	// Return zero values if nil
	resp, _ := args.Get(0).(container.ExecInspect)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ContainerExecResize(ctx context.Context, execID string, options container.ResizeOptions) error {
	args := m.Called(ctx, execID, options)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerExecStart(ctx context.Context, execID string, config container.ExecStartOptions) error {
	args := m.Called(ctx, execID, config)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerExport(ctx context.Context, containerID string) (io.ReadCloser, error) { // Renamed container -> containerID
	args := m.Called(ctx, containerID) // Use containerID
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) ContainerInspectWithRaw(ctx context.Context, containerID string, getSize bool) (types.ContainerJSON, []byte, error) {
	args := m.Called(ctx, containerID, getSize)
	// Return zero values if nil
	resp, _ := args.Get(0).(types.ContainerJSON)
	data, _ := args.Get(1).([]byte)
	return resp, data, args.Error(2)
}

func (m *MockDockerClient) ContainerKill(ctx context.Context, containerID, signal string) error {
	args := m.Called(ctx, containerID, signal)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerList(ctx context.Context, options container.ListOptions) ([]container.Summary, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]container.Summary), args.Error(1)
}

func (m *MockDockerClient) ContainerLogs(ctx context.Context, containerID string, options container.LogsOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, containerID, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) ContainerPause(ctx context.Context, containerID string) error {
	args := m.Called(ctx, containerID)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerRename(ctx context.Context, containerID, newName string) error {
	args := m.Called(ctx, containerID, newName)
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

func (m *MockDockerClient) ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerStatPath(ctx context.Context, containerID, path string) (container.PathStat, error) {
	args := m.Called(ctx, containerID, path)
	// Return zero values if nil
	resp, _ := args.Get(0).(container.PathStat)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ContainerStats(ctx context.Context, containerID string, stream bool) (container.StatsResponseReader, error) {
	args := m.Called(ctx, containerID, stream)
	// Return zero values if nil
	resp, _ := args.Get(0).(container.StatsResponseReader)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ContainerStatsOneShot(ctx context.Context, containerID string) (container.StatsResponseReader, error) {
	args := m.Called(ctx, containerID)
	// Return zero values if nil
	resp, _ := args.Get(0).(container.StatsResponseReader)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ContainerStop(ctx context.Context, containerID string, options container.StopOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerTop(ctx context.Context, containerID string, arguments []string) (container.TopResponse, error) {
	args := m.Called(ctx, containerID, arguments)
	// Return zero values if nil
	resp, _ := args.Get(0).(container.TopResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ContainerUnpause(ctx context.Context, containerID string) error {
	args := m.Called(ctx, containerID)
	return args.Error(0)
}

func (m *MockDockerClient) ContainerUpdate(ctx context.Context, containerID string, updateConfig container.UpdateConfig) (container.UpdateResponse, error) {
	args := m.Called(ctx, containerID, updateConfig)
	// Return zero values if nil
	resp, _ := args.Get(0).(container.UpdateResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ContainersPrune(ctx context.Context, pruneFilters filters.Args) (container.PruneReport, error) {
	args := m.Called(ctx, pruneFilters)
	// Return zero values if nil
	resp, _ := args.Get(0).(container.PruneReport)
	return resp, args.Error(1)
}

// Add more stub methods here... e.g., ContainerList, ImageList, etc.
// For brevity, only adding a few common ones initially.
// The compiler will indicate if more are required by the functions under test.

func (m *MockDockerClient) ContainerWait(ctx context.Context, containerID string, condition container.WaitCondition) (<-chan container.WaitResponse, <-chan error) {
	args := m.Called(ctx, containerID, condition)
	var respChan chan container.WaitResponse
	var errChan chan error
	if args.Get(0) != nil {
		respChan = args.Get(0).(chan container.WaitResponse)
	}
	if args.Get(1) != nil {
		errChan = args.Get(1).(chan error)
	}
	return respChan, errChan
}

func (m *MockDockerClient) CopyFromContainer(ctx context.Context, containerID, srcPath string) (io.ReadCloser, container.PathStat, error) {
	args := m.Called(ctx, containerID, srcPath)
	var rc io.ReadCloser
	var stat container.PathStat
	if args.Get(0) != nil {
		rc = args.Get(0).(io.ReadCloser)
	}
	if args.Get(1) != nil {
		stat = args.Get(1).(container.PathStat)
	}
	return rc, stat, args.Error(2)
}

func (m *MockDockerClient) DaemonHost() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockDockerClient) CopyToContainer(ctx context.Context, containerID, path string, content io.Reader, options container.CopyToContainerOptions) error {
	args := m.Called(ctx, containerID, path, content, options)
	return args.Error(0)
}

func (m *MockDockerClient) DialHijack(ctx context.Context, url, proto string, meta map[string][]string) (net.Conn, error) {
	args := m.Called(ctx, url, proto, meta)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(net.Conn), args.Error(1)
}

func (m *MockDockerClient) Dialer() func(context.Context) (net.Conn, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(func(context.Context) (net.Conn, error))
}

func (m *MockDockerClient) DiskUsage(ctx context.Context, options types.DiskUsageOptions) (types.DiskUsage, error) {
	args := m.Called(ctx, options)
	// Return zero values if nil
	resp, _ := args.Get(0).(types.DiskUsage)
	return resp, args.Error(1)
}

func (m *MockDockerClient) DistributionInspect(ctx context.Context, image, encodedRegistryAuth string) (registry.DistributionInspect, error) {
	args := m.Called(ctx, image, encodedRegistryAuth)
	// Return zero values if nil
	resp, _ := args.Get(0).(registry.DistributionInspect)
	return resp, args.Error(1)
}

func (m *MockDockerClient) Events(ctx context.Context, options events.ListOptions) (<-chan events.Message, <-chan error) {
	args := m.Called(ctx, options)
	var msgChan chan events.Message
	var errChan chan error
	if args.Get(0) != nil {
		msgChan = args.Get(0).(chan events.Message)
	}
	if args.Get(1) != nil {
		errChan = args.Get(1).(chan error)
	}
	return msgChan, errChan
}

func (m *MockDockerClient) HTTPClient() *http.Client {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*http.Client)
}

func (m *MockDockerClient) ImageBuild(ctx context.Context, buildContext io.Reader, options types.ImageBuildOptions) (types.ImageBuildResponse, error) {
	args := m.Called(ctx, buildContext, options)
	// Return zero values if nil
	resp, _ := args.Get(0).(types.ImageBuildResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ImageCreate(ctx context.Context, parentReference string, options image.CreateOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, parentReference, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) ImageHistory(ctx context.Context, imageID string, options ...client.ImageHistoryOption) ([]image.HistoryResponseItem, error) { // Use client.ImageHistoryOption
	// Convert variadic options to a slice for mock call if needed, or pass directly if mock supports variadic
	// For simplicity, let's assume the mock call handles variadic args or we don't need to assert on them here.
	args := m.Called(ctx, imageID) // Keep mock call simple for now
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]image.HistoryResponseItem), args.Error(1)
}

func (m *MockDockerClient) ImageImport(ctx context.Context, source image.ImportSource, ref string, options image.ImportOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, source, ref, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) ImageInspectWithRaw(ctx context.Context, imageID string) (image.InspectResponse, []byte, error) {
	args := m.Called(ctx, imageID)
	// Return zero values if nil
	resp, _ := args.Get(0).(image.InspectResponse)
	data, _ := args.Get(1).([]byte)
	return resp, data, args.Error(2)
}

// ImageInspect is deprecated, use ImageInspectWithRaw
func (m *MockDockerClient) ImageInspect(ctx context.Context, imageID string, options ...client.ImageInspectOption) (image.InspectResponse, error) { // Added variadic options
	// Convert variadic options to a slice for mock call if needed, or pass directly if mock supports variadic
	// For simplicity, let's assume the mock call handles variadic args or we don't need to assert on them here.
	args := m.Called(ctx, imageID) // Keep mock call simple for now
	// Return zero values if nil
	resp, _ := args.Get(0).(image.InspectResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ImageList(ctx context.Context, options image.ListOptions) ([]image.Summary, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]image.Summary), args.Error(1)
}

func (m *MockDockerClient) ImageLoad(ctx context.Context, input io.Reader, options ...client.ImageLoadOption) (image.LoadResponse, error) { // Added variadic options
	// Convert variadic options to a slice for mock call if needed, or pass directly if mock supports variadic
	// For simplicity, let's assume the mock call handles variadic args or we don't need to assert on them here.
	args := m.Called(ctx, input) // Keep mock call simple for now
	// Return zero values if nil
	resp, _ := args.Get(0).(image.LoadResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ImagePull(ctx context.Context, ref string, options image.PullOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, ref, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) ImagePush(ctx context.Context, ref string, options image.PushOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, ref, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) ImageRemove(ctx context.Context, imageID string, options image.RemoveOptions) ([]image.DeleteResponse, error) {
	args := m.Called(ctx, imageID, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]image.DeleteResponse), args.Error(1)
}

func (m *MockDockerClient) ImageSave(ctx context.Context, images []string, options ...client.ImageSaveOption) (io.ReadCloser, error) { // Added variadic options
	// Convert variadic options to a slice for mock call if needed, or pass directly if mock supports variadic
	// For simplicity, let's assume the mock call handles variadic args or we don't need to assert on them here.
	args := m.Called(ctx, images) // Keep mock call simple for now
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) ImageSearch(ctx context.Context, term string, options registry.SearchOptions) ([]registry.SearchResult, error) {
	args := m.Called(ctx, term, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]registry.SearchResult), args.Error(1)
}

func (m *MockDockerClient) ImageTag(ctx context.Context, imageID, ref string) error {
	args := m.Called(ctx, imageID, ref)
	return args.Error(0)
}

func (m *MockDockerClient) ImagesPrune(ctx context.Context, pruneFilter filters.Args) (image.PruneReport, error) {
	args := m.Called(ctx, pruneFilter)
	// Return zero values if nil
	resp, _ := args.Get(0).(image.PruneReport)
	return resp, args.Error(1)
}

func (m *MockDockerClient) Info(ctx context.Context) (system.Info, error) {
	args := m.Called(ctx)
	// Return zero values if nil
	resp, _ := args.Get(0).(system.Info)
	return resp, args.Error(1)
}

func (m *MockDockerClient) NegotiateAPIVersion(ctx context.Context) {
	m.Called(ctx)
}

func (m *MockDockerClient) NegotiateAPIVersionPing(ping types.Ping) {
	m.Called(ping)
}

func (m *MockDockerClient) NetworkConnect(ctx context.Context, networkID, containerID string, config *network.EndpointSettings) error {
	args := m.Called(ctx, networkID, containerID, config)
	return args.Error(0)
}

func (m *MockDockerClient) NetworkCreate(ctx context.Context, name string, options network.CreateOptions) (network.CreateResponse, error) {
	args := m.Called(ctx, name, options)
	// Return zero values if nil
	resp, _ := args.Get(0).(network.CreateResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) NetworkDisconnect(ctx context.Context, networkID, containerID string, force bool) error {
	args := m.Called(ctx, networkID, containerID, force)
	return args.Error(0)
}

func (m *MockDockerClient) NetworkInspectWithRaw(ctx context.Context, networkID string, options network.InspectOptions) (network.Inspect, []byte, error) {
	args := m.Called(ctx, networkID, options)
	// Return zero values if nil
	resp, _ := args.Get(0).(network.Inspect)
	data, _ := args.Get(1).([]byte)
	return resp, data, args.Error(2)
}

// NetworkInspect is deprecated, use NetworkInspectWithRaw
func (m *MockDockerClient) NetworkInspect(ctx context.Context, networkID string, options network.InspectOptions) (network.Inspect, error) {
	args := m.Called(ctx, networkID, options)
	// Return zero values if nil
	resp, _ := args.Get(0).(network.Inspect)
	return resp, args.Error(1)
}

func (m *MockDockerClient) NetworkList(ctx context.Context, options network.ListOptions) ([]network.Summary, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]network.Summary), args.Error(1)
}

func (m *MockDockerClient) NetworkRemove(ctx context.Context, networkID string) error {
	args := m.Called(ctx, networkID)
	return args.Error(0)
}

func (m *MockDockerClient) NetworksPrune(ctx context.Context, pruneFilter filters.Args) (network.PruneReport, error) {
	args := m.Called(ctx, pruneFilter)
	// Return zero values if nil
	resp, _ := args.Get(0).(network.PruneReport)
	return resp, args.Error(1)
}

func (m *MockDockerClient) NodeInspectWithRaw(ctx context.Context, nodeID string) (swarm.Node, []byte, error) {
	args := m.Called(ctx, nodeID)
	// Return zero values if nil
	resp, _ := args.Get(0).(swarm.Node)
	data, _ := args.Get(1).([]byte)
	return resp, data, args.Error(2)
}

func (m *MockDockerClient) NodeList(ctx context.Context, options types.NodeListOptions) ([]swarm.Node, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]swarm.Node), args.Error(1)
}

func (m *MockDockerClient) NodeRemove(ctx context.Context, nodeID string, options types.NodeRemoveOptions) error {
	args := m.Called(ctx, nodeID, options)
	return args.Error(0)
}

func (m *MockDockerClient) NodeUpdate(ctx context.Context, nodeID string, version swarm.Version, node swarm.NodeSpec) error {
	args := m.Called(ctx, nodeID, version, node)
	return args.Error(0)
}

func (m *MockDockerClient) PluginCreate(ctx context.Context, createContext io.Reader, options types.PluginCreateOptions) error {
	args := m.Called(ctx, createContext, options)
	return args.Error(0)
}

func (m *MockDockerClient) PluginDisable(ctx context.Context, name string, options types.PluginDisableOptions) error {
	args := m.Called(ctx, name, options)
	return args.Error(0)
}

func (m *MockDockerClient) PluginEnable(ctx context.Context, name string, options types.PluginEnableOptions) error {
	args := m.Called(ctx, name, options)
	return args.Error(0)
}

func (m *MockDockerClient) PluginInspectWithRaw(ctx context.Context, name string) (*types.Plugin, []byte, error) {
	args := m.Called(ctx, name)
	// Return zero values if nil
	resp, _ := args.Get(0).(*types.Plugin)
	data, _ := args.Get(1).([]byte)
	return resp, data, args.Error(2)
}

func (m *MockDockerClient) PluginInstall(ctx context.Context, name string, options types.PluginInstallOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) PluginList(ctx context.Context, filter filters.Args) (types.PluginsListResponse, error) {
	args := m.Called(ctx, filter)
	// Return zero values if nil
	resp, _ := args.Get(0).(types.PluginsListResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) PluginPush(ctx context.Context, name, registryAuth string) (io.ReadCloser, error) {
	args := m.Called(ctx, name, registryAuth)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) PluginRemove(ctx context.Context, name string, options types.PluginRemoveOptions) error {
	args := m.Called(ctx, name, options)
	return args.Error(0)
}

func (m *MockDockerClient) PluginSet(ctx context.Context, name string, pluginArgs []string) error { // Renamed args to pluginArgs to avoid conflict
	args := m.Called(ctx, name, pluginArgs) // Correctly capture mock.Arguments
	return args.Error(0)                    // Return the error from the mock call arguments
}

func (m *MockDockerClient) PluginUpgrade(ctx context.Context, name string, options types.PluginInstallOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, name, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) RegistryLogin(ctx context.Context, auth registry.AuthConfig) (registry.AuthenticateOKBody, error) { // Corrected type to registry.AuthConfig
	args := m.Called(ctx, auth)
	// Return zero values if nil
	resp, _ := args.Get(0).(registry.AuthenticateOKBody)
	return resp, args.Error(1)
}

func (m *MockDockerClient) SecretCreate(ctx context.Context, secret swarm.SecretSpec) (types.SecretCreateResponse, error) { // Corrected return type
	args := m.Called(ctx, secret)
	// Return zero values if nil
	resp, _ := args.Get(0).(types.SecretCreateResponse) // Corrected type assertion
	return resp, args.Error(1)
}
func (m *MockDockerClient) SecretInspectWithRaw(ctx context.Context, secretID string) (swarm.Secret, []byte, error) {
	args := m.Called(ctx, secretID)
	// Return zero values if nil
	resp, _ := args.Get(0).(swarm.Secret)
	data, _ := args.Get(1).([]byte)
	return resp, data, args.Error(2)
}

func (m *MockDockerClient) SecretList(ctx context.Context, options types.SecretListOptions) ([]swarm.Secret, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]swarm.Secret), args.Error(1)
}

func (m *MockDockerClient) SecretRemove(ctx context.Context, secretID string) error {
	args := m.Called(ctx, secretID)
	return args.Error(0)
}

func (m *MockDockerClient) SecretUpdate(ctx context.Context, secretID string, version swarm.Version, secret swarm.SecretSpec) error {
	args := m.Called(ctx, secretID, version, secret)
	return args.Error(0)
}

func (m *MockDockerClient) ServerVersion(ctx context.Context) (types.Version, error) {
	args := m.Called(ctx)
	// Return zero values if nil
	resp, _ := args.Get(0).(types.Version)
	return resp, args.Error(1)
}

func (m *MockDockerClient) ServiceCreate(ctx context.Context, service swarm.ServiceSpec, options types.ServiceCreateOptions) (swarm.ServiceCreateResponse, error) { // Corrected return type
	args := m.Called(ctx, service, options)
	// Return zero values if nil
	resp, _ := args.Get(0).(swarm.ServiceCreateResponse) // Corrected type assertion
	return resp, args.Error(1)
}

func (m *MockDockerClient) ServiceInspectWithRaw(ctx context.Context, serviceID string, options types.ServiceInspectOptions) (swarm.Service, []byte, error) {
	args := m.Called(ctx, serviceID, options)
	// Return zero values if nil
	resp, _ := args.Get(0).(swarm.Service)
	data, _ := args.Get(1).([]byte)
	return resp, data, args.Error(2)
}

func (m *MockDockerClient) ServiceList(ctx context.Context, options types.ServiceListOptions) ([]swarm.Service, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]swarm.Service), args.Error(1)
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

func (m *MockDockerClient) ServiceUpdate(ctx context.Context, serviceID string, version swarm.Version, service swarm.ServiceSpec, options types.ServiceUpdateOptions) (swarm.ServiceUpdateResponse, error) { // Corrected return type
	args := m.Called(ctx, serviceID, version, service, options)
	// Return zero values if nil
	resp, _ := args.Get(0).(swarm.ServiceUpdateResponse) // Corrected type assertion
	return resp, args.Error(1)
}

func (m *MockDockerClient) SwarmGetUnlockKey(ctx context.Context) (types.SwarmUnlockKeyResponse, error) {
	args := m.Called(ctx)
	// Return zero values if nil
	resp, _ := args.Get(0).(types.SwarmUnlockKeyResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) SwarmInit(ctx context.Context, req swarm.InitRequest) (string, error) {
	args := m.Called(ctx, req)
	return args.String(0), args.Error(1)
}

func (m *MockDockerClient) SwarmInspect(ctx context.Context) (swarm.Swarm, error) {
	args := m.Called(ctx)
	// Return zero values if nil
	resp, _ := args.Get(0).(swarm.Swarm)
	return resp, args.Error(1)
}

func (m *MockDockerClient) SwarmJoin(ctx context.Context, req swarm.JoinRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockDockerClient) SwarmLeave(ctx context.Context, force bool) error {
	args := m.Called(ctx, force)
	return args.Error(0)
}

func (m *MockDockerClient) SwarmUnlock(ctx context.Context, req swarm.UnlockRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockDockerClient) SwarmUpdate(ctx context.Context, version swarm.Version, swarm swarm.Spec, flags swarm.UpdateFlags) error {
	args := m.Called(ctx, version, swarm, flags)
	return args.Error(0)
}

func (m *MockDockerClient) TaskInspectWithRaw(ctx context.Context, taskID string) (swarm.Task, []byte, error) {
	args := m.Called(ctx, taskID)
	// Return zero values if nil
	resp, _ := args.Get(0).(swarm.Task)
	data, _ := args.Get(1).([]byte)
	return resp, data, args.Error(2)
}

func (m *MockDockerClient) TaskList(ctx context.Context, options types.TaskListOptions) ([]swarm.Task, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]swarm.Task), args.Error(1)
}

func (m *MockDockerClient) TaskLogs(ctx context.Context, taskID string, options container.LogsOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, taskID, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockDockerClient) VolumeCreate(ctx context.Context, options volume.CreateOptions) (volume.Volume, error) {
	args := m.Called(ctx, options)
	// Return zero values if nil
	resp, _ := args.Get(0).(volume.Volume)
	return resp, args.Error(1)
}

func (m *MockDockerClient) VolumeInspect(ctx context.Context, volumeID string) (volume.Volume, error) {
	args := m.Called(ctx, volumeID)
	// Return zero values if nil
	resp, _ := args.Get(0).(volume.Volume)
	return resp, args.Error(1)
}

func (m *MockDockerClient) VolumeInspectWithRaw(ctx context.Context, volumeID string) (volume.Volume, []byte, error) {
	args := m.Called(ctx, volumeID)
	// Return zero values if nil
	resp, _ := args.Get(0).(volume.Volume)
	data, _ := args.Get(1).([]byte)
	return resp, data, args.Error(2)
}

func (m *MockDockerClient) VolumeList(ctx context.Context, options volume.ListOptions) (volume.ListResponse, error) { // Corrected options type
	args := m.Called(ctx, options)
	// Return zero values if nil
	resp, _ := args.Get(0).(volume.ListResponse)
	return resp, args.Error(1)
}

func (m *MockDockerClient) VolumeRemove(ctx context.Context, volumeID string, force bool) error {
	args := m.Called(ctx, volumeID, force)
	return args.Error(0)
}

func (m *MockDockerClient) VolumeUpdate(ctx context.Context, volumeID string, version swarm.Version, options volume.UpdateOptions) error {
	args := m.Called(ctx, volumeID, version, options)
	return args.Error(0)
}

func (m *MockDockerClient) VolumesPrune(ctx context.Context, pruneFilter filters.Args) (volume.PruneReport, error) {
	args := m.Called(ctx, pruneFilter)
	// Return zero values if nil
	resp, _ := args.Get(0).(volume.PruneReport)
	return resp, args.Error(1)
}

// --- End added methods ---

func TestCreate(t *testing.T) {
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

	// Mock exec create
	execID := types.IDResponse{ID: "exec-id"}
	mockClient.On("ContainerExecCreate", mock.Anything, "test-container", mock.MatchedBy(func(config container.ExecOptions) bool { // Changed types.ExecConfig to container.ExecOptions
		return len(config.Cmd) >= 1 && config.Cmd[0] == "ls"
	})).Return(execID, nil).Once()

	// Set up exec config
	execConfig := ExecConfig{
		Cmd:          []string{"ls", "-la"},
		AttachStdout: true,
		AttachStderr: true,
	}

	// Set up options
	options := CreateOptions{
		Timeout: 10 * time.Second,
		Logger:  logrus.New(),
	}

	// Test Create
	id, err := Create(context.Background(), mockClient, "test-container", execConfig, options)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, "exec-id", id)
	mockClient.AssertExpectations(t)
}

func TestCreate_ContainerNotRunning(t *testing.T) {
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
	mockClient.On("ContainerInspect", mock.Anything, "test-container").Return(containerJSON, nil).Once()

	// Set up exec config
	execConfig := ExecConfig{
		Cmd:          []string{"ls", "-la"},
		AttachStdout: true,
		AttachStderr: true,
	}

	// Set up options
	options := CreateOptions{
		Logger: logrus.New(),
	}

	// Test Create
	_, err := Create(context.Background(), mockClient, "test-container", execConfig, options)

	// Verify
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrContainerNotRunning)
	mockClient.AssertExpectations(t)
}

func TestCreate_InvalidCommand(t *testing.T) {
	// Create mock Docker client
	mockClient := new(MockDockerClient)

	// Set up exec config with empty command
	execConfig := ExecConfig{
		Cmd:          []string{},
		AttachStdout: true,
		AttachStderr: true,
	}

	// Set up options
	options := CreateOptions{
		Logger: logrus.New(),
	}

	// Test Create
	_, err := Create(context.Background(), mockClient, "test-container", execConfig, options)

	// Verify
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCommand)
}

func TestDefaultSecurityValidator(t *testing.T) {
	testCases := []struct {
		name        string
		config      ExecConfig
		expectError bool
	}{
		{
			name: "Safe command",
			config: ExecConfig{
				Cmd:        []string{"ls", "-la"},
				Privileged: false,
			},
			expectError: false,
		},
		{
			name: "Dangerous command: rm -rf /",
			config: ExecConfig{
				Cmd:        []string{"rm", "-rf", "/"},
				Privileged: false,
			},
			expectError: true,
		},
		{
			name: "Dangerous command: reboot",
			config: ExecConfig{
				Cmd:        []string{"reboot"},
				Privileged: false,
			},
			expectError: true,
		},
		{
			name: "Privileged mode",
			config: ExecConfig{
				Cmd:        []string{"ls"},
				Privileged: true,
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := DefaultSecurityValidator(tc.config)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateAndWait(t *testing.T) {
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

	// Mock exec create
	execID := types.IDResponse{ID: "exec-id"}
	mockClient.On("ContainerExecCreate", mock.Anything, "test-container", mock.Anything).Return(execID, nil).Once()

	// Incomplete test - would need to mock more methods to test fully
	// Just check that validation works

	// Set up exec config with empty command
	execConfig := ExecConfig{
		Cmd:          []string{},
		AttachStdout: true,
		AttachStderr: true,
	}

	// Set up options
	options := CreateOptions{
		Logger: logrus.New(),
	}

	// Test CreateAndWait with invalid command
	_, _, _, err := CreateAndWait(context.Background(), mockClient, "test-container", execConfig, options)

	// Verify
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCommand)
}

func TestValidateUser(t *testing.T) {
	testCases := []struct {
		user     string
		expected bool
	}{
		{"", true},                    // Empty user (defaults to root)
		{"root", true},                // Valid username
		{"1000", true},                // Valid numeric user
		{"user:group", true},          // Valid user:group format
		{"1000:1000", true},           // Valid numeric user:group
		{"user.name", true},           // Valid username with dot
		{"user:group1:group2", false}, // Invalid format: too many colons
		{"1000.5", false},             // Invalid numeric user
		{"user:1000.5", false},        // Invalid numeric group
	}

	for _, tc := range testCases {
		t.Run(tc.user, func(t *testing.T) {
			result := ValidateUser(tc.user)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSanitizeCommand(t *testing.T) {
	testCases := []struct {
		name            string
		command         []string
		expectedWrapped bool
	}{
		{
			name:            "Simple command",
			command:         []string{"ls", "-la"},
			expectedWrapped: false,
		},
		{
			name:            "Command with shell metacharacters",
			command:         []string{"ls", "-la", "|", "grep", "foo"},
			expectedWrapped: true,
		},
		{
			name:            "Command with redirect",
			command:         []string{"echo", "hello", ">", "file.txt"},
			expectedWrapped: true,
		},
		{
			name:            "Command with variables",
			command:         []string{"echo", "$HOME"},
			expectedWrapped: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sanitized, err := SanitizeCommand(tc.command)

			assert.NoError(t, err)
			if tc.expectedWrapped {
				assert.Equal(t, "sh", sanitized[0])
				assert.Equal(t, "-c", sanitized[1])
				assert.Equal(t, strings.Join(tc.command, " "), sanitized[2])
			} else {
				assert.Equal(t, tc.command, sanitized)
			}
		})
	}

	// Test empty command
	_, err := SanitizeCommand([]string{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCommand)
}

func TestCreateMultiple(t *testing.T) {
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
	mockClient.On("ContainerInspect", mock.Anything, "test-container").Return(containerJSON, nil).Times(2)

	// Mock exec create
	execID1 := types.IDResponse{ID: "exec-id-1"}
	mockClient.On("ContainerExecCreate", mock.Anything, "test-container", mock.MatchedBy(func(config container.ExecOptions) bool { // Changed types.ExecConfig to container.ExecOptions
		return len(config.Cmd) >= 1 && config.Cmd[0] == "ls"
	})).Return(execID1, nil).Once()

	execID2 := types.IDResponse{ID: "exec-id-2"}
	mockClient.On("ContainerExecCreate", mock.Anything, "test-container", mock.MatchedBy(func(config container.ExecOptions) bool { // Changed types.ExecConfig to container.ExecOptions
		return len(config.Cmd) >= 1 && config.Cmd[0] == "echo"
	})).Return(execID2, nil).Once()

	// Set up exec configs
	execConfigs := []ExecConfig{
		{
			Cmd:          []string{"ls", "-la"},
			AttachStdout: true,
			AttachStderr: true,
		},
		{
			Cmd:          []string{"echo", "hello"},
			AttachStdout: true,
			AttachStderr: true,
		},
	}

	// Set up options
	options := CreateOptions{
		Timeout: 10 * time.Second,
		Logger:  logrus.New(),
	}

	// Test CreateMultiple
	ids, err := CreateMultiple(context.Background(), mockClient, "test-container", execConfigs, options)

	// Verify
	assert.NoError(t, err)
	assert.Len(t, ids, 2)
	assert.Equal(t, "exec-id-1", ids[0])
	assert.Equal(t, "exec-id-2", ids[1])
	mockClient.AssertExpectations(t)
}
