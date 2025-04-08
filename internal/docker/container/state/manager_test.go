package state

import (
	"context"
	"io"       // Import for ContainerExport
	"net"      // Import for DialHijack
	"net/http" // Import for HTTPClient
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/checkpoint" // Import for CheckpointCreate
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"             // Import for ContainersPrune
	"github.com/docker/docker/api/types/image"               // Import for ImageHistory
	"github.com/docker/docker/api/types/network"             // Import for ContainerCreate
	"github.com/docker/docker/api/types/registry"            // Import for DistributionInspect
	"github.com/docker/docker/api/types/swarm"               // Import for ConfigCreate
	"github.com/docker/docker/api/types/system"              // Import for Info
	"github.com/docker/docker/api/types/volume"              // Import for VolumeCreate
	"github.com/docker/docker/client"                        // Import for ImageHistoryOption
	specs "github.com/opencontainers/image-spec/specs-go/v1" // Import for ContainerCreate
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockDockerClient is a mock Docker client for testing
type MockDockerClient struct {
	mock.Mock
}

func (m *MockDockerClient) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	args := m.Called(ctx, containerID)
	return args.Get(0).(types.ContainerJSON), args.Error(1)
}

func (m *MockDockerClient) ContainerList(ctx context.Context, options container.ListOptions) ([]types.Container, error) { // Use container.ListOptions
	args := m.Called(ctx, options)
	return args.Get(0).([]types.Container), args.Error(1)
}

func (m *MockDockerClient) Events(ctx context.Context, options events.ListOptions) (<-chan events.Message, <-chan error) { // Use events.ListOptions
	args := m.Called(ctx, options)
	return args.Get(0).(<-chan events.Message), args.Get(1).(<-chan error)
}

// BuildCachePrune mocks the BuildCachePrune method
func (m *MockDockerClient) BuildCachePrune(ctx context.Context, opts types.BuildCachePruneOptions) (*types.BuildCachePruneReport, error) {
	args := m.Called(ctx, opts)
	var report *types.BuildCachePruneReport
	if args.Get(0) != nil {
		report = args.Get(0).(*types.BuildCachePruneReport)
	}
	return report, args.Error(1)
}

// BuildCancel mocks the BuildCancel method
func (m *MockDockerClient) BuildCancel(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// CheckpointCreate mocks the CheckpointCreate method
func (m *MockDockerClient) CheckpointCreate(ctx context.Context, containerID string, options checkpoint.CreateOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

// CheckpointDelete mocks the CheckpointDelete method
func (m *MockDockerClient) CheckpointDelete(ctx context.Context, containerID string, options checkpoint.DeleteOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

// CheckpointList mocks the CheckpointList method
func (m *MockDockerClient) CheckpointList(ctx context.Context, container string, options checkpoint.ListOptions) ([]checkpoint.Summary, error) {
	args := m.Called(ctx, container, options)
	var summaries []checkpoint.Summary
	if args.Get(0) != nil {
		summaries = args.Get(0).([]checkpoint.Summary)
	}
	return summaries, args.Error(1)
}

// ClientVersion mocks the ClientVersion method
func (m *MockDockerClient) ClientVersion() string {
	args := m.Called()
	return args.String(0)
}

// Close mocks the Close method
func (m *MockDockerClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

// ConfigCreate mocks the ConfigCreate method
func (m *MockDockerClient) ConfigCreate(ctx context.Context, config swarm.ConfigSpec) (types.ConfigCreateResponse, error) {
	args := m.Called(ctx, config)
	return args.Get(0).(types.ConfigCreateResponse), args.Error(1)
}

// ConfigInspectWithRaw mocks the ConfigInspectWithRaw method
func (m *MockDockerClient) ConfigInspectWithRaw(ctx context.Context, id string) (swarm.Config, []byte, error) {
	args := m.Called(ctx, id)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(swarm.Config), data, args.Error(2)
}

// ConfigList mocks the ConfigList method
func (m *MockDockerClient) ConfigList(ctx context.Context, options types.ConfigListOptions) ([]swarm.Config, error) {
	args := m.Called(ctx, options)
	var configs []swarm.Config
	if args.Get(0) != nil {
		configs = args.Get(0).([]swarm.Config)
	}
	return configs, args.Error(1)
}

// ConfigRemove mocks the ConfigRemove method
func (m *MockDockerClient) ConfigRemove(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// ConfigUpdate mocks the ConfigUpdate method
func (m *MockDockerClient) ConfigUpdate(ctx context.Context, id string, version swarm.Version, config swarm.ConfigSpec) error {
	args := m.Called(ctx, id, version, config)
	return args.Error(0)
}

// ContainerAttach mocks the ContainerAttach method
func (m *MockDockerClient) ContainerAttach(ctx context.Context, containerID string, options container.AttachOptions) (types.HijackedResponse, error) {
	args := m.Called(ctx, containerID, options)
	return args.Get(0).(types.HijackedResponse), args.Error(1)
}

// ContainerCommit mocks the ContainerCommit method
func (m *MockDockerClient) ContainerCommit(ctx context.Context, containerID string, options container.CommitOptions) (types.IDResponse, error) { // Use types.IDResponse
	args := m.Called(ctx, containerID, options)
	return args.Get(0).(types.IDResponse), args.Error(1) // Use types.IDResponse
}

// ContainerCreate mocks the ContainerCreate method
func (m *MockDockerClient) ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, platform *specs.Platform, containerName string) (container.CreateResponse, error) {
	args := m.Called(ctx, config, hostConfig, networkingConfig, platform, containerName)
	// Handle potential nil return for the response struct if necessary
	var resp container.CreateResponse
	if args.Get(0) != nil {
		resp = args.Get(0).(container.CreateResponse)
	}
	return resp, args.Error(1)
}

// ContainerDiff mocks the ContainerDiff method
func (m *MockDockerClient) ContainerDiff(ctx context.Context, containerID string) ([]container.FilesystemChange, error) {
	args := m.Called(ctx, containerID)
	var changes []container.FilesystemChange
	if args.Get(0) != nil {
		changes = args.Get(0).([]container.FilesystemChange)
	}
	return changes, args.Error(1)
}

// ContainerExecAttach mocks the ContainerExecAttach method
func (m *MockDockerClient) ContainerExecAttach(ctx context.Context, execID string, config container.ExecStartOptions) (types.HijackedResponse, error) { // Use container.ExecStartOptions
	args := m.Called(ctx, execID, config)
	return args.Get(0).(types.HijackedResponse), args.Error(1)
}

// ContainerExecCreate mocks the ContainerExecCreate method
func (m *MockDockerClient) ContainerExecCreate(ctx context.Context, containerID string, options container.ExecOptions) (types.IDResponse, error) { // Use container.ExecOptions
	args := m.Called(ctx, containerID, options)
	return args.Get(0).(types.IDResponse), args.Error(1)
}

// ContainerExecInspect mocks the ContainerExecInspect method
func (m *MockDockerClient) ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error) { // Use container.ExecInspect
	args := m.Called(ctx, execID)
	return args.Get(0).(container.ExecInspect), args.Error(1) // Use container.ExecInspect
}

// ContainerExecResize mocks the ContainerExecResize method
func (m *MockDockerClient) ContainerExecResize(ctx context.Context, execID string, options container.ResizeOptions) error {
	args := m.Called(ctx, execID, options)
	return args.Error(0)
}

// ContainerExecStart mocks the ContainerExecStart method
func (m *MockDockerClient) ContainerExecStart(ctx context.Context, execID string, config container.ExecStartOptions) error { // Use container.ExecStartOptions
	args := m.Called(ctx, execID, config)
	return args.Error(0)
}

// ContainerExport mocks the ContainerExport method
func (m *MockDockerClient) ContainerExport(ctx context.Context, containerID string) (io.ReadCloser, error) {
	args := m.Called(ctx, containerID)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// ContainerInspectWithRaw mocks the ContainerInspectWithRaw method
func (m *MockDockerClient) ContainerInspectWithRaw(ctx context.Context, containerID string, size bool) (types.ContainerJSON, []byte, error) {
	args := m.Called(ctx, containerID, size)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(types.ContainerJSON), data, args.Error(2)
}

// ContainerKill mocks the ContainerKill method
func (m *MockDockerClient) ContainerKill(ctx context.Context, containerID, signal string) error {
	args := m.Called(ctx, containerID, signal)
	return args.Error(0)
}

// ContainerLogs mocks the ContainerLogs method
func (m *MockDockerClient) ContainerLogs(ctx context.Context, containerID string, options container.LogsOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, containerID, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// ContainerPause mocks the ContainerPause method
func (m *MockDockerClient) ContainerPause(ctx context.Context, containerID string) error {
	args := m.Called(ctx, containerID)
	return args.Error(0)
}

// ContainerRemove mocks the ContainerRemove method
func (m *MockDockerClient) ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

// ContainerRename mocks the ContainerRename method
func (m *MockDockerClient) ContainerRename(ctx context.Context, containerID, newContainerName string) error {
	args := m.Called(ctx, containerID, newContainerName)
	return args.Error(0)
}

// ContainerResize mocks the ContainerResize method
func (m *MockDockerClient) ContainerResize(ctx context.Context, containerID string, options container.ResizeOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

// ContainerRestart mocks the ContainerRestart method
func (m *MockDockerClient) ContainerRestart(ctx context.Context, containerID string, options container.StopOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

// ContainerStart mocks the ContainerStart method
func (m *MockDockerClient) ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

// ContainerStatPath mocks the ContainerStatPath method
func (m *MockDockerClient) ContainerStatPath(ctx context.Context, containerID, path string) (container.PathStat, error) { // Use container.PathStat
	args := m.Called(ctx, containerID, path)
	return args.Get(0).(container.PathStat), args.Error(1) // Use container.PathStat
}

// ContainerStats mocks the ContainerStats method
// Note: The actual client returns types.ContainerStats (with a Body), which contains the reader.
// The mock should return the reader type expected by the interface.
func (m *MockDockerClient) ContainerStats(ctx context.Context, containerID string, stream bool) (container.StatsResponseReader, error) { // Use container.StatsResponseReader
	args := m.Called(ctx, containerID, stream)
	return args.Get(0).(container.StatsResponseReader), args.Error(1) // Use container.StatsResponseReader
}

// ContainerStatsOneShot mocks the ContainerStatsOneShot method
// Note: The actual client library doesn't have a dedicated OneShot method.
// Stats are typically read from the Body of types.ContainerStats.
// This mock might need adjustment based on how it's used in tests.
func (m *MockDockerClient) ContainerStatsOneShot(ctx context.Context, containerID string) (container.StatsResponseReader, error) { // Use container.StatsResponseReader
	args := m.Called(ctx, containerID)
	return args.Get(0).(container.StatsResponseReader), args.Error(1) // Use container.StatsResponseReader
}

// ContainerStop mocks the ContainerStop method
func (m *MockDockerClient) ContainerStop(ctx context.Context, containerID string, options container.StopOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

// ContainerTop mocks the ContainerTop method
func (m *MockDockerClient) ContainerTop(ctx context.Context, containerID string, arguments []string) (container.ContainerTopOKBody, error) {
	args := m.Called(ctx, containerID, arguments)
	return args.Get(0).(container.ContainerTopOKBody), args.Error(1)
}

// ContainerUnpause mocks the ContainerUnpause method
func (m *MockDockerClient) ContainerUnpause(ctx context.Context, containerID string) error {
	args := m.Called(ctx, containerID)
	return args.Error(0)
}

// ContainerUpdate mocks the ContainerUpdate method
func (m *MockDockerClient) ContainerUpdate(ctx context.Context, containerID string, updateConfig container.UpdateConfig) (container.ContainerUpdateOKBody, error) {
	args := m.Called(ctx, containerID, updateConfig)
	return args.Get(0).(container.ContainerUpdateOKBody), args.Error(1)
}

// ContainerWait mocks the ContainerWait method
func (m *MockDockerClient) ContainerWait(ctx context.Context, containerID string, condition container.WaitCondition) (<-chan container.WaitResponse, <-chan error) { // Use container.WaitResponse
	args := m.Called(ctx, containerID, condition)
	// Return channels - these might need more sophisticated mocking depending on test needs
	var bodyChan chan container.WaitResponse // Use container.WaitResponse
	var errChan chan error
	if args.Get(0) != nil {
		bodyChan = args.Get(0).(chan container.WaitResponse) // Use container.WaitResponse
	}
	if args.Get(1) != nil {
		errChan = args.Get(1).(chan error)
	}
	return bodyChan, errChan
}

// ContainersPrune mocks the ContainersPrune method
func (m *MockDockerClient) ContainersPrune(ctx context.Context, pruneFilters filters.Args) (container.PruneReport, error) { // Use container.PruneReport
	args := m.Called(ctx, pruneFilters)
	return args.Get(0).(container.PruneReport), args.Error(1) // Use container.PruneReport
}

// CopyFromContainer mocks the CopyFromContainer method
func (m *MockDockerClient) CopyFromContainer(ctx context.Context, containerID, srcPath string) (io.ReadCloser, container.PathStat, error) { // Use container.PathStat
	args := m.Called(ctx, containerID, srcPath)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Get(1).(container.PathStat), args.Error(2) // Use container.PathStat
}

// CopyToContainer mocks the CopyToContainer method
func (m *MockDockerClient) CopyToContainer(ctx context.Context, containerID, path string, content io.Reader, options container.CopyToContainerOptions) error { // Use container.CopyToContainerOptions
	args := m.Called(ctx, containerID, path, content, options)
	return args.Error(0)
}

// DaemonHost mocks the DaemonHost method
func (m *MockDockerClient) DaemonHost() string {
	args := m.Called()
	return args.String(0)
}

// DialHijack mocks the DialHijack method
func (m *MockDockerClient) DialHijack(ctx context.Context, url, proto string, meta map[string][]string) (net.Conn, error) {
	args := m.Called(ctx, url, proto, meta)
	var conn net.Conn
	if args.Get(0) != nil {
		conn = args.Get(0).(net.Conn)
	}
	return conn, args.Error(1)
}

// Dialer mocks the Dialer method
func (m *MockDockerClient) Dialer() func(context.Context) (net.Conn, error) {
	args := m.Called()
	// Return a function matching the signature
	if args.Get(0) != nil {
		return args.Get(0).(func(context.Context) (net.Conn, error))
	}
	return func(ctx context.Context) (net.Conn, error) { return nil, nil } // Default mock dialer
}

// DiskUsage mocks the DiskUsage method
func (m *MockDockerClient) DiskUsage(ctx context.Context, options types.DiskUsageOptions) (types.DiskUsage, error) {
	args := m.Called(ctx, options)
	return args.Get(0).(types.DiskUsage), args.Error(1)
}

// DistributionInspect mocks the DistributionInspect method
func (m *MockDockerClient) DistributionInspect(ctx context.Context, image, encodedAuth string) (registry.DistributionInspect, error) {
	args := m.Called(ctx, image, encodedAuth)
	return args.Get(0).(registry.DistributionInspect), args.Error(1)
}

// HTTPClient mocks the HTTPClient method
func (m *MockDockerClient) HTTPClient() *http.Client {
	args := m.Called()
	if args.Get(0) != nil {
		return args.Get(0).(*http.Client)
	}
	return nil // Or return a default mock client
}

// ImageBuild mocks the ImageBuild method
func (m *MockDockerClient) ImageBuild(ctx context.Context, buildContext io.Reader, options types.ImageBuildOptions) (types.ImageBuildResponse, error) {
	args := m.Called(ctx, buildContext, options)
	return args.Get(0).(types.ImageBuildResponse), args.Error(1)
}

// ImageCreate mocks the ImageCreate method
func (m *MockDockerClient) ImageCreate(ctx context.Context, parentReference string, options image.CreateOptions) (io.ReadCloser, error) { // Use image.CreateOptions
	args := m.Called(ctx, parentReference, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// ImageHistory mocks the ImageHistory method
func (m *MockDockerClient) ImageHistory(ctx context.Context, imageID string, options ...client.ImageHistoryOption) ([]image.HistoryResponseItem, error) { // Added options parameter
	// Pass options along if the mock needs to consider them, otherwise just match the signature
	args := m.Called(ctx, imageID, options) // Pass options to Called
	var history []image.HistoryResponseItem
	if args.Get(0) != nil {
		history = args.Get(0).([]image.HistoryResponseItem)
		history = args.Get(0).([]image.HistoryResponseItem)
	}
	return history, args.Error(1)
}

// ImageImport mocks the ImageImport method
func (m *MockDockerClient) ImageImport(ctx context.Context, source image.ImportSource, ref string, options image.ImportOptions) (io.ReadCloser, error) { // Use image types
	args := m.Called(ctx, source, ref, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// ImageInspect mocks the ImageInspect method (Added & Updated)
func (m *MockDockerClient) ImageInspect(ctx context.Context, imageID string, options ...client.ImageInspectOption) (image.InspectResponse, error) { // Updated signature
	args := m.Called(ctx, imageID, options)                   // Pass options
	return args.Get(0).(image.InspectResponse), args.Error(1) // Use image.InspectResponse
}

// ImageInspectWithRaw mocks the ImageInspectWithRaw method
func (m *MockDockerClient) ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error) {
	args := m.Called(ctx, imageID)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(types.ImageInspect), data, args.Error(2)
}

// ImageList mocks the ImageList method
func (m *MockDockerClient) ImageList(ctx context.Context, options image.ListOptions) ([]image.Summary, error) { // Use image.ListOptions and image.Summary
	args := m.Called(ctx, options)
	var summaries []image.Summary // Use image.Summary
	if args.Get(0) != nil {
		summaries = args.Get(0).([]image.Summary) // Use image.Summary
	}
	return summaries, args.Error(1)
}

// ImageLoad mocks the ImageLoad method
func (m *MockDockerClient) ImageLoad(ctx context.Context, input io.Reader, options ...client.ImageLoadOption) (image.LoadResponse, error) { // Use image.LoadResponse and options
	args := m.Called(ctx, input, options)                  // Pass options instead of quiet
	return args.Get(0).(image.LoadResponse), args.Error(1) // Use image.LoadResponse
}

// ImagePull mocks the ImagePull method
func (m *MockDockerClient) ImagePull(ctx context.Context, refStr string, options image.PullOptions) (io.ReadCloser, error) { // Use image.PullOptions
	args := m.Called(ctx, refStr, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// ImagePush mocks the ImagePush method
func (m *MockDockerClient) ImagePush(ctx context.Context, refStr string, options image.PushOptions) (io.ReadCloser, error) { // Use image.PushOptions
	args := m.Called(ctx, refStr, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// ImageRemove mocks the ImageRemove method
func (m *MockDockerClient) ImageRemove(ctx context.Context, imageID string, options image.RemoveOptions) ([]image.DeleteResponse, error) { // Use image.RemoveOptions and image.DeleteResponse
	args := m.Called(ctx, imageID, options)
	var items []image.DeleteResponse // Use image.DeleteResponse
	if args.Get(0) != nil {
		items = args.Get(0).([]image.DeleteResponse) // Use image.DeleteResponse
	}
	return items, args.Error(1)
}

// ImageSave mocks the ImageSave method
func (m *MockDockerClient) ImageSave(ctx context.Context, imageIDs []string, options ...client.ImageSaveOption) (io.ReadCloser, error) { // Added options parameter
	args := m.Called(ctx, imageIDs, options) // Pass options
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// ImageSearch mocks the ImageSearch method
func (m *MockDockerClient) ImageSearch(ctx context.Context, term string, options registry.SearchOptions) ([]registry.SearchResult, error) { // Use registry.SearchOptions
	args := m.Called(ctx, term, options)
	var results []registry.SearchResult
	if args.Get(0) != nil {
		results = args.Get(0).([]registry.SearchResult)
	}
	return results, args.Error(1)
}

// ImageTag mocks the ImageTag method
func (m *MockDockerClient) ImageTag(ctx context.Context, source, target string) error {
	args := m.Called(ctx, source, target)
	return args.Error(0)
}

// ImagesPrune mocks the ImagesPrune method
func (m *MockDockerClient) ImagesPrune(ctx context.Context, pruneFilter filters.Args) (image.PruneReport, error) { // Use image.PruneReport
	args := m.Called(ctx, pruneFilter)
	return args.Get(0).(image.PruneReport), args.Error(1) // Use image.PruneReport
}

// Info mocks the Info method
func (m *MockDockerClient) Info(ctx context.Context) (system.Info, error) { // Use system.Info
	args := m.Called(ctx)
	return args.Get(0).(system.Info), args.Error(1) // Use system.Info
}

// NegotiateAPIVersion mocks the NegotiateAPIVersion method
func (m *MockDockerClient) NegotiateAPIVersion(ctx context.Context) {
	m.Called(ctx)
}

// NegotiateAPIVersionPing mocks the NegotiateAPIVersionPing method
func (m *MockDockerClient) NegotiateAPIVersionPing(ping types.Ping) {
	m.Called(ping)
}

// NetworkConnect mocks the NetworkConnect method
func (m *MockDockerClient) NetworkConnect(ctx context.Context, networkID, containerID string, config *network.EndpointSettings) error {
	args := m.Called(ctx, networkID, containerID, config)
	return args.Error(0)
}

// NetworkCreate mocks the NetworkCreate method
func (m *MockDockerClient) NetworkCreate(ctx context.Context, name string, options network.CreateOptions) (network.CreateResponse, error) { // Use network types
	args := m.Called(ctx, name, options)
	return args.Get(0).(network.CreateResponse), args.Error(1) // Use network.CreateResponse
}

// NetworkDisconnect mocks the NetworkDisconnect method
func (m *MockDockerClient) NetworkDisconnect(ctx context.Context, networkID, containerID string, force bool) error {
	args := m.Called(ctx, networkID, containerID, force)
	return args.Error(0)
}

// NetworkInspect mocks the NetworkInspect method
func (m *MockDockerClient) NetworkInspect(ctx context.Context, networkID string, options network.InspectOptions) (network.Inspect, error) { // Use network types
	args := m.Called(ctx, networkID, options)
	return args.Get(0).(network.Inspect), args.Error(1) // Use network.Inspect
}

// NetworkInspectWithRaw mocks the NetworkInspectWithRaw method
func (m *MockDockerClient) NetworkInspectWithRaw(ctx context.Context, networkID string, options network.InspectOptions) (network.Inspect, []byte, error) { // Use network types
	args := m.Called(ctx, networkID, options)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(network.Inspect), data, args.Error(2) // Use network.Inspect
}

// NetworkList mocks the NetworkList method
func (m *MockDockerClient) NetworkList(ctx context.Context, options network.ListOptions) ([]network.Summary, error) { // Use network types
	args := m.Called(ctx, options)
	var networks []network.Summary // Use network.Summary
	if args.Get(0) != nil {
		networks = args.Get(0).([]network.Summary) // Use network.Summary
	}
	return networks, args.Error(1)
}

// NetworkRemove mocks the NetworkRemove method
func (m *MockDockerClient) NetworkRemove(ctx context.Context, networkID string) error {
	args := m.Called(ctx, networkID)
	return args.Error(0)
}

// NetworksPrune mocks the NetworksPrune method
func (m *MockDockerClient) NetworksPrune(ctx context.Context, pruneFilter filters.Args) (network.PruneReport, error) { // Use network.PruneReport
	args := m.Called(ctx, pruneFilter)
	return args.Get(0).(network.PruneReport), args.Error(1) // Use network.PruneReport
}

// NodeInspectWithRaw mocks the NodeInspectWithRaw method
func (m *MockDockerClient) NodeInspectWithRaw(ctx context.Context, nodeID string) (swarm.Node, []byte, error) {
	args := m.Called(ctx, nodeID)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(swarm.Node), data, args.Error(2)
}

// NodeList mocks the NodeList method
func (m *MockDockerClient) NodeList(ctx context.Context, options types.NodeListOptions) ([]swarm.Node, error) {
	args := m.Called(ctx, options)
	var nodes []swarm.Node
	if args.Get(0) != nil {
		nodes = args.Get(0).([]swarm.Node)
	}
	return nodes, args.Error(1)
}

// NodeRemove mocks the NodeRemove method
func (m *MockDockerClient) NodeRemove(ctx context.Context, nodeID string, options types.NodeRemoveOptions) error {
	args := m.Called(ctx, nodeID, options)
	return args.Error(0)
}

// NodeUpdate mocks the NodeUpdate method
func (m *MockDockerClient) NodeUpdate(ctx context.Context, nodeID string, version swarm.Version, node swarm.NodeSpec) error {
	args := m.Called(ctx, nodeID, version, node)
	return args.Error(0)
}

// Ping mocks the Ping method
func (m *MockDockerClient) Ping(ctx context.Context) (types.Ping, error) {
	args := m.Called(ctx)
	return args.Get(0).(types.Ping), args.Error(1)
}

// PluginCreate mocks the PluginCreate method
func (m *MockDockerClient) PluginCreate(ctx context.Context, createContext io.Reader, options types.PluginCreateOptions) error {
	args := m.Called(ctx, createContext, options)
	return args.Error(0)
}

// PluginDisable mocks the PluginDisable method
func (m *MockDockerClient) PluginDisable(ctx context.Context, name string, options types.PluginDisableOptions) error {
	args := m.Called(ctx, name, options)
	return args.Error(0)
}

// PluginEnable mocks the PluginEnable method
func (m *MockDockerClient) PluginEnable(ctx context.Context, name string, options types.PluginEnableOptions) error {
	args := m.Called(ctx, name, options)
	return args.Error(0)
}

// PluginInspectWithRaw mocks the PluginInspectWithRaw method
func (m *MockDockerClient) PluginInspectWithRaw(ctx context.Context, name string) (*types.Plugin, []byte, error) {
	args := m.Called(ctx, name)
	var plugin *types.Plugin
	var data []byte
	if args.Get(0) != nil {
		plugin = args.Get(0).(*types.Plugin)
	}
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return plugin, data, args.Error(2)
}

// PluginInstall mocks the PluginInstall method
func (m *MockDockerClient) PluginInstall(ctx context.Context, name string, options types.PluginInstallOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, name, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// PluginList mocks the PluginList method
func (m *MockDockerClient) PluginList(ctx context.Context, filter filters.Args) (types.PluginsListResponse, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).(types.PluginsListResponse), args.Error(1)
}

// PluginPush mocks the PluginPush method
func (m *MockDockerClient) PluginPush(ctx context.Context, name, registryAuth string) (io.ReadCloser, error) {
	args := m.Called(ctx, name, registryAuth)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// PluginRemove mocks the PluginRemove method
func (m *MockDockerClient) PluginRemove(ctx context.Context, name string, options types.PluginRemoveOptions) error {
	args := m.Called(ctx, name, options)
	return args.Error(0)
}

// PluginSet mocks the PluginSet method
func (m *MockDockerClient) PluginSet(ctx context.Context, name string, args []string) error {
	mArgs := m.Called(ctx, name, args) // Renamed internal variable to avoid conflict
	return mArgs.Error(0)
}

// PluginUpgrade mocks the PluginUpgrade method
func (m *MockDockerClient) PluginUpgrade(ctx context.Context, name string, options types.PluginInstallOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, name, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// RegistryLogin mocks the RegistryLogin method
func (m *MockDockerClient) RegistryLogin(ctx context.Context, auth registry.AuthConfig) (registry.AuthenticateOKBody, error) { // Use registry.AuthConfig
	args := m.Called(ctx, auth)
	return args.Get(0).(registry.AuthenticateOKBody), args.Error(1)
}

// SecretCreate mocks the SecretCreate method
func (m *MockDockerClient) SecretCreate(ctx context.Context, secret swarm.SecretSpec) (types.SecretCreateResponse, error) {
	args := m.Called(ctx, secret)
	return args.Get(0).(types.SecretCreateResponse), args.Error(1)
}

// SecretInspectWithRaw mocks the SecretInspectWithRaw method
func (m *MockDockerClient) SecretInspectWithRaw(ctx context.Context, id string) (swarm.Secret, []byte, error) {
	args := m.Called(ctx, id)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(swarm.Secret), data, args.Error(2)
}

// SecretList mocks the SecretList method
func (m *MockDockerClient) SecretList(ctx context.Context, options types.SecretListOptions) ([]swarm.Secret, error) {
	args := m.Called(ctx, options)
	var secrets []swarm.Secret
	if args.Get(0) != nil {
		secrets = args.Get(0).([]swarm.Secret)
	}
	return secrets, args.Error(1)
}

// SecretRemove mocks the SecretRemove method
func (m *MockDockerClient) SecretRemove(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// SecretUpdate mocks the SecretUpdate method
func (m *MockDockerClient) SecretUpdate(ctx context.Context, id string, version swarm.Version, secret swarm.SecretSpec) error {
	args := m.Called(ctx, id, version, secret)
	return args.Error(0)
}

// ServerVersion mocks the ServerVersion method
func (m *MockDockerClient) ServerVersion(ctx context.Context) (types.Version, error) {
	args := m.Called(ctx)
	return args.Get(0).(types.Version), args.Error(1)
}

// ServiceCreate mocks the ServiceCreate method
func (m *MockDockerClient) ServiceCreate(ctx context.Context, service swarm.ServiceSpec, options types.ServiceCreateOptions) (swarm.ServiceCreateResponse, error) { // Use swarm.ServiceCreateResponse
	args := m.Called(ctx, service, options)
	return args.Get(0).(swarm.ServiceCreateResponse), args.Error(1) // Use swarm.ServiceCreateResponse
}

// ServiceInspectWithRaw mocks the ServiceInspectWithRaw method
func (m *MockDockerClient) ServiceInspectWithRaw(ctx context.Context, serviceID string, options types.ServiceInspectOptions) (swarm.Service, []byte, error) {
	args := m.Called(ctx, serviceID, options)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(swarm.Service), data, args.Error(2)
}

// ServiceList mocks the ServiceList method
func (m *MockDockerClient) ServiceList(ctx context.Context, options types.ServiceListOptions) ([]swarm.Service, error) {
	args := m.Called(ctx, options)
	var services []swarm.Service
	if args.Get(0) != nil {
		services = args.Get(0).([]swarm.Service)
	}
	return services, args.Error(1)
}

// ServiceLogs mocks the ServiceLogs method
func (m *MockDockerClient) ServiceLogs(ctx context.Context, serviceID string, options container.LogsOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, serviceID, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// ServiceRemove mocks the ServiceRemove method
func (m *MockDockerClient) ServiceRemove(ctx context.Context, serviceID string) error {
	args := m.Called(ctx, serviceID)
	return args.Error(0)
}

// ServiceUpdate mocks the ServiceUpdate method
func (m *MockDockerClient) ServiceUpdate(ctx context.Context, serviceID string, version swarm.Version, service swarm.ServiceSpec, options types.ServiceUpdateOptions) (swarm.ServiceUpdateResponse, error) { // Use swarm.ServiceUpdateResponse
	args := m.Called(ctx, serviceID, version, service, options)
	return args.Get(0).(swarm.ServiceUpdateResponse), args.Error(1) // Use swarm.ServiceUpdateResponse
}

// SwarmGetUnlockKey mocks the SwarmGetUnlockKey method
func (m *MockDockerClient) SwarmGetUnlockKey(ctx context.Context) (types.SwarmUnlockKeyResponse, error) {
	args := m.Called(ctx)
	return args.Get(0).(types.SwarmUnlockKeyResponse), args.Error(1)
}

// SwarmInit mocks the SwarmInit method
func (m *MockDockerClient) SwarmInit(ctx context.Context, req swarm.InitRequest) (string, error) {
	args := m.Called(ctx, req)
	return args.String(0), args.Error(1)
}

// SwarmInspect mocks the SwarmInspect method
func (m *MockDockerClient) SwarmInspect(ctx context.Context) (swarm.Swarm, error) {
	args := m.Called(ctx)
	return args.Get(0).(swarm.Swarm), args.Error(1)
}

// SwarmJoin mocks the SwarmJoin method
func (m *MockDockerClient) SwarmJoin(ctx context.Context, req swarm.JoinRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

// SwarmLeave mocks the SwarmLeave method
func (m *MockDockerClient) SwarmLeave(ctx context.Context, force bool) error {
	args := m.Called(ctx, force)
	return args.Error(0)
}

// SwarmUnlock mocks the SwarmUnlock method
func (m *MockDockerClient) SwarmUnlock(ctx context.Context, req swarm.UnlockRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

// SwarmUpdate mocks the SwarmUpdate method
func (m *MockDockerClient) SwarmUpdate(ctx context.Context, version swarm.Version, swarm swarm.Spec, flags swarm.UpdateFlags) error {
	args := m.Called(ctx, version, swarm, flags)
	return args.Error(0)
}

// TaskInspectWithRaw mocks the TaskInspectWithRaw method
func (m *MockDockerClient) TaskInspectWithRaw(ctx context.Context, taskID string) (swarm.Task, []byte, error) {
	args := m.Called(ctx, taskID)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(swarm.Task), data, args.Error(2)
}

// TaskList mocks the TaskList method
func (m *MockDockerClient) TaskList(ctx context.Context, options types.TaskListOptions) ([]swarm.Task, error) {
	args := m.Called(ctx, options)
	var tasks []swarm.Task
	if args.Get(0) != nil {
		tasks = args.Get(0).([]swarm.Task)
	}
	return tasks, args.Error(1)
}

// TaskLogs mocks the TaskLogs method
func (m *MockDockerClient) TaskLogs(ctx context.Context, taskID string, options container.LogsOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, taskID, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// VolumeCreate mocks the VolumeCreate method
func (m *MockDockerClient) VolumeCreate(ctx context.Context, options volume.CreateOptions) (volume.Volume, error) { // Use volume.Volume
	args := m.Called(ctx, options)
	return args.Get(0).(volume.Volume), args.Error(1) // Use volume.Volume
}

// VolumeInspect mocks the VolumeInspect method
func (m *MockDockerClient) VolumeInspect(ctx context.Context, volumeID string) (volume.Volume, error) { // Use volume.Volume
	args := m.Called(ctx, volumeID)
	return args.Get(0).(volume.Volume), args.Error(1) // Use volume.Volume
}

// VolumeInspectWithRaw mocks the VolumeInspectWithRaw method
func (m *MockDockerClient) VolumeInspectWithRaw(ctx context.Context, volumeID string) (volume.Volume, []byte, error) { // Use volume.Volume
	args := m.Called(ctx, volumeID)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(volume.Volume), data, args.Error(2) // Use volume.Volume
}

// VolumeList mocks the VolumeList method
func (m *MockDockerClient) VolumeList(ctx context.Context, options volume.ListOptions) (volume.ListResponse, error) { // Use volume.ListOptions
	args := m.Called(ctx, options) // Use options
	return args.Get(0).(volume.ListResponse), args.Error(1)
}

// VolumeRemove mocks the VolumeRemove method
func (m *MockDockerClient) VolumeRemove(ctx context.Context, volumeID string, force bool) error {
	args := m.Called(ctx, volumeID, force)
	return args.Error(0)
}

// VolumeUpdate mocks the VolumeUpdate method
func (m *MockDockerClient) VolumeUpdate(ctx context.Context, volumeID string, version swarm.Version, options volume.UpdateOptions) error {
	args := m.Called(ctx, volumeID, version, options)
	return args.Error(0)
}

// VolumesPrune mocks the VolumesPrune method
func (m *MockDockerClient) VolumesPrune(ctx context.Context, pruneFilter filters.Args) (volume.PruneReport, error) { // Use volume.PruneReport
	args := m.Called(ctx, pruneFilter)
	return args.Get(0).(volume.PruneReport), args.Error(1) // Use volume.PruneReport
}

func TestNewManager(t *testing.T) {
	mockClient := new(MockDockerClient)
	logger := logrus.New()

	// Create a new manager
	manager := NewManager(mockClient, logger)

	// Verify manager is properly initialized
	assert.NotNil(t, manager, "Manager should not be nil")
	assert.Equal(t, mockClient, manager.client, "Client should be set")
	assert.Equal(t, logger, manager.logger, "Logger should be set")
	assert.NotNil(t, manager.containers, "Containers map should be initialized")
	assert.NotNil(t, manager.eventHandlers, "Event handlers map should be initialized")
	assert.NotNil(t, manager.watchContext, "Watch context should be initialized")
	assert.NotNil(t, manager.watchCancel, "Watch cancel function should be initialized")
	assert.False(t, manager.isWatching, "Manager should not be watching initially")
}

func TestIsValidTransition(t *testing.T) {
	mockClient := new(MockDockerClient)
	manager := NewManager(mockClient, nil)

	testCases := []struct {
		fromState ContainerState
		toState   ContainerState
		expected  bool
	}{
		{StateCreated, StateRunning, true},
		{StateCreated, StateRemoving, false}, // Invalid transition - Use StateRemoving
		{StateRunning, StatePaused, true},
		{StateRunning, StateExited, true},
		{StatePaused, StateRunning, true},
		{StateExited, StateRunning, true},
		{StateExited, StatePaused, false}, // Invalid transition
		{StateRestarting, StateRunning, true},
		{StateUnknown, StateRunning, true}, // Can transition from unknown to any state
	}

	for _, tc := range testCases {
		t.Run(string(tc.fromState)+"->"+string(tc.toState), func(t *testing.T) {
			result := manager.IsValidTransition(tc.fromState, tc.toState)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetState(t *testing.T) {
	mockClient := new(MockDockerClient)
	manager := NewManager(mockClient, nil)

	containerID := "test-container"
	containerJSON := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: containerID,
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
			},
		},
	}

	// Setup mock
	mockClient.On("ContainerInspect", mock.Anything, containerID).Return(containerJSON, nil).Once()

	// Get state
	state, err := manager.GetState(containerID)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, StateRunning, state)
	mockClient.AssertExpectations(t)

	// Test cached value
	state, err = manager.GetState(containerID)
	assert.NoError(t, err)
	assert.Equal(t, StateRunning, state)
	// Mock should not be called again
	mockClient.AssertExpectations(t)
}

func TestUpdateState(t *testing.T) {
	manager := NewManager(nil, nil)

	containerID := "test-container"

	// Initialize state to created
	err := manager.UpdateState(containerID, StateCreated)
	assert.NoError(t, err)

	// Verify state was set
	info, _ := manager.GetContainerInfo(containerID)
	assert.Equal(t, StateCreated, info.CurrentState)
	assert.Equal(t, StateUnknown, info.PreviousState) // Initial state is unknown

	// Update to running (valid transition)
	err = manager.UpdateState(containerID, StateRunning)
	assert.NoError(t, err)

	// Verify state was updated
	info, _ = manager.GetContainerInfo(containerID)
	assert.Equal(t, StateRunning, info.CurrentState)
	assert.Equal(t, StateCreated, info.PreviousState)

	// Test invalid transition
	err = manager.UpdateState(containerID, StateDead)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidStateTransition)

	// Verify state was not changed
	info, _ = manager.GetContainerInfo(containerID)
	assert.Equal(t, StateRunning, info.CurrentState)
}

func TestRegisterStateChangeHandler(t *testing.T) {
	manager := NewManager(nil, nil)

	containerID := "test-container"
	handlerDone := make(chan bool) // Use a channel for synchronization

	// Register handler for running state
	manager.RegisterStateChangeHandler(StateRunning, func(id string, oldState, newState ContainerState, info *ContainerInfo) {
		assert.Equal(t, containerID, id)
		assert.Equal(t, StateCreated, oldState)
		assert.Equal(t, StateRunning, newState)
		handlerDone <- true // Signal completion
	})

	// Initialize state to created
	_ = manager.UpdateState(containerID, StateCreated)

	// Update to running
	_ = manager.UpdateState(containerID, StateRunning)

	// Wait for handler to be called using the channel
	select {
	case <-handlerDone:
		// Handler completed successfully
	case <-time.After(1 * time.Second): // Add a timeout
		t.Fatal("Handler was not called within the timeout period")
	}

	// Verification is implicit by receiving from the channel
}

func TestHandleEvent(t *testing.T) {
	mockClient := new(MockDockerClient)
	manager := NewManager(mockClient, nil)

	containerID := "test-container"

	// Create mock inspect response
	containerJSON := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: containerID,
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
			},
		},
	}

	// Set up mock
	mockClient.On("ContainerInspect", mock.Anything, containerID).Return(containerJSON, nil).Once()

	// Create mock event
	event := events.Message{
		Type:   "container",
		Action: "start",
		ID:     containerID,
	}

	// Handle event
	manager.handleEvent(event)

	// Verify state was updated
	info, err := manager.GetContainerInfo(containerID)
	assert.NoError(t, err)
	assert.Equal(t, StateRunning, info.CurrentState)

	// Test health status event
	mockClient.On("ContainerInspect", mock.Anything, containerID).Return(containerJSON, nil).Once()
	healthEvent := events.Message{
		Type:   "container",
		Action: "health_status",
		ID:     containerID,
		Actor: events.Actor{
			Attributes: map[string]string{
				"health_status": "healthy",
			},
		},
	}

	// Handle health event
	manager.handleEvent(healthEvent)

	// Verify health status was updated
	info, err = manager.GetContainerInfo(containerID)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", info.HealthStatus)
}

func TestStartAndStopWatching(t *testing.T) {
	mockClient := new(MockDockerClient)
	manager := NewManager(mockClient, nil)

	eventCh := make(chan events.Message)
	errCh := make(chan error)

	// Set up mock for Events call
	mockClient.On("Events", mock.Anything, mock.Anything).Return((<-chan events.Message)(eventCh), (<-chan error)(errCh))

	// Mock container list
	mockClient.On("ContainerList", mock.Anything, mock.Anything).Return([]types.Container{}, nil)

	// Start watching
	err := manager.StartWatching()
	require.NoError(t, err)
	assert.True(t, manager.isWatching)

	// Stop watching
	manager.StopWatching()
	assert.False(t, manager.isWatching)

	// Close channels
	close(eventCh)
	close(errCh)
}

func TestListContainers(t *testing.T) {
	manager := NewManager(nil, nil)

	// Add some containers
	_ = manager.UpdateState("container1", StateCreated)
	_ = manager.UpdateState("container2", StateRunning)
	_ = manager.UpdateState("container3", StateExited)

	// List containers
	containers := manager.ListContainers()

	// Verify
	assert.Len(t, containers, 3)
	assert.Equal(t, StateCreated, containers["container1"])
	assert.Equal(t, StateRunning, containers["container2"])
	assert.Equal(t, StateExited, containers["container3"])
}

func TestMapDockerStateToContainerState(t *testing.T) {
	testCases := []struct {
		dockerState *types.ContainerState
		expected    ContainerState
	}{
		{nil, StateUnknown},
		{&types.ContainerState{Status: "created"}, StateCreated},
		{&types.ContainerState{Running: true}, StateRunning},
		{&types.ContainerState{Paused: true}, StatePaused},
		{&types.ContainerState{Restarting: true}, StateRestarting},
		{&types.ContainerState{Dead: true}, StateDead},
		{&types.ContainerState{Status: "removing"}, StateRemoving},
		{&types.ContainerState{Status: "exited"}, StateExited},
		{&types.ContainerState{Status: "unknown"}, StateUnknown},
	}

	for _, tc := range testCases {
		result := mapDockerStateToContainerState(tc.dockerState)
		assert.Equal(t, tc.expected, result)
	}
}

func TestInitializeContainerStates(t *testing.T) {
	mockClient := new(MockDockerClient)
	manager := NewManager(mockClient, nil)

	// Create mock containers
	containers := []types.Container{
		{ID: "container1"},
		{ID: "container2"},
	}

	// Create mock container JSON responses
	container1JSON := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: "container1",
			State: &types.ContainerState{
				Status:  "running",
				Running: true,
			},
		},
	}

	container2JSON := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID: "container2",
			State: &types.ContainerState{
				Status: "exited",
			},
		},
	}

	// Set up mocks
	mockClient.On("ContainerList", mock.Anything, mock.Anything).Return(containers, nil)
	mockClient.On("ContainerInspect", mock.Anything, "container1").Return(container1JSON, nil)
	mockClient.On("ContainerInspect", mock.Anything, "container2").Return(container2JSON, nil)

	// Initialize container states
	err := manager.initializeContainerStates()
	assert.NoError(t, err)

	// Verify states were initialized
	states := manager.ListContainers()
	assert.Len(t, states, 2)
	assert.Equal(t, StateRunning, states["container1"])
	assert.Equal(t, StateExited, states["container2"])
}
