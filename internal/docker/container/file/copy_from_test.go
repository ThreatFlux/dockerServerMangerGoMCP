package file

import (
	"archive/tar"
	"bufio" // Added import
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"      // Added http import
	"os"            // Keep for os.FileMode, os.MkdirTemp, os.RemoveAll, os.ReadFile
	"path/filepath" // Keep for Join
	"testing"
	"time"

	"net"

	types "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/checkpoint"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events" // Added events import
	"github.com/docker/docker/api/types/filters"
	apiimage "github.com/docker/docker/api/types/image"     // Use apiimage alias
	apinetwork "github.com/docker/docker/api/types/network" // Use apinetwork alias
	"github.com/docker/docker/api/types/registry"
	swarm "github.com/docker/docker/api/types/swarm" // Use swarm alias
	"github.com/docker/docker/api/types/system"      // Use system alias
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"                          // Import the actual client package
	ocispec "github.com/opencontainers/image-spec/specs-go/v1" // Use ocispec alias
	"github.com/sirupsen/logrus"                               // Re-added logrus import
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock net.Conn for HijackedResponse
type mockNetConn struct{}

func (m *mockNetConn) Read(b []byte) (n int, err error)   { return 0, io.EOF }
func (m *mockNetConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockNetConn) Close() error                       { return nil } // Important: No-op close
func (m *mockNetConn) LocalAddr() net.Addr                { return nil }
func (m *mockNetConn) RemoteAddr() net.Addr               { return nil }
func (m *mockNetConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockNetConn) SetWriteDeadline(t time.Time) error { return nil }

// MockDockerClient is a mock implementation of the client.APIClient interface for testing
type MockDockerClient struct {
	mock.Mock
}

// Ensure MockDockerClient implements client.APIClient (compile-time check)
var _ client.APIClient = (*MockDockerClient)(nil)

// --- MOCK METHODS ---
// Corrected signatures based on previous findings and standard SDK structure

func (m *MockDockerClient) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) { // Use types
	args := m.Called(ctx, containerID)
	return args.Get(0).(types.ContainerJSON), args.Error(1) // Use types
}

func (m *MockDockerClient) ContainerList(ctx context.Context, options container.ListOptions) ([]types.Container, error) { // Use types
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]types.Container), args.Error(1) // Use types
}

func (m *MockDockerClient) ContainerStatPath(ctx context.Context, containerID, path string) (container.PathStat, error) {
	args := m.Called(ctx, containerID, path)
	return args.Get(0).(container.PathStat), args.Error(1)
}

func (m *MockDockerClient) CopyFromContainer(ctx context.Context, containerID, srcPath string) (io.ReadCloser, container.PathStat, error) {
	args := m.Called(ctx, containerID, srcPath)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Get(1).(container.PathStat), args.Error(2)
}

func (m *MockDockerClient) CopyToContainer(ctx context.Context, containerID, path string, content io.Reader, options container.CopyToContainerOptions) error {
	args := m.Called(ctx, containerID, path, content, options)
	return args.Error(0)
}

// Add other required methods from client.APIClient with correct signatures
func (m *MockDockerClient) BuildCachePrune(ctx context.Context, opts types.BuildCachePruneOptions) (*types.BuildCachePruneReport, error) { // Use types
	args := m.Called(ctx, opts)
	var report *types.BuildCachePruneReport // Use types
	if args.Get(0) != nil {
		report = args.Get(0).(*types.BuildCachePruneReport) // Use types
	}
	return report, args.Error(1)
}
func (m *MockDockerClient) BuildCancel(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
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
	var summaries []checkpoint.Summary
	if args.Get(0) != nil {
		summaries = args.Get(0).([]checkpoint.Summary)
	}
	return summaries, args.Error(1)
}
func (m *MockDockerClient) ClientVersion() string {
	args := m.Called()
	return args.String(0)
}
func (m *MockDockerClient) Close() error {
	args := m.Called()
	return args.Error(0)
}
func (m *MockDockerClient) ConfigCreate(ctx context.Context, config swarm.ConfigSpec) (types.ConfigCreateResponse, error) { // Use types
	args := m.Called(ctx, config)
	return args.Get(0).(types.ConfigCreateResponse), args.Error(1) // Use types
}

func (m *MockDockerClient) ConfigInspectWithRaw(ctx context.Context, id string) (swarm.Config, []byte, error) {
	args := m.Called(ctx, id) // Added missing m.Called
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(swarm.Config), data, args.Error(2)
}
func (m *MockDockerClient) ConfigList(ctx context.Context, options types.ConfigListOptions) ([]swarm.Config, error) { // Use types
	args := m.Called(ctx, options)
	var configs []swarm.Config
	if args.Get(0) != nil {
		configs = args.Get(0).([]swarm.Config)
	}
	return configs, args.Error(1)
}
func (m *MockDockerClient) ConfigRemove(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockDockerClient) ConfigUpdate(ctx context.Context, id string, version swarm.Version, config swarm.ConfigSpec) error {
	args := m.Called(ctx, id, version, config)
	return args.Error(0)
}
func (m *MockDockerClient) ContainerAttach(ctx context.Context, containerID string, options container.AttachOptions) (types.HijackedResponse, error) { // Use types
	args := m.Called(ctx, containerID, options)
	return args.Get(0).(types.HijackedResponse), args.Error(1) // Use types
}

func (m *MockDockerClient) ContainerCommit(ctx context.Context, containerID string, options container.CommitOptions) (types.IDResponse, error) { // Use types
	args := m.Called(ctx, containerID, options)          // Added missing m.Called
	return args.Get(0).(types.IDResponse), args.Error(1) // Use types
}
func (m *MockDockerClient) ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *apinetwork.NetworkingConfig, platform *ocispec.Platform, containerName string) (container.CreateResponse, error) {
	args := m.Called(ctx, config, hostConfig, networkingConfig, platform, containerName)
	var resp container.CreateResponse
	if args.Get(0) != nil {
		resp = args.Get(0).(container.CreateResponse)
	}
	return resp, args.Error(1)
}
func (m *MockDockerClient) ContainerDiff(ctx context.Context, containerID string) ([]container.FilesystemChange, error) {
	args := m.Called(ctx, containerID)
	var changes []container.FilesystemChange
	if args.Get(0) != nil {
		changes = args.Get(0).([]container.FilesystemChange)
	}
	return changes, args.Error(1)
}
func (m *MockDockerClient) ContainerExecAttach(ctx context.Context, execID string, config container.ExecStartOptions) (types.HijackedResponse, error) { // Use types
	args := m.Called(ctx, execID, config)
	return args.Get(0).(types.HijackedResponse), args.Error(1) // Use types
}

func (m *MockDockerClient) ContainerExecCreate(ctx context.Context, containerID string, options container.ExecOptions) (types.IDResponse, error) { // Use types
	args := m.Called(ctx, containerID, options)          // Added missing m.Called
	return args.Get(0).(types.IDResponse), args.Error(1) // Use types
}
func (m *MockDockerClient) ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error) {
	args := m.Called(ctx, execID)
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
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}
func (m *MockDockerClient) ContainerInspectWithRaw(ctx context.Context, containerID string, size bool) (types.ContainerJSON, []byte, error) { // Use types
	args := m.Called(ctx, containerID, size)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(types.ContainerJSON), data, args.Error(2) // Use types
}

// Add ContainerLogs method
func (m *MockDockerClient) ContainerLogs(ctx context.Context, containerID string, options container.LogsOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, containerID, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
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
func (m *MockDockerClient) ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}
func (m *MockDockerClient) ContainerStats(ctx context.Context, containerID string, stream bool) (container.StatsResponseReader, error) { // Corrected return type
	args := m.Called(ctx, containerID, stream)
	var reader container.StatsResponseReader // Corrected variable type
	if args.Get(0) != nil {
		reader = args.Get(0).(container.StatsResponseReader) // Corrected type assertion
	}
	return reader, args.Error(1)
}
func (m *MockDockerClient) ContainerStatsOneShot(ctx context.Context, containerID string) (container.StatsResponseReader, error) {
	args := m.Called(ctx, containerID)
	return args.Get(0).(container.StatsResponseReader), args.Error(1)
}

// Add ContainerTop method
func (m *MockDockerClient) ContainerTop(ctx context.Context, containerID string, arguments []string) (container.ContainerTopOKBody, error) {
	args := m.Called(ctx, containerID, arguments)
	var body container.ContainerTopOKBody
	if args.Get(0) != nil {
		body = args.Get(0).(container.ContainerTopOKBody)
	}
	return body, args.Error(1)
}

func (m *MockDockerClient) ContainerStop(ctx context.Context, containerID string, options container.StopOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}
func (m *MockDockerClient) ContainerUnpause(ctx context.Context, containerID string) error {
	args := m.Called(ctx, containerID)
	return args.Error(0)
}
func (m *MockDockerClient) ContainerUpdate(ctx context.Context, containerID string, updateConfig container.UpdateConfig) (container.ContainerUpdateOKBody, error) {
	args := m.Called(ctx, containerID, updateConfig)
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
	return args.Get(0).(container.PruneReport), args.Error(1)
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
	return args.Get(0).(types.DiskUsage), args.Error(1) // Use types
}

func (m *MockDockerClient) Events(ctx context.Context, options events.ListOptions) (<-chan events.Message, <-chan error) {
	args := m.Called(ctx, options)
	var msgCh chan events.Message
	var errCh chan error
	if args.Get(0) != nil {
		msgCh = args.Get(0).(chan events.Message)
	}
	if args.Get(1) != nil {
		errCh = args.Get(1).(chan error)
	}
	return msgCh, errCh
}

// Add HTTPClient method
func (m *MockDockerClient) HTTPClient() *http.Client {
	args := m.Called()
	if args.Get(0) != nil {
		return args.Get(0).(*http.Client)
	}
	return nil // Or return a default client if needed
}

func (m *MockDockerClient) DistributionInspect(ctx context.Context, image, encodedAuth string) (registry.DistributionInspect, error) {
	args := m.Called(ctx, image, encodedAuth)
	return args.Get(0).(registry.DistributionInspect), args.Error(1)
}
func (m *MockDockerClient) ImageBuild(ctx context.Context, buildContext io.Reader, options types.ImageBuildOptions) (types.ImageBuildResponse, error) { // Use types
	args := m.Called(ctx, buildContext, options)
	return args.Get(0).(types.ImageBuildResponse), args.Error(1) // Use types
}

func (m *MockDockerClient) ImageCreate(ctx context.Context, parentReference string, options apiimage.CreateOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, parentReference, options) // Added missing m.Called
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}
func (m *MockDockerClient) ImageHistory(ctx context.Context, imageID string, options ...client.ImageHistoryOption) ([]apiimage.HistoryResponseItem, error) { // Added options parameter
	// Convert variadic options to a slice of interface{} for m.Called
	optsSlice := make([]interface{}, len(options))
	for i, opt := range options {
		optsSlice[i] = opt
	}
	args := m.Called(append([]interface{}{ctx, imageID}, optsSlice...)...)
	var history []apiimage.HistoryResponseItem
	if args.Get(0) != nil {
		history = args.Get(0).([]apiimage.HistoryResponseItem)
	}
	return history, args.Error(1)
}
func (m *MockDockerClient) ImageImport(ctx context.Context, source apiimage.ImportSource, ref string, options apiimage.ImportOptions) (io.ReadCloser, error) { // Changed source type to apiimage.ImportSource
	args := m.Called(ctx, source, ref, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

// Add ImageInspect method - Corrected Signature
func (m *MockDockerClient) ImageInspect(ctx context.Context, imageID string, options ...client.ImageInspectOption) (apiimage.InspectResponse, error) {
	// Convert variadic options to a slice of interface{} for m.Called
	optsSlice := make([]interface{}, len(options))
	for i, opt := range options {
		optsSlice[i] = opt
	}
	args := m.Called(append([]interface{}{ctx, imageID}, optsSlice...)...)
	var inspect apiimage.InspectResponse
	if args.Get(0) != nil {
		inspect = args.Get(0).(apiimage.InspectResponse)
	}
	return inspect, args.Error(1)
}

func (m *MockDockerClient) ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error) { // Use types
	args := m.Called(ctx, imageID)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(types.ImageInspect), data, args.Error(2) // Use types
}

// Add ImageList method
func (m *MockDockerClient) ImageList(ctx context.Context, options apiimage.ListOptions) ([]apiimage.Summary, error) {
	args := m.Called(ctx, options)
	var summaries []apiimage.Summary
	if args.Get(0) != nil {
		summaries = args.Get(0).([]apiimage.Summary)
	}
	return summaries, args.Error(1)
}

func (m *MockDockerClient) ImageLoad(ctx context.Context, input io.Reader, options ...client.ImageLoadOption) (apiimage.LoadResponse, error) { // Corrected signature
	// Convert variadic options to a slice of interface{} for m.Called
	optsSlice := make([]interface{}, len(options))
	for i, opt := range options {
		optsSlice[i] = opt
	}
	args := m.Called(append([]interface{}{ctx, input}, optsSlice...)...)
	return args.Get(0).(apiimage.LoadResponse), args.Error(1) // Use apiimage.LoadResponse
}

func (m *MockDockerClient) ImagePull(ctx context.Context, refStr string, options apiimage.PullOptions) (io.ReadCloser, error) { // Corrected signature
	args := m.Called(ctx, refStr, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}

func (m *MockDockerClient) ImagePush(ctx context.Context, refStr string, options apiimage.PushOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, refStr, options) // Added missing m.Called
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}
func (m *MockDockerClient) ImageRemove(ctx context.Context, imageID string, options apiimage.RemoveOptions) ([]apiimage.DeleteResponse, error) {
	args := m.Called(ctx, imageID, options)
	var items []apiimage.DeleteResponse
	if args.Get(0) != nil {
		items = args.Get(0).([]apiimage.DeleteResponse)
	}
	return items, args.Error(1)
}
func (m *MockDockerClient) ImageSave(ctx context.Context, imageIDs []string, options ...client.ImageSaveOption) (io.ReadCloser, error) { // Added options parameter
	// Convert variadic options to a slice of interface{} for m.Called
	optsSlice := make([]interface{}, len(options))
	for i, opt := range options {
		optsSlice[i] = opt
	}
	args := m.Called(append([]interface{}{ctx, imageIDs}, optsSlice...)...)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}
func (m *MockDockerClient) ImageSearch(ctx context.Context, term string, options registry.SearchOptions) ([]registry.SearchResult, error) {
	args := m.Called(ctx, term, options)
	var results []registry.SearchResult
	if args.Get(0) != nil {
		results = args.Get(0).([]registry.SearchResult)
	}
	return results, args.Error(1)
}
func (m *MockDockerClient) ImageTag(ctx context.Context, source, target string) error {
	args := m.Called(ctx, source, target)
	return args.Error(0)
}
func (m *MockDockerClient) ImagesPrune(ctx context.Context, pruneFilter filters.Args) (apiimage.PruneReport, error) { // Use apiimage.PruneReport
	args := m.Called(ctx, pruneFilter)
	return args.Get(0).(apiimage.PruneReport), args.Error(1) // Use apiimage.PruneReport
}

func (m *MockDockerClient) Info(ctx context.Context) (system.Info, error) { // Use system.Info
	args := m.Called(ctx) // Added missing m.Called
	var info system.Info  // Use system.Info
	if args.Get(0) != nil {
		info = args.Get(0).(system.Info) // Use system.Info
	}
	return info, args.Error(1)
}
func (m *MockDockerClient) NegotiateAPIVersion(ctx context.Context) { m.Called(ctx) }
func (m *MockDockerClient) NegotiateAPIVersionPing(ping types.Ping) { m.Called(ping) } // Use types
func (m *MockDockerClient) NetworkConnect(ctx context.Context, networkID, containerID string, config *apinetwork.EndpointSettings) error {
	args := m.Called(ctx, networkID, containerID, config)
	return args.Error(0)
}
func (m *MockDockerClient) NetworkCreate(ctx context.Context, name string, options apinetwork.CreateOptions) (apinetwork.CreateResponse, error) { // Added NetworkCreate
	args := m.Called(ctx, name, options)
	return args.Get(0).(apinetwork.CreateResponse), args.Error(1)
}
func (m *MockDockerClient) NetworkDisconnect(ctx context.Context, networkID, containerID string, force bool) error {
	args := m.Called(ctx, networkID, containerID, force)
	return args.Error(0)
}
func (m *MockDockerClient) NetworkInspect(ctx context.Context, networkID string, options apinetwork.InspectOptions) (apinetwork.Inspect, error) { // Added NetworkInspect
	args := m.Called(ctx, networkID, options)
	return args.Get(0).(apinetwork.Inspect), args.Error(1)
}
func (m *MockDockerClient) NetworkInspectWithRaw(ctx context.Context, networkID string, options apinetwork.InspectOptions) (apinetwork.Inspect, []byte, error) { // Use apinetwork.Inspect
	args := m.Called(ctx, networkID, options)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	var res apinetwork.Inspect // Use apinetwork.Inspect
	if args.Get(0) != nil {
		res = args.Get(0).(apinetwork.Inspect) // Use apinetwork.Inspect
	}
	return res, data, args.Error(2)
}
func (m *MockDockerClient) NetworkList(ctx context.Context, options apinetwork.ListOptions) ([]apinetwork.Summary, error) { // Use apinetwork.Summary
	args := m.Called(ctx, options)
	var summaries []apinetwork.Summary // Use apinetwork.Summary
	if args.Get(0) != nil {
		summaries = args.Get(0).([]apinetwork.Summary) // Use apinetwork.Summary
	}
	return summaries, args.Error(1)
}
func (m *MockDockerClient) NetworkRemove(ctx context.Context, networkID string) error { // Added NetworkRemove
	args := m.Called(ctx, networkID)
	return args.Error(0)
}
func (m *MockDockerClient) NetworksPrune(ctx context.Context, pruneFilter filters.Args) (apinetwork.PruneReport, error) { // Use apinetwork.PruneReport
	args := m.Called(ctx, pruneFilter)
	return args.Get(0).(apinetwork.PruneReport), args.Error(1) // Use apinetwork.PruneReport
}
func (m *MockDockerClient) NodeInspectWithRaw(ctx context.Context, nodeID string) (swarm.Node, []byte, error) {
	args := m.Called(ctx, nodeID) // Added missing m.Called
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(swarm.Node), data, args.Error(2)
}
func (m *MockDockerClient) NodeList(ctx context.Context, options types.NodeListOptions) ([]swarm.Node, error) { // Use types
	args := m.Called(ctx, options)
	var nodes []swarm.Node
	if args.Get(0) != nil {
		nodes = args.Get(0).([]swarm.Node)
	}
	return nodes, args.Error(1)
}
func (m *MockDockerClient) NodeRemove(ctx context.Context, nodeID string, options types.NodeRemoveOptions) error { // Use types
	args := m.Called(ctx, nodeID, options)
	return args.Error(0)
}
func (m *MockDockerClient) NodeUpdate(ctx context.Context, nodeID string, version swarm.Version, node swarm.NodeSpec) error {
	args := m.Called(ctx, nodeID, version, node)
	return args.Error(0)
}
func (m *MockDockerClient) Ping(ctx context.Context) (types.Ping, error) { // Use types
	args := m.Called(ctx)
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
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}
func (m *MockDockerClient) PluginList(ctx context.Context, filter filters.Args) (types.PluginsListResponse, error) { // Use types
	args := m.Called(ctx, filter)
	return args.Get(0).(types.PluginsListResponse), args.Error(1) // Use types
}
func (m *MockDockerClient) PluginPush(ctx context.Context, name, registryAuth string) (io.ReadCloser, error) {
	args := m.Called(ctx, name, registryAuth)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
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
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}
func (m *MockDockerClient) RegistryLogin(ctx context.Context, auth registry.AuthConfig) (registry.AuthenticateOKBody, error) {
	args := m.Called(ctx, auth)
	return args.Get(0).(registry.AuthenticateOKBody), args.Error(1)
}
func (m *MockDockerClient) SecretCreate(ctx context.Context, secret swarm.SecretSpec) (types.SecretCreateResponse, error) { // Use types
	args := m.Called(ctx, secret)
	return args.Get(0).(types.SecretCreateResponse), args.Error(1) // Use types
}
func (m *MockDockerClient) SecretInspectWithRaw(ctx context.Context, id string) (swarm.Secret, []byte, error) {
	args := m.Called(ctx, id) // Added missing m.Called
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(swarm.Secret), data, args.Error(2)
}
func (m *MockDockerClient) SecretList(ctx context.Context, options types.SecretListOptions) ([]swarm.Secret, error) { // Use types
	args := m.Called(ctx, options)
	var secrets []swarm.Secret
	if args.Get(0) != nil {
		secrets = args.Get(0).([]swarm.Secret)
	}
	return secrets, args.Error(1)
}
func (m *MockDockerClient) SecretRemove(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockDockerClient) SecretUpdate(ctx context.Context, id string, version swarm.Version, secret swarm.SecretSpec) error {
	args := m.Called(ctx, id, version, secret)
	return args.Error(0)
}
func (m *MockDockerClient) ServerVersion(ctx context.Context) (types.Version, error) { // Use types
	args := m.Called(ctx)
	return args.Get(0).(types.Version), args.Error(1) // Use types
}
func (m *MockDockerClient) ServiceCreate(ctx context.Context, service swarm.ServiceSpec, options types.ServiceCreateOptions) (swarm.ServiceCreateResponse, error) { // Use types
	args := m.Called(ctx, service, options)
	return args.Get(0).(swarm.ServiceCreateResponse), args.Error(1)
}
func (m *MockDockerClient) ServiceInspectWithRaw(ctx context.Context, serviceID string, options types.ServiceInspectOptions) (swarm.Service, []byte, error) { // Use types
	args := m.Called(ctx, serviceID, options)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(swarm.Service), data, args.Error(2)
}
func (m *MockDockerClient) ServiceList(ctx context.Context, options types.ServiceListOptions) ([]swarm.Service, error) { // Use types
	args := m.Called(ctx, options)
	var services []swarm.Service
	if args.Get(0) != nil {
		services = args.Get(0).([]swarm.Service)
	}
	return services, args.Error(1)
}
func (m *MockDockerClient) ServiceLogs(ctx context.Context, serviceID string, options container.LogsOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, serviceID, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}
func (m *MockDockerClient) ServiceRemove(ctx context.Context, serviceID string) error {
	args := m.Called(ctx, serviceID)
	return args.Error(0)
}
func (m *MockDockerClient) ServiceUpdate(ctx context.Context, serviceID string, version swarm.Version, service swarm.ServiceSpec, options types.ServiceUpdateOptions) (swarm.ServiceUpdateResponse, error) { // Use types
	args := m.Called(ctx, serviceID, version, service, options)
	return args.Get(0).(swarm.ServiceUpdateResponse), args.Error(1)
}
func (m *MockDockerClient) SwarmGetUnlockKey(ctx context.Context) (types.SwarmUnlockKeyResponse, error) { // Use types
	args := m.Called(ctx)
	return args.Get(0).(types.SwarmUnlockKeyResponse), args.Error(1) // Use types
}
func (m *MockDockerClient) SwarmInit(ctx context.Context, req swarm.InitRequest) (string, error) {
	args := m.Called(ctx, req)
	return args.String(0), args.Error(1)
}
func (m *MockDockerClient) SwarmInspect(ctx context.Context) (swarm.Swarm, error) {
	args := m.Called(ctx)
	return args.Get(0).(swarm.Swarm), args.Error(1)
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
	args := m.Called(ctx, taskID) // Added missing m.Called
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(swarm.Task), data, args.Error(2)
}
func (m *MockDockerClient) TaskList(ctx context.Context, options types.TaskListOptions) ([]swarm.Task, error) { // Use types
	args := m.Called(ctx, options)
	var tasks []swarm.Task
	if args.Get(0) != nil {
		tasks = args.Get(0).([]swarm.Task)
	}
	return tasks, args.Error(1)
}
func (m *MockDockerClient) TaskLogs(ctx context.Context, taskID string, options container.LogsOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, taskID, options)
	var reader io.ReadCloser
	if args.Get(0) != nil {
		reader = args.Get(0).(io.ReadCloser)
	}
	return reader, args.Error(1)
}
func (m *MockDockerClient) VolumeCreate(ctx context.Context, options volume.CreateOptions) (volume.Volume, error) { // Added VolumeCreate
	args := m.Called(ctx, options)
	return args.Get(0).(volume.Volume), args.Error(1)
}
func (m *MockDockerClient) VolumeInspect(ctx context.Context, volumeID string) (volume.Volume, error) { // Added VolumeInspect
	args := m.Called(ctx, volumeID)
	return args.Get(0).(volume.Volume), args.Error(1)
}
func (m *MockDockerClient) VolumeInspectWithRaw(ctx context.Context, volumeID string) (volume.Volume, []byte, error) {
	args := m.Called(ctx, volumeID)
	var data []byte
	if args.Get(1) != nil {
		data = args.Get(1).([]byte)
	}
	return args.Get(0).(volume.Volume), data, args.Error(2)
}
func (m *MockDockerClient) VolumeList(ctx context.Context, options volume.ListOptions) (volume.ListResponse, error) { // Added VolumeList
	args := m.Called(ctx, options)
	return args.Get(0).(volume.ListResponse), args.Error(1)
}
func (m *MockDockerClient) VolumeRemove(ctx context.Context, volumeID string, force bool) error { // Added VolumeRemove
	args := m.Called(ctx, volumeID, force)
	return args.Error(0)
}
func (m *MockDockerClient) VolumeUpdate(ctx context.Context, volumeID string, version swarm.Version, options volume.UpdateOptions) error {
	args := m.Called(ctx, volumeID, version, options)
	return args.Error(0)
}
func (m *MockDockerClient) VolumesPrune(ctx context.Context, pruneFilter filters.Args) (volume.PruneReport, error) { // Changed to volume.PruneReport
	args := m.Called(ctx, pruneFilter)
	return args.Get(0).(volume.PruneReport), args.Error(1) // Changed to volume.PruneReport
}

// --- Test Functions ---

// createTarArchive creates a simple tar archive in memory for testing
func createTarArchive(files map[string]string) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	defer tw.Close()

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// TestCopyFromContainer_ValidInput tests successful file copy from container
func TestCopyFromContainer_ValidInput(t *testing.T) {
	mockClient := new(MockDockerClient)
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel) // Enable debug logging for tests

	// Create a dummy tar archive
	tarBuf, err := createTarArchive(map[string]string{"test.txt": "hello world"})
	require.NoError(t, err)

	// Mock CopyFromContainer
	mockClient.On("CopyFromContainer", mock.Anything, "test-container", "/app/test.txt").
		Return(io.NopCloser(tarBuf), container.PathStat{Name: "test.txt", Size: int64(len("hello world")), Mode: 0644}, nil)

	// Call the top-level function directly
	// Note: The destination path needs to be a directory for extraction
	tempDir, err := os.MkdirTemp("", "copy-test-dest-")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	err = CopyFromContainer(context.Background(), mockClient, "test-container", "/app/test.txt", tempDir, CopyFromOptions{Logger: logger})
	require.NoError(t, err)

	// Verify the extracted file
	extractedFilePath := filepath.Join(tempDir, "test.txt")
	content, err := os.ReadFile(extractedFilePath)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(content))

	mockClient.AssertExpectations(t)
}

// TestCopyFromContainer_ContainerNotFound tests container not found error
func TestCopyFromContainer_ContainerNotFound(t *testing.T) {
	mockClient := new(MockDockerClient)
	logger := logrus.New()

	// Mock ContainerInspect to return a "not found" error
	notFoundErr := errors.New("Error response from daemon: No such container: non-existent-container") // Simulate Docker error
	mockClient.On("ContainerInspect", mock.Anything, "non-existent-container").Return(types.ContainerJSON{}, notFoundErr)

	// Call the top-level function directly
	err := CopyFromContainer(context.Background(), mockClient, "non-existent-container", "/app/test.txt", "/tmp/dest", CopyFromOptions{Logger: logger})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrContainerNotFound) // Check for specific error type

	mockClient.AssertExpectations(t)
}

// TestCopyFromContainer_FileNotFound tests file not found inside container error
func TestCopyFromContainer_FileNotFound(t *testing.T) {
	mockClient := new(MockDockerClient)
	logger := logrus.New()

	// Mock ContainerInspect to succeed
	mockClient.On("ContainerInspect", mock.Anything, "test-container").Return(types.ContainerJSON{}, nil)
	// Mock ContainerStatPath to return a "not found" error
	pathNotFoundErr := errors.New("Error response from daemon: lstat /app/non-existent.txt: no such file or directory") // Simulate Docker error
	mockClient.On("ContainerStatPath", mock.Anything, "test-container", "/app/non-existent.txt").
		Return(container.PathStat{}, pathNotFoundErr)

	// Call the top-level function directly
	err := CopyFromContainer(context.Background(), mockClient, "test-container", "/app/non-existent.txt", "/tmp/dest", CopyFromOptions{Logger: logger})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path not found in container") // Check for specific error text

	mockClient.AssertExpectations(t)
}

// TestListContainerFiles tests listing files in a container directory
func TestListContainerFiles(t *testing.T) {
	mockClient := new(MockDockerClient)
	// logger := logrus.New() // logger is unused

	// Mock ContainerExecCreate
	mockClient.On("ContainerExecCreate", mock.Anything, "test-container", mock.AnythingOfType("container.ExecOptions")).
		Return(types.IDResponse{ID: "exec-id-123"}, nil)

	// Mock ContainerExecAttach to return the file list
	fileListOutput := "file1.txt\nsubdir\nfile2.log"
	mockReader := io.NopCloser(bytes.NewReader([]byte(fileListOutput)))
	mockHijack := types.HijackedResponse{Reader: bufio.NewReader(mockReader), Conn: &mockNetConn{}} // Use mockNetConn
	mockClient.On("ContainerExecAttach", mock.Anything, "exec-id-123", mock.AnythingOfType("container.ExecStartOptions")).
		Return(mockHijack, nil)

	// Mock ContainerExecInspect to indicate successful completion
	mockClient.On("ContainerExecInspect", mock.Anything, "exec-id-123").
		Return(container.ExecInspect{Running: false, ExitCode: 0}, nil)

	// Call the top-level function directly
	files, err := ListContainerFiles(context.Background(), mockClient, "test-container", "/app/data")
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"file1.txt", "subdir", "file2.log"}, files)

	mockClient.AssertExpectations(t)
}

// TestCheckFileExists tests checking if a file exists
func TestCheckFileExists(t *testing.T) {
	mockClient := new(MockDockerClient)
	// logger := logrus.New() // logger is unused

	// Mock ContainerStatPath for existing file
	mockClient.On("ContainerStatPath", mock.Anything, "test-container", "/app/exists.txt").
		Return(container.PathStat{Name: "exists.txt", Mode: 0644}, nil)

	// Mock ContainerStatPath for non-existing file (Docker typically returns 404 error)
	notFoundErr := errors.New("Error response from daemon: lstat /app/notexists.txt: no such file or directory")
	mockClient.On("ContainerStatPath", mock.Anything, "test-container", "/app/notexists.txt").
		Return(container.PathStat{}, notFoundErr)

	// Call the top-level function directly
	exists, err := CheckFileExists(context.Background(), mockClient, "test-container", "/app/exists.txt")
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = CheckFileExists(context.Background(), mockClient, "test-container", "/app/notexists.txt")
	require.NoError(t, err) // Expect no error, just false
	assert.False(t, exists)

	mockClient.AssertExpectations(t)
}
