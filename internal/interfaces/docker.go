// Package interfaces defines common interfaces for Docker operations
package interfaces

import (
	"context"
	"io"
	// "time" // Removed unused import

	"github.com/docker/docker/api/types" // Added import for types.ContainerJSON
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters" // Added import
	"github.com/docker/docker/api/types/image"   // Added import
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Removed unused import
)

// ContainerService defines methods for container operations
type ContainerService interface {
	// Adjusted signature to match expected usage in orchestrator.go
	ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, platform string, containerName string) (container.CreateResponse, error)
	ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error
	ContainerStop(ctx context.Context, containerID string, options container.StopOptions) error
	ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)       // Use types.ContainerJSON
	ContainerList(ctx context.Context, options container.ListOptions) ([]types.Container, error) // Use types.Container
	NetworkConnect(ctx context.Context, networkID, containerID string, config *network.EndpointSettings) error
	// Add other methods used by service_manager.go as needed
}

// ImageService defines methods for image operations
type ImageService interface {
	ImagePull(ctx context.Context, refStr string, options image.PullOptions) (io.ReadCloser, error)
	// ImageBuild(ctx context.Context, buildContext io.Reader, options image.BuildOptions) (image.BuildResponse, error) // Removed problematic method for now
	ImageInspectWithRaw(ctx context.Context, imageID string) (image.InspectResponse, []byte, error)
	ImageRemove(ctx context.Context, imageID string, options image.RemoveOptions) ([]image.DeleteResponse, error)
	// Add other methods used by service_manager.go as needed
}

// VolumeService defines methods for volume operations (already likely defined elsewhere, ensure consistency)
type VolumeService interface {
	VolumeCreate(ctx context.Context, options volume.CreateOptions) (volume.Volume, error)
	VolumeInspect(ctx context.Context, volumeID string) (volume.Volume, error)
	VolumeList(ctx context.Context, filter filters.Args) (volume.ListResponse, error) // Use imported type
	VolumeRemove(ctx context.Context, volumeID string, force bool) error
	InspectRaw(ctx context.Context, name string) (volume.Volume, error) // Added InspectRaw based on usage
	// Add other methods if needed
}

// NetworkService defines methods for network operations (already likely defined elsewhere, ensure consistency)
type NetworkService interface {
	NetworkCreate(ctx context.Context, name string, options network.CreateOptions) (network.CreateResponse, error)
	NetworkInspect(ctx context.Context, networkID string, options network.InspectOptions) (network.Inspect, error)
	NetworkList(ctx context.Context, options network.ListOptions) ([]network.Summary, error)
	NetworkRemove(ctx context.Context, networkID string) error
	NetworkConnect(ctx context.Context, networkID, containerID string, config *network.EndpointSettings) error
	NetworkDisconnect(ctx context.Context, networkID, containerID string, force bool) error
	// Add other methods if needed
}

// Removed placeholder FiltersArgs interface as it's imported now
