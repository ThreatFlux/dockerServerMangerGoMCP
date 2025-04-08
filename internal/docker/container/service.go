package container

import (
	"context"
	"io"
	"strings" // Added for error checking
	"time"

	"github.com/docker/docker/api/types" // Added import
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	// Import errdefs for proper error checking
	"github.com/docker/docker/errdefs"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// Service defines the interface for container management operations
// Aligned with interfaces.ContainerService
type Service interface {
	ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, platform string, containerName string) (container.CreateResponse, error)
	ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error
	ContainerStop(ctx context.Context, containerID string, options container.StopOptions) error
	ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)       // Use types.ContainerJSON
	ContainerList(ctx context.Context, options container.ListOptions) ([]types.Container, error) // Use types.Container
	NetworkConnect(ctx context.Context, networkID, containerID string, config *network.EndpointSettings) error

	// --- Methods previously defined in this interface ---
	// List returns a list of containers (Potentially redundant with ContainerList, review usage)
	List(ctx context.Context, opts ListOptions) ([]models.Container, error)

	// Get returns detailed information about a container (Potentially redundant with ContainerInspect, review usage)
	Get(ctx context.Context, containerID string) (*models.Container, error)

	// Create creates a new container (Potentially redundant with ContainerCreate, review usage)
	Create(ctx context.Context, opts CreateOptions) (*models.Container, error)

	// Start starts a container (Original method signature)
	Start(ctx context.Context, containerID string, opts StartOptions) error

	// Stop stops a container (Original method signature)
	Stop(ctx context.Context, containerID string, opts StopOptions) error

	// Restart restarts a container
	Restart(ctx context.Context, containerID string, opts RestartOptions) error

	// Kill sends a signal to a container
	Kill(ctx context.Context, containerID string, opts KillOptions) error

	// Remove removes a container (Original method signature)
	Remove(ctx context.Context, containerID string, opts RemoveOptions) error

	// Logs returns the logs of a container
	Logs(ctx context.Context, containerID string, opts LogOptions) (io.ReadCloser, error)

	// Stats returns the stats of a container
	Stats(ctx context.Context, containerID string, opts StatsOptions) (models.ContainerStats, error)

	// StreamStats streams the stats of a container
	StreamStats(ctx context.Context, containerID string, opts StatsOptions) (<-chan models.ContainerStats, <-chan error)

	// Prune removes stopped containers
	Prune(ctx context.Context, opts PruneOptions) (PruneResult, error)

	// Rename renames a container
	Rename(ctx context.Context, containerID, newName string) error

	// Update updates container resource limits
	Update(ctx context.Context, containerID string, opts UpdateOptions) error

	// Pause pauses a container
	Pause(ctx context.Context, containerID string) error

	// Unpause unpauses a container
	Unpause(ctx context.Context, containerID string) error

	// Commit creates a new image from a container
	Commit(ctx context.Context, containerID string, opts CommitOptions) (string, error)

	// Wait waits for a container to exit
	Wait(ctx context.Context, containerID string, opts WaitOptions) (<-chan container.WaitResponse, <-chan error)

	// Exec executes a command in a container
	Exec(ctx context.Context, containerID string, opts ExecOptions) (ExecResult, error)

	// Top lists processes running inside a container
	Top(ctx context.Context, containerID string, psArgs string) (TopResult, error)

	// Changes inspects changes on a container's filesystem
	Changes(ctx context.Context, containerID string) ([]ChangeItem, error)

	// GetArchive retrieves a file or directory from a container as a tar archive
	GetArchive(ctx context.Context, containerID string, opts ArchiveOptions) (io.ReadCloser, models.ResourceStat, error)

	// PutArchive copies files/directories to a container.
	PutArchive(ctx context.Context, containerID string, path string, content io.Reader) error
}

// TopResult holds the result of a container top command
type TopResult struct {
	Titles    []string   `json:"titles"`
	Processes [][]string `json:"processes"`
}

// ArchiveOptions contains options for getting/putting archives
type ArchiveOptions struct {
	Path string // Path to the file or directory inside the container
}

// ChangeItem represents a change in the container's filesystem
type ChangeItem struct {
	Path string `json:"path"`
	Kind int    `json:"kind"` // 0: Modified, 1: Added, 2: Deleted
}

// ListOptions contains options for listing containers
type ListOptions struct {
	All     bool
	Latest  bool
	Since   string
	Before  string
	Limit   int
	Filters filters.Args
	Size    bool
}

// CreateOptions contains options for creating a container
type CreateOptions struct {
	Name          string
	Config        *container.Config
	HostConfig    *container.HostConfig
	NetworkConfig *network.NetworkingConfig
	Platform      *specs.Platform
}

// StartOptions contains options for starting a container
type StartOptions struct {
	CheckpointID  string
	CheckpointDir string
}

// StopOptions contains options for stopping a container
type StopOptions struct {
	Timeout int
}

// RestartOptions contains options for restarting a container
type RestartOptions struct {
	Timeout int
}

// KillOptions contains options for killing a container
type KillOptions struct {
	Signal string
}

// RemoveOptions contains options for removing a container
type RemoveOptions struct {
	Force         bool
	RemoveVolumes bool
	RemoveLinks   bool
}

// LogOptions contains options for retrieving container logs
type LogOptions struct {
	ShowStdout bool
	ShowStderr bool
	Since      time.Time
	Until      time.Time
	Timestamps bool
	Follow     bool
	Tail       string
	Details    bool
}

// StatsOptions contains options for container stats
type StatsOptions struct {
	Stream  bool
	OneShot bool
}

// PruneOptions contains options for pruning containers
type PruneOptions struct {
	Filters filters.Args
}

// PruneResult contains the result of a prune operation
type PruneResult struct {
	ContainersDeleted []string
	SpaceReclaimed    uint64
}

// UpdateOptions contains options for updating a container
type UpdateOptions struct {
	Resources     container.Resources
	RestartPolicy *container.RestartPolicy
}

// CommitOptions contains options for committing a container
type CommitOptions struct {
	Comment   string
	Author    string
	Reference string
	Config    *container.Config
	Pause     bool
	Changes   []string
}

// WaitOptions contains options for waiting on a container
type WaitOptions struct {
	Condition container.WaitCondition
}

// ExecOptions contains options for executing a command
type ExecOptions struct {
	Config      container.ExecOptions
	StartConfig container.ExecStartOptions
}

// ExecResult contains the result of an exec operation
type ExecResult struct {
	ExecID       string
	OutputReader io.ReadCloser
	ErrorChannel <-chan error
}

// IsErrContainerConflict checks if an error is a Docker container conflict error.
func IsErrContainerConflict(err error) bool {
	if err == nil {
		return false
	}
	if errdefs.IsConflict(err) {
		return true
	}
	return strings.Contains(err.Error(), "Conflict. The container name") && strings.Contains(err.Error(), "is already in use")
}
