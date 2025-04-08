package image

import (
	"context"
	"io"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"                  // Import image directly
	imagetypes "github.com/docker/docker/api/types/image"       // Keep alias for now if used elsewhere
	registrytypes "github.com/docker/docker/api/types/registry" // Add registry import with alias
)

// Service defines the interface for Docker image operations
// Aligned with interfaces.ImageService
type Service interface {
	ImagePull(ctx context.Context, refStr string, options image.PullOptions) (io.ReadCloser, error)
	ImageInspectWithRaw(ctx context.Context, imageID string) (image.InspectResponse, []byte, error)               // Use direct type
	ImageRemove(ctx context.Context, imageID string, options image.RemoveOptions) ([]image.DeleteResponse, error) // Use direct type

	// --- Methods previously defined in this interface (Keep for now, ensure implementation exists) ---
	List(ctx context.Context, options ListOptions) ([]imagetypes.Summary, error) // Use imagetypes.Summary
	Build(ctx context.Context, options BuildOptions) (io.ReadCloser, error)
	Tag(ctx context.Context, imageID, ref string) error
	Inspect(ctx context.Context, imageID string) (types.ImageInspect, error)                              // Use types.ImageInspect
	History(ctx context.Context, imageID string) ([]imagetypes.HistoryResponseItem, error)                // Use imagetypes.HistoryResponseItem
	Prune(ctx context.Context, options PruneOptions) (imagetypes.PruneReport, error)                      // Use imagetypes.PruneReport
	Search(ctx context.Context, term string, options SearchOptions) ([]registrytypes.SearchResult, error) // Use registrytypes.SearchResult
}

// ListOptions defines options for listing images
type ListOptions struct {
	All                bool
	FilterLabels       map[string]string
	FilterDanglingOnly bool
	MatchName          string
	FilterBefore       string
	FilterSince        string
	FilterReference    string
}

// PullOptions defines options for pulling images
type PullOptions struct {
	All            bool
	Platform       string
	RegistryAuth   string
	ProgressOutput io.Writer
	Quiet          bool
}

// BuildOptions defines options for building images
type BuildOptions struct {
	Context        io.Reader
	ContextDir     string
	Dockerfile     string
	Tags           []string
	BuildArgs      map[string]*string
	NoCache        bool
	Remove         bool
	ForceRemove    bool
	PullParent     bool
	ProgressOutput io.Writer
	BuildLabels    map[string]string
	Target         string
	Platform       string
	RegistryAuth   string
}

// RemoveOptions defines options for removing images
type RemoveOptions struct {
	Force         bool
	PruneChildren bool
}

// PruneOptions defines options for pruning images
type PruneOptions struct {
	FilterLabels map[string]string
	FilterUntil  string
	All          bool
}

// SearchOptions defines options for searching images
type SearchOptions struct {
	Limit           int
	FilterStars     int
	FilterAutomated bool
	FilterOfficial  bool
}
