package image

import (
	"context"
	"io"
	"testing"

	"github.com/docker/docker/api/types"
	imagetypes "github.com/docker/docker/api/types/image"       // Use alias
	registrytypes "github.com/docker/docker/api/types/registry" // Use alias
)

// MockService implements Service interface for testing
type MockService struct {
	ListFunc                func(ctx context.Context, options ListOptions) ([]imagetypes.Summary, error)
	ImagePullFunc           func(ctx context.Context, refStr string, options imagetypes.PullOptions) (io.ReadCloser, error) // Added ImagePullFunc field
	BuildFunc               func(ctx context.Context, options BuildOptions) (io.ReadCloser, error)
	ImageRemoveFunc         func(ctx context.Context, imageID string, options imagetypes.RemoveOptions) ([]imagetypes.DeleteResponse, error) // Added ImageRemoveFunc field
	TagFunc                 func(ctx context.Context, imageID, ref string) error
	InspectFunc             func(ctx context.Context, imageID string) (types.ImageInspect, error)                               // Use types.ImageInspect
	HistoryFunc             func(ctx context.Context, imageID string) ([]imagetypes.HistoryResponseItem, error)                 // Use imagetypes.HistoryResponseItem
	PruneFunc               func(ctx context.Context, options PruneOptions) (imagetypes.PruneReport, error)                     // Use imagetypes.PruneReport
	SearchFunc              func(ctx context.Context, term string, options SearchOptions) ([]registrytypes.SearchResult, error) // Use registrytypes.SearchResult
	ImageInspectWithRawFunc func(ctx context.Context, imageID string) (types.ImageInspect, []byte, error)                       // Added missing func field
}

// List implements Service.List
func (m *MockService) List(ctx context.Context, options ListOptions) ([]imagetypes.Summary, error) { // Use imagetypes.Summary
	if m.ListFunc != nil {
		return m.ListFunc(ctx, options)
	}
	return []imagetypes.Summary{}, nil // Use imagetypes.Summary
}

// ImagePull implements Service.ImagePull
func (m *MockService) ImagePull(ctx context.Context, refStr string, options imagetypes.PullOptions) (io.ReadCloser, error) {
	if m.ImagePullFunc != nil {
		return m.ImagePullFunc(ctx, refStr, options)
	}
	return nil, nil
}

// Build implements Service.Build
func (m *MockService) Build(ctx context.Context, options BuildOptions) (io.ReadCloser, error) {
	if m.BuildFunc != nil {
		return m.BuildFunc(ctx, options)
	}
	return nil, nil
}

// ImageRemove implements Service.ImageRemove
func (m *MockService) ImageRemove(ctx context.Context, imageID string, options imagetypes.RemoveOptions) ([]imagetypes.DeleteResponse, error) {
	if m.ImageRemoveFunc != nil {
		return m.ImageRemoveFunc(ctx, imageID, options)
	}
	return []imagetypes.DeleteResponse{}, nil
}

// Tag implements Service.Tag
func (m *MockService) Tag(ctx context.Context, imageID, ref string) error {
	if m.TagFunc != nil {
		return m.TagFunc(ctx, imageID, ref)
	}
	return nil
}

// Inspect implements Service.Inspect
func (m *MockService) Inspect(ctx context.Context, imageID string) (types.ImageInspect, error) {
	if m.InspectFunc != nil {
		return m.InspectFunc(ctx, imageID)
	}
	return types.ImageInspect{}, nil
}

// History implements Service.History
func (m *MockService) History(ctx context.Context, imageID string) ([]imagetypes.HistoryResponseItem, error) { // Use imagetypes.HistoryResponseItem
	if m.HistoryFunc != nil {
		return m.HistoryFunc(ctx, imageID)
	}
	return []imagetypes.HistoryResponseItem{}, nil // Use imagetypes.HistoryResponseItem
}

// Prune implements Service.Prune
func (m *MockService) Prune(ctx context.Context, options PruneOptions) (imagetypes.PruneReport, error) { // Use imagetypes.PruneReport
	if m.PruneFunc != nil {
		return m.PruneFunc(ctx, options)
	}
	return imagetypes.PruneReport{}, nil // Use imagetypes.PruneReport
}

// Search implements Service.Search
func (m *MockService) Search(ctx context.Context, term string, options SearchOptions) ([]registrytypes.SearchResult, error) { // Use registrytypes.SearchResult
	if m.SearchFunc != nil {
		return m.SearchFunc(ctx, term, options)
	}
	return []registrytypes.SearchResult{}, nil // Use registrytypes.SearchResult
}

// ImageInspectWithRaw implements Service.ImageInspectWithRaw
func (m *MockService) ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error) {
	if m.ImageInspectWithRawFunc != nil {
		return m.ImageInspectWithRawFunc(ctx, imageID)
	}
	return types.ImageInspect{}, nil, nil
}

// TestServiceInterface ensures the interface is properly defined
func TestServiceInterface(t *testing.T) {
	// This test doesn't actually test functionality, but ensures that MockService implements Service
	var _ Service = &MockService{}
}
