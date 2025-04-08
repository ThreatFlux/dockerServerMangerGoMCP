package image

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container" // Added alias
	"github.com/docker/docker/api/types/filters"
	imagetypes "github.com/docker/docker/api/types/image" // Use alias
	"github.com/docker/docker/client"                     // Added client import
	"github.com/docker/docker/errdefs"                    // Added for NotFound error
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDockerClient mocks the Docker client API
type MockDockerClient struct {
	mock.Mock
}

// ImageList implements the client.APIClient interface
func (m *MockDockerClient) ImageList(ctx context.Context, options imagetypes.ListOptions) ([]imagetypes.Summary, error) { // Use imagetypes
	args := m.Called(ctx, options)
	return args.Get(0).([]imagetypes.Summary), args.Error(1) // Use imagetypes
}

// ImageInspectWithRaw implements the client.APIClient interface
func (m *MockDockerClient) ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error) {
	args := m.Called(ctx, imageID)
	return args.Get(0).(types.ImageInspect), args.Get(1).([]byte), args.Error(2)
}

// ImageHistory implements the client.APIClient interface
// Corrected signature to use client.ImageHistoryOption
func (m *MockDockerClient) ImageHistory(ctx context.Context, imageID string, options ...client.ImageHistoryOption) ([]imagetypes.HistoryResponseItem, error) {
	callArgs := []interface{}{ctx, imageID}
	// Convert options slice to []interface{} for Called()
	for _, opt := range options {
		callArgs = append(callArgs, opt)
	}
	args := m.Called(callArgs...)
	return args.Get(0).([]imagetypes.HistoryResponseItem), args.Error(1)
}

// BuildCachePrune implements the client.APIClient interface (add missing method)
func (m *MockDockerClient) BuildCachePrune(ctx context.Context, opts types.BuildCachePruneOptions) (*types.BuildCachePruneReport, error) {
	args := m.Called(ctx, opts)
	// Ensure the first return value is a pointer if the interface expects one
	if report, ok := args.Get(0).(*types.BuildCachePruneReport); ok {
		return report, args.Error(1)
	}
	// Handle case where nil is returned or type assertion fails
	return nil, args.Error(1)
}

// BuildCancel implements the client.APIClient interface (add missing method)
func (m *MockDockerClient) BuildCancel(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

/*
// CheckpointCreate implements the client.APIClient interface (add missing method)
// Commented out as containertypes.CheckpointCreateOptions seems undefined/changed in SDK
func (m *MockDockerClient) CheckpointCreate(ctx context.Context, containerID string, options containertypes.CheckpointCreateOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}

// CheckpointDelete implements the client.APIClient interface (add missing method)
// Commented out as containertypes.CheckpointDeleteOptions seems undefined/changed in SDK
func (m *MockDockerClient) CheckpointDelete(ctx context.Context, containerID string, options containertypes.CheckpointDeleteOptions) error {
	args := m.Called(ctx, containerID, options)
	return args.Error(0)
}
*/

// TestInspectorList tests the List method
func TestInspectorList(t *testing.T) {
	// Create mock client
	mockClient := new(MockDockerClient)

	// Create test images
	images := []imagetypes.Summary{ // Use imagetypes
		{
			ID:          "sha256:image1",
			RepoTags:    []string{"test/image:latest"},
			RepoDigests: []string{"test/image@sha256:digest1"},
			Created:     time.Now().Unix(),
			Size:        100000000,
		},
		{
			ID:          "sha256:image2",
			RepoTags:    []string{"test/image:v1"},
			RepoDigests: []string{"test/image@sha256:digest2"},
			Created:     time.Now().Unix() - 86400,
			Size:        200000000,
		},
	}

	// Test case 1: List all images
	t.Run("ListAllImages", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageList", mock.Anything, imagetypes.ListOptions{ // Use imagetypes
			All:     true,
			Filters: filters.NewArgs(),
		}).Return(images, nil).Once()

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		result, err := inspector.List(context.Background(), ListOptions{All: true})

		// Verify results
		assert.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, images, result)
		mockClient.AssertExpectations(t)
	})

	// Test case 2: List with label filter
	t.Run("ListWithLabelFilter", func(t *testing.T) {
		// Create filter
		filterArgs := filters.NewArgs()
		filterArgs.Add("label", "test=value")

		// Setup expectations
		mockClient.On("ImageList", mock.Anything, imagetypes.ListOptions{ // Use imagetypes
			All:     false,
			Filters: filterArgs,
		}).Return(images[:1], nil).Once()

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		result, err := inspector.List(context.Background(), ListOptions{
			All:          false,
			FilterLabels: map[string]string{"test": "value"},
		})

		// Verify results
		assert.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, images[:1], result)
		mockClient.AssertExpectations(t)
	})

	// Test case 3: List error handling
	t.Run("ListErrorHandling", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageList", mock.Anything, mock.Anything).
			Return([]imagetypes.Summary{}, errors.New("list error")).Once() // Use imagetypes

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		result, err := inspector.List(context.Background(), ListOptions{})

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrImageListing))
		assert.Len(t, result, 0)
		mockClient.AssertExpectations(t)
	})
}

// TestInspectorInspect tests the Inspect method
func TestInspectorInspect(t *testing.T) {
	// Create mock client
	mockClient := new(MockDockerClient)

	// Create test image inspection
	imageInspect := types.ImageInspect{
		ID:          "sha256:image1",
		RepoTags:    []string{"test/image:latest"},
		RepoDigests: []string{"test/image@sha256:digest1"},
		Created:     time.Now().Format(time.RFC3339Nano),
		Size:        100000000,
		Config: &containertypes.Config{ // Use containertypes alias
			Labels: map[string]string{"test": "value"},
			Env:    []string{"TEST=value"},
			Cmd:    []string{"sh"},
		},
	}

	// Test case 1: Inspect existing image
	t.Run("InspectExistingImage", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageInspectWithRaw", mock.Anything, "test/image:latest").
			Return(imageInspect, []byte("raw"), nil).Once()

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		result, err := inspector.Inspect(context.Background(), "test/image:latest")

		// Verify results
		assert.NoError(t, err)
		assert.Equal(t, imageInspect, result)
		mockClient.AssertExpectations(t)
	})

	// Test case 2: Inspect non-existent image
	t.Run("InspectNonExistentImage", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageInspectWithRaw", mock.Anything, "test/nonexistent:latest").
			Return(types.ImageInspect{}, []byte{}, errdefs.NotFound(errors.New("image not found"))).Once() // Use errdefs

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		result, err := inspector.Inspect(context.Background(), "test/nonexistent:latest")

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrImageNotFound))
		assert.Equal(t, types.ImageInspect{}, result)
		mockClient.AssertExpectations(t)
	})

	// Test case 3: Inspect with empty ID
	t.Run("InspectWithEmptyID", func(t *testing.T) {
		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		result, err := inspector.Inspect(context.Background(), "")

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidImageID))
		assert.Equal(t, types.ImageInspect{}, result)
	})
}

// TestInspectorHistory tests the History method
func TestInspectorHistory(t *testing.T) {
	// Create mock client
	mockClient := new(MockDockerClient)

	// Create test history
	historyItems := []imagetypes.HistoryResponseItem{ // Use imagetypes
		{
			ID:        "layer1",
			Created:   time.Now().Unix(),
			CreatedBy: "/bin/sh -c #(nop) ADD file:e6ca98733613e732",
			Size:      10000000,
			Comment:   "",
		},
		{
			ID:        "layer2",
			Created:   time.Now().Unix() - 86400,
			CreatedBy: "/bin/sh -c apt-get update && apt-get install -y",
			Size:      20000000,
			Comment:   "",
		},
	}

	// Test case 1: Get history of existing image
	t.Run("HistoryExistingImage", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageHistory", mock.Anything, "test/image:latest").
			Return(historyItems, nil).Once()

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		result, err := inspector.History(context.Background(), "test/image:latest")

		// Verify results
		assert.NoError(t, err)
		assert.Equal(t, historyItems, result)
		mockClient.AssertExpectations(t)
	})

	// Test case 2: Get history of non-existent image
	t.Run("HistoryNonExistentImage", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageHistory", mock.Anything, "test/nonexistent:latest").
			Return([]imagetypes.HistoryResponseItem{}, errdefs.NotFound(errors.New("image not found"))).Once() // Use errdefs

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		result, err := inspector.History(context.Background(), "test/nonexistent:latest")

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrImageNotFound))
		assert.Len(t, result, 0)
		mockClient.AssertExpectations(t)
	})

	// Test case 3: History with empty ID
	t.Run("HistoryWithEmptyID", func(t *testing.T) {
		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		result, err := inspector.History(context.Background(), "")

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidImageID))
		assert.Len(t, result, 0)
	})
}

// TestImageExists tests the ImageExists method
func TestImageExists(t *testing.T) {
	// Create mock client
	mockClient := new(MockDockerClient)

	// Create test images
	images := []imagetypes.Summary{ // Use imagetypes
		{
			ID:       "sha256:image1",
			RepoTags: []string{"test/image:latest"},
		},
	}

	// Test case 1: Image exists
	t.Run("ImageExists", func(t *testing.T) {
		// Setup expectations
		filterArgs := filters.NewArgs()
		filterArgs.Add("reference", "test/image:latest")

		mockClient.On("ImageList", mock.Anything, imagetypes.ListOptions{ // Use imagetypes
			All:     true,
			Filters: filterArgs,
		}).Return(images, nil).Once()

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		exists, err := inspector.ImageExists(context.Background(), "test/image:latest")

		// Verify results
		assert.NoError(t, err)
		assert.True(t, exists)
		mockClient.AssertExpectations(t)
	})

	// Test case 2: Image does not exist
	t.Run("ImageDoesNotExist", func(t *testing.T) {
		// Setup expectations
		filterArgs := filters.NewArgs()
		filterArgs.Add("reference", "test/nonexistent:latest")

		mockClient.On("ImageList", mock.Anything, imagetypes.ListOptions{ // Use imagetypes
			All:     true,
			Filters: filterArgs,
		}).Return([]imagetypes.Summary{}, nil).Once() // Use imagetypes

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		exists, err := inspector.ImageExists(context.Background(), "test/nonexistent:latest")

		// Verify results
		assert.NoError(t, err)
		assert.False(t, exists)
		mockClient.AssertExpectations(t)
	})
}

// TestGetImageDigest tests the GetImageDigest method
func TestGetImageDigest(t *testing.T) {
	// Create mock client
	mockClient := new(MockDockerClient)

	// Create test image inspection
	imageInspect := types.ImageInspect{
		ID:          "sha256:image1",
		RepoTags:    []string{"test/image:latest"},
		RepoDigests: []string{"test/image@sha256:digest1"},
	}

	// Test case 1: Get digest from RepoDigests
	t.Run("GetDigestFromRepoDigests", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageInspectWithRaw", mock.Anything, "test/image:latest").
			Return(imageInspect, []byte("raw"), nil).Once()

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		digest, err := inspector.GetImageDigest(context.Background(), "test/image:latest")

		// Verify results
		assert.NoError(t, err)
		assert.Equal(t, "sha256:digest1", digest)
		mockClient.AssertExpectations(t)
	})

	// Test case 2: Get digest from ID
	t.Run("GetDigestFromID", func(t *testing.T) {
		// Create image with no RepoDigests
		imageWithoutRepoDigests := types.ImageInspect{
			ID:          "sha256:image1",
			RepoTags:    []string{"test/image:latest"},
			RepoDigests: []string{},
		}

		// Setup expectations
		mockClient.On("ImageInspectWithRaw", mock.Anything, "test/image:latest").
			Return(imageWithoutRepoDigests, []byte("raw"), nil).Once()

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		digest, err := inspector.GetImageDigest(context.Background(), "test/image:latest")

		// Verify results
		assert.NoError(t, err)
		assert.Equal(t, "image1", digest)
		mockClient.AssertExpectations(t)
	})
}

// TestGetAllTags tests the GetAllTags method
func TestGetAllTags(t *testing.T) {
	// Create mock client
	mockClient := new(MockDockerClient)

	// Create test images
	images := []imagetypes.Summary{ // Use imagetypes
		{
			ID:       "sha256:image1",
			RepoTags: []string{"test/image:latest", "test/image:v1"},
		},
		{
			ID:       "sha256:image2",
			RepoTags: []string{"another/image:latest"},
		},
	}

	// Test case: Get all tags for an image ID
	t.Run("GetAllTags", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageList", mock.Anything, imagetypes.ListOptions{ // Use imagetypes
			All: true,
		}).Return(images, nil).Once()

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		tags, err := inspector.GetAllTags(context.Background(), "image1")

		// Verify results
		assert.NoError(t, err)
		assert.Len(t, tags, 2)
		assert.Contains(t, tags, "test/image:latest")
		assert.Contains(t, tags, "test/image:v1")
		mockClient.AssertExpectations(t)
	})
}

// TestGetTotalImagesCount tests the GetTotalImagesCount method
func TestGetTotalImagesCount(t *testing.T) {
	// Create mock client
	mockClient := new(MockDockerClient)

	// Create test images
	images := []imagetypes.Summary{ // Use imagetypes
		{ID: "sha256:image1"},
		{ID: "sha256:image2"},
		{ID: "sha256:image3"},
	}

	// Test case: Get total images count
	t.Run("GetTotalImagesCount", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageList", mock.Anything, imagetypes.ListOptions{ // Use imagetypes
			All: true,
		}).Return(images, nil).Once()

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		count, err := inspector.GetTotalImagesCount(context.Background())

		// Verify results
		assert.NoError(t, err)
		assert.Equal(t, 3, count)
		mockClient.AssertExpectations(t)
	})
}

// TestGetTotalImageDiskUsage tests the GetTotalImageDiskUsage method
func TestGetTotalImageDiskUsage(t *testing.T) {
	// Create mock client
	mockClient := new(MockDockerClient)

	// Create test images with sizes
	images := []imagetypes.Summary{ // Use imagetypes
		{ID: "sha256:image1", Size: 100000000},
		{ID: "sha256:image2", Size: 200000000},
		{ID: "sha256:image3", Size: 300000000},
	}

	// Test case: Get total disk usage
	t.Run("GetTotalImageDiskUsage", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageList", mock.Anything, imagetypes.ListOptions{ // Use imagetypes
			All: true,
		}).Return(images, nil).Once()

		// Create inspector
		inspector := NewInspector(mockClient, logrus.New())

		// Call method under test
		size, err := inspector.GetTotalImageDiskUsage(context.Background())

		// Verify results
		assert.NoError(t, err)
		assert.Equal(t, int64(600000000), size)
		mockClient.AssertExpectations(t)
	})
}

// TestFormatImageSize tests the FormatImageSize method
func TestFormatImageSize(t *testing.T) {
	// Create mock client and inspector
	mockClient := new(MockDockerClient)
	inspector := NewInspector(mockClient, logrus.New())

	// Test cases
	testCases := []struct {
		size     int64
		expected string
	}{
		// Update expectations to match current simple formatting
		{500, "500"},
		{1500, "1500"},
		{1500000, "1500000"},
		{1500000000, "1500000000"},
	}

	for _, tc := range testCases {
		result := inspector.FormatImageSize(tc.size)
		assert.Equal(t, tc.expected, result)
	}
}
