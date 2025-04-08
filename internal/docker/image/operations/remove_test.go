package operations

import (
	"context"
	"errors"
	"testing"

	// Removed unused types import
	imagetypes "github.com/docker/docker/api/types/image" // Add alias
	"github.com/docker/docker/client"
	// Removed unused filters import
	// Removed duplicate client import below
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	dockermocks "github.com/threatflux/dockerServerMangerGoMCP/internal/docker" // Import for mock
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/image"       // Local image package
	// Removed conflicting local image package import
)

// TestRemoveManager_Remove tests the Remove method
func TestRemoveManager_Remove(t *testing.T) {
	// Create mock client
	mockClient := new(dockermocks.MockDockerClient)

	// Test case 1: Successful image removal
	t.Run("SuccessfulImageRemoval", func(t *testing.T) {
		// Setup expectations
		deleteItems := []imagetypes.DeleteResponse{
			{Deleted: "sha256:layer1"},
			{Untagged: "image:latest"},
		}
		mockClient.On("ImageRemove", mock.Anything, "image:latest", mock.Anything).
			Return(deleteItems, nil).Once()

		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.Remove(context.Background(), "image:latest", image.RemoveOptions{
			Force:         false,
			PruneChildren: true,
		})

		// Verify results
		assert.NoError(t, err)
		assert.Equal(t, deleteItems, result)
		mockClient.AssertExpectations(t)
	})

	// Test case 2: Remove with empty image ID
	t.Run("RemoveWithEmptyImageID", func(t *testing.T) {
		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.Remove(context.Background(), "", image.RemoveOptions{})

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidImageID))
		assert.Nil(t, result)
	})

	// Test case 3: Remove non-existent image
	t.Run("RemoveNonExistentImage", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageRemove", mock.Anything, "nonexistent:latest", mock.Anything).
			Return(nil, client.IsErrNotFound(errors.New("image not found"))).Once() // Pass error type

		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.Remove(context.Background(), "nonexistent:latest", image.RemoveOptions{})

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrImageNotFoundDuringRemoval))
		assert.Nil(t, result)
		mockClient.AssertExpectations(t)
	})

	// Test case 4: Remove image in use
	t.Run("RemoveImageInUse", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageRemove", mock.Anything, "inuse:latest", mock.Anything).
			Return(nil, errors.New("conflict: image is being used by running container")).Once()

		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.Remove(context.Background(), "inuse:latest", image.RemoveOptions{})

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrImageInUse))
		assert.Nil(t, result)
		mockClient.AssertExpectations(t)
	})

	// Test case 5: Force removal of image in use
	t.Run("ForceRemovalOfImageInUse", func(t *testing.T) {
		// Setup expectations
		deleteItems := []imagetypes.DeleteResponse{
			{Deleted: "sha256:layer1"},
			{Untagged: "inuse:latest"},
		}
		mockClient.On("ImageRemove", mock.Anything, "inuse:latest", image.RemoveOptions{
			Force:         true,
			PruneChildren: false,
		}).Return(deleteItems, nil).Once()

		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.Remove(context.Background(), "inuse:latest", image.RemoveOptions{
			Force:         true,
			PruneChildren: false,
		})

		// Verify results
		assert.NoError(t, err)
		assert.Equal(t, deleteItems, result)
		mockClient.AssertExpectations(t)
	})

	// Test case 6: Remove with context cancellation
	t.Run("RemoveWithContextCancellation", func(t *testing.T) {
		// Create a cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.Remove(ctx, "image:latest", image.RemoveOptions{})

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrContextCancelled))
		assert.Nil(t, result)
	})
}

// TestRemoveManager_RemoveMultiple tests the RemoveMultiple method
func TestRemoveManager_RemoveMultiple(t *testing.T) {
	// Create mock client
	mockClient := new(dockermocks.MockDockerClient)

	// Test case: Remove multiple images with mixed results
	t.Run("RemoveMultipleImagesWithMixedResults", func(t *testing.T) {
		// Setup expectations for successful removal
		deleteItems1 := []imagetypes.DeleteResponse{
			{Deleted: "sha256:layer1"},
			{Untagged: "image1:latest"},
		}
		mockClient.On("ImageRemove", mock.Anything, "image1:latest", mock.Anything).
			Return(deleteItems1, nil).Once()

		// Setup expectations for failed removal
		mockClient.On("ImageRemove", mock.Anything, "image2:latest", mock.Anything).
			Return(nil, errors.New("image removal error")).Once()

		// Setup expectations for another successful removal
		deleteItems3 := []imagetypes.DeleteResponse{
			{Deleted: "sha256:layer3"},
			{Untagged: "image3:latest"},
		}
		mockClient.On("ImageRemove", mock.Anything, "image3:latest", mock.Anything).
			Return(deleteItems3, nil).Once()

		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		imageList := []string{"image1:latest", "image2:latest", "image3:latest"}
		items, errs := manager.RemoveMultiple(context.Background(), imageList, image.RemoveOptions{})

		// Verify results
		assert.Len(t, items, 4) // Combined items from both successful removals
		assert.Len(t, errs, 1)  // One error from the failed removal
		mockClient.AssertExpectations(t)
	})
}

// TestRemoveManager_RemoveByFilter tests the RemoveByFilter method
func TestRemoveManager_RemoveByFilter(t *testing.T) {
	// Create mock client
	mockClient := new(dockermocks.MockDockerClient)

	// Test case: Remove images by filter
	t.Run("RemoveImagesByFilter", func(t *testing.T) {
		// Mock image list response
		images := []imagetypes.Summary{
			{
				ID:       "sha256:image1",
				RepoTags: []string{"test/image:1"},
			},
			{
				ID:       "sha256:image2",
				RepoTags: []string{"test/image:2"},
			},
		}

		// Setup expectations for image listing
		mockClient.On("ImageList", mock.Anything, mock.Anything).
			Return(images, nil).Once()

		// Setup expectations for image removal
		deleteItems1 := []imagetypes.DeleteResponse{
			{Deleted: "sha256:layer1"},
			{Untagged: "test/image:1"},
		}
		mockClient.On("ImageRemove", mock.Anything, "sha256:image1", mock.Anything).
			Return(deleteItems1, nil).Once()

		// Setup expectations for second image removal
		deleteItems2 := []imagetypes.DeleteResponse{
			{Deleted: "sha256:layer2"},
			{Untagged: "test/image:2"},
		}
		mockClient.On("ImageRemove", mock.Anything, "sha256:image2", mock.Anything).
			Return(deleteItems2, nil).Once()

		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		filterLabels := map[string]string{"test": "value"}
		items, errs := manager.RemoveByFilter(context.Background(), filterLabels, false, image.RemoveOptions{})

		// Verify results
		assert.Len(t, items, 4) // Combined items from both removals
		assert.Empty(t, errs)   // No errors
		mockClient.AssertExpectations(t)
	})

	// Test case: No images found for filter
	t.Run("NoImagesFoundForFilter", func(t *testing.T) {
		// Setup expectations for image listing - empty result
		mockClient.On("ImageList", mock.Anything, mock.Anything).
			Return([]imagetypes.Summary{}, nil).Once()

		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		filterLabels := map[string]string{"test": "nonexistent"}
		items, errs := manager.RemoveByFilter(context.Background(), filterLabels, true, image.RemoveOptions{})

		// Verify results
		assert.Nil(t, items)
		assert.Nil(t, errs)
		mockClient.AssertExpectations(t)
	})

	// Test case: Error listing images
	t.Run("ErrorListingImages", func(t *testing.T) {
		// Setup expectations for image listing - error
		mockClient.On("ImageList", mock.Anything, mock.Anything).
			Return([]imagetypes.Summary{}, errors.New("list error")).Once()

		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		filterLabels := map[string]string{"test": "value"}
		items, errs := manager.RemoveByFilter(context.Background(), filterLabels, false, image.RemoveOptions{})

		// Verify results
		assert.Nil(t, items)
		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "failed to list images")
		mockClient.AssertExpectations(t)
	})
}

// TestRemoveManager_PruneImages tests the PruneImages method
func TestRemoveManager_PruneImages(t *testing.T) {
	// Create mock client
	mockClient := new(dockermocks.MockDockerClient)

	// Test case: Successful image pruning
	t.Run("SuccessfulImagePruning", func(t *testing.T) {
		// Mock prune response
		pruneReport := imagetypes.PruneReport{
			ImagesDeleted: []imagetypes.DeleteResponse{
				{Deleted: "sha256:layer1"},
				{Untagged: "image1:latest"},
			},
			SpaceReclaimed: 100000000,
		}

		// Setup expectations
		mockClient.On("ImagesPrune", mock.Anything, mock.Anything).
			Return(pruneReport, nil).Once()

		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.PruneImages(context.Background(), image.PruneOptions{ // Use local PruneOptions
			All:          true,
			FilterLabels: map[string]string{"test": "value"},
			FilterUntil:  "24h",
		})

		// Verify results
		assert.NoError(t, err)
		assert.Equal(t, pruneReport, result)
		mockClient.AssertExpectations(t)
	})

	// Test case: Error during pruning
	t.Run("ErrorDuringPruning", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImagesPrune", mock.Anything, mock.Anything).
			Return(imagetypes.PruneReport{}, errors.New("prune error")).Once()

		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.PruneImages(context.Background(), image.PruneOptions{}) // Use local PruneOptions

		// Verify results
		assert.Error(t, err)
		assert.Equal(t, imagetypes.PruneReport{}, result)
		mockClient.AssertExpectations(t)
	})

	// Test case: Prune with context cancellation
	t.Run("PruneWithContextCancellation", func(t *testing.T) {
		// Create a cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Create remove manager
		manager := NewRemoveManager(mockClient, logrus.New())

		// Call method under test
		result, err := manager.PruneImages(ctx, image.PruneOptions{}) // Use local PruneOptions

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrContextCancelled))
		assert.Equal(t, imagetypes.PruneReport{}, result)
	})
}
