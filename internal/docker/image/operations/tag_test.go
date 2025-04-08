package operations

import (
	"context"
	"errors"
	"testing"

	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	dockermocks "github.com/threatflux/dockerServerMangerGoMCP/internal/docker" // Import for mock
)

// TestTagManager_Tag tests the Tag method
func TestTagManager_Tag(t *testing.T) {
	// Create mock client
	mockClient := new(dockermocks.MockDockerClient)

	// Test case 1: Successful tag
	t.Run("SuccessfulTag", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageTag", mock.Anything, "image:latest", "newrepo/image:v1").
			Return(nil).Once()

		// Create tag manager
		manager := NewTagManager(mockClient, logrus.New())

		// Call method under test
		err := manager.Tag(context.Background(), "image:latest", "newrepo/image:v1")

		// Verify results
		assert.NoError(t, err)
		mockClient.AssertExpectations(t)
	})

	// Test case 2: Tag with empty source image ID
	t.Run("TagWithEmptySourceImageID", func(t *testing.T) {
		// Create tag manager
		manager := NewTagManager(mockClient, logrus.New())

		// Call method under test
		err := manager.Tag(context.Background(), "", "newrepo/image:v1")

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidImageID))
	})

	// Test case 3: Tag with empty target reference
	t.Run("TagWithEmptyTargetReference", func(t *testing.T) {
		// Create tag manager
		manager := NewTagManager(mockClient, logrus.New())

		// Call method under test
		err := manager.Tag(context.Background(), "image:latest", "")

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTagReference))
	})

	// Test case 4: Tag with invalid target reference
	t.Run("TagWithInvalidTargetReference", func(t *testing.T) {
		// Create tag manager
		manager := NewTagManager(mockClient, logrus.New())

		// Call method under test - reference with invalid characters
		err := manager.Tag(context.Background(), "image:latest", "invalid/ref@#$%")

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTagReference))
	})

	// Test case 5: Tag non-existent image
	t.Run("TagNonExistentImage", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageTag", mock.Anything, "nonexistent:latest", "newrepo/image:v1").
			Return(client.IsErrNotFound(errors.New("no such image"))).Once()

		// Create tag manager
		manager := NewTagManager(mockClient, logrus.New())

		// Call method under test
		err := manager.Tag(context.Background(), "nonexistent:latest", "newrepo/image:v1")

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrImageNotFound))
		mockClient.AssertExpectations(t)
	})

	// Test case 6: Tag with context cancellation
	t.Run("TagWithContextCancellation", func(t *testing.T) {
		// Create a cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Create tag manager
		manager := NewTagManager(mockClient, logrus.New())

		// Call method under test
		err := manager.Tag(ctx, "image:latest", "newrepo/image:v1")

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrContextCancelled))
	})

	// Test case 7: Tag with generic error
	t.Run("TagWithGenericError", func(t *testing.T) {
		// Setup expectations
		mockClient.On("ImageTag", mock.Anything, "image:latest", "newrepo/image:v1").
			Return(errors.New("tag error")).Once()

		// Create tag manager
		manager := NewTagManager(mockClient, logrus.New())

		// Call method under test
		err := manager.Tag(context.Background(), "image:latest", "newrepo/image:v1")

		// Verify results
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrImageTag))
		mockClient.AssertExpectations(t)
	})
}

// TestTagManager_AddMultipleTags tests the AddMultipleTags method
func TestTagManager_AddMultipleTags(t *testing.T) {
	// Create mock client
	mockClient := new(dockermocks.MockDockerClient)

	// Test case: Add multiple tags with mixed results
	t.Run("AddMultipleTagsWithMixedResults", func(t *testing.T) {
		// Setup expectations for successful tags
		mockClient.On("ImageTag", mock.Anything, "image:latest", "newrepo/image:v1").
			Return(nil).Once()
		mockClient.On("ImageTag", mock.Anything, "image:latest", "newrepo/image:v3").
			Return(nil).Once()

		// Setup expectation for failed tag
		mockClient.On("ImageTag", mock.Anything, "image:latest", "newrepo/image:v2").
			Return(errors.New("tag error")).Once()

		// Create tag manager
		manager := NewTagManager(mockClient, logrus.New())

		// Call method under test
		tags := []string{"newrepo/image:v1", "newrepo/image:v2", "newrepo/image:v3"}
		successful, errs := manager.AddMultipleTags(context.Background(), "image:latest", tags)

		// Verify results
		assert.Len(t, successful, 2)
		assert.Contains(t, successful, "newrepo/image:v1")
		assert.Contains(t, successful, "newrepo/image:v3")

		assert.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "newrepo/image:v2")

		mockClient.AssertExpectations(t)
	})
}

// TestTagManager_ValidateTagReference tests the ValidateTagReference method
func TestTagManager_ValidateTagReference(t *testing.T) {
	// Create tag manager
	manager := NewTagManager(nil, logrus.New())

	// Test cases
	testCases := []struct {
		name        string
		reference   string
		expectError bool
	}{
		{"ValidSimpleReference", "image:latest", false},
		{"ValidFullReference", "docker_test.io/library/ubuntu:20.04", false},
		{"ValidWithDigest", "image@sha256:abc123", false},
		{"EmptyReference", "", true},
		{"InvalidCharacters", "image:tag@#$", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call method under test
			err := manager.ValidateTagReference(tc.reference)

			// Verify results
			if tc.expectError {
				assert.Error(t, err)
				assert.True(t, errors.Is(err, ErrInvalidTagReference))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
