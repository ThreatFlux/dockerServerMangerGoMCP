package operations

import (
	"context"
	"fmt"
	"strings"

	// "github.com/docker_test/docker_test/api/types" // Removed unused import
	"github.com/docker/docker/api/types/filters"          // Added for prune filters
	imagetypes "github.com/docker/docker/api/types/image" // Added for image types
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/image"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// RemoveManager manages image removal operations
type RemoveManager struct {
	client client.APIClient
	logger *logrus.Logger
}

// NewRemoveManager creates a new remove manager
func NewRemoveManager(client client.APIClient, logger *logrus.Logger) *RemoveManager {
	if logger == nil {
		logger = logrus.New()
	}

	return &RemoveManager{
		client: client,
		logger: logger,
	}
}

// Remove removes an image
func (m *RemoveManager) Remove(ctx context.Context, imageIDOrName string, options image.RemoveOptions) ([]imagetypes.DeleteResponse, error) { // Use imagetypes.DeleteResponse
	// Validate image ID/name
	if imageIDOrName == "" {
		return nil, ErrInvalidImageID
	}

	m.logger.WithFields(logrus.Fields{
		"image":          imageIDOrName,
		"force":          options.Force,
		"prune_children": options.PruneChildren,
	}).Info("Removing Docker image")

	// Check for context cancellation
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%w: %v", ErrContextCancelled, ctx.Err())
	}

	// Prepare remove options
	removeOpts := imagetypes.RemoveOptions{ // Use imagetypes.RemoveOptions
		Force:         options.Force,
		PruneChildren: options.PruneChildren,
	}

	// Try to remove the image
	items, err := m.client.ImageRemove(ctx, imageIDOrName, removeOpts)
	if err != nil {
		// Handle specific error cases
		if client.IsErrNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrImageNotFoundDuringRemoval, imageIDOrName)
		}

		// Check for "image is in use" error
		if strings.Contains(err.Error(), "image is being used") ||
			strings.Contains(err.Error(), "conflict") &&
				strings.Contains(err.Error(), "in use") {
			return nil, fmt.Errorf("%w: %s - %v", ErrImageInUse, imageIDOrName, err)
		}

		// Generic error case
		return nil, fmt.Errorf("%w: %v", ErrImageRemove, err)
	}

	// Log deletion details
	for _, item := range items {
		if item.Deleted != "" {
			m.logger.WithField("image", item.Deleted).Debug("Deleted image layer")
		}
		if item.Untagged != "" {
			m.logger.WithField("image", item.Untagged).Debug("Untagged image")
		}
	}

	m.logger.WithField("image", imageIDOrName).Info("Successfully removed Docker image")

	return items, nil
}

// RemoveMultiple removes multiple images
func (m *RemoveManager) RemoveMultiple(ctx context.Context, imageIDsOrNames []string, options image.RemoveOptions) ([]imagetypes.DeleteResponse, []error) { // Use imagetypes.DeleteResponse
	var (
		allItems []imagetypes.DeleteResponse // Use imagetypes.DeleteResponse
		errors   []error
	)

	// Process each image
	for _, imageIDOrName := range imageIDsOrNames {
		items, err := m.Remove(ctx, imageIDOrName, options)
		if err != nil {
			m.logger.WithError(err).WithField("image", imageIDOrName).Error("Failed to remove image")
			errors = append(errors, fmt.Errorf("failed to remove %s: %w", imageIDOrName, err))
		} else {
			allItems = append(allItems, items...)
		}
	}

	return allItems, errors
}

// RemoveByFilter removes images matching the provided filter
func (m *RemoveManager) RemoveByFilter(ctx context.Context, filterLabels map[string]string, danglingOnly bool, options image.RemoveOptions) ([]imagetypes.DeleteResponse, []error) { // Use imagetypes.DeleteResponse
	var (
		allItems []imagetypes.DeleteResponse // Use imagetypes.DeleteResponse
		errors   []error
	)

	// Create list options to find images to remove
	listOpts := image.ListOptions{
		All:                true,
		FilterLabels:       filterLabels,
		FilterDanglingOnly: danglingOnly,
	}

	// Get inspector to list images
	inspector := image.NewInspector(m.client, m.logger)

	// List images matching the filter
	images, err := inspector.List(ctx, listOpts)
	if err != nil {
		return nil, []error{fmt.Errorf("failed to list images: %w", err)}
	}

	if len(images) == 0 {
		m.logger.Info("No images found matching the filter")
		return nil, nil
	}

	// Remove each image
	for _, img := range images {
		// Log the image being processed
		m.logger.WithFields(logrus.Fields{
			"image_id": img.ID,
			"tags":     img.RepoTags,
			"size":     utils.FormatImageSize(img.Size),
		}).Debug("Removing image")

		// Remove the image
		items, err := m.Remove(ctx, img.ID, options)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to remove %s: %w", img.ID, err))
		} else {
			allItems = append(allItems, items...)
		}
	}

	return allItems, errors
}

// PruneImages removes unused images
func (m *RemoveManager) PruneImages(ctx context.Context, options image.PruneOptions) (imagetypes.PruneReport, error) { // Use imagetypes.PruneReport
	m.logger.WithFields(logrus.Fields{
		"all":           options.All,
		"filter_labels": options.FilterLabels,
		"filter_until":  options.FilterUntil,
	}).Info("Pruning Docker images")

	// Check for context cancellation
	if ctx.Err() != nil {
		return imagetypes.PruneReport{}, fmt.Errorf("%w: %v", ErrContextCancelled, ctx.Err()) // Use imagetypes.PruneReport
	}

	// Create prune filters using filters.Args
	pruneFilters := filters.NewArgs()
	if !options.All {
		pruneFilters.Add("dangling", "true")
	}

	// Add label filters
	for key, value := range options.FilterLabels {
		pruneFilters.Add("label", fmt.Sprintf("%s=%s", key, value))
	}

	// Add until filter if specified
	if options.FilterUntil != "" {
		pruneFilters.Add("until", options.FilterUntil)
	}

	// Prune images
	pruneReport, err := m.client.ImagesPrune(ctx, pruneFilters) // Pass pruneFilters
	if err != nil {
		return imagetypes.PruneReport{}, fmt.Errorf("failed to prune images: %w", err) // Use imagetypes.PruneReport
	}

	// Log prune results
	m.logger.WithFields(logrus.Fields{
		"images_deleted":  len(pruneReport.ImagesDeleted),
		"space_reclaimed": utils.FormatImageSize(int64(pruneReport.SpaceReclaimed)), // Cast uint64 to int64
	}).Info("Successfully pruned Docker images")

	return pruneReport, nil
}
