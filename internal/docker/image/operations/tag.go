package operations

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// TagManager manages image tag operations
type TagManager struct {
	client client.APIClient
	logger *logrus.Logger
}

// NewTagManager creates a new tag manager
func NewTagManager(client client.APIClient, logger *logrus.Logger) *TagManager {
	if logger == nil {
		logger = logrus.New()
	}

	return &TagManager{
		client: client,
		logger: logger,
	}
}

// Tag tags an image
func (m *TagManager) Tag(ctx context.Context, imageIDOrName, ref string) error {
	// Validate image ID/name
	if imageIDOrName == "" {
		return ErrInvalidImageID
	}

	// Validate tag reference
	if ref == "" {
		return ErrInvalidTagReference
	}

	// Attempt to parse the reference to validate it
	_, err := utils.ParseImageName(ref)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTagReference, err)
	}

	m.logger.WithFields(logrus.Fields{
		"image": imageIDOrName,
		"tag":   ref,
	}).Info("Tagging Docker image")

	// Check for context cancellation
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %v", ErrContextCancelled, ctx.Err())
	}

	// Tag the image
	err = m.client.ImageTag(ctx, imageIDOrName, ref)
	if err != nil {
		// Handle specific error cases
		if client.IsErrNotFound(err) {
			return fmt.Errorf("%w: source image %s not found", ErrImageNotFound, imageIDOrName)
		}

		// Check for "no such image" error (may not be caught by IsErrNotFound)
		if strings.Contains(err.Error(), "No such image") {
			return fmt.Errorf("%w: source image %s not found", ErrImageNotFound, imageIDOrName)
		}

		// Generic error case
		return fmt.Errorf("%w: %v", ErrImageTag, err)
	}

	m.logger.WithFields(logrus.Fields{
		"image": imageIDOrName,
		"tag":   ref,
	}).Info("Successfully tagged Docker image")

	return nil
}

// AddMultipleTags adds multiple tags to an image
func (m *TagManager) AddMultipleTags(ctx context.Context, imageIDOrName string, tags []string) ([]string, []error) {
	var (
		successful []string
		errors     []error
	)

	// Process each tag
	for _, tag := range tags {
		err := m.Tag(ctx, imageIDOrName, tag)
		if err != nil {
			m.logger.WithError(err).WithFields(logrus.Fields{
				"image": imageIDOrName,
				"tag":   tag,
			}).Error("Failed to tag image")
			errors = append(errors, fmt.Errorf("failed to add tag %s: %w", tag, err))
		} else {
			successful = append(successful, tag)
		}
	}

	return successful, errors
}

// ValidateTagReference validates a tag reference
func (m *TagManager) ValidateTagReference(ref string) error {
	if ref == "" {
		return ErrInvalidTagReference
	}

	// Attempt to parse the reference to validate it
	_, err := utils.ParseImageName(ref)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTagReference, err)
	}

	return nil
}
