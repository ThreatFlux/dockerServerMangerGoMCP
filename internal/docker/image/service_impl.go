package image

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/api/types"
	imagetypes "github.com/docker/docker/api/types/image"
	registrytypes "github.com/docker/docker/api/types/registry"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils" // Added utils import
)

// serviceImpl implements the image.Service interface
type serviceImpl struct {
	dockerManager docker.Manager
	logger        *logrus.Logger
}

// NewService creates a new image service implementation
func NewService(dockerManager docker.Manager, logger *logrus.Logger) Service {
	return &serviceImpl{
		dockerManager: dockerManager,
		logger:        logger,
	}
}

// List returns a list of Docker images
func (s *serviceImpl) List(ctx context.Context, options ListOptions) ([]imagetypes.Summary, error) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Convert ListOptions to Docker API options
	dockerOptions := imagetypes.ListOptions{
		All: options.All,
		Filters: utils.BuildFilterArgs(map[string]string{ // Use utils.BuildFilterArgs
			"label":     strings.Join(utils.FormatLabels(options.FilterLabels), ","), // Use utils.FormatLabels and join
			"dangling":  fmt.Sprintf("%t", options.FilterDanglingOnly),
			"reference": options.FilterReference,
			"before":    options.FilterBefore,
			"since":     options.FilterSince,
			// MatchName is not directly supported by Docker API filters, handle separately if needed
		}),
	}

	s.logger.WithField("options", dockerOptions).Debug("Listing images with options")
	images, err := cli.ImageList(ctx, dockerOptions)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list images from Docker API")
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	// TODO: Add filtering for MatchName if required, as it's not a direct API filter

	s.logger.WithField("count", len(images)).Debug("Successfully listed images")
	return images, nil
}

// ImagePull pulls an image from a registry
func (s *serviceImpl) ImagePull(ctx context.Context, refStr string, options imagetypes.PullOptions) (io.ReadCloser, error) { // Use imagetypes.PullOptions
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Use the provided options directly
	dockerOptions := options

	s.logger.WithFields(logrus.Fields{
		"ref":     refStr,
		"options": dockerOptions,
	}).Info("Pulling image")

	reader, err := cli.ImagePull(ctx, refStr, dockerOptions)
	if err != nil {
		s.logger.WithError(err).WithField("ref", refStr).Error("Failed to pull image")
		return nil, fmt.Errorf("failed to pull image %s: %w", refStr, err)
	}

	s.logger.WithField("ref", refStr).Info("Image pull started")
	return reader, nil // Return the reader for streaming progress
}

// Build builds an image from a context
func (s *serviceImpl) Build(ctx context.Context, options BuildOptions) (io.ReadCloser, error) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Convert BuildOptions to Docker API options
	dockerOptions := types.ImageBuildOptions{
		Tags:        options.Tags,
		Dockerfile:  options.Dockerfile,
		BuildArgs:   options.BuildArgs,
		NoCache:     options.NoCache,
		Remove:      options.Remove,
		ForceRemove: options.ForceRemove,
		PullParent:  options.PullParent,
		Labels:      options.BuildLabels,
		Target:      options.Target,
		Platform:    options.Platform,
		// TODO: Handle RegistryAuth if needed for private base images
		// TODO: Handle ContextDir if needed (requires more complex handling than just io.Reader)
	}

	s.logger.WithFields(logrus.Fields{
		"tags":       options.Tags,
		"dockerfile": options.Dockerfile,
		"options":    dockerOptions,
	}).Info("Building image")

	response, err := cli.ImageBuild(ctx, options.Context, dockerOptions)
	if err != nil {
		s.logger.WithError(err).Error("Failed to start image build")
		return nil, fmt.Errorf("failed to build image: %w", err)
	}

	s.logger.Info("Image build started")
	// Return the response body (reader) for streaming build output
	return response.Body, nil
}

// ImageRemove removes an image
func (s *serviceImpl) ImageRemove(ctx context.Context, imageID string, options imagetypes.RemoveOptions) ([]imagetypes.DeleteResponse, error) { // Use imagetypes alias
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Use the provided options directly
	dockerOptions := options

	s.logger.WithFields(logrus.Fields{
		"imageID": imageID,
		"options": dockerOptions,
	}).Info("Removing image")
	// Pass the imageID directly to the client
	response, err := cli.ImageRemove(ctx, imageID, dockerOptions)
	if err != nil {
		s.logger.WithError(err).WithField("imageID", imageID).Error("Failed to remove image")
		return nil, fmt.Errorf("failed to remove image %s: %w", imageID, err)
	}

	s.logger.WithField("imageID", imageID).Info("Image removed successfully")
	return response, nil
}

// Tag tags an image
func (s *serviceImpl) Tag(ctx context.Context, imageID, ref string) error {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"imageID": imageID,
		"tag":     ref,
	}).Info("Tagging image")

	err = cli.ImageTag(ctx, imageID, ref)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"imageID": imageID,
			"tag":     ref,
		}).Error("Failed to tag image")
		return fmt.Errorf("failed to tag image %s with %s: %w", imageID, ref, err)
	}

	s.logger.WithFields(logrus.Fields{
		"imageID": imageID,
		"tag":     ref,
	}).Info("Image tagged successfully")
	return nil
}

// Inspect inspects an image
func (s *serviceImpl) Inspect(ctx context.Context, imageID string) (types.ImageInspect, error) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return types.ImageInspect{}, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	s.logger.WithField("imageID", imageID).Debug("Inspecting image")
	inspectData, _, err := cli.ImageInspectWithRaw(ctx, imageID) // Use ImageInspectWithRaw to get detailed info
	if err != nil {
		s.logger.WithError(err).WithField("imageID", imageID).Warn("Failed to inspect image")
		// Consider wrapping common Docker errors (like not found)
		return types.ImageInspect{}, fmt.Errorf("failed to inspect image %s: %w", imageID, err)
	}

	s.logger.WithField("imageID", imageID).Debug("Image inspected successfully")
	return inspectData, nil
}

// ImageInspectWithRaw inspects an image and returns the raw JSON response
func (s *serviceImpl) ImageInspectWithRaw(ctx context.Context, imageID string) (imagetypes.InspectResponse, []byte, error) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return imagetypes.InspectResponse{}, nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	s.logger.WithField("imageID", imageID).Debug("Inspecting image (raw)")
	inspectData, rawJSON, err := cli.ImageInspectWithRaw(ctx, imageID)
	if err != nil {
		s.logger.WithError(err).WithField("imageID", imageID).Warn("Failed to inspect image (raw)")
		// Consider wrapping common Docker errors (like not found)
		return imagetypes.InspectResponse{}, nil, fmt.Errorf("failed to inspect image %s: %w", imageID, err)
	}

	s.logger.WithField("imageID", imageID).Debug("Image inspected successfully (raw)")
	return inspectData, rawJSON, nil
}

// History returns the history of an image
func (s *serviceImpl) History(ctx context.Context, imageID string) ([]imagetypes.HistoryResponseItem, error) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	s.logger.WithField("imageID", imageID).Debug("Getting image history")
	history, err := cli.ImageHistory(ctx, imageID)
	if err != nil {
		s.logger.WithError(err).WithField("imageID", imageID).Error("Failed to get image history")
		return nil, fmt.Errorf("failed to get history for image %s: %w", imageID, err)
	}

	s.logger.WithField("imageID", imageID).Debug("Image history retrieved successfully")
	return history, nil
}

// Prune removes unused images
func (s *serviceImpl) Prune(ctx context.Context, options PruneOptions) (imagetypes.PruneReport, error) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return imagetypes.PruneReport{}, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Convert PruneOptions to Docker API filters
	filterArgs := utils.BuildFilterArgs(map[string]string{ // Use utils.BuildFilterArgs
		"label":    strings.Join(utils.FormatLabels(options.FilterLabels), ","), // Use utils.FormatLabels and join
		"until":    options.FilterUntil,
		"dangling": fmt.Sprintf("%t", !options.All), // Prune dangling if All is false
	})

	s.logger.WithField("filters", filterArgs).Info("Pruning images")
	report, err := cli.ImagesPrune(ctx, filterArgs)
	if err != nil {
		s.logger.WithError(err).Error("Failed to prune images")
		return imagetypes.PruneReport{}, fmt.Errorf("failed to prune images: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"images_deleted":  len(report.ImagesDeleted),
		"space_reclaimed": report.SpaceReclaimed,
	}).Info("Images pruned successfully")
	return report, nil
}

// Search searches for images in registries
func (s *serviceImpl) Search(ctx context.Context, term string, options SearchOptions) ([]registrytypes.SearchResult, error) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Convert SearchOptions to Docker API options
	dockerOptions := registrytypes.SearchOptions{
		Limit: options.Limit,
		Filters: utils.BuildFilterArgs(map[string]string{ // Use utils.BuildFilterArgs
			"stars":        fmt.Sprintf("%d", options.FilterStars),
			"is-official":  fmt.Sprintf("%t", options.FilterOfficial),
			"is-automated": fmt.Sprintf("%t", options.FilterAutomated),
		}),
		// TODO: Handle RegistryAuth if needed for private registries
	}

	s.logger.WithFields(logrus.Fields{
		"term":    term,
		"options": dockerOptions,
	}).Info("Searching for images")

	results, err := cli.ImageSearch(ctx, term, dockerOptions)
	if err != nil {
		s.logger.WithError(err).WithField("term", term).Error("Failed to search images")
		return nil, fmt.Errorf("failed to search images for term '%s': %w", term, err)
	}

	s.logger.WithField("term", term).WithField("count", len(results)).Info("Image search completed")
	return results, nil
}
