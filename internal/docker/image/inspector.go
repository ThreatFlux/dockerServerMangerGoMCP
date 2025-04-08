package image

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	imagetypes "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/sirupsen/logrus"
)

// Common errors
var (
	ErrImageNotFound    = errors.New("image not found")
	ErrImageInspection  = errors.New("failed to inspect image")
	ErrImageListing     = errors.New("failed to list images")
	ErrImageHistory     = errors.New("failed to get image history")
	ErrInvalidImageID   = errors.New("invalid image ID or reference")
	ErrContextCancelled = errors.New("operation cancelled")
)

// InspectorClient defines the interface for Docker client methods used by the image inspector.
type InspectorClient interface {
	ImageList(ctx context.Context, options imagetypes.ListOptions) ([]imagetypes.Summary, error)
	ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error)
	ImageHistory(ctx context.Context, imageID string, options ...client.ImageHistoryOption) ([]imagetypes.HistoryResponseItem, error) // Added options parameter
}

// Inspector provides methods for inspecting Docker images
type Inspector struct {
	client InspectorClient // Use the interface type
	logger *logrus.Logger
}

// NewInspector creates a new image inspector
func NewInspector(client InspectorClient, logger *logrus.Logger) *Inspector { // Accept the interface type
	// If no client (real or mock) is provided, create a default real client.
	// Note: This requires the 'client' package alias if creating a real client here.
	// For simplicity in this refactor, we assume a client is always provided.
	// If needed, add default client creation logic similar to volume inspector.
	if client == nil {
		// Handle nil client case, maybe return error or create default
		// For now, let's assume a valid client is passed.
		// If default creation is needed:
		// defaultCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		// if err != nil { /* handle error */ }
		// client = defaultCli
		panic("Image Inspector requires a valid Docker client") // Or return an error
	}

	if logger == nil {
		logger = logrus.New()
	}
	return &Inspector{
		client: client, // Store the provided client (as interface)
		logger: logger,
	}
}

// List returns a list of Docker images based on the provided options
func (i *Inspector) List(ctx context.Context, options ListOptions) ([]imagetypes.Summary, error) { // Use imagetypes.Summary
	i.logger.WithField("options", fmt.Sprintf("%+v", options)).Debug("Listing Docker images")
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%w: %v", ErrContextCancelled, ctx.Err())
	}

	filterArgs := filters.NewArgs()
	for key, value := range options.FilterLabels {
		filterArgs.Add("label", fmt.Sprintf("%s=%s", key, value))
	}
	if options.FilterDanglingOnly {
		filterArgs.Add("dangling", "true")
	}
	if options.MatchName != "" {
		filterArgs.Add("reference", options.MatchName)
	}
	if options.FilterBefore != "" {
		filterArgs.Add("before", options.FilterBefore)
	}
	if options.FilterSince != "" {
		filterArgs.Add("since", options.FilterSince)
	}
	if options.FilterReference != "" {
		filterArgs.Add("reference", options.FilterReference)
	}

	// Use imagetypes.ListOptions
	images, err := i.client.ImageList(ctx, imagetypes.ListOptions{ // Use imagetypes.ListOptions
		All:     options.All,
		Filters: filterArgs,
	})
	if err != nil {
		i.logger.WithError(err).Error("Failed to list Docker images")
		return nil, fmt.Errorf("%w: %v", ErrImageListing, err)
	}

	i.logger.WithField("count", len(images)).Debug("Listed Docker images")
	return images, nil // Return type is []imagetypes.Summary
}

// Inspect returns detailed information about a Docker image
func (i *Inspector) Inspect(ctx context.Context, imageIDOrName string) (types.ImageInspect, error) { // Keep types.ImageInspect
	i.logger.WithField("image", imageIDOrName).Debug("Inspecting Docker image")
	if ctx.Err() != nil {
		return types.ImageInspect{}, fmt.Errorf("%w: %v", ErrContextCancelled, ctx.Err())
	}
	if imageIDOrName == "" {
		return types.ImageInspect{}, ErrInvalidImageID
	}

	inspect, _, err := i.client.ImageInspectWithRaw(ctx, imageIDOrName)
	if err != nil {
		if errdefs.IsNotFound(err) {
			i.logger.WithField("image", imageIDOrName).Debug("Image not found")
			return types.ImageInspect{}, fmt.Errorf("%w: %s", ErrImageNotFound, imageIDOrName)
		}
		i.logger.WithError(err).WithField("image", imageIDOrName).Error("Failed to inspect Docker image")
		return types.ImageInspect{}, fmt.Errorf("%w: %v", ErrImageInspection, err)
	}

	i.logger.WithFields(logrus.Fields{
		"image":      imageIDOrName,
		"id":         inspect.ID,
		"created":    inspect.Created,
		"size_bytes": inspect.Size,
	}).Debug("Inspected Docker image")
	return inspect, nil
}

// History returns the history of a Docker image
func (i *Inspector) History(ctx context.Context, imageIDOrName string) ([]imagetypes.HistoryResponseItem, error) {
	i.logger.WithField("image", imageIDOrName).Debug("Getting Docker image history")
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%w: %v", ErrContextCancelled, ctx.Err())
	}
	if imageIDOrName == "" {
		return nil, ErrInvalidImageID
	}

	history, err := i.client.ImageHistory(ctx, imageIDOrName)
	if err != nil {
		if errdefs.IsNotFound(err) {
			i.logger.WithField("image", imageIDOrName).Debug("Image not found")
			return nil, fmt.Errorf("%w: %s", ErrImageNotFound, imageIDOrName)
		}
		i.logger.WithError(err).WithField("image", imageIDOrName).Error("Failed to get Docker image history")
		return nil, fmt.Errorf("%w: %v", ErrImageHistory, err)
	}

	i.logger.WithFields(logrus.Fields{
		"image":  imageIDOrName,
		"layers": len(history),
	}).Debug("Retrieved Docker image history")
	return history, nil
}

// GetImageDigest extracts the digest from an image
func (i *Inspector) GetImageDigest(ctx context.Context, imageIDOrName string) (string, error) {
	inspect, err := i.Inspect(ctx, imageIDOrName)
	if err != nil {
		return "", err
	}
	if len(inspect.RepoDigests) > 0 {
		parts := strings.SplitN(inspect.RepoDigests[0], "@", 2)
		if len(parts) == 2 {
			return parts[1], nil
		}
	}
	if inspect.ID != "" {
		return strings.TrimPrefix(inspect.ID, "sha256:"), nil
	}
	return "", fmt.Errorf("no digest found for image %s", imageIDOrName)
}

// GetImageCreationTime returns the creation time of an image
func (i *Inspector) GetImageCreationTime(ctx context.Context, imageIDOrName string) (time.Time, error) {
	inspect, err := i.Inspect(ctx, imageIDOrName)
	if err != nil {
		return time.Time{}, err
	}
	creationTime, err := time.Parse(time.RFC3339Nano, inspect.Created)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse image creation time: %w", err)
	}
	return creationTime, nil
}

// GetImageSize returns the size of an image in bytes
func (i *Inspector) GetImageSize(ctx context.Context, imageIDOrName string) (int64, error) {
	inspect, err := i.Inspect(ctx, imageIDOrName)
	if err != nil {
		return 0, err
	}
	return inspect.Size, nil
}

// GetImageLabels returns the labels of an image
func (i *Inspector) GetImageLabels(ctx context.Context, imageIDOrName string) (map[string]string, error) {
	inspect, err := i.Inspect(ctx, imageIDOrName)
	if err != nil {
		return nil, err
	}
	if inspect.Config == nil {
		return make(map[string]string), nil
	}
	return inspect.Config.Labels, nil
}

// GetImageExposedPorts returns the exposed ports of an image as map[string]struct{}
func (i *Inspector) GetImageExposedPorts(ctx context.Context, imageIDOrName string) (map[string]struct{}, error) {
	inspect, err := i.Inspect(ctx, imageIDOrName)
	if err != nil {
		return nil, err
	}
	if inspect.Config == nil || inspect.Config.ExposedPorts == nil {
		return make(map[string]struct{}), nil
	}
	exposedPorts := make(map[string]struct{})
	for port := range inspect.Config.ExposedPorts {
		exposedPorts[string(port)] = struct{}{}
	}
	return exposedPorts, nil
}

// GetImageEnvironment returns the environment variables of an image
func (i *Inspector) GetImageEnvironment(ctx context.Context, imageIDOrName string) ([]string, error) {
	inspect, err := i.Inspect(ctx, imageIDOrName)
	if err != nil {
		return nil, err
	}
	if inspect.Config == nil {
		return []string{}, nil
	}
	return inspect.Config.Env, nil
}

// GetImageCommand returns the default command of an image
func (i *Inspector) GetImageCommand(ctx context.Context, imageIDOrName string) ([]string, error) {
	inspect, err := i.Inspect(ctx, imageIDOrName)
	if err != nil {
		return nil, err
	}
	if inspect.Config == nil {
		return []string{}, nil
	}
	return inspect.Config.Cmd, nil
}

// GetImageEntrypoint returns the entrypoint of an image
func (i *Inspector) GetImageEntrypoint(ctx context.Context, imageIDOrName string) ([]string, error) {
	inspect, err := i.Inspect(ctx, imageIDOrName)
	if err != nil {
		return nil, err
	}
	if inspect.Config == nil {
		return []string{}, nil
	}
	return inspect.Config.Entrypoint, nil
}

// ImageExists checks if an image exists
func (i *Inspector) ImageExists(ctx context.Context, imageIDOrName string) (bool, error) {
	filterArgs := filters.NewArgs()
	filterArgs.Add("reference", imageIDOrName)
	// Use imagetypes.ListOptions
	images, err := i.client.ImageList(ctx, imagetypes.ListOptions{
		All:     true,
		Filters: filterArgs,
	})
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrImageListing, err)
	}
	return len(images) > 0, nil
}

// GetAllTags returns all tags for an image
func (i *Inspector) GetAllTags(ctx context.Context, imageID string) ([]string, error) {
	// Use image types.ListOptions
	images, err := i.client.ImageList(ctx, imagetypes.ListOptions{
		All: true,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrImageListing, err)
	}
	var tags []string
	for _, img := range images {
		trimmedID := strings.TrimPrefix(img.ID, "sha256:")
		if strings.HasPrefix(trimmedID, imageID) || strings.HasPrefix(img.ID, imageID) {
			tags = append(tags, img.RepoTags...)
		}
	}
	return tags, nil
}

// GetImageOSArch returns the OS and architecture of an image
func (i *Inspector) GetImageOSArch(ctx context.Context, imageIDOrName string) (string, string, error) {
	inspect, err := i.Inspect(ctx, imageIDOrName)
	if err != nil {
		return "", "", err
	}
	return inspect.Os, inspect.Architecture, nil
}

// GetImageLayers returns the layers of an image
func (i *Inspector) GetImageLayers(ctx context.Context, imageIDOrName string) ([]string, error) {
	history, err := i.History(ctx, imageIDOrName)
	if err != nil {
		return nil, err
	}
	var layers []string
	for _, item := range history {
		if item.Size > 0 {
			layers = append(layers, item.ID)
		}
	}
	return layers, nil
}

// GetTotalImagesCount returns the total number of images
func (i *Inspector) GetTotalImagesCount(ctx context.Context) (int, error) {
	// Use image types.ListOptions
	images, err := i.client.ImageList(ctx, imagetypes.ListOptions{
		All: true,
	})
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrImageListing, err)
	}
	return len(images), nil
}

// GetTotalImageDiskUsage returns the total disk space used by all images
func (i *Inspector) GetTotalImageDiskUsage(ctx context.Context) (int64, error) {
	// Use image types.ListOptions
	images, err := i.client.ImageList(ctx, imagetypes.ListOptions{
		All: true,
	})
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrImageListing, err)
	}
	var totalSize int64
	for _, img := range images {
		totalSize += img.Size
	}
	return totalSize, nil
}

// FormatImageSize formats the image size in a human-readable format
func (i *Inspector) FormatImageSize(size int64) string {
	// return utils.FormatImageSize(size) // Commented out until utils is fixed
	return fmt.Sprintf("%d", size) // Return raw size as string for now
}
