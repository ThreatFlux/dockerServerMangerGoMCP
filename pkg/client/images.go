package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/docker/distribution/reference"                      // Added for robust image ref parsing
	"github.com/docker/docker/api/types/registry"                   // Import registry types
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Keep internal import
)

// ImageListOptions represents options for listing images
type ImageListOptions struct {
	All     bool
	Digests bool
	Filters map[string][]string
}

// ImagePullOptions represents options for pulling images
type ImagePullOptions struct {
	Registry     string
	Repository   string
	Tag          string
	Platform     string
	Auth         *registry.AuthConfig // Use registry.AuthConfig
	RegistryAuth interface{}
}

// ImageBuildOptions represents options for building images
// Note: This mirrors models.ImageBuildRequest but includes io.Reader for context
type ImageBuildOptions struct {
	Repository     string                         `json:"repository"`
	Tag            string                         `json:"tag"`
	Dockerfile     string                         `json:"dockerfile"`
	Context        io.Reader                      `json:"-"` // Build context stream
	BuildArgs      map[string]string              `json:"build_args"`
	Labels         map[string]string              `json:"labels"`
	NoCache        bool                           `json:"no_cache"`
	Pull           bool                           `json:"pull"`
	RemoveAfter    bool                           `json:"remove_after"` // Corresponds to 'rm' in Docker API
	ForceRemove    bool                           `json:"force_remove"` // Corresponds to 'forcerm' in Docker API
	Target         string                         `json:"target"`
	Platform       string                         `json:"platform"`
	ExtraHosts     []string                       `json:"extra_hosts"`
	NetworkMode    string                         `json:"network_mode"`
	CgroupParent   string                         `json:"cgroup_parent"`
	ShmSize        int64                          `json:"shm_size"`
	Memory         int64                          `json:"memory"`
	MemorySwap     int64                          `json:"memory_swap"`
	CPUSetCPUs     string                         `json:"cpuset_cpus"`
	CPUSetMems     string                         `json:"cpuset_mems"`
	CPUShares      int64                          `json:"cpu_shares"`
	CPUPeriod      int64                          `json:"cpu_period"`
	CPUQuota       int64                          `json:"cpu_quota"`
	BuildID        string                         `json:"build_id"`
	Secrets        []map[string]string            `json:"secrets"`
	CacheFrom      []string                       `json:"cache_from"`
	SecurityOpt    []string                       `json:"security_opt"`
	NetworkConfig  map[string]string              `json:"network_config"`
	Squash         bool                           `json:"squash"`
	AuthConfigs    map[string]registry.AuthConfig `json:"auth_configs"` // Use registry.AuthConfig
	OutputFormat   string                         `json:"output_format"`
	BuildContextID string                         `json:"build_context_id"`
	// Ulimits field removed as it's complex and less common for client lib
}

// buildQueryParams converts image list options to URL query parameters
func buildImageListQueryParams(options *ImageListOptions) url.Values {
	query := url.Values{}

	if options == nil {
		return query
	}

	if options.All {
		query.Set("all", "true")
	}

	if options.Digests {
		query.Set("digests", "true")
	}

	if len(options.Filters) > 0 {
		filters, err := json.Marshal(options.Filters)
		if err == nil {
			query.Set("filters", string(filters))
		}
	}

	return query
}

// encodeAuthConfig encodes the auth configuration
func encodeAuthConfig(auth *registry.AuthConfig) (string, error) { // Use registry.AuthConfig
	if auth == nil {
		return "", nil
	}

	jsonAuth, err := json.Marshal(auth)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth config: %w", err)
	}

	return base64.URLEncoding.EncodeToString(jsonAuth), nil
}

// ListImages lists images with optional filters
func (c *APIClient) ListImages(ctx context.Context, filters map[string]string) ([]models.Image, error) { // Use models.Image
	// Convert simple filters map to the expected format
	options := &ImageListOptions{}
	if len(filters) > 0 {
		options.Filters = make(map[string][]string)
		for k, v := range filters {
			options.Filters[k] = []string{v}
		}
	}

	// Build query params
	query := buildImageListQueryParams(options)
	path := APIPathImages // Use constant
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	// Create request
	req, err := c.newRequest(ctx, http.MethodGet, APIPathImages, nil) // Use constant path
	if err != nil {
		return nil, fmt.Errorf("failed to create list images request: %w", err)
	}

	// Add query parameters
	req.URL.RawQuery = query.Encode()

	// Execute request
	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list images request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var images []models.Image // Use models.Image
	if err := c.handleResponse(resp, &images); err != nil {
		// Attempt direct unmarshal if wrapped response fails
		bodyBytes, readErr := io.ReadAll(resp.Body) // Need to re-read body if handleResponse failed early
		if readErr == nil {
			var directImages []models.Image
			if errDirect := json.Unmarshal(bodyBytes, &directImages); errDirect == nil {
				return directImages, nil
			}
		}
		// Return original handleResponse error if direct unmarshal also fails
		return nil, fmt.Errorf("failed to parse images response: %w", err)
	}

	return images, nil
}

// GetImage gets detailed information about an image
func (c *APIClient) GetImage(ctx context.Context, id string) (*models.Image, error) { // Use models.Image
	if id == "" {
		return nil, fmt.Errorf("image ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s", APIPathImages, id)

	var image models.Image // Use models.Image
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &image); err != nil {
		return nil, fmt.Errorf("failed to get image: %w", err)
	}

	return &image, nil
}

// PullImage pulls an image from a registry
func (c *APIClient) PullImage(ctx context.Context, ref string, auth *registry.AuthConfig) error { // Use registry.AuthConfig
	if ref == "" {
		return fmt.Errorf("image reference cannot be empty")
	}

	// Parse reference
	repo, tag := parseImageRef(ref)

	path := fmt.Sprintf("%s/pull", APIPathImages)

	// Create query parameters
	query := url.Values{}
	query.Set("fromImage", repo)
	if tag != "" {
		query.Set("tag", tag)
	}

	// Create request
	req, err := c.newRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("failed to create pull image request: %w", err)
	}

	// Add query parameters
	req.URL.RawQuery = query.Encode()

	// Add auth header if provided
	if auth != nil {
		authHeader, err := encodeAuthConfig(auth)
		if err != nil {
			return fmt.Errorf("failed to encode auth config: %w", err)
		}

		if authHeader != "" {
			req.Header.Set("X-Registry-Auth", authHeader)
		}
	}

	// Execute request
	resp, err := c.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("pull image request failed: %w", err)
	}
	defer resp.Body.Close()

	// Use handleResponse for consistent error handling and response parsing
	// We don't expect a specific body on success for pull, so pass nil for 'out'
	err = c.handleResponse(resp, nil)
	if err != nil {
		// handleResponse already wraps standard errors like ErrNotFound
		return fmt.Errorf("pull image failed: %w", err)
	}

	// Success (handleResponse returned nil)
	return nil
}

// BuildImage builds an image from a context
func (c *APIClient) BuildImage(ctx context.Context, options *models.ImageBuildRequest) (string, error) { // Use models.ImageBuildRequest
	if options == nil {
		return "", fmt.Errorf("build options cannot be nil")
	}
	// TODO: Implement BuildImage client logic
	// Requires handling multipart form data or tar stream upload
	return "", ErrNotImplemented
}

// RemoveImage removes an image with optional force flag
func (c *APIClient) RemoveImage(ctx context.Context, id string, force bool) error {
	if id == "" {
		return fmt.Errorf("image ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s", APIPathImages, id)

	// Add force flag if specified
	query := url.Values{}
	if force {
		query.Set("force", "true")
	}
	// Add other potential flags like noprune if needed from API spec

	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	if err := c.doRequest(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return fmt.Errorf("failed to remove image: %w", err)
	}

	return nil
}

// TagImage tags an image with a repository and tag
func (c *APIClient) TagImage(ctx context.Context, id, repo, tag string) error {
	if id == "" {
		return fmt.Errorf("image ID cannot be empty")
	}

	if repo == "" {
		return fmt.Errorf("repository cannot be empty")
	}

	// Path needs to be constructed carefully, API might expect ID in path or query
	// Assuming API expects ID in path for tagging action
	path := fmt.Sprintf("%s/%s/tag", APIPathImages, url.PathEscape(id)) // URL encode ID

	// Add repo and tag parameters
	query := url.Values{}
	query.Set("repo", repo)
	if tag != "" {
		query.Set("tag", tag)
	} else {
		query.Set("tag", "latest") // Default tag if not provided
	}

	path += "?" + query.Encode()

	if err := c.doRequest(ctx, http.MethodPost, path, nil, nil); err != nil {
		return fmt.Errorf("failed to tag image: %w", err)
	}

	return nil
}

// GetImageHistory gets the history of an image
func (c *APIClient) GetImageHistory(ctx context.Context, id string) ([]models.ImageHistoryResponse, error) { // Use models.ImageHistoryResponse
	if id == "" {
		return nil, fmt.Errorf("image ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/history", APIPathImages, url.PathEscape(id)) // URL encode ID

	var history []models.ImageHistoryResponse // Use models.ImageHistoryResponse
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &history); err != nil {
		return nil, fmt.Errorf("failed to get image history: %w", err)
	}

	return history, nil
}

// PushImage pushes an image to a registry
func (c *APIClient) PushImage(ctx context.Context, ref string, auth *registry.AuthConfig) error { // Use registry.AuthConfig
	if ref == "" {
		return fmt.Errorf("image reference cannot be empty")
	}

	// Parse reference
	repo, tag := parseImageRef(ref)
	if repo == "" {
		return fmt.Errorf("invalid image reference for push: %s", ref)
	}

	// Path needs image name (repo)
	path := fmt.Sprintf("%s/%s/push", APIPathImages, url.PathEscape(repo)) // URL encode repo

	// Add tag parameter if specified
	query := url.Values{}
	if tag != "" {
		query.Set("tag", tag)
	}

	// Create request
	req, err := c.newRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("failed to create push image request: %w", err)
	}

	// Add tag query parameter
	req.URL.RawQuery = query.Encode()

	// Add auth header if provided
	if auth != nil {
		authHeader, err := encodeAuthConfig(auth)
		if err != nil {
			return fmt.Errorf("failed to encode auth config: %w", err)
		}

		if authHeader != "" {
			req.Header.Set("X-Registry-Auth", authHeader)
		}
	}

	// Execute request
	resp, err := c.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("push image request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("push image failed with status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Read all output - although we're not using it here
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read push image response: %w", err)
	}

	return nil
}

// SearchImages searches for images in registries
func (c *APIClient) SearchImages(ctx context.Context, term string, limit int) ([]registry.SearchResult, error) { // Use registry.SearchResult
	if term == "" {
		return nil, fmt.Errorf("search term cannot be empty")
	}

	path := fmt.Sprintf("%s/search", APIPathImages)

	// Add query parameters
	query := url.Values{}
	query.Set("term", term)
	if limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", limit))
	}
	path += "?" + query.Encode()

	var results []registry.SearchResult // Use registry.SearchResult
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &results); err != nil {
		return nil, fmt.Errorf("failed to search images: %w", err)
	}

	return results, nil
}

// parseImageRef splits an image reference (e.g., "repo/image:tag") into repository and tag
func parseImageRef(ref string) (repository string, tag string) {
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		// Basic fallback if normalization fails completely
		parts := strings.SplitN(ref, ":", 2)
		repository = parts[0]
		if len(parts) == 2 {
			tag = parts[1]
		} else {
			tag = "latest" // Default tag if split doesn't find ':'
		}
		return repository, tag
	}

	repository = reference.TrimNamed(named).Name() // Use TrimNamed to get only the repo name

	if tagged, ok := named.(reference.Tagged); ok {
		tag = tagged.Tag()
	} else if _, ok := named.(reference.Digested); ok {
		tag = "" // Digests don't have tags
	} else {
		// Neither tagged nor digested, default to latest
		tag = "latest"
	}
	return repository, tag
}
