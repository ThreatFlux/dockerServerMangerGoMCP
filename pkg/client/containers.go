package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	// "time" // Removed unused import

	"github.com/docker/docker/api/types/container" // Add container import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// ContainerListOptions represents options for listing containers
type ContainerListOptions struct {
	All     bool
	Limit   int
	Size    bool
	Filters map[string][]string
}

// ContainerLogOptions represents options for getting container logs
type ContainerLogOptions struct {
	ShowStdout bool
	ShowStderr bool
	Since      string
	Until      string
	Timestamps bool
	Follow     bool
	Tail       string
	Details    bool
}

// ExecStartOptions represents options for starting an exec instance
type ExecStartOptions struct {
	Detach      bool
	Tty         bool
	Interactive bool
}

// buildQueryParams converts container list options to URL query parameters
func buildContainerListQueryParams(options *ContainerListOptions) url.Values {
	query := url.Values{}

	if options == nil {
		return query
	}

	if options.All {
		query.Set("all", "true")
	}

	if options.Limit > 0 {
		query.Set("limit", strconv.Itoa(options.Limit))
	}

	if options.Size {
		query.Set("size", "true")
	}

	if len(options.Filters) > 0 {
		filters, err := json.Marshal(options.Filters)
		if err == nil {
			query.Set("filters", string(filters))
		}
	}

	return query
}

// buildLogQueryParams converts container log options to URL query parameters
func buildContainerLogQueryParams(options *ContainerLogOptions) url.Values {
	query := url.Values{}

	if options == nil {
		return query
	}

	query.Set("stdout", strconv.FormatBool(options.ShowStdout))
	query.Set("stderr", strconv.FormatBool(options.ShowStderr))

	if options.Since != "" {
		query.Set("since", options.Since)
	}

	if options.Until != "" {
		query.Set("until", options.Until)
	}

	if options.Timestamps {
		query.Set("timestamps", "true")
	}

	if options.Follow {
		query.Set("follow", "true")
	}

	if options.Tail != "" {
		query.Set("tail", options.Tail)
	}

	if options.Details {
		query.Set("details", "true")
	}

	return query
}

// ListContainers lists containers with optional filters
func (c *APIClient) ListContainers(ctx context.Context, filters map[string]string) ([]models.Container, error) {
	// Convert simple filters map to the expected format
	options := &ContainerListOptions{}
	if len(filters) > 0 {
		options.Filters = make(map[string][]string)
		for k, v := range filters {
			options.Filters[k] = []string{v}
		}
	}

	// Build query params
	query := buildContainerListQueryParams(options)
	url := c.buildURL(APIPathContainers)
	if len(query) > 0 {
		url += "?" + query.Encode()
	}

	// Create request
	req, err := c.newRequest(ctx, http.MethodGet, APIPathContainers, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create list containers request: %w", err)
	}

	// Add query parameters
	req.URL.RawQuery = query.Encode()

	// Execute request
	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list containers request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var containers []models.Container
	if err := c.handleResponse(resp, &containers); err != nil {
		return nil, fmt.Errorf("failed to parse containers response: %w", err)
	}

	return containers, nil
}

// GetContainer gets detailed information about a container
func (c *APIClient) GetContainer(ctx context.Context, id string) (*models.Container, error) {
	if id == "" {
		return nil, fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s", APIPathContainers, id)

	var container models.Container
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &container); err != nil {
		return nil, fmt.Errorf("failed to get container: %w", err)
	}

	return &container, nil
}

// CreateContainer creates a new container
func (c *APIClient) CreateContainer(ctx context.Context, req *models.ContainerCreateRequest) (*models.Container, error) { // Use models.ContainerCreateRequest
	if req == nil {
		return nil, fmt.Errorf("create container request cannot be nil")
	}

	// Validate required fields
	if req.Image == "" {
		return nil, fmt.Errorf("image name cannot be empty")
	}

	var container models.Container
	if err := c.doRequest(ctx, http.MethodPost, APIPathContainers, req, &container); err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	return &container, nil
}

// StartContainer starts a container
func (c *APIClient) StartContainer(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/start", APIPathContainers, id)

	if err := c.doRequest(ctx, http.MethodPost, path, nil, nil); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	return nil
}

// StopContainer stops a container with optional timeout
func (c *APIClient) StopContainer(ctx context.Context, id string, timeout *int) error {
	if id == "" {
		return fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/stop", APIPathContainers, id)

	// Add timeout if specified
	if timeout != nil {
		query := url.Values{}
		query.Set("t", strconv.Itoa(*timeout))
		path += "?" + query.Encode()
	}

	if err := c.doRequest(ctx, http.MethodPost, path, nil, nil); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	return nil
}

// RestartContainer restarts a container with optional timeout
func (c *APIClient) RestartContainer(ctx context.Context, id string, timeout *int) error {
	if id == "" {
		return fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/restart", APIPathContainers, id)

	// Add timeout if specified
	if timeout != nil {
		query := url.Values{}
		query.Set("t", strconv.Itoa(*timeout))
		path += "?" + query.Encode()
	}

	if err := c.doRequest(ctx, http.MethodPost, path, nil, nil); err != nil {
		return fmt.Errorf("failed to restart container: %w", err)
	}

	return nil
}

// PauseContainer pauses a container
func (c *APIClient) PauseContainer(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/pause", APIPathContainers, id)

	if err := c.doRequest(ctx, http.MethodPost, path, nil, nil); err != nil {
		return fmt.Errorf("failed to pause container: %w", err)
	}

	return nil
}

// UnpauseContainer unpauses a container
func (c *APIClient) UnpauseContainer(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/unpause", APIPathContainers, id)

	if err := c.doRequest(ctx, http.MethodPost, path, nil, nil); err != nil {
		return fmt.Errorf("failed to unpause container: %w", err)
	}

	return nil
}

// RemoveContainer removes a container with optional force flag
func (c *APIClient) RemoveContainer(ctx context.Context, id string, force bool) error {
	if id == "" {
		return fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s", APIPathContainers, id)

	// Add force flag if specified
	if force {
		query := url.Values{}
		query.Set("force", "true")
		path += "?" + query.Encode()
	}

	if err := c.doRequest(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	return nil
}

// GetContainerLogs gets logs from a container
func (c *APIClient) GetContainerLogs(ctx context.Context, id string, options map[string]string) (io.ReadCloser, error) {
	if id == "" {
		return nil, fmt.Errorf("container ID cannot be empty")
	}

	// Convert options map to log options struct
	logOptions := &ContainerLogOptions{
		ShowStdout: true,
		ShowStderr: true,
	}

	if options != nil {
		if val, ok := options["stdout"]; ok {
			logOptions.ShowStdout = val == "true"
		}
		if val, ok := options["stderr"]; ok {
			logOptions.ShowStderr = val == "true"
		}
		if val, ok := options["since"]; ok {
			logOptions.Since = val
		}
		if val, ok := options["until"]; ok {
			logOptions.Until = val
		}
		if val, ok := options["timestamps"]; ok {
			logOptions.Timestamps = val == "true"
		}
		if val, ok := options["follow"]; ok {
			logOptions.Follow = val == "true"
		}
		if val, ok := options["tail"]; ok {
			logOptions.Tail = val
		}
		if val, ok := options["details"]; ok {
			logOptions.Details = val == "true"
		}
	}

	path := fmt.Sprintf("%s/%s/logs", APIPathContainers, id)

	// Create request
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create container logs request: %w", err)
	}

	// Add query parameters
	query := buildContainerLogQueryParams(logOptions)
	req.URL.RawQuery = query.Encode()

	// Execute request
	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("container logs request failed: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		// Attempt to parse error response for more details
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodySnippet := string(bodyBytes)
		if len(bodySnippet) > 100 {
			bodySnippet = bodySnippet[:100] + "..."
		}
		return nil, fmt.Errorf("container logs request failed with status code %d: %s", resp.StatusCode, bodySnippet)
	}

	return resp.Body, nil
}

// GetContainerStats gets stats from a container
func (c *APIClient) GetContainerStats(ctx context.Context, id string) (*models.ContainerStats, error) {
	if id == "" {
		return nil, fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/stats", APIPathContainers, id)

	// Add query parameters to get non-streaming stats
	query := url.Values{}
	query.Set("stream", "false")
	path += "?" + query.Encode()

	var stats models.ContainerStats
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &stats); err != nil {
		return nil, fmt.Errorf("failed to get container stats: %w", err)
	}

	return &stats, nil
}

// GetContainerProcesses gets processes running in a container
func (c *APIClient) GetContainerProcesses(ctx context.Context, id string) ([][]string, error) {
	if id == "" {
		return nil, fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/top", APIPathContainers, id)

	// Create request
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create container processes request: %w", err)
	}

	// Execute request
	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("container processes request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var topResponse struct {
		Titles    []string   `json:"Titles"`
		Processes [][]string `json:"Processes"`
	}

	if err := c.handleResponse(resp, &topResponse); err != nil {
		return nil, fmt.Errorf("failed to parse container processes response: %w", err)
	}

	return topResponse.Processes, nil
}

// ExecCreate creates an exec instance in a container
func (c *APIClient) ExecCreate(ctx context.Context, containerID string, req *models.ContainerExecCreateRequest) (string, error) { // Use models.ContainerExecCreateRequest
	if containerID == "" {
		return "", fmt.Errorf("container ID cannot be empty")
	}

	if req == nil {
		return "", fmt.Errorf("exec config cannot be nil")
	}

	// Validate required fields
	if len(req.Command) == 0 {
		return "", fmt.Errorf("command cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/exec", APIPathContainers, containerID)

	// Send request
	var response struct {
		ID string `json:"Id"`
	}

	if err := c.doRequest(ctx, http.MethodPost, path, req, &response); err != nil {
		return "", fmt.Errorf("failed to create exec instance: %w", err)
	}

	return response.ID, nil
}

// ExecStart starts an exec instance
func (c *APIClient) ExecStart(ctx context.Context, execID string, interactive bool) (io.ReadWriteCloser, error) {
	if execID == "" {
		return nil, fmt.Errorf("exec ID cannot be empty")
	}

	path := fmt.Sprintf("/exec/%s/start", execID)

	// Create request with hijacked connection for interactive sessions
	startConfig := ExecStartOptions{
		Detach:      false,
		Tty:         true,
		Interactive: interactive,
	}

	// Create HTTP request manually to handle hijacking
	req, err := c.newRequest(ctx, http.MethodPost, path, startConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create exec start request: %w", err)
	}

	// Set up for hijacking
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")

	// This is a simplified version - in a real implementation, you would
	// need to hijack the connection and handle the bidirectional stream
	// For now, we'll return an error indicating this is not fully implemented
	return nil, fmt.Errorf("exec start with interactive mode is not fully implemented in this client")
}

// ExecResize resizes the TTY session of an exec instance
func (c *APIClient) ExecResize(ctx context.Context, execID string, height, width uint) error {
	if execID == "" {
		return fmt.Errorf("exec ID cannot be empty")
	}

	path := fmt.Sprintf("/exec/%s/resize", execID)

	// Add resize parameters
	query := url.Values{}
	query.Set("h", strconv.FormatUint(uint64(height), 10))
	query.Set("w", strconv.FormatUint(uint64(width), 10))
	path += "?" + query.Encode()

	if err := c.doRequest(ctx, http.MethodPost, path, nil, nil); err != nil {
		return fmt.Errorf("failed to resize exec instance: %w", err)
	}

	return nil
}

// RenameContainer renames a container
func (c *APIClient) RenameContainer(ctx context.Context, id string, newName string) error {
	if id == "" {
		return fmt.Errorf("container ID cannot be empty")
	}
	if newName == "" {
		return fmt.Errorf("new name cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/rename", APIPathContainers, id)

	// Add new name parameter
	query := url.Values{}
	query.Set("name", newName)
	path += "?" + query.Encode()

	if err := c.doRequest(ctx, http.MethodPost, path, nil, nil); err != nil {
		return fmt.Errorf("failed to rename container: %w", err)
	}

	return nil
}

// WaitContainer waits for a container to reach a certain condition
func (c *APIClient) WaitContainer(ctx context.Context, id string, condition string) (int, error) {
	if id == "" {
		return -1, fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/wait", APIPathContainers, id)

	// Add condition parameter if specified
	if condition != "" {
		query := url.Values{}
		query.Set("condition", condition)
		path += "?" + query.Encode()
	}

	var response struct {
		StatusCode int    `json:"StatusCode"`
		Error      string `json:"Error,omitempty"` // Assuming API might return an error message
	}

	if err := c.doRequest(ctx, http.MethodPost, path, nil, &response); err != nil {
		return -1, fmt.Errorf("failed to wait for container: %w", err)
	}

	if response.Error != "" {
		return response.StatusCode, fmt.Errorf("wait container error: %s", response.Error)
	}

	return response.StatusCode, nil
}

// ResizeContainerTTY resizes the TTY of a running container
func (c *APIClient) ResizeContainerTTY(ctx context.Context, id string, height, width uint) error {
	if id == "" {
		return fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/resize", APIPathContainers, id)

	// Add resize parameters
	query := url.Values{}
	query.Set("h", strconv.FormatUint(uint64(height), 10))
	query.Set("w", strconv.FormatUint(uint64(width), 10))
	path += "?" + query.Encode()

	if err := c.doRequest(ctx, http.MethodPost, path, nil, nil); err != nil {
		return fmt.Errorf("failed to resize container TTY: %w", err)
	}

	return nil
}

// UpdateContainer updates the configuration of a container
func (c *APIClient) UpdateContainer(ctx context.Context, id string, updateConfig *container.UpdateConfig) (*models.Container, error) { // Use container.UpdateConfig
	if id == "" {
		return nil, fmt.Errorf("container ID cannot be empty")
	}
	if updateConfig == nil {
		return nil, fmt.Errorf("update config cannot be nil")
	}

	path := fmt.Sprintf("%s/%s/update", APIPathContainers, id)

	var container models.Container
	if err := c.doRequest(ctx, http.MethodPost, path, updateConfig, &container); err != nil {
		return nil, fmt.Errorf("failed to update container: %w", err)
	}

	return &container, nil
}

// CopyToContainer copies files/folders to a container
func (c *APIClient) CopyToContainer(ctx context.Context, containerID, path string, content io.Reader) error {
	if containerID == "" {
		return fmt.Errorf("container ID cannot be empty")
	}

	// Ensure path is absolute
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	apiPath := fmt.Sprintf("%s/%s/archive?path=%s", APIPathContainers, containerID, url.QueryEscape(path)) // Use /archive path

	// Create request with content
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.buildURL(apiPath), content) // Use PUT method
	if err != nil {
		return fmt.Errorf("failed to create copy to container request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-tar")
	req.Header.Set("User-Agent", c.config.UserAgent)

	// Set authentication header
	c.setAuthHeader(req)

	// Set additional headers
	for key, value := range c.config.Headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := c.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("copy to container request failed: %w", err)
	}
	defer resp.Body.Close()

	// Use handleResponse for consistent error handling
	if err := c.handleResponse(resp, nil); err != nil {
		return fmt.Errorf("copy to container failed: %w", err)
	}

	return nil
}

// CopyFromContainer copies files/folders from a container
func (c *APIClient) CopyFromContainer(ctx context.Context, containerID, path string) (io.ReadCloser, error) {
	if containerID == "" {
		return nil, fmt.Errorf("container ID cannot be empty")
	}

	if path == "" {
		return nil, fmt.Errorf("path cannot be empty")
	}

	// Path needs to be constructed carefully
	basePath := fmt.Sprintf("%s/%s/archive", APIPathContainers, containerID) // Use /archive path
	query := url.Values{}
	query.Set("path", path) // Use non-escaped path for query param

	// Create request
	req, err := c.newRequest(ctx, http.MethodGet, basePath, nil) // Use base path
	if err != nil {
		return nil, fmt.Errorf("failed to create copy from container request: %w", err)
	}
	req.URL.RawQuery = query.Encode() // Set query params separately

	// Execute request
	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("copy from container request failed: %w", err)
	}

	// Check status code directly, do not use handleResponse for streams
	if resp.StatusCode != http.StatusOK {
		// Read body for error context before closing
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close() // Close body on error
		bodySnippet := string(bodyBytes)
		if len(bodySnippet) > 100 {
			bodySnippet = bodySnippet[:100] + "..."
		}
		// Try to parse standard error response
		var errorResp models.ErrorResponse
		if json.Unmarshal(bodyBytes, &errorResp) == nil && !errorResp.Success {
			baseErr := ErrServerError
			if resp.StatusCode == http.StatusNotFound {
				baseErr = ErrNotFound
			}
			return nil, fmt.Errorf("%w: %s", baseErr, errorResp.Error.Message)
		}
		// Fallback generic error
		return nil, fmt.Errorf("copy from container failed with status code %d: %s", resp.StatusCode, bodySnippet)
	}

	// Return the response body directly for the caller to handle the tar stream
	return resp.Body, nil
}
