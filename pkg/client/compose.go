package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// ComposeUpOptions is now defined in internal/models

// ComposeDownOptions is now defined in internal/models

// UploadComposeFile uploads a Compose file to the server
func (c *APIClient) UploadComposeFile(ctx context.Context, content io.Reader, filename string) (string, error) {
	if content == nil {
		return "", fmt.Errorf("content cannot be nil")
	}

	if filename == "" {
		filename = "docker_test-compose.yml"
	}

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add file
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return "", fmt.Errorf("failed to create form file: %w", err)
	}

	_, err = io.Copy(part, content)
	if err != nil {
		return "", fmt.Errorf("failed to copy content: %w", err)
	}

	// Close writer
	err = writer.Close()
	if err != nil {
		return "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// Create request
	path := fmt.Sprintf("%s/upload", APIPathCompose)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.buildURL(path), body)
	if err != nil {
		return "", fmt.Errorf("failed to create upload request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", writer.FormDataContentType())
	c.setAuthHeader(req)

	// Execute request
	resp, err := c.Do(ctx, req)
	if err != nil {
		return "", fmt.Errorf("upload request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var uploadResponse struct {
		FileID string `json:"fileId"`
	}

	if err := c.handleResponse(resp, &uploadResponse); err != nil {
		return "", fmt.Errorf("failed to parse upload response: %w", err)
	}

	return uploadResponse.FileID, nil
}

// ValidateComposeFile validates a Compose file
func (c *APIClient) ValidateComposeFile(ctx context.Context, fileID string) ([]string, error) {
	if fileID == "" {
		return nil, fmt.Errorf("file ID cannot be empty")
	}

	path := fmt.Sprintf("%s/validate", APIPathCompose)

	// Create request body
	reqBody := struct {
		FileID string `json:"fileId"`
	}{
		FileID: fileID,
	}

	// Send request
	var validateResponse struct {
		Valid    bool     `json:"valid"`
		Errors   []string `json:"errors,omitempty"`
		Warnings []string `json:"warnings,omitempty"`
	}

	if err := c.doRequest(ctx, http.MethodPost, path, reqBody, &validateResponse); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	if !validateResponse.Valid {
		return validateResponse.Errors, fmt.Errorf("compose file is invalid: %s", strings.Join(validateResponse.Errors, "; "))
	}

	return validateResponse.Warnings, nil
}

// ComposeUp deploys services defined in Compose files
func (c *APIClient) ComposeUp(ctx context.Context, files []io.Reader, options *models.ComposeUpOptions) (string, error) { // Use models.ComposeUpOptions
	if len(files) == 0 {
		return "", fmt.Errorf("at least one compose file is required")
	}

	if options == nil {
		options = &models.ComposeUpOptions{} // Use models.ComposeUpOptions
	}

	// Upload each file
	var fileIDs []string
	for i, file := range files {
		filename := fmt.Sprintf("docker_test-compose-%d.yml", i+1)
		fileID, err := c.UploadComposeFile(ctx, file, filename)
		if err != nil {
			return "", fmt.Errorf("failed to upload compose file: %w", err)
		}
		fileIDs = append(fileIDs, fileID)
	}

	// Create up request body
	reqBody := struct {
		FileIDs []string                 `json:"fileIds"`
		Options *models.ComposeUpOptions `json:"options"` // Use models.ComposeUpOptions
	}{
		FileIDs: fileIDs,
		Options: options,
	}

	// Send request
	var upResponse struct {
		DeploymentID string `json:"deploymentId"`
	}

	if err := c.doRequest(ctx, http.MethodPost, APIPathCompose+"/up", reqBody, &upResponse); err != nil {
		return "", fmt.Errorf("compose up failed: %w", err)
	}

	return upResponse.DeploymentID, nil
}

// ComposeDown shuts down a Compose deployment
func (c *APIClient) ComposeDown(ctx context.Context, id string, options *models.ComposeDownOptions) error { // Use models.ComposeDownOptions
	if id == "" {
		return fmt.Errorf("deployment ID cannot be empty")
	}

	if options == nil {
		options = &models.ComposeDownOptions{} // Use models.ComposeDownOptions
	}

	path := fmt.Sprintf("%s/%s/down", APIPathCompose, id)

	if err := c.doRequest(ctx, http.MethodPost, path, options, nil); err != nil {
		return fmt.Errorf("compose down failed: %w", err)
	}

	return nil
}

// GetComposeStatus gets the status of a Compose deployment
func (c *APIClient) GetComposeStatus(ctx context.Context, id string) (*models.ComposeStatus, error) { // Use models.ComposeStatus
	if id == "" {
		return nil, fmt.Errorf("deployment ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s", APIPathCompose, id)

	var status models.ComposeStatus // Use models.ComposeStatus
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &status); err != nil {
		return nil, fmt.Errorf("failed to get compose status: %w", err)
	}

	return &status, nil
}

// ListComposeDeployments lists Compose deployments
func (c *APIClient) ListComposeDeployments(ctx context.Context) ([]models.ComposeDeploymentResponse, error) { // Use models.ComposeDeploymentResponse
	var deployments []models.ComposeDeploymentResponse // Use models.ComposeDeploymentResponse
	if err := c.doRequest(ctx, http.MethodGet, APIPathCompose, nil, &deployments); err != nil {
		return nil, fmt.Errorf("failed to list compose deployments: %w", err)
	}

	return deployments, nil
}

// ScaleComposeService scales a service in a Compose deployment
func (c *APIClient) ScaleComposeService(ctx context.Context, id string, service string, replicas int) error {
	if id == "" {
		return fmt.Errorf("deployment ID cannot be empty")
	}

	if service == "" {
		return fmt.Errorf("service name cannot be empty")
	}

	if replicas < 0 {
		return fmt.Errorf("replicas must be non-negative")
	}

	path := fmt.Sprintf("%s/%s/scale", APIPathCompose, id)

	// Create scale request body
	reqBody := struct {
		Service  string `json:"service"`
		Replicas int    `json:"replicas"`
	}{
		Service:  service,
		Replicas: replicas,
	}

	if err := c.doRequest(ctx, http.MethodPost, path, reqBody, nil); err != nil {
		return fmt.Errorf("scale service failed: %w", err)
	}

	return nil
}

// RestartComposeService restarts a service in a Compose deployment
func (c *APIClient) RestartComposeService(ctx context.Context, id string, service string) error {
	if id == "" {
		return fmt.Errorf("deployment ID cannot be empty")
	}

	if service == "" {
		return fmt.Errorf("service name cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/restart", APIPathCompose, id)

	// Create restart request body
	reqBody := struct {
		Service string `json:"service"`
	}{
		Service: service,
	}

	if err := c.doRequest(ctx, http.MethodPost, path, reqBody, nil); err != nil {
		return fmt.Errorf("restart service failed: %w", err)
	}

	return nil
}

// PullComposeImages pulls images for a Compose deployment
func (c *APIClient) PullComposeImages(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("deployment ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/pull", APIPathCompose, id)

	if err := c.doRequest(ctx, http.MethodPost, path, nil, nil); err != nil {
		return fmt.Errorf("pull images failed: %w", err)
	}

	return nil
}

// GetComposeLogs gets logs for a service in a Compose deployment
func (c *APIClient) GetComposeLogs(ctx context.Context, id string, service string, tail int) (io.ReadCloser, error) {
	if id == "" {
		return nil, fmt.Errorf("deployment ID cannot be empty")
	}

	// Allow empty service name to get logs for all services in the deployment

	path := fmt.Sprintf("%s/%s/logs", APIPathCompose, id) // Remove service from path

	// Add query parameters
	query := url.Values{}
	query.Set("service", service) // Add service as query parameter
	if tail > 0 {
		query.Set("tail", fmt.Sprintf("%d", tail))
	}

	// Create request
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create logs request: %w", err)
	}

	// Add query parameters
	req.URL.RawQuery = query.Encode()

	// Execute request
	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("logs request failed: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("logs request failed with status code %d", resp.StatusCode)
	}

	return resp.Body, nil
}

// WatchComposeDeployment watches the status of a Compose deployment
func (c *APIClient) WatchComposeDeployment(ctx context.Context, id string, interval time.Duration) (<-chan *models.ComposeStatus, <-chan error) { // Use models.ComposeStatus
	statusCh := make(chan *models.ComposeStatus) // Use models.ComposeStatus
	errCh := make(chan error, 1)

	if id == "" {
		errCh <- fmt.Errorf("deployment ID cannot be empty")
		close(statusCh)
		return statusCh, errCh
	}

	if interval <= 0 {
		interval = 2 * time.Second
	}

	go func() {
		defer close(statusCh)
		defer close(errCh)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case <-ticker.C:
				status, err := c.GetComposeStatus(ctx, id)
				if err != nil {
					errCh <- err
					return
				}

				statusCh <- status

				// Check if all services are in a final (settled) state (exited or dead)
				allSettled := true
				if len(status.Services) == 0 {
					allSettled = false // No services means not settled yet or error
				} else {
					for _, service := range status.Services {
						// Keep looping if any service is NOT in a final state
						if service.State != string(models.ServiceStatusExited) && service.State != string(models.ServiceStatusDead) {
							allSettled = false
							break
						}
					}
				}

				// If all services are settled, send the final status and exit the goroutine
				if allSettled {
					// statusCh <- status // Send final status (optional, already sent in loop)
					return // Exit goroutine
				}
			}
		}
	}()

	return statusCh, errCh
}
