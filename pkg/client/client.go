package client

import (
	"bytes"
	"context"
	"crypto/tls" // Added import
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect" // Added import
	"strings" // Added import
	"time"

	networktypes "github.com/docker/docker/api/types/network"       // Added for EndpointSettings
	registrytypes "github.com/docker/docker/api/types/registry"     // Added for AuthConfig
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Re-added internal import
)

// API paths
const (
	APIBasePath         = "/api/v1"
	APIPathHealth       = "/health"
	APIPathAuth         = "/auth"
	APIPathAuthLogin    = "/auth/login"
	APIPathAuthRegister = "/auth/register"
	APIPathAuthRefresh  = "/auth/refresh"
	APIPathAuthLogout   = "/auth/logout"
	APIPathUser         = "/user"
	APIPathUserMe       = "/user/me"
	APIPathContainers   = "/containers"
	APIPathImages       = "/images"
	APIPathVolumes      = "/volumes"
	APIPathNetworks     = "/networks"
	APIPathCompose      = "/compose"
	APIPathSystem       = "/system"
	APIPathSystemInfo   = "/system/info"
	APIPathSystemPing   = "/system/ping"
	APIPathSystemEvents = "/system/events"
)

// Common errors
var (
	ErrNotFound         = fmt.Errorf("resource not found")
	ErrUnauthorized     = fmt.Errorf("unauthorized")
	ErrForbidden        = fmt.Errorf("forbidden")
	ErrBadRequest       = fmt.Errorf("bad request")
	ErrServerError      = fmt.Errorf("server error")
	ErrTimeout          = fmt.Errorf("request timeout")
	ErrConnectionFailed = fmt.Errorf("connection failed")
	ErrAlreadyExists    = fmt.Errorf("resource already exists")
	ErrConflict         = fmt.Errorf("conflict")
	ErrNotImplemented   = fmt.Errorf("not implemented")
)

// --- Client Configuration ---

// ClientOption represents a functional option for configuring the client
type ClientOption func(*ClientConfig) error

// ClientConfig represents the configuration for the client
type ClientConfig struct {
	BaseURL               string
	Timeout               time.Duration
	MaxRetries            int
	RetryDelay            time.Duration
	UserAgent             string
	AccessToken           string
	RefreshToken          string
	HTTPClient            *http.Client
	Headers               map[string]string
	AutoRefresh           bool
	TLSInsecureSkipVerify bool
}

// DefaultClientConfig returns the default client configuration
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		BaseURL:               "http://localhost:8080",
		Timeout:               time.Second * 30,
		MaxRetries:            3,
		RetryDelay:            time.Second * 1,
		UserAgent:             "DockerServerManagerClient/1.0",
		Headers:               make(map[string]string),
		AutoRefresh:           true,
		TLSInsecureSkipVerify: false,
	}
}

// WithBaseURL sets the base URL
func WithBaseURL(baseURL string) ClientOption {
	return func(config *ClientConfig) error {
		if baseURL == "" {
			return fmt.Errorf("base URL cannot be empty")
		}
		_, err := url.Parse(baseURL)
		if err != nil {
			return fmt.Errorf("invalid base URL: %w", err)
		}
		config.BaseURL = baseURL
		return nil
	}
}

// WithTimeout sets the timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(config *ClientConfig) error {
		if timeout <= 0 {
			return fmt.Errorf("timeout must be positive")
		}
		config.Timeout = timeout
		return nil
	}
}

// WithRetryOptions sets the retry options
func WithRetryOptions(maxRetries int, retryDelay time.Duration) ClientOption {
	return func(config *ClientConfig) error {
		if maxRetries < 0 {
			return fmt.Errorf("max retries must be non-negative")
		}
		if retryDelay < 0 {
			return fmt.Errorf("retry delay must be non-negative")
		}
		config.MaxRetries = maxRetries
		config.RetryDelay = retryDelay
		return nil
	}
}

// WithUserAgent sets the user agent
func WithUserAgent(userAgent string) ClientOption {
	return func(config *ClientConfig) error {
		if userAgent == "" {
			return fmt.Errorf("user agent cannot be empty")
		}
		config.UserAgent = userAgent
		return nil
	}
}

// WithAccessToken sets the initial access token
func WithAccessToken(token string) ClientOption {
	return func(config *ClientConfig) error {
		config.AccessToken = token
		return nil
	}
}

// WithRefreshToken sets the initial refresh token
func WithRefreshToken(token string) ClientOption {
	return func(config *ClientConfig) error {
		config.RefreshToken = token
		return nil
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) ClientOption {
	return func(config *ClientConfig) error {
		if client == nil {
			return fmt.Errorf("HTTP client cannot be nil")
		}
		config.HTTPClient = client
		return nil
	}
}

// WithHeader adds an HTTP header
func WithHeader(key, value string) ClientOption {
	return func(config *ClientConfig) error {
		if key == "" {
			return fmt.Errorf("header key cannot be empty")
		}
		if config.Headers == nil {
			config.Headers = make(map[string]string)
		}
		config.Headers[key] = value
		return nil
	}
}

// WithAutoRefresh sets the auto refresh option
func WithAutoRefresh(autoRefresh bool) ClientOption {
	return func(config *ClientConfig) error {
		config.AutoRefresh = autoRefresh
		return nil
	}
}

// WithTLSInsecureSkipVerify sets the TLS insecure skip verify option
func WithTLSInsecureSkipVerify(skip bool) ClientOption {
	return func(config *ClientConfig) error {
		config.TLSInsecureSkipVerify = skip
		return nil
	}
}

// AuthResponse represents the response from authentication endpoints
// Using models.TokenResponse structure now
type AuthResponse = models.TokenResponse

// Client defines the interface for the Docker Server Manager API client
// Uses types from internal/models
type Client interface {
	// Authentication
	Login(ctx context.Context, username, password string) (*AuthResponse, error)           // Uses models.TokenResponse via alias
	Register(ctx context.Context, username, password, email string) (*AuthResponse, error) // Uses models.TokenResponse via alias
	RefreshToken(ctx context.Context) (*AuthResponse, error)                               // Uses models.TokenResponse via alias
	Logout(ctx context.Context) error

	// Health check
	Health(ctx context.Context) (map[string]interface{}, error)

	// User management
	GetCurrentUser(ctx context.Context) (*models.UserResponse, error) // Return UserResponse
	UpdateCurrentUser(ctx context.Context, user *models.User) (*models.User, error)
	ChangePassword(ctx context.Context, oldPassword, newPassword string) error

	// Containers
	ListContainers(ctx context.Context, filters map[string]string) ([]models.Container, error)
	GetContainer(ctx context.Context, id string) (*models.Container, error)
	CreateContainer(ctx context.Context, req *models.ContainerCreateRequest) (*models.Container, error)
	StartContainer(ctx context.Context, id string) error
	StopContainer(ctx context.Context, id string, timeout *int) error
	RestartContainer(ctx context.Context, id string, timeout *int) error
	PauseContainer(ctx context.Context, id string) error
	UnpauseContainer(ctx context.Context, id string) error
	RemoveContainer(ctx context.Context, id string, force bool) error

	// Container operations
	GetContainerLogs(ctx context.Context, id string, options map[string]string) (io.ReadCloser, error)
	GetContainerStats(ctx context.Context, id string) (*models.ContainerStats, error)
	GetContainerProcesses(ctx context.Context, id string) ([][]string, error)

	// Exec
	ExecCreate(ctx context.Context, containerID string, req *models.ContainerExecCreateRequest) (string, error)
	ExecStart(ctx context.Context, execID string, interactive bool) (io.ReadWriteCloser, error)
	ExecResize(ctx context.Context, execID string, height, width uint) error
	// Images
	ListImages(ctx context.Context, filters map[string]string) ([]models.Image, error)
	GetImage(ctx context.Context, id string) (*models.Image, error)
	PullImage(ctx context.Context, ref string, auth *registrytypes.AuthConfig) error
	BuildImage(ctx context.Context, options *models.ImageBuildRequest) (string, error)
	RemoveImage(ctx context.Context, id string, force bool) error
	TagImage(ctx context.Context, id, repo, tag string) error

	// Volumes
	ListVolumes(ctx context.Context, filters map[string]string) ([]models.Volume, error)
	GetVolume(ctx context.Context, name string) (*models.Volume, error)
	CreateVolume(ctx context.Context, options *models.VolumeCreateRequest) (*models.Volume, error)
	RemoveVolume(ctx context.Context, name string, force bool) error

	// Networks
	ListNetworks(ctx context.Context, filters map[string]string) ([]models.Network, error)
	GetNetwork(ctx context.Context, id string) (*models.Network, error)
	CreateNetwork(ctx context.Context, options *models.NetworkCreateRequest) (*models.Network, error)
	RemoveNetwork(ctx context.Context, id string) error
	ConnectContainerToNetwork(ctx context.Context, networkID, containerID string, config *networktypes.EndpointSettings) error
	DisconnectContainerFromNetwork(ctx context.Context, networkID, containerID string, force bool) error

	// Compose
	ComposeUp(ctx context.Context, files []io.Reader, options interface{}) (string, error)      // Placeholder type
	ComposeDown(ctx context.Context, id string, options interface{}) error                      // Placeholder type
	GetComposeStatus(ctx context.Context, id string) (*models.ComposeDeploymentResponse, error) // Use models type
	ListComposeDeployments(ctx context.Context) ([]models.ComposeDeployment, error)             // Use models type

	// System
	GetSystemInfo(ctx context.Context) (*models.SystemInfoResponse, error)                                                      // Use models type
	GetEvents(ctx context.Context, since, until time.Time, filters map[string]string) (<-chan models.DockerEvent, <-chan error) // Use models.DockerEvent

	// Raw HTTP
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// APIClient implements the Client interface
type APIClient struct {
	config       ClientConfig
	httpClient   *http.Client
	accessToken  string
	refreshToken string
	tokenExpiry  time.Time
	tokenLock    chan struct{}
	refreshing   bool
}

// NewClient creates a new API client
func NewClient(opts ...ClientOption) (*APIClient, error) {
	config := DefaultClientConfig()

	// Apply options
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return nil, fmt.Errorf("option application failed: %w", err)
		}
	}

	// Create HTTP client if not provided
	httpClient := config.HTTPClient
	if httpClient == nil {
		// Configure transport with TLS settings
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: config.TLSInsecureSkipVerify},
		}
		httpClient = &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
		}
	} else if config.TLSInsecureSkipVerify {
		// Modify existing client's transport if skip verify is set
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{}
			}
			transport.TLSClientConfig.InsecureSkipVerify = true
		} else {
			fmt.Println("Warning: Cannot set TLSInsecureSkipVerify on custom HTTPClient transport")
		}
	}

	// Create client
	client := &APIClient{
		config:       config,
		httpClient:   httpClient,
		accessToken:  config.AccessToken,
		refreshToken: config.RefreshToken,
		tokenLock:    make(chan struct{}, 1),
	}

	// Initialize token lock
	client.tokenLock <- struct{}{}

	return client, nil
}

// buildURL builds the full URL for a given path
func (c *APIClient) buildURL(path string) string {
	baseURL := strings.TrimSuffix(c.config.BaseURL, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("%s%s%s", baseURL, APIBasePath, path)
}

// setAuthHeader sets the Authorization header for a request
func (c *APIClient) setAuthHeader(req *http.Request) {
	if c.accessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
	}
}

// newRequest creates a new HTTP request
func (c *APIClient) newRequest(ctx context.Context, method, path string, body interface{}) (*http.Request, error) {
	url := c.buildURL(path)

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if body != nil { // Only set Content-Type if there is a body
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.config.UserAgent)

	// Set additional headers
	for key, value := range c.config.Headers {
		req.Header.Set(key, value)
	}

	return req, nil
}

// handleResponse handles the HTTP response and decodes the JSON body if provided
func (c *APIClient) handleResponse(resp *http.Response, out interface{}) error {
	// Always read and close the body to prevent resource leaks
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		// Return read error, but still try to determine base error from status code if possible
		baseErr := ErrServerError
		switch resp.StatusCode {
		case http.StatusNotFound:
			baseErr = ErrNotFound
		case http.StatusUnauthorized:
			baseErr = ErrUnauthorized
		case http.StatusForbidden:
			baseErr = ErrForbidden
		case http.StatusBadRequest:
			baseErr = ErrBadRequest
		case http.StatusConflict:
			baseErr = ErrConflict
		case http.StatusNotImplemented:
			baseErr = ErrNotImplemented
		}
		return fmt.Errorf("%w: failed to read response body: %w", baseErr, readErr)
	}

	// Check for successful status codes (2xx)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if resp.StatusCode == http.StatusNoContent || out == nil {
			return nil // Nothing to decode
		}

		// 1. Try decoding into the standard success wrapper
		var successResp models.SuccessResponse
		var wrapperErr error                            // Declare wrapperErr here
		wrapperErr = json.Unmarshal(body, &successResp) // Assign error here
		if wrapperErr == nil && successResp.Success {
			if successResp.Data == nil {
				// Handle cases where Data is explicitly null
				outVal := reflect.ValueOf(out)
				if outVal.Kind() == reflect.Ptr && !outVal.IsNil() {
					outVal.Elem().Set(reflect.Zero(outVal.Elem().Type()))
				}
				return nil
			}
			// Marshal the Data field and unmarshal into the target 'out'
			dataBytes, marshalErr := json.Marshal(successResp.Data)
			if marshalErr != nil {
				return fmt.Errorf("failed to re-marshal success data: %w", marshalErr)
			}
			if unmarshalErr := json.Unmarshal(dataBytes, out); unmarshalErr != nil {
				return fmt.Errorf("failed to decode success data field into target type: %w", unmarshalErr)
			}
			return nil
		}

		// 2. If wrapper fails or doesn't match, try decoding the raw body directly into 'out'
		if errDirect := json.Unmarshal(body, out); errDirect == nil {
			return nil // Successfully decoded directly
		} else {
			// Return a more informative error if both attempts fail
			// Use the original wrapperErr if it exists, otherwise use errDirect
			decodeErr := wrapperErr // Use the captured wrapperErr
			if decodeErr == nil {
				decodeErr = errDirect
			}
			return fmt.Errorf("failed to decode successful response body (tried wrapper and direct): %w", decodeErr)
		}
	}

	// Handle error status codes (non-2xx)
	// 1. Try decoding into the standard error wrapper
	var errorResp models.ErrorResponse
	if err := json.Unmarshal(body, &errorResp); err == nil && !errorResp.Success && errorResp.Error.Message != "" {
		// Use the specific error message from the API response
		baseErr := ErrServerError // Default
		switch resp.StatusCode {
		case http.StatusNotFound:
			baseErr = ErrNotFound
		case http.StatusUnauthorized:
			baseErr = ErrUnauthorized
		case http.StatusForbidden:
			baseErr = ErrForbidden
		case http.StatusBadRequest:
			baseErr = ErrBadRequest
		case http.StatusConflict:
			baseErr = ErrConflict
		case http.StatusNotImplemented:
			baseErr = ErrNotImplemented
		}
		if errorResp.Error.Code != "" {
			return fmt.Errorf("%w: API error (%s): %s", baseErr, errorResp.Error.Code, errorResp.Error.Message)
		}
		return fmt.Errorf("%w: %s", baseErr, errorResp.Error.Message)
	}

	// 2. If error wrapper fails, return a generic error based on status code, including body snippet
	bodySnippet := string(body)
	if len(bodySnippet) > 100 { // Limit snippet length
		bodySnippet = bodySnippet[:100] + "..."
	}
	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("%w (body: %s)", ErrNotFound, bodySnippet)
	case http.StatusUnauthorized:
		return fmt.Errorf("%w (body: %s)", ErrUnauthorized, bodySnippet)
	case http.StatusForbidden:
		return fmt.Errorf("%w (body: %s)", ErrForbidden, bodySnippet)
	case http.StatusBadRequest:
		return fmt.Errorf("%w (body: %s)", ErrBadRequest, bodySnippet)
	case http.StatusConflict:
		return fmt.Errorf("%w (body: %s)", ErrConflict, bodySnippet)
	case http.StatusInternalServerError:
		return fmt.Errorf("%w (body: %s)", ErrServerError, bodySnippet)
	case http.StatusNotImplemented:
		return fmt.Errorf("%w (body: %s)", ErrNotImplemented, bodySnippet)
	default:
		return fmt.Errorf("unexpected status code %d (body: %s)", resp.StatusCode, bodySnippet)
	}
}

// Do sends an HTTP request and returns the response
func (c *APIClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") == "" {
		c.setAuthHeader(req)
	}

	var resp *http.Response
	var err error

	for retry := 0; retry <= c.config.MaxRetries; retry++ {
		var reqBodyBytes []byte
		if req.Body != nil {
			reqBodyBytes, err = io.ReadAll(req.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read request body for retry: %w", err)
			}
			req.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
		}

		resp, err = c.httpClient.Do(req)
		if err != nil {
			// Check for timeout or connection errors
			if urlErr, ok := err.(*url.Error); ok && (urlErr.Timeout() || urlErr.Temporary()) {
				if retry < c.config.MaxRetries {
					time.Sleep(c.config.RetryDelay)
					if req.Body != nil { // Reset body for retry
						req.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
					}
					continue
				}
				return nil, ErrTimeout // Return specific timeout error after retries
			}
			return nil, fmt.Errorf("%w: %w", ErrConnectionFailed, err) // Return specific connection error
		}

		// Check for 401 Unauthorized and attempt refresh if enabled
		if resp.StatusCode == http.StatusUnauthorized && c.config.AutoRefresh && c.refreshToken != "" && !c.refreshing {
			resp.Body.Close() // Close the original response body
			refreshErr := c.tryRefreshToken(ctx)
			if refreshErr == nil {
				// Retry the original request with the new token
				if req.Body != nil { // Reset body for retry
					req.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
				}
				c.setAuthHeader(req) // Set the new token
				resp, err = c.httpClient.Do(req)
				if err != nil {
					return nil, fmt.Errorf("%w: %w", ErrConnectionFailed, err)
				}
			} else {
				// Refresh failed, return the refresh error
				return nil, refreshErr
			}
		}

		// Check for retryable status codes (e.g., 5xx)
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			if retry < c.config.MaxRetries {
				resp.Body.Close() // Close body before retry
				time.Sleep(c.config.RetryDelay)
				if req.Body != nil { // Reset body for retry
					req.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
				}
				continue
			}
		}

		// If not retrying, break the loop
		break
	}

	return resp, err // Return the final response or error
}

// doRequest is a helper function to make requests and handle responses
func (c *APIClient) doRequest(ctx context.Context, method, path string, body, out interface{}) error {
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return err
	}

	resp, err := c.Do(ctx, req)
	if err != nil {
		return err
	}
	// Defer closing the body here, handleResponse will read it
	defer resp.Body.Close()

	return c.handleResponse(resp, out)
}

// tryRefreshToken attempts to refresh the access token using the refresh token
func (c *APIClient) tryRefreshToken(ctx context.Context) error {
	select {
	case <-c.tokenLock:
		defer func() { c.tokenLock <- struct{}{} }()
	case <-ctx.Done():
		return ctx.Err()
	}

	if !c.tokenNeedsRefresh() {
		return nil
	}

	c.refreshing = true
	defer func() { c.refreshing = false }()

	// Create request body
	refreshReq := map[string]string{"refresh_token": c.refreshToken}

	// Create request using doRequest which handles body marshaling
	var authResp AuthResponse // Define variable to receive response
	if err := c.doRequest(ctx, http.MethodPost, APIPathAuthRefresh, refreshReq, &authResp); err != nil {
		// Clear tokens on refresh failure
		c.accessToken = ""
		c.refreshToken = ""
		c.tokenExpiry = time.Time{}
		return fmt.Errorf("token refresh failed: %w", err)
	}

	// Update tokens (moved logic here from below)
	c.accessToken = authResp.AccessToken
	if authResp.RefreshToken != "" { // Only update refresh token if provided in response
		c.refreshToken = authResp.RefreshToken
	}
	c.tokenExpiry = authResp.ExpiresAt

	return nil // Return successful response

	// End of removed original code
}

// tokenNeedsRefresh checks if the access token is missing or expired
func (c *APIClient) tokenNeedsRefresh() bool {
	return c.accessToken == "" || time.Now().After(c.tokenExpiry.Add(-10*time.Second))
}

// Removed misplaced closing brace

// Health checks the API health
func (c *APIClient) Health(ctx context.Context) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := c.doRequest(ctx, http.MethodGet, APIPathHealth, nil, &result)
	return result, err
}

// Implementations for the Client interface methods will reside in other files
// (e.g., auth.go, containers.go, images.go, etc.)
