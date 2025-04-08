package client

import (
	"context"
	"encoding/json"

	"io" // Added import for io.EOF
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Added import
)

// TestNewClient tests the creation of a new client
func TestNewClient(t *testing.T) {
	// Test with default options
	client, err := NewClient()
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, DefaultClientConfig().BaseURL, client.config.BaseURL)

	// Test with custom options
	baseURL := "https://example.com"
	timeout := time.Second * 60
	userAgent := "TestAgent/1.0"
	accessToken := "test-access-token"
	refreshToken := "test-refresh-token"

	client, err = NewClient(
		WithBaseURL(baseURL),
		WithTimeout(timeout),
		WithUserAgent(userAgent),
		WithAccessToken(accessToken),
		WithRefreshToken(refreshToken),
	)
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, baseURL, client.config.BaseURL)
	assert.Equal(t, timeout, client.config.Timeout)
	assert.Equal(t, userAgent, client.config.UserAgent)
	assert.Equal(t, accessToken, client.accessToken)
	assert.Equal(t, refreshToken, client.refreshToken)

	// Test with custom HTTP client
	httpClient := &http.Client{Timeout: time.Second * 120}
	client, err = NewClient(WithHTTPClient(httpClient))
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, httpClient, client.httpClient)

	// Test with invalid options
	_, err = NewClient(WithTimeout(0))
	assert.Error(t, err)

	_, err = NewClient(WithBaseURL(""))
	assert.Error(t, err)

	_, err = NewClient(WithUserAgent(""))
	assert.Error(t, err)

	_, err = NewClient(WithHTTPClient(nil))
	assert.Error(t, err)

	_, err = NewClient(WithRetryOptions(-1, 0))
	assert.Error(t, err)
}

// TestBuildURL tests the URL building
func TestBuildURL(t *testing.T) {
	client, err := NewClient(WithBaseURL("https://example.com"))
	require.NoError(t, err)

	// Test various paths
	assert.Equal(t, "https://example.com/api/v1/health", client.buildURL(APIPathHealth))
	assert.Equal(t, "https://example.com/api/v1/auth/login", client.buildURL(APIPathAuthLogin))
	assert.Equal(t, "https://example.com/api/v1/containers", client.buildURL(APIPathContainers))

	// Test with trailing slash in base URL
	client, err = NewClient(WithBaseURL("https://example.com/"))
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/api/v1/health", client.buildURL(APIPathHealth)) // Corrected: No double slash expected even with trailing slash in base URL
}

// TestSetAuthHeader tests the auth header setting
func TestSetAuthHeader(t *testing.T) {
	accessToken := "test-access-token"
	client, err := NewClient(WithAccessToken(accessToken))
	require.NoError(t, err)

	// Create test request
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	// Set auth header
	client.setAuthHeader(req)

	// Check header
	assert.Equal(t, "Bearer "+accessToken, req.Header.Get("Authorization"))

	// Test with empty token
	client.accessToken = ""
	req, err = http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	client.setAuthHeader(req)
	assert.Empty(t, req.Header.Get("Authorization"))
}

// TestNewRequest tests the request creation
func TestNewRequest(t *testing.T) {
	client, err := NewClient(
		WithBaseURL("https://example.com"),
		WithUserAgent("TestAgent/1.0"),
		WithAccessToken("test-token"),
		WithHeader("X-Test", "test-value"),
	)
	require.NoError(t, err)

	// Create test context
	ctx := context.Background()

	// Test GET request without body
	req, err := client.newRequest(ctx, http.MethodGet, APIPathHealth, nil)
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, req.Method)
	assert.Equal(t, "https://example.com/api/v1/health", req.URL.String())
	assert.Empty(t, req.Header.Get("Content-Type")) // GET request has no body, so no Content-Type
	assert.Equal(t, "application/json", req.Header.Get("Accept"))
	assert.Equal(t, "TestAgent/1.0", req.Header.Get("User-Agent"))
	// Authorization header is set by Do(), not newRequest()
	assert.Equal(t, "test-value", req.Header.Get("X-Test"))

	// Test POST request with body
	body := map[string]string{"key": "value"}
	req, err = client.newRequest(ctx, http.MethodPost, APIPathAuthLogin, body)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "https://example.com/api/v1/auth/login", req.URL.String())
	assert.NotNil(t, req.Body)
	assert.Equal(t, "application/json", req.Header.Get("Content-Type")) // POST request with body should have Content-Type
}

// TestHandleResponse tests the response handling
func TestHandleResponse(t *testing.T) {
	client, err := NewClient()
	require.NoError(t, err)

	// Test successful response
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       createMockBody(`{"key":"value"}`),
	}

	var result map[string]string
	err = client.handleResponse(resp, &result)
	require.NoError(t, err)
	assert.Equal(t, "value", result["key"])

	// Test various status codes
	statusCodes := map[int]error{
		http.StatusNotFound:            ErrNotFound,
		http.StatusUnauthorized:        ErrUnauthorized,
		http.StatusForbidden:           ErrForbidden,
		http.StatusBadRequest:          ErrBadRequest,
		http.StatusConflict:            ErrConflict,
		http.StatusInternalServerError: ErrServerError,
		http.StatusNotImplemented:      ErrNotImplemented,
	}

	for code, expectedErr := range statusCodes {
		resp := &http.Response{
			StatusCode: code,
			Body:       createMockBody(`{}`),
		}

		err = client.handleResponse(resp, nil)
		assert.ErrorIs(t, err, expectedErr) // Check if the error wraps the expected base error
	}

	// Test with nil output parameter
	resp = &http.Response{
		StatusCode: http.StatusOK,
		Body:       createMockBody(`{"key":"value"}`),
	}
	err = client.handleResponse(resp, nil)
	assert.NoError(t, err)

	// Test with invalid JSON
	resp = &http.Response{
		StatusCode: http.StatusOK,
		Body:       createMockBody(`{"key":invalid}`),
	}
	err = client.handleResponse(resp, &result)
	assert.Error(t, err)
}

// TestDo tests the HTTP request execution
func TestDo(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle refresh token request separately
		if r.URL.Path == APIBasePath+APIPathAuthRefresh && r.Method == http.MethodPost {
			var refreshReq map[string]string
			if err := json.NewDecoder(r.Body).Decode(&refreshReq); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(models.ErrorResponse{Success: false, Error: models.ErrorInfo{Code: "INVALID_REQUEST", Message: "invalid request body"}})
				return
			}
			refreshToken, ok := refreshReq["refresh_token"]
			if !ok || refreshToken != "valid-refresh" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(models.ErrorResponse{Success: false, Error: models.ErrorInfo{Code: "INVALID_TOKEN", Message: "invalid refresh token"}})
				return
			}
			// Return success response for refresh
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(models.SuccessResponse{
				Success: true,
				Data: models.TokenResponse{
					AccessToken:  "refreshed-token",
					RefreshToken: "valid-refresh", // Keep the same refresh token for simplicity in test
					ExpiresAt:    time.Now().Add(time.Hour),
				},
			})
			return
		}

		// Handle original health check request
		if r.URL.Path == APIBasePath+APIPathHealth && r.Method == http.MethodGet {
			assert.Equal(t, "TestAgent/1.0", r.Header.Get("User-Agent"))
			authHeader := r.Header.Get("Authorization")

			if authHeader == "Bearer valid-token" || authHeader == "Bearer refreshed-token" {
				// Success for valid or refreshed token
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(models.SuccessResponse{Success: true, Data: map[string]string{"status": "ok"}})
			} else if authHeader == "Bearer invalid-token" {
				// Initial 401 to trigger refresh
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(models.ErrorResponse{Success: false, Error: models.ErrorInfo{Code: "INVALID_TOKEN", Message: "invalid token"}})
			} else {
				// Success for no token (initial request before refresh logic tested)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(models.SuccessResponse{Success: true, Data: map[string]string{"status": "ok"}})
			}
			return
		}

		// Fallback for unexpected requests
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create client with test server URL
	client, err := NewClient(
		WithBaseURL(server.URL),
		WithUserAgent("TestAgent/1.0"),
	)
	require.NoError(t, err)

	// Create test context
	ctx := context.Background()

	// Create test request
	req, err := client.newRequest(ctx, http.MethodGet, APIPathHealth, nil)
	require.NoError(t, err)

	// Test successful request
	resp, err := client.Do(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Test with valid token
	client.accessToken = "valid-token"
	req, err = client.newRequest(ctx, http.MethodGet, APIPathHealth, nil)
	require.NoError(t, err)
	resp, err = client.Do(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Test with invalid token but valid refresh token
	client.accessToken = "invalid-token"
	client.refreshToken = "valid-refresh"
	client.config.AutoRefresh = true
	req, err = client.newRequest(ctx, http.MethodGet, APIPathHealth, nil)
	require.NoError(t, err)
	resp, err = client.Do(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "refreshed-token", client.accessToken)
	resp.Body.Close()
}

// TestHealth tests the health check endpoint
func TestHealth(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/health", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","version":"1.0.0"}`))
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test health check
	result, err := client.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
	assert.Equal(t, "1.0.0", result["version"])
}

// Helper function to create a mock response body
func createMockBody(body string) *mockReadCloser {
	return &mockReadCloser{
		Reader: body,
	}
}

// mockReadCloser implements io.ReadCloser for testing
type mockReadCloser struct {
	Reader string
	offset int
}

func (m *mockReadCloser) Read(p []byte) (n int, err error) {
	if m.offset >= len(m.Reader) {
		return 0, io.EOF
	}

	n = copy(p, m.Reader[m.offset:])
	m.offset += n
	return n, nil
}

func (m *mockReadCloser) Close() error {
	return nil
}
