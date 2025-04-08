package client

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// LoginRequest represents the request body for a login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// RegisterRequest represents the request body for a register request
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// PasswordChangeRequest represents the request body for a password change
type PasswordChangeRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

// Login authenticates with the API and returns an authentication response
func (c *APIClient) Login(ctx context.Context, username, password string) (*AuthResponse, error) {
	// Validate input
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// Create request body
	reqBody := LoginRequest{
		Username: username,
		Password: password,
	}

	// Send request
	var authResp AuthResponse
	if err := c.doRequest(ctx, http.MethodPost, APIPathAuthLogin, reqBody, &authResp); err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	// Update tokens
	c.accessToken = authResp.AccessToken
	c.refreshToken = authResp.RefreshToken
	c.tokenExpiry = authResp.ExpiresAt

	return &authResp, nil
}

// Register registers a new user and returns an authentication response
func (c *APIClient) Register(ctx context.Context, username, password, email string) (*AuthResponse, error) {
	// Validate input
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if email == "" {
		return nil, fmt.Errorf("email cannot be empty")
	}

	// Create request body
	reqBody := RegisterRequest{
		Username: username,
		Password: password,
		Email:    email,
	}

	// Send request
	var authResp AuthResponse
	if err := c.doRequest(ctx, http.MethodPost, APIPathAuthRegister, reqBody, &authResp); err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	// Update tokens
	c.accessToken = authResp.AccessToken
	c.refreshToken = authResp.RefreshToken
	c.tokenExpiry = authResp.ExpiresAt

	return &authResp, nil
}

// RefreshToken refreshes the access token using the refresh token
func (c *APIClient) RefreshToken(ctx context.Context) (*AuthResponse, error) {
	// Check if refresh token is available
	if c.refreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	// Create URL and request
	// Create request body
	reqBody := map[string]string{"refresh_token": c.refreshToken}

	// Create request using doRequest which handles body marshaling
	var authResp AuthResponse // Define variable to receive response
	if err := c.doRequest(ctx, http.MethodPost, APIPathAuthRefresh, reqBody, &authResp); err != nil {
		// Clear tokens on refresh failure
		c.accessToken = ""
		c.refreshToken = ""
		c.tokenExpiry = time.Time{}
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	// Update tokens (moved logic here from below)
	c.accessToken = authResp.AccessToken
	if authResp.RefreshToken != "" { // Only update refresh token if provided in response
		c.refreshToken = authResp.RefreshToken
	}
	c.tokenExpiry = authResp.ExpiresAt

	return &authResp, nil // Return successful response

	/* Original code sending token in header - REMOVED
	url := c.buildURL(APIPathAuthRefresh)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}
	*/

	// Set headers
	// End of removed original code
}

// Logout logs out the current user and invalidates the tokens
func (c *APIClient) Logout(ctx context.Context) error {
	// Check if access token is available
	if c.accessToken == "" {
		return fmt.Errorf("not logged in")
	}

	// Send logout request
	err := c.doRequest(ctx, http.MethodPost, APIPathAuthLogout, nil, nil)
	if err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}

	// Clear tokens
	c.accessToken = ""
	c.refreshToken = ""
	c.tokenExpiry = time.Time{}

	return nil
}

// GetCurrentUser returns the current authenticated user
func (c *APIClient) GetCurrentUser(ctx context.Context) (*models.UserResponse, error) { // Return UserResponse
	var userResp models.UserResponse // Expect UserResponse
	if err := c.doRequest(ctx, http.MethodGet, APIPathUserMe, nil, &userResp); err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}
	return &userResp, nil
}

// UpdateCurrentUser updates the current user's profile
func (c *APIClient) UpdateCurrentUser(ctx context.Context, user *models.User) (*models.User, error) {
	if user == nil {
		return nil, fmt.Errorf("user cannot be nil")
	}

	var updatedUser models.User
	if err := c.doRequest(ctx, http.MethodPut, APIPathUserMe, user, &updatedUser); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}
	return &updatedUser, nil
}

// ChangePassword changes the current user's password
func (c *APIClient) ChangePassword(ctx context.Context, oldPassword, newPassword string) error {
	// Validate input
	if oldPassword == "" {
		return fmt.Errorf("old password cannot be empty")
	}
	if newPassword == "" {
		return fmt.Errorf("new password cannot be empty")
	}

	// Create request body
	reqBody := PasswordChangeRequest{
		OldPassword: oldPassword,
		NewPassword: newPassword,
	}

	// Send request
	if err := c.doRequest(ctx, http.MethodPut, APIPathUserMe+"/password", reqBody, nil); err != nil {
		return fmt.Errorf("password change failed: %w", err)
	}

	return nil
}

// SetToken manually sets the access and refresh tokens
func (c *APIClient) SetToken(accessToken, refreshToken string, expiresAt time.Time) {
	// Acquire token lock
	<-c.tokenLock
	defer func() { c.tokenLock <- struct{}{} }()

	c.accessToken = accessToken
	c.refreshToken = refreshToken
	c.tokenExpiry = expiresAt
}

// GetToken returns the current access and refresh tokens
func (c *APIClient) GetToken() (accessToken, refreshToken string, expiresAt time.Time) {
	// Acquire token lock
	<-c.tokenLock
	defer func() { c.tokenLock <- struct{}{} }()

	return c.accessToken, c.refreshToken, c.tokenExpiry
}

// HasValidToken checks if the client has a valid access token
func (c *APIClient) HasValidToken() bool {
	// Acquire token lock
	<-c.tokenLock
	defer func() { c.tokenLock <- struct{}{} }()

	return c.accessToken != "" && time.Now().Before(c.tokenExpiry)
}
