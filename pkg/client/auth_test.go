package client

import (
	"context"
	"encoding/json"
	"fmt" // Added import for Sprintf
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// TestLogin tests the login functionality
func TestLogin(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/auth/login", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Read and verify request body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var loginReq LoginRequest
		err = json.Unmarshal(body, &loginReq)
		require.NoError(t, err)

		// Check login credentials
		if loginReq.Username == "validuser" && loginReq.Password == "validpass" {
			// Success response
			w.WriteHeader(http.StatusOK)
			// Use email and roles matching models.User struct
			// Return structure matching models.TokenResponse
			w.Write([]byte(fmt.Sprintf(`{
				"access_token": "test-access-token",
				"refresh_token": "test-refresh-token",
				"token_type": "Bearer",
				"expires_in": 3600,
				"expires_at": "%s",
				"user_id": 1,
				"roles": ["user"]
			}`, time.Now().Add(time.Hour).Format(time.RFC3339))))
		} else {
			// Error response
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Invalid credentials"}`))
		}
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test successful login
	resp, err := client.Login(context.Background(), "validuser", "validpass")
	require.NoError(t, err)
	assert.Equal(t, "test-access-token", resp.AccessToken)
	assert.Equal(t, "test-refresh-token", resp.RefreshToken)
	assert.NotZero(t, resp.ExpiresAt)
	assert.Equal(t, uint(1), resp.UserID)
	assert.Contains(t, resp.Roles, "user")

	// Check that client tokens were updated
	assert.Equal(t, "test-access-token", client.accessToken)
	assert.Equal(t, "test-refresh-token", client.refreshToken)
	assert.Equal(t, resp.ExpiresAt, client.tokenExpiry)

	// Test failed login
	_, err = client.Login(context.Background(), "invaliduser", "invalidpass")
	assert.Error(t, err)

	// Test invalid input
	_, err = client.Login(context.Background(), "", "validpass")
	assert.Error(t, err)

	_, err = client.Login(context.Background(), "validuser", "")
	assert.Error(t, err)
}

// TestRegister tests the registration functionality
func TestRegister(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/auth/register", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Read and verify request body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var registerReq RegisterRequest
		err = json.Unmarshal(body, &registerReq)
		require.NoError(t, err)

		// Check registration input
		if registerReq.Username == "newuser" &&
			registerReq.Password == "newpass" &&
			registerReq.Email == "new@example.com" {
			// Success response
			w.WriteHeader(http.StatusCreated)
			// Use email and roles matching models.User struct
			// Return structure matching models.TokenResponse
			w.Write([]byte(fmt.Sprintf(`{
				"access_token": "new-access-token",
				"refresh_token": "new-refresh-token",
				"token_type": "Bearer",
				"expires_in": 3600,
				"expires_at": "%s",
				"user_id": 2,
				"roles": ["user"]
			}`, time.Now().Add(time.Hour).Format(time.RFC3339))))
		} else if registerReq.Username == "existinguser" {
			// Error response - user already exists
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"error": "Username already exists"}`))
		} else {
			// Generic error
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Invalid registration data"}`))
		}
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test successful registration
	resp, err := client.Register(context.Background(), "newuser", "newpass", "new@example.com")
	require.NoError(t, err)
	assert.Equal(t, "new-access-token", resp.AccessToken)
	assert.Equal(t, "new-refresh-token", resp.RefreshToken)
	assert.NotZero(t, resp.ExpiresAt)
	assert.Equal(t, uint(2), resp.UserID)
	assert.Contains(t, resp.Roles, "user")

	// Check that client tokens were updated
	assert.Equal(t, "new-access-token", client.accessToken)
	assert.Equal(t, "new-refresh-token", client.refreshToken)
	assert.Equal(t, resp.ExpiresAt, client.tokenExpiry)

	// Test failed registration - username exists
	_, err = client.Register(context.Background(), "existinguser", "newpass", "new@example.com")
	assert.Error(t, err)

	// Test failed registration - invalid data
	_, err = client.Register(context.Background(), "invalid", "invalid", "invalid")
	assert.Error(t, err)

	// Test invalid input
	_, err = client.Register(context.Background(), "", "newpass", "new@example.com")
	assert.Error(t, err)

	_, err = client.Register(context.Background(), "newuser", "", "new@example.com")
	assert.Error(t, err)

	_, err = client.Register(context.Background(), "newuser", "newpass", "")
	assert.Error(t, err)
}

// TestRefreshToken tests the token refresh functionality
func TestRefreshToken(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/auth/refresh", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Check refresh token in request body
		var reqBody map[string]string
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)
		refreshToken, ok := reqBody["refresh_token"]
		require.True(t, ok, "refresh_token not found in request body")

		if refreshToken == "valid-refresh-token" {
			// Success response (matching models.TokenResponse)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(models.TokenResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
				ExpiresAt:    time.Now().Add(time.Hour),
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				// UserID and Roles might not be returned on refresh, omit if so
			})
		} else {
			// Error response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.ErrorResponse{
				Success: false,
				Error:   models.ErrorInfo{Code: "INVALID_TOKEN", Message: "Invalid refresh token"},
			})
		}
	}))
	defer server.Close()

	// Create client with valid refresh token
	client, err := NewClient(
		WithBaseURL(server.URL),
		WithRefreshToken("valid-refresh-token"),
	)
	require.NoError(t, err)

	// Test successful refresh
	resp, err := client.RefreshToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "new-access-token", resp.AccessToken)
	assert.Equal(t, "new-refresh-token", resp.RefreshToken)
	assert.NotZero(t, resp.ExpiresAt)

	// Check that client tokens were updated
	assert.Equal(t, "new-access-token", client.accessToken)   // Match this test's mock response
	assert.Equal(t, "new-refresh-token", client.refreshToken) // Match this test's mock response
	assert.Equal(t, resp.ExpiresAt, client.tokenExpiry)

	// Create client with invalid refresh token
	client, err = NewClient(
		WithBaseURL(server.URL),
		WithRefreshToken("invalid-refresh-token"),
	)
	require.NoError(t, err)

	// Test failed refresh
	_, err = client.RefreshToken(context.Background())
	assert.Error(t, err)

	// Test with no refresh token
	client, err = NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	_, err = client.RefreshToken(context.Background())
	assert.Error(t, err)
}

// TestLogout tests the logout functionality
func TestLogout(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/auth/logout", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Check access token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer valid-access-token" {
			// Success response
			w.WriteHeader(http.StatusNoContent)
		} else {
			// Error response
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Invalid token"}`))
		}
	}))
	defer server.Close()

	// Create client with valid access token
	client, err := NewClient(
		WithBaseURL(server.URL),
		WithAccessToken("valid-access-token"),
		WithRefreshToken("valid-refresh-token"),
	)
	require.NoError(t, err)

	// Set expiry for token
	client.tokenExpiry = time.Now().Add(time.Hour)

	// Test successful logout
	err = client.Logout(context.Background())
	require.NoError(t, err)

	// Check that client tokens were cleared
	assert.Empty(t, client.accessToken)
	assert.Empty(t, client.refreshToken)
	assert.True(t, client.tokenExpiry.IsZero())

	// Create client with invalid access token
	client, err = NewClient(
		WithBaseURL(server.URL),
		WithAccessToken("invalid-access-token"),
	)
	require.NoError(t, err)

	// Test failed logout
	err = client.Logout(context.Background())
	assert.Error(t, err)

	// Test with no access token
	client, err = NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	err = client.Logout(context.Background())
	assert.Error(t, err)
}

// TestGetCurrentUser tests getting the current user's profile
func TestGetCurrentUser(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/user/me", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		// Check access token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer valid-access-token" {
			// Success response
			w.WriteHeader(http.StatusOK)
			// Return user details wrapped in SuccessResponse
			userResp := models.UserResponse{
				ID:            1,
				Email:         "testuser@example.com",
				Name:          "Test User",
				Roles:         []string{"admin"}, // Use simple string slice for roles in response
				EmailVerified: true,
				Active:        true,
				CreatedAt:     time.Now().Add(-24 * time.Hour),
				UpdatedAt:     time.Now(),
			}
			successResp := models.SuccessResponse{
				Success: true,
				Data:    userResp,
				Meta:    models.MetadataResponse{Timestamp: time.Now()}, // Add basic meta
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(successResp) // Encode the wrapped response
		} else {
			// Error response
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Invalid token"}`))
		}
	}))
	defer server.Close()

	// Create client with valid access token
	client, err := NewClient(
		WithBaseURL(server.URL),
		WithAccessToken("valid-access-token"),
	)
	require.NoError(t, err)

	// Test successful get
	user, err := client.GetCurrentUser(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint(1), user.ID) // Check ID on UserResponse
	assert.Equal(t, "testuser@example.com", user.Email)
	assert.Equal(t, "Test User", user.Name)
	// Check roles directly on the string slice
	foundAdminRole := false
	for _, role := range user.Roles {
		if role == string(models.RoleAdmin) { // Cast RoleAdmin for comparison
			foundAdminRole = true
			break
		}
	}
	assert.True(t, foundAdminRole, "User should have 'admin' role")

	// Create client with invalid access token
	client, err = NewClient(
		WithBaseURL(server.URL),
		WithAccessToken("invalid-access-token"),
	)
	require.NoError(t, err)

	// Test failed get
	_, err = client.GetCurrentUser(context.Background())
	assert.Error(t, err)
}

// TestUpdateCurrentUser tests updating the current user's profile
func TestUpdateCurrentUser(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/user/me", r.URL.Path)
		assert.Equal(t, http.MethodPut, r.Method)

		// Check access token
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer valid-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Invalid token"}`))
			return
		}

		// Read and verify request body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var userReq models.User
		err = json.Unmarshal(body, &userReq)
		require.NoError(t, err)

		// Return updated user based on request, matching models.User
		w.WriteHeader(http.StatusOK)
		// Construct roles JSON manually for the mock response
		rolesJSON := `[]`
		if len(userReq.Roles) > 0 {
			rolesJSON = `[{"role": "` + string(userReq.Roles[0].Role) + `"}]` // Assuming one role for simplicity in mock
		}
		w.Write([]byte(fmt.Sprintf(`{
			"id": 1,
			"name": "%s",
			"email": "%s",
			"roles": %s,
			"createdAt": "%s",
			"updatedAt": "%s"
		}`, userReq.Name, userReq.Email, rolesJSON, time.Now().Add(-24*time.Hour).Format(time.RFC3339), time.Now().Format(time.RFC3339))))
	}))
	defer server.Close()

	// Create client with valid access token
	client, err := NewClient(
		WithBaseURL(server.URL),
		WithAccessToken("valid-access-token"),
	)
	require.NoError(t, err)

	// Create user update using correct fields
	userUpdate := &models.User{
		Name:  "Updated User", // Use Name field
		Email: "updated@example.com",
		Roles: []models.UserRole{{Role: models.RoleUser}}, // Use Roles field
	}

	// Test successful update
	updatedUser, err := client.UpdateCurrentUser(context.Background(), userUpdate)
	require.NoError(t, err)
	assert.Equal(t, uint(1), updatedUser.ID)                                                     // Cast 1 to uint to match ID type
	assert.Equal(t, userUpdate.Name, updatedUser.Name)                                           // Check Name
	assert.Equal(t, userUpdate.Email, updatedUser.Email)                                         // Check Email
	assert.True(t, updatedUser.HasRole(models.RoleUser), "Updated user should have 'user' role") // Check role using helper

	// Test with nil user
	_, err = client.UpdateCurrentUser(context.Background(), nil)
	assert.Error(t, err)

	// Create client with invalid access token
	client, err = NewClient(
		WithBaseURL(server.URL),
		WithAccessToken("invalid-access-token"),
	)
	require.NoError(t, err)

	// Test failed update
	_, err = client.UpdateCurrentUser(context.Background(), userUpdate)
	assert.Error(t, err)
}

// TestChangePassword tests changing the user's password
func TestChangePassword(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/user/me/password", r.URL.Path)
		assert.Equal(t, http.MethodPut, r.Method)

		// Check access token
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer valid-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Invalid token"}`))
			return
		}

		// Read and verify request body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var pwdReq PasswordChangeRequest
		err = json.Unmarshal(body, &pwdReq)
		require.NoError(t, err)

		// Check old password
		if pwdReq.OldPassword == "oldpass" && pwdReq.NewPassword == "newpass" {
			// Success response
			w.WriteHeader(http.StatusNoContent)
		} else {
			// Error response
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Invalid password"}`))
		}
	}))
	defer server.Close()

	// Create client with valid access token
	client, err := NewClient(
		WithBaseURL(server.URL),
		WithAccessToken("valid-access-token"),
	)
	require.NoError(t, err)

	// Test successful password change
	err = client.ChangePassword(context.Background(), "oldpass", "newpass")
	require.NoError(t, err)

	// Test failed password change - wrong old password
	err = client.ChangePassword(context.Background(), "wrongpass", "newpass")
	assert.Error(t, err)

	// Test invalid input
	err = client.ChangePassword(context.Background(), "", "newpass")
	assert.Error(t, err)

	err = client.ChangePassword(context.Background(), "oldpass", "")
	assert.Error(t, err)

	// Create client with invalid access token
	client, err = NewClient(
		WithBaseURL(server.URL),
		WithAccessToken("invalid-access-token"),
	)
	require.NoError(t, err)

	// Test failed password change - invalid token
	err = client.ChangePassword(context.Background(), "oldpass", "newpass")
	assert.Error(t, err)
}

// TestTokenManagement tests the token management functions
func TestTokenManagement(t *testing.T) {
	// Create client
	client, err := NewClient()
	require.NoError(t, err)

	// Test setting tokens
	accessToken := "test-access-token"
	refreshToken := "test-refresh-token"
	expiresAt := time.Now().Add(time.Hour)

	client.SetToken(accessToken, refreshToken, expiresAt)

	// Test getting tokens
	gotAccess, gotRefresh, gotExpiry := client.GetToken()
	assert.Equal(t, accessToken, gotAccess)
	assert.Equal(t, refreshToken, gotRefresh)
	assert.Equal(t, expiresAt, gotExpiry)

	// Test token validity
	assert.True(t, client.HasValidToken())

	// Test expired token
	client.SetToken(accessToken, refreshToken, time.Now().Add(-time.Hour))
	assert.False(t, client.HasValidToken())

	// Test empty token
	client.SetToken("", refreshToken, expiresAt)
	assert.False(t, client.HasValidToken())
}
