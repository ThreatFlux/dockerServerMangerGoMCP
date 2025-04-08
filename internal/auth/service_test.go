package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

func TestMockService(t *testing.T) {
	// Create mock service
	mockService := &MockService{}

	// Test Login
	t.Run("Login", func(t *testing.T) {
		// Setup mock function
		expectedTokenPair := &TokenPair{
			AccessToken:  "mock-access-token",
			RefreshToken: "mock-refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		}
		expectedErr := errors.New("mock error")

		mockService.LoginFunc = func(ctx context.Context, email, password string) (*TokenPair, error) {
			// Verify input parameters
			assert.Equal(t, "test@example.com", email)
			assert.Equal(t, "password", password)
			return expectedTokenPair, expectedErr
		}

		// Call the function
		tokenPair, err := mockService.Login(context.Background(), "test@example.com", "password")

		// Verify output
		assert.Equal(t, expectedTokenPair, tokenPair)
		assert.Equal(t, expectedErr, err)
	})

	// Test Register
	t.Run("Register", func(t *testing.T) {
		// Setup mock function
		user := &models.User{
			Email:    "test@example.com",
			Password: "password",
		}
		expectedTokenPair := &TokenPair{
			AccessToken:  "mock-access-token",
			RefreshToken: "mock-refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		}
		expectedErr := errors.New("mock error")

		mockService.RegisterFunc = func(ctx context.Context, u *models.User) (*TokenPair, error) {
			// Verify input parameters
			assert.Equal(t, user, u)
			return expectedTokenPair, expectedErr
		}

		// Call the function
		tokenPair, err := mockService.Register(context.Background(), user)

		// Verify output
		assert.Equal(t, expectedTokenPair, tokenPair)
		assert.Equal(t, expectedErr, err)
	})

	// Test Verify
	t.Run("Verify", func(t *testing.T) {
		// Setup mock function
		expectedTokenDetails := &TokenDetails{
			TokenUUID: "mock-uuid",
			UserID:    1,
			Roles:     []string{"admin"},
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		expectedErr := errors.New("mock error")

		mockService.VerifyFunc = func(ctx context.Context, tokenString string) (*TokenDetails, error) {
			// Verify input parameters
			assert.Equal(t, "mock-token", tokenString)
			return expectedTokenDetails, expectedErr
		}

		// Call the function
		tokenDetails, err := mockService.Verify(context.Background(), "mock-token")

		// Verify output
		assert.Equal(t, expectedTokenDetails, tokenDetails)
		assert.Equal(t, expectedErr, err)
	})

	// Test Refresh
	t.Run("Refresh", func(t *testing.T) {
		// Setup mock function
		expectedTokenPair := &TokenPair{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		}
		expectedErr := errors.New("mock error")

		mockService.RefreshFunc = func(ctx context.Context, refreshToken string) (*TokenPair, error) {
			// Verify input parameters
			assert.Equal(t, "mock-refresh-token", refreshToken)
			return expectedTokenPair, expectedErr
		}

		// Call the function
		tokenPair, err := mockService.Refresh(context.Background(), "mock-refresh-token")

		// Verify output
		assert.Equal(t, expectedTokenPair, tokenPair)
		assert.Equal(t, expectedErr, err)
	})

	// Test Logout
	t.Run("Logout", func(t *testing.T) {
		// Setup mock function
		expectedErr := errors.New("mock error")

		mockService.LogoutFunc = func(ctx context.Context, token string) error {
			// Verify input parameters
			assert.Equal(t, "mock-token", token)
			return expectedErr
		}

		// Call the function
		err := mockService.Logout(context.Background(), "mock-token")

		// Verify output
		assert.Equal(t, expectedErr, err)
	})

	// Test GenerateTokens
	t.Run("GenerateTokens", func(t *testing.T) {
		// Setup mock function
		user := &models.User{
			ID:    1,
			Email: "test@example.com",
		}
		expectedTokenPair := &TokenPair{
			AccessToken:  "mock-access-token",
			RefreshToken: "mock-refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		}
		expectedErr := errors.New("mock error")

		mockService.GenerateFunc = func(ctx context.Context, u *models.User) (*TokenPair, error) {
			// Verify input parameters
			assert.Equal(t, user, u)
			return expectedTokenPair, expectedErr
		}

		// Call the function
		tokenPair, err := mockService.GenerateTokens(context.Background(), user)

		// Verify output
		assert.Equal(t, expectedTokenPair, tokenPair)
		assert.Equal(t, expectedErr, err)
	})

	// Test HashPassword
	t.Run("HashPassword", func(t *testing.T) {
		// Setup mock function
		expectedHash := "hashed-password"
		expectedErr := errors.New("mock error")

		mockService.HashFunc = func(password string) (string, error) {
			// Verify input parameters
			assert.Equal(t, "password", password)
			return expectedHash, expectedErr
		}

		// Call the function
		hash, err := mockService.HashPassword("password")

		// Verify output
		assert.Equal(t, expectedHash, hash)
		assert.Equal(t, expectedErr, err)
	})

	// Test CheckPassword
	t.Run("CheckPassword", func(t *testing.T) {
		// Setup mock function
		expectedResult := true

		mockService.CheckFunc = func(password, hash string) bool {
			// Verify input parameters
			assert.Equal(t, "password", password)
			assert.Equal(t, "hashed-password", hash)
			return expectedResult
		}

		// Call the function
		result := mockService.CheckPassword("password", "hashed-password")

		// Verify output
		assert.Equal(t, expectedResult, result)
	})

	// Test nil functions
	t.Run("nil functions", func(t *testing.T) {
		// Create a new mock service with nil functions
		emptyMock := &MockService{}

		// Test all functions
		tokenPair, err := emptyMock.Login(context.Background(), "", "")
		require.Nil(t, tokenPair)
		require.Nil(t, err)

		tokenPair, err = emptyMock.Register(context.Background(), nil)
		require.Nil(t, tokenPair)
		require.Nil(t, err)

		tokenDetails, err := emptyMock.Verify(context.Background(), "")
		require.Nil(t, tokenDetails)
		require.Nil(t, err)

		tokenPair, err = emptyMock.Refresh(context.Background(), "")
		require.Nil(t, tokenPair)
		require.Nil(t, err)

		err = emptyMock.Logout(context.Background(), "")
		require.Nil(t, err)

		tokenPair, err = emptyMock.GenerateTokens(context.Background(), nil)
		require.Nil(t, tokenPair)
		require.Nil(t, err)

		hash, err := emptyMock.HashPassword("")
		require.Equal(t, "", hash)
		require.Nil(t, err)

		result := emptyMock.CheckPassword("password", "password")
		require.True(t, result)
		result = emptyMock.CheckPassword("password", "different")
		require.False(t, result)
	})
}
