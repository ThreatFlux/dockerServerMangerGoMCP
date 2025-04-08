package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus" // Added import
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

func TestJWTService(t *testing.T) {
	// Create a test JWT configuration
	config := JWTConfig{
		AccessTokenSecret:  "test-access-secret",
		RefreshTokenSecret: "test-refresh-secret",
		AccessTokenExpiry:  15,     // 15 minutes
		RefreshTokenExpiry: 24 * 7, // 7 days
		Issuer:             "test-issuer",
		Audience:           []string{"test-audience"},
	}

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs

	// Create a test JWT service
	jwtService := NewJWTService(config, logger) // Pass logger
	require.NotNil(t, jwtService)

	// Create a test user
	user := &models.User{
		ID:    1,
		Email: "test@example.com",
		Roles: []models.UserRole{
			{Role: models.RoleAdmin},
			{Role: models.RoleUser},
		},
	}

	// Test GenerateTokenPair
	t.Run("GenerateTokenPair", func(t *testing.T) {
		// Generate tokens
		tokenPair, err := jwtService.GenerateTokenPair(user)
		require.NoError(t, err)
		require.NotNil(t, tokenPair)

		// Verify token pair
		assert.NotEmpty(t, tokenPair.AccessToken)
		assert.NotEmpty(t, tokenPair.RefreshToken)
		assert.False(t, tokenPair.ExpiresAt.IsZero())
		assert.True(t, tokenPair.ExpiresAt.After(time.Now()))
	})

	// Test ExtractTokenDetails for access token
	t.Run("ExtractTokenDetails_AccessToken", func(t *testing.T) {
		// Generate tokens
		tokenPair, err := jwtService.GenerateTokenPair(user)
		require.NoError(t, err)
		require.NotNil(t, tokenPair)

		// Extract token details
		tokenDetails, err := jwtService.ExtractTokenDetails(tokenPair.AccessToken, false)
		require.NoError(t, err)
		require.NotNil(t, tokenDetails)

		// Verify token details
		assert.Equal(t, uint(1), tokenDetails.UserID)
		assert.Equal(t, []string{"admin", "user"}, tokenDetails.Roles)
		assert.NotEmpty(t, tokenDetails.TokenUUID)
		assert.False(t, tokenDetails.ExpiresAt.IsZero())
		assert.True(t, tokenDetails.ExpiresAt.After(time.Now()))
		assert.Equal(t, config.Issuer, tokenDetails.Issuer)
		assert.Equal(t, "1", tokenDetails.Subject)
		assert.Equal(t, config.Audience, tokenDetails.Audience)
		assert.False(t, tokenDetails.IsRefresh)
	})

	// Test ExtractTokenDetails for refresh token
	t.Run("ExtractTokenDetails_RefreshToken", func(t *testing.T) {
		// Generate tokens
		tokenPair, err := jwtService.GenerateTokenPair(user)
		require.NoError(t, err)
		require.NotNil(t, tokenPair)

		// Extract token details
		tokenDetails, err := jwtService.ExtractTokenDetails(tokenPair.RefreshToken, true)
		require.NoError(t, err)
		require.NotNil(t, tokenDetails)

		// Verify token details
		assert.Equal(t, uint(1), tokenDetails.UserID)
		assert.Equal(t, []string{"admin", "user"}, tokenDetails.Roles)
		assert.NotEmpty(t, tokenDetails.TokenUUID)
		assert.False(t, tokenDetails.ExpiresAt.IsZero())
		assert.True(t, tokenDetails.ExpiresAt.After(time.Now()))
		assert.Equal(t, config.Issuer, tokenDetails.Issuer)
		assert.Equal(t, "1", tokenDetails.Subject)
		assert.Equal(t, config.Audience, tokenDetails.Audience)
		assert.True(t, tokenDetails.IsRefresh)
	})

	// Test RefreshTokens
	t.Run("RefreshTokens", func(t *testing.T) {
		// Generate tokens
		tokenPair, err := jwtService.GenerateTokenPair(user)
		require.NoError(t, err)
		require.NotNil(t, tokenPair)

		// Refresh tokens
		newTokenPair, err := jwtService.RefreshTokens(tokenPair.RefreshToken)
		require.NoError(t, err)
		require.NotNil(t, newTokenPair)

		// Verify new token pair
		assert.NotEmpty(t, newTokenPair.AccessToken)
		assert.NotEmpty(t, newTokenPair.RefreshToken)
		assert.NotEqual(t, tokenPair.AccessToken, newTokenPair.AccessToken)
		assert.NotEqual(t, tokenPair.RefreshToken, newTokenPair.RefreshToken)
	})

	// Test GetTokenUUID
	t.Run("GetTokenUUID", func(t *testing.T) {
		// Generate tokens
		tokenPair, err := jwtService.GenerateTokenPair(user)
		require.NoError(t, err)
		require.NotNil(t, tokenPair)

		// Get access token UUID
		accessUUID, err := jwtService.GetTokenUUID(tokenPair.AccessToken, false)
		require.NoError(t, err)
		assert.NotEmpty(t, accessUUID)

		// Get refresh token UUID
		refreshUUID, err := jwtService.GetTokenUUID(tokenPair.RefreshToken, true)
		require.NoError(t, err)
		assert.NotEmpty(t, refreshUUID)

		// UUIDs should be different
		assert.NotEqual(t, accessUUID, refreshUUID)
	})

	// Test error cases
	t.Run("ErrorCases", func(t *testing.T) {
		// Test missing key
		t.Run("MissingKey", func(t *testing.T) {
			emptyConfig := JWTConfig{}
			emptyLogger := logrus.New()
			emptyLogger.SetLevel(logrus.FatalLevel)
			emptyService := NewJWTService(emptyConfig, emptyLogger) // Pass logger

			// Generate tokens should fail
			_, err := emptyService.GenerateTokenPair(user)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrMissingKey)

			// Extract token details should fail
			_, err = emptyService.ExtractTokenDetails("token", false)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrMissingKey)
		})

		// Test invalid token
		t.Run("InvalidToken", func(t *testing.T) {
			_, err := jwtService.ExtractTokenDetails("invalid.token.string", false)
			assert.Error(t, err)
		})

		// Test expired token
		t.Run("ExpiredToken", func(t *testing.T) {
			// Create expired claims
			now := time.Now()
			claims := &CustomClaims{
				UserID:    1,
				Roles:     []string{"admin", "user"},
				TokenUUID: "test-uuid",
				IsRefresh: false,
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
					NotBefore: jwt.NewNumericDate(now.Add(-2 * time.Hour)),
					Issuer:    config.Issuer,
					Audience:  config.Audience,
					ID:        "test-uuid",
					Subject:   "1",
				},
			}

			// Create expired token
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString([]byte(config.AccessTokenSecret))
			require.NoError(t, err)

			// Extract token details should fail with expired error
			_, err = jwtService.ExtractTokenDetails(tokenString, false)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrExpiredToken)

			// GetTokenUUID should still work with expired token
			uuid, err := jwtService.GetTokenUUID(tokenString, false)
			assert.NoError(t, err)
			assert.Equal(t, "test-uuid", uuid)
		})

		// Test token not yet valid
		t.Run("TokenNotYetValid", func(t *testing.T) {
			// Create not yet valid claims
			now := time.Now()
			claims := &CustomClaims{
				UserID:    1,
				Roles:     []string{"admin", "user"},
				TokenUUID: "test-uuid",
				IsRefresh: false,
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(now),
					NotBefore: jwt.NewNumericDate(now.Add(1 * time.Hour)),
					Issuer:    config.Issuer,
					Audience:  config.Audience,
					ID:        "test-uuid",
					Subject:   "1",
				},
			}

			// Create not yet valid token
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString([]byte(config.AccessTokenSecret))
			require.NoError(t, err)

			// Extract token details should fail with not yet valid error
			_, err = jwtService.ExtractTokenDetails(tokenString, false)
			assert.Error(t, err)
		})

		// Test different signing method
		t.Run("DifferentSigningMethod", func(t *testing.T) {
			// Create token with different signing method
			claims := &CustomClaims{
				UserID:    1,
				Roles:     []string{"admin", "user"},
				TokenUUID: "test-uuid",
				IsRefresh: false,
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					Issuer:    config.Issuer,
					Audience:  config.Audience,
					ID:        "test-uuid",
					Subject:   "1",
				},
			}

			// We have to create a mock token string with incorrect method
			// since we can't actually sign with a different method
			token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
			tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
			require.NoError(t, err)

			// Extract token details should fail with invalid signing method error
			_, err = jwtService.ExtractTokenDetails(tokenString, false)
			assert.Error(t, err)
		})

		// Test refresh token used for access token verification
		t.Run("RefreshTokenForAccessValidation", func(t *testing.T) {
			// Generate tokens
			tokenPair, err := jwtService.GenerateTokenPair(user)
			require.NoError(t, err)
			require.NotNil(t, tokenPair)

			// Try to validate refresh token as access token
			_, err = jwtService.ExtractTokenDetails(tokenPair.RefreshToken, false)
			assert.Error(t, err)
		})

		// Test access token used for refresh token verification
		t.Run("AccessTokenForRefreshValidation", func(t *testing.T) {
			// Generate tokens
			tokenPair, err := jwtService.GenerateTokenPair(user)
			require.NoError(t, err)
			require.NotNil(t, tokenPair)

			// Try to validate access token as refresh token
			_, err = jwtService.ExtractTokenDetails(tokenPair.AccessToken, true)
			assert.Error(t, err)
		})

		// Test token with invalid claims
		t.Run("InvalidClaims", func(t *testing.T) {
			// Create claims with invalid values
			invalidClaims := []CustomClaims{
				{
					// Missing user ID
					UserID:    0,
					Roles:     []string{"admin"},
					TokenUUID: "test-uuid",
					IsRefresh: false,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Issuer:    config.Issuer,
						Audience:  config.Audience,
						Subject:   "0",
					},
				},
				{
					// Missing roles
					UserID:    1,
					Roles:     nil,
					TokenUUID: "test-uuid",
					IsRefresh: false,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Issuer:    config.Issuer,
						Audience:  config.Audience,
						Subject:   "1",
					},
				},
				{
					// Missing token UUID
					UserID:    1,
					Roles:     []string{"admin"},
					TokenUUID: "",
					IsRefresh: false,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Issuer:    config.Issuer,
						Audience:  config.Audience,
						Subject:   "1",
					},
				},
				{
					// Wrong issuer
					UserID:    1,
					Roles:     []string{"admin"},
					TokenUUID: "test-uuid",
					IsRefresh: false,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Issuer:    "wrong-issuer",
						Audience:  config.Audience,
						Subject:   "1",
					},
				},
				{
					// Wrong audience
					UserID:    1,
					Roles:     []string{"admin"},
					TokenUUID: "test-uuid",
					IsRefresh: false,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Issuer:    config.Issuer,
						Audience:  []string{"wrong-audience"},
						Subject:   "1",
					},
				},
			}

			for i, claims := range invalidClaims {
				t.Run(fmt.Sprintf("InvalidClaim_%d", i), func(t *testing.T) {
					token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
					tokenString, err := token.SignedString([]byte(config.AccessTokenSecret))
					require.NoError(t, err)

					// Extract token details should fail
					_, err = jwtService.ExtractTokenDetails(tokenString, false)
					assert.Error(t, err)
				})
			}
		})
	})
}

func TestDefaultJWTConfig(t *testing.T) {
	config := DefaultJWTConfig()

	// Verify default values
	assert.Equal(t, 15, config.AccessTokenExpiry)
	assert.Equal(t, 24*7, config.RefreshTokenExpiry)
	assert.Equal(t, "docker_test-server-manager", config.Issuer)
	assert.Equal(t, []string{"dsm-api"}, config.Audience)
}
