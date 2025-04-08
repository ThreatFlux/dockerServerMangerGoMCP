package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupTestDB creates a test database for token store tests
func setupTokenStoreTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate the schemas
	err = db.AutoMigrate(&models.Token{})
	require.NoError(t, err)

	return db
}

// testTokenStore runs common tests against any TokenStore implementation
func testTokenStore(t *testing.T, store TokenStore) {
	ctx := context.Background()

	// Generate test data
	userID := uint(1)
	tokenUUID := uuid.New().String()
	tokenType := "access"
	token := "test-token"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Test StoreToken
	t.Run("StoreToken", func(t *testing.T) {
		err := store.StoreToken(ctx, userID, tokenUUID, tokenType, token, expiresAt)
		require.NoError(t, err)

		// Try storing the same token again - should fail
		err = store.StoreToken(ctx, userID, tokenUUID, tokenType, token, expiresAt)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrDuplicateToken)
	})

	// Test GetToken
	t.Run("GetToken", func(t *testing.T) {
		// Get existing token
		tokenModel, err := store.GetToken(ctx, tokenUUID)
		require.NoError(t, err)
		assert.Equal(t, tokenUUID, tokenModel.UUID)
		assert.Equal(t, userID, tokenModel.UserID)
		assert.Equal(t, tokenType, tokenModel.Type)
		assert.Equal(t, token, tokenModel.Token)
		assert.False(t, tokenModel.Blacklist)
		assert.Equal(t, expiresAt.Unix(), tokenModel.ExpiresAt.Unix())

		// Get non-existent token
		_, err = store.GetToken(ctx, "non-existent")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	// Test IsTokenBlacklisted
	t.Run("IsTokenBlacklisted", func(t *testing.T) {
		// Check existing token
		blacklisted, err := store.IsTokenBlacklisted(ctx, tokenUUID)
		require.NoError(t, err)
		assert.False(t, blacklisted)

		// Check non-existent token
		_, err = store.IsTokenBlacklisted(ctx, "non-existent")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	// Test BlacklistToken
	t.Run("BlacklistToken", func(t *testing.T) {
		// Blacklist existing token
		err := store.BlacklistToken(ctx, tokenUUID)
		require.NoError(t, err)

		// Check if token is blacklisted
		blacklisted, err := store.IsTokenBlacklisted(ctx, tokenUUID)
		require.NoError(t, err)
		assert.True(t, blacklisted)

		// Get token should now return ErrTokenBlacklisted
		_, err = store.GetToken(ctx, tokenUUID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenBlacklisted)

		// Try to blacklist non-existent token
		err = store.BlacklistToken(ctx, "non-existent")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	// Store another token for additional tests
	otherTokenUUID := uuid.New().String()
	err := store.StoreToken(ctx, userID, otherTokenUUID, tokenType, "other-token", expiresAt)
	require.NoError(t, err)

	// Test DeleteToken
	t.Run("DeleteToken", func(t *testing.T) {
		// Delete existing token
		err := store.DeleteToken(ctx, otherTokenUUID)
		require.NoError(t, err)

		// Token should now be gone
		_, err = store.GetToken(ctx, otherTokenUUID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenNotFound)

		// Try to delete non-existent token
		err = store.DeleteToken(ctx, "non-existent")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	// Store expired token
	expiredTokenUUID := uuid.New().String()
	expiredAt := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
	err = store.StoreToken(ctx, userID, expiredTokenUUID, tokenType, "expired-token", expiredAt)
	require.NoError(t, err)

	// Test GetToken with expired token
	t.Run("GetToken_ExpiredToken", func(t *testing.T) {
		_, err := store.GetToken(ctx, expiredTokenUUID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenExpired)
	})

	// Test DeleteExpiredTokens
	t.Run("DeleteExpiredTokens", func(t *testing.T) {
		count, err := store.DeleteExpiredTokens(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, count) // Should delete only the expired token

		// Expired token should now be gone
		_, err = store.GetToken(ctx, expiredTokenUUID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	// Store tokens for another user
	otherUserID := uint(2)
	otherUserToken1 := uuid.New().String()
	otherUserToken2 := uuid.New().String()
	err = store.StoreToken(ctx, otherUserID, otherUserToken1, tokenType, "other-user-token-1", expiresAt)
	require.NoError(t, err)
	err = store.StoreToken(ctx, otherUserID, otherUserToken2, tokenType, "other-user-token-2", expiresAt)
	require.NoError(t, err)

	// Test DeleteUserTokens
	t.Run("DeleteUserTokens", func(t *testing.T) {
		count, err := store.DeleteUserTokens(ctx, otherUserID)
		require.NoError(t, err)
		assert.Equal(t, 2, count) // Should delete both tokens for the other user

		// Other user's tokens should now be gone
		_, err = store.GetToken(ctx, otherUserToken1)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenNotFound)
		_, err = store.GetToken(ctx, otherUserToken2)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenNotFound)

		// First user's token should still be there
		_, err = store.GetToken(ctx, tokenUUID)
		assert.Error(t, err) // It's blacklisted, but still exists
		assert.ErrorIs(t, err, ErrTokenBlacklisted)
	})
}

func TestGormTokenStore(t *testing.T) {
	// Set up test database
	db := setupTokenStoreTestDB(t)

	// Create GORM token store
	store := NewGormTokenStore(db)
	require.NotNil(t, store)

	// Run common tests
	testTokenStore(t, store)
}

func TestInMemoryTokenStore(t *testing.T) {
	// Create in-memory token store
	store := NewInMemoryTokenStore()
	require.NotNil(t, store)

	// Run common tests
	testTokenStore(t, store)
}
