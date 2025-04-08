package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"gorm.io/gorm"
)

// Token store errors
var (
	ErrTokenNotFound    = errors.New("token not found")
	ErrTokenBlacklisted = errors.New("token is blacklisted")
	ErrTokenExpired     = errors.New("token has expired")
	ErrDBOperation      = errors.New("database operation failed")
	ErrDuplicateToken   = errors.New("token already exists")
)

// TokenStore defines the interface for token storage operations
type TokenStore interface {
	// StoreToken stores a token in the database
	StoreToken(ctx context.Context, userID uint, tokenUUID string, tokenType string, token string, expiresAt time.Time) error

	// GetToken retrieves a token from the database
	GetToken(ctx context.Context, tokenUUID string) (*models.Token, error)

	// BlacklistToken adds a token to the blacklist
	BlacklistToken(ctx context.Context, tokenUUID string) error

	// DeleteToken removes a token from the database
	DeleteToken(ctx context.Context, tokenUUID string) error

	// DeleteExpiredTokens removes all expired tokens from the database
	DeleteExpiredTokens(ctx context.Context) (int, error)

	// DeleteUserTokens removes all tokens for a specific user
	DeleteUserTokens(ctx context.Context, userID uint) (int, error)

	// IsTokenBlacklisted checks if a token is blacklisted
	IsTokenBlacklisted(ctx context.Context, tokenUUID string) (bool, error)
}

// GormTokenStore implements TokenStore using GORM for database operations
type GormTokenStore struct {
	db *gorm.DB
}

// NewGormTokenStore creates a new GormTokenStore
func NewGormTokenStore(db *gorm.DB) *GormTokenStore {
	return &GormTokenStore{
		db: db,
	}
}

// StoreToken stores a token in the database
func (s *GormTokenStore) StoreToken(ctx context.Context, userID uint, tokenUUID string, tokenType string, token string, expiresAt time.Time) error {
	// Check if the token already exists
	var count int64
	if err := s.db.WithContext(ctx).Model(&models.Token{}).Where("uuid = ?", tokenUUID).Count(&count).Error; err != nil {
		return fmt.Errorf("%w: %v", ErrDBOperation, err)
	}

	if count > 0 {
		return ErrDuplicateToken
	}

	// Create a new token record
	tokenModel := models.Token{
		UUID:      tokenUUID,
		UserID:    userID,
		Token:     token,
		Type:      tokenType,
		Blacklist: false,
		ExpiresAt: expiresAt,
	}

	// Insert into database
	if err := s.db.WithContext(ctx).Create(&tokenModel).Error; err != nil {
		return fmt.Errorf("%w: %v", ErrDBOperation, err)
	}

	return nil
}

// GetToken retrieves a token from the database
func (s *GormTokenStore) GetToken(ctx context.Context, tokenUUID string) (*models.Token, error) {
	var token models.Token

	// Query the database
	result := s.db.WithContext(ctx).Where("uuid = ?", tokenUUID).First(&token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDBOperation, result.Error)
	}

	// Check if the token is blacklisted
	if token.Blacklist {
		return &token, ErrTokenBlacklisted
	}

	// Check if the token has expired
	if token.ExpiresAt.Before(time.Now()) {
		return &token, ErrTokenExpired
	}

	return &token, nil
}

// BlacklistToken adds a token to the blacklist
func (s *GormTokenStore) BlacklistToken(ctx context.Context, tokenUUID string) error {
	// Update the token
	result := s.db.WithContext(ctx).Model(&models.Token{}).Where("uuid = ?", tokenUUID).Update("blacklist", true)
	if result.Error != nil {
		return fmt.Errorf("%w: %v", ErrDBOperation, result.Error)
	}

	// Check if the token was found
	if result.RowsAffected == 0 {
		return ErrTokenNotFound
	}

	return nil
}

// DeleteToken removes a token from the database
func (s *GormTokenStore) DeleteToken(ctx context.Context, tokenUUID string) error {
	// Delete the token
	result := s.db.WithContext(ctx).Where("uuid = ?", tokenUUID).Delete(&models.Token{})
	if result.Error != nil {
		return fmt.Errorf("%w: %v", ErrDBOperation, result.Error)
	}

	// Check if the token was found
	if result.RowsAffected == 0 {
		return ErrTokenNotFound
	}

	return nil
}

// DeleteExpiredTokens removes all expired tokens from the database
func (s *GormTokenStore) DeleteExpiredTokens(ctx context.Context) (int, error) {
	// Delete expired tokens
	result := s.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&models.Token{})
	if result.Error != nil {
		return 0, fmt.Errorf("%w: %v", ErrDBOperation, result.Error)
	}

	return int(result.RowsAffected), nil
}

// DeleteUserTokens removes all tokens for a specific user
func (s *GormTokenStore) DeleteUserTokens(ctx context.Context, userID uint) (int, error) {
	// Delete user tokens
	result := s.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.Token{})
	if result.Error != nil {
		return 0, fmt.Errorf("%w: %v", ErrDBOperation, result.Error)
	}

	return int(result.RowsAffected), nil
}

// IsTokenBlacklisted checks if a token is blacklisted
func (s *GormTokenStore) IsTokenBlacklisted(ctx context.Context, tokenUUID string) (bool, error) {
	var token models.Token

	// Query the database
	result := s.db.WithContext(ctx).Select("blacklist").Where("uuid = ?", tokenUUID).First(&token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return false, ErrTokenNotFound
		}
		return false, fmt.Errorf("%w: %v", ErrDBOperation, result.Error)
	}

	return token.Blacklist, nil
}

// InMemoryTokenStore implements TokenStore using an in-memory store (for testing)
type InMemoryTokenStore struct {
	tokens map[string]models.Token
}

// NewInMemoryTokenStore creates a new InMemoryTokenStore
func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{
		tokens: make(map[string]models.Token),
	}
}

// StoreToken stores a token in memory
func (s *InMemoryTokenStore) StoreToken(ctx context.Context, userID uint, tokenUUID string, tokenType string, token string, expiresAt time.Time) error {
	// Check if the token already exists
	if _, exists := s.tokens[tokenUUID]; exists {
		return ErrDuplicateToken
	}

	// Store the token
	s.tokens[tokenUUID] = models.Token{
		ID:        uint(len(s.tokens) + 1),
		UUID:      tokenUUID,
		UserID:    userID,
		Token:     token,
		Type:      tokenType,
		Blacklist: false,
		ExpiresAt: expiresAt,
	}

	return nil
}

// GetToken retrieves a token from memory
func (s *InMemoryTokenStore) GetToken(ctx context.Context, tokenUUID string) (*models.Token, error) {
	token, exists := s.tokens[tokenUUID]
	if !exists {
		return nil, ErrTokenNotFound
	}

	// Check if the token is blacklisted
	if token.Blacklist {
		return &token, ErrTokenBlacklisted
	}

	// Check if the token has expired
	if token.ExpiresAt.Before(time.Now()) {
		return &token, ErrTokenExpired
	}

	return &token, nil
}

// BlacklistToken adds a token to the blacklist
func (s *InMemoryTokenStore) BlacklistToken(ctx context.Context, tokenUUID string) error {
	token, exists := s.tokens[tokenUUID]
	if !exists {
		return ErrTokenNotFound
	}

	token.Blacklist = true
	s.tokens[tokenUUID] = token

	return nil
}

// DeleteToken removes a token from memory
func (s *InMemoryTokenStore) DeleteToken(ctx context.Context, tokenUUID string) error {
	if _, exists := s.tokens[tokenUUID]; !exists {
		return ErrTokenNotFound
	}

	delete(s.tokens, tokenUUID)
	return nil
}

// DeleteExpiredTokens removes all expired tokens from memory
func (s *InMemoryTokenStore) DeleteExpiredTokens(ctx context.Context) (int, error) {
	count := 0
	now := time.Now()

	for uuid, token := range s.tokens {
		if token.ExpiresAt.Before(now) {
			delete(s.tokens, uuid)
			count++
		}
	}

	return count, nil
}

// DeleteUserTokens removes all tokens for a specific user
func (s *InMemoryTokenStore) DeleteUserTokens(ctx context.Context, userID uint) (int, error) {
	count := 0

	for uuid, token := range s.tokens {
		if token.UserID == userID {
			delete(s.tokens, uuid)
			count++
		}
	}

	return count, nil
}

// IsTokenBlacklisted checks if a token is blacklisted
func (s *InMemoryTokenStore) IsTokenBlacklisted(ctx context.Context, tokenUUID string) (bool, error) {
	token, exists := s.tokens[tokenUUID]
	if !exists {
		return false, ErrTokenNotFound
	}

	return token.Blacklist, nil
}
