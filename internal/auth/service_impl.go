package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus" // Added import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"gorm.io/gorm"
)

// Service errors
var (
	ErrEmailTaken          = errors.New("email address is already in use")
	ErrTokenInvalid        = errors.New("invalid or expired token")
	ErrRefreshTokenInvalid = errors.New("invalid refresh token")
	ErrUserCreationFailed  = errors.New("failed to create user")
)

// ServiceImpl implements the Service interface
type ServiceImpl struct {
	db              database.Database
	jwtService      *JWTService
	passwordService *PasswordService
	tokenStore      TokenStore
	log             *logrus.Logger // Added logger
}

// NewService creates a new authentication service
func NewService(db database.Database, jwtConfig JWTConfig, passwordConfig PasswordConfig, tokenStore TokenStore, log *logrus.Logger) Service { // Added logger param
	return &ServiceImpl{
		db:              db,
		jwtService:      NewJWTService(jwtConfig, log), // Pass logger
		passwordService: NewPasswordService(passwordConfig),
		tokenStore:      tokenStore,
		log:             log, // Store logger
	}
}

// Login authenticates a user and returns a token pair
func (s *ServiceImpl) Login(ctx context.Context, email, password string) (*TokenPair, error) {
	// Find the user by email
	var user models.User
	if err := s.db.DB().WithContext(ctx).
		Preload("Roles").
		Where("email = ?", email).
		First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Check if user is active
	if !user.Active {
		return nil, ErrUserInactive
	}
	s.log.WithFields(logrus.Fields{"email": email, "userID": user.ID, "storedHash": user.Password}).Debug("User found, checking password")

	// Verify password
	passwordMatch := s.passwordService.CheckPassword(password, user.Password)
	s.log.WithFields(logrus.Fields{"email": email, "userID": user.ID, "match": passwordMatch}).Debug("Password check result")
	if !passwordMatch {
		s.log.WithFields(logrus.Fields{"email": email, "userID": user.ID}).Warn("Password mismatch during login")
		return nil, ErrInvalidCredentials
	}

	// Update last login time
	now := time.Now()
	user.LastLogin = &now
	if err := s.db.DB().WithContext(ctx).
		Model(&user).
		Update("last_login", now).Error; err != nil {
		// Non-critical error, log it but continue
		fmt.Printf("Failed to update last login time: %v\n", err)
	}

	// Generate tokens
	tokens, err := s.GenerateTokens(ctx, &user)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

// Register creates a new user and returns a token pair
func (s *ServiceImpl) Register(ctx context.Context, user *models.User) (*TokenPair, error) {
	// Check if email is already taken
	var count int64
	if err := s.db.DB().WithContext(ctx).
		Model(&models.User{}).
		Where("email = ?", user.Email).
		Count(&count).Error; err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	if count > 0 {
		return nil, ErrEmailTaken
	}

	// Password should already be hashed by the controller/handler before calling Register
	// hashedPassword, err := s.passwordService.HashPassword(user.Password)
	// if err != nil {
	// 	return nil, err
	// }
	// user.Password = hashedPassword // Assume user.Password is already the correct hash

	// Set default values
	user.Active = true
	user.EmailVerified = false
	var err error // Declare err variable here

	// Ensure user has at least the basic user role
	hasUserRole := false
	for _, role := range user.Roles {
		if role.Role == models.RoleUser {
			hasUserRole = true
			break
		}
	}

	if !hasUserRole {
		user.Roles = append(user.Roles, models.UserRole{
			Role: models.RoleUser,
		})
	}

	// Create user in database
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserCreationFailed, err)
	}

	// Generate tokens
	tokens, err := s.GenerateTokens(ctx, user)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

// Verify verifies a JWT token and returns the token details
func (s *ServiceImpl) Verify(ctx context.Context, tokenString string) (*TokenDetails, error) {
	// Extract token details
	tokenDetails, err := s.jwtService.ExtractTokenDetails(tokenString, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	// Check if token is blacklisted
	isBlacklisted, err := s.tokenStore.IsTokenBlacklisted(ctx, tokenDetails.TokenUUID)
	if err != nil && !errors.Is(err, ErrTokenNotFound) {
		return nil, err
	}

	if isBlacklisted {
		return nil, ErrTokenBlacklisted
	}

	return tokenDetails, nil
}

// Refresh refreshes an expired access token using a valid refresh token
func (s *ServiceImpl) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	// Extract refresh token details
	tokenDetails, err := s.jwtService.ExtractTokenDetails(refreshToken, true)
	if err != nil {
		if errors.Is(err, ErrExpiredToken) {
			// Attempt to blacklist the token even if expired
			tokenUUID, err := s.jwtService.GetTokenUUID(refreshToken, true)
			if err == nil && tokenUUID != "" {
				_ = s.tokenStore.BlacklistToken(ctx, tokenUUID)
			}
		}
		return nil, fmt.Errorf("%w: %v", ErrRefreshTokenInvalid, err)
	}

	// Check if refresh token is blacklisted
	isBlacklisted, err := s.tokenStore.IsTokenBlacklisted(ctx, tokenDetails.TokenUUID)
	if err != nil && !errors.Is(err, ErrTokenNotFound) {
		return nil, err
	}

	if isBlacklisted {
		return nil, ErrTokenBlacklisted
	}

	// Find the user to get updated roles
	var user models.User
	if err := s.db.DB().WithContext(ctx).
		Preload("Roles").
		First(&user, tokenDetails.UserID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Check if user is active
	if !user.Active {
		return nil, ErrUserInactive
	}

	// Blacklist the old refresh token
	err = s.tokenStore.BlacklistToken(ctx, tokenDetails.TokenUUID)
	if err != nil && !errors.Is(err, ErrTokenNotFound) {
		return nil, err
	}

	// Generate new tokens
	newTokens, err := s.GenerateTokens(ctx, &user)
	if err != nil {
		return nil, err
	}

	return newTokens, nil
}

// Logout invalidates a token
func (s *ServiceImpl) Logout(ctx context.Context, token string) error {
	// Extract token UUID
	tokenUUID, err := s.jwtService.GetTokenUUID(token, false)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	// Blacklist the token
	err = s.tokenStore.BlacklistToken(ctx, tokenUUID)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			// Token not found in store, but we can still consider the logout successful
			return nil
		}
		return err
	}

	return nil
}

// GenerateTokens generates a new token pair for a user
func (s *ServiceImpl) GenerateTokens(ctx context.Context, user *models.User) (*TokenPair, error) {
	// Generate token pair
	tokenPair, err := s.jwtService.GenerateTokenPair(user)
	if err != nil {
		return nil, err
	}

	// Extract access token details for storage
	accessDetails, err := s.jwtService.ExtractTokenDetails(tokenPair.AccessToken, false)
	if err != nil {
		return nil, err
	}

	// Extract refresh token details for storage
	refreshDetails, err := s.jwtService.ExtractTokenDetails(tokenPair.RefreshToken, true)
	if err != nil {
		return nil, err
	}

	// Store access token
	err = s.tokenStore.StoreToken(
		ctx,
		user.ID,
		accessDetails.TokenUUID,
		"access",
		tokenPair.AccessToken,
		accessDetails.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}

	// Store refresh token
	err = s.tokenStore.StoreToken(
		ctx,
		user.ID,
		refreshDetails.TokenUUID,
		"refresh",
		tokenPair.RefreshToken,
		refreshDetails.ExpiresAt,
	)
	if err != nil {
		// If storing refresh token fails, clean up access token
		_ = s.tokenStore.DeleteToken(ctx, accessDetails.TokenUUID)
		return nil, err
	}

	return tokenPair, nil
}

// HashPassword hashes a password
func (s *ServiceImpl) HashPassword(password string) (string, error) {
	return s.passwordService.HashPassword(password)
}

// CheckPassword verifies if a password matches a hash
func (s *ServiceImpl) CheckPassword(password, hash string) bool {
	return s.passwordService.CheckPassword(password, hash)
}
