package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"gorm.io/gorm"
)

// Authentication-related errors
var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrUserNotFound        = errors.New("user not found")
	ErrUserInactive        = errors.New("user account is inactive")
	ErrEmailNotVerified    = errors.New("email not verified")
	ErrUserAlreadyExists   = errors.New("user already exists")
	ErrInvalidEmail        = errors.New("invalid email address")
	ErrInvalidPassword     = errors.New("invalid password")
	ErrUserCreation        = errors.New("failed to create user")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

// AuthService implements the Service interface for authentication
type AuthService struct {
	db                       *gorm.DB
	jwtService               *JWTService
	passwordService          *PasswordService
	tokenStore               TokenStore
	requireEmailVerification bool
}

// NewAuthService creates a new authentication service
func NewAuthService(
	db *gorm.DB,
	jwtService *JWTService,
	passwordService *PasswordService,
	tokenStore TokenStore,
	requireEmailVerification bool,
) *AuthService {
	return &AuthService{
		db:                       db,
		jwtService:               jwtService,
		passwordService:          passwordService,
		tokenStore:               tokenStore,
		requireEmailVerification: requireEmailVerification,
	}
}

// Login authenticates a user and returns a token pair
func (s *AuthService) Login(ctx context.Context, email, password string) (*TokenPair, error) {
	var user models.User

	// Find user by email
	result := s.db.WithContext(ctx).
		Preload("Roles").
		Where("email = ?", email).
		First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("database error: %w", result.Error)
	}

	// Check if user is active
	if !user.Active {
		return nil, ErrUserInactive
	}

	// Check if email verification is required
	if s.requireEmailVerification && !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	// Verify password
	if !s.passwordService.CheckPassword(password, user.Password) {
		return nil, ErrInvalidCredentials
	}

	// Generate tokens
	tokenPair, err := s.GenerateTokens(ctx, &user)
	if err != nil {
		return nil, err
	}

	// Update last login timestamp
	now := time.Now()
	user.LastLogin = &now
	s.db.WithContext(ctx).Save(&user)

	return tokenPair, nil
}

// Register creates a new user and returns a token pair
func (s *AuthService) Register(ctx context.Context, user *models.User) (*TokenPair, error) {
	// Validate email
	if user.Email == "" {
		return nil, ErrInvalidEmail
	}

	// Check if user already exists
	var count int64
	result := s.db.WithContext(ctx).Model(&models.User{}).Where("email = ?", user.Email).Count(&count)
	if result.Error != nil {
		return nil, fmt.Errorf("database error: %w", result.Error)
	}
	if count > 0 {
		return nil, ErrUserAlreadyExists
	}

	// Validate and hash password
	if err := s.passwordService.ValidatePassword(user.Password); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPassword, err)
	}
	hashedPassword, err := s.passwordService.HashPassword(user.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}
	user.Password = hashedPassword

	// Add default role if not specified
	if len(user.Roles) == 0 {
		user.Roles = []models.UserRole{
			{Role: models.RoleUser},
		}
	}

	// Set default fields
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	user.Active = true

	// Set email verification status
	if !s.requireEmailVerification {
		user.EmailVerified = true
	}

	// Create user in database
	result = s.db.WithContext(ctx).Create(user)
	if result.Error != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserCreation, result.Error)
	}

	// Generate tokens if email verification is not required
	if !s.requireEmailVerification {
		return s.GenerateTokens(ctx, user)
	}

	// Otherwise, return nil tokens (user needs to verify email first)
	return nil, nil
}

// Verify verifies a JWT token and returns the token details
func (s *AuthService) Verify(ctx context.Context, tokenString string) (*TokenDetails, error) {
	// Extract token details
	tokenDetails, err := s.jwtService.ExtractTokenDetails(tokenString, false)
	if err != nil {
		return nil, err
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
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	// Extract refresh token details
	tokenDetails, err := s.jwtService.ExtractTokenDetails(refreshToken, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRefreshToken, err)
	}

	// Check if token is blacklisted
	isBlacklisted, err := s.tokenStore.IsTokenBlacklisted(ctx, tokenDetails.TokenUUID)
	if err != nil && !errors.Is(err, ErrTokenNotFound) {
		return nil, err
	}
	if isBlacklisted {
		return nil, ErrTokenBlacklisted
	}

	// Load user
	var user models.User
	result := s.db.WithContext(ctx).Preload("Roles").First(&user, tokenDetails.UserID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("database error: %w", result.Error)
	}

	// Check if user is active
	if !user.Active {
		return nil, ErrUserInactive
	}

	// Blacklist the used refresh token
	if err := s.tokenStore.BlacklistToken(ctx, tokenDetails.TokenUUID); err != nil && !errors.Is(err, ErrTokenNotFound) {
		return nil, err
	}

	// Generate new tokens
	return s.GenerateTokens(ctx, &user)
}

// Logout invalidates a token
func (s *AuthService) Logout(ctx context.Context, token string) error {
	// Check if it's an access token or refresh token
	var tokenUUID string
	var err error

	// Try as access token first
	tokenUUID, err = s.jwtService.GetTokenUUID(token, false)
	if err != nil {
		// If not an access token, try as refresh token
		tokenUUID, err = s.jwtService.GetTokenUUID(token, true)
		if err != nil {
			return fmt.Errorf("invalid token: %w", err)
		}
	}

	// Blacklist the token
	err = s.tokenStore.BlacklistToken(ctx, tokenUUID)
	if err != nil && !errors.Is(err, ErrTokenNotFound) {
		return err
	}

	return nil
}

// GenerateTokens generates a new token pair for a user
func (s *AuthService) GenerateTokens(ctx context.Context, user *models.User) (*TokenPair, error) {
	// Generate token pair
	tokenPair, err := s.jwtService.GenerateTokenPair(user)
	if err != nil {
		return nil, err
	}

	// Get token UUIDs
	accessUUID, err := s.jwtService.GetTokenUUID(tokenPair.AccessToken, false)
	if err != nil {
		return nil, err
	}
	refreshUUID, err := s.jwtService.GetTokenUUID(tokenPair.RefreshToken, true)
	if err != nil {
		return nil, err
	}

	// Store tokens in database
	accessExpiry := time.Now().Add(time.Minute * time.Duration(s.jwtService.Config.AccessTokenExpiry))
	refreshExpiry := time.Now().Add(time.Hour * time.Duration(s.jwtService.Config.RefreshTokenExpiry))

	// Store access token
	err = s.tokenStore.StoreToken(ctx, user.ID, accessUUID, "access", tokenPair.AccessToken, accessExpiry)
	if err != nil {
		return nil, err
	}

	// Store refresh token
	err = s.tokenStore.StoreToken(ctx, user.ID, refreshUUID, "refresh", tokenPair.RefreshToken, refreshExpiry)
	if err != nil {
		// If refresh token storage fails, delete the access token too
		s.tokenStore.DeleteToken(ctx, accessUUID)
		return nil, err
	}

	return tokenPair, nil
}

// HashPassword hashes a password
func (s *AuthService) HashPassword(password string) (string, error) {
	return s.passwordService.HashPassword(password)
}

// CheckPassword verifies if a password matches a hash
func (s *AuthService) CheckPassword(password, hash string) bool {
	return s.passwordService.CheckPassword(password, hash)
}
