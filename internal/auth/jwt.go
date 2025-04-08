package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus" // Added import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// JWT error definitions
var (
	ErrInvalidToken         = errors.New("invalid token")
	ErrExpiredToken         = errors.New("token has expired")
	ErrTokenNotYetValid     = errors.New("token not yet valid")
	ErrInvalidSigningMethod = errors.New("invalid signing method")
	ErrInvalidClaims        = errors.New("invalid token claims")
	ErrMissingKey           = errors.New("signing key is missing")
	ErrTokenGeneration      = errors.New("failed to generate token")
	ErrInvalidAudience      = errors.New("invalid token audience")
	ErrInvalidIssuer        = errors.New("invalid token issuer")
	ErrInvalidUserID        = errors.New("invalid user ID in token")
	ErrInvalidUUID          = errors.New("invalid UUID in token")
	ErrInvalidRoles         = errors.New("invalid roles in token")
	ErrNotRefreshToken      = errors.New("token is not a refresh token")
)

// JWTConfig contains configuration for JWT token generation and validation
type JWTConfig struct {
	// Secret key used for signing tokens
	AccessTokenSecret string

	// Secret key used for signing refresh tokens
	RefreshTokenSecret string

	// AccessTokenExpiry defines the lifetime of an access token in minutes
	AccessTokenExpiry int

	// RefreshTokenExpiry defines the lifetime of a refresh token in hours
	RefreshTokenExpiry int

	// Issuer identifies the principal that issued the JWT
	Issuer string

	// Audience identifies the recipients that the JWT is intended for
	Audience []string
}

// DefaultJWTConfig returns the default JWT configuration
func DefaultJWTConfig() JWTConfig {
	return JWTConfig{
		AccessTokenExpiry:  15,     // 15 minutes
		RefreshTokenExpiry: 24 * 7, // 7 days
		Issuer:             "docker_test-server-manager",
		Audience:           []string{"dsm-api"},
	}
}

// CustomClaims defines the custom claims for JWT tokens
type CustomClaims struct {
	UserID    uint     `json:"uid"`
	Roles     []string `json:"roles"`
	TokenUUID string   `json:"tid"`
	IsRefresh bool     `json:"refresh"`
	jwt.RegisteredClaims
}

// JWTService implements JWT operations for authentication
type JWTService struct {
	Config JWTConfig
	log    *logrus.Logger // Added logger
}

// NewJWTService creates a new JWT service with the provided configuration
func NewJWTService(config JWTConfig, log *logrus.Logger) *JWTService { // Added logger param
	// Use default config if secrets are empty (should ideally error out or use secure defaults)
	if config.AccessTokenSecret == "" || config.RefreshTokenSecret == "" {
		log.Warn("JWT secrets are empty in config, using potentially insecure defaults!")
		// Consider generating random secrets here if this is acceptable
	} // Added missing closing brace
	return &JWTService{
		Config: config,
		log:    log, // Store logger
	}
	// Removed extra closing brace
}

// GenerateTokenPair generates a new access/refresh token pair for a user
func (s *JWTService) GenerateTokenPair(user *models.User) (*TokenPair, error) {
	// Check if the configuration is valid
	if s.Config.AccessTokenSecret == "" || s.Config.RefreshTokenSecret == "" {
		return nil, ErrMissingKey
	}

	// Get user roles
	roles := user.GetRoleNames()

	// Generate access token
	accessToken, _, accessExpiresAt, err := s.generateAccessToken(user.ID, roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, _, _, err := s.generateRefreshToken(user.ID, roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessExpiresAt,
	}, nil
}

// generateAccessToken creates a new access token for a user
func (s *JWTService) generateAccessToken(userID uint, roles []string) (string, string, time.Time, error) {
	// Generate a unique ID for the token
	tokenUUID := uuid.New().String()

	// Set expiration time
	expiresAt := time.Now().Add(time.Minute * time.Duration(s.Config.AccessTokenExpiry))
	issuedAt := time.Now()
	notBefore := issuedAt

	// Create the claims
	claims := CustomClaims{
		UserID:    userID,
		Roles:     roles,
		TokenUUID: tokenUUID,
		IsRefresh: false,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(notBefore),
			Issuer:    s.Config.Issuer,
			Audience:  s.Config.Audience,
			ID:        tokenUUID,
			Subject:   fmt.Sprintf("%d", userID),
		},
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token
	tokenString, err := token.SignedString([]byte(s.Config.AccessTokenSecret))
	if err != nil {
		return "", "", time.Time{}, err
	}

	return tokenString, tokenUUID, expiresAt, nil
}

// generateRefreshToken creates a new refresh token for a user
func (s *JWTService) generateRefreshToken(userID uint, roles []string) (string, string, time.Time, error) {
	// Generate a unique ID for the token
	tokenUUID := uuid.New().String()

	// Set expiration time
	expiresAt := time.Now().Add(time.Hour * time.Duration(s.Config.RefreshTokenExpiry))
	issuedAt := time.Now()
	notBefore := issuedAt

	// Create the claims
	claims := CustomClaims{
		UserID:    userID,
		Roles:     roles,
		TokenUUID: tokenUUID,
		IsRefresh: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(notBefore),
			Issuer:    s.Config.Issuer,
			Audience:  s.Config.Audience,
			ID:        tokenUUID,
			Subject:   fmt.Sprintf("%d", userID),
		},
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token
	tokenString, err := token.SignedString([]byte(s.Config.RefreshTokenSecret))
	if err != nil {
		return "", "", time.Time{}, err
	}

	return tokenString, tokenUUID, expiresAt, nil
}

// ExtractTokenDetails validates a token and extracts its details
func (s *JWTService) ExtractTokenDetails(tokenString string, isRefresh bool) (*TokenDetails, error) {
	// Determine which secret to use
	secret := s.Config.AccessTokenSecret
	if isRefresh {
		secret = s.Config.RefreshTokenSecret // Assign to the outer 'secret' variable
		if secret == "" {
			return nil, ErrMissingKey
		}
	} else if secret == "" {
		return nil, ErrMissingKey
	}
	s.log.WithField("is_refresh", isRefresh).Debug("Attempting to parse and validate token") // Added log

	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSigningMethod
		}
		return []byte(secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotYetValid
		}
		// Log the specific parsing error
		s.log.WithError(err).Warn("Token parsing/validation failed") // Added log
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	s.log.Debug("Token parsed and validated successfully") // Added log

	// Extract claims
	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClaims
	}

	// Validate claims
	if err := s.validateClaims(claims, isRefresh); err != nil {
		return nil, err
	}

	// Extract expiration time
	expiresAt, err := claims.GetExpirationTime()
	if err != nil {
		return nil, ErrInvalidClaims
	}

	// Extract issuer
	issuer, err := claims.GetIssuer()
	if err != nil {
		return nil, ErrInvalidClaims
	}

	// Extract subject
	subject, err := claims.GetSubject()
	if err != nil {
		return nil, ErrInvalidClaims
	}

	// Extract audience
	audience, err := claims.GetAudience()
	if err != nil {
		return nil, ErrInvalidClaims
	}

	// Extract issued at
	issuedAt, err := claims.GetIssuedAt()
	if err != nil {
		return nil, ErrInvalidClaims
	}

	// Extract not before
	notBefore, err := claims.GetNotBefore()
	if err != nil {
		return nil, ErrInvalidClaims
	}

	// Create token details
	tokenDetails := &TokenDetails{
		TokenUUID: claims.TokenUUID,
		UserID:    claims.UserID,
		Roles:     claims.Roles,
		ExpiresAt: expiresAt.Time,
		IssuedAt:  issuedAt.Time,
		NotBefore: notBefore.Time,
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audience,
		IsRefresh: claims.IsRefresh,
	}

	return tokenDetails, nil
}

// validateClaims validates token claims based on configuration
func (s *JWTService) validateClaims(claims *CustomClaims, isRefresh bool) error {
	// Check if the token is of the expected type (access/refresh)
	if isRefresh && !claims.IsRefresh {
		return ErrNotRefreshToken
	}
	if !isRefresh && claims.IsRefresh {
		return ErrInvalidToken
	}

	// Verify issuer
	if claims.Issuer != s.Config.Issuer {
		return ErrInvalidIssuer
	}

	// Verify audience
	audienceValid := false
	for _, expectedAud := range s.Config.Audience {
		for _, tokenAud := range claims.Audience {
			if expectedAud == tokenAud {
				audienceValid = true
				break
			}
		}
		if audienceValid {
			break
		}
	}
	if !audienceValid {
		return ErrInvalidAudience
	}

	// Verify user ID
	if claims.UserID == 0 {
		return ErrInvalidUserID
	}

	// Verify token UUID
	if claims.TokenUUID == "" {
		return ErrInvalidUUID
	}

	// Verify roles
	if claims.Roles == nil {
		return ErrInvalidRoles
	}

	return nil
}

// RefreshTokens generates new tokens from a valid refresh token
func (s *JWTService) RefreshTokens(refreshToken string) (*TokenPair, error) {
	// Extract details from the refresh token
	tokenDetails, err := s.ExtractTokenDetails(refreshToken, true)
	if err != nil {
		return nil, err
	}

	// Create a mock user from the token details
	user := &models.User{
		ID: tokenDetails.UserID,
	}

	// Generate new tokens
	return s.GenerateTokenPair(user)
}

// GetTokenUUID extracts the UUID from a token without full validation
func (s *JWTService) GetTokenUUID(tokenString string, isRefresh bool) (string, error) {
	// Determine which secret to use
	secret := s.Config.AccessTokenSecret
	if isRefresh {
		secret = s.Config.RefreshTokenSecret
	}
	if secret == "" {
		return "", ErrMissingKey
	}

	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSigningMethod
		}
		return []byte(secret), nil
	})
	if err != nil {
		// We still extract the UUID even if the token is expired
		if errors.Is(err, jwt.ErrTokenExpired) {
			if claims, ok := token.Claims.(*CustomClaims); ok {
				return claims.TokenUUID, nil
			}
		}
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Extract claims
	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return "", ErrInvalidClaims
	}

	return claims.TokenUUID, nil
}
