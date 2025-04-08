package auth

import (
	"context"
	"time"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// TokenPair represents a pair of JWT tokens - access and refresh
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// TokenDetails contains detailed information about a JWT token
type TokenDetails struct {
	TokenUUID string
	UserID    uint
	Roles     []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	NotBefore time.Time
	Issuer    string
	Subject   string
	Audience  []string
	IsRefresh bool
}

// Service defines the authentication service interface
type Service interface {
	// Login authenticates a user and returns a token pair
	Login(ctx context.Context, email, password string) (*TokenPair, error)

	// Register creates a new user and returns a token pair
	Register(ctx context.Context, user *models.User) (*TokenPair, error)

	// Verify verifies a JWT token and returns the token details
	Verify(ctx context.Context, tokenString string) (*TokenDetails, error)

	// Refresh refreshes an expired access token using a valid refresh token
	Refresh(ctx context.Context, refreshToken string) (*TokenPair, error)

	// Logout invalidates a token
	Logout(ctx context.Context, token string) error

	// GenerateTokens generates a new token pair for a user
	GenerateTokens(ctx context.Context, user *models.User) (*TokenPair, error)

	// HashPassword hashes a password
	HashPassword(password string) (string, error)

	// CheckPassword verifies if a password matches a hash
	CheckPassword(password, hash string) bool
}

// MockService is a mock implementation of the Service interface for testing
type MockService struct {
	LoginFunc    func(ctx context.Context, email, password string) (*TokenPair, error)
	RegisterFunc func(ctx context.Context, user *models.User) (*TokenPair, error)
	VerifyFunc   func(ctx context.Context, tokenString string) (*TokenDetails, error)
	RefreshFunc  func(ctx context.Context, refreshToken string) (*TokenPair, error)
	LogoutFunc   func(ctx context.Context, token string) error
	GenerateFunc func(ctx context.Context, user *models.User) (*TokenPair, error)
	HashFunc     func(password string) (string, error)
	CheckFunc    func(password, hash string) bool
}

// Login is a mock implementation
func (m *MockService) Login(ctx context.Context, email, password string) (*TokenPair, error) {
	if m.LoginFunc != nil {
		return m.LoginFunc(ctx, email, password)
	}
	return nil, nil
}

// Register is a mock implementation
func (m *MockService) Register(ctx context.Context, user *models.User) (*TokenPair, error) {
	if m.RegisterFunc != nil {
		return m.RegisterFunc(ctx, user)
	}
	return nil, nil
}

// Verify is a mock implementation
func (m *MockService) Verify(ctx context.Context, tokenString string) (*TokenDetails, error) {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(ctx, tokenString)
	}
	return nil, nil
}

// Refresh is a mock implementation
func (m *MockService) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	if m.RefreshFunc != nil {
		return m.RefreshFunc(ctx, refreshToken)
	}
	return nil, nil
}

// Logout is a mock implementation
func (m *MockService) Logout(ctx context.Context, token string) error {
	if m.LogoutFunc != nil {
		return m.LogoutFunc(ctx, token)
	}
	return nil
}

// GenerateTokens is a mock implementation
func (m *MockService) GenerateTokens(ctx context.Context, user *models.User) (*TokenPair, error) {
	if m.GenerateFunc != nil {
		return m.GenerateFunc(ctx, user)
	}
	return nil, nil
}

// HashPassword is a mock implementation
func (m *MockService) HashPassword(password string) (string, error) {
	if m.HashFunc != nil {
		return m.HashFunc(password)
	}
	return password, nil
}

// CheckPassword is a mock implementation
func (m *MockService) CheckPassword(password, hash string) bool {
	if m.CheckFunc != nil {
		return m.CheckFunc(password, hash)
	}
	return password == hash
}
