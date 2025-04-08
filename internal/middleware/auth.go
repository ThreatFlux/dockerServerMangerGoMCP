package middleware

import (
	// "context" // Removed unused import
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// Define unexported type for context keys
type contextKey int

const (
	// userIDKey is the context key for the user ID
	userIDKey contextKey = iota
	// userRolesKey is the context key for the user roles
	userRolesKey
	// tokenDetailsKey is the context key for the token details
	tokenDetailsKey
)

// Authentication errors
var (
	ErrAuthHeaderMissing = errors.New("authorization header is required")
	ErrInvalidAuthHeader = errors.New("invalid authorization header format")
	ErrTokenVerification = errors.New("failed to verify token")
	ErrInsufficientRole  = errors.New("insufficient role permissions")
)

// AuthMiddleware provides JWT authentication for routes
type AuthMiddleware struct {
	authService auth.Service
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(authService auth.Service) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
	}
}

// RequireAuthentication middleware ensures that the request has a valid JWT token
func (m *AuthMiddleware) RequireAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract and validate token
		tokenDetails, err := m.extractAndValidateToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}

		// Store user information in the context using string keys for Gin
		c.Set("userID", tokenDetails.UserID)
		c.Set("userRoles", tokenDetails.Roles)
		c.Set("tokenDetails", tokenDetails)

		c.Next()
	}
}

// RequireRole middleware ensures that the user has at least one of the required roles
func (m *AuthMiddleware) RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user roles from context
		ctxRoles, exists := c.Get("userRoles") // Use string key
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			c.Abort()
			return
		}

		userRoles, ok := ctxRoles.([]string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "invalid role format in token",
			})
			c.Abort()
			return
		}

		// Check if user has at least one of the required roles
		for _, userRole := range userRoles {
			for _, requiredRole := range roles {
				if userRole == requiredRole {
					c.Next()
					return
				}
			}
		}

		// User doesn't have any of the required roles
		c.JSON(http.StatusForbidden, gin.H{
			"error": fmt.Sprintf("access denied: requires one of these roles: %s", strings.Join(roles, ", ")),
		})
		c.Abort()
	}
}

// RequireAdmin middleware ensures that the user has admin role
func (m *AuthMiddleware) RequireAdmin() gin.HandlerFunc {
	return m.RequireRole(string(models.RoleAdmin))
}

// extractAndValidateToken extracts the JWT token from the Authorization header and validates it
func (m *AuthMiddleware) extractAndValidateToken(c *gin.Context) (*auth.TokenDetails, error) {
	// Get Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return nil, ErrAuthHeaderMissing
	}

	// Extract token from header
	headerParts := strings.Split(authHeader, " ")
	if len(headerParts) != 2 || headerParts[0] != "Bearer" {
		return nil, ErrInvalidAuthHeader
	}
	tokenString := headerParts[1]

	// Verify token
	tokenDetails, err := m.authService.Verify(c.Request.Context(), tokenString)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenVerification, err)
	}

	return tokenDetails, nil
}

// GetUserID extracts the user ID from the request context
// Note: Gin context is needed here, not standard context, to use c.Get
func GetUserID(c *gin.Context) (uint, error) { // Changed ctx to c *gin.Context
	value, exists := c.Get("userID") // Use c.Get with string key
	if !exists {
		return 0, errors.New("user ID not found in context")
	}

	userID, ok := value.(uint)
	if !ok {
		return 0, errors.New("user ID in context has invalid type")
	}

	return userID, nil
}

// GetUserRoles extracts the user roles from the request context
func GetUserRoles(c *gin.Context) ([]string, error) { // Changed ctx to c *gin.Context
	value, exists := c.Get("userRoles") // Use c.Get with string key
	if !exists {
		return nil, errors.New("user roles not found in context")
	}

	roles, ok := value.([]string)
	if !ok {
		return nil, errors.New("user roles in context have invalid type")
	}

	return roles, nil
}

// GetTokenDetails extracts the token details from the request context
func GetTokenDetails(c *gin.Context) (*auth.TokenDetails, error) { // Changed ctx to c *gin.Context
	value, exists := c.Get("tokenDetails") // Use c.Get with string key
	if !exists {
		return nil, errors.New("token details not found in context")
	}

	tokenDetails, ok := value.(*auth.TokenDetails)
	if !ok {
		return nil, errors.New("token details in context have invalid type")
	}

	return tokenDetails, nil
}

// HasRole checks if the user has a specific role
func HasRole(c *gin.Context, role string) (bool, error) { // Changed ctx to c *gin.Context
	roles, err := GetUserRoles(c) // Pass gin.Context
	if err != nil {
		return false, err
	}

	for _, r := range roles {
		if r == role {
			return true, nil
		}
	}

	return false, nil
}

// IsAdmin checks if the user is an admin
func IsAdmin(c *gin.Context) (bool, error) { // Changed ctx to c *gin.Context
	return HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
}
