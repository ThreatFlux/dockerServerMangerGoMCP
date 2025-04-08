package middleware

import (
	"net/http"
	"strconv" // Added for Itoa
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// CORSConfig contains configuration for CORS middleware
type CORSConfig struct {
	// AllowOrigins is a list of origins a cross-domain request can be executed from
	AllowOrigins []string

	// AllowMethods is a list of methods the client is allowed to use
	AllowMethods []string

	// AllowHeaders is a list of non-simple headers the client is allowed to use
	AllowHeaders []string

	// ExposeHeaders is a list of headers that are safe to expose to the API
	ExposeHeaders []string

	// AllowCredentials indicates whether the request can include user credentials
	AllowCredentials bool

	// MaxAge indicates how long the results of a preflight request can be cached
	MaxAge time.Duration
}

// DefaultCORSConfig returns the default CORS configuration
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}
}

// CORS returns the middleware with default configuration
func CORS() gin.HandlerFunc {
	return CORSWithConfig(DefaultCORSConfig())
}

// CORSWithConfig returns the CORS middleware with custom configuration
func CORSWithConfig(config CORSConfig) gin.HandlerFunc {
	// Normalize AllowOrigins
	normalizedAllowOrigins := normalizeOrigins(config.AllowOrigins)

	// Convert MaxAge to seconds
	maxAgeSeconds := int(config.MaxAge.Seconds())

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Origin not allowed
		if origin == "" || !isOriginAllowed(normalizedAllowOrigins, origin) {
			// Process request
			c.Next()
			return
		}

		// Set headers
		c.Header("Access-Control-Allow-Origin", origin)

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			// Set preflight headers
			c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowMethods, ", "))
			c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowHeaders, ", "))
			c.Header("Access-Control-Max-Age", strconv.Itoa(maxAgeSeconds)) // Use strconv.Itoa

			if config.AllowCredentials {
				c.Header("Access-Control-Allow-Credentials", "true")
			}

			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		// Set headers for regular requests
		if len(config.ExposeHeaders) > 0 {
			c.Header("Access-Control-Expose-Headers", strings.Join(config.ExposeHeaders, ", "))
		}

		if config.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		c.Next()
	}
}

// normalizeOrigins normalizes the origin values
func normalizeOrigins(origins []string) []string {
	if len(origins) == 0 {
		return []string{"*"}
	}

	for i, origin := range origins {
		origins[i] = strings.ToLower(origin)
	}

	return origins
}

// isOriginAllowed checks if the origin is allowed
func isOriginAllowed(allowedOrigins []string, origin string) bool {
	origin = strings.ToLower(origin)

	for _, allowedOrigin := range allowedOrigins {
		if allowedOrigin == "*" {
			return true
		}

		if allowedOrigin == origin {
			return true
		}

		// Handle wildcard subdomains
		if strings.HasPrefix(allowedOrigin, "*.") {
			domainSuffix := allowedOrigin[1:] // Remove first character (*)
			if strings.HasSuffix(origin, domainSuffix) {
				return true
			}
		}
	}

	return false
}
