package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupCORSTest() *gin.Engine {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create test router
	router := gin.New()

	return router
}

func TestCORS_DefaultConfig(t *testing.T) {
	// Setup
	router := setupCORSTest()

	// Add CORS middleware with default config
	router.Use(CORS())

	// Add test route
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Test case 1: Simple request with Origin header
	t.Run("Simple Request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		resp := httptest.NewRecorder()

		router.ServeHTTP(resp, req)

		// Check response
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, "success", resp.Body.String())

		// Check CORS headers
		assert.Equal(t, "http://example.com", resp.Header().Get("Access-Control-Allow-Origin"))
	})

	// Test case 2: Preflight request
	t.Run("Preflight Request", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		resp := httptest.NewRecorder()

		router.ServeHTTP(resp, req)

		// Check response
		assert.Equal(t, http.StatusNoContent, resp.Code)

		// Check CORS headers
		assert.Equal(t, "http://example.com", resp.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, resp.Header().Get("Access-Control-Allow-Methods"), "GET")
	})

	// Test case 3: Request without Origin header
	t.Run("No Origin Header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		resp := httptest.NewRecorder()

		router.ServeHTTP(resp, req)

		// Check response
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, "success", resp.Body.String())

		// Check CORS headers - should not be set
		assert.Empty(t, resp.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestCORS_CustomConfig(t *testing.T) {
	// Setup
	router := setupCORSTest()

	// Create custom CORS config
	config := CORSConfig{
		AllowOrigins:     []string{"http://example.com", "https://example.org"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"X-Custom-Header"},
		ExposeHeaders:    []string{"X-Custom-Response-Header"},
		AllowCredentials: true,
		MaxAge:           1 * time.Hour,
	}

	// Add CORS middleware with custom config
	router.Use(CORSWithConfig(config))

	// Add test route
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Test case 1: Allowed origin
	t.Run("Allowed Origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		resp := httptest.NewRecorder()

		router.ServeHTTP(resp, req)

		// Check response
		assert.Equal(t, http.StatusOK, resp.Code)

		// Check CORS headers
		assert.Equal(t, "http://example.com", resp.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", resp.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "X-Custom-Response-Header", resp.Header().Get("Access-Control-Expose-Headers"))
	})

	// Test case 2: Disallowed origin
	t.Run("Disallowed Origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://unauthorized.com")
		resp := httptest.NewRecorder()

		router.ServeHTTP(resp, req)

		// Check response
		assert.Equal(t, http.StatusOK, resp.Code)

		// Check CORS headers - should not be set
		assert.Empty(t, resp.Header().Get("Access-Control-Allow-Origin"))
	})

	// Test case 3: Preflight request with custom headers
	t.Run("Preflight Request with Custom Headers", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "X-Custom-Header")
		resp := httptest.NewRecorder()

		router.ServeHTTP(resp, req)

		// Check response
		assert.Equal(t, http.StatusNoContent, resp.Code)

		// Check CORS headers
		assert.Equal(t, "http://example.com", resp.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST", resp.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "X-Custom-Header", resp.Header().Get("Access-Control-Allow-Headers"))
		assert.Equal(t, "true", resp.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "3600", resp.Header().Get("Access-Control-Max-Age"))
	})
}

func TestCORS_WildcardOrigin(t *testing.T) {
	// Setup
	router := setupCORSTest()

	// Create config with wildcard
	config := CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET"},
	}

	// Add CORS middleware
	router.Use(CORSWithConfig(config))

	// Add test route
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Test with any origin
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://any-domain.com")
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusOK, resp.Code)

	// Check CORS headers
	assert.Equal(t, "http://any-domain.com", resp.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_WildcardSubdomainOrigin(t *testing.T) {
	// Setup
	router := setupCORSTest()

	// Create config with wildcard subdomain
	config := CORSConfig{
		AllowOrigins: []string{"*.example.com"},
		AllowMethods: []string{"GET"},
	}

	// Add CORS middleware
	router.Use(CORSWithConfig(config))

	// Add test route
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Test case 1: Matching subdomain
	t.Run("Matching Subdomain", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://sub.example.com")
		resp := httptest.NewRecorder()

		router.ServeHTTP(resp, req)

		// Check response
		assert.Equal(t, http.StatusOK, resp.Code)

		// Check CORS headers
		assert.Equal(t, "https://sub.example.com", resp.Header().Get("Access-Control-Allow-Origin"))
	})

	// Test case 2: Non-matching domain
	t.Run("Non-matching Domain", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://example.org")
		resp := httptest.NewRecorder()

		router.ServeHTTP(resp, req)

		// Check response
		assert.Equal(t, http.StatusOK, resp.Code)

		// Check CORS headers - should not be set
		assert.Empty(t, resp.Header().Get("Access-Control-Allow-Origin"))
	})
}
