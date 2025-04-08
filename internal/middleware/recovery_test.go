package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func setupRecoveryTest() (*gin.Engine, *bytes.Buffer, *logrus.Logger) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create test router
	router := gin.New()

	// Create test logger
	logger := logrus.New()
	logOutput := new(bytes.Buffer)
	logger.SetOutput(logOutput)
	logger.SetFormatter(&logrus.JSONFormatter{})

	return router, logOutput, logger
}

func TestRecoveryMiddleware_BasicRecovery(t *testing.T) {
	// Setup
	router, logOutput, logger := setupRecoveryTest()

	// Create recovery middleware
	recoveryMiddleware := NewRecoveryMiddleware(logger)

	// Add middleware and test route that will panic
	router.Use(recoveryMiddleware.Recovery())
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	// Create test request
	req := httptest.NewRequest("GET", "/panic", nil)
	resp := httptest.NewRecorder()

	// Perform request (should not cause actual panic)
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusInternalServerError, resp.Code)

	// Parse response body
	var respBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &respBody)
	assert.NoError(t, err)

	// Verify response fields
	assert.Equal(t, "Internal Server Error", respBody["error"])
	assert.NotEmpty(t, respBody["timestamp"])

	// Check log output
	var logEntry map[string]interface{}
	err = json.Unmarshal(logOutput.Bytes(), &logEntry)
	assert.NoError(t, err)

	// Verify log fields
	assert.Equal(t, "test panic", logEntry["error"])
	assert.Contains(t, logEntry["stack"], "runtime/debug.Stack")
	assert.Equal(t, "error", logEntry["level"])
	assert.Contains(t, logEntry["message"], "[Recovery] Panic recovered")
}

func TestRecoveryMiddleware_RequestDetails(t *testing.T) {
	// Setup
	router, logOutput, logger := setupRecoveryTest()

	// Add request ID middleware first
	router.Use(RequestIDMiddleware())

	// Create recovery middleware
	recoveryMiddleware := NewRecoveryMiddleware(logger)
	router.Use(recoveryMiddleware.Recovery())

	// Add test route that will panic with custom headers
	router.GET("/panic", func(c *gin.Context) {
		c.Set("custom_value", "test_value")
		panic("test panic with custom request")
	})

	// Create test request with custom header
	req := httptest.NewRequest("GET", "/panic", nil)
	req.Header.Set("X-Custom-Header", "test-header-value")
	req.Header.Set("X-Request-ID", "test-request-id")
	resp := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusInternalServerError, resp.Code)

	// Parse response body
	var respBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &respBody)
	assert.NoError(t, err)

	// Verify response includes request ID
	assert.Equal(t, "test-request-id", respBody["request_id"])

	// Check log output
	var logEntry map[string]interface{}
	err = json.Unmarshal(logOutput.Bytes(), &logEntry)
	assert.NoError(t, err)

	// Verify request information in log
	assert.Equal(t, "test-request-id", logEntry["request_id"])
	assert.Equal(t, "GET", logEntry["method"])
	assert.Equal(t, "/panic", logEntry["path"])
	assert.Contains(t, logEntry["request"], "X-Custom-Header")
}

func TestRecoverDefault(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create test router with default recovery
	router := gin.New()
	router.Use(RecoverDefault())

	// Add test route that will panic
	router.GET("/panic", func(c *gin.Context) {
		panic("test default panic recovery")
	})

	// Create test request
	req := httptest.NewRequest("GET", "/panic", nil)
	resp := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusInternalServerError, resp.Code)

	// Parse response body
	var respBody map[string]interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &respBody)
	assert.NoError(t, err)

	// Verify response fields
	assert.Equal(t, "Internal Server Error", respBody["error"])
	assert.NotEmpty(t, respBody["timestamp"])
}

func TestSafeHandler(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create test router
	router := gin.New()

	// Add request ID middleware
	router.Use(RequestIDMiddleware())

	// Test cases:
	// 1. Handler that panics
	router.GET("/panic", SafeHandler(func(c *gin.Context) {
		panic("safe handler test panic")
	}))

	// 2. Handler that doesn't panic
	router.GET("/normal", SafeHandler(func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}))

	// Test case 1: Handler that panics
	t.Run("Panic Handler", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/panic", nil)
		resp := httptest.NewRecorder()

		router.ServeHTTP(resp, req)

		// Check response
		assert.Equal(t, http.StatusInternalServerError, resp.Code)

		// Parse response body
		var respBody map[string]interface{}
		err := json.Unmarshal(resp.Body.Bytes(), &respBody)
		assert.NoError(t, err)

		// Verify response fields
		assert.Equal(t, "Internal Server Error", respBody["error"])
		assert.NotEmpty(t, respBody["timestamp"])
		assert.NotEmpty(t, respBody["request_id"])
	})

	// Test case 2: Handler that doesn't panic
	t.Run("Normal Handler", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/normal", nil)
		resp := httptest.NewRecorder()

		router.ServeHTTP(resp, req)

		// Check response
		assert.Equal(t, http.StatusOK, resp.Code)

		// Parse response body
		var respBody map[string]interface{}
		err := json.Unmarshal(resp.Body.Bytes(), &respBody)
		assert.NoError(t, err)

		// Verify response
		assert.Equal(t, "success", respBody["message"])
	})
}
