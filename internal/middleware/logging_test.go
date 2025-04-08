package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func setupLoggingTest() (*gin.Engine, *bytes.Buffer, *logrus.Logger) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create test router
	router := gin.New()

	// Create test logger
	logger := logrus.New()
	logOutput := new(bytes.Buffer)
	logger.SetOutput(logOutput)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.DebugLevel)

	return router, logOutput, logger
}

func TestLoggingMiddleware_BasicLogging(t *testing.T) {
	// Setup
	router, logOutput, logger := setupLoggingTest()

	// Create logging middleware
	loggingMiddleware := NewLoggingMiddleware(logger)

	// Add middleware and test route
	router.Use(loggingMiddleware.Logger())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	resp := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "success", resp.Body.String())

	// Check log output
	logData := make(map[string]interface{})
	err := json.Unmarshal(logOutput.Bytes(), &logData)
	assert.NoError(t, err)

	// Verify basic log fields
	assert.Equal(t, float64(http.StatusOK), logData["status"])
	assert.Equal(t, "GET", logData["method"])
	assert.Equal(t, "/test", logData["path"])
	assert.Equal(t, "info", logData["level"])
	assert.Contains(t, logData["latency"], "ns")
}

func TestLoggingMiddleware_RequestResponseBodyLogging(t *testing.T) {
	// Setup
	router, logOutput, logger := setupLoggingTest()

	// Create logging middleware with request and response body logging
	loggingMiddleware := NewLoggingMiddleware(
		logger,
		WithRequestBodyLogging(true),
		WithResponseBodyLogging(true),
	)

	// Add middleware and test route
	router.Use(loggingMiddleware.Logger())
	router.POST("/test", func(c *gin.Context) {
		var data map[string]string
		if err := c.BindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success", "data": data})
	})

	// Create test request
	requestBody := `{"key": "value"}`
	req := httptest.NewRequest("POST", "/test", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusOK, resp.Code)

	// Check log output
	logData := make(map[string]interface{})
	err := json.Unmarshal(logOutput.Bytes(), &logData)
	assert.NoError(t, err)

	// Verify body logging
	assert.Equal(t, requestBody, logData["request_body"])
	assert.Contains(t, logData["response_body"], "success")
	assert.Contains(t, logData["response_body"], "value")
}

func TestLoggingMiddleware_HeaderLogging(t *testing.T) {
	// Setup
	router, logOutput, logger := setupLoggingTest()

	// Create logging middleware with header logging
	loggingMiddleware := NewLoggingMiddleware(
		logger,
		WithHeaderLogging(true),
	)

	// Add middleware and test route
	router.Use(loggingMiddleware.Logger())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Test-Header", "test-value")
	req.Header.Set("Authorization", "Bearer token")
	resp := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(resp, req)

	// Check log output
	logData := make(map[string]interface{})
	err := json.Unmarshal(logOutput.Bytes(), &logData)
	assert.NoError(t, err)

	// Verify header logging
	headers, ok := logData["request_headers"].(map[string]interface{})
	assert.True(t, ok)

	// Check custom header
	testHeader, ok := headers["X-Test-Header"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, "test-value", testHeader[0])

	// Check that sensitive headers are redacted
	authHeader, ok := headers["Authorization"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, "[REDACTED]", authHeader[0])
}

func TestLoggingMiddleware_ErrorLogging(t *testing.T) {
	// Setup
	router, logOutput, logger := setupLoggingTest()

	// Create logging middleware
	loggingMiddleware := NewLoggingMiddleware(logger)

	// Add middleware and test route
	router.Use(loggingMiddleware.Logger())
	router.GET("/error", func(c *gin.Context) {
		c.AbortWithStatus(http.StatusInternalServerError)
	})

	// Create test request
	req := httptest.NewRequest("GET", "/error", nil)
	resp := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusInternalServerError, resp.Code)

	// Check log output
	logData := make(map[string]interface{})
	err := json.Unmarshal(logOutput.Bytes(), &logData)
	assert.NoError(t, err)

	// Verify error logging level
	assert.Equal(t, "error", logData["level"])
	assert.Equal(t, float64(http.StatusInternalServerError), logData["status"])
}

func TestLoggingMiddleware_MaxBodySize(t *testing.T) {
	// Setup
	router, logOutput, logger := setupLoggingTest()

	// Create logging middleware with small max body size
	maxSize := 10
	loggingMiddleware := NewLoggingMiddleware(
		logger,
		WithRequestBodyLogging(true),
		WithResponseBodyLogging(true),
		WithMaxBodyLogSize(maxSize),
	)

	// Add middleware and test route
	router.Use(loggingMiddleware.Logger())
	router.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "this is a response that is longer than the max body size")
	})

	// Create test request with large body
	requestBody := "this is a request body that is longer than the max body size"
	req := httptest.NewRequest("POST", "/test", strings.NewReader(requestBody))
	resp := httptest.NewRecorder()

	// Perform request
	router.ServeHTTP(resp, req)

	// Check log output
	logData := make(map[string]interface{})
	err := json.Unmarshal(logOutput.Bytes(), &logData)
	assert.NoError(t, err)

	// Verify truncated body logging
	requestBodyLogged, ok := logData["request_body"].(string)
	assert.True(t, ok)
	assert.Equal(t, requestBody[:maxSize], requestBodyLogged)

	responseBodyLogged, ok := logData["response_body"].(string)
	assert.True(t, ok)
	assert.Equal(t, "this is a ", responseBodyLogged)
}

func TestRequestIDMiddleware(t *testing.T) {
	// Setup
	router := gin.New()

	// Add middleware and test route
	router.Use(RequestIDMiddleware())
	router.GET("/test", func(c *gin.Context) {
		// Get request ID from context
		requestID, exists := c.Get("request_id")
		assert.True(t, exists)
		assert.NotEmpty(t, requestID)

		c.String(http.StatusOK, "success")
	})

	// Test case 1: No request ID in header, middleware should generate one
	t.Run("Generated Request ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		resp := httptest.NewRecorder()

		router.ServeHTTP(resp, req)

		// Check response
		assert.Equal(t, http.StatusOK, resp.Code)

		// Check request ID header in response
		requestID := resp.Header().Get("X-Request-ID")
		assert.NotEmpty(t, requestID)
	})

	// Test case 2: Request ID in header, middleware should use it
	t.Run("Provided Request ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Request-ID", "test-request-id")
		resp := httptest.NewRecorder()

		router.ServeHTTP(resp, req)

		// Check response
		assert.Equal(t, http.StatusOK, resp.Code)

		// Check request ID header in response
		requestID := resp.Header().Get("X-Request-ID")
		assert.Equal(t, "test-request-id", requestID)
	})
}
