package utils

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv" // Added for Atoi
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

var (
	// Common errors
	ErrInvalidRequest      = errors.New("invalid request")
	ErrRequestTimeout      = errors.New("request timeout")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrForbidden           = errors.New("forbidden")
	ErrNotFound            = errors.New("not found")
	ErrMethodNotAllowed    = errors.New("method not allowed")
	ErrTooManyRequests     = errors.New("too many requests")
	ErrInternalServerError = errors.New("internal server error")
	ErrBadGateway          = errors.New("bad gateway")
	ErrServiceUnavailable  = errors.New("service unavailable")
	ErrGatewayTimeout      = errors.New("gateway timeout")

	// Security-related errors
	ErrContentTypeNotAllowed = errors.New("content type not allowed")
	ErrInvalidContentLength  = errors.New("invalid content length")
	ErrRequestEntityTooLarge = errors.New("request entity too large")
	ErrInvalidHostHeader     = errors.New("invalid host header")
	ErrCSRFValidationFailed  = errors.New("CSRF validation failed")
	ErrIPAddressBlocked      = errors.New("IP address blocked")
	ErrRateLimitExceeded     = errors.New("rate limit exceeded")

	// Validation regexes for HTTP utilities
	safePathRegex       = regexp.MustCompile(`^[a-zA-Z0-9_./-]+$`)
	sanitizeHTMLRegex   = regexp.MustCompile(`[&<>"'/]`)
	contentTypeRegex    = regexp.MustCompile(`^[a-zA-Z0-9-]+/[a-zA-Z0-9-+.]+$`)
	headerNameRegex     = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	headerValueRegex    = regexp.MustCompile(`^[^\r\n]*$`)
	sensitiveHeadersSet = map[string]bool{
		"authorization":       true,
		"proxy-authorization": true,
		"x-api-key":           true,
		"api-key":             true,
		"password":            true,
		"token":               true,
		"access-token":        true,
		"refresh-token":       true,
		"jwt":                 true,
		"secret":              true,
		"cookie":              true,
		"set-cookie":          true,
	}

	// Default rate limiter settings
	defaultRateLimiter = NewRateLimiter(10, 30) // 10 requests per second, burst of 30
)

// RateLimiter manages rate limiting for HTTP requests
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	visitor  map[string]time.Time
	rate     rate.Limit
	burst    int
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rps int, burst int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		visitor:  make(map[string]time.Time),
		rate:     rate.Limit(rps),
		burst:    burst,
	}
}

// GetLimiter gets or creates a rate limiter for the given IP
func (rl *RateLimiter) GetLimiter(key string) *rate.Limiter {
	limiter, exists := rl.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.limiters[key] = limiter
		rl.visitor[key] = time.Now()
	}
	return limiter
}

// CleanupLimiters removes old limiters
func (rl *RateLimiter) CleanupLimiters(maxAge time.Duration) {
	for key, lastSeen := range rl.visitor {
		if time.Since(lastSeen) > maxAge {
			delete(rl.limiters, key)
			delete(rl.visitor, key)
		}
	}
}

// Response represents a standardized API response
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
	Meta    *Meta       `json:"meta,omitempty"`
}

// APIError represents an API error
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Meta contains metadata for pagination responses
type Meta struct {
	Page       int       `json:"page,omitempty"`
	PerPage    int       `json:"per_page,omitempty"`
	TotalPages int       `json:"total_pages,omitempty"`
	Total      int       `json:"total,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	RequestID  string    `json:"request_id,omitempty"`
	Version    string    `json:"version,omitempty"`
}

// HTTPResponse is a wrapper for HTTP responses
type HTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

// HTTPClientConfig contains configuration for the HTTP client
type HTTPClientConfig struct {
	Timeout               time.Duration
	KeepAlive             time.Duration
	MaxIdleConns          int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	ExpectContinueTimeout time.Duration
	ResponseHeaderTimeout time.Duration
	MaxResponseBodySize   int64
	Proxy                 func(*http.Request) (*url.URL, error)
	TLSConfig             *tls.Config
	AllowedContentTypes   []string
	DisallowedHosts       []string
}

// DefaultHTTPClientConfig returns the default HTTP client configuration
func DefaultHTTPClientConfig() HTTPClientConfig {
	return HTTPClientConfig{
		Timeout:               30 * time.Second,
		KeepAlive:             30 * time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxResponseBodySize:   10 * 1024 * 1024, // 10MB
		AllowedContentTypes:   []string{"application/json", "text/plain", "application/xml"},
	}
}

// SecureHTTPClientConfig returns a secure HTTP client configuration
func SecureHTTPClientConfig() HTTPClientConfig {
	config := DefaultHTTPClientConfig()
	config.TLSConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	return config
}

// CreateHTTPClient creates an HTTP client with the given configuration
func CreateHTTPClient(config HTTPClientConfig) *http.Client {
	transport := &http.Transport{
		Proxy: config.Proxy,
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: config.KeepAlive,
		}).DialContext,
		MaxIdleConns:          config.MaxIdleConns,
		IdleConnTimeout:       config.IdleConnTimeout,
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		ExpectContinueTimeout: config.ExpectContinueTimeout,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		TLSClientConfig:       config.TLSConfig,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}

	return client
}

// HTTPRequest sends an HTTP request with security checks
func HTTPRequest(ctx context.Context, method, urlString string, headers map[string]string, body io.Reader, config HTTPClientConfig) (*HTTPResponse, error) { // Renamed url to urlString
	// Validate URL
	if err := ValidateURL(urlString, []string{"http", "https"}, ValidationOptions{Required: true}); err != nil { // Use urlString
		return nil, fmt.Errorf("invalid URL: %w", ErrInvalidRequest)
	}

	// Parse URL to check host
	parsedURL, err := url.Parse(urlString) // Use url package, parse urlString
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	// Check if host is disallowed
	for _, disallowedHost := range config.DisallowedHosts {
		if strings.EqualFold(parsedURL.Host, disallowedHost) {
			return nil, fmt.Errorf("host is not allowed: %w", ErrForbidden)
		}
	}

	// Create client with the provided configuration
	client := CreateHTTPClient(config)

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, urlString, body) // Use urlString
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	for key, value := range headers {
		// Validate header name and value
		if !headerNameRegex.MatchString(key) {
			return nil, fmt.Errorf("invalid header name: %w", ErrInvalidRequest)
		}
		if !headerValueRegex.MatchString(value) {
			return nil, fmt.Errorf("invalid header value: %w", ErrInvalidRequest)
		}
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check content type if specified
	if len(config.AllowedContentTypes) > 0 {
		contentType := resp.Header.Get("Content-Type")
		isAllowed := false
		for _, allowedType := range config.AllowedContentTypes {
			if strings.HasPrefix(contentType, allowedType) {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return nil, fmt.Errorf("content type %s not allowed: %w", contentType, ErrContentTypeNotAllowed)
		}
	}

	// Limit response body size
	var bodyReader io.Reader = resp.Body
	if config.MaxResponseBodySize > 0 {
		bodyReader = io.LimitReader(resp.Body, config.MaxResponseBodySize)
	}

	// Read response body
	respBody, err := io.ReadAll(bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Copy headers
	respHeaders := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			respHeaders[key] = values[0]
		}
	}

	// Return response
	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       respBody,
	}, nil
}

// ErrorResponse returns a standardized error response
func ErrorResponse(c *gin.Context, statusCode int, code, message, details string) {
	logEntry := logrus.WithFields(logrus.Fields{
		"status_code": statusCode,
		"error_code":  code,
		"message":     message,
		"client_ip":   GetClientIP(c),
		"path":        c.Request.URL.Path,
		"method":      c.Request.Method,
		"request_id":  c.GetString("request_id"),
	})

	if details != "" {
		logEntry = logEntry.WithField("details", details)
	}

	// Don't log 4xx errors as errors, they're client errors
	if statusCode >= 500 {
		logEntry.Error("API error response")
	} else {
		logEntry.Info("API client error response")
	}

	c.JSON(statusCode, Response{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
			Details: details,
		},
		Meta: &Meta{
			Timestamp: time.Now(),
			RequestID: c.GetString("request_id"),
		},
	})
}

// SuccessResponse returns a standardized success response
func SuccessResponse(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    data,
		Meta: &Meta{
			Timestamp: time.Now(),
			RequestID: c.GetString("request_id"),
		},
	})
}

// PaginatedResponse returns a standardized paginated response
func PaginatedResponse(c *gin.Context, data interface{}, page, perPage, total int) {
	// Calculate total pages
	totalPages := 0
	if perPage > 0 {
		totalPages = (total + perPage - 1) / perPage
	}

	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    data,
		Meta: &Meta{
			Page:       page,
			PerPage:    perPage,
			TotalPages: totalPages,
			Total:      total,
			Timestamp:  time.Now(),
			RequestID:  c.GetString("request_id"),
		},
	})
}

// NoContentResponse returns a 204 No Content response
func NoContentResponse(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// FileResponse sends a file as response
func FileResponse(c *gin.Context, data []byte, filename, contentType string) {
	// Security check for filename
	if !ValidatePathHTTP(filename) {
		ErrorResponse(c, http.StatusBadRequest, "INVALID_FILENAME", "Invalid filename", "")
		return
	}

	// Set headers
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Data(http.StatusOK, contentType, data)
}

// CSVResponse sends a CSV file as response
func CSVResponse(c *gin.Context, data []byte, filename string) {
	FileResponse(c, data, filename, "text/csv")
}

// JSONResponse sends a JSON file as response
func JSONResponse(c *gin.Context, data []byte, filename string) {
	FileResponse(c, data, filename, "application/json")
}

// XMLResponse sends an XML file as response
func XMLResponse(c *gin.Context, data []byte, filename string) {
	FileResponse(c, data, filename, "application/xml")
}

// BadRequest returns a 400 Bad Request response
func BadRequest(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusBadRequest, "BAD_REQUEST", message, "")
}

// Unauthorized returns a 401 Unauthorized response
func Unauthorized(c *gin.Context, message string) {
	if message == "" {
		message = "Authentication is required to access this resource"
	}
	ErrorResponse(c, http.StatusUnauthorized, "UNAUTHORIZED", message, "")
}

// Forbidden returns a 403 Forbidden response
func Forbidden(c *gin.Context, message string) {
	if message == "" {
		message = "You do not have permission to access this resource"
	}
	ErrorResponse(c, http.StatusForbidden, "FORBIDDEN", message, "")
}

// NotFound returns a 404 Not Found response
func NotFound(c *gin.Context, message string) {
	if message == "" {
		message = "The requested resource was not found"
	}
	ErrorResponse(c, http.StatusNotFound, "NOT_FOUND", message, "")
}

// MethodNotAllowed returns a 405 Method Not Allowed response
func MethodNotAllowed(c *gin.Context, message string) {
	if message == "" {
		message = "The method is not allowed for this resource"
	}
	ErrorResponse(c, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", message, "")
}

// Conflict returns a 409 Conflict response
func Conflict(c *gin.Context, message string) {
	if message == "" {
		message = "The request could not be completed due to a conflict"
	}
	ErrorResponse(c, http.StatusConflict, "CONFLICT", message, "")
}

// UnprocessableEntity returns a 422 Unprocessable Entity response
func UnprocessableEntity(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusUnprocessableEntity, "UNPROCESSABLE_ENTITY", message, "")
}

// TooManyRequests returns a 429 Too Many Requests response
func TooManyRequests(c *gin.Context, message string) {
	if message == "" {
		message = "Too many requests, please try again later"
	}
	ErrorResponse(c, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", message, "")
}

// InternalServerError returns a 500 Internal Server Error response
func InternalServerError(c *gin.Context, message string) {
	if message == "" {
		message = "An internal server error occurred"
	}
	ErrorResponse(c, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", message, "")
}

// ServiceUnavailable returns a 503 Service Unavailable response
func ServiceUnavailable(c *gin.Context, message string) {
	if message == "" {
		message = "The service is currently unavailable"
	}
	ErrorResponse(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", message, "")
}

// StatusAccepted returns a 202 Accepted response
func StatusAccepted(c *gin.Context, message string) {
	c.JSON(http.StatusAccepted, Response{
		Success: true,
		Data:    gin.H{"message": message}, // Include message in data
		Meta: &Meta{
			Timestamp: time.Now(),
			RequestID: c.GetString("request_id"),
		},
	})
}

// BindJSON binds the request body to the given struct with error handling
func BindJSON(c *gin.Context, obj interface{}) bool {
	// Limit the request body size
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024*1024) // 1MB

	if err := c.ShouldBindJSON(obj); err != nil {
		BadRequest(c, "Invalid JSON format: "+err.Error())
		return false
	}
	return true
}

// BindQuery binds the query parameters to the given struct with error handling
func BindQuery(c *gin.Context, obj interface{}) bool {
	if err := c.ShouldBindQuery(obj); err != nil {
		BadRequest(c, "Invalid query parameters: "+err.Error())
		return false
	}
	return true
}

// BindForm binds the form data to the given struct with error handling
func BindForm(c *gin.Context, obj interface{}) bool {
	if err := c.ShouldBind(obj); err != nil {
		BadRequest(c, "Invalid form data: "+err.Error())
		return false
	}
	return true
}

// BindURI binds the URI parameters to the given struct with error handling
func BindURI(c *gin.Context, obj interface{}) bool {
	if err := c.ShouldBindUri(obj); err != nil {
		BadRequest(c, "Invalid URI parameters: "+err.Error())
		return false
	}
	return true
}

// BindHeader binds the header values to the given struct with error handling
func BindHeader(c *gin.Context, obj interface{}) bool {
	if err := c.ShouldBindHeader(obj); err != nil {
		BadRequest(c, "Invalid header values: "+err.Error())
		return false
	}
	return true
}

// GetClientIP returns the client IP address
func GetClientIP(c *gin.Context) string {
	// Get client IP based on trusted headers
	clientIP := c.ClientIP()

	// If client IP is empty or localhost, try to get it from the request
	if clientIP == "" || clientIP == "::1" || clientIP == "127.0.0.1" {
		if ip, _, err := net.SplitHostPort(c.Request.RemoteAddr); err == nil {
			clientIP = ip
		}
	}

	return clientIP
}

// IsValidContentType checks if the content type is valid
func IsValidContentType(contentType string, allowedTypes []string) bool {
	if len(allowedTypes) == 0 {
		return true
	}

	for _, t := range allowedTypes {
		if strings.HasPrefix(contentType, t) {
			return true
		}
	}
	return false
}

// ValidateRequestHeaders checks if the request headers are valid
func ValidateRequestHeaders(c *gin.Context, config map[string]string) bool {
	for key, expectedValue := range config {
		value := c.GetHeader(key)
		if value == "" {
			BadRequest(c, fmt.Sprintf("Missing required header: %s", key))
			return false
		}
		if expectedValue != "" && value != expectedValue {
			BadRequest(c, fmt.Sprintf("Invalid value for header %s", key))
			return false
		}
	}
	return true
}

// SanitizeHeaders returns a map of headers with sensitive information masked
func SanitizeHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string)
	for key, value := range headers {
		if isSensitiveHeader(key) {
			result[key] = "********"
		} else {
			result[key] = value
		}
	}
	return result
}

// isSensitiveHeader checks if a header is sensitive
func isSensitiveHeader(header string) bool {
	header = strings.ToLower(header)
	_, ok := sensitiveHeadersSet[header]
	if ok {
		return true
	}

	// Check prefixes
	return strings.HasPrefix(header, "x-auth-") ||
		strings.HasPrefix(header, "auth-") ||
		strings.HasPrefix(header, "x-token-") ||
		strings.Contains(header, "secret") ||
		strings.Contains(header, "password") ||
		strings.Contains(header, "token") ||
		strings.Contains(header, "credential")
}

// ValidateCSRFToken validates a CSRF token
func ValidateCSRFToken(c *gin.Context, token string) bool {
	csrfToken := c.GetHeader("X-CSRF-Token")
	if csrfToken == "" {
		csrfToken = c.Request.FormValue("csrf_token")
	}

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(csrfToken), []byte(token)) == 1
}

// SecureHeaders adds security headers to the response
func SecureHeaders(c *gin.Context) {
	// Content Security Policy (CSP)
	c.Header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'")

	// X-Content-Type-Options prevents MIME type sniffing
	c.Header("X-Content-Type-Options", "nosniff")

	// X-Frame-Options prevents clickjacking
	c.Header("X-Frame-Options", "DENY")

	// X-XSS-Protection enables the XSS filter in browsers
	c.Header("X-XSS-Protection", "1; mode=block")

	// Strict-Transport-Security enforces HTTPS
	c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

	// Referrer-Policy controls how much referrer information is included with requests
	c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

	// Feature-Policy restricts which browser features can be used
	c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
}

// RateLimitMiddleware creates a middleware that limits request rates
func RateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := GetClientIP(c)

		if limiter.GetLimiter(key).Allow() == false {
			TooManyRequests(c, "Rate limit exceeded")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequestIDMiddleware creates a middleware that adds a request ID
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = GenerateRequestID()
		}

		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}

// LoggingMiddleware creates a middleware that logs requests
func LoggingMiddleware(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()
		clientIP := GetClientIP(c)
		method := c.Request.Method

		if query != "" {
			path = path + "?" + query
		}

		fields := logrus.Fields{
			"status_code":  statusCode,
			"latency":      latency,
			"client_ip":    clientIP,
			"method":       method,
			"path":         path,
			"request_id":   c.GetString("request_id"),
			"user_agent":   c.Request.UserAgent(),
			"body_size":    c.Writer.Size(),
			"content_type": c.Writer.Header().Get("Content-Type"),
		}

		if statusCode >= 500 {
			logger.WithFields(fields).Error("API request failed")
		} else if statusCode >= 400 {
			logger.WithFields(fields).Warn("API request had client error")
		} else {
			logger.WithFields(fields).Info("API request completed")
		}
	}
}

// RecoveryMiddleware creates a middleware that recovers from panics
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Log the error
				logrus.WithFields(logrus.Fields{
					"error":      err,
					"client_ip":  GetClientIP(c),
					"path":       c.Request.URL.Path,
					"method":     c.Request.Method,
					"request_id": c.GetString("request_id"),
				}).Error("Panic recovered in API request")

				// Return error response
				InternalServerError(c, "An unexpected error occurred")
				c.Abort()
			}
		}()

		c.Next()
	}
}

// TimeoutMiddleware creates a middleware that adds a timeout to requests
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		// Update the request context
		c.Request = c.Request.WithContext(ctx)

		// Create a channel to signal when the request is done
		done := make(chan struct{})

		// Process the request in a goroutine
		go func() {
			c.Next()
			close(done)
		}()

		// Wait for the request to complete or timeout
		select {
		case <-done:
			// Request completed normally
			return
		case <-ctx.Done():
			// Request timed out
			if ctx.Err() == context.DeadlineExceeded {
				InternalServerError(c, "Request timed out")
				c.Abort()
			}
		}
	}
}

// CORSMiddleware creates a middleware that adds CORS headers
func CORSMiddleware(allowOrigins []string, allowMethods []string, allowHeaders []string, maxAge int) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Check if the origin is allowed
		allowOrigin := "*"
		if len(allowOrigins) > 0 {
			allowed := false
			for _, allowedOrigin := range allowOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					allowOrigin = origin // Use the actual origin instead of "*"
					break
				}
			}

			if !allowed {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}

		// Set CORS headers
		c.Header("Access-Control-Allow-Origin", allowOrigin)
		c.Header("Access-Control-Allow-Credentials", "true")

		if len(allowMethods) > 0 {
			c.Header("Access-Control-Allow-Methods", strings.Join(allowMethods, ", "))
		} else {
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		}

		if len(allowHeaders) > 0 {
			c.Header("Access-Control-Allow-Headers", strings.Join(allowHeaders, ", "))
		} else {
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		}

		if maxAge > 0 {
			c.Header("Access-Control-Max-Age", fmt.Sprintf("%d", maxAge))
		} else {
			c.Header("Access-Control-Max-Age", "86400") // 24 hours
		}

		// Handle preflight OPTIONS requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// ValidatePath validates a file path for security in HTTP context
func ValidatePathHTTP(path string) bool {
	return safePathRegex.MatchString(path) && !strings.Contains(path, "..")
}

// SanitizeHTML sanitizes HTML content
func SanitizeHTML(input string) string {
	return sanitizeHTMLRegex.ReplaceAllStringFunc(input, func(s string) string {
		switch s {
		case "&":
			return "&amp;"
		case "<":
			return "&lt;"
		case ">":
			return "&gt;"
		case "\"":
			return "&quot;"
		case "'":
			return "&#39;"
		case "/":
			return "&#x2F;"
		default:
			return s
		}
	})
}

// GenerateRequestID generates a unique request ID
func GenerateRequestID() string {
	// Generate a UUID v4
	uuid, err := uuid.NewRandom()
	if err != nil {
		// Fallback to timestamp-based ID if UUID generation fails
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return uuid.String()
}

// GetPaginationParams extracts page and page_size from query parameters with defaults and limits.
func GetPaginationParams(c *gin.Context) (page int, pageSize int) {
	const defaultPage = 1
	const defaultPageSize = 10
	const maxPageSize = 100

	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "10")

	var err error
	page, err = strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = defaultPage
	}

	pageSize, err = strconv.Atoi(pageSizeStr)
	if err != nil || pageSize <= 0 {
		pageSize = defaultPageSize
	}

	// Apply a maximum page size limit
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	return page, pageSize
}

// GetRequestID retrieves the request ID from the context
func GetRequestID(c *gin.Context) string {
	if reqID, exists := c.Get("request_id"); exists {
		if idStr, ok := reqID.(string); ok {
			return idStr
		}
	}
	// Fallback if not found (should ideally always be set by middleware)
	return GenerateRequestID()
}

// ToJSON converts an object to JSON bytes
func ToJSON(obj interface{}) ([]byte, error) {
	return json.Marshal(obj)
}

// FromJSON converts JSON bytes to an object
func FromJSON(data []byte, obj interface{}) error {
	return json.Unmarshal(data, obj)
}

// PaginateResults paginates a slice of results
func PaginateResults(results interface{}, page, perPage int) (interface{}, int, int, error) {
	v := reflect.ValueOf(results)

	if v.Kind() != reflect.Slice {
		return nil, 0, 0, fmt.Errorf("results must be a slice")
	}

	total := v.Len()

	if perPage <= 0 {
		perPage = 10 // Default per page
	}

	if page <= 0 {
		page = 1 // Default page
	}

	start := (page - 1) * perPage
	end := start + perPage

	if start >= total {
		// Return empty slice of the same type
		return reflect.MakeSlice(v.Type(), 0, 0).Interface(), page, total, nil
	}

	if end > total {
		end = total
	}

	// Create a slice with the paginated results
	return v.Slice(start, end).Interface(), page, total, nil
}

// StructToMap converts a struct to a map using JSON tags
func StructToMap(obj interface{}) (map[string]interface{}, error) {
	// Convert to JSON
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	// Convert JSON to map
	var result map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// MapToStruct converts a map to a struct using JSON tags
func MapToStruct(m map[string]interface{}, obj interface{}) error {
	// Convert map to JSON
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return err
	}

	// Convert JSON to struct
	return json.Unmarshal(jsonBytes, obj)
}

// FormatError formats an error for API responses
func FormatError(err error) APIError {
	code := "INTERNAL_ERROR"
	message := "An internal error occurred"
	details := ""

	// Handle errors by type
	if errors.Is(err, ErrInvalidRequest) {
		code = "INVALID_REQUEST"
		message = "Invalid request"
	} else if errors.Is(err, ErrRequestTimeout) {
		code = "REQUEST_TIMEOUT"
		message = "Request timed out"
	} else if errors.Is(err, ErrUnauthorized) {
		code = "UNAUTHORIZED"
		message = "Authentication required"
	} else if errors.Is(err, ErrForbidden) {
		code = "FORBIDDEN"
		message = "Permission denied"
	} else if errors.Is(err, ErrNotFound) {
		code = "NOT_FOUND"
		message = "Resource not found"
	} else if errors.Is(err, ErrMethodNotAllowed) {
		code = "METHOD_NOT_ALLOWED"
		message = "Method not allowed"
	} else if errors.Is(err, ErrTooManyRequests) {
		code = "RATE_LIMIT_EXCEEDED"
		message = "Rate limit exceeded"
	} else if errors.Is(err, ErrInternalServerError) {
		code = "INTERNAL_SERVER_ERROR"
		message = "Internal server error"
	} else if errors.Is(err, ErrBadGateway) {
		code = "BAD_GATEWAY"
		message = "Bad gateway"
	} else if errors.Is(err, ErrServiceUnavailable) {
		code = "SERVICE_UNAVAILABLE"
		message = "Service unavailable"
	} else if errors.Is(err, ErrGatewayTimeout) {
		code = "GATEWAY_TIMEOUT"
		message = "Gateway timeout"
	}

	// Get error details
	if err != nil {
		details = err.Error()
	}

	return APIError{
		Code:    code,
		Message: message,
		Details: details,
	}
}
