package middleware

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// ResponseWriter is a wrapper for gin.ResponseWriter that captures the response body
type ResponseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

// Write captures the response body and writes it to the original ResponseWriter
func (w *ResponseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// WriteString captures the response body and writes it to the original ResponseWriter
func (w *ResponseWriter) WriteString(s string) (int, error) {
	w.body.WriteString(s)
	return w.ResponseWriter.WriteString(s)
}

// LoggingMiddleware logs HTTP requests and responses
type LoggingMiddleware struct {
	logger          *logrus.Logger // Correct type
	logRequestBody  bool
	logResponseBody bool
	logHeaders      bool
	maxBodyLogSize  int
}

// NewLoggingMiddleware creates a new logging middleware
func NewLoggingMiddleware(logger *logrus.Logger, opts ...LoggingOption) *LoggingMiddleware {
	m := &LoggingMiddleware{
		logger:          logger,
		logRequestBody:  false,
		logResponseBody: false,
		logHeaders:      true,
		maxBodyLogSize:  1024, // Default to 1KB max for body logging
	}

	// Apply options
	for _, opt := range opts {
		opt(m)
	}

	return m
}

// LoggingOption configures the logging middleware
type LoggingOption func(*LoggingMiddleware)

// WithRequestBodyLogging enables logging of request bodies
func WithRequestBodyLogging(enabled bool) LoggingOption {
	return func(m *LoggingMiddleware) {
		m.logRequestBody = enabled
	}
}

// WithResponseBodyLogging enables logging of response bodies
func WithResponseBodyLogging(enabled bool) LoggingOption {
	return func(m *LoggingMiddleware) {
		m.logResponseBody = enabled
	}
}

// WithHeaderLogging enables logging of request headers
func WithHeaderLogging(enabled bool) LoggingOption {
	return func(m *LoggingMiddleware) {
		m.logHeaders = enabled
	}
}

// WithMaxBodyLogSize sets the maximum size of request/response bodies to log
func WithMaxBodyLogSize(sizeBytes int) LoggingOption {
	return func(m *LoggingMiddleware) {
		m.maxBodyLogSize = sizeBytes
	}
}

// Logger returns a gin middleware function for logging requests
func (m *LoggingMiddleware) Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Read request body if configured
		var requestBody []byte
		if m.logRequestBody && c.Request.Body != nil {
			// Read body
			var bodyBytes []byte
			bodyBytes, _ = io.ReadAll(c.Request.Body)

			// Limit size if needed
			if len(bodyBytes) > m.maxBodyLogSize {
				requestBody = bodyBytes[:m.maxBodyLogSize]
			} else {
				requestBody = bodyBytes
			}

			// Replace request body so it can be read again
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Collect headers if configured
		var requestHeaders map[string][]string
		if m.logHeaders {
			requestHeaders = make(map[string][]string)
			for k, v := range c.Request.Header {
				// Skip sensitive headers
				if k != "Authorization" && k != "Cookie" {
					requestHeaders[k] = v
				} else {
					requestHeaders[k] = []string{"[REDACTED]"}
				}
			}
		}

		// Create custom response writer if we need to capture the response body
		var responseBodyBuffer *bytes.Buffer
		if m.logResponseBody {
			responseBodyBuffer = &bytes.Buffer{}
			blw := &ResponseWriter{
				ResponseWriter: c.Writer,
				body:           responseBodyBuffer,
			}
			c.Writer = blw
		}

		// Process request
		c.Next()

		// Get response details
		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

		// Create full path with query parameters
		fullPath := path
		if raw != "" {
			fullPath = path + "?" + raw
		}

		// Determine log level based on status code
		logLevel := logrus.InfoLevel
		if statusCode >= 400 && statusCode < 500 {
			logLevel = logrus.WarnLevel
		} else if statusCode >= 500 {
			logLevel = logrus.ErrorLevel
		}

		// Prepare log fields
		fields := logrus.Fields{
			"status":     statusCode,
			"latency":    latency.String(),
			"client_ip":  clientIP,
			"method":     method,
			"path":       fullPath,
			"request_id": c.GetString("request_id"),
			"user_agent": c.Request.UserAgent(),
			"referer":    c.Request.Referer(),
			"handler":    c.HandlerName(),
		}

		// Add request body if available
		if m.logRequestBody && len(requestBody) > 0 {
			fields["request_body"] = string(requestBody)
		}

		// Add request headers if available
		if m.logHeaders && len(requestHeaders) > 0 {
			fields["request_headers"] = requestHeaders
		}

		// Add response body if available
		if m.logResponseBody && responseBodyBuffer != nil {
			responseBody := responseBodyBuffer.Bytes()
			if len(responseBody) > m.maxBodyLogSize {
				fields["response_body"] = string(responseBody[:m.maxBodyLogSize])
			} else {
				fields["response_body"] = string(responseBody)
			}
		}

		// Add errors if any
		if errorMessage != "" {
			fields["error"] = errorMessage
		}

		// Log with appropriate level
		logEntry := m.logger.WithFields(fields)

		switch logLevel {
		case logrus.InfoLevel:
			logEntry.Info("Request processed")
		case logrus.WarnLevel:
			logEntry.Warn("Request processed with warning")
		case logrus.ErrorLevel:
			logEntry.Error("Request processed with error")
		}
	}
}

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get request ID from header or generate a new one
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("%d", time.Now().UnixNano())
		}

		// Set request ID in context and header
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}
