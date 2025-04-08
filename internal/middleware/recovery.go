package middleware

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// RecoveryMiddleware represents the panic recovery middleware
type RecoveryMiddleware struct {
	logger *logrus.Logger
}

// NewRecoveryMiddleware creates a new recovery middleware
func NewRecoveryMiddleware(logger *logrus.Logger) *RecoveryMiddleware {
	return &RecoveryMiddleware{
		logger: logger,
	}
}

// Recovery returns a middleware that recovers from panics
func (m *RecoveryMiddleware) Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Check for broken connection, as it is not really an error
				var brokenPipe bool
				if ne, ok := err.(*net.OpError); ok {
					if se, ok := ne.Err.(*os.SyscallError); ok {
						if strings.Contains(strings.ToLower(se.Error()), "broken pipe") ||
							strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
							brokenPipe = true
						}
					}
				}

				// Get request details
				httpRequest, _ := httputil.DumpRequest(c.Request, false)

				// Get stack trace
				stackTrace := string(debug.Stack())

				// Build log fields
				fields := logrus.Fields{
					"error":      err,
					"request":    string(httpRequest),
					"stack":      stackTrace,
					"client_ip":  c.ClientIP(),
					"method":     c.Request.Method,
					"path":       c.Request.URL.Path,
					"request_id": c.GetString("request_id"),
				}

				// Log error
				m.logger.WithFields(fields).Error("[Recovery] Panic recovered")

				// If the connection is dead, we can't write a status to it
				if brokenPipe {
					c.Abort()
					return
				}

				// Create error response
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error":      "Internal Server Error",
					"timestamp":  time.Now().Format(time.RFC3339),
					"request_id": c.GetString("request_id"),
				})
			}
		}()
		c.Next()
	}
}

// RecoverDefault is a convenience function that creates a recovery middleware with default settings
func RecoverDefault() gin.HandlerFunc {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	return NewRecoveryMiddleware(logger).Recovery()
}

// SafeHandler wraps a handler function to recover from panics
func SafeHandler(handler func(c *gin.Context)) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Get request ID for correlation
				requestID := c.GetString("request_id")
				if requestID == "" {
					requestID = fmt.Sprintf("%d", time.Now().UnixNano())
				}

				// Log the panic
				logrus.WithFields(logrus.Fields{
					"error":      err,
					"stack":      string(debug.Stack()),
					"request_id": requestID,
				}).Error("[SafeHandler] Panic recovered")

				// Return error response
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error":      "Internal Server Error",
					"request_id": requestID,
					"timestamp":  time.Now().Format(time.RFC3339),
				})
			}
		}()
		handler(c)
	}
}
