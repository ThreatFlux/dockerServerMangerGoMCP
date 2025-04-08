// Package lifecycle implements Docker container lifecycle operations.
package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	dockertypes "github.com/docker/docker/api/types" // Use alias again
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	imagetypes "github.com/docker/docker/api/types/image" // Use imagetypes alias
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/security" // Added security import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"          // Added models import
)

// Common standardized errors for container operations.
var (
	// ErrContainerNotFound is returned when a container does not exist.
	ErrContainerNotFound = errors.New("container not found")

	// ErrContainerAlreadyExists is returned when attempting to create a container with an existing name.
	ErrContainerAlreadyExists = errors.New("container already exists")

	// ErrNoSuchImage is returned when a referenced image does not exist.
	ErrNoSuchImage = errors.New("no such image")

	// ErrInvalidConfig is returned when a container configuration is invalid.
	ErrInvalidConfig = errors.New("invalid container configuration")

	// ErrOperationFailed is returned when a container operation fails.
	ErrOperationFailed = errors.New("container operation failed")

	// ErrInvalidContainerID is returned when a container ID is invalid.
	ErrInvalidContainerID = errors.New("invalid container ID")

	// ErrInvalidContainerName is returned when a container name is invalid.
	ErrInvalidContainerName = errors.New("invalid container name")

	// ErrContextCanceled is returned when an operation is canceled via context.
	ErrContextCanceled = errors.New("operation was canceled")

	// ErrTimeout is returned when an operation times out.
	ErrTimeout = errors.New("operation timed out")

	// ErrImagePullFailed is returned when an image pull operation fails.
	ErrImagePullFailed = errors.New("failed to pull image")

	// ErrSecurityViolation is returned when a container configuration violates security policies.
	ErrSecurityViolation = errors.New("security policy violation")

	// ErrInsufficientPermissions is returned when the user has insufficient permissions.
	ErrInsufficientPermissions = errors.New("insufficient permissions for operation")

	// ErrNetworkConnectFailed is returned when a container cannot be connected to a network.
	ErrNetworkConnectFailed = errors.New("failed to connect container to network")

	// ErrResourceLimitExceeded is returned when a resource limit is exceeded.
	ErrResourceLimitExceeded = errors.New("resource limit exceeded")

	// ErrInvalidInput is returned when the input parameters are invalid.
	ErrInvalidInput = errors.New("invalid input parameters")

	// ErrContainerStartFailed is returned when a container fails to start.
	ErrContainerStartFailed = errors.New("container failed to start")

	// ErrContainerStopFailed is returned when a container fails to stop.
	ErrContainerStopFailed = errors.New("container failed to stop")

	// ErrContainerRemoveFailed is returned when a container cannot be removed.
	ErrContainerRemoveFailed = errors.New("container removal failed")

	// ErrExecCreateFailed is returned when an exec instance cannot be created.
	ErrExecCreateFailed = errors.New("exec creation failed")

	// ErrExecStartFailed is returned when an exec instance fails to start.
	ErrExecStartFailed = errors.New("exec start failed")
)

// ContainerOperation represents a container lifecycle operation
type ContainerOperation string // Added back type definition

const (
	// ContainerOperationCreate represents container creation
	ContainerOperationCreate ContainerOperation = "create"

	// ContainerOperationStart represents container start
	ContainerOperationStart ContainerOperation = "start"

	// ContainerOperationStop represents container stop
	ContainerOperationStop ContainerOperation = "stop"

	// ContainerOperationRestart represents container restart
	ContainerOperationRestart ContainerOperation = "restart"

	// ContainerOperationRemove represents container removal
	ContainerOperationRemove ContainerOperation = "remove"

	// ContainerOperationKill represents container kill
	ContainerOperationKill ContainerOperation = "kill"

	// ContainerOperationPause represents container pause
	ContainerOperationPause ContainerOperation = "pause"

	// ContainerOperationUnpause represents container unpause
	ContainerOperationUnpause ContainerOperation = "unpause"

	// ContainerOperationInspect represents container inspection
	ContainerOperationInspect ContainerOperation = "inspect"

	// ContainerOperationExec represents command execution in a container
	ContainerOperationExec ContainerOperation = "exec"

	// ContainerOperationLogs represents retrieving container logs
	ContainerOperationLogs ContainerOperation = "logs"

	// ContainerOperationStats represents retrieving container stats
	ContainerOperationStats ContainerOperation = "stats"

	// ContainerOperationList represents listing containers
	ContainerOperationList ContainerOperation = "list"

	// ContainerOperationCopyTo represents copying files to a container
	ContainerOperationCopyTo ContainerOperation = "copy_to"

	// ContainerOperationCopyFrom represents copying files from a container
	ContainerOperationCopyFrom ContainerOperation = "copy_from"

	// ContainerOperationExport represents exporting a container
	ContainerOperationExport ContainerOperation = "export"

	// ContainerOperationRename represents renaming a container
	ContainerOperationRename ContainerOperation = "rename"

	// ContainerOperationUpdate represents updating a container
	ContainerOperationUpdate ContainerOperation = "update"

	// ContainerOperationPrune represents pruning containers
	ContainerOperationPrune ContainerOperation = "prune"
)

// OperationOptions represents options for container operations
type OperationOptions struct {
	// Timeout for the operation
	Timeout time.Duration

	// Context to use for the operation
	Context context.Context

	// Logger for operation logging
	Logger *logrus.Logger

	// SecurityOptions for container security
	SecurityManager *security.DefaultsManager // Changed type

	// RetryOptions for operation retries
	RetryOptions RetryOptions

	// SkipImagePull skips pulling the image if set to true
	SkipImagePull bool

	// Force forces the operation even if it would otherwise fail
	Force bool

	// DryRun performs a dry run without actually executing the operation
	DryRun bool

	// RequestID is a unique identifier for the request
	RequestID string

	// User is the user performing the operation
	User string

	// MaskSensitiveData determines whether sensitive data should be masked in logs
	MaskSensitiveData bool

	// ValidationLevel determines how strictly to validate inputs
	ValidationLevel ValidationLevel

	// DetailLevel determines the level of detail to return for operations
	DetailLevel DetailLevel
}

// ValidationLevel represents the level of input validation to perform
type ValidationLevel int

const (
	// ValidationLevelNone performs no validation
	ValidationLevelNone ValidationLevel = iota

	// ValidationLevelBasic performs basic validation
	ValidationLevelBasic

	// ValidationLevelStrict performs strict validation
	ValidationLevelStrict

	// ValidationLevelParanoid performs paranoid validation
	ValidationLevelParanoid
)

// DetailLevel represents the level of detail to return for operations
type DetailLevel int

const (
	// DetailLevelMinimal returns minimal details
	DetailLevelMinimal DetailLevel = iota

	// DetailLevelStandard returns standard details
	DetailLevelStandard

	// DetailLevelFull returns full details
	DetailLevelFull

	// DetailLevelDebug returns debug-level details
	DetailLevelDebug
)

// RetryOptions represents options for operation retries
type RetryOptions struct {
	// MaxRetries is the maximum number of retries
	MaxRetries int

	// RetryDelay is the delay between retries
	RetryDelay time.Duration

	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration

	// Jitter adds randomness to the retry delay
	Jitter float64

	// RetryableErrors specifies which error types should trigger a retry
	RetryableErrors []error

	// RetryStatusCodes specifies which HTTP status codes should trigger a retry
	RetryStatusCodes []int

	// BackoffFactor is the factor by which to increase delay between retries
	BackoffFactor float64
}

// DefaultRetryOptions returns default retry options
func DefaultRetryOptions() RetryOptions {
	return RetryOptions{
		MaxRetries:    3,
		RetryDelay:    1 * time.Second,
		MaxDelay:      10 * time.Second,
		Jitter:        0.1,
		BackoffFactor: 2.0,
		RetryableErrors: []error{
			ErrTimeout,
			ErrImagePullFailed,
		},
		RetryStatusCodes: []int{
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout,
			http.StatusTooManyRequests,
		},
	}
}

// DefaultOperationOptions returns default operation options
func DefaultOperationOptions() OperationOptions {
	return OperationOptions{
		Timeout: 30 * time.Second,
		Logger:  logrus.New(),
		// SecurityManager:   nil, // TODO: Initialize with a default manager if possible/needed
		RetryOptions:      DefaultRetryOptions(),
		SkipImagePull:     false,
		Force:             false,
		DryRun:            false,
		MaskSensitiveData: true,
		ValidationLevel:   ValidationLevelStrict,
		DetailLevel:       DetailLevelStandard,
	}
}

// ContainerManager manages container lifecycle operations
type ContainerManager struct {
	client  client.APIClient
	options OperationOptions
	logger  *logrus.Logger
	mu      sync.RWMutex
}

// NewContainerManager creates a new container manager
func NewContainerManager(client client.APIClient, options ...OperationOptions) *ContainerManager {
	opts := DefaultOperationOptions()
	if len(options) > 0 {
		opts = options[0]
	}

	if opts.Logger == nil {
		opts.Logger = logrus.New()
	}

	if opts.Context == nil {
		opts.Context = context.Background()
	}

	return &ContainerManager{
		client:  client,
		options: opts,
		logger:  opts.Logger,
	}
}

// NewDefaultContainerManager creates a new container manager with default options
func NewDefaultContainerManager() (*ContainerManager, error) {
	client, err := docker.GetDefaultClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	return NewContainerManager(client), nil
}

// WithContext returns a new container manager with the given context
func (m *ContainerManager) WithContext(ctx context.Context) *ContainerManager {
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.Context = ctx
	return NewContainerManager(m.client, opts)
}

// WithTimeout returns a new container manager with the given timeout
func (m *ContainerManager) WithTimeout(timeout time.Duration) *ContainerManager {
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.Timeout = timeout
	return NewContainerManager(m.client, opts)
}

// WithLogger returns a new container manager with the given logger
func (m *ContainerManager) WithLogger(logger *logrus.Logger) *ContainerManager {
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.Logger = logger
	return NewContainerManager(m.client, opts)
}

// WithSecurityOptions returns a new container manager with the given security options
func (m *ContainerManager) WithSecurityManager(secMgr *security.DefaultsManager) *ContainerManager { // Changed method name and type
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.SecurityManager = secMgr // Changed field name
	return NewContainerManager(m.client, opts)
}

// WithRetryOptions returns a new container manager with the given retry options
func (m *ContainerManager) WithRetryOptions(retryOpts RetryOptions) *ContainerManager {
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.RetryOptions = retryOpts
	return NewContainerManager(m.client, opts)
}

// WithSkipImagePull returns a new container manager with SkipImagePull set
func (m *ContainerManager) WithSkipImagePull(skip bool) *ContainerManager {
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.SkipImagePull = skip
	return NewContainerManager(m.client, opts)
}

// WithForce returns a new container manager with Force set
func (m *ContainerManager) WithForce(force bool) *ContainerManager {
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.Force = force
	return NewContainerManager(m.client, opts)
}

// WithDryRun returns a new container manager with DryRun set
func (m *ContainerManager) WithDryRun(dryRun bool) *ContainerManager {
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.DryRun = dryRun
	return NewContainerManager(m.client, opts)
}

// WithRequestID returns a new container manager with RequestID set
func (m *ContainerManager) WithRequestID(requestID string) *ContainerManager {
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.RequestID = requestID
	return NewContainerManager(m.client, opts)
}

// WithUser returns a new container manager with User set
func (m *ContainerManager) WithUser(user string) *ContainerManager {
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.User = user
	return NewContainerManager(m.client, opts)
}

// WithValidationLevel returns a new container manager with ValidationLevel set
func (m *ContainerManager) WithValidationLevel(level ValidationLevel) *ContainerManager {
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.ValidationLevel = level
	return NewContainerManager(m.client, opts)
}

// WithDetailLevel returns a new container manager with DetailLevel set
func (m *ContainerManager) WithDetailLevel(level DetailLevel) *ContainerManager {
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.DetailLevel = level
	return NewContainerManager(m.client, opts)
}

// WithMaskSensitiveData returns a new container manager with MaskSensitiveData set
func (m *ContainerManager) WithMaskSensitiveData(mask bool) *ContainerManager {
	m.mu.RLock()
	opts := m.options
	m.mu.RUnlock()

	opts.MaskSensitiveData = mask
	return NewContainerManager(m.client, opts)
}

// GetClient returns the Docker client
func (m *ContainerManager) GetClient() client.APIClient {
	return m.client
}

// GetContext returns the context for operations
func (m *ContainerManager) GetContext() context.Context {
	m.mu.RLock()
	ctx := m.options.Context
	m.mu.RUnlock()

	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// GetContextWithTimeout returns a context with timeout
func (m *ContainerManager) GetContextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx := m.GetContext()
	if timeout <= 0 {
		m.mu.RLock()
		timeout = m.options.Timeout
		m.mu.RUnlock()
	}
	return context.WithTimeout(ctx, timeout)
}

// MergeContexts merges a parent context with a timeout context to ensure that both
// the parent context's cancellation and the timeout are respected
func (m *ContainerManager) MergeContexts(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}

	if timeout <= 0 {
		m.mu.RLock()
		timeout = m.options.Timeout
		m.mu.RUnlock()
	}

	// Create a context that respects the timeout
	timeoutCtx, timeoutCancel := context.WithTimeout(parent, timeout)

	// Create a derived context that also respects the parent's cancellation
	// This isn't strictly necessary if timeoutCtx is derived from parent,
	// but it makes the relationship explicit.
	mergedCtx, mergedCancel := context.WithCancel(timeoutCtx)

	// Goroutine to cancel the merged context if the parent context is cancelled
	go func() {
		select {
		case <-parent.Done():
			mergedCancel() // Cancel merged if parent cancels
		case <-mergedCtx.Done():
			// Merged context already done (e.g., timeout or explicit cancel)
		}
	}()

	// Return the merged context and a function that cancels both
	return mergedCtx, func() {
		mergedCancel()
		timeoutCancel()
	}
}

// RetryOperation executes an operation with retry logic
func (m *ContainerManager) RetryOperation(ctx context.Context, operation func() error) error {
	m.mu.RLock()
	opts := m.options.RetryOptions
	m.mu.RUnlock()

	var lastErr error
	delay := opts.RetryDelay

	for i := 0; i <= opts.MaxRetries; i++ {
		if ctx.Err() != nil {
			return ErrContextCanceled // Check context before attempting operation
		}

		lastErr = operation()
		if lastErr == nil {
			return nil // Success
		}

		// Check if the error is retryable
		isRetryable := false
		for _, retryableErr := range opts.RetryableErrors {
			if errors.Is(lastErr, retryableErr) {
				isRetryable = true
				break
			}
		}

		// Check if the status code (if applicable) is retryable
		// This requires the error to potentially wrap an HTTP status code error
		var httpErr interface{ StatusCode() int }
		if errors.As(lastErr, &httpErr) {
			for _, statusCode := range opts.RetryStatusCodes {
				if httpErr.StatusCode() == statusCode {
					isRetryable = true
					break
				}
			}
		}

		if !isRetryable {
			return lastErr // Not a retryable error
		}

		// If it's the last attempt, return the error
		if i == opts.MaxRetries {
			break
		}

		// Calculate next delay with backoff and jitter
		currentDelay := delay
		if opts.Jitter > 0 {
			// jitter := time.Duration(float64(currentDelay) * opts.Jitter * (utils.RandomFloat64() - 0.5)) // Commented out due to undefined utils.RandomFloat64
			// currentDelay += jitter
		}

		m.logger.WithError(lastErr).WithFields(logrus.Fields{
			"attempt":    i + 1,
			"max_tries":  opts.MaxRetries + 1,
			"next_delay": currentDelay,
		}).Warn("Operation failed, retrying...")

		// Wait for the delay or context cancellation
		select {
		case <-time.After(currentDelay):
			// Continue to next retry
		case <-ctx.Done():
			m.logger.WithError(ctx.Err()).Warn("Retry cancelled by context")
			return ErrContextCanceled
		}

		// Increase delay for next retry
		delay = time.Duration(float64(delay) * opts.BackoffFactor)
		if delay > opts.MaxDelay {
			delay = opts.MaxDelay
		}
	}

	return fmt.Errorf("operation failed after %d retries: %w", opts.MaxRetries, lastErr)
}

// ValidateContainerID checks if a container ID is valid
func (m *ContainerManager) ValidateContainerID(id string) error {
	if len(id) != 64 {
		return fmt.Errorf("%w: expected 64 characters, got %d", ErrInvalidContainerID, len(id))
	}
	for _, r := range id {
		if (r < 'a' || r > 'f') && (r < '0' || r > '9') {
			return fmt.Errorf("%w: contains invalid character '%c'", ErrInvalidContainerID, r)
		}
	}
	return nil
}

// ValidateContainerName checks if a container name is valid according to Docker rules
// Names must match /?[a-zA-Z0-9][a-zA-Z0-9_.-]+
func (m *ContainerManager) ValidateContainerName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name cannot be empty", ErrInvalidContainerName)
	}
	// Allow optional leading slash
	if strings.HasPrefix(name, "/") {
		name = name[1:]
		if name == "" {
			return fmt.Errorf("%w: name cannot be just '/'", ErrInvalidContainerName)
		}
	}

	// Must start with an alphanumeric character
	if !((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= '0' && name[0] <= '9')) {
		return fmt.Errorf("%w: must start with an alphanumeric character", ErrInvalidContainerName)
	}

	// Subsequent characters can be alphanumeric, underscore, period, or hyphen
	for i := 1; i < len(name); i++ {
		char := name[i]
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '.' || char == '-') {
			return fmt.Errorf("%w: contains invalid character '%c'", ErrInvalidContainerName, char)
		}
	}
	return nil
}

// ValidateSecurityOptions checks container configuration against security policies
func (m *ContainerManager) ValidateSecurityOptions(config *container.Config, hostConfig *container.HostConfig, netConfig *network.NetworkingConfig) error {
	m.mu.RLock()
	secMgr := m.options.SecurityManager
	m.mu.RUnlock()

	if secMgr == nil {
		m.logger.Warn("No security manager configured, skipping security validation")
		return nil // No manager, no validation
	}

	// violations := secMgr.ValidateContainerConfig(config, hostConfig, netConfig) // Commented out due to undefined method
	violations := []error{} // Placeholder
	if len(violations) > 0 {
		m.logger.WithField("violations", violations).Error("Container configuration violates security policies")
		// Combine violations into a single error message
		var errMsgs []string
		for _, v := range violations {
			errMsgs = append(errMsgs, v.Error())
		}
		return fmt.Errorf("%w: %s", ErrSecurityViolation, strings.Join(errMsgs, "; "))
	}
	return nil
}

// ApplySecurityDefaults applies default security settings if a manager is configured
func (m *ContainerManager) ApplySecurityDefaults(config *container.Config, hostConfig *container.HostConfig, netConfig *network.NetworkingConfig) {
	m.mu.RLock()
	secMgr := m.options.SecurityManager
	m.mu.RUnlock()

	if secMgr != nil {
		// secMgr.ApplyDefaults(config, hostConfig, netConfig) // Commented out due to undefined method
		m.logger.Debug("Applied security defaults to container configuration (method call commented out)")
	}
}

// CreateSecureHostConfig creates a HostConfig with security defaults applied
func (m *ContainerManager) CreateSecureHostConfig() *container.HostConfig {
	hostConfig := &container.HostConfig{}
	m.ApplySecurityDefaults(nil, hostConfig, nil) // Apply defaults to an empty HostConfig
	return hostConfig
}

// SanitizeLogEntry masks sensitive data in log fields
func (m *ContainerManager) SanitizeLogEntry(fields logrus.Fields) logrus.Fields {
	m.mu.RLock()
	mask := m.options.MaskSensitiveData
	m.mu.RUnlock()

	if !mask {
		return fields
	}

	sanitizedFields := make(logrus.Fields, len(fields))
	for key, value := range fields {
		if m.IsSensitiveField(key) {
			sanitizedFields[key] = "***REDACTED***"
		} else {
			// Recursively sanitize maps and slices
			switch v := value.(type) {
			case map[string]interface{}:
				sanitizedMap := make(map[string]interface{}, len(v))
				for k, val := range v {
					if m.IsSensitiveField(k) {
						sanitizedMap[k] = "***REDACTED***"
					} else {
						// Basic check for sensitive-like values within the map
						if strVal, ok := val.(string); ok && isLikelySensitiveValue(strVal) {
							sanitizedMap[k] = "***REDACTED***"
						} else {
							sanitizedMap[k] = val // Keep non-sensitive values
						}
					}
				}
				sanitizedFields[key] = sanitizedMap
			case []string:
				// Sanitize environment variables within slices
				if key == "Env" || key == "env" { // Check common keys for env vars
					sanitizedFields[key] = sanitizeEnvVars(v)
				} else {
					sanitizedFields[key] = value // Keep other string slices as is
				}
			case string:
				if isLikelySensitiveValue(v) {
					sanitizedFields[key] = "***REDACTED***"
				} else {
					sanitizedFields[key] = v
				}
			default:
				sanitizedFields[key] = value
			}
		}
	}
	return sanitizedFields
}

// isLikelySensitiveValue checks if a string value looks like sensitive data (basic heuristic)
func isLikelySensitiveValue(value string) bool {
	// Simple checks for common patterns like keys, tokens, passwords
	lowerValue := strings.ToLower(value)
	if strings.Contains(lowerValue, "password") || strings.Contains(lowerValue, "secret") ||
		strings.Contains(lowerValue, "token") || strings.Contains(lowerValue, "apikey") ||
		strings.Contains(lowerValue, "private_key") {
		return true
	}
	// Check for base64-like strings (potential tokens/keys)
	if len(value) > 20 && isBase64Like(value) {
		return true
	}
	// Check for hex-like strings (potential keys)
	if len(value) > 32 && isHexLike(value) {
		return true
	}
	return false
}

// isBase64Like checks if a string resembles Base64 encoding
func isBase64Like(value string) bool {
	// Basic check: length multiple of 4, contains only Base64 chars
	if len(value)%4 != 0 {
		return false
	}
	for _, r := range value {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	return true
}

// isHexLike checks if a string resembles Hex encoding
func isHexLike(value string) bool {
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// sanitizeEnvVars specifically sanitizes environment variable slices
func sanitizeEnvVars(envVars []string) []string {
	sanitized := make([]string, len(envVars))
	for i, envVar := range envVars {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 2 {
			key := strings.ToLower(parts[0])
			if strings.Contains(key, "pass") || strings.Contains(key, "secret") || strings.Contains(key, "token") || strings.Contains(key, "key") {
				sanitized[i] = parts[0] + "=***REDACTED***"
			} else {
				sanitized[i] = envVar // Keep non-sensitive env vars
			}
		} else {
			sanitized[i] = envVar // Keep malformed entries as is
		}
	}
	return sanitized
}

// LogOperation logs the start of a container operation
func (m *ContainerManager) LogOperation(operation ContainerOperation, fields logrus.Fields) {
	m.mu.RLock()
	logger := m.logger
	requestID := m.options.RequestID
	user := m.options.User
	m.mu.RUnlock()

	logFields := logrus.Fields{
		"operation": operation,
	}
	if requestID != "" {
		logFields["request_id"] = requestID
	}
	if user != "" {
		logFields["user"] = user
	}
	for k, v := range fields {
		logFields[k] = v
	}

	logger.WithFields(m.SanitizeLogEntry(logFields)).Info("Performing container operation")
}

// LogError logs an error during a container operation
func (m *ContainerManager) LogError(operation ContainerOperation, err error, fields logrus.Fields) {
	m.mu.RLock()
	logger := m.logger
	requestID := m.options.RequestID
	user := m.options.User
	m.mu.RUnlock()

	logFields := logrus.Fields{
		"operation": operation,
	}
	if requestID != "" {
		logFields["request_id"] = requestID
	}
	if user != "" {
		logFields["user"] = user
	}
	for k, v := range fields {
		logFields[k] = v
	}

	// Determine log level based on error type
	level := logrus.ErrorLevel
	if errors.Is(err, ErrContainerNotFound) || errors.Is(err, ErrNoSuchImage) {
		level = logrus.WarnLevel
	} else if errors.Is(err, context.Canceled) {
		level = logrus.InfoLevel // Context cancellation is often expected
	}

	logger.WithFields(m.SanitizeLogEntry(logFields)).WithError(err).Log(level, "Container operation failed")
}

// PullImage pulls an image if not present locally or if forced
func (m *ContainerManager) PullImage(ctx context.Context, image string, auth string) error {
	m.mu.RLock()
	skipPull := m.options.SkipImagePull
	m.mu.RUnlock()

	fields := logrus.Fields{"image": image}
	m.LogOperation("image_pull_check", fields)

	if !skipPull {
		_, _, err := m.client.ImageInspectWithRaw(ctx, image)
		if err == nil {
			m.logger.WithFields(fields).Debug("Image already exists locally, skipping pull")
			return nil // Image exists locally
		}
		if !client.IsErrNotFound(err) {
			m.LogError("image_inspect", err, fields)
			return fmt.Errorf("failed to inspect image: %w", err)
		}
		// Image not found, proceed to pull
		m.logger.WithFields(fields).Info("Image not found locally, pulling...")
	} else {
		m.logger.WithFields(fields).Info("Skipping image pull as requested")
		return nil
	}

	pullOptions := imagetypes.PullOptions{} // Use alias
	if auth != "" {
		pullOptions.RegistryAuth = auth
	}

	m.LogOperation("image_pull", fields)
	reader, err := m.client.ImagePull(ctx, image, pullOptions)
	if err != nil {
		m.LogError("image_pull", err, fields)
		return fmt.Errorf("%w: %v", ErrImagePullFailed, err)
	}
	defer reader.Close()

	// Read and process the pull output
	if err := m.readPullOutput(ctx, reader); err != nil {
		// Log the error but potentially return the original pull error if more indicative
		m.LogError("image_pull_output", err, fields)
		return fmt.Errorf("%w: error processing pull output: %v", ErrImagePullFailed, err)
	}

	m.logger.WithFields(fields).Info("Image pulled successfully")
	return nil
}

// readPullOutput reads and logs the output from an image pull operation
func (m *ContainerManager) readPullOutput(ctx context.Context, reader io.ReadCloser) error {
	decoder := json.NewDecoder(reader)
	for {
		select {
		case <-ctx.Done():
			return ErrContextCanceled
		default:
			var msg jsonmessage
			if err := decoder.Decode(&msg); err != nil {
				if err == io.EOF {
					return nil // End of stream
				}
				// Check for context cancellation within the decode loop
				if ctx.Err() != nil {
					return ErrContextCanceled
				}
				return fmt.Errorf("error decoding pull output: %w", err)
			}

			// Log progress or errors
			logFields := logrus.Fields{
				"status":    msg.Status,
				"id":        msg.ID,
				"progress":  msg.Progress,
				"stream":    msg.Stream, // Added stream field
				"error":     msg.Error,  // Added error field
				"error_msg": msg.ErrorMessage,
			}
			if msg.Error != nil || msg.ErrorMessage != "" {
				m.logger.WithFields(logFields).Error("Image pull error reported in stream")
				// Optionally return an error here if needed
				// return fmt.Errorf("pull error: %s", msg.ErrorMessage)
			} else if msg.Progress != "" {
				m.logger.WithFields(logFields).Debug("Image pull progress")
			} else if msg.Status != "" {
				m.logger.WithFields(logFields).Info("Image pull status")
			}
		}
	}
}

// jsonmessage mirrors the structure returned by Docker image pull/build
type jsonmessage struct {
	Stream       string      `json:"stream"`
	Status       string      `json:"status"`
	Progress     string      `json:"progress"`
	ID           string      `json:"id"`
	Error        error       `json:"errorDetail"` // Changed to error type
	ErrorMessage string      `json:"error"`       // Keep original error message field
	Aux          interface{} `json:"aux"`
}

// jsonmsgError mirrors the structure of errorDetail in jsonmessage
type jsonmsgError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// InspectContainer retrieves detailed information about a container
func (m *ContainerManager) InspectContainer(ctx context.Context, containerID string) (dockertypes.ContainerJSON, error) { // Use alias
	fields := logrus.Fields{"container_id": containerID}
	m.LogOperation(ContainerOperationInspect, fields)

	if err := m.ValidateContainerID(containerID); err != nil {
		m.LogError(ContainerOperationInspect, err, fields)
		return dockertypes.ContainerJSON{}, err // Use alias
	}

	ctx, cancel := m.GetContextWithTimeout(0) // Use default timeout
	defer cancel()

	containerJSON, err := m.client.ContainerInspect(ctx, containerID)
	if err != nil {
		if client.IsErrNotFound(err) {
			m.LogError(ContainerOperationInspect, ErrContainerNotFound, fields)
			return dockertypes.ContainerJSON{}, ErrContainerNotFound // Use alias
		}
		m.LogError(ContainerOperationInspect, err, fields)
		return dockertypes.ContainerJSON{}, fmt.Errorf("%w: %v", ErrOperationFailed, err) // Use alias
	}

	m.LogOperation(ContainerOperationInspect, logrus.Fields{"container_id": containerID, "status": "success"})
	return containerJSON, nil
}

// ListContainers lists containers based on provided options
func (m *ContainerManager) ListContainers(ctx context.Context, options container.ListOptions) ([]dockertypes.Container, error) { // Corrected options type, Use alias for return
	fields := logrus.Fields{"all": options.All, "limit": options.Limit, "size": options.Size, "filters": options.Filters}
	m.LogOperation(ContainerOperationList, fields)

	ctx, cancel := m.GetContextWithTimeout(0) // Use default timeout
	defer cancel()

	containers, err := m.client.ContainerList(ctx, options)
	if err != nil {
		m.LogError(ContainerOperationList, err, fields)
		return nil, fmt.Errorf("%w: %v", ErrOperationFailed, err)
	}

	m.LogOperation(ContainerOperationList, logrus.Fields{"count": len(containers), "status": "success"})
	return containers, nil
}

// MonitorEvents streams Docker events
func (m *ContainerManager) MonitorEvents(ctx context.Context, filters filters.Args, eventCh chan<- events.Message) error {
	fields := logrus.Fields{"filters": filters}
	m.LogOperation("monitor_events", fields)

	// Use the provided context directly for streaming
	msgChan, errChan := m.client.Events(ctx, events.ListOptions{Filters: filters}) // Use alias

	for {
		select {
		case msg := <-msgChan:
			// Log event details (consider sanitizing)
			logFields := logrus.Fields{
				"type":   msg.Type,
				"action": msg.Action,
				"id":     msg.Actor.ID,
				"scope":  msg.Scope,
				"time":   time.Unix(msg.Time, msg.TimeNano).Format(time.RFC3339Nano),
			}
			// Add attributes, sanitizing potentially sensitive ones
			sanitizedAttributes := make(map[string]string)
			for k, v := range msg.Actor.Attributes {
				if m.IsSensitiveField(k) || isLikelySensitiveValue(v) {
					sanitizedAttributes[k] = "***REDACTED***"
				} else {
					sanitizedAttributes[k] = v
				}
			}
			logFields["attributes"] = sanitizedAttributes
			m.logger.WithFields(logFields).Debug("Received Docker event")

			// Send the event to the provided channel
			select {
			case eventCh <- msg:
			case <-ctx.Done():
				m.logger.Info("Event monitoring stopped by context cancellation.")
				return ErrContextCanceled
			}
		case err := <-errChan:
			if err != nil {
				// Check if the error is due to context cancellation
				if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
					m.logger.Info("Event monitoring stream closed or context cancelled.")
					return nil // Normal closure or cancellation
				}
				m.LogError("monitor_events_stream", err, fields)
				return fmt.Errorf("error receiving events: %w", err)
			}
			// Nil error means the stream closed gracefully from the daemon side
			m.logger.Info("Event monitoring stream closed by daemon.")
			return nil
		case <-ctx.Done():
			m.logger.Info("Event monitoring stopped by context cancellation.")
			return ErrContextCanceled
		}
	}
}

// GetContainerLogs retrieves logs from a container
func (m *ContainerManager) GetContainerLogs(ctx context.Context, containerID string, options container.LogsOptions) (io.ReadCloser, error) { // Corrected options type
	fields := logrus.Fields{
		"container_id": containerID,
		"show_stdout":  options.ShowStdout,
		"show_stderr":  options.ShowStderr,
		"follow":       options.Follow,
		"timestamps":   options.Timestamps,
		"tail":         options.Tail,
		"since":        options.Since,
		"until":        options.Until,
	}
	m.LogOperation(ContainerOperationLogs, fields)

	if err := m.ValidateContainerID(containerID); err != nil {
		m.LogError(ContainerOperationLogs, err, fields)
		return nil, err
	}

	ctx, cancel := m.GetContextWithTimeout(0) // Use default timeout, streaming handled by caller
	defer cancel()                            // Cancel context if function returns early

	logReader, err := m.client.ContainerLogs(ctx, containerID, options)
	if err != nil {
		if client.IsErrNotFound(err) {
			m.LogError(ContainerOperationLogs, ErrContainerNotFound, fields)
			return nil, ErrContainerNotFound
		}
		m.LogError(ContainerOperationLogs, err, fields)
		return nil, fmt.Errorf("%w: %v", ErrOperationFailed, err)
	}

	m.LogOperation(ContainerOperationLogs, logrus.Fields{"container_id": containerID, "status": "success"})
	return logReader, nil
}

// FormatContainerStatus formats the container status string based on state and health
func (m *ContainerManager) FormatContainerStatus(containerJSON dockertypes.ContainerJSON) string { // Use alias
	if containerJSON.State == nil {
		return "unknown"
	}
	state := containerJSON.State.Status
	if state == "running" && containerJSON.State.Health != nil {
		switch containerJSON.State.Health.Status {
		case dockertypes.Healthy: // Use alias
			return "healthy"
		case dockertypes.Unhealthy: // Use alias
			return "unhealthy"
		case dockertypes.Starting: // Use alias
			return "starting"
		}
	}
	// Handle specific exit codes if needed
	if state == "exited" {
		return fmt.Sprintf("exited (%d)", containerJSON.State.ExitCode)
	}
	return state
}

// GetContainerHealth returns the health status string of a container
func (m *ContainerManager) GetContainerHealth(containerJSON dockertypes.ContainerJSON) string { // Use alias
	if containerJSON.State != nil && containerJSON.State.Health != nil {
		return containerJSON.State.Health.Status
	}
	return "" // No health check configured or state unavailable
}

// GetContainerNetworkMode returns the network mode of a container
func (m *ContainerManager) GetContainerNetworkMode(containerJSON dockertypes.ContainerJSON) string { // Use alias
	if containerJSON.HostConfig != nil {
		return string(containerJSON.HostConfig.NetworkMode)
	}
	return "unknown"
}

// GetContainerNetworkIPs returns a map of network names to IP addresses
func (m *ContainerManager) GetContainerNetworkIPs(containerJSON dockertypes.ContainerJSON) map[string]string { // Use alias
	ips := make(map[string]string)
	if containerJSON.NetworkSettings != nil && containerJSON.NetworkSettings.Networks != nil {
		for name, settings := range containerJSON.NetworkSettings.Networks {
			if settings.IPAddress != "" {
				ips[name] = settings.IPAddress
			}
		}
	}
	return ips
}

// GetContainerPortMappings returns a slice of port mappings
func (m *ContainerManager) GetContainerPortMappings(containerJSON dockertypes.ContainerJSON) []models.PortMapping { // Use alias
	mappings := []models.PortMapping{}
	if containerJSON.NetworkSettings != nil && containerJSON.NetworkSettings.Ports != nil {
		for containerPortProto, hostBindings := range containerJSON.NetworkSettings.Ports {
			parts := strings.SplitN(string(containerPortProto), "/", 2)
			containerPort := parts[0]
			proto := "tcp" // Default to tcp
			if len(parts) > 1 {
				proto = parts[1]
			}
			if hostBindings != nil {
				for _, binding := range hostBindings {
					mappings = append(mappings, models.PortMapping{
						HostIP:        binding.HostIP,
						HostPort:      binding.HostPort,
						ContainerPort: containerPort,
						Type:          proto,
					})
				}
			} else {
				// Exposed but not published
				mappings = append(mappings, models.PortMapping{
					ContainerPort: containerPort,
					Type:          proto,
				})
			}
		}
	}
	return mappings
}

// GetContainerUptime calculates the uptime of a running container
func (m *ContainerManager) GetContainerUptime(containerJSON dockertypes.ContainerJSON) time.Duration { // Use alias
	if containerJSON.State != nil && containerJSON.State.Running {
		// Parse StartedAt string into time.Time
		startedAt, err := time.Parse(time.RFC3339Nano, containerJSON.State.StartedAt)
		if err == nil && !startedAt.IsZero() { // Check if time is not zero after parsing
			return time.Since(startedAt)
		}
		if err != nil {
			m.logger.WithError(err).WithField("startedAt", containerJSON.State.StartedAt).Warn("Failed to parse container start time")
		}
	}
	return 0
}

// GetContainerRestartCount returns the restart count of a container
func (m *ContainerManager) GetContainerRestartCount(containerJSON dockertypes.ContainerJSON) int { // Use alias
	if containerJSON.State != nil {
		// RestartCount might not exist in all SDK versions, return 0 if so.
		// return containerJSON.State.RestartCount // Commented out
		return 0 // Return 0 as field might not exist
	}
	return 0
}

// GetContainerEnv returns the environment variables of a container as a map
func (m *ContainerManager) GetContainerEnv(containerJSON dockertypes.ContainerJSON) map[string]string { // Use alias
	envMap := make(map[string]string)
	if containerJSON.Config != nil && containerJSON.Config.Env != nil {
		for _, envVar := range containerJSON.Config.Env {
			parts := strings.SplitN(envVar, "=", 2)
			if len(parts) == 2 {
				key := parts[0]
				value := parts[1]
				if m.IsSensitiveEnvVar(key) {
					envMap[key] = "***REDACTED***"
				} else {
					envMap[key] = value
				}
			} else if len(parts) == 1 {
				envMap[parts[0]] = "" // Handle variables without values
			}
		}
	}
	return envMap
}

// GetContainerLabels returns the labels of a container
func (m *ContainerManager) GetContainerLabels(containerJSON dockertypes.ContainerJSON) map[string]string { // Use alias
	if containerJSON.Config != nil && containerJSON.Config.Labels != nil {
		return containerJSON.Config.Labels
	}
	return make(map[string]string)
}

// GetContainerSecurityInfo extracts key security-related settings
func (m *ContainerManager) GetContainerSecurityInfo(containerJSON dockertypes.ContainerJSON) map[string]interface{} { // Use alias
	info := make(map[string]interface{})
	if containerJSON.HostConfig != nil {
		info["Privileged"] = containerJSON.HostConfig.Privileged
		info["ReadOnlyRootfs"] = containerJSON.HostConfig.ReadonlyRootfs
		info["CapAdd"] = containerJSON.HostConfig.CapAdd
		info["CapDrop"] = containerJSON.HostConfig.CapDrop
		info["SecurityOpt"] = containerJSON.HostConfig.SecurityOpt
		info["NetworkMode"] = containerJSON.HostConfig.NetworkMode
		info["PidMode"] = containerJSON.HostConfig.PidMode
		info["IpcMode"] = containerJSON.HostConfig.IpcMode
		info["UTSMode"] = containerJSON.HostConfig.UTSMode
		info["UsernsMode"] = containerJSON.HostConfig.UsernsMode
	}
	// Add checks for sensitive mounts if needed (requires parsing containerJSON.Mounts)
	// sensitiveMounts := []string{}
	// for _, mount := range containerJSON.Mounts {
	// 	// Example check: if mount source is sensitive path like /var/run/docker_test.sock
	// 	if mount.Source == "/var/run/docker_test.sock" {
	// 		sensitiveMounts = append(sensitiveMounts, fmt.Sprintf("%s:%s", mount.Source, mount.Destination))
	// 	}
	// }
	// info["SensitiveMounts"] = sensitiveMounts

	return info
}

// PrintContainerInfo generates a human-readable summary of container info
func (m *ContainerManager) PrintContainerInfo(containerJSON dockertypes.ContainerJSON) string { // Use alias
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ID: %s\n", containerJSON.ID[:12])) // Short ID
	sb.WriteString(fmt.Sprintf("Name: %s\n", containerJSON.Name))
	sb.WriteString(fmt.Sprintf("Image: %s\n", containerJSON.Config.Image))
	sb.WriteString(fmt.Sprintf("Status: %s\n", m.FormatContainerStatus(containerJSON)))
	if containerJSON.State != nil {
		startedAt, err := time.Parse(time.RFC3339Nano, containerJSON.State.StartedAt)
		if err == nil && !startedAt.IsZero() {
			// sb.WriteString(fmt.Sprintf("Started: %s (%s ago)\n", startedAt.Format(time.RFC1123), utils.HumanDuration(time.Since(startedAt)))) // Commented out HumanDuration
			sb.WriteString(fmt.Sprintf("Started: %s (%s ago)\n", startedAt.Format(time.RFC1123), time.Since(startedAt).Round(time.Second).String()))
		}
	}
	if containerJSON.State != nil && containerJSON.State.Status == "exited" {
		finishedAt, err := time.Parse(time.RFC3339Nano, containerJSON.State.FinishedAt)
		if err == nil && !finishedAt.IsZero() {
			// sb.WriteString(fmt.Sprintf("Finished: %s (%s ago)\n", finishedAt.Format(time.RFC1123), utils.HumanDuration(time.Since(finishedAt)))) // Commented out HumanDuration
			sb.WriteString(fmt.Sprintf("Finished: %s (%s ago)\n", finishedAt.Format(time.RFC1123), time.Since(finishedAt).Round(time.Second).String()))
			sb.WriteString(fmt.Sprintf("Exit Code: %d\n", containerJSON.State.ExitCode))
		}
	}

	ips := m.GetContainerNetworkIPs(containerJSON)
	if len(ips) > 0 {
		sb.WriteString("IP Addresses:\n")
		for netName, ip := range ips {
			sb.WriteString(fmt.Sprintf("  - %s: %s\n", netName, ip))
		}
	}

	ports := m.GetContainerPortMappings(containerJSON)
	if len(ports) > 0 {
		sb.WriteString("Ports:\n")
		for _, p := range ports {
			if p.HostIP != "" || p.HostPort != "" {
				sb.WriteString(fmt.Sprintf("  - %s:%s -> %s/%s\n", p.HostIP, p.HostPort, p.ContainerPort, p.Type))
			} else {
				sb.WriteString(fmt.Sprintf("  - %s/%s (exposed)\n", p.ContainerPort, p.Type))
			}
		}
	}

	return sb.String()
}

// TraceRequest logs the start of an API request
func (m *ContainerManager) TraceRequest(operation ContainerOperation, fields map[string]interface{}) {
	m.mu.RLock()
	logger := m.logger
	requestID := m.options.RequestID
	user := m.options.User
	m.mu.RUnlock()

	logFields := logrus.Fields{
		"operation": operation,
		"phase":     "request_start",
	}
	if requestID != "" {
		logFields["request_id"] = requestID
	}
	if user != "" {
		logFields["user"] = user
	}
	for k, v := range fields {
		logFields[k] = v
	}
	logger.WithFields(m.SanitizeLogEntry(logFields)).Trace("API request received")
}

// TraceResponse logs the completion of an API request
func (m *ContainerManager) TraceResponse(operation ContainerOperation, response interface{}, fields map[string]interface{}) {
	m.mu.RLock()
	logger := m.logger
	requestID := m.options.RequestID
	user := m.options.User
	m.mu.RUnlock()

	logFields := logrus.Fields{
		"operation": operation,
		"phase":     "response_sent",
	}
	if requestID != "" {
		logFields["request_id"] = requestID
	}
	if user != "" {
		logFields["user"] = user
	}
	for k, v := range fields {
		logFields[k] = v
	}

	// Attempt to marshal response for logging, handle errors gracefully
	// Limit the size of the logged response to avoid excessive log volume
	const maxLogSize = 1024
	var responseStr string
	if response != nil {
		respBytes, err := json.Marshal(response)
		if err == nil {
			if len(respBytes) > maxLogSize {
				responseStr = string(respBytes[:maxLogSize]) + "... (truncated)"
			} else {
				responseStr = string(respBytes)
			}
		} else {
			responseStr = fmt.Sprintf("Error marshaling response: %v", err)
		}
		// Sanitize the response string if needed, though marshaling might handle some cases
		if isLikelySensitiveValue(responseStr) { // Basic check on the marshaled string
			logFields["response"] = "***REDACTED***"
		} else {
			logFields["response"] = responseStr
		}
	}

	logger.WithFields(m.SanitizeLogEntry(logFields)).Trace("API response sent")
}

// ExecuteCommand creates and starts an exec instance in a container
func (m *ContainerManager) ExecuteCommand(ctx context.Context, containerID string, cmd []string, options container.ExecOptions) (container.ExecCreateResponse, error) { // Use alias
	fields := logrus.Fields{"container_id": containerID, "command": strings.Join(cmd, " ")}
	m.LogOperation(ContainerOperationExec, fields)

	if err := m.ValidateContainerID(containerID); err != nil {
		m.LogError(ContainerOperationExec, err, fields)
		return container.ExecCreateResponse{}, err // Use alias
	}

	ctx, cancel := m.GetContextWithTimeout(0) // Use default timeout
	defer cancel()

	// Ensure required options are set
	if options.Cmd == nil {
		options.Cmd = cmd
	}
	if !options.AttachStdout {
		options.AttachStdout = true // Default to capturing stdout
	}
	if !options.AttachStderr {
		options.AttachStderr = true // Default to capturing stderr
	}

	// Apply security defaults if manager is configured
	m.ApplySecurityDefaults(nil, nil, nil) // Security defaults might influence exec options in future

	// Validate security options related to exec if needed
	// Example: Disallow privileged exec unless user is admin
	// if options.Privileged && !isAdmin { ... return ErrInsufficientPermissions ... }

	resp, err := m.client.ContainerExecCreate(ctx, containerID, options)
	if err != nil {
		if client.IsErrNotFound(err) {
			m.LogError(ContainerOperationExec, ErrContainerNotFound, fields)
			return container.ExecCreateResponse{}, ErrContainerNotFound // Use alias
		}
		m.LogError(ContainerOperationExec, err, fields)
		return container.ExecCreateResponse{}, fmt.Errorf("%w: %v", ErrExecCreateFailed, err) // Use alias
	}

	m.LogOperation(ContainerOperationExec, logrus.Fields{"container_id": containerID, "exec_id": resp.ID, "status": "created"})
	return resp, nil
}

// StartCommand starts a previously created exec instance
func (m *ContainerManager) StartCommand(ctx context.Context, execID string, options container.ExecStartOptions) error { // Use alias
	fields := logrus.Fields{"exec_id": execID, "detach": options.Detach, "tty": options.Tty}
	m.LogOperation("exec_start", fields)

	ctx, cancel := m.GetContextWithTimeout(0) // Use default timeout
	defer cancel()

	err := m.client.ContainerExecStart(ctx, execID, options)
	if err != nil {
		// Check for specific errors like "exec instance not found"
		if strings.Contains(err.Error(), "No such exec instance") {
			m.LogError("exec_start", fmt.Errorf("exec instance %s not found: %w", execID, err), fields)
			return fmt.Errorf("exec instance %s not found", execID)
		}
		m.LogError("exec_start", err, fields)
		return fmt.Errorf("%w: %v", ErrExecStartFailed, err)
	}

	m.LogOperation("exec_start", logrus.Fields{"exec_id": execID, "status": "started"})
	return nil
}

// InspectCommand inspects a previously created exec instance
func (m *ContainerManager) InspectCommand(ctx context.Context, execID string) (container.ExecInspect, error) { // Use alias
	fields := logrus.Fields{"exec_id": execID}
	m.LogOperation("exec_inspect", fields)

	ctx, cancel := m.GetContextWithTimeout(0) // Use default timeout
	defer cancel()

	inspectResp, err := m.client.ContainerExecInspect(ctx, execID)
	if err != nil {
		// Check for specific errors like "exec instance not found"
		if strings.Contains(err.Error(), "No such exec instance") {
			m.LogError("exec_inspect", fmt.Errorf("exec instance %s not found: %w", execID, err), fields)
			return container.ExecInspect{}, fmt.Errorf("exec instance %s not found", execID) // Use alias
		}
		m.LogError("exec_inspect", err, fields)
		return container.ExecInspect{}, fmt.Errorf("%w: %v", ErrOperationFailed, err) // Use alias
	}

	m.LogOperation("exec_inspect", logrus.Fields{"exec_id": execID, "running": inspectResp.Running, "exit_code": inspectResp.ExitCode, "status": "success"})
	return inspectResp, nil
}

// IsSensitiveField checks if a field name is considered sensitive
func (m *ContainerManager) IsSensitiveField(field string) bool {
	lowerField := strings.ToLower(field)
	sensitiveKeywords := []string{"password", "secret", "token", "apikey", "private_key", "auth", "credential"}
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(lowerField, keyword) {
			return true
		}
	}
	// Add more specific field names if needed
	// sensitiveFields := map[string]bool{"DockerCfg": true, "RegistryAuth": true}
	// if sensitiveFields[field] {
	// 	return true
	// }
	return false
}

// IsHealthy checks if a container's state indicates it is healthy.
func (m *ContainerManager) IsHealthy(containerJSON dockertypes.ContainerJSON) bool { // Use alias
	if containerJSON.State == nil {
		return false // Cannot determine health without state
	}
	if !containerJSON.State.Running {
		return false // Not running, cannot be healthy
	}
	if containerJSON.State.Health == nil {
		// No health check configured, consider it "healthy" if running
		// Alternatively, could return false or a specific status like "unknown"
		return true
	}
	return containerJSON.State.Health.Status == dockertypes.Healthy // Use alias
}

// GetErrorMessage provides a user-friendly error message based on common Docker errors
func (m *ContainerManager) GetErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	if client.IsErrNotFound(err) {
		return "Resource not found."
	}
	// if client.IsErrUnauthorized(err) { // Commented out due to undefined function
	// 	return "Unauthorized access."
	// }
	if errors.Is(err, context.DeadlineExceeded) {
		return "Operation timed out."
	}
	if errors.Is(err, context.Canceled) {
		return "Operation canceled."
	}
	// Add more specific error mappings as needed
	if strings.Contains(err.Error(), "No such container") {
		return "Container not found."
	}
	if strings.Contains(err.Error(), "No such image") {
		return "Image not found."
	}
	if strings.Contains(err.Error(), "driver failed programming external connectivity") {
		return "Network error: Could not program external connectivity (check port conflicts)."
	}
	if strings.Contains(err.Error(), "address already in use") {
		return "Network error: Address or port already in use."
	}
	// Default generic message
	return fmt.Sprintf("An unexpected error occurred: %v", err)
}

// WaitForContainer waits for a container to reach a specific condition (e.g., "not-running", "healthy")
func (m *ContainerManager) WaitForContainer(ctx context.Context, containerID string, condition container.WaitCondition) (container.WaitResponse, error) { // Corrected return type
	fields := logrus.Fields{"container_id": containerID, "condition": condition}
	m.LogOperation("container_wait", fields)

	if err := m.ValidateContainerID(containerID); err != nil {
		m.LogError("container_wait", err, fields)
		return container.WaitResponse{}, err // Corrected return type
	}

	// Use the provided context directly, timeout should be handled by the caller if needed
	statusCh, errCh := m.client.ContainerWait(ctx, containerID, condition)

	select {
	case status := <-statusCh:
		logFields := logrus.Fields{
			"container_id": containerID,
			"condition":    condition,
			"exit_code":    status.StatusCode,
			"status":       "condition_met",
		}
		if status.Error != nil {
			logFields["wait_error"] = status.Error.Message
		}
		m.LogOperation("container_wait", logFields)
		// Check if the wait itself returned an error message
		if status.Error != nil {
			err := fmt.Errorf("wait error: %s", status.Error.Message)
			m.LogError("container_wait", err, fields)
			return status, err // Return status even on wait error
		}
		return status, nil
	case err := <-errCh:
		// Check if the error is due to context cancellation
		if errors.Is(err, context.Canceled) {
			m.LogError("container_wait", ErrContextCanceled, fields)
			return container.WaitResponse{}, ErrContextCanceled // Corrected return type
		}
		if errors.Is(err, context.DeadlineExceeded) {
			m.LogError("container_wait", ErrTimeout, fields)
			return container.WaitResponse{}, ErrTimeout // Corrected return type
		}
		m.LogError("container_wait", err, fields)
		return container.WaitResponse{}, fmt.Errorf("%w: %v", ErrOperationFailed, err) // Corrected return type
	case <-ctx.Done():
		m.LogError("container_wait", ErrContextCanceled, fields)
		return container.WaitResponse{}, ErrContextCanceled // Corrected return type
	}
}

// CopyToContainer copies content to a path in a container
func (m *ContainerManager) CopyToContainer(ctx context.Context, containerID string, dstPath string, content io.Reader, options container.CopyToContainerOptions) error { // Use alias
	fields := logrus.Fields{"container_id": containerID, "destination": dstPath}
	m.LogOperation(ContainerOperationCopyTo, fields)

	if err := m.ValidateContainerID(containerID); err != nil {
		m.LogError(ContainerOperationCopyTo, err, fields)
		return err
	}

	ctx, cancel := m.GetContextWithTimeout(0) // Use default timeout
	defer cancel()

	err := m.client.CopyToContainer(ctx, containerID, dstPath, content, options)
	if err != nil {
		if client.IsErrNotFound(err) {
			m.LogError(ContainerOperationCopyTo, ErrContainerNotFound, fields)
			return ErrContainerNotFound
		}
		m.LogError(ContainerOperationCopyTo, err, fields)
		return fmt.Errorf("%w: %v", ErrOperationFailed, err)
	}

	m.LogOperation(ContainerOperationCopyTo, logrus.Fields{"container_id": containerID, "destination": dstPath, "status": "success"})
	return nil
}

// CopyFromContainer copies content from a path in a container
func (m *ContainerManager) CopyFromContainer(ctx context.Context, containerID string, srcPath string) (io.ReadCloser, container.PathStat, error) { // Use alias
	fields := logrus.Fields{"container_id": containerID, "source": srcPath}
	m.LogOperation(ContainerOperationCopyFrom, fields)

	if err := m.ValidateContainerID(containerID); err != nil {
		m.LogError(ContainerOperationCopyFrom, err, fields)
		return nil, container.PathStat{}, err // Use alias
	}

	ctx, cancel := m.GetContextWithTimeout(0) // Use default timeout
	// We don't defer cancel here because the caller needs the reader (logReader)
	// The caller is responsible for closing the reader, which should handle context

	reader, stat, err := m.client.CopyFromContainer(ctx, containerID, srcPath)
	if err != nil {
		cancel() // Cancel context as the operation failed
		if client.IsErrNotFound(err) {
			// Distinguish between container not found and path not found
			if strings.Contains(err.Error(), "No such container") {
				m.LogError(ContainerOperationCopyFrom, ErrContainerNotFound, fields)
				return nil, container.PathStat{}, ErrContainerNotFound // Use alias
			}
			m.LogError(ContainerOperationCopyFrom, fmt.Errorf("path not found: %s", srcPath), fields)
			return nil, container.PathStat{}, fmt.Errorf("path not found: %s", srcPath) // Use alias
		}
		m.LogError(ContainerOperationCopyFrom, err, fields)
		return nil, container.PathStat{}, fmt.Errorf("%w: %v", ErrOperationFailed, err) // Use alias
	}

	// Wrap the reader with a closer that also cancels the context
	wrappedReader := &contextClosingReader{
		ReadCloser: reader,
		cancel:     cancel, // Pass the cancel function
	}

	logFields := logrus.Fields{
		"container_id": containerID,
		"source":       srcPath,
		"stat_name":    stat.Name,
		"stat_size":    stat.Size,
		"stat_mode":    stat.Mode,
		"status":       "success",
	}
	m.LogOperation(ContainerOperationCopyFrom, logFields)
	return wrappedReader, stat, nil
}

// contextClosingReader wraps an io.ReadCloser and calls a cancel function on Close()
type contextClosingReader struct {
	io.ReadCloser
	cancel context.CancelFunc
}

// Close closes the underlying reader and cancels the associated context.
func (r *contextClosingReader) Close() error {
	err := r.ReadCloser.Close()
	if r.cancel != nil {
		r.cancel()
	}
	return err
}

// ReadAllWithTimeout reads all data from an io.ReadCloser with a timeout.
func (m *ContainerManager) ReadAllWithTimeout(reader io.ReadCloser, timeout time.Duration) ([]byte, error) {
	defer reader.Close()

	if timeout <= 0 {
		m.mu.RLock()
		timeout = m.options.Timeout
		m.mu.RUnlock()
	}

	resultChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		data, err := io.ReadAll(reader)
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- data
	}()

	select {
	case data := <-resultChan:
		return data, nil
	case err := <-errChan:
		return nil, err
	case <-time.After(timeout):
		return nil, ErrTimeout
	}
}

// GetContainerStats retrieves stats for a container (single shot or stream)
// GetContainerStats retrieves resource usage statistics for a container.
// Note: This function currently only supports non-streaming stats (stream=false).
// For streaming stats, the caller should use the Docker client directly or a dedicated streaming function.
func (m *ContainerManager) GetContainerStats(ctx context.Context, containerID string, stream bool) (*models.ContainerStats, error) {
	fields := logrus.Fields{"container_id": containerID, "stream": stream}
	m.LogOperation(ContainerOperationStats, fields)

	if err := m.ValidateContainerID(containerID); err != nil {
		m.LogError(ContainerOperationStats, err, fields)
		return nil, err
	}

	// This implementation only supports non-streaming stats retrieval.
	if stream {
		err := errors.New("streaming stats not supported by this function, use Docker client directly or implement a dedicated streaming handler")
		m.LogError(ContainerOperationStats, err, fields)
		return nil, err
	}

	// Use default timeout for single shot stats retrieval
	opCtx, cancel := m.GetContextWithTimeout(0)
	defer cancel()

	resp, err := m.client.ContainerStats(opCtx, containerID, false) // Force stream=false
	if err != nil {
		if client.IsErrNotFound(err) {
			m.LogError(ContainerOperationStats, ErrContainerNotFound, fields)
			return nil, ErrContainerNotFound
		}
		wrappedErr := fmt.Errorf("%w getting stats: %v", ErrOperationFailed, err)
		m.LogError(ContainerOperationStats, wrappedErr, fields)
		return nil, wrappedErr
	}
	defer resp.Body.Close()

	// Decode the single stats object for non-streaming requests
	var dockerStats container.StatsResponse // Use the correct Docker API type
	if err := json.NewDecoder(resp.Body).Decode(&dockerStats); err != nil {
		wrappedErr := fmt.Errorf("failed to decode stats JSON: %w", err)
		m.LogError(ContainerOperationStats, wrappedErr, fields)
		return nil, wrappedErr
	}

	// Convert Docker API stats to internal model stats
	modelStats := models.FromDockerStatsJSON(&dockerStats) // Use the conversion function
	if modelStats == nil {
		// This should ideally not happen if decoding succeeded, but handle defensively
		err := errors.New("failed to convert Docker stats to internal model")
		m.LogError(ContainerOperationStats, err, fields)
		return nil, err
	}

	m.logger.WithFields(fields).Info("Successfully retrieved container stats") // Use logger directly
	return modelStats, nil
}

// IsSensitiveEnvVar checks if an environment variable name is likely sensitive.
func (m *ContainerManager) IsSensitiveEnvVar(name string) bool {
	lowerName := strings.ToLower(name)
	return strings.Contains(lowerName, "pass") || strings.Contains(lowerName, "secret") || strings.Contains(lowerName, "token") || strings.Contains(lowerName, "key")
}
