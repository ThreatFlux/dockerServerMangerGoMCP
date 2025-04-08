// Package lifecycle implements Docker container lifecycle operations.
package lifecycle

import (
	"context"
	"fmt"
	"strings"
	"time"

	// "github.com/docker_test/docker_test/api/types" // Removed unused import
	"github.com/docker/docker/api/types/container" // Added for container.StopOptions, container.LogsOptions, container.ListOptions, container.StartOptions
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Removed unused import
)

// StartOptions contains options for starting a container
type StartOptions struct {
	// ID of the container to start
	ContainerID string `json:"container_id"`

	// Name of the container to start (alternative to ID)
	ContainerName string `json:"container_name"`

	// CheckHealthStatus indicates whether to check health status after starting
	CheckHealthStatus bool `json:"check_health_status"`

	// HealthCheckTimeout is the timeout for health check in seconds
	HealthCheckTimeout int `json:"health_check_timeout"`

	// HealthCheckInterval is the interval between health checks in milliseconds
	HealthCheckInterval int `json:"health_check_interval"`

	// Timeout is the operation timeout in seconds
	Timeout int `json:"timeout"`

	// MaxRetries is the maximum number of retries for start operation
	MaxRetries int `json:"max_retries"`

	// LogOutput determines whether to log container output during start
	LogOutput bool `json:"log_output"`

	// LogOutputLines is the number of log lines to capture
	LogOutputLines int `json:"log_output_lines"`
}

// StartResult contains the result of a container start operation
type StartResult struct {
	// ContainerID is the ID of the started container
	ContainerID string `json:"container_id"`

	// ContainerName is the name of the started container
	ContainerName string `json:"container_name"`

	// Success indicates whether the start operation was successful
	Success bool `json:"success"`

	// Started indicates whether the container was actually started (it might have already been running)
	Started bool `json:"started"`

	// AlreadyRunning indicates whether the container was already running
	AlreadyRunning bool `json:"already_running"`

	// HealthStatus contains the health status after starting, if health check was enabled
	HealthStatus string `json:"health_status,omitempty"`

	// Logs contains the start logs, if log capture was enabled
	Logs string `json:"logs,omitempty"`

	// Message contains additional information about the operation
	Message string `json:"message,omitempty"`

	// Error contains the error message, if the operation failed
	Error string `json:"error,omitempty"`

	// InitialState is the container state before starting
	InitialState string `json:"initial_state,omitempty"`

	// FinalState is the container state after starting
	FinalState string `json:"final_state,omitempty"`
}

// Starter manages container start operations
type Starter struct {
	containerManager *ContainerManager
	logger           *logrus.Logger
}

// NewStarter creates a new container starter
func NewStarter(containerManager *ContainerManager) *Starter {
	return &Starter{
		containerManager: containerManager,
		logger:           containerManager.logger,
	}
}

// Start starts a container with the given options
func (s *Starter) Start(ctx context.Context, opts StartOptions) (*StartResult, error) {
	// Initialize result
	result := &StartResult{
		Success: false,
		Started: false,
	}

	// Validate options and resolve container ID/name
	containerID, err := s.validateAndResolveContainer(ctx, opts)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.ContainerID = containerID

	// Apply timeout if specified
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.Timeout)*time.Second)
		defer cancel()
	}

	// Get container details before starting
	containerBefore, err := s.containerManager.InspectContainer(ctx, containerID)
	if err != nil {
		result.Error = fmt.Sprintf("failed to inspect container before starting: %v", err)
		return result, errors.Wrap(err, "failed to inspect container before starting")
	}

	result.ContainerName = strings.TrimPrefix(containerBefore.Name, "/")
	result.InitialState = containerBefore.State.Status

	// Check if container is already running
	if containerBefore.State.Running {
		result.AlreadyRunning = true
		result.Success = true
		result.Message = "container is already running"
		result.FinalState = containerBefore.State.Status

		// If health check is requested, perform it
		if opts.CheckHealthStatus && containerBefore.State.Health != nil {
			result.HealthStatus = containerBefore.State.Health.Status
		}

		return result, nil
	}

	// Set up retries with backoff
	maxRetries := 3
	if opts.MaxRetries > 0 {
		maxRetries = opts.MaxRetries
	}

	// Start container with retries
	var startErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Log operation
		s.containerManager.LogOperation(ContainerOperationStart, logrus.Fields{
			"container_id": containerID,
			"attempt":      attempt + 1,
			"max_attempts": maxRetries + 1,
		})

		// Start the container
		startErr = s.containerManager.client.ContainerStart(ctx, containerID, container.StartOptions{}) // Use container.StartOptions

		// Success - break retry loop
		if startErr == nil {
			result.Started = true
			break
		}

		// Don't retry certain errors
		if client.IsErrNotFound(startErr) ||
			strings.Contains(startErr.Error(), "cannot start a paused container") ||
			strings.Contains(startErr.Error(), "container is already in use") {
			break
		}

		// Check if we reached the maximum number of retries
		if attempt == maxRetries {
			break
		}

		// Calculate backoff delay with jitter (100ms, 200ms, 400ms...)
		backoffDelay := s.calculateBackoffDelay(attempt)

		// Log retry
		s.logger.WithFields(logrus.Fields{
			"container_id": containerID,
			"attempt":      attempt + 1,
			"max_attempts": maxRetries + 1,
			"delay":        backoffDelay.String(),
			"error":        startErr.Error(),
		}).Info("Retrying container start after error")

		// Wait for backoff delay
		select {
		case <-time.After(backoffDelay):
			// Continue to next attempt
		case <-ctx.Done():
			// Context cancelled or timed out
			startErr = errors.Wrap(ctx.Err(), "context cancelled during backoff")
			break // Exit retry loop
		}
		if startErr != nil { // Check if context error occurred
			break
		}
	}

	// Handle start error
	if startErr != nil {
		result.Error = fmt.Sprintf("failed to start container: %v", startErr)
		return result, errors.Wrap(startErr, "failed to start container after retries")
	}

	// Get container details after starting
	containerAfter, err := s.containerManager.InspectContainer(ctx, containerID)
	if err != nil {
		// Container started but we couldn't inspect it
		result.Success = true
		result.Error = fmt.Sprintf("container started, but failed to inspect: %v", err)
		return result, nil
	}

	result.FinalState = containerAfter.State.Status
	result.Success = containerAfter.State.Running

	// Capture logs if requested
	if opts.LogOutput && result.Success {
		logs, err := s.containerManager.GetContainerLogs(ctx, containerID, container.LogsOptions{ // Use container.LogsOptions
			ShowStdout: true,
			ShowStderr: true,
			Tail:       fmt.Sprintf("%d", opts.LogOutputLines),
			Timestamps: true,
		})

		if err == nil && logs != nil {
			defer logs.Close()

			// Read logs with a timeout
			logBytes, err := s.containerManager.ReadAllWithTimeout(logs, 5*time.Second)
			if err == nil {
				result.Logs = string(logBytes)
			}
		}
	}

	// Wait for health check if requested
	if opts.CheckHealthStatus && containerAfter.Config.Healthcheck != nil {
		healthStatus, err := s.waitForHealthCheck(ctx, containerID, opts)
		if err != nil {
			result.HealthStatus = "health check failed: " + err.Error()
		} else {
			result.HealthStatus = healthStatus
		}
	}

	return result, nil
}

// StartMultiple starts multiple containers in sequence
func (s *Starter) StartMultiple(ctx context.Context, containerIDs []string, options StartOptions) (map[string]*StartResult, error) {
	results := make(map[string]*StartResult)
	var firstError error

	for _, containerID := range containerIDs {
		// Update options with current container ID
		options.ContainerID = containerID

		// Start the container
		result, err := s.Start(ctx, options)

		// Store the result
		results[containerID] = result

		// Store the first error encountered
		if err != nil && firstError == nil {
			firstError = err
		}
	}

	return results, firstError
}

// validateAndResolveContainer validates options and resolves container name to ID if needed
func (s *Starter) validateAndResolveContainer(ctx context.Context, opts StartOptions) (string, error) {
	// Check if at least one of ID or Name is provided
	if opts.ContainerID == "" && opts.ContainerName == "" {
		return "", errors.New("either container ID or name must be provided")
	}

	// If ID is provided, validate it
	if opts.ContainerID != "" {
		if err := s.containerManager.ValidateContainerID(opts.ContainerID); err != nil {
			return "", errors.Wrap(err, "invalid container ID")
		}
		return opts.ContainerID, nil
	}

	// If only name is provided, resolve it to an ID
	containers, err := s.containerManager.ListContainers(ctx, container.ListOptions{All: true}) // Use container.ListOptions
	if err != nil {
		return "", errors.Wrap(err, "failed to list containers")
	}

	for _, container := range containers {
		for _, name := range container.Names {
			// Docker adds a leading slash to container names
			if strings.TrimPrefix(name, "/") == opts.ContainerName {
				return container.ID, nil
			}
		}
	}

	return "", errors.Errorf("container with name %s not found", opts.ContainerName)
}

// waitForHealthCheck waits for a container's health check to complete
func (s *Starter) waitForHealthCheck(ctx context.Context, containerID string, opts StartOptions) (string, error) {
	// Calculate timeout and interval
	timeout := 30 * time.Second
	if opts.HealthCheckTimeout > 0 {
		timeout = time.Duration(opts.HealthCheckTimeout) * time.Second
	}

	interval := 500 * time.Millisecond
	if opts.HealthCheckInterval > 0 {
		interval = time.Duration(opts.HealthCheckInterval) * time.Millisecond
	}

	// Create a context with timeout
	healthCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Start time for logging
	startTime := time.Now()

	// Poll container health status
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Inspect container
			container, err := s.containerManager.InspectContainer(healthCtx, containerID)
			if err != nil {
				return "", errors.Wrap(err, "failed to inspect container during health check")
			}

			// Check if health info is available
			if container.State.Health == nil {
				return "health check not configured", nil
			}

			// Log current health status
			s.logger.WithFields(logrus.Fields{
				"container_id":  containerID,
				"health_status": container.State.Health.Status,
				"elapsed_time":  time.Since(startTime).String(),
			}).Debug("Container health check status")

			// Check if health status is determined
			switch container.State.Health.Status {
			case "healthy":
				return "healthy", nil
			case "unhealthy":
				return "unhealthy", errors.New("container health check failed")
			case "starting":
				// Continue polling
			default:
				// Unknown status, log it but continue
				s.logger.WithField("status", container.State.Health.Status).Warning("Unknown health status")
			}

		case <-healthCtx.Done():
			// Timeout or context cancelled
			return "timeout", errors.Wrap(healthCtx.Err(), "health check timed out")
		}
	}
}

// calculateBackoffDelay calculates a backoff delay with exponential increase
func (s *Starter) calculateBackoffDelay(attempt int) time.Duration {
	baseDelay := 100 * time.Millisecond
	maxDelay := 10 * time.Second

	// Calculate exponential backoff: 100ms, 200ms, 400ms, 800ms, etc.
	multiplier := 1 << uint(attempt) // 2^attempt
	delay := baseDelay * time.Duration(multiplier)

	// Add jitter (±10%)
	jitter := float64(delay) * 0.1 * (float64(time.Now().Nanosecond()%100)/100.0 - 0.5)
	delay = delay + time.Duration(jitter)

	// Cap at maximum delay
	if delay > maxDelay {
		delay = maxDelay
	}

	return delay
}

// ToModel converts a StartResult to a ContainerOperation
func (s *Starter) ToModel(result *StartResult) ContainerOperation { // Use ContainerOperation from this package
	status := "success"
	if !result.Success {
		status = "error"
	}

	// Return type should match the definition in common.go
	// Assuming ContainerOperation is just a string for now
	return ContainerOperation(fmt.Sprintf( // Use ContainerOperation from this package
		"Operation: start, ContainerID: %s, Name: %s, Status: %s, Message: %s, Error: %s",
		result.ContainerID,
		result.ContainerName,
		status,
		result.Message,
		result.Error,
	))
}
