// Package exec provides functionality for executing commands in Docker containers.
package exec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	containertypes "github.com/docker/docker/api/types/container" // Added import alias
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs" // Added for error checking
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// Common errors
var (
	// ErrContainerNotFound indicates the container was not found
	ErrContainerNotFound = errors.New("container not found")

	// ErrContainerNotRunning indicates the container is not running
	ErrContainerNotRunning = errors.New("container not running")

	// ErrInvalidCommand indicates an invalid command
	ErrInvalidCommand = errors.New("invalid command")

	// ErrExecNotFound indicates the exec instance was not found
	ErrExecNotFound = errors.New("exec instance not found")

	// ErrExecCreateFailed indicates exec creation failed
	ErrExecCreateFailed = errors.New("exec creation failed")
)

// ExecConfig defines configuration for creating an exec instance
type ExecConfig struct {
	// Command to execute in the container
	Cmd []string

	// User that will run the command
	User string

	// AttachStdin indicates whether to attach to stdin
	AttachStdin bool

	// AttachStdout indicates whether to attach to stdout
	AttachStdout bool

	// AttachStderr indicates whether to attach to stderr
	AttachStderr bool

	// Tty indicates whether to allocate a TTY
	Tty bool

	// DetachKeys is the key sequence used to detach from the container
	DetachKeys string

	// Env are additional environment variables
	Env []string

	// WorkingDir is the working directory
	WorkingDir string

	// Privileged indicates whether to run the command with extended privileges
	Privileged bool

	// SecurityOpts are security options
	SecurityOpts []string
}

// CreateOptions defines options for creating an exec instance
type CreateOptions struct {
	// Timeout is the timeout for the operation
	Timeout time.Duration

	// Logger for logging
	Logger *logrus.Logger

	// SecurityValidator validates security settings
	SecurityValidator func(config ExecConfig) error
}

// DefaultSecurityValidator is the default security validator
var DefaultSecurityValidator = func(config ExecConfig) error {
	// Check for dangerous commands
	dangerousCommands := []string{
		"rm -rf /", "mkfs", "dd", "reboot", "shutdown", "halt", "poweroff",
		"init", "chmod -R 777", "chown -R", "iptables", "route",
	}

	cmdStr := strings.Join(config.Cmd, " ")
	for _, dc := range dangerousCommands {
		if strings.Contains(cmdStr, dc) {
			return fmt.Errorf("potentially dangerous command detected: %s", dc)
		}
	}

	// Check for privileged mode
	if config.Privileged {
		return fmt.Errorf("privileged mode not allowed")
	}

	return nil
}

// Create creates an exec instance in a container
func Create(ctx context.Context, client client.APIClient, containerID string, config ExecConfig, options CreateOptions) (string, error) {
	// Validate inputs
	if containerID == "" {
		return "", fmt.Errorf("empty container ID")
	}

	if len(config.Cmd) == 0 {
		return "", fmt.Errorf("%w: empty command", ErrInvalidCommand)
	}

	// Use default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Validate security
	securityValidator := options.SecurityValidator
	if securityValidator == nil {
		securityValidator = DefaultSecurityValidator
	}

	if err := securityValidator(config); err != nil {
		return "", fmt.Errorf("security validation failed: %w", err)
	}

	// Check if the container exists and is running
	containerJSON, err := client.ContainerInspect(ctx, containerID)
	if err != nil {
		if errdefs.IsNotFound(err) { // Use errdefs.IsNotFound
			return "", fmt.Errorf("%w: %s", ErrContainerNotFound, containerID)
		}
		return "", fmt.Errorf("failed to inspect container: %w", err)
	}

	// Check if the container is running
	if !containerJSON.State.Running {
		return "", fmt.Errorf("%w: %s", ErrContainerNotRunning, containerID)
	}

	// Create Docker exec config using containertypes.ExecOptions
	execConfig := containertypes.ExecOptions{
		User:         config.User,
		Privileged:   config.Privileged,
		Tty:          config.Tty,
		AttachStdin:  config.AttachStdin,
		AttachStdout: config.AttachStdout,
		AttachStderr: config.AttachStderr,
		DetachKeys:   config.DetachKeys,
		Cmd:          config.Cmd,
		Env:          config.Env,
		WorkingDir:   config.WorkingDir,
	}

	// Create exec instance
	execCreateResp, err := client.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrExecCreateFailed, err)
	}

	// Log exec creation
	logger.WithFields(logrus.Fields{
		"container_id": containerID,
		"exec_id":      execCreateResp.ID,
		"command":      strings.Join(config.Cmd, " "),
	}).Debug("Created exec instance")

	return execCreateResp.ID, nil
}

// CreateAndWait creates an exec instance and waits for it to complete
func CreateAndWait(ctx context.Context, client client.APIClient, containerID string, config ExecConfig, options CreateOptions) (int, []byte, []byte, error) {
	// Create exec instance
	execID, err := Create(ctx, client, containerID, config, options)
	if err != nil {
		return -1, nil, nil, err
	}

	// Set up options for starting the exec instance
	startOptions := StartOptions{
		Timeout: options.Timeout,
		Logger:  options.Logger,
	}

	// Start and wait for the exec instance
	exitCode, stdout, stderr, err := StartAndWait(ctx, client, execID, startOptions)
	if err != nil {
		return -1, nil, nil, err
	}

	return exitCode, stdout, stderr, nil
}

// CreateMultiple creates multiple exec instances in a container
func CreateMultiple(ctx context.Context, client client.APIClient, containerID string, configs []ExecConfig, options CreateOptions) ([]string, error) {
	// Validate inputs
	if containerID == "" {
		return nil, fmt.Errorf("empty container ID")
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("no exec configs provided")
	}

	// Use default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Create a throttle to limit API calls
	throttle := utils.NewThrottle(10, time.Second) // Max 10 API calls per second

	// Create exec instances
	var execIDs []string
	for i, config := range configs {
		// Wait for throttle
		if err := throttle.Wait(ctx); err != nil {
			return execIDs, fmt.Errorf("throttle error: %w", err)
		}

		// Create exec instance
		execID, err := Create(ctx, client, containerID, config, options)
		if err != nil {
			return execIDs, fmt.Errorf("failed to create exec instance %d: %w", i, err)
		}

		execIDs = append(execIDs, execID)
	}

	return execIDs, nil
}

// ValidateUser validates a user for exec
func ValidateUser(user string) bool {
	// Check for empty user (defaults to root)
	if user == "" {
		return true
	}

	// Check for user:group format
	parts := strings.Split(user, ":")
	if len(parts) > 2 {
		return false
	}

	// Check for numeric user
	if strings.Contains(parts[0], ".") {
		return false
	}

	// Check for numeric group if specified
	if len(parts) == 2 && strings.Contains(parts[1], ".") {
		return false
	}

	return true
}

// SanitizeCommand sanitizes a command for exec
func SanitizeCommand(cmd []string) ([]string, error) {
	if len(cmd) == 0 {
		return nil, ErrInvalidCommand
	}

	// Shell metacharacters to check for
	shellMetachars := []string{";", "&&", "||", "`", "$", "<", ">", "|", "*", "?", "[", "]", "{", "}", "&"}

	// Check if the command contains shell metacharacters
	cmdStr := strings.Join(cmd, " ")
	for _, meta := range shellMetachars {
		if strings.Contains(cmdStr, meta) {
			// Wrap the command with sh -c if it contains shell metacharacters
			return []string{"sh", "-c", cmdStr}, nil
		}
	}

	return cmd, nil
}
