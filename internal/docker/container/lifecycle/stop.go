// Package lifecycle implements Docker container lifecycle operations.
package lifecycle

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container" // Added import
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// StopOptions contains options for stopping a container
type StopOptions struct {
	// ID of the container to stop
	ContainerID string `json:"container_id"`

	// Name of the container to stop (alternative to ID)
	ContainerName string `json:"container_name"`

	// Timeout in seconds before killing the container (default: 10)
	Timeout int `json:"timeout"`

	// OperationTimeout is the overall operation timeout in seconds
	OperationTimeout int `json:"operation_timeout"`

	// Force indicates whether to force kill the container if it cannot be stopped
	Force bool `json:"force"`

	// WaitForStop indicates whether to wait for the container to fully stop
	WaitForStop bool `json:"wait_for_stop"`

	// WaitTimeout is the timeout for waiting for a container to stop
	WaitTimeout int `json:"wait_timeout"`

	// Signal is the signal to send to the container (e.g. "SIGTERM")
	// If empty, the default stop signal for the container will be used
	Signal string `json:"signal"`

	// OnlySendSignal indicates whether to only send the signal without waiting
	OnlySendSignal bool `json:"only_send_signal"`
}

// StopResult contains the result of a container stop operation
type StopResult struct {
	// ContainerID is the ID of the stopped container
	ContainerID string `json:"container_id"`

	// ContainerName is the name of the stopped container
	ContainerName string `json:"container_name"`

	// Success indicates whether the stop operation was successful
	Success bool `json:"success"`

	// Stopped indicates whether the container was actually stopped
	// This is false if the container was already stopped
	Stopped bool `json:"stopped"`

	// WasStopped indicates whether the container was already stopped
	WasStopped bool `json:"was_stopped"`

	// WasKilled indicates whether the container was forcibly killed
	WasKilled bool `json:"was_killed"`

	// ExitCode is the exit code of the container (if available)
	ExitCode int `json:"exit_code,omitempty"`

	// StopDuration is the time it took to stop the container
	StopDuration string `json:"stop_duration,omitempty"`

	// Error contains the error message, if the operation failed
	Error string `json:"error,omitempty"`

	// InitialState is the container state before stopping
	InitialState string `json:"initial_state,omitempty"`

	// FinalState is the container state after stopping
	FinalState string `json:"final_state,omitempty"`

	// MessageDetail contains additional information about the operation
	MessageDetail string `json:"message_detail,omitempty"`
}

// Stopper manages container stop operations
type Stopper struct {
	containerManager *ContainerManager
	logger           *logrus.Logger
}

// NewStopper creates a new container stopper
func NewStopper(containerManager *ContainerManager) *Stopper {
	return &Stopper{
		containerManager: containerManager,
		logger:           containerManager.logger,
	}
}

// Stop stops a container with the given options
func (s *Stopper) Stop(ctx context.Context, opts StopOptions) (*StopResult, error) {
	// Initialize result
	result := &StopResult{
		Success: false,
		Stopped: false,
	}

	// Validate options and resolve container ID/name
	containerID, err := s.validateAndResolveContainer(ctx, opts)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.ContainerID = containerID

	// Apply operation timeout if specified
	if opts.OperationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.OperationTimeout)*time.Second)
		defer cancel()
	}

	// Record start time for calculating stop duration
	startTime := time.Now()

	// Get container details before stopping
	containerBefore, err := s.containerManager.InspectContainer(ctx, containerID)
	if err != nil {
		result.Error = fmt.Sprintf("failed to inspect container before stopping: %v", err)
		return result, errors.Wrap(err, "failed to inspect container before stopping")
	}

	result.ContainerName = strings.TrimPrefix(containerBefore.Name, "/")
	result.InitialState = containerBefore.State.Status

	// Check if container is already stopped
	if !containerBefore.State.Running {
		result.WasStopped = true
		result.Success = true
		result.FinalState = containerBefore.State.Status

		// Get exit code if available
		if containerBefore.State.ExitCode != 0 {
			result.ExitCode = containerBefore.State.ExitCode
		}

		s.logger.WithFields(logrus.Fields{
			"container_id":   containerID,
			"container_name": result.ContainerName,
			"state":          containerBefore.State.Status,
		}).Info("Container is already stopped")

		return result, nil
	}

	// Determine stop timeout
	stopTimeout := 10 // Default 10 seconds
	if opts.Timeout > 0 {
		stopTimeout = opts.Timeout
	}

	// Log operation
	s.containerManager.LogOperation(ContainerOperationStop, logrus.Fields{
		"container_id":   containerID,
		"container_name": result.ContainerName,
		"timeout":        stopTimeout,
		"force":          opts.Force,
		"signal":         opts.Signal,
	})

	// If only sending signal, use the container kill method with the specified signal
	if opts.OnlySendSignal && opts.Signal != "" {
		err = s.containerManager.client.ContainerKill(ctx, containerID, opts.Signal)
		if err != nil {
			result.Error = fmt.Sprintf("failed to send signal to container: %v", err)
			return result, errors.Wrap(err, "failed to send signal to container")
		}

		result.Success = true
		result.Stopped = false
		result.MessageDetail = fmt.Sprintf("Signal %s sent to container", opts.Signal)

		// Get container details after signal
		containerAfter, err := s.containerManager.InspectContainer(ctx, containerID)
		if err == nil {
			result.FinalState = containerAfter.State.Status
			// If the container stopped due to the signal
			if !containerAfter.State.Running {
				result.Stopped = true
				result.ExitCode = containerAfter.State.ExitCode
			}
		}

		return result, nil
	}

	// Stop the container
	timeoutPtr := stopTimeout // Create pointer for StopOptions
	err = s.containerManager.client.ContainerStop(ctx, containerID, container.StopOptions{
		Timeout: &timeoutPtr,
		Signal:  opts.Signal,
	})

	// Handle stop error
	if err != nil {
		// If force is enabled, try to kill the container
		if opts.Force {
			s.logger.WithFields(logrus.Fields{
				"container_id": containerID,
				"error":        err.Error(),
			}).Warning("Failed to stop container gracefully, trying force kill")

			killErr := s.containerManager.client.ContainerKill(ctx, containerID, "SIGKILL")
			if killErr != nil {
				result.Error = fmt.Sprintf("failed to kill container after stop failure: %v (original: %v)", killErr, err)
				return result, errors.Wrap(err, "failed to stop container and force kill also failed")
			}

			result.WasKilled = true
			result.Stopped = true
			result.MessageDetail = "Container was forcefully killed after graceful stop failed"
		} else {
			result.Error = fmt.Sprintf("failed to stop container: %v", err)
			return result, errors.Wrap(err, "failed to stop container")
		}
	} else {
		result.Stopped = true
	}

	// Calculate stop duration
	stopDuration := time.Since(startTime)
	result.StopDuration = stopDuration.String()

	// Wait for container to fully stop if requested
	if opts.WaitForStop {
		waitTimeout := 30 // Default 30 seconds
		if opts.WaitTimeout > 0 {
			waitTimeout = opts.WaitTimeout
		}

		waitCtx, waitCancel := context.WithTimeout(ctx, time.Duration(waitTimeout)*time.Second)
		defer waitCancel()

		statusCh, errCh := s.containerManager.client.ContainerWait(waitCtx, containerID, container.WaitConditionNotRunning)

		select {
		case err := <-errCh:
			if err != nil {
				s.logger.WithFields(logrus.Fields{
					"container_id": containerID,
					"error":        err.Error(),
				}).Warning("Error waiting for container to stop")

				// Don't fail the operation if waiting fails but container was actually stopped
				if !result.WasKilled {
					result.MessageDetail = fmt.Sprintf("Container stop initiated, but error waiting for completion: %v", err)
				}
			}
		case status := <-statusCh:
			result.ExitCode = int(status.StatusCode)
			result.MessageDetail = "Container stopped successfully and wait completed"
		case <-waitCtx.Done():
			if waitCtx.Err() == context.DeadlineExceeded {
				result.MessageDetail = "Container stop initiated, but wait for completion timed out"
			} else {
				result.MessageDetail = "Container stop initiated, but wait was cancelled"
			}
		}
	}

	// Get container details after stopping
	containerAfter, err := s.containerManager.InspectContainer(ctx, containerID)
	if err != nil {
		// Don't fail the operation if inspection fails
		s.logger.WithFields(logrus.Fields{
			"container_id": containerID,
			"error":        err.Error(),
		}).Warning("Failed to inspect container after stopping")

		result.Success = true
		return result, nil
	}

	result.FinalState = containerAfter.State.Status
	result.Success = !containerAfter.State.Running

	// Get exit code if available
	if containerAfter.State.ExitCode != 0 {
		result.ExitCode = containerAfter.State.ExitCode
	}

	return result, nil
}

// StopMultiple stops multiple containers in sequence
func (s *Stopper) StopMultiple(ctx context.Context, containerIDs []string, options StopOptions) (map[string]*StopResult, error) {
	results := make(map[string]*StopResult)
	var firstError error

	for _, containerID := range containerIDs {
		// Update options with current container ID
		options.ContainerID = containerID

		// Stop the container
		result, err := s.Stop(ctx, options)

		// Store the result
		results[containerID] = result

		// Store the first error encountered
		if err != nil && firstError == nil {
			firstError = err
		}
	}

	return results, firstError
}

// ForceKill forcefully kills a container without graceful shutdown
func (s *Stopper) ForceKill(ctx context.Context, containerID string, signal string) (*StopResult, error) {
	// Initialize result
	result := &StopResult{
		ContainerID: containerID,
		Success:     false,
		Stopped:     false,
		WasKilled:   true,
	}

	// If no signal specified, use SIGKILL
	if signal == "" {
		signal = "SIGKILL"
	}

	// Get container details before killing
	containerBefore, err := s.containerManager.InspectContainer(ctx, containerID)
	if err != nil {
		result.Error = fmt.Sprintf("failed to inspect container before killing: %v", err)
		return result, errors.Wrap(err, "failed to inspect container before killing")
	}

	result.ContainerName = strings.TrimPrefix(containerBefore.Name, "/")
	result.InitialState = containerBefore.State.Status

	// Check if container is already stopped
	if !containerBefore.State.Running {
		result.WasStopped = true
		result.Success = true
		result.FinalState = containerBefore.State.Status

		// Get exit code if available
		if containerBefore.State.ExitCode != 0 {
			result.ExitCode = containerBefore.State.ExitCode
		}

		return result, nil
	}

	// Log operation
	s.containerManager.LogOperation(ContainerOperationKill, logrus.Fields{
		"container_id": containerID,
		"signal":       signal,
	})

	// Kill the container
	err = s.containerManager.client.ContainerKill(ctx, containerID, signal)
	if err != nil {
		result.Error = fmt.Sprintf("failed to kill container: %v", err)
		return result, errors.Wrap(err, "failed to kill container")
	}

	result.Stopped = true
	result.WasKilled = true

	// Get container details after killing
	containerAfter, err := s.containerManager.InspectContainer(ctx, containerID)
	if err != nil {
		// Don't fail the operation if inspection fails
		s.logger.WithFields(logrus.Fields{
			"container_id": containerID,
			"error":        err.Error(),
		}).Warning("Failed to inspect container after killing")

		result.Success = true
		return result, nil
	}

	result.FinalState = containerAfter.State.Status
	result.Success = !containerAfter.State.Running

	// Get exit code if available
	if containerAfter.State.ExitCode != 0 {
		result.ExitCode = containerAfter.State.ExitCode
	}

	return result, nil
}

// validateAndResolveContainer validates options and resolves container name to ID if needed
func (s *Stopper) validateAndResolveContainer(ctx context.Context, opts StopOptions) (string, error) {
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

	for _, c := range containers { // Renamed variable to avoid conflict
		for _, name := range c.Names {
			// Docker adds a leading slash to container names
			if strings.TrimPrefix(name, "/") == opts.ContainerName {
				return c.ID, nil
			}
		}
	}

	return "", errors.Errorf("container with name %s not found", opts.ContainerName)
}

// ToModel converts a StopResult to a ContainerOperation
func (s *Stopper) ToModel(result *StopResult) ContainerOperation { // Use ContainerOperation from this package
	status := "success"
	if !result.Success {
		status = "error"
	}

	// Return type should match the definition in common.go
	return ContainerOperation(fmt.Sprintf( // Use ContainerOperation from this package
		"Operation: stop, ContainerID: %s, Name: %s, Status: %s, Message: %s, Error: %s",
		result.ContainerID,
		result.ContainerName,
		status,
		result.MessageDetail,
		result.Error,
	))
}
