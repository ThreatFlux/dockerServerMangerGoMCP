package exec

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/sirupsen/logrus"
)

// Info represents information about an exec instance
type Info struct {
	ID          string    `json:"id"`
	ContainerID string    `json:"container_id"`
	Command     []string  `json:"command"`
	User        string    `json:"user"`
	Running     bool      `json:"running"`
	ExitCode    int       `json:"exit_code"`
	Pid         int       `json:"pid"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	FinishedAt  time.Time `json:"finished_at,omitempty"`
	Privileged  bool      `json:"privileged"`
	OpenStdin   bool      `json:"open_stdin"`
	OpenStdout  bool      `json:"open_stdout"`
	OpenStderr  bool      `json:"open_stderr"`
	// Revert ProcessConfig/ExecConfig field for now
	// ProcessConfig types.ExecConfig `json:"process_config"`
}

// InspectOptions defines options for inspecting an exec instance
type InspectOptions struct {
	Timeout time.Duration
	Logger  *logrus.Logger
}

// Inspect inspects an exec instance
func Inspect(ctx context.Context, client client.APIClient, execID string, options InspectOptions) (*Info, error) {
	if execID == "" {
		return nil, fmt.Errorf("empty exec ID")
	}

	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// client.ContainerExecInspect returns types.ContainerExecInspect
	execInspect, err := client.ContainerExecInspect(ctx, execID)
	if err != nil {
		if errdefs.IsNotFound(err) { // Use errdefs.IsNotFound
			return nil, fmt.Errorf("%w: %s", ErrExecNotFound, execID)
		}
		return nil, fmt.Errorf("failed to inspect exec instance: %w", err)
	}

	// Create exec info - temporarily remove ProcessConfig related fields
	execInfo := &Info{
		ID:          execID,
		ContainerID: execInspect.ContainerID,
		Running:     execInspect.Running,
		ExitCode:    execInspect.ExitCode,
		Pid:         execInspect.Pid,
		// Command:    ?, // Cannot determine command reliably yet
		// User:       ?, // Cannot determine user reliably yet
		// Privileged: ?, // Cannot determine privileged status reliably yet
		// OpenStdin:  ?, // Cannot determine stdin status reliably yet
		// OpenStdout: ?, // Cannot determine stdout status reliably yet
		// OpenStderr: ?, // Cannot determine stderr status reliably yet
	}

	// TODO: Investigate the structure of types.ContainerExecInspect in v27.1.1
	// and correctly populate Command, User, Privileged, OpenStdin, OpenStdout, OpenStderr.
	// Example: It might be execInspect.ProcessConfig.Cmd, execInspect.Config.Cmd, or directly execInspect.Cmd

	logger.WithFields(logrus.Fields{
		"exec_id":      execID,
		"container_id": execInspect.ContainerID,
		"running":      execInspect.Running,
		"exit_code":    execInspect.ExitCode,
	}).Debug("Inspected exec instance")

	return execInfo, nil
}

// InspectMultiple inspects multiple exec instances
func InspectMultiple(ctx context.Context, client client.APIClient, execIDs []string, options InspectOptions) (map[string]*Info, error) {
	if len(execIDs) == 0 {
		return nil, fmt.Errorf("no exec IDs provided")
	}

	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	result := make(map[string]*Info)
	var firstErr error

	for _, execID := range execIDs {
		execInfo, err := Inspect(ctx, client, execID, options)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"exec_id": execID,
				"error":   err.Error(),
			}).Warn("Failed to inspect exec instance")

			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		result[execID] = execInfo
	}

	if len(result) == 0 && firstErr != nil {
		return nil, firstErr
	}

	return result, nil
}

// ListExecs lists all exec instances for a container (UNRELIABLE)
func ListExecs(ctx context.Context, client client.APIClient, containerID string, options InspectOptions) ([]*Info, error) {
	if containerID == "" {
		return nil, fmt.Errorf("empty container ID")
	}
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	_, err := client.ContainerInspect(ctx, containerID)
	if err != nil {
		if errdefs.IsNotFound(err) { // Use errdefs.IsNotFound
			return nil, fmt.Errorf("%w: %s", ErrContainerNotFound, containerID)
		}
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	logger.Warn("ListExecs function is unreliable and likely returns an empty list.")
	return []*Info{}, nil // Return empty list as this method is unreliable
}

// WaitForExecToComplete waits for an exec instance to complete
func WaitForExecToComplete(ctx context.Context, client client.APIClient, execID string, timeout time.Duration) (int, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	for {
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		default:
			inspectResult, err := client.ContainerExecInspect(ctx, execID)
			if err != nil {
				if errdefs.IsNotFound(err) { // Use errdefs.IsNotFound
					return -1, fmt.Errorf("%w: %s", ErrExecNotFound, execID)
				}
				return -1, fmt.Errorf("failed to inspect exec instance: %w", err)
			}
			if !inspectResult.Running {
				return inspectResult.ExitCode, nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// GetRunningExecsCount gets the number of running execs for a container (UNRELIABLE)
func GetRunningExecsCount(ctx context.Context, client client.APIClient, containerID string, options InspectOptions) (int, error) {
	execs, err := ListExecs(ctx, client, containerID, options)
	if err != nil {
		return 0, err
	}
	runningCount := 0
	for _, exec := range execs {
		if exec != nil && exec.Running {
			runningCount++
		}
	}
	return runningCount, nil
}

// JSON serializes an ExecInfo to JSON
func (e *Info) JSON() ([]byte, error) {
	return json.Marshal(e)
}

// String returns a string representation of an ExecInfo
func (e *Info) String() string {
	var status string
	if e.Running {
		status = "Running"
	} else {
		status = fmt.Sprintf("Exited with code %d", e.ExitCode)
	}
	// Command might be empty now
	return fmt.Sprintf("Exec ID: %s, Container ID: %s, Command: %v, Status: %s",
		e.ID, e.ContainerID, e.Command, status)
}
