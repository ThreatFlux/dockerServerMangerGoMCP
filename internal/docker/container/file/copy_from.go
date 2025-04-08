// Package file provides utilities for container file operations
package file

import (
	"context"
	// "errors" // Removed unused import
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container" // Uncommented import
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils/archiver"
)

// isNotFoundError checks if an error indicates a "not found" condition.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	// Check common Docker error strings for "not found" or "no such file"
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no such file or directory")
}

// CopyFromOptions defines options for copying files from a container
type CopyFromOptions struct {
	// AllowOverwriteDirWithFile specifies whether to allow overwriting a directory with a file
	AllowOverwriteDirWithFile bool

	// CopyUIDGID specifies whether to copy UID/GID ownership
	CopyUIDGID bool

	// Timeout is the timeout for the operation
	Timeout time.Duration

	// Logger for logging
	Logger *logrus.Logger
}

// CopyFromContainer copies a file or directory from a container
func CopyFromContainer(ctx context.Context, client client.APIClient, containerID, srcPath, dstPath string, options CopyFromOptions) error {
	// Validate inputs
	if containerID == "" {
		return fmt.Errorf("%w: empty container ID", ErrInvalidPath)
	}
	if srcPath == "" {
		return fmt.Errorf("%w: empty source path", ErrInvalidPath)
	}
	if dstPath == "" {
		return fmt.Errorf("%w: empty destination path", ErrInvalidPath)
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

	// Check if the container exists
	_, err := client.ContainerInspect(ctx, containerID)
	if err != nil {
		if isNotFoundError(err) {
			return fmt.Errorf("%w: container ID %s", ErrContainerNotFound, containerID)
		}
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	// Stat the path inside the container to check if it exists and is a directory
	_, err = statPathInContainer(ctx, client, containerID, srcPath) // Use _ for unused stat
	if err != nil {
		return err // Error already formatted by statPathInContainer
	}

	// Get the archive stream from the container
	reader, _, err := client.CopyFromContainer(ctx, containerID, srcPath)
	if err != nil {
		return fmt.Errorf("failed to copy from container: %w", err)
	}
	defer reader.Close()

	// Prepare destination path
	dstExists := true
	dstInfo, err := os.Stat(dstPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat destination path %s: %w", dstPath, err)
		}
		dstExists = false
	}

	extractPath := dstPath
	// If the destination exists and is a directory, extract *into* it.
	// Otherwise, extract *to* the specified dstPath (creating parent dirs if needed).
	if dstExists && dstInfo.IsDir() {
		// No change needed, extractPath is already dstPath
	} else if !dstExists {
		parentDir := filepath.Dir(dstPath)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return fmt.Errorf("failed to create destination directory %s: %w", parentDir, err)
		}
		extractPath = dstPath
	}

	// Extract the archive to the destination path
	extractOptions := archiver.ArchiveOptions{ // Use archiver.ArchiveOptions
		PreserveOwnership: options.CopyUIDGID,
		Overwrite:         options.AllowOverwriteDirWithFile, // Map AllowOverwriteDirWithFile to Overwrite
		// Assuming default compression (Gzip) is acceptable for extraction detection
		Compression: archiver.CompressionGzip,
		// PreservePaths and PreservePermissions are often default true in extraction tools
		PreservePaths:       true,
		PreservePermissions: true,
	}

	logger.WithFields(logrus.Fields{
		"container": containerID,
		"src":       srcPath,
		"dst":       extractPath,
	}).Info("Extracting archive from container")

	if err := archiver.ExtractArchive(reader, extractPath, extractOptions); err != nil { // Use archiver.ExtractArchive
		return fmt.Errorf("failed to extract archive to %s: %w", extractPath, err)
	}

	logger.WithFields(logrus.Fields{
		"container": containerID,
		"src":       srcPath,
		"dst":       extractPath,
	}).Info("Successfully copied files from container")

	return nil
}

// statPathInContainer checks if a path exists in the container and returns its stat info.
func statPathInContainer(ctx context.Context, client client.APIClient, containerID, path string) (container.PathStat, error) { // Use container.PathStat
	stat, err := client.ContainerStatPath(ctx, containerID, path)
	if err != nil {
		if isNotFoundError(err) {
			return container.PathStat{}, fmt.Errorf("path not found in container %s: %s", containerID, path) // Use container.PathStat
		}
		return container.PathStat{}, fmt.Errorf("failed to stat path '%s' in container %s: %w", path, containerID, err) // Use container.PathStat
	}
	return stat, nil
}

// --- Functions related to copying TO container were moved to copy_to.go ---

// Helper function to check if an error is a "not found" error
// Moved to top level as it's used by both copy_to and copy_from logic potentially

// --- Additional helper functions if needed ---

// ListContainerFiles lists files within a specific directory in a container.
// Note: This requires executing 'ls' or similar inside the container.
func ListContainerFiles(ctx context.Context, client client.APIClient, containerID, path string) ([]string, error) {
	// Sanitize path to prevent command injection issues
	cleanPath := sanitizePath(path)

	// Prepare the command to list files
	cmd := []string{"ls", "-1", cleanPath}

	// Create exec configuration
	execConfig := container.ExecOptions{ // Use container.ExecOptions
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true, // Capture errors from ls itself
	}

	// Create the exec instance
	execResp, err := client.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		if isNotFoundError(err) {
			return nil, fmt.Errorf("%w: container ID %s", ErrContainerNotFound, containerID)
		}
		return nil, fmt.Errorf("failed to create exec instance for ls: %w", err)
	}

	// Attach to the exec instance to get the output stream
	attachResp, err := client.ContainerExecAttach(ctx, execResp.ID, container.ExecStartOptions{}) // Use container.ExecStartOptions
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec instance for ls: %w", err)
	}
	defer attachResp.Close()

	// Read the output
	outputBytes, err := io.ReadAll(attachResp.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read exec output for ls: %w", err)
	}

	// Check the exit code after reading output
	inspectResp, err := client.ContainerExecInspect(ctx, execResp.ID)
	if err != nil {
		logrus.WithError(err).Warnf("Failed to inspect exec instance %s after running ls", execResp.ID)
	} else if inspectResp.ExitCode != 0 {
		return nil, fmt.Errorf("ls command failed in container (exit code %d): %s", inspectResp.ExitCode, string(outputBytes))
	}

	// Split the output into lines (filenames)
	outputStr := string(outputBytes)
	files := strings.Split(strings.TrimSpace(outputStr), "\n")

	// Filter out empty strings that might result from splitting
	var validFiles []string
	for _, f := range files {
		if f != "" {
			validFiles = append(validFiles, f)
		}
	}

	return validFiles, nil
}

// CheckFileExists checks if a specific file or directory exists within a container.
func CheckFileExists(ctx context.Context, client client.APIClient, containerID, path string) (bool, error) {
	_, err := statPathInContainer(ctx, client, containerID, path)
	if err != nil {
		if strings.Contains(err.Error(), "path not found") {
			return false, nil // Explicitly not found
		}
		return false, err // Other error occurred
	}
	return true, nil // Stat successful, path exists
}

// getContainerPathStat is a duplicate of statPathInContainer, removing it.
// func getContainerPathStat(ctx context.Context, client client.APIClient, containerID, path string) (container.PathStat, error) { // Use container.PathStat
// 	stat, err := client.ContainerStatPath(ctx, containerID, path)
// 	if err != nil {
// 		if isNotFoundError(err) {
// 			return container.PathStat{}, fmt.Errorf("path not found: %s", path) // Use container.PathStat
// 		}
// 		return container.PathStat{}, fmt.Errorf("failed to stat path '%s': %w", path, err) // Use container.PathStat
// 	}
// 	return stat, nil
// }
