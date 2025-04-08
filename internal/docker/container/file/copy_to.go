// Package file provides utilities for container file operations
package file

import (
	"archive/tar" // Added import
	"bytes"       // Added import
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils/archiver"
	// "sync" // Removed unused import
	// "sync" // Removed unused import
)

// ProgressCallback is a function that is called with progress updates
type ProgressCallback func(progress float64, bytesProcessed int64, totalBytes int64)

// CopyToOptions defines options for copying files to a container
type CopyToOptions struct {
	// ProgressCallback is called with progress updates if set
	ProgressCallback ProgressCallback

	// Timeout is the timeout for the operation
	Timeout time.Duration

	// Overwrite indicates whether to overwrite existing files
	Overwrite bool

	// PreservePaths indicates whether to preserve paths during extraction
	PreservePaths bool

	// PreservePermissions indicates whether to preserve file permissions
	PreservePermissions bool

	// AllowOverwrite indicates whether overwriting existing files is allowed
	AllowOverwrite bool

	// Logger for logging
	Logger *logrus.Logger
}

// CopyToContainer copies a file or directory to a container
func CopyToContainer(ctx context.Context, client client.APIClient, containerID, srcPath, dstPath string, options CopyToOptions) error {
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

	// Verify the source path exists FIRST
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrFileNotFound, srcPath) // Return error immediately
		}
		return fmt.Errorf("failed to stat source path: %w", err) // Return other stat errors
	}
	// Source path exists, now check container...

	// Check if the container exists and is running
	containerJSON, err := client.ContainerInspect(ctx, containerID)
	if err != nil {
		if isNotFoundError(err) { // Use helper function
			return fmt.Errorf("%w: container ID %s", ErrContainerNotFound, containerID)
		}
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	// Check if the container is running
	if !containerJSON.State.Running {
		return fmt.Errorf("%w: container ID %s", ErrContainerNotRunning, containerID)
	}

	// Create archive from the source path (srcInfo already obtained)
	archiveOptions := archiver.ArchiveOptions{
		Compression:         archiver.CompressionGzip,
		IncludeBaseDir:      false,
		PreservePaths:       options.PreservePaths,
		PreservePermissions: options.PreservePermissions,
	}

	// Create a reader for the archive
	archiveReader, err := archiver.ArchiveFile(srcPath, archiveOptions)
	if err != nil {
		return fmt.Errorf("failed to create archive: %w", err)
	}
	// Assuming ArchiveFile returns io.ReadCloser
	if rc, ok := archiveReader.(io.ReadCloser); ok {
		defer rc.Close()
	}

	// Create a copy operation with progress tracking
	copyOp := &copyOperation{
		client:           client,
		containerID:      containerID,
		srcPath:          srcPath,
		dstPath:          dstPath,
		srcInfo:          srcInfo,
		reader:           archiveReader, // Pass the original reader
		progressCallback: options.ProgressCallback,
		logger:           logger,
	}

	// Execute the copy operation
	if err := copyOp.execute(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrCopyOperationFailed, err)
	}

	return nil
}

// CopyMultipleToContainer copies multiple files or directories to a container
func CopyMultipleToContainer(ctx context.Context, client client.APIClient, containerID string, paths []PathMapping, options CopyToOptions) error {
	// Validate inputs
	if containerID == "" {
		return fmt.Errorf("%w: empty container ID", ErrInvalidPath)
	}

	if len(paths) == 0 {
		return fmt.Errorf("no paths specified")
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

	// Check if the container exists and is running
	containerJSON, err := client.ContainerInspect(ctx, containerID)
	if err != nil {
		if isNotFoundError(err) { // Use helper function
			return fmt.Errorf("%w: container ID %s", ErrContainerNotFound, containerID)
		}
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	// Check if the container is running
	if !containerJSON.State.Running {
		return fmt.Errorf("%w: container ID %s", ErrContainerNotRunning, containerID)
	}

	// Process each path mapping
	for _, pathMapping := range paths {
		// Verify the source path exists
		srcInfo, err := os.Stat(pathMapping.SrcPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%w: %s", ErrFileNotFound, pathMapping.SrcPath)
			}
			return fmt.Errorf("failed to stat source path: %w", err)
		}

		// Create archive from the source path
		archiveOptions := archiver.ArchiveOptions{
			Compression:         archiver.CompressionGzip,
			IncludeBaseDir:      false,
			PreservePaths:       options.PreservePaths,
			PreservePermissions: options.PreservePermissions,
		}

		// Create a reader for the archive
		archiveReader, err := archiver.ArchiveFile(pathMapping.SrcPath, archiveOptions)
		if err != nil {
			return fmt.Errorf("failed to create archive for %s: %w", pathMapping.SrcPath, err)
		}
		// Assuming ArchiveFile returns io.ReadCloser
		if rc, ok := archiveReader.(io.ReadCloser); ok {
			defer rc.Close()
		}

		// Create a copy operation with progress tracking
		copyOp := &copyOperation{
			client:           client,
			containerID:      containerID,
			srcPath:          pathMapping.SrcPath,
			dstPath:          pathMapping.DstPath,
			srcInfo:          srcInfo,
			reader:           archiveReader, // Pass original reader
			progressCallback: options.ProgressCallback,
			logger:           logger,
		}

		// Execute the copy operation
		if err := copyOp.execute(ctx); err != nil {
			return fmt.Errorf("%w: %v for %s -> %s", ErrCopyOperationFailed, err, pathMapping.SrcPath, pathMapping.DstPath)
		}
	}

	return nil
}

// CopyContentToContainer copies content from a reader to a file in a container
func CopyContentToContainer(ctx context.Context, client client.APIClient, containerID string, content io.Reader, dstPath string, mode os.FileMode, options CopyToOptions) error {
	// Validate inputs
	if containerID == "" {
		return fmt.Errorf("%w: empty container ID", ErrInvalidPath)
	}

	if content == nil {
		return fmt.Errorf("nil content reader")
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

	// Check if the container exists and is running
	containerJSON, err := client.ContainerInspect(ctx, containerID)
	if err != nil {
		if isNotFoundError(err) { // Use helper function
			return fmt.Errorf("%w: container ID %s", ErrContainerNotFound, containerID)
		}
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	// Check if the container is running
	if !containerJSON.State.Running {
		return fmt.Errorf("%w: container ID %s", ErrContainerNotRunning, containerID)
	}

	// Create a tar archive containing the content
	now := time.Now()
	tarHeader := &tar.Header{ // Use tar.Header
		Name:    filepath.Base(dstPath),
		Mode:    int64(mode),
		Size:    0, // We'll update this later
		ModTime: now,
	}

	// Create a pipe to write the tar archive
	pr, pw := io.Pipe()
	// var wg sync.WaitGroup // Removed WaitGroup

	// Write the tar archive in a goroutine
	// wg.Add(1) // Removed WaitGroup
	go func() {
		// defer wg.Done() // Removed WaitGroup
		tw := tar.NewWriter(pw) // Use tar.NewWriter
		var err error           // Declare err variable to be visible in the outer defer
		defer func() {
			closeErr := tw.Close()
			if err == nil { // If no previous error, use Close error
				err = closeErr
			}
			// Close the pipe writer
			// Pass the final error (if any) to the reader side
			pw.CloseWithError(err)
		}()

		// Get the content size
		// Removed duplicate closing parenthesis from previous incorrect defer
		var buf bytes.Buffer // Use bytes.Buffer
		size, err := io.Copy(&buf, content)
		if err != nil {
			logger.WithError(err).Error("Failed to read content")
			pw.CloseWithError(err) // Close pipe with error on failure
			return
		}

		// Update the header size
		tarHeader.Size = size

		// Write the header
		if err := tw.WriteHeader(tarHeader); err != nil {
			logger.WithError(err).Error("Failed to write tar header")
			pw.CloseWithError(err) // Close pipe with error on failure
			return
		}

		// Write the content
		if _, err := io.Copy(tw, &buf); err != nil {
			logger.WithError(err).Error("Failed to write content to tar archive")
			pw.CloseWithError(err) // Close pipe with error on failure
			return
		}
	}()

	// Wait for the goroutine to finish writing before proceeding
	// This ensures the pipe reader has all data before CopyToContainer reads it.
	// wg.Wait() // We actually need to wait *after* ensuring the directory exists

	// Create directory path if needed
	dirPath := filepath.Dir(dstPath)
	if dirPath != "." && dirPath != "/" {
		// Ensure the directory exists
		mkdirCmd := []string{"mkdir", "-p", dirPath}
		execConfig := container.ExecOptions{ // Use container.ExecOptions
			Cmd:          mkdirCmd,
			AttachStdout: false,
			AttachStderr: true,
		}

		// Create the exec instance
		execID, err := client.ContainerExecCreate(ctx, containerID, execConfig)
		if err != nil {
			pr.Close()
			return fmt.Errorf("failed to create directory in container: %w", err)
		}

		// Start the exec instance
		err = client.ContainerExecStart(ctx, execID.ID, container.ExecStartOptions{}) // Use container.ExecStartOptions
		if err != nil {
			pr.Close()
			return fmt.Errorf("failed to create directory in container: %w", err)
		}

		// Wait for the exec to complete
		for {
			inspect, err := client.ContainerExecInspect(ctx, execID.ID)
			if err != nil {
				pr.Close()
				return fmt.Errorf("failed to inspect exec: %w", err)
			}
			if !inspect.Running {
				if inspect.ExitCode != 0 {
					pr.Close()
					return fmt.Errorf("failed to create directory in container, exit code: %d", inspect.ExitCode)
				}
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Removed wg.Wait() - Pipe closing handles synchronization

	// Copy the archive to the container
	// Use the correct options type from the container package
	err = client.CopyToContainer(ctx, containerID, filepath.Dir(dstPath), pr, container.CopyToContainerOptions{
		AllowOverwriteDirWithFile: options.AllowOverwrite,
	})
	if err != nil {
		return fmt.Errorf("failed to copy to container: %w", err)
	}

	return nil
}

// PathMapping represents a source to destination path mapping
type PathMapping struct {
	SrcPath string
	DstPath string
}

// copyOperation represents a container copy operation
type copyOperation struct {
	client           client.APIClient
	containerID      string
	srcPath          string
	dstPath          string
	srcInfo          os.FileInfo
	reader           io.Reader
	progressCallback ProgressCallback
	logger           *logrus.Logger
}

// execute performs the copy operation
func (op *copyOperation) execute(ctx context.Context) error {
	// Determine the total size for progress tracking
	var totalBytes int64
	if op.srcInfo != nil {
		if op.srcInfo.IsDir() {
			// Estimate directory size (this is approximate)
			totalBytes, _ = getDirSize(op.srcPath)
		} else {
			totalBytes = op.srcInfo.Size()
		}
	}

	// Create a progress tracking reader if a callback is provided
	var reader io.Reader = op.reader
	if op.progressCallback != nil && totalBytes > 0 {
		reader = &progressReader{
			reader:           op.reader,
			totalBytes:       totalBytes,
			bytesRead:        0,
			progressCallback: op.progressCallback,
		}
	}

	// Copy the archive to the container
	// Use the correct options type from the container package
	err := op.client.CopyToContainer(ctx, op.containerID, op.dstPath, reader, container.CopyToContainerOptions{
		AllowOverwriteDirWithFile: true, // Assuming overwrite is allowed for simplicity here
	})
	if err != nil {
		return fmt.Errorf("failed to copy to container: %w", err)
	}

	// Call the progress callback with 100% completion
	if op.progressCallback != nil {
		op.progressCallback(1.0, totalBytes, totalBytes)
	}

	return nil
}

// progressReader is a reader that reports progress
type progressReader struct {
	reader           io.Reader
	totalBytes       int64
	bytesRead        int64
	progressCallback ProgressCallback
	lastReportTime   time.Time
}

// Read implements the io.Reader interface with progress tracking
func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.bytesRead += int64(n)

		// Don't report progress too often (max once per 100ms)
		if time.Since(r.lastReportTime) > 100*time.Millisecond || r.bytesRead == r.totalBytes {
			progress := float64(r.bytesRead) / float64(r.totalBytes)
			r.progressCallback(progress, r.bytesRead, r.totalBytes)
			r.lastReportTime = time.Now()
		}
	}
	return n, err
}

// getDirSize calculates the total size of a directory
func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// sanitizePath sanitizes a container path
func sanitizePath(path string) string {
	// Ensure path starts with / for absolute paths
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Clean the path to remove any .. or other unsafe elements
	return filepath.Clean(path)
}

// isNotFoundError checks if an error indicates a "not found" condition.
// Copied from copy_from.go - consider moving to a shared util package.
// func isNotFoundError(err error) bool { ... } // Already defined above
