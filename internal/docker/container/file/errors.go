// Package file provides utilities for container file operations
package file

import "errors"

var (
	// ErrContainerNotFound indicates the container was not found
	ErrContainerNotFound = errors.New("container not found")

	// ErrContainerNotRunning indicates the container is not running
	ErrContainerNotRunning = errors.New("container not running")

	// ErrInvalidPath indicates an invalid file path
	ErrInvalidPath = errors.New("invalid path")

	// ErrFileNotFound indicates the file was not found
	ErrFileNotFound = errors.New("file not found")

	// ErrCopyOperationFailed indicates the copy operation failed
	ErrCopyOperationFailed = errors.New("copy operation failed")

	// ErrExtractOperationFailed indicates the extract operation failed (Added for copy_from.go)
	ErrExtractOperationFailed = errors.New("extract operation failed")

	// ErrStatOperationFailed indicates the stat operation failed (Added for copy_from.go)
	ErrStatOperationFailed = errors.New("stat operation failed")
)
