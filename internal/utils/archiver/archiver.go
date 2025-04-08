// Package archiver provides utilities for working with container file archives
package archiver

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Common errors
var (
	// ErrInvalidPath indicates an invalid file path
	ErrInvalidPath = errors.New("invalid path")

	// ErrPathTraversal indicates a potential path traversal attempt
	ErrPathTraversal = errors.New("path traversal attempt detected")

	// ErrInvalidArchive indicates an invalid or corrupt archive
	ErrInvalidArchive = errors.New("invalid or corrupt archive")

	// ErrExtractionFailed indicates extraction failed
	ErrExtractionFailed = errors.New("archive extraction failed")

	// ErrCompressionFailed indicates compression failed
	ErrCompressionFailed = errors.New("archive compression failed")

	// ErrEmptyArchive indicates an empty archive
	ErrEmptyArchive = errors.New("empty archive")
)

// CompressionType represents the type of compression to use
type CompressionType string

const (
	// CompressionNone uses no compression
	CompressionNone CompressionType = "none"

	// CompressionGzip uses gzip compression
	CompressionGzip CompressionType = "gzip"
)

// ArchiveOptions contains options for creating and extracting archives
type ArchiveOptions struct {
	// Compression specifies the compression type
	Compression CompressionType

	// IncludeFiles is a list of file patterns to include
	IncludeFiles []string

	// ExcludeFiles is a list of file patterns to exclude
	ExcludeFiles []string

	// IncludeBaseDir specifies whether to include the base directory
	IncludeBaseDir bool

	// StripComponents specifies the number of directory components to strip
	StripComponents int

	// Overwrite specifies whether to overwrite existing files during extraction
	Overwrite bool

	// PreservePaths specifies whether to preserve paths during extraction
	PreservePaths bool

	// PreservePermissions specifies whether to preserve file permissions
	PreservePermissions bool

	// PreserveOwnership specifies whether to preserve file ownership
	PreserveOwnership bool
}

// DefaultArchiveOptions provides default options for archiving
var DefaultArchiveOptions = ArchiveOptions{
	Compression:         CompressionGzip,
	IncludeFiles:        []string{"*"},
	ExcludeFiles:        []string{},
	IncludeBaseDir:      false,
	StripComponents:     0,
	Overwrite:           true,
	PreservePaths:       true,
	PreservePermissions: true,
	PreserveOwnership:   false,
}

// IsPathSafe checks if a path is safe from traversal attacks
func IsPathSafe(path string) bool {
	// Clean the path to resolve .. and other relative elements
	cleanPath := filepath.Clean(path)

	// Check if the path is an absolute path (platform specific)
	if filepath.IsAbs(cleanPath) && !filepath.IsAbs(path) {
		return false
	}

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return false
	}

	return true
}

// SanitizePath sanitizes a path for safe use
func SanitizePath(path string) (string, error) {
	// Check if path is safe
	if !IsPathSafe(path) {
		return "", ErrPathTraversal
	}

	// Clean the path
	cleanPath := filepath.Clean(path)

	// Ensure the path doesn't escape from the current directory
	if strings.HasPrefix(cleanPath, "..") {
		return "", ErrPathTraversal
	}

	// Remove any leading separator
	cleanPath = strings.TrimPrefix(cleanPath, string(filepath.Separator))

	return cleanPath, nil
}

// ArchiveFile archives a file or directory into a tar stream
func ArchiveFile(path string, options ArchiveOptions) (io.Reader, error) {
	// Verify path exists
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	// Create buffer to hold the archive
	var buf bytes.Buffer

	// Create gzip writer if compression is enabled
	var finalWriter io.Writer = &buf
	var gzipWriter *gzip.Writer
	if options.Compression == CompressionGzip {
		gzipWriter = gzip.NewWriter(&buf)
		finalWriter = gzipWriter
	}

	// Create tar writer
	tarWriter := tar.NewWriter(finalWriter)

	// Track task completion
	var archiveErr error
	defer func() {
		// Close the tar writer
		if err := tarWriter.Close(); err != nil && archiveErr == nil {
			archiveErr = err
		}

		// Close the gzip writer if it exists
		if gzipWriter != nil {
			if err := gzipWriter.Close(); err != nil && archiveErr == nil {
				archiveErr = err
			}
		}
	}()

	// Define base directory for archiving
	baseDir := ""
	if options.IncludeBaseDir {
		baseDir = filepath.Base(path)
	}

	// Walk the file tree and add files to the archive
	if fileInfo.IsDir() {
		// Archive directory
		err = filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Get relative path
			relPath, err := filepath.Rel(path, filePath)
			if err != nil {
				return err
			}

			// Skip the root directory itself
			if relPath == "." {
				return nil
			}

			// Check include/exclude patterns
			if !shouldIncludeFile(relPath, options.IncludeFiles, options.ExcludeFiles) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			// Construct archive path
			archivePath := relPath
			if baseDir != "" {
				archivePath = filepath.Join(baseDir, relPath)
			}

			// Add file to archive
			return addFileToArchive(tarWriter, filePath, archivePath, info)
		})
	} else {
		// Archive single file
		archivePath := filepath.Base(path)
		if baseDir != "" {
			archivePath = filepath.Join(baseDir, archivePath)
		}

		// Check include/exclude patterns
		if shouldIncludeFile(archivePath, options.IncludeFiles, options.ExcludeFiles) {
			err = addFileToArchive(tarWriter, path, archivePath, fileInfo)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCompressionFailed, err)
	}

	if archiveErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrCompressionFailed, archiveErr)
	}

	return &buf, nil
}

// ArchiveFiles archives multiple files or directories into a tar stream
func ArchiveFiles(paths []string, options ArchiveOptions) (io.Reader, error) {
	// Create buffer to hold the archive
	var buf bytes.Buffer

	// Create gzip writer if compression is enabled
	var finalWriter io.Writer = &buf
	var gzipWriter *gzip.Writer
	if options.Compression == CompressionGzip {
		gzipWriter = gzip.NewWriter(&buf)
		finalWriter = gzipWriter
	}

	// Create tar writer
	tarWriter := tar.NewWriter(finalWriter)

	// Track task completion
	var archiveErr error
	defer func() {
		// Close the tar writer
		if err := tarWriter.Close(); err != nil && archiveErr == nil {
			archiveErr = err
		}

		// Close the gzip writer if it exists
		if gzipWriter != nil {
			if err := gzipWriter.Close(); err != nil && archiveErr == nil {
				archiveErr = err
			}
		}
	}()

	// Process each path
	for _, path := range paths {
		// Verify path exists
		fileInfo, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("failed to stat path %s: %w", path, err)
		}

		// Define base directory for archiving
		baseDir := ""
		if options.IncludeBaseDir {
			baseDir = filepath.Base(path)
		}

		// Walk the file tree and add files to the archive
		if fileInfo.IsDir() {
			// Archive directory
			err = filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				// Get relative path
				relPath, err := filepath.Rel(path, filePath)
				if err != nil {
					return err
				}

				// Skip the root directory itself
				if relPath == "." {
					return nil
				}

				// Check include/exclude patterns
				if !shouldIncludeFile(relPath, options.IncludeFiles, options.ExcludeFiles) {
					if info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				// Construct archive path
				archivePath := relPath
				if baseDir != "" {
					archivePath = filepath.Join(baseDir, relPath)
				}

				// Add file to archive
				return addFileToArchive(tarWriter, filePath, archivePath, info)
			})
		} else {
			// Archive single file
			archivePath := filepath.Base(path)
			if baseDir != "" {
				archivePath = filepath.Join(baseDir, archivePath)
			}

			// Check include/exclude patterns
			if shouldIncludeFile(archivePath, options.IncludeFiles, options.ExcludeFiles) {
				err = addFileToArchive(tarWriter, path, archivePath, fileInfo)
			}
		}

		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCompressionFailed, err)
		}
	}

	if archiveErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrCompressionFailed, archiveErr)
	}

	return &buf, nil
}

// ExtractArchive extracts a tar archive to a destination directory
func ExtractArchive(src io.Reader, destDir string, options ArchiveOptions) error {
	// Verify destination directory exists
	fileInfo, err := os.Stat(destDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Create destination directory
			if err := os.MkdirAll(destDir, 0755); err != nil {
				return fmt.Errorf("failed to create destination directory: %w", err)
			}
		} else {
			return fmt.Errorf("failed to stat destination directory: %w", err)
		}
	} else if !fileInfo.IsDir() {
		return fmt.Errorf("destination is not a directory: %s", destDir)
	}

	// Create gzip reader if compression is enabled
	var tarReader *tar.Reader
	if options.Compression == CompressionGzip {
		gzipReader, err := gzip.NewReader(src)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}
		defer gzipReader.Close()
		tarReader = tar.NewReader(gzipReader)
	} else {
		tarReader = tar.NewReader(src)
	}

	// Extract files from the archive
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}

		// Skip the entry if too many components are stripped
		components := strings.Split(header.Name, "/")
		if len(components) <= options.StripComponents {
			continue
		}

		// Strip components if specified
		entryPath := header.Name
		if options.StripComponents > 0 {
			entryPath = filepath.Join(components[options.StripComponents:]...)
		}

		// Check include/exclude patterns
		if !shouldIncludeFile(entryPath, options.IncludeFiles, options.ExcludeFiles) {
			continue
		}

		// Sanitize path to prevent path traversal
		entryPath, err = SanitizePath(entryPath)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrPathTraversal, header.Name)
		}

		// Create full path to the destination
		fullPath := filepath.Join(destDir, entryPath)

		// Handle different entry types
		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := extractDir(fullPath, header, options); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			// Extract regular file
			if err := extractFile(fullPath, header, tarReader, options); err != nil {
				return err
			}
		case tar.TypeSymlink:
			// Create symbolic link
			if err := extractSymlink(fullPath, header, options); err != nil {
				return err
			}
		}
	}

	return nil
}

// ListArchiveContents lists the contents of a tar archive
func ListArchiveContents(src io.Reader, options ArchiveOptions) ([]string, error) {
	var files []string

	// Create gzip reader if compression is enabled
	var tarReader *tar.Reader
	if options.Compression == CompressionGzip {
		gzipReader, err := gzip.NewReader(src)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}
		defer gzipReader.Close()
		tarReader = tar.NewReader(gzipReader)
	} else {
		tarReader = tar.NewReader(src)
	}

	// List files in the archive
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}

		// Skip the entry if too many components are stripped
		components := strings.Split(header.Name, "/")
		if len(components) <= options.StripComponents {
			continue
		}

		// Strip components if specified
		entryPath := header.Name
		if options.StripComponents > 0 {
			entryPath = filepath.Join(components[options.StripComponents:]...)
		}

		// Check include/exclude patterns
		if !shouldIncludeFile(entryPath, options.IncludeFiles, options.ExcludeFiles) {
			continue
		}

		// Add file to the list
		files = append(files, entryPath)
	}

	if len(files) == 0 {
		return nil, ErrEmptyArchive
	}

	return files, nil
}

// addFileToArchive adds a file to a tar archive
func addFileToArchive(tw *tar.Writer, filePath, archivePath string, info os.FileInfo) error {
	// Sanitize the archive path
	archivePath, err := SanitizePath(archivePath)
	if err != nil {
		return err
	}

	// Create header
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}

	// Set the filename
	header.Name = archivePath

	// Write header
	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	// If it's a regular file, write the content
	if info.Mode().IsRegular() {
		file, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(tw, file)
		if err != nil {
			return err
		}
	}

	return nil
}

// shouldIncludeFile checks if a file should be included based on patterns
func shouldIncludeFile(path string, includePatterns, excludePatterns []string) bool {
	// Check exclude patterns first
	for _, pattern := range excludePatterns {
		matched, _ := filepath.Match(pattern, path)
		if matched {
			return false
		}
	}

	// If no include patterns specified, include all
	if len(includePatterns) == 0 {
		return true
	}

	// Check include patterns
	for _, pattern := range includePatterns {
		matched, _ := filepath.Match(pattern, path)
		if matched {
			return true
		}
	}

	return false
}

// extractDir creates a directory during extraction
func extractDir(path string, header *tar.Header, options ArchiveOptions) error {
	// Create the directory
	err := os.MkdirAll(path, 0755)
	if err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	// Set permissions if specified
	if options.PreservePermissions {
		err = os.Chmod(path, header.FileInfo().Mode())
		if err != nil {
			return fmt.Errorf("failed to set permissions for directory %s: %w", path, err)
		}
	}

	return nil
}

// extractFile extracts a file during extraction
func extractFile(path string, header *tar.Header, reader *tar.Reader, options ArchiveOptions) error {
	// Check if file exists and overwrite mode
	_, err := os.Stat(path)
	if err == nil && !options.Overwrite {
		return fmt.Errorf("file already exists and overwrite is disabled: %s", path)
	}

	// Ensure the parent directory exists
	dirPath := filepath.Dir(path)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("failed to create parent directory for %s: %w", path, err)
	}

	// Create the file
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer file.Close()

	// Copy the content
	_, err = io.Copy(file, reader)
	if err != nil {
		return fmt.Errorf("failed to write file content for %s: %w", path, err)
	}

	// Set permissions if specified
	if options.PreservePermissions {
		err = os.Chmod(path, header.FileInfo().Mode())
		if err != nil {
			return fmt.Errorf("failed to set permissions for file %s: %w", path, err)
		}
	}

	// Set modification time
	if err := os.Chtimes(path, time.Now(), header.ModTime); err != nil {
		return fmt.Errorf("failed to set modification time for %s: %w", path, err)
	}

	return nil
}

// extractSymlink creates a symbolic link during extraction
func extractSymlink(path string, header *tar.Header, options ArchiveOptions) error {
	// Ensure the parent directory exists
	dirPath := filepath.Dir(path)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("failed to create parent directory for %s: %w", path, err)
	}

	// Remove existing file/symlink if it exists
	if _, err := os.Lstat(path); err == nil {
		if !options.Overwrite {
			return fmt.Errorf("symlink already exists and overwrite is disabled: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("failed to remove existing symlink %s: %w", path, err)
		}
	}

	// Validate symlink destination for security
	linkDest := header.Linkname
	if !options.PreservePaths {
		cleanDest := filepath.Clean(linkDest)
		if filepath.IsAbs(cleanDest) || strings.HasPrefix(cleanDest, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%w: %s", ErrPathTraversal, linkDest)
		}
	}

	// Create the symlink
	if err := os.Symlink(linkDest, path); err != nil {
		return fmt.Errorf("failed to create symlink %s -> %s: %w", path, linkDest, err)
	}

	return nil
}

// ValidateArchive validates a tar archive
func ValidateArchive(src io.Reader, options ArchiveOptions) error {
	// Create gzip reader if compression is enabled
	var tarReader *tar.Reader
	if options.Compression == CompressionGzip {
		gzipReader, err := gzip.NewReader(src)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}
		defer gzipReader.Close()
		tarReader = tar.NewReader(gzipReader)
	} else {
		tarReader = tar.NewReader(src)
	}

	// Read the first header
	_, err := tarReader.Next()
	if err == io.EOF {
		return ErrEmptyArchive
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArchive, err)
	}

	// Check a few more headers to verify the archive is valid
	for i := 0; i < 5; i++ {
		_, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}
	}

	return nil
}
