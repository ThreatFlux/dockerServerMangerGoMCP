package api

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime" // Added import
	"net/http"
	"os"
	"path/filepath"
	"strings" // Re-added import
	"time"

	"github.com/docker/docker/api/types/container" // Added import
	"github.com/docker/docker/client"              // Added import
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/container/file"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils/archiver" // Added import

	"github.com/gorilla/websocket" // Added import
)

// FileController handles container file-related API requests
type FileController struct {
	// containerRepo *repositories.ContainerRepository // Removed - Repository file does not exist
	dockerClient client.APIClient // Changed from docker_test.Client
	tempDir      string
	logger       *logrus.Logger
}

// NewFileController creates a new file controller
func NewFileController(
	// containerRepo *repositories.ContainerRepository, // Removed
	dockerClient client.APIClient, // Changed from docker_test.Client
	tempDir string,
	logger *logrus.Logger,
) *FileController {
	// If no temp directory is specified, use the system temp directory
	if tempDir == "" {
		tempDir = os.TempDir()
	}

	return &FileController{
		// containerRepo: containerRepo, // Removed
		dockerClient: dockerClient, // Changed from docker_test.Client
		tempDir:      tempDir,
		logger:       logger,
	}
}

// RegisterRoutes registers the file API routes
func (ctrl *FileController) RegisterRoutes(router *gin.RouterGroup, authMW *middleware.AuthMiddleware) {
	file := router.Group("/containers")

	// Require authentication for all routes
	file.Use(authMW.RequireAuthentication())

	// File operations
	file.GET("/:id/files", ctrl.ListFiles)
	file.GET("/:id/files/download", ctrl.DownloadFile)
	file.POST("/:id/files/upload", ctrl.UploadFile)
	file.PUT("/:id/files/edit", ctrl.EditFile)
	file.DELETE("/:id/files/remove", ctrl.RemoveFile)
	file.GET("/:id/files/tail", ctrl.TailFile)
	file.GET("/:id/files/archive", ctrl.ArchiveFiles)
	file.POST("/:id/files/extract", ctrl.ExtractArchive)
}

// ListFiles handles GET /containers/:id/files
func (ctrl *FileController) ListFiles(c *gin.Context) {
	// Get container ID from path
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Validate container ID
	if err := utils.ValidateContainerName(containerID); err != nil { // Changed to ValidateContainerName
		utils.BadRequest(c, err.Error())
		return
	}

	// Get path from query
	path := c.DefaultQuery("path", "/")

	// Get user ID from context - Removed as userID is no longer used here
	/*
		userID, err := middleware.GetUserID(c) // Pass gin.Context
		if err != nil {
			utils.Unauthorized(c, "Authentication required")
			return
		}
	*/

	// TODO: Re-implement container permission check if ContainerRepository is added
	/*
		// Check if user has permission to access this container
		isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
		dbContainer, err := ctrl.containerRepo.FindByIDOrName(c.Request.Context(), containerID) // Keep c.Request.Context() for DB call
		if err != nil || dbContainer == nil || (dbContainer.UserID != userID && !isAdmin) {
			utils.Forbidden(c, "You don't have permission to access this container's files")
			return
		}
	*/

	// Parse query parameters
	includeHidden := c.DefaultQuery("include_hidden", "false") == "true"

	// List files directly within the container using exec
	fileNames, err := file.ListContainerFiles(c.Request.Context(), ctrl.dockerClient, containerID, path)
	if err != nil {
		ctrl.logger.WithError(err).WithFields(logrus.Fields{
			"containerID": containerID,
			"path":        path,
		}).Error("Failed to list files in container")
		// Handle specific errors like "path not found" if ListContainerFiles returns them
		if strings.Contains(err.Error(), "path not found") {
			utils.NotFound(c, "Path not found in container")
		} else {
			utils.InternalServerError(c, "Failed to list container files: "+err.Error())
		}
		return
	}

	// Define a simple struct for the response as models.FileEntry is undefined
	type SimpleFileEntry struct {
		Name string `json:"name"`
		Path string `json:"path"`
		// Add IsDirectory, Size, etc. if ListContainerFiles can provide them (e.g., by using 'ls -l')
	}

	// Create response
	fileList := make([]SimpleFileEntry, 0, len(fileNames))
	for _, name := range fileNames {
		// Skip hidden files if requested
		if !includeHidden && strings.HasPrefix(name, ".") {
			continue
		}
		fileList = append(fileList, SimpleFileEntry{
			Name: name,
			Path: filepath.Join(path, name),
		})
	}

	// Return file list
	// TODO: Define models.FileListResponse if it doesn't exist
	// utils.SuccessResponse(c, models.FileListResponse{Files: fileList})
	utils.SuccessResponse(c, gin.H{"files": fileList}) // Temporary response structure
	/* // Removed block using undefined models.FileListResponse
	utils.SuccessResponse(c, models.FileListResponse{
		Container: containerID,
		Path:      path,
		Files:     fileList,
	})
	*/
}

// DownloadFile handles GET /containers/:id/files/download
func (ctrl *FileController) DownloadFile(c *gin.Context) {
	// Get container ID from path
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Validate container ID
	if err := utils.ValidateContainerName(containerID); err != nil { // Changed to ValidateContainerName
		utils.BadRequest(c, err.Error())
		return
	}

	// Get path from query
	path := c.Query("path")
	if path == "" {
		utils.BadRequest(c, "File path is required")
		return
	}

	// Get user ID from context - Removed as userID is no longer used here
	/*
		userID, err := middleware.GetUserID(c) // Pass gin.Context
		if err != nil {
			utils.Unauthorized(c, "Authentication required")
			return
		}
	*/

	// TODO: Re-implement container permission check if ContainerRepository is added
	/*
		// Check if user has permission to access this container
		isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
		dbContainer, err := ctrl.containerRepo.FindByIDOrName(c.Request.Context(), containerID) // Keep c.Request.Context() for DB call
		if err != nil || dbContainer == nil || (dbContainer.UserID != userID && !isAdmin) {
			utils.Forbidden(c, "You don't have permission to access this container's files")
			return
		}
	*/

	// Get format parameter
	format := c.DefaultQuery("format", "raw")
	if format != "raw" && format != "base64" && format != "tar" {
		utils.BadRequest(c, "Invalid format. Supported formats: raw, base64, tar")
		return
	}

	// Create temp directory for extraction
	tempPath := filepath.Join(ctrl.tempDir, fmt.Sprintf("download-file-%s-%d", containerID, time.Now().UnixNano()))
	defer os.RemoveAll(tempPath)
	err := os.MkdirAll(tempPath, 0755) // Changed = to :=
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to create temp directory")
		utils.InternalServerError(c, "Failed to create temp directory")
		return
	}

	// Get file from container
	destinationPath := filepath.Join(tempPath, filepath.Base(path))
	err = file.CopyFromContainer(c.Request.Context(), ctrl.dockerClient, containerID, path, tempPath, file.CopyFromOptions{ // Renamed CopyFrom to CopyFromContainer
		Timeout: 30 * time.Second,
		Logger:  ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithFields(logrus.Fields{
			"containerID": containerID,
			"path":        path,
		}).Error("Failed to copy file from container")
		utils.InternalServerError(c, "Failed to download file: "+err.Error())
		return
	}

	// Check if directory was copied
	fileInfo, err := os.Stat(destinationPath)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to stat downloaded file")
		utils.InternalServerError(c, "Failed to access downloaded file")
		return
	}

	// If it's a directory, we need to tar it
	if fileInfo.IsDir() {
		if format == "raw" {
			utils.BadRequest(c, "Cannot download a directory in raw format. Use tar or base64 format")
			return
		}

		// Create a tar archive stream
		archiveReader, err := archiver.ArchiveFile(destinationPath, archiver.ArchiveOptions{
			Compression: archiver.CompressionNone, // No compression for .tar
		})
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to create tar archive stream")
			utils.InternalServerError(c, "Failed to create archive of directory")
			return
		}
		// Stream the archive
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.tar", filepath.Base(path)))
		c.DataFromReader(http.StatusOK, -1, "application/x-tar", archiveReader, nil) // Use DataFromReader
		return                                                                       // Important: return after streaming
	}

	// Process based on format (for single files)
	if format == "base64" {
		// Read file and encode as base64
		fileContent, err := os.ReadFile(destinationPath)
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to read file")
			utils.InternalServerError(c, "Failed to read file")
			return
		}

		base64Content := base64.StdEncoding.EncodeToString(fileContent)
		utils.SuccessResponse(c, gin.H{
			"container": containerID,
			"path":      path,
			"content":   base64Content,
			"size":      len(fileContent),
			"encoding":  "base64",
		})
		return
	} else if format == "tar" {
		// Create a tar archive stream for the single file
		archiveReader, err := archiver.ArchiveFile(destinationPath, archiver.ArchiveOptions{
			Compression: archiver.CompressionNone, // No compression for .tar
		})
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to create tar archive stream for single file")
			utils.InternalServerError(c, "Failed to create archive")
			return
		}
		// Stream the archive
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.tar", filepath.Base(path)))
		c.DataFromReader(http.StatusOK, -1, "application/x-tar", archiveReader, nil) // Use DataFromReader
		return                                                                       // Important: return after streaming
	}

	// For raw format, check file size
	if fileInfo.Size() > 50*1024*1024 { // 50MB limit
		utils.BadRequest(c, "File is too large for raw download. Use tar or base64 format, or download a smaller file")
		return
	}

	// Set appropriate content type based on file extension
	contentType := mime.TypeByExtension(filepath.Ext(path)) // Replaced utils.GetContentType
	if contentType == "" {
		contentType = "application/octet-stream" // Default if extension unknown
	}
	c.Header("Content-Type", contentType)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(path)))

	// Serve the file using FileAttachment for better header handling
	c.FileAttachment(destinationPath, filepath.Base(path))
}

// UploadFile handles POST /containers/:id/files/upload
func (ctrl *FileController) UploadFile(c *gin.Context) {
	// Get container ID from path
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Validate container ID
	if err := utils.ValidateContainerName(containerID); err != nil { // Changed to ValidateContainerName
		utils.BadRequest(c, err.Error())
		return
	}

	// Get destination path from form
	destinationPath := c.PostForm("path")
	if destinationPath == "" {
		utils.BadRequest(c, "Destination path is required")
		return
	}

	// Get content format
	format := c.DefaultQuery("format", "file")
	if format != "file" && format != "base64" && format != "tar" {
		utils.BadRequest(c, "Invalid format. Supported formats: file, base64, tar")
		return
	}

	// Get overwrite parameter
	overwrite := c.DefaultPostForm("overwrite", "false") == "true"

	// Get user ID from context - Removed as userID is no longer used here
	/*
		userID, err := middleware.GetUserID(c) // Pass gin.Context
		if err != nil {
			utils.Unauthorized(c, "Authentication required")
			return
		}
	*/

	// TODO: Re-implement container permission check if ContainerRepository is added
	/*
		// Check if user has permission to access this container
		isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
		dbContainer, err := ctrl.containerRepo.FindByIDOrName(c.Request.Context(), containerID) // Keep c.Request.Context() for DB call
		if err != nil || dbContainer == nil || (dbContainer.UserID != userID && !isAdmin) {
			utils.Forbidden(c, "You don't have permission to modify this container's files")
			return
		}
	*/

	// Create temp directory for file processing
	tempPath := filepath.Join(ctrl.tempDir, fmt.Sprintf("upload-file-%s-%d", containerID, time.Now().UnixNano()))
	defer os.RemoveAll(tempPath)
	err := os.MkdirAll(tempPath, 0755) // Changed = to :=
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to create temp directory")
		utils.InternalServerError(c, "Failed to create temp directory")
		return
	}

	// Process based on format
	var srcPath string

	if format == "file" {
		// Get file from form
		uploadedFile, header, err := c.Request.FormFile("file")
		if err != nil {
			utils.BadRequest(c, "Failed to get uploaded file: "+err.Error())
			return
		}
		defer uploadedFile.Close()

		// Validate file size (100MB limit)
		if header.Size > 100*1024*1024 {
			utils.BadRequest(c, "File is too large (max 100MB)")
			return
		}

		// Create file in temp directory
		srcPath = filepath.Join(tempPath, header.Filename)
		outFile, err := os.Create(srcPath)
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to create temporary file")
			utils.InternalServerError(c, "Failed to process uploaded file")
			return
		}
		defer outFile.Close()

		// Copy file to temp directory
		_, err = io.Copy(outFile, uploadedFile)
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to save uploaded file")
			utils.InternalServerError(c, "Failed to save uploaded file")
			return
		}

	} else if format == "base64" {
		// Get base64 content from form
		base64Content := c.PostForm("content")
		if base64Content == "" {
			utils.BadRequest(c, "Base64 content is required")
			return
		}

		// Decode base64 content
		fileContent, err := base64.StdEncoding.DecodeString(base64Content)
		if err != nil {
			utils.BadRequest(c, "Invalid base64 encoding: "+err.Error())
			return
		}

		// Create file in temp directory
		filename := filepath.Base(destinationPath)
		if filename == "." || filename == "/" {
			filename = "content"
		}

		srcPath = filepath.Join(tempPath, filename)
		err = os.WriteFile(srcPath, fileContent, 0644)
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to write decoded content to file")
			utils.InternalServerError(c, "Failed to process content")
			return
		}

	} else if format == "tar" {
		// Get tar file from form
		tarFile, header, err := c.Request.FormFile("file")
		if err != nil {
			utils.BadRequest(c, "Failed to get uploaded tar file: "+err.Error())
			return
		}
		defer tarFile.Close()

		// Validate file size (200MB limit for tar archives)
		if header.Size > 200*1024*1024 {
			utils.BadRequest(c, "Tar archive is too large (max 200MB)")
			return
		}

		// Validate tar file
		if !strings.HasSuffix(header.Filename, ".tar") { // Replaced utils.IsTarFile
			utils.BadRequest(c, "File must be a tar archive")
			return
		}

		// Save tar file to temp directory
		srcPath = filepath.Join(tempPath, "archive.tar")
		outFile, err := os.Create(srcPath)
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to create temporary tar file")
			utils.InternalServerError(c, "Failed to process uploaded tar file")
			return
		}
		defer outFile.Close()

		// Copy tar file to temp directory
		_, err = io.Copy(outFile, tarFile)
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to save uploaded tar file")
			utils.InternalServerError(c, "Failed to save uploaded tar file")
			return
		}

		// Extract tar archive to temp directory
		extractDir := filepath.Join(tempPath, "extracted")
		err = os.MkdirAll(extractDir, 0755)
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to create extraction directory")
			utils.InternalServerError(c, "Failed to prepare for tar extraction")
			return
		}

		// Open the source tar file for reading
		srcFile, err := os.Open(srcPath)
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to open source tar file")
			utils.InternalServerError(c, "Failed to open uploaded archive")
			return
		}
		defer srcFile.Close()

		// Extract using archiver package
		err = archiver.ExtractArchive(srcFile, extractDir, archiver.ArchiveOptions{
			Compression: archiver.CompressionNone, // Assuming .tar is uncompressed
			Overwrite:   overwrite,                // Use overwrite flag from request
		})
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to extract tar archive")
			utils.InternalServerError(c, "Failed to extract tar archive")
			return
		}

		// Update srcPath to the extracted directory
		srcPath = extractDir
	}

	// Copy file/directory to container
	err = file.CopyToContainer(c.Request.Context(), ctrl.dockerClient, containerID, srcPath, destinationPath, file.CopyToOptions{ // Renamed CopyTo to CopyToContainer
		Overwrite: overwrite,
		Timeout:   30 * time.Second,
		Logger:    ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithFields(logrus.Fields{
			"containerID": containerID,
			"srcPath":     srcPath,
			"destPath":    destinationPath,
		}).Error("Failed to copy file to container")
		utils.InternalServerError(c, "Failed to upload file: "+err.Error())
		return
	}

	// Return success
	utils.SuccessResponse(c, gin.H{
		"status":    "success",
		"message":   "File uploaded successfully",
		"container": containerID,
		"path":      destinationPath,
	})
}

// EditFile handles PUT /containers/:id/files/edit
func (ctrl *FileController) EditFile(c *gin.Context) {
	// Get container ID from path
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Validate container ID
	if err := utils.ValidateContainerName(containerID); err != nil { // Changed to ValidateContainerName
		utils.BadRequest(c, err.Error())
		return
	}

	// Parse request body
	var req models.FileEditRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate file path
	if req.Path == "" {
		utils.BadRequest(c, "File path is required")
		return
	}

	// Removed format handling as content is expected to be base64
	/*
		// Get content format
		format := req.Format
		if format == "" {
			format = "text"
		}
		if format != "text" && format != "base64" {
			utils.BadRequest(c, "Invalid format. Supported formats: text, base64")
			return
		}
	*/

	// Get user ID from context - Removed as userID is no longer used here
	/*
		userID, err := middleware.GetUserID(c) // Pass gin.Context
		if err != nil {
			utils.Unauthorized(c, "Authentication required")
			return
		}
	*/

	// TODO: Re-implement container permission check if ContainerRepository is added
	/*
		// Check if user has permission to access this container
		isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
		dbContainer, err := ctrl.containerRepo.FindByIDOrName(c.Request.Context(), containerID) // Keep c.Request.Context() for DB call
		if err != nil || dbContainer == nil || (dbContainer.UserID != userID && !isAdmin) {
			utils.Forbidden(c, "You don't have permission to modify this container's files")
			return
		}
	*/

	// Create temp directory for file processing
	tempPath := filepath.Join(ctrl.tempDir, fmt.Sprintf("edit-file-%s-%d", containerID, time.Now().UnixNano()))
	defer os.RemoveAll(tempPath)
	err := os.MkdirAll(tempPath, 0755) // Changed = to :=
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to create temp directory")
		utils.InternalServerError(c, "Failed to create temp directory")
		return
	}

	// First, we need to copy the existing file to our temp location if we're not creating a new file
	if !req.Create {
		err = file.CopyFromContainer(c.Request.Context(), ctrl.dockerClient, containerID, req.Path, tempPath, file.CopyFromOptions{ // Renamed CopyFrom to CopyFromContainer
			Timeout: 10 * time.Second,
			Logger:  ctrl.logger,
		})
		if err != nil {
			ctrl.logger.WithError(err).WithFields(logrus.Fields{
				"containerID": containerID,
				"path":        req.Path,
			}).Error("Failed to copy file from container for editing")
			utils.NotFound(c, "Failed to find file for editing: "+err.Error())
			return
		}
	}

	// Prepare file content (assuming base64 encoding)
	fileContent, err := base64.StdEncoding.DecodeString(req.Content)
	if err != nil {
		utils.BadRequest(c, "Invalid base64 encoding for content: "+err.Error())
		return
	}

	// Create/overwrite file in temp directory
	filePath := filepath.Join(tempPath, filepath.Base(req.Path))
	err = os.WriteFile(filePath, fileContent, 0644)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to write file content")
		utils.InternalServerError(c, "Failed to process file content")
		return
	}

	// Copy modified file back to container
	err = file.CopyToContainer(c.Request.Context(), ctrl.dockerClient, containerID, filePath, req.Path, file.CopyToOptions{ // Renamed CopyTo to CopyToContainer
		Overwrite: true, // We need to overwrite since we're editing
		Timeout:   20 * time.Second,
		Logger:    ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithFields(logrus.Fields{
			"containerID": containerID,
			"filePath":    filePath,
			"destPath":    req.Path,
		}).Error("Failed to copy modified file to container")
		utils.InternalServerError(c, "Failed to save edited file: "+err.Error())
		return
	}

	// Return success
	utils.SuccessResponse(c, gin.H{
		"status":    "success",
		"message":   "File edited successfully",
		"container": containerID,
		"path":      req.Path,
	})
}

// RemoveFile handles DELETE /containers/:id/files/remove
func (ctrl *FileController) RemoveFile(c *gin.Context) {
	// Get container ID from path
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Validate container ID
	if err := utils.ValidateContainerName(containerID); err != nil { // Changed to ValidateContainerName
		utils.BadRequest(c, err.Error())
		return
	}

	// Get path from query
	path := c.Query("path")
	if path == "" {
		utils.BadRequest(c, "File path is required")
		return
	}

	// Get user ID from context - Removed as userID is no longer used here
	/*
		userID, err := middleware.GetUserID(c) // Pass gin.Context
		if err != nil {
			utils.Unauthorized(c, "Authentication required")
			return
		}
	*/

	// TODO: Re-implement container permission check if ContainerRepository is added
	/*
		// Check if user has permission to access this container
		isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
		dbContainer, err := ctrl.containerRepo.FindByIDOrName(c.Request.Context(), containerID) // Keep c.Request.Context() for DB call
		if err != nil || dbContainer == nil || (dbContainer.UserID != userID && !isAdmin) {
			utils.Forbidden(c, "You don't have permission to modify this container's files")
			return
		}
	*/

	// Get recursive parameter
	recursive := c.DefaultQuery("recursive", "false") == "true"

	// Get force parameter
	force := c.DefaultQuery("force", "false") == "true"

	// Create and execute a script to remove the file
	var script string
	if recursive {
		script = fmt.Sprintf("rm -r%s '%s'", force_flag(force), path)
	} else {
		script = fmt.Sprintf("rm %s'%s'", force_flag(force), path)
	}

	// Execute command in container
	execConfig := container.ExecOptions{ // Changed docker_test.ExecConfig to container.ExecOptions
		Cmd:          []string{"sh", "-c", script},
		AttachStdout: true,
		AttachStderr: true,
	}

	execID, err := ctrl.dockerClient.ContainerExecCreate(c.Request.Context(), containerID, execConfig)
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to create exec instance for file removal")
		utils.InternalServerError(c, "Failed to remove file: "+err.Error())
		return
	}

	// Start the exec instance
	err = ctrl.dockerClient.ContainerExecStart(c.Request.Context(), execID.ID, container.ExecStartOptions{}) // Changed docker_test.ExecStartCheck to container.ExecStartOptions
	if err != nil {
		ctrl.logger.WithError(err).WithField("execID", execID.ID).Error("Failed to start exec instance for file removal")
		utils.InternalServerError(c, "Failed to remove file: "+err.Error())
		return
	}

	// Check the exit code
	inspect, err := ctrl.dockerClient.ContainerExecInspect(c.Request.Context(), execID.ID)
	if err != nil {
		ctrl.logger.WithError(err).WithField("execID", execID.ID).Error("Failed to inspect exec instance for file removal")
		utils.InternalServerError(c, "Failed to verify file removal")
		return
	}

	if inspect.ExitCode != 0 {
		utils.BadRequest(c, fmt.Sprintf("Failed to remove file (exit code %d). Make sure the path exists and you have permission to remove it", inspect.ExitCode))
		return
	}

	// Return success
	utils.SuccessResponse(c, gin.H{
		"status":    "success",
		"message":   "File removed successfully",
		"container": containerID,
		"path":      path,
	})
}

// TailFile handles GET /containers/:id/files/tail
func (ctrl *FileController) TailFile(c *gin.Context) {
	// Get container ID from path
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Validate container ID
	if err := utils.ValidateContainerName(containerID); err != nil { // Changed to ValidateContainerName
		utils.BadRequest(c, err.Error())
		return
	}

	// Get path from query
	path := c.Query("path")
	if path == "" {
		utils.BadRequest(c, "File path is required")
		return
	}

	// Get user ID from context - Removed as userID is no longer used here
	/*
		userID, err := middleware.GetUserID(c) // Pass gin.Context
		if err != nil {
			utils.Unauthorized(c, "Authentication required")
			return
		}
	*/

	// TODO: Re-implement container permission check if ContainerRepository is added
	/*
		// Check if user has permission to access this container
		isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
		dbContainer, err := ctrl.containerRepo.FindByIDOrName(c.Request.Context(), containerID) // Keep c.Request.Context() for DB call
		if err != nil || dbContainer == nil || (dbContainer.UserID != userID && !isAdmin) {
			utils.Forbidden(c, "You don't have permission to access this container's files")
			return
		}
	*/

	// Get lines parameter
	lines := c.DefaultQuery("lines", "100")

	// Get follow parameter
	follow := c.DefaultQuery("follow", "false") == "true"

	// Create and execute a script to tail the file
	cmd := []string{"tail"}
	if follow {
		cmd = append(cmd, "-f")
	}
	cmd = append(cmd, "-n", lines, path)

	// Execute command in container
	execConfig := container.ExecOptions{ // Changed docker_test.ExecConfig to container.ExecOptions
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	}

	execID, err := ctrl.dockerClient.ContainerExecCreate(c.Request.Context(), containerID, execConfig)
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to create exec instance for file tail")
		utils.InternalServerError(c, "Failed to tail file: "+err.Error())
		return
	}

	// If follow is enabled, we use websocket; otherwise, we just return the output
	if follow {
		WebsocketUpgrader.CheckOrigin = func(r *http.Request) bool {
			return true // Allow all origins for websocket in this example
		}

		// Upgrade to websocket
		ws, err := WebsocketUpgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to upgrade to websocket")
			return
		}
		defer ws.Close()

		// Start exec and attach to websocket
		attachment, err := ctrl.dockerClient.ContainerExecAttach(c.Request.Context(), execID.ID, container.ExecStartOptions{}) // Changed docker_test.ExecStartCheck to container.ExecStartOptions
		if err != nil {
			ctrl.logger.WithError(err).WithField("execID", execID.ID).Error("Failed to attach to exec instance")
			ws.WriteMessage(websocket.TextMessage, []byte("Error: "+err.Error()))
			return
		}
		defer attachment.Close()

		// Forward output to websocket
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := attachment.Reader.Read(buf)
				if err != nil {
					if err != io.EOF {
						ctrl.logger.WithError(err).Error("Error reading from exec")
					}
					break
				}
				err = ws.WriteMessage(websocket.TextMessage, buf[:n])
				if err != nil {
					ctrl.logger.WithError(err).Error("Error writing to websocket")
					break
				}
			}
		}()

		// Listen for close signal
		for {
			_, _, err := ws.ReadMessage()
			if err != nil {
				break
			}
		}
	} else {
		// Start exec and capture output
		var stdout bytes.Buffer                                                                                                // Removed unused stderr
		attachment, err := ctrl.dockerClient.ContainerExecAttach(c.Request.Context(), execID.ID, container.ExecStartOptions{}) // Changed docker_test.ExecStartCheck to container.ExecStartOptions
		if err != nil {
			ctrl.logger.WithError(err).WithField("execID", execID.ID).Error("Failed to attach to exec instance")
			utils.InternalServerError(c, "Failed to tail file: "+err.Error())
			return
		}
		defer attachment.Close()

		// Copy output to buffer
		io.Copy(&stdout, attachment.Reader)

		// Check exit code
		inspect, err := ctrl.dockerClient.ContainerExecInspect(c.Request.Context(), execID.ID)
		if err != nil {
			ctrl.logger.WithError(err).WithField("execID", execID.ID).Error("Failed to inspect exec instance")
			utils.InternalServerError(c, "Failed to verify file tail")
			return
		}

		if inspect.ExitCode != 0 {
			utils.BadRequest(c, "Failed to tail file. Make sure the path exists and is a valid file")
			return
		}

		// Return the output
		utils.SuccessResponse(c, gin.H{
			"container": containerID,
			"path":      path,
			"lines":     lines,
			"content":   stdout.String(),
		})
	}
}

// ArchiveFiles handles GET /containers/:id/files/archive
func (ctrl *FileController) ArchiveFiles(c *gin.Context) {
	// Get container ID from path
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Validate container ID
	if err := utils.ValidateContainerName(containerID); err != nil { // Changed to ValidateContainerName
		utils.BadRequest(c, err.Error())
		return
	}

	// Get path from query
	path := c.Query("path")
	if path == "" {
		utils.BadRequest(c, "Path is required")
		return
	}

	// Get user ID from context - Removed as userID is no longer used here
	/*
		userID, err := middleware.GetUserID(c) // Pass gin.Context
		if err != nil {
			utils.Unauthorized(c, "Authentication required")
			return
		}
	*/

	// TODO: Re-implement container permission check if ContainerRepository is added
	/*
		// Check if user has permission to access this container
		isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
		dbContainer, err := ctrl.containerRepo.FindByIDOrName(c.Request.Context(), containerID) // Keep c.Request.Context() for DB call
		if err != nil || dbContainer == nil || (dbContainer.UserID != userID && !isAdmin) {
			utils.Forbidden(c, "You don't have permission to access this container's files")
			return
		}
	*/

	// Get archive format
	format := c.DefaultQuery("format", "tar")
	if format != "tar" && format != "tar.gz" {
		utils.BadRequest(c, "Invalid format. Supported formats: tar, tar.gz")
		return
	}

	// Get compression flag
	compress := format == "tar.gz"

	// Create temp directory for extraction
	tempPath := filepath.Join(ctrl.tempDir, fmt.Sprintf("archive-files-%s-%d", containerID, time.Now().UnixNano()))
	defer os.RemoveAll(tempPath)
	err := os.MkdirAll(tempPath, 0755) // Changed = to :=
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to create temp directory")
		utils.InternalServerError(c, "Failed to create temp directory")
		return
	}

	// Copy files from container
	err = file.CopyFromContainer(c.Request.Context(), ctrl.dockerClient, containerID, path, tempPath, file.CopyFromOptions{ // Renamed CopyFrom to CopyFromContainer
		// Recursive: true, // Field does not exist in CopyFromOptions
		Timeout: 30 * time.Second,
		Logger:  ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to copy files from container")
		utils.InternalServerError(c, "Failed to access container files: "+err.Error())
		return
	}

	// Create archive file
	archiveName := fmt.Sprintf("%s-%s", containerID, filepath.Base(path))
	if archiveName == fmt.Sprintf("%s-.", containerID) || archiveName == fmt.Sprintf("%s-/", containerID) {
		archiveName = fmt.Sprintf("%s-files", containerID)
	}

	// archivePath := filepath.Join(tempPath, archiveName+"."+format) // No longer creating a file path

	// Determine compression type
	compressionType := archiver.CompressionNone
	contentType := "application/x-tar"
	if compress {
		compressionType = archiver.CompressionGzip
		contentType = "application/gzip"
		archiveName += ".tar.gz" // Adjust filename for gzip
	} else {
		archiveName += ".tar" // Adjust filename for tar
	}

	// Create archive stream
	archiveReader, err := archiver.ArchiveFile(filepath.Join(tempPath, filepath.Base(path)), archiver.ArchiveOptions{
		Compression: compressionType,
	})
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to create archive stream")
		utils.InternalServerError(c, "Failed to create archive")
		return
	}

	// Set response headers for downloading
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", archiveName))
	c.Header("Content-Type", contentType)

	// Stream the archive
	c.DataFromReader(http.StatusOK, -1, contentType, archiveReader, nil)
}

// ExtractArchive handles POST /containers/:id/files/extract
func (ctrl *FileController) ExtractArchive(c *gin.Context) {
	// Get container ID from path
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Validate container ID
	if err := utils.ValidateContainerName(containerID); err != nil { // Changed to ValidateContainerName
		utils.BadRequest(c, err.Error())
		return
	}

	// Get destination path from form
	destinationPath := c.PostForm("path")
	if destinationPath == "" {
		utils.BadRequest(c, "Destination path is required")
		return
	}

	// Get user ID from context - Removed as userID is no longer used here
	/*
		userID, err := middleware.GetUserID(c.Request.Context())
		if err != nil {
			utils.Unauthorized(c, "Authentication required")
			return
		}
	*/

	// TODO: Re-implement container permission check if ContainerRepository is added
	/*
		// Check if user has permission to access this container
		isAdmin, _ := middleware.HasRole(c.Request.Context(), string(models.RoleAdmin))
		dbContainer, err := ctrl.containerRepo.FindByIDOrName(c.Request.Context(), containerID)
		if err != nil || dbContainer == nil || (dbContainer.UserID != userID && !isAdmin) {
			utils.Forbidden(c, "You don't have permission to modify this container's files")
			return
		}
	*/

	// Get overwrite parameter
	overwrite := c.DefaultPostForm("overwrite", "false") == "true"

	// Get archive file from form
	archiveFile, header, err := c.Request.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "Failed to get uploaded archive file: "+err.Error())
		return
	}
	defer archiveFile.Close()

	// Validate file size (200MB limit for archives)
	if header.Size > 200*1024*1024 {
		utils.BadRequest(c, "Archive file is too large (max 200MB)")
		return
	}

	// Validate archive file
	isTar := strings.HasSuffix(header.Filename, ".tar")
	isGzip := strings.HasSuffix(header.Filename, ".gz") || strings.HasSuffix(header.Filename, ".tgz")
	if !isTar && !isGzip { // Replaced utils.IsTarFile and utils.IsGzipFile
		utils.BadRequest(c, "File must be a tar or tar.gz archive")
		return
	}

	// Create temp directory for extraction
	tempPath := filepath.Join(ctrl.tempDir, fmt.Sprintf("extract-archive-%s-%d", containerID, time.Now().UnixNano()))
	defer os.RemoveAll(tempPath)
	err = os.MkdirAll(tempPath, 0755)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to create temp directory")
		utils.InternalServerError(c, "Failed to create temp directory")
		return
	}

	// Save archive file to temp directory
	archivePath := filepath.Join(tempPath, header.Filename)
	outFile, err := os.Create(archivePath)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to create temporary archive file")
		utils.InternalServerError(c, "Failed to process uploaded archive")
		return
	}
	defer outFile.Close()

	// Copy archive file to temp directory
	_, err = io.Copy(outFile, archiveFile)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to save uploaded archive")
		utils.InternalServerError(c, "Failed to save uploaded archive")
		return
	}

	// Close the file after writing
	outFile.Close()

	// Extract archive based on type
	extractDir := filepath.Join(tempPath, "extracted")
	err = os.MkdirAll(extractDir, 0755)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to create extraction directory")
		utils.InternalServerError(c, "Failed to prepare for archive extraction")
		return
	}

	// Open the saved archive file for reading
	archiveFile, err = os.Open(archivePath) // Changed := to =
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to open temporary archive file")
		utils.InternalServerError(c, "Failed to process uploaded archive")
		return
	}
	defer archiveFile.Close()

	// Determine compression type based on filename (or could use http.DetectContentType)
	compression := archiver.CompressionNone
	if strings.HasSuffix(header.Filename, ".gz") || strings.HasSuffix(header.Filename, ".tgz") { // Replaced utils.IsGzipFile
		compression = archiver.CompressionGzip
	}

	// Extract archive using archiver package
	err = archiver.ExtractArchive(archiveFile, extractDir, archiver.ArchiveOptions{
		Compression: compression,
		Overwrite:   overwrite, // Use overwrite flag from request
	})
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to extract archive")
		utils.InternalServerError(c, "Failed to extract archive: "+err.Error()) // Include error details
		return
	}

	// Validate extracted contents for security
	err = validateExtractedContents(extractDir)
	if err != nil {
		ctrl.logger.WithError(err).Error("Invalid archive contents")
		utils.BadRequest(c, "Archive validation failed: "+err.Error())
		return
	}

	// Copy extracted content to container
	err = file.CopyToContainer(c.Request.Context(), ctrl.dockerClient, containerID, extractDir, destinationPath, file.CopyToOptions{ // Renamed CopyTo to CopyToContainer
		Overwrite: overwrite,
		// Recursive: true, // Field does not exist in CopyToOptions
		Timeout: 30 * time.Second,
		Logger:  ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithFields(logrus.Fields{
			"containerID": containerID,
			"extractDir":  extractDir,
			"destPath":    destinationPath,
		}).Error("Failed to copy extracted files to container")
		utils.InternalServerError(c, "Failed to extract archive to container: "+err.Error())
		return
	}

	// Return success
	utils.SuccessResponse(c, gin.H{
		"status":    "success",
		"message":   "Archive extracted successfully",
		"container": containerID,
		"path":      destinationPath,
	})
}

// Helper functions

// force_flag returns the force flag for the rm command
func force_flag(force bool) string {
	if force {
		return "f"
	}
	return ""
}

// validateExtractedContents checks extracted files for security issues using filepath.WalkDir
func validateExtractedContents(dir string) error {
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Propagate errors encountered during walk (e.g., permission denied)
			return fmt.Errorf("error walking extracted directory at %s: %w", path, err)
		}

		// Get the path relative to the extraction directory
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			// Should not happen if walk started correctly, but handle defensively
			return fmt.Errorf("could not get relative path for %s: %w", path, err)
		}

		// Skip the root directory itself
		if relPath == "." {
			return nil
		}

		// Check for absolute paths (using relative path)
		if filepath.IsAbs(relPath) {
			return fmt.Errorf("archive contains absolute paths: %s", relPath)
		}

		// Check for path traversal attempts using the relative path
		cleanRelPath := filepath.Clean(relPath)
		if strings.HasPrefix(cleanRelPath, ".."+string(filepath.Separator)) || cleanRelPath == ".." {
			return fmt.Errorf("archive contains invalid path patterns (traversal attempt): %s", relPath)
		}

		// Get file info for size and permission checks
		info, err := d.Info()
		if err != nil {
			// Handle cases where info cannot be obtained (e.g., broken symlink)
			return fmt.Errorf("could not get file info for %s: %w", relPath, err)
		}

		// Check file size limit (100MB per file) - only for regular files
		if !info.IsDir() && info.Size() > 100*1024*1024 {
			return fmt.Errorf("archive contains files larger than 100MB: %s (%d bytes)", relPath, info.Size())
		}

		// Check for potentially dangerous file types if not dir
		if !info.IsDir() {
			// Check file permissions
			if info.Mode()&0111 != 0 { // Check execute bit
				// File has execute permissions, check if it's a script or binary
				ext := filepath.Ext(relPath)
				dangerousExts := map[string]bool{
					".sh": true, ".bash": true, ".py": true, ".pl": true, ".rb": true, ".exe": true, ".bin": true, ".bat": true, ".cmd": true,
				}
				if dangerousExts[ext] {
					// Attempt to remove execute permissions
					// Use the full path for os.Chmod
					err := os.Chmod(path, info.Mode()&^0111)
					if err != nil {
						// Log warning but don't necessarily fail the whole validation? Or return error?
						// Returning error for now for stricter security.
						return fmt.Errorf("failed to remove execute permissions from potentially dangerous file %s: %w", relPath, err)
					}
					// Log a warning that permissions were modified
					logrus.Warnf("Removed execute permission from potentially dangerous file in archive: %s", relPath)
				}
			}
		}

		// Add more checks here if needed (e.g., symlink validation)

		return nil // Continue walking
	})

	if err != nil {
		// Return the first error encountered during the walk
		return fmt.Errorf("archive validation failed: %w", err)
	}

	return nil // All checks passed
}
