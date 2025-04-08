package container

import (
	// "archive/tar" // Removed unused import
	// "bytes" // Removed unused import
	"fmt"
	"io"
	// "net/http" // Removed unused import
	"os"            // Re-add for temp file handling
	"path/filepath" // Added for path cleaning
	"strings"       // Added for error checking

	"github.com/gin-gonic/gin"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/container" // Import local container package
	_ "github.com/threatflux/dockerServerMangerGoMCP/internal/models"         // Use blank identifier for swag annotations
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// GetFiles godoc
// @Summary Download file or directory from container
// @Description Retrieves a file or directory from a container as a TAR archive.
// @Tags Containers
// @Produce application/x-tar
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Param path query string true "Absolute path to the file or directory inside the container" example(/etc/nginx/nginx.conf)
// @Success 200 {file} binary "TAR archive of the requested path"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID or missing path parameter"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container or path not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id}/files [get]
func (ctrl *Controller) GetFiles(c *gin.Context) {
	containerID := c.Param("id")
	path := c.Query("path")
	if path == "" {
		utils.BadRequest(c, "Missing required query parameter: path")
		return
	}

	// Sanitize the path
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		// Consider making paths relative to a base dir or requiring absolute paths
		utils.BadRequest(c, "Path must be absolute")
		return
	}

	ctrl.logger.WithField("containerID", containerID).WithField("path", path).Info("Getting archive from container")

	// Use the service to get the archive stream and stats
	archiveReader, _, err := ctrl.containerService.GetArchive(c.Request.Context(), containerID, container.ArchiveOptions{Path: path}) // Use blank identifier for stat
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).WithField("path", path).Error("Failed to get archive from service")
		// Differentiate errors based on message content
		errStr := err.Error()
		if strings.Contains(errStr, "not found") {
			if strings.Contains(errStr, "container") {
				utils.NotFound(c, "Container not found")
			} else {
				utils.NotFound(c, "Path not found in container")
			}
		} else {
			utils.InternalServerError(c, "Failed to retrieve file or directory: "+errStr)
		}
		return
	}
	defer archiveReader.Close()

	// Set headers for file download
	// Use the base name of the path for the download filename
	downloadName := filepath.Base(path) + ".tar"
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, downloadName))
	c.Header("Content-Type", "application/x-tar")
	// Set Content-Length if available (stat.Size might be for the file itself, not the tar)
	// Docker API doesn't guarantee Content-Length for the tar stream, so we stream it.
	// c.Header("Content-Length", fmt.Sprintf("%d", stat.Size)) // Be cautious with this

	// Stream the archive content directly to the response
	_, err = io.Copy(c.Writer, archiveReader)
	if err != nil {
		// Log error, but response headers might already be sent
		ctrl.logger.WithError(err).WithField("containerID", containerID).WithField("path", path).Error("Failed to stream archive to client")
		// Avoid writing another response header if possible
		// c.String(http.StatusInternalServerError, "Error streaming file content")
	}

	// Gin handles setting status code implicitly if data is written successfully (usually 200 OK)
}

// PutFiles godoc
// @Summary Upload file or directory to container
// @Description Uploads a TAR archive to a specified path within a container. The request body must be the TAR archive.
// @Tags Containers
// @Accept application/x-tar
// @Produce json
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Param path query string true "Absolute destination path inside the container" example(/usr/share/nginx/html)
// @Param archive body []byte true "TAR archive content"
// @Success 200 {object} models.SuccessResponse{message=string} "Archive successfully uploaded"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID, missing path parameter, or empty/invalid request body (e.g., malformed tar)"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error (e.g., failed to write archive)"
// @Router /containers/{id}/files [post]
func (ctrl *Controller) PutFiles(c *gin.Context) {
	containerID := c.Param("id")
	// Destination path inside the container
	destPath := c.Query("path")
	if destPath == "" {
		utils.BadRequest(c, "Missing required query parameter: path (destination path inside container)")
		return
	}

	// Sanitize the destination path
	destPath = filepath.Clean(destPath)
	if !filepath.IsAbs(destPath) {
		utils.BadRequest(c, "Destination path must be absolute")
		return
	}

	// Create a temporary file to store the uploaded archive
	tempFile, err := os.CreateTemp("", "upload-*.tar")
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to create temporary file for upload")
		utils.InternalServerError(c, "Failed to process upload")
		return
	}
	defer os.Remove(tempFile.Name()) // Ensure cleanup
	defer tempFile.Close()

	// Copy request body to the temporary file
	written, err := io.Copy(tempFile, c.Request.Body)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to write request body to temporary file")
		utils.InternalServerError(c, "Failed to process upload data")
		return
	}
	if written == 0 {
		utils.BadRequest(c, "Request body cannot be empty (must contain TAR archive)")
		return
	}

	// Rewind the temporary file to read from the beginning
	_, err = tempFile.Seek(0, io.SeekStart)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to seek temporary file")
		utils.InternalServerError(c, "Failed to process upload data")
		return
	}

	ctrl.logger.WithField("containerID", containerID).WithField("path", destPath).Info("Putting archive into container from temp file")

	// Use the service to put the archive, passing the temp file reader
	err = ctrl.containerService.PutArchive(c.Request.Context(), containerID, destPath, tempFile) // Pass temp file reader
	if err != nil {
		errStr := err.Error()
		ctrl.logger.WithError(err).WithField("containerID", containerID).WithField("path", destPath).Error("Failed to put archive into container")

		// Differentiate errors based on message content
		if strings.Contains(errStr, "not found") {
			utils.NotFound(c, "Container not found")
		} else if strings.Contains(errStr, "malformed archive") || strings.Contains(errStr, "tar") {
			utils.BadRequest(c, "Invalid archive format: "+errStr)
		} else if strings.Contains(errStr, "permission denied") {
			utils.Forbidden(c, "Permission denied to write to path: "+errStr)
		} else {
			utils.InternalServerError(c, "Failed to upload archive: "+errStr)
		}
		return
	}

	// Use standard Gin JSON response for success
	utils.SuccessResponse(c, gin.H{"message": "Archive successfully uploaded to " + destPath}) // Use helper
}
