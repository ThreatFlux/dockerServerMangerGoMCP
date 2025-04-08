package container

import (
	"encoding/json" // Added for filter parsing
	"io"            // Added for reading logs
	"net/http"      // Added for status codes
	"strconv"       // Added for timeout parsing
	"strings"       // Added for string manipulation
	"time"          // Added for time parsing

	"github.com/docker/docker/api/types/filters" // Added for Docker filters
	"github.com/docker/docker/errdefs"           // Added for specific error checking
	"github.com/gin-contrib/sse"                 // Added for SSE streaming in Stats
	"github.com/gin-gonic/gin"
	containerSvc "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/container" // Added import alias
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// Start godoc
// @Summary Start a container
// @Description Starts a stopped or created container.
// @Tags Containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Success 204 "Container started successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id}/start [post]
func (ctrl *Controller) Start(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// No request body expected for start, but check for optional query params if needed later.
	// var req models.ContainerStartRequest // Removed JSON binding

	// Check if user has permission to start this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Start container
	startOpts := containerSvc.StartOptions{} // Pass empty options for now
	err := ctrl.containerService.Start(c.Request.Context(), containerID, startOpts)
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to start container")
		// TODO: Improve error handling (e.g., check if already started)
		utils.InternalServerError(c, "Failed to start container: "+err.Error())
		return
	}

	// Return 204 No Content on success
	utils.NoContentResponse(c)
}

// Stop godoc
// @Summary Stop a container
// @Description Stops a running container.
// @Tags Containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Param timeout query int false "Timeout in seconds to wait for container to stop before killing it" default(10) example(5)
// @Success 204 "Container stopped successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID or timeout"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id}/stop [post]
func (ctrl *Controller) Stop(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Parse timeout query parameter (optional)
	timeoutStr := c.DefaultQuery("timeout", "10") // Default to 10 seconds
	timeout, err := strconv.Atoi(timeoutStr)
	if err != nil || timeout < 0 {
		utils.BadRequest(c, "Invalid timeout value provided")
		return
	}

	// Check if user has permission to stop this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Stop container
	stopOpts := containerSvc.StopOptions{ // Use containerSvc alias
		Timeout: timeout,
	}
	err = ctrl.containerService.Stop(c.Request.Context(), containerID, stopOpts) // Use = instead of :=
	if err != nil {
		if errdefs.IsNotFound(err) {
			utils.NotFound(c, "Container not found")
		} else {
			ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to stop container")
			// TODO: Improve error handling for other cases (e.g., already stopped)
			utils.InternalServerError(c, "Failed to stop container: "+err.Error())
		}
		return
	}

	// Return 204 No Content on success
	utils.NoContentResponse(c)
}

// Restart godoc
// @Summary Restart a container
// @Description Restarts a container.
// @Tags Containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Param timeout query int false "Timeout in seconds to wait for container to stop before starting it" default(10) example(5)
// @Success 204 "Container restarted successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID or timeout"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id}/restart [post]
func (ctrl *Controller) Restart(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Parse timeout query parameter (optional)
	timeoutStr := c.DefaultQuery("timeout", "10") // Default to 10 seconds
	timeout, err := strconv.Atoi(timeoutStr)
	if err != nil || timeout < 0 {
		utils.BadRequest(c, "Invalid timeout value provided")
		return
	}

	// Check if user has permission to restart this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Restart container
	restartOpts := containerSvc.RestartOptions{ // Use containerSvc alias
		Timeout: timeout,
	}
	err = ctrl.containerService.Restart(c.Request.Context(), containerID, restartOpts) // Use = instead of :=
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to restart container")
		utils.InternalServerError(c, "Failed to restart container: "+err.Error())
		return
	}

	// Return 204 No Content on success
	utils.NoContentResponse(c)
}

// Pause godoc
// @Summary Pause a container
// @Description Pauses a running container.
// @Tags Containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Success 204 "Container paused successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found or not running"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id}/pause [post]
func (ctrl *Controller) Pause(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Check if user has permission to pause this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Pause container
	err := ctrl.containerService.Pause(c.Request.Context(), containerID)
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to pause container")
		// TODO: Improve error handling (e.g., check if already paused)
		utils.InternalServerError(c, "Failed to pause container: "+err.Error())
		return
	}

	// Return 204 No Content on success
	utils.NoContentResponse(c)
}

// Unpause godoc
// @Summary Unpause a container
// @Description Unpauses a paused container.
// @Tags Containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Success 204 "Container unpaused successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found or not paused"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id}/unpause [post]
func (ctrl *Controller) Unpause(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Check if user has permission to unpause this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Unpause container
	err := ctrl.containerService.Unpause(c.Request.Context(), containerID)
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to unpause container")
		// TODO: Improve error handling (e.g., check if not paused)
		utils.InternalServerError(c, "Failed to unpause container: "+err.Error())
		return
	}

	// Return 204 No Content on success
	utils.NoContentResponse(c)
}

// Rename godoc
// @Summary Rename a container
// @Description Renames an existing container.
// @Tags Containers
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Param name body models.ContainerRenameRequest true "New Container Name"
// @Success 200 {object} models.SuccessResponse{data=models.ContainerResponse} "Successfully renamed container"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID or new name"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 409 {object} models.ErrorResponse "New name already in use"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id}/rename [post]
func (ctrl *Controller) Rename(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Parse request body
	var req models.ContainerRenameRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate new name
	if err := utils.ValidateContainerName(req.Name); err != nil {
		utils.BadRequest(c, "Invalid container name: "+err.Error())
		return
	}

	// Check if user has permission to rename this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Rename container
	err := ctrl.containerService.Rename(c.Request.Context(), containerID, req.Name)
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to rename container")
		// TODO: Improve error handling (check for 409 conflict)
		utils.InternalServerError(c, "Failed to rename container: "+err.Error())
		return
	}

	// Get updated container details (use the new name to fetch)
	container, err := ctrl.containerService.Get(c.Request.Context(), req.Name) // Fetch by new name
	if err != nil {
		ctrl.logger.WithError(err).WithField("newName", req.Name).Error("Failed to get container details after rename")
		utils.InternalServerError(c, "Container was renamed but failed to retrieve updated details")
		return
	}

	// Update container in database if it's managed
	// TODO: Re-enable DB update when ContainerRepository is implemented
	// dbContainer, err := ctrl.containerRepo.FindByContainerID(c.Request.Context(), containerID) // Find by OLD ID
	// if err == nil && dbContainer != nil {
	// 	dbContainer.Name = req.Name
	// 	dbContainer.UpdatedAt = time.Now()
	//
	// 	err = ctrl.containerRepo.Update(c.Request.Context(), dbContainer)
	// 	if err != nil {
	// 		ctrl.logger.WithError(err).WithField("containerID", containerID).Warn("Failed to update container name in database")
	// 	}
	// }

	// Return the updated container
	utils.SuccessResponse(c, toContainerResponse(container)) // Pass the models.Container directly
}

// Remove godoc
// @Summary Remove a container
// @Description Removes a container.
// @Tags Containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Param force query bool false "Force removal of a running container" default(false) example(true)
// @Param volumes query bool false "Remove anonymous volumes associated with the container" default(false) example(true)
// @Success 204 "Container removed successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 409 {object} models.ErrorResponse "Conflict (e.g., container is running and force=false)"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id} [delete]
func (ctrl *Controller) Remove(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Parse query parameters
	force := c.Query("force") == "true"
	removeVolumes := c.Query("volumes") == "true"

	// Check if user has permission to remove this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Remove container
	removeOpts := containerSvc.RemoveOptions{ // Use containerSvc alias
		Force:         force,
		RemoveVolumes: removeVolumes,
		// RemoveLinks: false, // Add if needed
	}
	err := ctrl.containerService.Remove(c.Request.Context(), containerID, removeOpts) // Pass options struct
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to remove container")
		// TODO: Improve error handling (check for 404, 409)
		utils.InternalServerError(c, "Failed to remove container: "+err.Error())
		return
	}

	// Remove from database if it's managed
	// TODO: Re-enable DB delete when ContainerRepository is implemented
	// dbContainer, err := ctrl.containerRepo.FindByContainerID(c.Request.Context(), containerID)
	// if err == nil && dbContainer != nil {
	// 	err = ctrl.containerRepo.Delete(c.Request.Context(), dbContainer.ID)
	// 	if err != nil {
	// 		ctrl.logger.WithError(err).WithField("containerID", containerID).Warn("Failed to delete container from database")
	// 	}
	// }

	// Return success
	utils.NoContentResponse(c)
}

// Logs godoc
// @Summary Get container logs
// @Description Retrieves logs from a container. Can optionally stream logs.
// @Tags Containers
// @Produce plain
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Param follow query bool false "Stream logs" default(false) example(true)
// @Param stdout query bool false "Include stdout" default(true) example(true)
// @Param stderr query bool false "Include stderr" default(true) example(true)
// @Param since query string false "Show logs since timestamp (e.g., 2013-01-02T13:23:37Z) or relative (e.g., 42m for 42 minutes)" example(1h)
// @Param until query string false "Show logs before timestamp (e.g., 2013-01-02T13:23:37Z) or relative (e.g., 42m for 42 minutes)" example(2023-10-27T11:00:00Z)
// @Param timestamps query bool false "Show timestamps" default(false) example(true)
// @Param tail query string false "Number of lines to show from the end of the logs (e.g., 100 or all)" default("all") example(50)
// @Success 200 {string} string "Container logs stream"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID or query parameters"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id}/logs [get]
func (ctrl *Controller) Logs(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Parse query parameters
	var req models.ContainerLogsRequest
	if !utils.BindQuery(c, &req) { // Use BindQuery for GET requests
		return
	}

	// Set default values
	if !req.ShowStdout && !req.ShowStderr {
		req.ShowStdout = true
		req.ShowStderr = true
	}

	// Check if user has permission to get logs for this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Create LogOptions from request
	logOpts := containerSvc.LogOptions{ // Use containerSvc alias
		ShowStdout: req.ShowStdout,
		ShowStderr: req.ShowStderr,
		Since:      req.Since, // Assuming time.Time binding works correctly
		Until:      req.Until, // Assuming time.Time binding works correctly
		Timestamps: req.Timestamps,
		Follow:     req.Follow,
		Tail:       req.Tail,
		// Details: false, // Add if needed
	}

	// Get logs
	logsReader, err := ctrl.containerService.Logs(c.Request.Context(), containerID, logOpts) // Pass options struct, rename result
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to get container logs")
		// TODO: Improve error handling (404)
		utils.InternalServerError(c, "Failed to get container logs: "+err.Error())
		return
	}
	defer logsReader.Close() // Ensure the reader is closed

	// Stream logs directly to the client
	// Set appropriate headers for streaming plain text
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("X-Content-Type-Options", "nosniff") // Prevent browser from interpreting content

	// Stream the logs
	// Use c.Writer directly for streaming
	_, err = io.Copy(c.Writer, logsReader)
	if err != nil {
		// Log the error, but we might not be able to send a JSON error response
		// if headers have already been written.
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Error streaming container logs")
		// Attempt to write an error status if possible (might not work if streaming started)
		if !c.Writer.Written() {
			// Can't use utils helpers here as they write JSON
			c.String(http.StatusInternalServerError, "Error streaming logs: %v", err)
		}
		return // Important to return here
	}

	// If follow=true, this handler will block until the stream is closed.
	// If follow=false, io.Copy will return once logs are finished.
	// No explicit JSON response is sent when streaming successfully.
}

// Stats godoc
// @Summary Get container resource usage statistics
// @Description Retrieves a live stream or a single snapshot of resource usage statistics for a container.
// @Tags Containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Param stream query bool false "Stream stats (true) or get a single snapshot (false)" default(false) example(true)
// @Success 200 {object} models.SuccessResponse{data=models.ContainerStats} "Container statistics (if stream=false)"
// @Success 200 {string} string "Container statistics stream (if stream=true, Content-Type: text/event-stream)"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id}/stats [get]
func (ctrl *Controller) Stats(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	stream := c.Query("stream") == "true"

	// Check if user has permission to get stats for this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Get stats
	statsOpts := containerSvc.StatsOptions{ // Use containerSvc alias
		Stream:  stream,
		OneShot: !stream, // OneShot should be true if stream is false
	}

	if !stream {
		// Get single stats reading
		stats, err := ctrl.containerService.Stats(c.Request.Context(), containerID, statsOpts) // Pass options struct
		if err != nil {
			ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to get container stats")
			// TODO: Improve error handling (404)
			utils.InternalServerError(c, "Failed to get container stats: "+err.Error())
			return
		}
		// Return stats
		utils.SuccessResponse(c, stats)
	} else {
		// Stream stats using SSE
		statsCh, errCh := ctrl.containerService.StreamStats(c.Request.Context(), containerID, statsOpts)

		c.Writer.Header().Set("Content-Type", "text/event-stream")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*") // Adjust CORS

		streamClosed := c.Stream(func(w io.Writer) bool {
			select {
			case stats, ok := <-statsCh:
				if !ok {
					return false
				} // Channel closed
				// Use sse.Encode directly
				sse.Encode(w, sse.Event{
					Event: "stats",
					Data:  stats, // Assuming stats is already marshallable
				})
				return true // Keep stream open
			case err, ok := <-errCh:
				if !ok {
					return false
				} // Channel closed
				ctrl.logger.WithError(err).Error("Error from stats stream")
				// Use sse.Encode directly for error
				sse.Encode(w, sse.Event{
					Event: "error",
					Data:  gin.H{"error": err.Error()},
				})
				return false // Close stream on error
			case <-c.Request.Context().Done():
				ctrl.logger.Info("Client disconnected from stats stream")
				return false // Close stream
			}
		})

		if streamClosed {
			ctrl.logger.Info("SSE stats stream to client closed")
		}
	}
}

// Top godoc
// @Summary List processes running inside a container
// @Description Shows the processes running inside a container, similar to the 'top' command.
// @Tags Containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "Container ID or Name"
// @Param ps_args query string false "Arguments to pass to 'ps' command (e.g., -ef)" default("")
// @Success 200 {object} models.SuccessResponse{data=models.TopResponse} "Successfully retrieved process list"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found or not running"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id}/top [get]
func (ctrl *Controller) Top(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Parse query parameters
	psArgs := c.DefaultQuery("ps_args", "")
	// _ = psArgs // Avoid unused variable error - Now used

	// Check if user has permission to get top for this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Get processes
	processes, err := ctrl.containerService.Top(c.Request.Context(), containerID, psArgs)
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to get container processes")
		// TODO: Improve error handling (404)
		utils.InternalServerError(c, "Failed to get container processes: "+err.Error())
		return
	}

	// Return processes
	utils.SuccessResponse(c, processes)
}

// Changes godoc
// @Summary Inspect changes on a container's filesystem
// @Description Shows changes to files or directories on a container's filesystem since it was created.
// @Tags Containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Success 200 {object} models.SuccessResponse{data=[]models.ChangeItemResponse} "Successfully retrieved filesystem changes"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id}/changes [get]
func (ctrl *Controller) Changes(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Check if user has permission to get changes for this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Get changes
	changes, err := ctrl.containerService.Changes(c.Request.Context(), containerID)
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to get container changes")
		// TODO: Improve error handling (404)
		utils.InternalServerError(c, "Failed to get container changes: "+err.Error())
		return
	}

	// Convert to response type
	responseItems := make([]models.ChangeItemResponse, len(changes))
	for i, item := range changes {
		responseItems[i] = models.ChangeItemResponse{
			Path: item.Path,
			Kind: item.Kind,
		}
	}

	// Return changes
	utils.SuccessResponse(c, responseItems)
}

// ListContainers godoc
// @Summary List containers
// @Description Get a list of containers based on optional filters.
// @Tags Containers
// @Produce json
// @Security BearerAuth
// @Param all query bool false "Show all containers (default shows just running)" default(false)
// @Param limit query int false "Maximum number of containers to return" default(-1)
// @Param size query bool false "Return container sizes" default(false)
// @Param filters query string false "Filters to apply (JSON map format, e.g., {\"status\":[\"running\"]})"
// @Success 200 {object} models.SuccessResponse{data=models.ContainerListResponse} "Successfully retrieved container list"
// @Failure 400 {object} models.ErrorResponse "Invalid filter format"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers [get]
func (ctrl *Controller) ListContainers(c *gin.Context) {
	// Parse query parameters
	all := c.Query("all") == "true"
	limitStr := c.DefaultQuery("limit", "-1")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		utils.BadRequest(c, "Invalid limit parameter")
		return
	}
	size := c.Query("size") == "true"
	filtersJSON := c.Query("filters")

	// Parse filters if provided
	var filterArgs filters.Args
	if filtersJSON != "" {
		var filterMap map[string][]string
		if err := json.Unmarshal([]byte(filtersJSON), &filterMap); err != nil {
			utils.BadRequest(c, "Invalid filters format: "+err.Error())
			return
		}
		filterArgs = filters.NewArgs()
		for key, values := range filterMap {
			for _, value := range values {
				filterArgs.Add(key, value)
			}
		}
	} else {
		filterArgs = filters.NewArgs() // Ensure filterArgs is initialized
	}

	// List options
	listOpts := containerSvc.ListOptions{ // Use containerSvc alias
		All:     all,
		Limit:   limit,
		Size:    size,
		Filters: filterArgs,
	}

	// List containers
	containers, err := ctrl.containerService.List(c.Request.Context(), listOpts)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to list containers")
		utils.InternalServerError(c, "Failed to list containers: "+err.Error())
		return
	}

	// Convert to response type
	// TODO: Implement pagination if needed
	respData := models.ContainerListResponse{
		Containers: toContainerListResponse(containers), // Pass []models.Container
		Metadata: models.MetadataResponse{
			Timestamp: time.Now(),
			RequestID: utils.GetRequestID(c),
			// Pagination: &models.PaginationResponse{...} // Add if paginating
		},
	}

	// Return list
	utils.SuccessResponse(c, respData)
}

// GetContainer godoc
// @Summary Get container details
// @Description Get detailed information about a specific container.
// @Tags Containers
// @Produce json
// @Security BearerAuth
// @Param id path string true "Container ID or Name" example(my-nginx-container)
// @Success 200 {object} models.SuccessResponse{data=models.ContainerResponse} "Successfully retrieved container details"
// @Failure 400 {object} models.ErrorResponse "Invalid container ID"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /containers/{id} [get]
func (ctrl *Controller) GetContainer(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Check if user has permission to get this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Get container details
	container, err := ctrl.containerService.Get(c.Request.Context(), containerID)
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to get container details")
		// TODO: Improve error handling (404)
		// Check if the error is a "not found" error from the Docker client
		if strings.Contains(err.Error(), "No such container") { // Basic check, might need refinement
			utils.NotFound(c, "Container not found")
		} else {
			utils.InternalServerError(c, "Failed to get container details: "+err.Error())
		}
		return
	}

	// Convert to response type
	utils.SuccessResponse(c, toContainerResponse(container)) // Pass the models.Container directly
}

// toContainerResponse converts a models.Container (likely enriched) to a models.ContainerResponse
// Note: This assumes the input is *models.Container from containerService.Get
func toContainerResponse(mContainer *models.Container) models.ContainerResponse { // Accept *models.Container
	// Start with fields directly available in models.Container
	resp := models.ContainerResponse{
		ID:            mContainer.ID, // Use the DB ID
		ContainerID:   mContainer.ContainerID,
		Name:          mContainer.Name,
		Image:         mContainer.Image, // Assuming Image field exists in models.Container
		ImageID:       mContainer.ImageID,
		Command:       mContainer.Command,
		Status:        mContainer.Status,
		State:         mContainer.State,              // Assuming State field exists
		Labels:        mContainer.Labels.StringMap(), // Convert JSONMap
		RestartPolicy: string(mContainer.RestartPolicy),
		Platform:      mContainer.Platform,
		Notes:         mContainer.Notes,
		UserID:        mContainer.UserID,
		CreatedAt:     mContainer.CreatedAt, // DB CreatedAt
		UpdatedAt:     mContainer.UpdatedAt, // DB UpdatedAt
	}

	// Use CreatedAt from DB model if available, otherwise parse from Docker info if needed
	// resp.Created = mContainer.CreatedAt // Already set from DB

	// State details (might be redundant if already in mContainer)
	if mContainer.State != "" { // Check if State is populated
		// resp.State = mContainer.State // Already set
		// resp.Status = mContainer.Status // Already set
		if !mContainer.StartedAt.IsZero() {
			resp.Started = mContainer.StartedAt
		}
		if !mContainer.FinishedAt.IsZero() {
			resp.Finished = mContainer.FinishedAt
		}
	}

	// Map Ports from models.Container.Ports (JSONMap)
	if mContainer.Ports != nil {
		resp.Ports = make([]models.PortMapping, 0, len(mContainer.Ports))
		// Assuming mContainer.Ports stores []PortMapping as JSON
		var portsData []models.PortMapping
		portBytes, _ := mContainer.Ports.Value() // Get JSON string/bytes
		if portStr, ok := portBytes.(string); ok {
			_ = json.Unmarshal([]byte(portStr), &portsData) // Unmarshal into slice
		} else if portByteSlice, ok := portBytes.([]byte); ok {
			_ = json.Unmarshal(portByteSlice, &portsData) // Unmarshal into slice
		}
		// Now map the unmarshalled data
		for _, p := range portsData {
			resp.Ports = append(resp.Ports, models.PortMapping{
				HostIP:        p.HostIP,
				HostPort:      p.HostPort,
				ContainerPort: p.ContainerPort,
				Type:          p.Type,
			})
		}
	}

	// Map Mounts from models.Container.Mounts (assuming it exists and is similar structure)
	// If Mounts are stored differently (e.g., JSONMap), adjust this logic
	resp.Volumes = make([]models.VolumeMountResponse, 0, len(mContainer.Mounts))
	for _, mount := range mContainer.Mounts { // Assuming mContainer.Mounts is []models.MountPoint
		resp.Volumes = append(resp.Volumes, models.VolumeMountResponse{
			Source:      mount.Source,
			Destination: mount.Destination,
			Mode:        mount.Mode,
			RW:          mount.RW,
			// VolumeID might need separate lookup if it's a named volume
		})
	}

	// Map Networks from models.Container.DetailedNetworkInfo (assuming it's populated)
	if mContainer.DetailedNetworkInfo != nil {
		resp.Networks = make([]models.NetworkConnectionResponse, 0, len(mContainer.DetailedNetworkInfo))
		for name, settings := range mContainer.DetailedNetworkInfo { // Iterate over the map
			// Need to find the specific endpoint details for *this* container within the network
			// This might require looking at mContainer.Networks (JSONMap) or similar field
			// For now, create a basic entry - needs refinement based on actual data structure
			resp.Networks = append(resp.Networks, models.NetworkConnectionResponse{
				NetworkID:   settings.ID,
				NetworkName: name,
				// IPAddress, Gateway, MacAddress, Aliases need to be sourced correctly
				// Potentially from mContainer.Networks JSONMap or mContainer.IPAddress
				IPAddress: mContainer.IPAddress, // Best guess for now
			})
		}
	}

	// Map HostConfig from models.Container fields if available
	// This requires models.Container to store these details, possibly in JSONMap fields
	// Example: Assuming ResourceLimits and SecurityInfo are populated
	// Ensure HostConfig is initialized before accessing fields
	if resp.HostConfig == nil {
		resp.HostConfig = &models.HostConfigResponse{}
	}
	// Check if ResourceLimits and SecurityInfo are populated before accessing
	if mContainer.ResourceLimits != (models.ResourceLimits{}) { // Check if not zero value
		resp.HostConfig.CPUShares = mContainer.ResourceLimits.CPUShares
		resp.HostConfig.Memory = mContainer.ResourceLimits.Memory
		resp.HostConfig.MemorySwap = mContainer.ResourceLimits.MemorySwap
		resp.HostConfig.CPUPeriod = mContainer.ResourceLimits.CPUPeriod
		resp.HostConfig.CPUQuota = mContainer.ResourceLimits.CPUQuota
		resp.HostConfig.CpusetCpus = mContainer.ResourceLimits.CpusetCpus
		resp.HostConfig.CpusetMems = mContainer.ResourceLimits.CpusetMems
		resp.HostConfig.BlkioWeight = mContainer.ResourceLimits.BlkioWeight
		// PidsLimit is not in HostConfigResponse, remove assignment
	}
	// Check if SecurityInfo seems populated (e.g., by checking if SecurityOpt is non-nil)
	// Avoid direct struct comparison due to slices.
	if mContainer.SecurityInfo.SecurityOpt != nil || mContainer.SecurityInfo.CapAdd != nil || mContainer.SecurityInfo.CapDrop != nil {
		resp.HostConfig.Privileged = mContainer.SecurityInfo.Privileged
		resp.HostConfig.ReadonlyRootfs = mContainer.SecurityInfo.ReadOnlyRootfs
		resp.HostConfig.SecurityOpt = mContainer.SecurityInfo.SecurityOpt
		resp.HostConfig.CapAdd = mContainer.SecurityInfo.CapAdd
		resp.HostConfig.CapDrop = mContainer.SecurityInfo.CapDrop
		// NetworkMode is already mapped directly from mContainer
	}
	// Map RestartPolicy directly from mContainer
	resp.HostConfig.RestartPolicy = string(mContainer.RestartPolicy)
	resp.HostConfig.NetworkMode = string(mContainer.NetworkMode)

	return resp
}

// toContainerListResponse converts a slice of models.Container to a slice of models.ContainerResponse
// Note: This assumes the input is []models.Container from containerService.List
func toContainerListResponse(containers []models.Container) []models.ContainerResponse { // Accept []models.Container
	responses := make([]models.ContainerResponse, len(containers))
	for i, mContainer := range containers { // Iterate over models.Container
		// Use fields directly from models.Container
		resp := models.ContainerResponse{
			ID:          mContainer.ID, // Use DB ID
			ContainerID: mContainer.ContainerID,
			Name:        mContainer.Name,
			Image:       mContainer.Image,
			ImageID:     mContainer.ImageID,
			Command:     mContainer.Command,
			State:       mContainer.State,
			Status:      mContainer.Status,
			Created:     mContainer.CreatedAt, // Use DB CreatedAt or parse Docker Created if needed
			Labels:      mContainer.Labels.StringMap(),
			Platform:    mContainer.Platform,
			Notes:       mContainer.Notes,
			UserID:      mContainer.UserID,
			CreatedAt:   mContainer.CreatedAt,
			UpdatedAt:   mContainer.UpdatedAt,
		}

		// Map Ports from models.Container.Ports (JSONMap)
		if mContainer.Ports != nil {
			resp.Ports = make([]models.PortMapping, 0, len(mContainer.Ports))
			var portsData []models.PortMapping
			portBytes, _ := mContainer.Ports.Value()
			if portStr, ok := portBytes.(string); ok {
				_ = json.Unmarshal([]byte(portStr), &portsData)
			} else if portByteSlice, ok := portBytes.([]byte); ok {
				_ = json.Unmarshal(portByteSlice, &portsData)
			}
			for _, p := range portsData {
				resp.Ports = append(resp.Ports, models.PortMapping{
					HostIP:        p.HostIP,
					HostPort:      p.HostPort,
					ContainerPort: p.ContainerPort,
					Type:          p.Type,
				})
			}
		}

		// Map Mounts from models.Container.Mounts
		resp.Volumes = make([]models.VolumeMountResponse, 0, len(mContainer.Mounts))
		for _, mount := range mContainer.Mounts {
			resp.Volumes = append(resp.Volumes, models.VolumeMountResponse{
				Source:      mount.Source,
				Destination: mount.Destination,
				Mode:        mount.Mode,
				RW:          mount.RW,
			})
		}

		// Map Networks from models.Container.DetailedNetworkInfo or Networks JSONMap
		if mContainer.DetailedNetworkInfo != nil {
			resp.Networks = make([]models.NetworkConnectionResponse, 0, len(mContainer.DetailedNetworkInfo))
			for name, settings := range mContainer.DetailedNetworkInfo {
				resp.Networks = append(resp.Networks, models.NetworkConnectionResponse{
					NetworkID:   settings.ID,
					NetworkName: name,
					IPAddress:   mContainer.IPAddress, // Best guess
					// Gateway, MacAddress, Aliases might need more info
				})
			}
		} else if mContainer.Networks != nil {
			// Fallback or alternative: Parse Networks JSONMap if DetailedNetworkInfo isn't populated
			// This requires knowing the structure stored in mContainer.Networks
		}

		responses[i] = resp
	}
	return responses
}

// hasContainerPermission checks if the user has permission to operate on a container
func (ctrl *Controller) hasContainerPermission(c *gin.Context, containerID string) bool {
	// Get user ID from context
	userID, err := middleware.GetUserID(c) // Pass gin.Context
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return false
	}
	_ = userID // Avoid unused variable error for now

	// Check if the user is an admin (has full access)
	isAdminUser, err := middleware.IsAdmin(c) // Use IsAdmin from middleware
	if err != nil {
		// Handle error getting roles, maybe log and deny?
		ctrl.logger.WithError(err).Warn("Could not determine user admin status")
		utils.InternalServerError(c, "Failed to verify user permissions")
		return false
	}
	if isAdminUser {
		return true
	}

	// For now, allow access only if admin, as DB lookup is commented out.
	// TODO: Implement proper permission check using ContainerRepository.
	// Re-check admin status in case of error above
	isAdminUser, _ = middleware.IsAdmin(c) // Ignore error here as it was handled above
	if !isAdminUser {
		utils.Forbidden(c, "Permission check requires database access (not implemented)")
		return false
	}

	// If admin, allow access
	return true
}

// isAdmin is defined in list.go, remove this duplicate
// func isAdmin(c *gin.Context) bool { ... }
