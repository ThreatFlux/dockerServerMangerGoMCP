package container

import (
	"bufio" // Added import
	"encoding/json"
	"io"  // Added import
	"net" // Added import
	"net/http"

	"github.com/docker/docker/pkg/stdcopy" // Added import for StdCopy
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	containerExec "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/container/exec" // Added import
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/middleware" // Removed unused import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin for now
	},
}

// Exec handles POST /containers/:id/exec
// @Summary      Execute Command in Container
// @Description  Creates and starts an exec instance in a running container.
// @Description  Supports both non-interactive execution (HTTP POST) and interactive sessions (WebSocket upgrade).
// @Description  For interactive sessions, upgrade the connection to WebSocket.
// @Tags         Containers
// @Accept       json
// @Produce      json
// @Security BearerAuth
// @Param        id   path      string                             true  "Container ID" example(my-running-container)
// @Param        exec body      models.ContainerExecCreateRequest  true  "Exec configuration"
// @Success      200  {object}  models.ContainerExecResponse       "Success (non-interactive)"
// @Success      101  {string}  string                             "Switching Protocols (interactive WebSocket)"
// @Failure      400  {object}  models.ErrorResponse               "Bad Request (e.g., missing command, invalid ID)"
// @Failure      401  {object}  models.ErrorResponse               "Unauthorized"
// @Failure      403  {object}  models.ErrorResponse               "Forbidden (user lacks permission)"
// @Failure      404  {object}  models.ErrorResponse               "Container Not Found"
// @Failure      500  {object}  models.ErrorResponse               "Internal Server Error"
// @Router       /api/v1/containers/{id}/exec [post]
func (ctrl *Controller) Exec(c *gin.Context) {
	// Get container ID from path parameter
	containerID := c.Param("id")
	if containerID == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	// Parse request body
	var req models.ContainerExecCreateRequest // Use ContainerExecCreateRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate exec request
	if len(req.Command) == 0 { // Use req.Command
		utils.BadRequest(c, "Command is required")
		return
	}

	// Check if user has permission to exec in this container
	if !ctrl.hasContainerPermission(c, containerID) {
		return
	}

	// Check if this is a WebSocket request
	isWebsocket := isWebSocketRequest(c.Request)

	if isWebsocket {
		// Handle WebSocket connection for interactive session
		handleExecWebSocket(c, ctrl, containerID, req)
	} else {
		// Handle regular HTTP request for non-interactive execution
		handleExecHTTP(c, ctrl, containerID, req)
	}
}

// handleExecWebSocket manages interactive exec through WebSocket
func handleExecWebSocket(c *gin.Context, ctrl *Controller, containerID string, req models.ContainerExecCreateRequest) { // Use ContainerExecCreateRequest
	// Force TTY and attach stdin for interactive sessions
	req.AttachStdin = true
	req.AttachStdout = true
	req.AttachStderr = true
	req.Tty = true

	// Get underlying Docker client
	dockerAPIClient, err := ctrl.dockerManager.GetClient() // Use dockerManager
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to get Docker client for exec create")
		utils.InternalServerError(c, "Failed to connect to Docker service")
		return
	}

	// Map request to exec config
	execConfig := mapRequestToExecConfig(req)
	createOpts := containerExec.CreateOptions{Logger: ctrl.logger} // Add options if needed

	// Create exec instance using the package function
	execID, err := containerExec.Create(c.Request.Context(), dockerAPIClient, containerID, execConfig, createOpts)
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to create exec instance")
		utils.InternalServerError(c, "Failed to create exec instance: "+err.Error())
		return
	}

	// Upgrade connection to WebSocket
	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to upgrade connection to WebSocket")
		return
	}
	defer ws.Close()

	// Start the exec instance (but don't wait)
	startOpts := containerExec.StartOptions{
		Logger:       ctrl.logger,
		AttachStdin:  execConfig.AttachStdin,
		AttachStdout: execConfig.AttachStdout,
		AttachStderr: execConfig.AttachStderr,
		Tty:          execConfig.Tty,
	}
	hijackedResp, err := containerExec.Start(c.Request.Context(), dockerAPIClient, execID, startOpts)
	if err != nil {
		ctrl.logger.WithError(err).WithFields(map[string]interface{}{
			"containerID": containerID,
			"execID":      execID,
		}).Error("Failed to start exec instance for WebSocket")
		// Try to send error over WebSocket before closing
		errMsg, _ := json.Marshal(map[string]string{"error": "Failed to start exec: " + err.Error()})
		ws.WriteMessage(websocket.TextMessage, errMsg)
		return // Exit after sending error
	}
	defer hijackedResp.Close() // Ensure the connection is closed

	// Type assert to access underlying connection details if possible
	// This assumes Start returns a type embedding types.HijackedResponse
	execConn, ok := hijackedResp.(interface {
		Conn() net.Conn // Assuming net.Conn or similar
		CloseWrite() error
		Reader() *bufio.Reader // Assuming bufio.Reader
	})
	if !ok {
		ctrl.logger.WithField("execID", execID).Error("Failed to get underlying connection from exec start response")
		// Try to send error over WebSocket
		errMsg, _ := json.Marshal(map[string]string{"error": "Internal server error: could not access exec stream"})
		ws.WriteMessage(websocket.TextMessage, errMsg)
		return
	}

	// Goroutine to read from WebSocket and write to exec stdin
	go func() {
		defer execConn.CloseWrite() // Close stdin when done reading from WebSocket
		for {
			messageType, p, err := ws.ReadMessage()
			if err != nil {
				// Log WebSocket read errors (client closed connection, etc.)
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					ctrl.logger.WithError(err).WithField("execID", execID).Warn("WebSocket read error")
				} else {
					ctrl.logger.WithField("execID", execID).Debug("WebSocket connection closed")
				}
				return
			}
			if messageType == websocket.TextMessage || messageType == websocket.BinaryMessage {
				if _, err := execConn.Conn().Write(p); err != nil { // Use execConn.Conn()
					ctrl.logger.WithError(err).WithField("execID", execID).Warn("Error writing to exec stdin")
					return
				}
			}
		}
	}()

	// Goroutine to read from exec stdout/stderr and write to WebSocket
	go func() {
		// Use customStdCopy or stdcopy.StdCopy based on TTY
		var writer io.Writer = &wsWriter{ws: ws} // Simple writer for WebSocket
		if !execConfig.Tty {
			// Demultiplex stdout/stderr if not TTY
			_, err := stdcopy.StdCopy(writer, writer, execConn.Reader()) // Use stdcopy and execConn.Reader()
			if err != nil && err != io.EOF {
				ctrl.logger.WithError(err).WithField("execID", execID).Warn("Error reading from exec stdout/stderr (demux)")
			}
		} else {
			// Copy directly if TTY
			_, err := io.Copy(writer, execConn.Reader()) // Use io.Copy and execConn.Reader()
			if err != nil && err != io.EOF {
				ctrl.logger.WithError(err).WithField("execID", execID).Warn("Error reading from exec stdout (TTY)")
			}
		}
		ctrl.logger.WithField("execID", execID).Debug("Finished reading from exec output")
		// Optionally send a close message or wait for exit code here if needed
	}()

	// Keep the handler alive while goroutines run
	// We could wait for an exit signal or just let the goroutines handle closure.
	// For simplicity, we let the read goroutine exit when the WebSocket closes.
	// A more robust implementation might wait for the exec to finish.
	select {} // Block indefinitely (or until connection closes)

}

// wsWriter is a simple io.Writer wrapper for WebSocket connections
type wsWriter struct {
	ws *websocket.Conn
}

func (w *wsWriter) Write(p []byte) (int, error) {
	err := w.ws.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// handleExecHTTP manages non-interactive exec through HTTP
func handleExecHTTP(c *gin.Context, ctrl *Controller, containerID string, req models.ContainerExecCreateRequest) { // Use ContainerExecCreateRequest
	// Default to capturing stdout/stderr
	if !req.AttachStdout && !req.AttachStderr {
		req.AttachStdout = true
		req.AttachStderr = true
	}

	// Get underlying Docker client
	dockerAPIClient, err := ctrl.dockerManager.GetClient() // Use dockerManager
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to get Docker client for exec create (HTTP)")
		utils.InternalServerError(c, "Failed to connect to Docker service")
		return
	}

	// Map request to exec config
	execConfig := mapRequestToExecConfig(req)
	createOpts := containerExec.CreateOptions{Logger: ctrl.logger} // Add options if needed

	// Create exec instance using the package function
	execID, err := containerExec.Create(c.Request.Context(), dockerAPIClient, containerID, execConfig, createOpts)
	if err != nil {
		ctrl.logger.WithError(err).WithField("containerID", containerID).Error("Failed to create exec instance")
		utils.InternalServerError(c, "Failed to create exec instance: "+err.Error())
		return
	}

	// Start exec and wait for completion
	startOpts := containerExec.StartOptions{ // Create StartOptions
		Logger:       ctrl.logger,
		AttachStdin:  execConfig.AttachStdin, // Pass relevant fields from execConfig
		AttachStdout: execConfig.AttachStdout,
		AttachStderr: execConfig.AttachStderr,
		Tty:          execConfig.Tty,
	}
	exitCode, _, _, err := containerExec.StartAndWait(c.Request.Context(), dockerAPIClient, execID, startOpts) // Assign stdout/stderr to _
	// TODO: Decide if stdoutBytes/stderrBytes should be returned in the response
	if err != nil {
		ctrl.logger.WithError(err).WithFields(map[string]interface{}{
			"containerID": containerID,
			"execID":      execID,
		}).Error("Failed to start exec instance")
		utils.InternalServerError(c, "Failed to start exec instance: "+err.Error())
		return
	}

	// Get exec inspection info (using direct client call as Inspect func doesn't seem to exist in exec package)
	inspect, err := dockerAPIClient.ContainerExecInspect(c.Request.Context(), execID)
	if err != nil {
		ctrl.logger.WithError(err).WithFields(map[string]interface{}{
			"containerID": containerID,
			"execID":      execID,
		}).Error("Failed to inspect exec instance")
		utils.InternalServerError(c, "Failed to inspect exec instance: "+err.Error())
		return
	}

	// Return the exec output
	// TODO: Populate ProcessConfig, OpenStdin etc. from inspect if needed
	utils.SuccessResponse(c, models.ContainerExecResponse{
		ID:       execID, // Use ID field for ExecID
		Running:  inspect.Running,
		ExitCode: exitCode, // Use exitCode from StartAndWait
		// Output needs to be handled differently, maybe separate stdout/stderr fields?
		// For now, let's omit it or combine stdout/stderr if needed.
		// Output: string(stdoutBytes) + string(stderrBytes), // Example combination
		ContainerID: inspect.ContainerID,
	})
}

// isWebSocketRequest checks if a request is a WebSocket upgrade request
func isWebSocketRequest(r *http.Request) bool {
	// Check for WebSocket upgrade header
	upgrade := r.Header.Get("Upgrade")
	return upgrade == "websocket"
}

// mapRequestToExecConfig converts the API request model to the exec package's config struct
func mapRequestToExecConfig(req models.ContainerExecCreateRequest) containerExec.ExecConfig {
	return containerExec.ExecConfig{
		Cmd:          req.Command,
		AttachStdin:  req.AttachStdin,
		AttachStdout: req.AttachStdout,
		AttachStderr: req.AttachStderr,
		DetachKeys:   req.DetachKeys,
		Tty:          req.Tty,
		Env:          req.Env,
		Privileged:   req.Privileged,
		WorkingDir:   req.WorkingDir,
		// User field is missing in ContainerExecCreateRequest, add if needed
	}
}
