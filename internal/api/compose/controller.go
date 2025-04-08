package compose

import (
	"context"

	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/interfaces" // Use interfaces package
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Added for request/response models
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

const defaultComposeProjectName = "default_dsm_project"

// Helper function to get environment variables for compose-go loader,
// ensuring COMPOSE_PROJECT_NAME is set.
func getEnvironment() map[string]string {
	env := map[string]string{}
	foundProjectName := false
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		key := pair[0]
		value := ""
		if len(pair) == 2 {
			value = pair[1]
		}
		env[key] = value
		if key == "COMPOSE_PROJECT_NAME" && value != "" {
			foundProjectName = true
		}
	}
	// If COMPOSE_PROJECT_NAME is not set in the environment, add a default one.
	if !foundProjectName {
		env["COMPOSE_PROJECT_NAME"] = defaultComposeProjectName
	}
	return env
}

// Controller handles Docker Compose related API requests
type Controller struct {
	composeService interfaces.ComposeService
	orchestrator   interfaces.ComposeOrchestrator
	statusTracker  interfaces.ComposeStatusTracker
	logger         *logrus.Logger
}

// NewController creates a new compose controller
func NewController(
	composeService interfaces.ComposeService,
	orchestrator interfaces.ComposeOrchestrator,
	statusTracker interfaces.ComposeStatusTracker,
	logger *logrus.Logger,
) *Controller {
	return &Controller{
		composeService: composeService,
		orchestrator:   orchestrator,
		statusTracker:  statusTracker,
		logger:         logger,
	}
}

// RegisterRoutes registers the compose API routes
func (ctrl *Controller) RegisterRoutes(router *gin.RouterGroup, authMW *middleware.AuthMiddleware) {
	compose := router.Group("/compose")
	compose.Use(authMW.RequireAuthentication()) // Require auth for all compose routes

	compose.GET("", ctrl.ListDeployments)
	compose.GET("/:id", ctrl.GetDeployment)
	compose.POST("/validate", ctrl.Validate)   // Use Validate handler
	compose.POST("/up", ctrl.Up)               // Use Up handler
	compose.POST("/:id/down", ctrl.Down)       // Use Down handler
	compose.POST("/:id/start", ctrl.Start)     // Use Start handler
	compose.POST("/:id/stop", ctrl.Stop)       // Use Stop handler
	compose.POST("/:id/restart", ctrl.Restart) // Use Restart handler
	compose.POST("/:id/scale", ctrl.Scale)     // Point to implemented Scale handler
}

// ListDeployments handles listing compose deployments
// @Summary List Compose Deployments
// @Description Get a list of tracked Docker Compose deployments and their status.
// @Tags Compose
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SuccessResponse{data=[]models.DeploymentInfo} "Successfully retrieved deployments"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /compose [get]
func (ctrl *Controller) ListDeployments(c *gin.Context) {
	deployments := ctrl.statusTracker.GetDeployments()
	// Note: DeploymentInfo contains the ComposeFile which can be large.
	// Consider creating a summary response model if needed.
	utils.SuccessResponse(c, deployments)
}

// GetDeployment handles getting details of a specific deployment
// @Summary Get Compose Deployment Details
// @Description Get detailed status information for a specific Docker Compose deployment by project name.
// @Tags Compose
// @Produce json
// @Security BearerAuth
// @Param id path string true "Project Name (ID)" example(my-web-app)
// @Success 200 {object} models.SuccessResponse{data=models.DeploymentInfo} "Successfully retrieved deployment details"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 404 {object} models.ErrorResponse "Deployment not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /compose/{id} [get]
func (ctrl *Controller) GetDeployment(c *gin.Context) {
	projectName := c.Param("id")
	deployment, exists := ctrl.statusTracker.GetDeployment(projectName)
	if !exists {
		utils.NotFound(c, fmt.Sprintf("Deployment '%s' not found", projectName))
		return
	}
	// Note: DeploymentInfo contains the ComposeFile which can be large.
	utils.SuccessResponse(c, deployment)
}

// Validate handles validating a compose file
// @Summary Validate Compose File
// @Description Parses and validates the structure of a provided Docker Compose file content.
// @Tags Compose
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body string true "Raw Compose file content (YAML)"
// @Success 200 {object} models.SuccessResponse{data=object{status=string}} "Compose file is valid"
// @Failure 400 {object} models.ErrorResponse "Invalid request body"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 422 {object} models.ErrorResponse "Validation failed (invalid YAML or structure)"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /compose/validate [post]
func (ctrl *Controller) Validate(c *gin.Context) {
	var req models.ComposeValidateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid request body: "+err.Error())
		return
	}

	// Use composeService.Parse (which uses compose-go)
	reader := strings.NewReader(req.ComposeFileContent)
	absWorkingDir, wdErr := filepath.Abs(".") // Get absolute path for current dir
	if wdErr != nil {
		ctrl.logger.WithError(wdErr).Warn("Failed to get absolute working directory, using '.'")
		absWorkingDir = "."
	}
	// Remove unused parseErr declaration
	// Remove unused parseErr declaration
	// Provide a placeholder project name for validation purposes
	parseOptions := models.ParseOptions{
		WorkingDir:  absWorkingDir,
		ProjectName: "dsm_validation_project", // Placeholder name
	}
	_, err := ctrl.composeService.Parse(c.Request.Context(), reader, parseOptions)
	if err != nil {
		// Add more specific error message for YAML parsing issues
		errMsg := fmt.Sprintf("Validation failed: %v", err)
		if strings.Contains(err.Error(), "yaml:") { // Add more context if it's a yaml lib error
			errMsg = fmt.Sprintf("Validation failed: %s (check indentation/syntax)", err.Error())
		}
		utils.UnprocessableEntity(c, errMsg)
		return
	}

	// If Parse succeeds, the file is valid according to compose-go
	utils.SuccessResponse(c, gin.H{"status": "valid"})
}

// Up handles deploying a compose project
// @Summary Deploy Compose Project (Up)
// @Description Parses, validates, and deploys a Docker Compose project.
// @Tags Compose
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.ComposeUpRequest true "Compose file content and deployment options"
// @Success 202 {object} models.SuccessResponse{message=string} "Deployment process started"
// @Failure 400 {object} models.ErrorResponse "Invalid request body"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 422 {object} models.ErrorResponse "Failed to parse or validate compose file"
// @Failure 500 {object} models.ErrorResponse "Internal server error during deployment"
// @Router /compose/up [post]
func (ctrl *Controller) Up(c *gin.Context) {
	var req models.ComposeUpRequest // Assuming this struct exists in models
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid request body: "+err.Error())
		return
	}

	// Parse the compose file content from the request struct
	reader := strings.NewReader(req.ComposeFileContent)
	// Provide an absolute working directory context for path resolution
	absWorkingDir, wdErr := filepath.Abs(".") // Get absolute path for current dir
	if wdErr != nil {
		ctrl.logger.WithError(wdErr).Warn("Failed to get absolute working directory, using '.'")
		absWorkingDir = "."
	}
	parseOptions := models.ParseOptions{
		WorkingDir:  absWorkingDir,
		ProjectName: req.ProjectName, // Pass project name from request
	}
	// TODO: Map other request options to models.ParseOptions if needed (e.g., env vars)
	composeFile, err := ctrl.composeService.Parse(c.Request.Context(), reader, parseOptions)
	if err != nil {
		utils.UnprocessableEntity(c, "Failed to parse compose file: "+err.Error())
		return
	}

	// Map request options to models.DeployOptions
	deployOptions := models.DeployOptions{ // Use models.DeployOptions
		ProjectName:           req.ProjectName,
		ForceRecreate:         req.ForceRecreate,
		NoBuild:               req.NoBuild,
		NoStart:               req.NoStart,
		Pull:                  req.Pull,
		RemoveOrphans:         req.RemoveOrphans,
		AdjustNetworkSettings: true, // Explicitly enable network adjustment
		// Timeout: // Map from req if needed
		// DependencyTimeout: // Map from req if needed
		Logger: ctrl.logger, // Pass controller logger
	}

	// Deploy using the orchestrator (runs in background)
	go func() {
		// Add panic recovery
		defer func() {
			if r := recover(); r != nil {
				ctrl.logger.Errorf("Panic recovered in background deployment goroutine: %v", r)
				// Optionally update status tracker about the panic
				ctrl.statusTracker.CompleteOperation(req.ProjectName, models.OperationStatusFailed, fmt.Errorf("panic during deployment: %v", r))
			}
		}()
		// Create a background context detached from the request context
		bgCtx := context.Background()

		ctrl.logger.Infof("Goroutine started for project: %s. Calling Deploy...", deployOptions.ProjectName) // Add log before Deploy call
		ctrl.logger.Infof("Starting background deployment for project: %s", deployOptions.ProjectName)       // Log start
		err := ctrl.orchestrator.Deploy(bgCtx, composeFile, deployOptions)
		if err != nil {
			// Log the error from the background deployment
			ctrl.logger.WithError(err).Errorf("Background compose deployment failed for project: %s", deployOptions.ProjectName)
			// Update status tracker with failure
			ctrl.statusTracker.CompleteOperation(req.ProjectName, models.OperationStatusFailed, err)
		} else {
			ctrl.logger.Infof("Background deployment finished successfully for project: %s", deployOptions.ProjectName) // Log success
			// Orchestrator should call CompleteOperation on success internally
		}
	}()

	// Return Accepted immediately
	utils.StatusAccepted(c, "Deployment process started for project "+req.ProjectName)
}

// Down handles removing (down) a compose project
// @Summary Remove Compose Project (Down)
// @Description Stops and removes containers, networks, and optionally volumes for a deployment.
// @Tags Compose
// @Produce json
// @Security BearerAuth
// @Param id path string true "Project Name (ID)" example(my-web-app)
// @Param remove_volumes query bool false "Remove named volumes declared in the 'volumes' section" default(false) example(true)
// @Param remove_orphans query bool false "Remove containers for services not defined in the Compose file" default(false) example(true)
// @Param force query bool false "Force removal" default(false) example(false)
// @Success 202 {object} models.SuccessResponse{message=string} "Removal process started"
// @Failure 400 {object} models.ErrorResponse "Invalid query parameters"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 404 {object} models.ErrorResponse "Deployment not found (required for ComposeFile)"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /compose/{id}/down [post]
func (ctrl *Controller) Down(c *gin.Context) {
	projectName := c.Param("id")
	var req models.ComposeDownRequest // Assuming this struct exists in models (binds query params)
	if err := c.ShouldBindQuery(&req); err != nil {
		utils.BadRequest(c, "Invalid query parameters: "+err.Error())
		return
	}

	// --- Placeholder Logic ---
	// TODO: Retrieve ComposeFile associated with projectName.
	// This might involve getting it from the statusTracker or a repository.
	deployment, exists := ctrl.statusTracker.GetDeployment(projectName)
	if !exists || deployment.ComposeFile == nil {
		utils.NotFound(c, fmt.Sprintf("Compose file for deployment '%s' not found or deployment untracked", projectName))
		return
	}
	composeFile := deployment.ComposeFile
	// --- End Placeholder Logic ---

	removeOptions := models.RemoveOptions{
		ProjectName:   projectName,
		RemoveVolumes: req.RemoveVolumes,
		RemoveOrphans: req.RemoveOrphans,
		Force:         req.Force,
		// Timeout: // Map from req if needed
		Logger: ctrl.logger,
	}

	// Run Remove in background
	go func() {
		bgCtx := context.Background()
		err := ctrl.orchestrator.Remove(bgCtx, composeFile, removeOptions) // Pass retrieved composeFile
		if err != nil {
			ctrl.logger.WithError(err).WithField("project", projectName).Error("Background compose removal failed")
			ctrl.statusTracker.CompleteOperation(projectName, models.OperationStatusFailed, err)
		}
		// Orchestrator should call CompleteOperation on success internally
	}()

	utils.StatusAccepted(c, "Removal process started for project "+projectName)
}

// Start handles starting a compose project's services
// @Summary Start Compose Project Services
// @Description Starts existing containers for services in a deployment.
// @Tags Compose
// @Produce json
// @Security BearerAuth
// @Param id path string true "Project Name (ID)" example(my-web-app)
// @Success 202 {object} models.SuccessResponse{message=string} "Start process started"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 404 {object} models.ErrorResponse "Deployment not found (required for ComposeFile)"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /compose/{id}/start [post]
func (ctrl *Controller) Start(c *gin.Context) {
	projectName := c.Param("id")
	// var req models.ComposeStartRequest // If options are needed
	// if err := c.ShouldBindQuery(&req); err != nil { ... }

	// --- Placeholder Logic ---
	deployment, exists := ctrl.statusTracker.GetDeployment(projectName)
	if !exists || deployment.ComposeFile == nil {
		utils.NotFound(c, fmt.Sprintf("Compose file for deployment '%s' not found or deployment untracked", projectName))
		return
	}
	composeFile := deployment.ComposeFile
	// --- End Placeholder Logic ---

	startOptions := models.StartOptions{
		ProjectName: projectName,
		// Timeout: // Map from req if needed
		Logger: ctrl.logger,
	}

	// Run Start in background
	go func() {
		bgCtx := context.Background()
		err := ctrl.orchestrator.Start(bgCtx, composeFile, startOptions) // Pass retrieved composeFile
		if err != nil {
			ctrl.logger.WithError(err).WithField("project", projectName).Error("Background compose start failed")
			ctrl.statusTracker.CompleteOperation(projectName, models.OperationStatusFailed, err)
		}
		// Orchestrator should call CompleteOperation on success internally
	}()

	utils.StatusAccepted(c, "Start process started for project "+projectName)
}

// Stop handles stopping a compose project's services
// @Summary Stop Compose Project Services
// @Description Stops running containers for services in a deployment without removing them.
// @Tags Compose
// @Produce json
// @Security BearerAuth
// @Param id path string true "Project Name (ID)" example(my-web-app)
// @Param timeout query int false "Timeout in seconds for stopping containers" example(5)
// @Success 202 {object} models.SuccessResponse{message=string} "Stop process started"
// @Failure 400 {object} models.ErrorResponse "Invalid query parameters"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 404 {object} models.ErrorResponse "Deployment not found (required for ComposeFile)"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /compose/{id}/stop [post]
func (ctrl *Controller) Stop(c *gin.Context) {
	projectName := c.Param("id")
	var req models.ComposeStopRequest // Assuming this struct exists in models
	if err := c.ShouldBindQuery(&req); err != nil {
		utils.BadRequest(c, "Invalid query parameters: "+err.Error())
		return
	}

	// --- Placeholder Logic ---
	deployment, exists := ctrl.statusTracker.GetDeployment(projectName)
	if !exists || deployment.ComposeFile == nil {
		utils.NotFound(c, fmt.Sprintf("Compose file for deployment '%s' not found or deployment untracked", projectName))
		return
	}
	composeFile := deployment.ComposeFile
	// --- End Placeholder Logic ---

	stopOptions := models.StopOptions{
		ProjectName: projectName,
		// Timeout: // Map from req.Timeout if needed
		Logger: ctrl.logger,
	}

	// Run Stop in background
	go func() {
		bgCtx := context.Background()
		err := ctrl.orchestrator.Stop(bgCtx, composeFile, stopOptions) // Pass retrieved composeFile
		if err != nil {
			ctrl.logger.WithError(err).WithField("project", projectName).Error("Background compose stop failed")
			ctrl.statusTracker.CompleteOperation(projectName, models.OperationStatusFailed, err)
		}
		// Orchestrator should call CompleteOperation on success internally
	}()

	utils.StatusAccepted(c, "Stop process started for project "+projectName)
}

// Restart handles restarting a compose project's services
// @Summary Restart Compose Project Services
// @Description Restarts containers for services in a deployment.
// @Tags Compose
// @Produce json
// @Security BearerAuth
// @Param id path string true "Project Name (ID)" example(my-web-app)
// @Param timeout query int false "Timeout in seconds for stopping containers before restarting" example(5)
// @Success 202 {object} models.SuccessResponse{message=string} "Restart process started"
// @Failure 400 {object} models.ErrorResponse "Invalid query parameters"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 404 {object} models.ErrorResponse "Deployment not found (required for ComposeFile)"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /compose/{id}/restart [post]
func (ctrl *Controller) Restart(c *gin.Context) {
	projectName := c.Param("id")
	var req models.ComposeRestartRequest // Assuming this struct exists in models
	if err := c.ShouldBindQuery(&req); err != nil {
		utils.BadRequest(c, "Invalid query parameters: "+err.Error())
		return
	}

	// --- Placeholder Logic ---
	deployment, exists := ctrl.statusTracker.GetDeployment(projectName)
	if !exists || deployment.ComposeFile == nil {
		utils.NotFound(c, fmt.Sprintf("Compose file for deployment '%s' not found or deployment untracked", projectName))
		return
	}
	composeFile := deployment.ComposeFile
	// --- End Placeholder Logic ---

	restartOptions := models.RestartOptions{
		ProjectName: projectName,
		// Timeout: // Map from req.Timeout if needed
		Logger: ctrl.logger,
	}

	// Run Restart in background
	go func() {
		bgCtx := context.Background()
		err := ctrl.orchestrator.Restart(bgCtx, composeFile, restartOptions) // Pass retrieved composeFile
		if err != nil {
			ctrl.logger.WithError(err).WithField("project", projectName).Error("Background compose restart failed")
			ctrl.statusTracker.CompleteOperation(projectName, models.OperationStatusFailed, err)
		}
		// Orchestrator should call CompleteOperation on success internally
	}()

	utils.StatusAccepted(c, "Restart process started for project "+projectName)
}

// Scale handles scaling a service within a compose project
// @Summary Scale Compose Service
// @Description Scales a specific service within a deployment to the desired number of replicas.
// @Tags Compose
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Project Name (ID)" example(my-web-app)
// @Param body body models.ComposeScaleRequest true "Service name and replica count"
// @Success 202 {object} models.SuccessResponse{message=string} "Scaling process started"
// @Failure 400 {object} models.ErrorResponse "Invalid request body or parameters"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 404 {object} models.ErrorResponse "Deployment or service not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /compose/{id}/scale [post]
func (ctrl *Controller) Scale(c *gin.Context) {
	projectName := c.Param("id")
	var req models.ComposeScaleRequest // Assuming this struct exists
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid request body: "+err.Error())
		return
	}

	if req.Service == "" {
		utils.BadRequest(c, "Service name is required")
		return
	}
	if req.Replicas < 0 {
		utils.BadRequest(c, "Replicas must be non-negative")
		return
	}

	// --- Placeholder Logic ---
	deployment, exists := ctrl.statusTracker.GetDeployment(projectName)
	if !exists || deployment.ComposeFile == nil {
		utils.NotFound(c, fmt.Sprintf("Compose file for deployment '%s' not found or deployment untracked", projectName))
		return
	}
	composeFile := deployment.ComposeFile
	// --- End Placeholder Logic ---

	scaleOptions := models.ScaleOptions{
		ProjectName: projectName,
		Service:     req.Service,
		Replicas:    req.Replicas,
		// Timeout: // Map from req if needed
		Logger: ctrl.logger,
	}

	// Run Scale in background
	go func() {
		bgCtx := context.Background()
		err := ctrl.orchestrator.Scale(bgCtx, composeFile, scaleOptions) // Pass retrieved composeFile
		if err != nil {
			ctrl.logger.WithError(err).WithFields(logrus.Fields{
				"project":  projectName,
				"service":  req.Service,
				"replicas": req.Replicas,
			}).Error("Background compose scale failed")
			ctrl.statusTracker.CompleteOperation(projectName, models.OperationStatusFailed, err)
		}
		// Orchestrator should call CompleteOperation on success internally
	}()

	utils.StatusAccepted(c, fmt.Sprintf("Scaling process started for service %s in project %s", req.Service, projectName))
}
