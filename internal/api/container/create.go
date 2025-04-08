package container

import (
	"net/http"
	"strconv" // Added for port validation
	"time"    // Added for timestamp in error response

	sdkContainer "github.com/docker/docker/api/types/container"                                  // Renamed alias
	"github.com/docker/docker/api/types/network"                                                 // Added for mapping
	dockerSvcContainer "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/container" // Import local container package

	"github.com/gin-gonic/gin"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// Create godoc
// @Summary Create a new container
// @Description Creates a new Docker container based on the provided configuration.
// @Tags Containers
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param container body models.ContainerCreateRequest true "Container Configuration"
// @Success 201 {object} models.SuccessResponse{data=models.Container} "Successfully created container"
// @Failure 400 {object} models.ErrorResponse "Invalid input or configuration"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied (e.g., creating privileged container as non-admin)"
// @Failure 404 {object} models.ErrorResponse "Image not found (if pull fails)"
// @Failure 409 {object} models.ErrorResponse "Container name already in use"
// @Failure 500 {object} models.ErrorResponse "Internal server error (e.g., Docker daemon error)"
// @Router /containers [post]
func (ctrl *Controller) Create(c *gin.Context) {
	// Parse request body
	var req models.ContainerCreateRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate container creation request
	validationResult := validateContainerCreateRequest(req)
	if !validationResult.IsValid() {
		// Use standard Gin JSON response for validation errors
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Invalid container creation request",
			},
			"validationErrors": validationResult.GetErrors(),
			"meta": gin.H{
				"timestamp":  time.Now(),                // Add timestamp
				"request_id": c.GetString("request_id"), // Add request ID
			},
		})
		return
	}

	// Get user ID from context
	userID, err := middleware.GetUserID(c) // Pass gin.Context
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}

	// Check privileged mode - only admins can create privileged containers
	if req.Privileged {
		isAdmin, err := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
		if err != nil || !isAdmin {
			utils.Forbidden(c, "Only admins can create privileged containers")
			return
		}
	}

	// Map request to Docker options
	createOpts, err := mapRequestToCreateOptions(req, userID)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to map request to create options")
		utils.BadRequest(c, "Invalid container configuration: "+err.Error())
		return
	}

	// Create container using the mapped options
	containerModel, err := ctrl.containerService.Create(c.Request.Context(), createOpts) // Pass createOpts, rename result var
	if err != nil {
		// Check if the error is a Docker conflict error (e.g., name already in use)
		// Note: This assumes the service layer propagates the error appropriately
		// or we might need to import the docker_test client here, which is less ideal.
		// A better approach might be for the service layer to return a specific error type.
		// For now, let's try checking the error message as a fallback.
		// TODO: Refactor service layer to return typed errors (e.g., ErrContainerConflict)
		if dockerSvcContainer.IsErrContainerConflict(err) { // Assuming IsErrContainerConflict exists in the service package
			ctrl.logger.WithError(err).Warn("Container creation conflict")
			utils.Conflict(c, "Container name already in use: "+req.Name) // Use 409 Conflict
		} else {
			ctrl.logger.WithError(err).Error("Failed to create container")
			utils.InternalServerError(c, "Failed to create container: "+err.Error()) // Keep 500 for other errors
		}
		return
	}

	// Return the created container using standard Gin JSON response
	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    containerModel,
		"meta": gin.H{
			"timestamp":  time.Now(),
			"request_id": c.GetString("request_id"),
		},
	})
}

// validateContainerCreateRequest validates a container creation request
func validateContainerCreateRequest(req models.ContainerCreateRequest) *utils.ValidationResult {
	result := utils.NewValidationResult()

	// Validate container name
	if err := utils.ValidateContainerName(req.Name); err != nil {
		result.AddError("name", "INVALID_NAME", err.Error(), req.Name)
	}

	// Validate image name
	if err := utils.ValidateImageName(req.Image); err != nil {
		result.AddError("image", "INVALID_IMAGE", err.Error(), req.Image)
	}

	// Validate ports
	for i, port := range req.Ports {
		// Validate ContainerPort
		containerPortInt, err := strconv.Atoi(port.ContainerPort)
		if err != nil {
			result.AddError(
				"ports["+strconv.Itoa(i)+"].containerPort",
				"INVALID_FORMAT",
				"Container port must be a number",
				port.ContainerPort,
			)
		} else if containerPortInt <= 0 || containerPortInt > 65535 {
			result.AddError(
				"ports["+strconv.Itoa(i)+"].containerPort",
				"INVALID_RANGE",
				"Container port must be between 1 and 65535",
				port.ContainerPort,
			)
		}

		// Validate HostPort (optional, can be empty or 0)
		if port.HostPort != "" {
			hostPortInt, err := strconv.Atoi(port.HostPort)
			if err != nil {
				result.AddError(
					"ports["+strconv.Itoa(i)+"].hostPort",
					"INVALID_FORMAT",
					"Host port must be a number",
					port.HostPort,
				)
			} else if hostPortInt < 0 || hostPortInt > 65535 { // Allow 0 for random assignment
				result.AddError(
					"ports["+strconv.Itoa(i)+"].hostPort",
					"INVALID_RANGE",
					"Host port must be between 0 and 65535",
					port.HostPort,
				)
			}
		}
	}

	// Validate volumes
	for i, volume := range req.Volumes {
		if volume.Source == "" {
			result.AddError(
				"volumes["+string(rune(i))+"].source",
				"REQUIRED",
				"Volume source is required",
				"",
			)
		}
		if volume.Destination == "" {
			result.AddError(
				"volumes["+string(rune(i))+"].destination",
				"REQUIRED",
				"Volume destination is required",
				"",
			)
		}
	}

	// Validate restart policy
	if req.RestartPolicy != "" {
		validPolicies := []string{"no", "on-failure", "always", "unless-stopped"}
		found := false
		for _, policy := range validPolicies {
			if req.RestartPolicy == policy {
				found = true
				break
			}
		}
		if !found {
			result.AddError(
				"restartPolicy",
				"INVALID_POLICY",
				"Restart policy must be one of: no, on-failure, always, unless-stopped",
				req.RestartPolicy,
			)
		}
	}

	// Validate resource limits
	if req.MemoryLimit < 0 {
		result.AddError(
			"memoryLimit",
			"INVALID_LIMIT",
			"Memory limit cannot be negative",
			string(rune(req.MemoryLimit)),
		)
	}
	if req.CPULimit < 0 {
		result.AddError(
			"cpuLimit",
			"INVALID_LIMIT",
			"CPU limit cannot be negative",
			string(rune(int64(req.CPULimit))),
		)
	}

	return result
}

// mapRequestToCreateOptions converts the API request model to Docker SDK options
func mapRequestToCreateOptions(req models.ContainerCreateRequest, userID uint) (dockerSvcContainer.CreateOptions, error) { // Use local package type
	// --- Map container.Config ---
	config := &sdkContainer.Config{ // Use SDK type here
		Image:      req.Image,
		Cmd:        req.Command,
		Entrypoint: req.Entrypoint,
		Env:        req.Env,
		Labels:     req.Labels,
		// TODO: Map ExposedPorts if needed from req.Ports
		// ExposedPorts: exposedPorts,
	}
	if config.Labels == nil {
		config.Labels = make(map[string]string)
	}
	// Add user ID label for tracking/management
	config.Labels["com.dockerservermanager.userid"] = strconv.FormatUint(uint64(userID), 10)
	if req.Notes != "" {
		config.Labels["com.dockerservermanager.notes"] = req.Notes
	}

	// --- Map container.HostConfig ---
	hostConfig := &sdkContainer.HostConfig{ // Use SDK type here
		Privileged: req.Privileged,
		AutoRemove: req.AutoRemove,
		Resources: sdkContainer.Resources{ // Use SDK type here
			Memory: req.MemoryLimit,
			// TODO: Convert CPULimit (float64 representing cores) to NanoCPUs (int64)
			// NanoCPUs: int64(req.CPULimit * 1e9),
		},
		// TODO: Map PortBindings if needed from req.Ports
		// PortBindings: portBindings,
		// TODO: Map Mounts if needed from req.Volumes
		// Mounts: mounts,
	}

	// Map RestartPolicy
	if req.RestartPolicy != "" {
		hostConfig.RestartPolicy = sdkContainer.RestartPolicy{ // Use SDK type here
			Name: sdkContainer.RestartPolicyMode(req.RestartPolicy), // Use SDK type here
			// TODO: Handle MaximumRetryCount for on-failure policy if needed
		}
	}

	// --- Map network.NetworkingConfig ---
	networkConfig := &network.NetworkingConfig{
		EndpointsConfig: make(map[string]*network.EndpointSettings),
	}
	if len(req.Networks) > 0 {
		// Assuming the first network is the primary one for endpoint settings
		// More complex scenarios might require different handling
		networkConfig.EndpointsConfig[req.Networks[0]] = &network.EndpointSettings{
			// TODO: Map Aliases, IPAddress, etc. if provided in request
		}
	}

	// --- TODO: Map Ports ---
	// exposedPorts := make(nat.PortSet)
	// portBindings := make(nat.PortMap)
	// for _, p := range req.Ports {
	// 	// ... complex mapping logic ...
	// }

	// --- TODO: Map Volumes ---
	// mounts := make([]mount.Mount, len(req.Volumes))
	// for i, v := range req.Volumes {
	// 	// ... complex mapping logic ...
	// }

	opts := dockerSvcContainer.CreateOptions{ // Use local package type
		Name:       req.Name,
		Config:     config,
		HostConfig: hostConfig,
		// NetworkingConfig: networkConfig, // This field doesn't exist in local CreateOptions
		// Platform: // TODO: Add platform support if needed
	}

	// TODO: Add validation for the generated options?

	return opts, nil
}
