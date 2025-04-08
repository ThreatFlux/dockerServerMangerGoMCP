package network

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	networktypes "github.com/docker/docker/api/types/network" // Added for Connect/Create options
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database/repositories"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/network"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Added import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"  // Added import
	"gorm.io/gorm"                                                  // Added for gorm errors
)

// Controller handles network-related API requests
type Controller struct {
	networkService network.Service
	networkRepo    repositories.NetworkRepository
	logger         *logrus.Logger
}

// NewController creates a new network controller
func NewController(
	networkService network.Service,
	networkRepo repositories.NetworkRepository,
	logger *logrus.Logger,
) *Controller {
	return &Controller{
		networkService: networkService,
		networkRepo:    networkRepo,
		logger:         logger,
	}
}

// RegisterRoutes registers the network API routes
func (ctrl *Controller) RegisterRoutes(router *gin.RouterGroup, authMW *middleware.AuthMiddleware) {
	networks := router.Group("/networks")
	networks.Use(authMW.RequireAuthentication()) // Require auth for all network routes

	networks.GET("", ctrl.List)
	networks.GET("/:id", ctrl.Get)
	networks.POST("", ctrl.Create)
	networks.DELETE("/:id", ctrl.Remove)
	networks.POST("/:id/connect", ctrl.Connect)
	networks.POST("/:id/disconnect", ctrl.Disconnect)
	// TODO: Add prune route if needed (requires admin)
}

// List godoc
// @Summary List networks
// @Description Retrieves a list of Docker networks.
// @Tags Networks
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1) example(1)
// @Param page_size query int false "Number of items per page" default(10) minimum(1) maximum(100) example(20)
// @Param sort_by query string false "Field to sort by (e.g., name, created_at, driver)" default(created_at) example(name)
// @Param sort_order query string false "Sort order (asc, desc)" default(desc) Enums(asc, desc) example(asc)
// @Param driver query string false "Filter by driver name" example(bridge)
// @Param name query string false "Filter by network name" example(app-net)
// @Success 200 {object} models.PaginatedResponse{data=[]models.NetworkResponse} "Successfully retrieved networks"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /networks [get]
func (ctrl *Controller) List(c *gin.Context) {
	// Parse query parameters
	page, pageSize := utils.GetPaginationParams(c)
	sortBy := c.DefaultQuery("sort_by", "created_at") // Default sort
	sortOrder := c.DefaultQuery("sort_order", "desc")
	driverFilter := c.Query("driver")
	nameFilter := c.Query("name")
	// TODO: Add label filter parsing

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.IsAdmin(c)

	// Prepare repository list options
	repoOptions := repositories.ListOptions{
		Page:      page,
		PageSize:  pageSize,
		SortBy:    sortBy,
		SortOrder: sortOrder,
		Driver:    driverFilter,
		Name:      nameFilter,
		UserID:    0, // Default to 0 (no user filter)
	}
	if !isAdmin {
		repoOptions.UserID = userID
	}

	// List networks from repository (includes filtering and pagination)
	dbNetworks, total, err := ctrl.networkRepo.List(c.Request.Context(), repoOptions)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to list networks from repository")
		utils.InternalServerError(c, "Failed to retrieve network list")
		return
	}

	// Convert to response models
	apiNetworks := make([]models.NetworkResponse, len(dbNetworks))
	for i, net := range dbNetworks {
		apiNetworks[i] = models.NetworkResponse{ // Assuming NetworkResponse exists
			ID:         net.ID,
			NetworkID:  net.NetworkID,
			Name:       net.Name,
			Driver:     net.Driver,
			Scope:      net.Scope,
			Created:    net.Created,
			Gateway:    net.Gateway,
			Subnet:     net.Subnet,
			IPRange:    net.IPRange,
			Internal:   net.Internal,
			EnableIPv6: net.EnableIPv6,
			Attachable: net.Attachable,
			Ingress:    net.Ingress,
			ConfigOnly: net.ConfigOnly,
			Labels:     net.Labels.StringMap(),  // Convert JSONMap
			Options:    net.Options.StringMap(), // Convert JSONMap
			// Containers: // Needs population if required
			Notes:     net.Notes,
			UserID:    net.UserID,
			CreatedAt: net.CreatedAt,
			UpdatedAt: net.UpdatedAt,
		}
	}

	// Return paginated response
	utils.PaginatedResponse(c, apiNetworks, page, pageSize, int(total))
}

// Get godoc
// @Summary Get network details
// @Description Retrieves detailed information about a specific network by its ID or name.
// @Tags Networks
// @Produce json
// @Security BearerAuth
// @Param id path string true "Network ID or Name" example(my-app-network)
// @Success 200 {object} models.SuccessResponse{data=models.NetworkResponse} "Successfully retrieved network details"
// @Failure 400 {object} models.ErrorResponse "Invalid network ID/name"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Network not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /networks/{id} [get]
func (ctrl *Controller) Get(c *gin.Context) {
	networkID := c.Param("id")
	if networkID == "" {
		utils.BadRequest(c, "Network ID is required")
		return
	}

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.IsAdmin(c)

	// Try finding by DB ID first
	var dbNetwork *models.Network
	if numericID, err := strconv.ParseUint(networkID, 10, 64); err == nil {
		dbNetwork, err = ctrl.networkRepo.FindByID(c.Request.Context(), uint(numericID))
	} else {
		dbNetwork, err = ctrl.networkRepo.FindByNetworkID(c.Request.Context(), networkID)
	}

	// Inspect using Docker API
	dockerNetwork, inspectErr := ctrl.networkService.InspectRaw(c.Request.Context(), networkID) // Use InspectRaw
	if inspectErr != nil {
		ctrl.logger.WithError(inspectErr).WithField("networkID", networkID).Error("Failed to inspect network via Docker API")
		if errors.Is(err, repositories.ErrNetworkNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
			utils.NotFound(c, "Network not found")
			return
		}
		utils.InternalServerError(c, "Failed to inspect network details")
		return
	}

	// Check permissions
	if dbNetwork != nil {
		if dbNetwork.UserID != userID && !isAdmin {
			utils.Forbidden(c, "You do not have permission to access this network")
			return
		}
	} else if !isAdmin {
		utils.Forbidden(c, "You do not have permission to access this network")
		return
	}

	// Convert Docker network info to response model
	response := models.NetworkResponse{
		NetworkID:  dockerNetwork.ID, // Use ID from Inspect result
		Name:       dockerNetwork.Name,
		Driver:     dockerNetwork.Driver,
		Scope:      dockerNetwork.Scope,
		Created:    dockerNetwork.Created,
		Internal:   dockerNetwork.Internal,
		EnableIPv6: dockerNetwork.EnableIPv6,
		Attachable: dockerNetwork.Attachable,
		Ingress:    dockerNetwork.Ingress,
		ConfigOnly: dockerNetwork.ConfigOnly,
		Labels:     dockerNetwork.Labels,
		Options:    dockerNetwork.Options,
		// Containers: // Map dockerNetwork.Containers if needed
	}
	if len(dockerNetwork.IPAM.Config) > 0 {
		response.Gateway = dockerNetwork.IPAM.Config[0].Gateway
		response.Subnet = dockerNetwork.IPAM.Config[0].Subnet
		response.IPRange = dockerNetwork.IPAM.Config[0].IPRange
	}

	// Add DB info if available
	if dbNetwork != nil {
		response.ID = dbNetwork.ID
		response.Notes = dbNetwork.Notes
		response.UserID = dbNetwork.UserID
		response.CreatedAt = dbNetwork.CreatedAt
		response.UpdatedAt = dbNetwork.UpdatedAt
	}

	utils.SuccessResponse(c, response)
}

// Create godoc
// @Summary Create a new network
// @Description Creates a new Docker network.
// @Tags Networks
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param network body models.NetworkCreateRequest true "Network Configuration"
// @Success 201 {object} models.SuccessResponse{data=models.NetworkResponse} "Successfully created network"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 409 {object} models.ErrorResponse "Network name already exists"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /networks [post]
func (ctrl *Controller) Create(c *gin.Context) {
	var req models.NetworkCreateRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}

	// Prepare options for service call
	createOptions := network.CreateOptions{
		Driver:     req.Driver,
		Options:    req.Options,
		Labels:     req.Labels,
		EnableIPv6: req.EnableIPv6,
		Internal:   req.Internal,
		Attachable: req.Attachable,
		Ingress:    req.Ingress,
		ConfigOnly: req.ConfigOnly,
		Scope:      req.Scope,
		// IPAM needs conversion
	}
	// Convert IPAM config from request model to networktypes.IPAM
	if req.IPAM != nil {
		ipamConfigs := make([]networktypes.IPAMConfig, len(req.IPAM.Config))
		for i, cfg := range req.IPAM.Config {
			ipamConfigs[i] = networktypes.IPAMConfig{
				Subnet:     cfg.Subnet,
				IPRange:    cfg.IPRange,
				Gateway:    cfg.Gateway,
				AuxAddress: cfg.AuxAddress, // Direct assignment should work if types match
			}
		}
		createOptions.IPAM = &networktypes.IPAM{
			Driver:  req.IPAM.Driver,
			Options: req.IPAM.Options, // Direct assignment should work if types match
			Config:  ipamConfigs,
		}
	}

	// Add user ID label
	if createOptions.Labels == nil {
		createOptions.Labels = make(map[string]string)
	}
	createOptions.Labels["com.dockerservermanager.userid"] = strconv.FormatUint(uint64(userID), 10)

	// Call service to create network (pass name separately)
	dockerNetModel, err := ctrl.networkService.Create(c.Request.Context(), req.Name, createOptions)
	if err != nil {
		ctrl.logger.WithError(err).WithField("name", req.Name).Error("Failed to create network via service")
		// TODO: Handle specific errors like name conflict
		utils.InternalServerError(c, "Failed to create network: "+err.Error())
		return
	}

	// Create record in database (using the returned model)
	dbNetwork := dockerNetModel      // Assume service returns the *models.Network
	dbNetwork.UserID = userID        // Ensure UserID is set
	dbNetwork.Notes = req.Notes      // Add notes from request
	dbNetwork.CreatedAt = time.Now() // Set DB creation time
	dbNetwork.UpdatedAt = time.Now()

	if err := ctrl.networkRepo.Create(c.Request.Context(), dbNetwork); err != nil {
		ctrl.logger.WithError(err).WithField("networkID", dbNetwork.NetworkID).Error("Failed to save network record to database after creation")
		// Consider rolling back Docker network creation?
	} else {
		// Update the ID in the response model if DB save was successful
	}

	// Convert to response model
	response := models.NetworkResponse{
		ID:         dbNetwork.ID,
		NetworkID:  dbNetwork.NetworkID, // Use NetworkID from model
		Name:       dbNetwork.Name,
		Driver:     dbNetwork.Driver,
		Scope:      dbNetwork.Scope,
		Created:    dbNetwork.Created,
		Internal:   dbNetwork.Internal,
		EnableIPv6: dbNetwork.EnableIPv6,
		Attachable: dbNetwork.Attachable,
		Ingress:    dbNetwork.Ingress,
		ConfigOnly: dbNetwork.ConfigOnly,
		Labels:     dbNetwork.Labels.StringMap(),
		Options:    dbNetwork.Options.StringMap(),
		Gateway:    dbNetwork.Gateway,
		Subnet:     dbNetwork.Subnet,
		IPRange:    dbNetwork.IPRange,
		Notes:      dbNetwork.Notes,
		UserID:     dbNetwork.UserID,
		CreatedAt:  dbNetwork.CreatedAt,
		UpdatedAt:  dbNetwork.UpdatedAt,
	}

	c.JSON(http.StatusCreated, models.SuccessResponse{Data: response})
}

// Remove godoc
// @Summary Remove a network
// @Description Removes a Docker network by its ID or name.
// @Tags Networks
// @Produce json
// @Security BearerAuth
// @Param id path string true "Network ID or Name" example(my-app-network)
// @Success 204 "Network removed successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid network ID/name"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Network not found"
// @Failure 409 {object} models.ErrorResponse "Conflict (e.g., network is in use)"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /networks/{id} [delete]
func (ctrl *Controller) Remove(c *gin.Context) {
	networkID := c.Param("id")
	if networkID == "" {
		utils.BadRequest(c, "Network ID is required")
		return
	}

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.IsAdmin(c)

	// Check permissions based on DB record if it exists
	dbNetwork, err := ctrl.networkRepo.FindByNetworkID(c.Request.Context(), networkID)
	if err == nil && dbNetwork != nil {
		if dbNetwork.UserID != userID && !isAdmin {
			utils.Forbidden(c, "You do not have permission to remove this network")
			return
		}
	} else if !errors.Is(err, repositories.ErrNetworkNotFound) && !errors.Is(err, gorm.ErrRecordNotFound) {
		ctrl.logger.WithError(err).WithField("networkID", networkID).Error("Failed to check network ownership")
		utils.InternalServerError(c, "Failed to verify network permissions")
		return
	} else if !isAdmin {
		// Check if it exists in Docker but not DB
		_, inspectErr := ctrl.networkService.InspectRaw(c.Request.Context(), networkID)
		if inspectErr == nil {
			utils.Forbidden(c, "You do not have permission to remove this unmanaged network")
			return
		}
	}

	// Call service to remove network
	removeOptions := network.RemoveOptions{}                                        // No options needed for service call
	err = ctrl.networkService.Remove(c.Request.Context(), networkID, removeOptions) // Pass options
	if err != nil {
		ctrl.logger.WithError(err).WithField("networkID", networkID).Error("Failed to remove network via service")
		// TODO: Handle specific errors (not found, in use)
		utils.InternalServerError(c, "Failed to remove network: "+err.Error())
		return
	}

	// Remove from database if it existed
	if dbNetwork != nil {
		if err := ctrl.networkRepo.Delete(c.Request.Context(), dbNetwork.ID); err != nil {
			ctrl.logger.WithError(err).WithField("networkID", networkID).Warning("Failed to delete network record from database after removal")
		}
	}

	utils.NoContentResponse(c)
}

// Connect godoc
// @Summary Connect a container to a network
// @Description Connects a container to a specified network.
// @Tags Networks
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Network ID or Name" example(my-app-network)
// @Param connect_info body models.NetworkConnectRequest true "Container Connect Info"
// @Success 200 {object} models.SuccessResponse "Container connected successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Network or container not found"
// @Failure 409 {object} models.ErrorResponse "Container already connected"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /networks/{id}/connect [post]
func (ctrl *Controller) Connect(c *gin.Context) {
	networkID := c.Param("id")
	if networkID == "" {
		utils.BadRequest(c, "Network ID is required")
		return
	}

	var req models.NetworkConnectRequest
	if !utils.BindJSON(c, &req) {
		return
	}
	if req.Container == "" { // Use Container field from request model
		utils.BadRequest(c, "Container ID or Name is required")
		return
	}

	// TODO: Add permission checks for both network and container

	connectOptions := network.ConnectOptions{}
	if req.EndpointConfig != nil {
		connectOptions.EndpointConfig = &networktypes.EndpointSettings{ // Use networktypes alias
			Aliases: req.EndpointConfig.Aliases,
		}
		if req.EndpointConfig.IPAMConfig != nil {
			connectOptions.EndpointConfig.IPAMConfig = &networktypes.EndpointIPAMConfig{ // Use networktypes alias
				IPv4Address: req.EndpointConfig.IPAMConfig.IPv4Address, // Access nested fields
				IPv6Address: req.EndpointConfig.IPAMConfig.IPv6Address,
			}
		}
	}

	err := ctrl.networkService.Connect(c.Request.Context(), networkID, req.Container, connectOptions) // Pass container separately
	if err != nil {
		ctrl.logger.WithError(err).WithFields(logrus.Fields{
			"networkID":   networkID,
			"containerID": req.Container,
		}).Error("Failed to connect container to network")
		// TODO: Handle specific errors (404, 409)
		utils.InternalServerError(c, "Failed to connect container: "+err.Error())
		return
	}

	utils.SuccessResponse(c, gin.H{"message": "Container connected successfully"})
}

// Disconnect godoc
// @Summary Disconnect a container from a network
// @Description Disconnects a container from a specified network.
// @Tags Networks
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Network ID or Name" example(my-app-network)
// @Param disconnect_info body models.NetworkDisconnectRequest true "Container Disconnect Info"
// @Success 200 {object} models.SuccessResponse "Container disconnected successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Network or container not found, or container not connected"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /networks/{id}/disconnect [post]
func (ctrl *Controller) Disconnect(c *gin.Context) {
	networkID := c.Param("id")
	if networkID == "" {
		utils.BadRequest(c, "Network ID is required")
		return
	}

	var req models.NetworkDisconnectRequest
	if !utils.BindJSON(c, &req) {
		return
	}
	if req.Container == "" { // Use Container field from request model
		utils.BadRequest(c, "Container ID or Name is required")
		return
	}

	// TODO: Add permission checks

	disconnectOptions := network.DisconnectOptions{
		Force: req.Force,
	}

	err := ctrl.networkService.Disconnect(c.Request.Context(), networkID, req.Container, disconnectOptions) // Pass container separately
	if err != nil {
		ctrl.logger.WithError(err).WithFields(logrus.Fields{
			"networkID":   networkID,
			"containerID": req.Container,
		}).Error("Failed to disconnect container from network")
		// TODO: Handle specific errors (404)
		utils.InternalServerError(c, "Failed to disconnect container: "+err.Error())
		return
	}

	utils.SuccessResponse(c, gin.H{"message": "Container disconnected successfully"})
}

// handleNotImplemented is a temporary handler - REMOVED as handlers are implemented
// func (ctrl *Controller) handleNotImplemented(c *gin.Context) { ... }
