package api

import (
	// "context" // Removed unused import
	"errors"
	// "encoding/json" // Removed unused import
	"fmt"
	"net/http"
	"strconv" // Added back strconv import
	"strings"
	"time"

	"github.com/docker/docker/api/types/filters" // Added for filters.Args
	networktypes "github.com/docker/docker/api/types/network"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database/repositories" // Re-add for permission checks later
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/network"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
	"gorm.io/gorm"
)

// NetworkController handles network-related API requests
type NetworkController struct {
	networkService network.Service
	networkRepo    repositories.NetworkRepository // Use the specific type
	dockerManager  docker.Manager
	logger         *logrus.Logger
}

// NewNetworkController creates a new network controller
func NewNetworkController(
	networkService network.Service,
	networkRepo repositories.NetworkRepository, // Use the specific type
	dockerManager docker.Manager,
	logger *logrus.Logger,
) *NetworkController {
	return &NetworkController{
		networkService: networkService,
		networkRepo:    networkRepo, // Assign repo
		dockerManager:  dockerManager,
		logger:         logger,
	}
}

// RegisterRoutes registers the network API routes
func (ctrl *NetworkController) RegisterRoutes(router *gin.RouterGroup, authMW *middleware.AuthMiddleware) {
	networks := router.Group("/networks")
	networks.Use(authMW.RequireAuthentication())

	networks.GET("", ctrl.ListNetworks)
	networks.GET("/:id", ctrl.GetNetwork)
	// networks.GET("/drivers", ctrl.GetNetworkDrivers) // Handler removed

	networks.POST("", ctrl.CreateNetwork)
	networks.DELETE("/:id", ctrl.DeleteNetwork)
	// networks.POST("/:id/inspect", ctrl.InspectNetwork) // Handler removed

	networks.POST("/:id/connect", ctrl.ConnectContainer)
	networks.POST("/:id/disconnect", ctrl.DisconnectContainer)

	adminNetworks := networks.Group("", authMW.RequireAdmin())
	adminNetworks.POST("/prune", ctrl.PruneNetworks)
	// adminNetworks.GET("/by-container/:container_id", ctrl.FindNetworksByContainer) // Handler removed
	// adminNetworks.GET("/by-subnet/:subnet", ctrl.FindNetworksBySubnet) // Handler removed
}

// ListNetworks handles GET /networks
func (ctrl *NetworkController) ListNetworks(c *gin.Context) {
	var req models.NetworkListRequest
	if !utils.BindQuery(c, &req) {
		return
	}
	req.PaginationRequest.SetDefaults()
	req.SortRequest.SetDefaults("name")

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin))

	// Prepare Docker API filters
	listFilters := filters.NewArgs()
	if req.Driver != "" {
		listFilters.Add("driver", req.Driver)
	}
	if nameFilter, ok := req.Filters["name"]; ok {
		listFilters.Add("name", nameFilter)
	} // Use Filters map
	if scope, ok := req.Filters["scope"]; ok {
		listFilters.Add("scope", scope)
	}
	if nType, ok := req.Filters["type"]; ok {
		listFilters.Add("type", nType)
	}
	if dangling, ok := req.Filters["dangling"]; ok {
		listFilters.Add("dangling", dangling)
	}
	// TODO: Add label filter parsing if needed

	// Get networks from Docker API
	dockerNetworks, err := ctrl.networkService.List(c.Request.Context(), network.ListOptions{ // Renamed variable
		Filters: listFilters,
		Timeout: 10 * time.Second,
		Logger:  ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to list networks")
		utils.InternalServerError(c, "Failed to list networks")
		return
	}

	// Filter based on search term and permissions (if needed after DB integration)
	filteredNetworks := make([]*models.Network, 0)
	for _, net := range dockerNetworks { // Use new variable name
		if req.Search != "" && !strings.Contains(net.Name, req.Search) {
			continue
		}

		// Permission check (simplified for now)
		dbNet, dbErr := ctrl.networkRepo.FindByNetworkID(c.Request.Context(), net.NetworkID)
		if !isAdmin && !isDefaultNetwork(net.Name) {
			if dbErr != nil || dbNet == nil || dbNet.UserID != userID {
				continue // Skip if not default, not in DB, or not owned by user
			}
		}
		// Enrich with DB data if found
		if dbErr == nil && dbNet != nil {
			net.ID = dbNet.ID
			net.UserID = dbNet.UserID
			net.Notes = dbNet.Notes
			net.CreatedAt = dbNet.CreatedAt // Prefer DB CreatedAt
			net.UpdatedAt = dbNet.UpdatedAt
		}

		filteredNetworks = append(filteredNetworks, net)
	}

	// TODO: Implement sorting if needed (requires sorting []*models.Network)
	sortedNetworks := filteredNetworks

	// Apply pagination
	total := len(sortedNetworks)
	offset := req.GetOffset()
	limit := req.PageSize
	end := offset + limit
	if end > total {
		end = total
	}

	var paginatedNetworks []*models.Network // Declare here
	if offset < total {
		paginatedNetworks = sortedNetworks[offset:end]
	} else {
		paginatedNetworks = []*models.Network{}
	}

	networkResponses := toNetworkResponseSlice(paginatedNetworks)

	response := models.NetworkListResponse{
		Networks: networkResponses,
		Metadata: models.MetadataResponse{
			Pagination: &models.PaginationResponse{
				Page:       req.Page,
				PageSize:   req.PageSize,
				TotalPages: (total + req.PageSize - 1) / req.PageSize,
				TotalItems: total,
			},
		},
	}
	utils.SuccessResponse(c, response)
}

// GetNetwork handles GET /networks/:id
func (ctrl *NetworkController) GetNetwork(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		utils.BadRequest(c, "Network ID is required")
		return
	}

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin))

	netModel, err := ctrl.networkService.Get(c.Request.Context(), id, network.GetOptions{
		Verbose: true, Timeout: 10 * time.Second, Logger: ctrl.logger,
	})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.NotFound(c, "Network not found")
			return
		}
		ctrl.logger.WithError(err).WithField("networkID", id).Error("Failed to get network from service")
		utils.InternalServerError(c, "Failed to retrieve network details")
		return
	}

	dbNetwork, dbErr := ctrl.networkRepo.FindByNetworkID(c.Request.Context(), netModel.NetworkID)
	if dbErr != nil && !errors.Is(dbErr, repositories.ErrNetworkNotFound) && !errors.Is(dbErr, gorm.ErrRecordNotFound) {
		ctrl.logger.WithError(dbErr).WithField("networkID", netModel.NetworkID).Warn("Failed to query network from database")
	}

	if dbNetwork != nil {
		if dbNetwork.UserID != userID && !isAdmin {
			utils.Forbidden(c, "You do not have permission to access this network")
			return
		}
		netModel.ID = dbNetwork.ID
		netModel.UserID = dbNetwork.UserID
		netModel.Notes = dbNetwork.Notes
		netModel.UpdatedAt = dbNetwork.UpdatedAt
	} else if !isAdmin && !isDefaultNetwork(netModel.Name) {
		utils.Forbidden(c, "You do not have permission to access this unmanaged network")
		return
	}

	response := convertNetworkModelToResponse(netModel)
	utils.SuccessResponse(c, response)
}

// CreateNetwork handles POST /networks
func (ctrl *NetworkController) CreateNetwork(c *gin.Context) {
	var req models.NetworkCreateRequest
	if !utils.BindJSON(c, &req) {
		return
	}
	if err := utils.ValidateNetworkName(req.Name); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin))

	if req.Driver != "" && req.Driver != "bridge" && !isAdmin {
		utils.Forbidden(c, "Only admins can use non-bridge network drivers")
		return
	}
	if err := validateNetworkOptions(req.Options, isAdmin); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	var dockerIPAM *networktypes.IPAM
	if req.IPAM != nil {
		dockerIPAM = &networktypes.IPAM{
			Driver:  req.IPAM.Driver,
			Options: req.IPAM.Options,
			Config:  make([]networktypes.IPAMConfig, len(req.IPAM.Config)),
		}
		for i, cfg := range req.IPAM.Config {
			dockerIPAM.Config[i] = networktypes.IPAMConfig{
				Subnet: cfg.Subnet, IPRange: cfg.IPRange, Gateway: cfg.Gateway, AuxAddress: cfg.AuxAddress,
			}
		}
	}

	createOpts := network.CreateOptions{
		Driver: req.Driver, EnableIPv6: req.EnableIPv6, Internal: req.Internal,
		Attachable: req.Attachable, Ingress: req.Ingress, ConfigOnly: req.ConfigOnly,
		CheckDuplicate: true, Options: req.Options, Labels: req.Labels, Scope: req.Scope,
		IPAM: dockerIPAM, Timeout: 10 * time.Second, Logger: ctrl.logger,
	}
	if createOpts.Labels == nil {
		createOpts.Labels = make(map[string]string)
	}
	createOpts.Labels["com.dockerservermanager.userid"] = strconv.FormatUint(uint64(userID), 10) // Use strconv

	netModel, err := ctrl.networkService.Create(c.Request.Context(), req.Name, createOpts)
	if err != nil {
		ctrl.logger.WithError(err).WithField("name", req.Name).Error("Failed to create network")
		if strings.Contains(err.Error(), "already exists") {
			utils.Conflict(c, "Network name already exists")
			return
		}
		utils.InternalServerError(c, "Failed to create network: "+err.Error())
		return
	}

	netModel.UserID = userID
	netModel.Notes = req.Notes
	netModel.CreatedAt = time.Now()
	netModel.UpdatedAt = time.Now()

	if err := ctrl.networkRepo.Create(c.Request.Context(), netModel); err != nil {
		ctrl.logger.WithError(err).WithField("networkID", netModel.NetworkID).Error("Failed to save network record to database after creation")
	}

	response := convertNetworkModelToResponse(netModel)
	c.JSON(http.StatusCreated, response)
}

// DeleteNetwork handles DELETE /networks/:id
func (ctrl *NetworkController) DeleteNetwork(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		utils.BadRequest(c, "Network ID is required")
		return
	}

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin))

	netModel, err := ctrl.networkService.Get(c.Request.Context(), id, network.GetOptions{Logger: ctrl.logger})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.NotFound(c, "Network not found")
			return
		}
		ctrl.logger.WithError(err).WithField("networkID", id).Error("Failed to get network for deletion check")
		utils.InternalServerError(c, "Failed to verify network existence")
		return
	}

	if isDefaultNetwork(netModel.Name) {
		utils.Forbidden(c, "Cannot delete default Docker networks")
		return
	}

	dbNetwork, dbErr := ctrl.networkRepo.FindByNetworkID(c.Request.Context(), netModel.NetworkID)
	if dbErr != nil && !errors.Is(dbErr, repositories.ErrNetworkNotFound) && !errors.Is(dbErr, gorm.ErrRecordNotFound) {
		ctrl.logger.WithError(dbErr).WithField("networkID", netModel.NetworkID).Warn("Failed to query network from database during delete")
	}

	if dbNetwork != nil {
		if dbNetwork.UserID != userID && !isAdmin {
			utils.Forbidden(c, "You do not have permission to delete this network")
			return
		}
	} else if !isAdmin {
		utils.Forbidden(c, "You do not have permission to delete this unmanaged network")
		return
	}

	force := c.Query("force") == "true"
	err = ctrl.networkService.Remove(c.Request.Context(), id, network.RemoveOptions{
		Force: force, Timeout: 10 * time.Second, Logger: ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithField("networkID", id).Error("Failed to delete network")
		if strings.Contains(err.Error(), "active endpoints") {
			utils.Conflict(c, "Network has active endpoints, use force=true to override")
			return
		}
		utils.InternalServerError(c, "Failed to delete network: "+err.Error())
		return
	}

	if dbNetwork != nil {
		if err := ctrl.networkRepo.Delete(c.Request.Context(), dbNetwork.ID); err != nil {
			ctrl.logger.WithError(err).WithField("networkID", id).Warn("Failed to delete network record from database after removal")
		}
	}

	utils.NoContentResponse(c)
}

// PruneNetworks handles POST /networks/prune
func (ctrl *NetworkController) PruneNetworks(c *gin.Context) {
	var req models.NetworkPruneRequest
	if !utils.BindQuery(c, &req) {
		return
	}

	pruneFilters := filters.NewArgs()
	for k, v := range req.Filters {
		pruneFilters.Add(k, v)
	}

	pruneResult, err := ctrl.networkService.Prune(c.Request.Context(), network.PruneOptions{
		Filters: pruneFilters,
		Timeout: 20 * time.Second,
		Logger:  ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to prune networks")
		utils.InternalServerError(c, "Failed to prune networks: "+err.Error())
		return
	}
	utils.SuccessResponse(c, pruneResult)
}

// ConnectContainer handles POST /networks/:id/connect
func (ctrl *NetworkController) ConnectContainer(c *gin.Context) {
	networkID := c.Param("id")
	if networkID == "" {
		utils.BadRequest(c, "Network ID is required")
		return
	}

	var req models.NetworkConnectRequest
	if !utils.BindJSON(c, &req) {
		return
	}
	if req.Container == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin))
	_ = userID  // Keep for permission check later
	_ = isAdmin // Keep for permission check later

	// TODO: Add permission check for container ownership if !isAdmin

	var endpointSettings *networktypes.EndpointSettings
	if req.EndpointConfig != nil {
		endpointSettings = &networktypes.EndpointSettings{Aliases: req.EndpointConfig.Aliases}
		if req.EndpointConfig.IPAMConfig != nil {
			endpointSettings.IPAMConfig = &networktypes.EndpointIPAMConfig{
				IPv4Address: req.EndpointConfig.IPAMConfig.IPv4Address,
				IPv6Address: req.EndpointConfig.IPAMConfig.IPv6Address,
			}
		}
	}

	err = ctrl.networkService.Connect(c.Request.Context(), networkID, req.Container, network.ConnectOptions{
		EndpointConfig: endpointSettings, Timeout: 10 * time.Second, Logger: ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithFields(logrus.Fields{"networkID": networkID, "containerID": req.Container}).Error("Failed to connect container to network")
		utils.InternalServerError(c, "Failed to connect container: "+err.Error())
		return
	}
	utils.SuccessResponse(c, gin.H{"message": "Container connected successfully"})
}

// DisconnectContainer handles POST /networks/:id/disconnect
func (ctrl *NetworkController) DisconnectContainer(c *gin.Context) {
	networkID := c.Param("id")
	if networkID == "" {
		utils.BadRequest(c, "Network ID is required")
		return
	}

	var req models.NetworkDisconnectRequest
	if !utils.BindJSON(c, &req) {
		return
	}
	if req.Container == "" {
		utils.BadRequest(c, "Container ID is required")
		return
	}

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin))
	_ = userID  // Keep for permission check later
	_ = isAdmin // Keep for permission check later

	// TODO: Add permission check for container ownership if !isAdmin

	err = ctrl.networkService.Disconnect(c.Request.Context(), networkID, req.Container, network.DisconnectOptions{
		Force: req.Force, Timeout: 10 * time.Second, Logger: ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithFields(logrus.Fields{"networkID": networkID, "containerID": req.Container}).Error("Failed to disconnect container from network")
		utils.InternalServerError(c, "Failed to disconnect container: "+err.Error())
		return
	}
	utils.SuccessResponse(c, gin.H{"message": "Container disconnected successfully"})
}

// isDefaultNetwork checks if a network name is one of the Docker defaults
func isDefaultNetwork(name string) bool {
	return name == "bridge" || name == "host" || name == "none"
}

// validateNetworkOptions validates driver options for security
func validateNetworkOptions(options map[string]string, isAdmin bool) error {
	if !isAdmin {
		for key := range options {
			lowerKey := strings.ToLower(key)
			if strings.Contains(lowerKey, "parent") || strings.Contains(lowerKey, "host") {
				return fmt.Errorf("network option '%s' requires admin privileges", key)
			}
		}
	}
	return nil
}

// toNetworkResponseSlice converts []*models.Network to []models.NetworkResponse
func toNetworkResponseSlice(networks []*models.Network) []models.NetworkResponse {
	responses := make([]models.NetworkResponse, len(networks))
	for i, net := range networks {
		if net != nil {
			responses[i] = convertNetworkModelToResponse(net) // Use helper
		}
	}
	return responses
}

// convertNetworkModelToResponse converts a *models.Network to models.NetworkResponse
func convertNetworkModelToResponse(net *models.Network) models.NetworkResponse {
	if net == nil {
		return models.NetworkResponse{}
	}
	resp := models.NetworkResponse{
		ID:         net.ID, // Use DB ID
		NetworkID:  net.NetworkID,
		Name:       net.Name,
		Driver:     net.Driver,
		Scope:      net.Scope,
		Created:    net.Created, // Use Docker Created time from model
		Internal:   net.Internal,
		EnableIPv6: net.EnableIPv6,
		Attachable: net.Attachable,
		Ingress:    net.Ingress,
		ConfigOnly: net.ConfigOnly,
		Labels:     utils.ConvertJSONMapToStringMap(net.Labels),  // Use util helper
		Options:    utils.ConvertJSONMapToStringMap(net.Options), // Use util helper
		// Containers: convertContainerMap(net.Containers), // Removed local helper call
		Notes:     net.Notes,
		UserID:    net.UserID,
		CreatedAt: net.CreatedAt, // Use DB CreatedAt
		UpdatedAt: net.UpdatedAt,
		Gateway:   net.Gateway,
		Subnet:    net.Subnet,
		IPRange:   net.IPRange,
	}
	// Populate Containers map if needed (requires logic)
	if net.Containers != nil {
		resp.Containers = make(map[string]models.NetworkContainerResponse)
		for id, data := range net.Containers {
			if containerData, ok := data.(map[string]interface{}); ok {
				resp.Containers[id] = models.NetworkContainerResponse{
					Name:        fmt.Sprintf("%v", containerData["Name"]),
					EndpointID:  fmt.Sprintf("%v", containerData["EndpointID"]),
					MacAddress:  fmt.Sprintf("%v", containerData["MacAddress"]),
					IPv4Address: fmt.Sprintf("%v", containerData["IPv4Address"]),
					IPv6Address: fmt.Sprintf("%v", containerData["IPv6Address"]),
				}
			}
		}
	}

	return resp
}

// Removed local helper functions
