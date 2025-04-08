package volume

import (
	"errors"
	// "fmt" // Removed unused import
	"strconv"
	"strings"
	"time"

	// volumetypes "github.com/docker_test/docker_test/api/types/volume" // Removed unused import
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database/repositories"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/volume"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
	"gorm.io/gorm" // Added for gorm.ErrRecordNotFound
)

// Controller handles volume-related API requests
type Controller struct {
	volumeService volume.Service
	volumeRepo    repositories.VolumeRepository
	logger        *logrus.Logger
}

// NewController creates a new volume controller
func NewController(
	volumeService volume.Service,
	volumeRepo repositories.VolumeRepository,
	logger *logrus.Logger,
) *Controller {
	return &Controller{
		volumeService: volumeService,
		volumeRepo:    volumeRepo,
		logger:        logger,
	}
}

// RegisterRoutes registers the volume API routes
func (ctrl *Controller) RegisterRoutes(router *gin.RouterGroup, authMW *middleware.AuthMiddleware) {
	volumes := router.Group("/volumes")
	volumes.Use(authMW.RequireAuthentication()) // Require auth for all volume routes

	volumes.GET("", ctrl.List)
	volumes.GET("/:id", ctrl.Get)
	volumes.POST("", ctrl.Create)
	volumes.DELETE("/:id", ctrl.Remove)
	// TODO: Add prune route if needed (requires admin)
}

// List godoc
// @Summary List volumes
// @Description Retrieves a paginated list of Docker volumes, optionally filtered.
// @Tags Volumes
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1) example(1)
// @Param page_size query int false "Number of items per page" default(10) minimum(1) maximum(100) example(20)
// @Param sort_by query string false "Field to sort by (e.g., name, created_at, driver)" default(created_at) example(name)
// @Param sort_order query string false "Sort order (asc, desc)" default(desc) Enums(asc, desc) example(asc)
// @Param driver query string false "Filter by driver name" example(local)
// @Param name query string false "Filter by volume name (exact match)" example(my-app-data)
// @Success 200 {object} models.PaginatedResponse{data=[]models.VolumeResponse} "Successfully retrieved volumes"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /volumes [get]
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

	// List volumes from repository (includes filtering and pagination)
	// Assuming List returns []*models.Volume based on previous errors
	dbVolumes, total, err := ctrl.volumeRepo.List(c.Request.Context(), repoOptions)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to list volumes from repository")
		utils.InternalServerError(c, "Failed to retrieve volume list")
		return
	}

	// Convert to response models
	apiVolumes := make([]models.VolumeResponse, len(dbVolumes))
	for i, vol := range dbVolumes { // vol is *models.Volume
		// Inline conversion logic
		resp := models.VolumeResponse{
			ID:         vol.ID,
			VolumeID:   vol.VolumeID,
			Name:       vol.Name,
			Driver:     vol.Driver,
			Mountpoint: vol.Mountpoint,
			CreatedAt:  vol.CreatedAt,
			Scope:      vol.Scope,
			Labels:     vol.Labels.StringMap(),
			Options:    vol.Options.StringMap(),
			InUse:      vol.InUse,
			Notes:      vol.Notes,
			UserID:     vol.UserID,
			UpdatedAt:  vol.UpdatedAt,
		}
		if vol.UsageData != nil {
			resp.Size = vol.UsageData.Size
			resp.SizeHuman = utils.FormatImageSize(vol.UsageData.Size)
		}
		apiVolumes[i] = resp
	}

	// Return paginated response
	utils.PaginatedResponse(c, apiVolumes, page, pageSize, int(total))
}

// Get godoc
// @Summary Get volume details
// @Description Retrieves detailed information about a specific volume by its name or database ID.
// @Tags Volumes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Volume Name or Database ID" example(my-app-data)
// @Success 200 {object} models.SuccessResponse{data=models.VolumeResponse} "Successfully retrieved volume details"
// @Failure 400 {object} models.ErrorResponse "Invalid volume ID/name"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Volume not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /volumes/{id} [get]
func (ctrl *Controller) Get(c *gin.Context) {
	volumeID := c.Param("id")
	if volumeID == "" {
		utils.BadRequest(c, "Volume ID is required")
		return
	}

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.IsAdmin(c)

	// Try getting from service first (which inspects Docker)
	vol, err := ctrl.volumeService.Get(c.Request.Context(), volumeID, volume.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") { // Check for Docker not found error
			utils.NotFound(c, "Volume not found")
		} else {
			ctrl.logger.WithError(err).WithField("volumeID", volumeID).Error("Failed to get volume from service")
			utils.InternalServerError(c, "Failed to retrieve volume details")
		}
		return
	}

	// Try finding DB record to enrich with metadata and check ownership
	dbVolume, dbErr := ctrl.volumeRepo.FindByVolumeID(c.Request.Context(), vol.VolumeID)
	if dbErr != nil && !errors.Is(dbErr, repositories.ErrVolumeNotFound) && !errors.Is(dbErr, gorm.ErrRecordNotFound) {
		ctrl.logger.WithError(dbErr).WithField("volumeID", vol.VolumeID).Warn("Failed to query volume from database")
		// Continue without DB info, but log the error
	}

	// Check permissions
	if dbVolume != nil { // Found in DB
		if dbVolume.UserID != userID && !isAdmin {
			utils.Forbidden(c, "You do not have permission to access this volume")
			return
		}
		// Enrich the volume model with DB data
		vol.ID = dbVolume.ID
		vol.UserID = dbVolume.UserID
		vol.Notes = dbVolume.Notes
		vol.UpdatedAt = dbVolume.UpdatedAt
		// CreatedAt from DB might differ from Docker's, decide which one to show
		// vol.CreatedAt = dbVolume.CreatedAt
	} else if !isAdmin { // Not found in DB and user is not admin
		utils.Forbidden(c, "You do not have permission to access this unmanaged volume")
		return
	}

	// Convert the final model (potentially enriched) to response
	response := convertVolumeModelToResponse(vol) // Use local helper
	utils.SuccessResponse(c, response)
}

// Create godoc
// @Summary Create a new volume
// @Description Creates a new Docker volume.
// @Tags Volumes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param volume body models.VolumeCreateRequest true "Volume Configuration"
// @Success 200 {object} models.SuccessResponse{data=models.VolumeResponse} "Successfully created volume" // Changed to 200 OK as we return the created object
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 409 {object} models.ErrorResponse "Volume name already exists"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /volumes [post]
func (ctrl *Controller) Create(c *gin.Context) {
	var req models.VolumeCreateRequest
	if !utils.BindJSON(c, &req) {
		return // Error handled by BindJSON
	}

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}

	// Prepare options for service call
	createOptions := volume.CreateOptions{
		Driver:     req.Driver,
		DriverOpts: req.DriverOpts,
		Labels:     req.Labels,
	}
	// Add user ID label for tracking ownership
	if createOptions.Labels == nil {
		createOptions.Labels = make(map[string]string)
	}
	createOptions.Labels["com.dockerservermanager.userid"] = strconv.FormatUint(uint64(userID), 10)

	// Call service to create volume (returns *models.Volume)
	createdVol, err := ctrl.volumeService.Create(c.Request.Context(), req.Name, createOptions)
	if err != nil {
		ctrl.logger.WithError(err).WithField("name", req.Name).Error("Failed to create volume via service")
		if strings.Contains(err.Error(), "already exists") {
			utils.Conflict(c, "Volume name already exists")
		} else {
			utils.InternalServerError(c, "Failed to create volume: "+err.Error())
		}
		return
	}

	// Add user ID and notes to the model returned by the service
	createdVol.UserID = userID
	createdVol.Notes = req.Notes
	createdVol.CreatedAt = time.Now() // Set DB creation time
	createdVol.UpdatedAt = time.Now()

	// Create record in database
	if err := ctrl.volumeRepo.Create(c.Request.Context(), createdVol); err != nil {
		ctrl.logger.WithError(err).WithField("volumeID", createdVol.VolumeID).Error("Failed to save volume record to database after creation")
		// Log warning but proceed, returning the created volume info
	} else {
		// Update the ID in the model if DB save was successful
		// (Create method should update the ID in the passed pointer)
	}

	// Convert the final model to response
	response := convertVolumeModelToResponse(createdVol) // Use local helper
	utils.SuccessResponse(c, response)                   // Use standard success response
}

// Remove godoc
// @Summary Remove a volume
// @Description Removes a Docker volume by its name or database ID.
// @Tags Volumes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Volume Name or Database ID" example(my-app-data)
// @Param force query bool false "Force removal of the volume" default(false) example(true)
// @Success 204 "Volume removed successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid volume ID/name"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Volume not found"
// @Failure 409 {object} models.ErrorResponse "Conflict (e.g., volume is in use)"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /volumes/{id} [delete]
func (ctrl *Controller) Remove(c *gin.Context) {
	volumeID := c.Param("id")
	if volumeID == "" {
		utils.BadRequest(c, "Volume ID is required")
		return
	}
	force := c.Query("force") == "true"

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.IsAdmin(c)

	// Check permissions based on DB record if it exists
	dbVolume, err := ctrl.volumeRepo.FindByVolumeID(c.Request.Context(), volumeID) // Find by name first
	if err != nil && !errors.Is(err, repositories.ErrVolumeNotFound) && !errors.Is(err, gorm.ErrRecordNotFound) {
		ctrl.logger.WithError(err).WithField("volumeID", volumeID).Error("Failed to check volume ownership")
		utils.InternalServerError(c, "Failed to verify volume permissions")
		return
	}

	if dbVolume != nil { // Found in DB
		if dbVolume.UserID != userID && !isAdmin {
			utils.Forbidden(c, "You do not have permission to remove this volume")
			return
		}
	} else if !isAdmin { // Not found in DB and user is not admin
		_, inspectErr := ctrl.volumeService.InspectRaw(c.Request.Context(), volumeID)
		if inspectErr == nil { // Exists in Docker but not DB
			utils.Forbidden(c, "You do not have permission to remove this unmanaged volume")
			return
		}
	}

	// Call service to remove volume
	removeOptions := volume.RemoveOptions{Force: force}                           // Create options struct
	err = ctrl.volumeService.Remove(c.Request.Context(), volumeID, removeOptions) // Pass options
	if err != nil {
		ctrl.logger.WithError(err).WithField("volumeID", volumeID).Error("Failed to remove volume via service")
		if strings.Contains(err.Error(), "volume in use") {
			utils.Conflict(c, "Volume is currently in use by a container")
			return
		}
		if strings.Contains(err.Error(), "no such volume") {
			utils.NotFound(c, "Volume not found")
			return
		}
		utils.InternalServerError(c, "Failed to remove volume: "+err.Error())
		return
	}

	// Remove from database if it existed
	if dbVolume != nil {
		if err := ctrl.volumeRepo.Delete(c.Request.Context(), dbVolume.ID); err != nil {
			ctrl.logger.WithError(err).WithField("volumeID", volumeID).Warning("Failed to delete volume record from database after removal")
		}
	}

	utils.NoContentResponse(c)
}

// Helper function to convert models.Volume (from DB/Service) to models.VolumeResponse
func convertVolumeModelToResponse(vol *models.Volume) models.VolumeResponse {
	resp := models.VolumeResponse{
		ID:         vol.ID,
		VolumeID:   vol.VolumeID,
		Name:       vol.Name,
		Driver:     vol.Driver,
		Mountpoint: vol.Mountpoint,
		CreatedAt:  vol.CreatedAt, // Use DB CreatedAt
		Scope:      vol.Scope,
		Labels:     vol.Labels.StringMap(),
		Options:    vol.Options.StringMap(),
		// Status:     vol.Status.StringMap(), // Assuming Status is JSONMap
		InUse:     vol.InUse,
		Notes:     vol.Notes,
		UserID:    vol.UserID,
		UpdatedAt: vol.UpdatedAt,
	}
	if vol.UsageData != nil {
		resp.Size = vol.UsageData.Size
		resp.SizeHuman = utils.FormatImageSize(vol.UsageData.Size)
	}
	return resp
}

// Removed redundant toVolumeModel and toVolumeUsageData helpers
// The service layer (internal/docker_test/volume/service.go) should handle conversion from Docker types to models.Volume
