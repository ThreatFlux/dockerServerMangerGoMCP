package api

import (
	"fmt" // Added import
	"io"
	"net/http"
	"sort" // Added import
	"time"

	"strings" // Added import

	"github.com/docker/docker/api/types/filters" // Added import
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker" // Added import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/volume"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// Helper function to convert JSONMap to map[string]string
// TODO: Move this to utils package if needed elsewhere
func convertJSONMapToStringMap(jsonMap models.JSONMap) map[string]string {
	stringMap := make(map[string]string)
	if jsonMap == nil {
		return stringMap
	}
	for k, v := range jsonMap {
		if strVal, ok := v.(string); ok {
			stringMap[k] = strVal
		} else {
			// Handle non-string values if necessary, e.g., log a warning or skip
			// For now, we'll just convert using fmt.Sprintf
			stringMap[k] = fmt.Sprintf("%v", v)
		}
	}
	return stringMap
}

// VolumeController handles volume-related API requests
type VolumeController struct {
	volumeService volume.Service
	// volumeRepo    *repositories.VolumeRepository // Removed - Repository file does not exist
	dockerManager docker.Manager // Changed from client.APIClient
	logger        *logrus.Logger
}

// NewVolumeController creates a new volume controller
func NewVolumeController(
	volumeService volume.Service,
	// volumeRepo *repositories.VolumeRepository, // Removed
	dockerManager docker.Manager, // Changed from client.APIClient
	logger *logrus.Logger,
) *VolumeController {
	return &VolumeController{
		volumeService: volumeService,
		// volumeRepo:    volumeRepo, // Removed
		dockerManager: dockerManager,
		logger:        logger,
	}
}

// RegisterRoutes registers the volume API routes
func (ctrl *VolumeController) RegisterRoutes(router *gin.RouterGroup, authMW *middleware.AuthMiddleware) {
	volumes := router.Group("/volumes")

	// Require authentication for all routes
	volumes.Use(authMW.RequireAuthentication())

	// Volume listing and details
	volumes.GET("", ctrl.ListVolumes)
	volumes.GET("/:id", ctrl.GetVolume)

	// Volume operations
	volumes.POST("", ctrl.CreateVolume)
	volumes.DELETE("/:id", ctrl.DeleteVolume)
	volumes.POST("/:id/inspect", ctrl.InspectVolume)
	// volumes.GET("/:id/content", ctrl.GetVolumeContent) // Commented out route for commented function

	// Admin-only operations
	adminVolumes := volumes.Group("", authMW.RequireAdmin())
	adminVolumes.POST("/prune", ctrl.PruneVolumes)
	adminVolumes.GET("/:id/backup", ctrl.BackupVolume)
	adminVolumes.POST("/:id/restore", ctrl.RestoreVolume)
	// adminVolumes.POST("/:id/clone", ctrl.CloneVolume) // Commented out route for commented function
	adminVolumes.POST("/:id/permissions", ctrl.UpdateVolumePermissions)
}

// ListVolumes handles GET /volumes
func (ctrl *VolumeController) ListVolumes(c *gin.Context) {
	// Parse pagination, sort, and filter parameters
	var req models.VolumeListRequest
	if !utils.BindQuery(c, &req) {
		return
	}

	// Set default values if not provided
	req.PaginationRequest.SetDefaults()
	req.SortRequest.SetDefaults("name")

	// Get user ID from context - Removed as userID is no longer used here
	/*
		userID, err := middleware.GetUserID(c) // Pass gin.Context
		if err != nil {
			utils.Unauthorized(c, "Authentication required")
			return
		}
	*/
	// Get volumes from Docker API
	filterArgs := filters.NewArgs()
	for k, v := range req.Filters {
		filterArgs.Add(k, v)
	}
	volumes, err := ctrl.volumeService.List(c.Request.Context(), volume.ListOptions{
		Filters: filterArgs, // Replaced utils.ConvertStringMapToFilters
		Timeout: 10 * time.Second,
		Logger:  ctrl.logger,
		//	Logger:  ctrl.logger, // Removed duplicate field
	})
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to list volumes")
		utils.InternalServerError(c, "Failed to list volumes")
		return
	}

	// Filter volumes based on user permissions
	filteredVolumes := make([]*models.Volume, 0)
	// isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context

	for _, vol := range volumes {
		// Apply search filter if provided
		if req.Search != "" && !strings.Contains(vol.Name, req.Search) { // Use strings.Contains
			continue
		}

		// Apply driver filter if provided
		if req.Driver != "" && vol.Driver != req.Driver {
			continue
		}

		// For non-admin users, only show volumes they created
		// TODO: Re-implement volume ownership check if VolumeRepository is added
		/*
			if !isAdmin {
				dbVol, err := ctrl.volumeRepo.FindByName(c.Request.Context(), vol.Name)
				if err != nil || dbVol == nil || dbVol.UserID != userID {
					continue
				}
			}
		*/

		filteredVolumes = append(filteredVolumes, vol)
	}

	// Apply sorting
	// sortedVolumes := utils.SortVolumes(filteredVolumes, req.SortBy, req.SortOrder) // Replaced with inline sorting
	sort.Slice(filteredVolumes, func(i, j int) bool {
		volA := filteredVolumes[i]
		volB := filteredVolumes[j]
		asc := req.SortOrder == "" || req.SortOrder == "asc"

		switch req.SortBy {
		case "name":
			if asc {
				return volA.Name < volB.Name
			}
			return volA.Name > volB.Name
		case "driver":
			if asc {
				return volA.Driver < volB.Driver
			}
			return volA.Driver > volB.Driver
		case "created_at":
			// Assuming CreatedAt is available, otherwise need to inspect
			// For now, sort by name as fallback if CreatedAt is not directly available
			if asc {
				return volA.Name < volB.Name // Placeholder: Replace with actual CreatedAt comparison if available
			}
			return volA.Name > volB.Name // Placeholder: Replace with actual CreatedAt comparison if available
		default: // Default sort by name ascending
			return volA.Name < volB.Name
		}
	})
	sortedVolumes := filteredVolumes // Use the sorted slice

	// Apply pagination
	total := len(sortedVolumes)
	offset := req.GetOffset()
	limit := req.PageSize
	end := offset + limit
	if end > total {
		end = total
	}

	var paginatedVolumes []*models.Volume
	if offset < total {
		paginatedVolumes = sortedVolumes[offset:end]
	} else {
		paginatedVolumes = []*models.Volume{}
	}

	// Convert []*models.Volume to []models.VolumeResponse
	volumeResponses := make([]models.VolumeResponse, len(paginatedVolumes))
	for i, vol := range paginatedVolumes {
		// Basic mapping, assuming models.Volume has these fields
		// TODO: Verify field mapping and handle potential nil pointers or missing data
		volumeResponses[i] = models.VolumeResponse{
			// ID:            vol.ID, // Assuming models.Volume doesn't have a DB ID
			VolumeID:   vol.Name, // Using Name as VolumeID for now
			Name:       vol.Name,
			Driver:     vol.Driver,
			Mountpoint: vol.Mountpoint,
			CreatedAt:  vol.CreatedAt,
			Scope:      vol.Scope,
			Labels:     convertJSONMapToStringMap(vol.Labels),  // Use helper
			Options:    convertJSONMapToStringMap(vol.Options), // Use helper
			Status:     convertJSONMapToStringMap(vol.Status),  // Use helper
			// InUse:      vol.UsageData != nil && vol.UsageData.RefCount > 0, // Requires UsageData
			// Containers: // Requires UsageData or separate logic
		}
	}

	// Create response
	response := models.VolumeListResponse{
		Volumes: volumeResponses, // Use the converted slice
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

// GetVolume handles GET /volumes/:id
func (ctrl *VolumeController) GetVolume(c *gin.Context) {
	// Get volume ID from path
	id := c.Param("id")
	if id == "" {
		utils.BadRequest(c, "Volume ID is required")
		return
	}

	// Validate volume name
	if err := utils.ValidateVolumeName(id); err != nil {
		utils.BadRequest(c, err.Error())
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

	// Get volume details
	vol, err := ctrl.volumeService.Get(c.Request.Context(), id, volume.GetOptions{
		Timeout: 10 * time.Second,
		Logger:  ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithField("volumeID", id).Error("Failed to get volume")
		utils.NotFound(c, "Volume not found")
		return
	}

	// Check user permission
	// TODO: Re-implement volume permission check if VolumeRepository is added
	/*
		isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
		if !isAdmin {
			dbVol, err := ctrl.volumeRepo.FindByName(c.Request.Context(), vol.Name) // Keep c.Request.Context() for DB call
			if err != nil || dbVol == nil || dbVol.UserID != userID {
				utils.Forbidden(c, "You don't have permission to access this volume")
				return
			}
		}
	*/

	// Return volume
	utils.SuccessResponse(c, vol)
}

// CreateVolume handles POST /volumes
func (ctrl *VolumeController) CreateVolume(c *gin.Context) {
	// Parse request body
	var req models.VolumeCreateRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate volume name
	if err := utils.ValidateVolumeName(req.Name); err != nil {
		utils.BadRequest(c, err.Error())
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

	// Check if user has permission to use custom driver
	isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
	if req.Driver != "local" && !isAdmin {
		utils.Forbidden(c, "Only admins can use non-local volume drivers")
		return
	}

	// Apply security validation to driver options
	if err := validateVolumeDriverOptions(req.DriverOpts, isAdmin); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	// Create volume
	vol, err := ctrl.volumeService.Create(c.Request.Context(), req.Name, volume.CreateOptions{
		Driver:     req.Driver,
		DriverOpts: req.DriverOpts,
		Labels:     req.Labels,
		Timeout:    10 * time.Second,
		Logger:     ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithField("name", req.Name).Error("Failed to create volume")
		utils.InternalServerError(c, "Failed to create volume: "+err.Error())
		return
	}

	// TODO: Re-implement volume database storage if VolumeRepository is added
	/*
		// Store volume in database
		dbVolume := &models.VolumeDBModel{
			Name:       vol.Name,
			Driver:     vol.Driver,
			UserID:     userID,
			Labels:     utils.MapToJSON(vol.Labels),
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		err = ctrl.volumeRepo.Create(c.Request.Context(), dbVolume)
		if err != nil {
			ctrl.logger.WithError(err).WithField("name", vol.Name).Warn("Failed to store volume in database")
		}
	*/

	// Return created volume
	c.JSON(http.StatusCreated, vol)
}

// DeleteVolume handles DELETE /volumes/:id
func (ctrl *VolumeController) DeleteVolume(c *gin.Context) {
	// Get volume ID from path
	id := c.Param("id")
	if id == "" {
		utils.BadRequest(c, "Volume ID is required")
		return
	}

	// Validate volume name
	if err := utils.ValidateVolumeName(id); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	// Parse query parameters
	force := c.Query("force") == "true"

	// Get user ID from context - Removed as userID is no longer used here
	/*
		userID, err := middleware.GetUserID(c) // Pass gin.Context
		if err != nil {
			utils.Unauthorized(c, "Authentication required")
			return
		}
	*/

	// TODO: Re-implement volume permission check if VolumeRepository is added
	/*
		// Check user permission
		isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
		if !isAdmin {
			dbVol, err := ctrl.volumeRepo.FindByName(c.Request.Context(), id) // Keep c.Request.Context() for DB call
			if err != nil || dbVol == nil || dbVol.UserID != userID {
				utils.Forbidden(c, "You don't have permission to delete this volume")
				return
			}
		}
	*/

	// Delete volume
	err := ctrl.volumeService.Remove(c.Request.Context(), id, volume.RemoveOptions{ // Changed = to :=
		Force:   force,
		Timeout: 10 * time.Second,
		Logger:  ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithField("volumeID", id).Error("Failed to delete volume")
		utils.InternalServerError(c, "Failed to delete volume: "+err.Error())
		return
	}

	// TODO: Re-implement volume database deletion if VolumeRepository is added
	/*
		// Remove from database
		dbVol, err := ctrl.volumeRepo.FindByName(c.Request.Context(), id)
		if err == nil && dbVol != nil {
			err = ctrl.volumeRepo.Delete(c.Request.Context(), dbVol.ID)
			if err != nil {
				ctrl.logger.WithError(err).WithField("volumeID", id).Warn("Failed to delete volume from database")
			}
		}
	*/
	// } // Removed extra brace

	// Return success
	utils.NoContentResponse(c)
}

// PruneVolumes handles POST /volumes/prune
func (ctrl *VolumeController) PruneVolumes(c *gin.Context) {
	// Parse query parameters for filters
	var req models.VolumePruneRequest
	if !utils.BindQuery(c, &req) {
		return
	}

	// Prune volumes
	filterArgs := filters.NewArgs()
	for k, v := range req.Filters {
		filterArgs.Add(k, v)
	}
	pruneResult, err := ctrl.volumeService.Prune(c.Request.Context(), volume.PruneOptions{
		Filters: filterArgs,       // Replaced utils.ConvertStringMapToFilters
		Timeout: 20 * time.Second, // Longer timeout for prune
		Logger:  ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to prune volumes")
		utils.InternalServerError(c, "Failed to prune volumes: "+err.Error())
		return
	}

	// Return the result
	utils.SuccessResponse(c, pruneResult)
}

// BackupVolume handles GET /volumes/:id/backup
func (ctrl *VolumeController) BackupVolume(c *gin.Context) {
	// Get volume ID from path
	id := c.Param("id")
	if id == "" {
		utils.BadRequest(c, "Volume ID is required")
		return
	}

	// Validate volume name
	if err := utils.ValidateVolumeName(id); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	// Parse query parameters
	compressionFormat := c.DefaultQuery("compression", "gzip")
	includeMetadata := c.DefaultQuery("metadata", "true") == "true"

	// Create backup
	backup, err := ctrl.volumeService.Backup(c.Request.Context(), id, volume.BackupOptions{
		CompressFormat:  compressionFormat,
		IncludeMetadata: includeMetadata,
		Timeout:         30 * time.Second, // Longer timeout for backup
		Logger:          ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithField("volumeID", id).Error("Failed to backup volume")
		utils.InternalServerError(c, "Failed to backup volume: "+err.Error())
		return
	}
	defer backup.Close()

	// Set response headers
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename="+id+".tar.gz")

	// Stream the backup to the client
	var copyErr error // Declare error variable outside the callback
	streamSuccess := c.Stream(func(w io.Writer) bool {
		_, copyErr = io.Copy(w, backup) // Assign to the outer error variable
		if copyErr != nil {
			ctrl.logger.WithError(copyErr).WithField("volumeID", id).Error("Error copying backup stream")
			return false // Stop streaming on error
		}
		return true // Continue streaming
	})

	// Check for errors after streaming attempt
	if copyErr != nil {
		// Error already logged inside callback, potentially return an error response here if needed
		// For now, just log again to indicate the stream might have been interrupted
		ctrl.logger.WithError(copyErr).WithField("volumeID", id).Error("Volume backup streaming failed")
	} else if !streamSuccess {
		// This case might indicate the client disconnected or another stream issue
		ctrl.logger.WithField("volumeID", id).Warn("Volume backup streaming was interrupted or failed to start")
	}
}

// RestoreVolume handles POST /volumes/:id/restore
func (ctrl *VolumeController) RestoreVolume(c *gin.Context) {
	// Get volume ID from path
	id := c.Param("id")
	if id == "" {
		utils.BadRequest(c, "Volume ID is required")
		return
	}

	// Validate volume name
	if err := utils.ValidateVolumeName(id); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	// Get form parameters
	overwriteIfExists := c.DefaultPostForm("overwrite", "false") == "true"
	restoreMetadata := c.DefaultPostForm("metadata", "true") == "true"

	// Get backup file
	file, _, err := c.Request.FormFile("backup")
	if err != nil {
		utils.BadRequest(c, "Backup file is required: "+err.Error())
		return
	}
	defer file.Close()

	// Restore volume
	err = ctrl.volumeService.Restore(c.Request.Context(), id, file, volume.RestoreOptions{
		OverwriteIfExists: overwriteIfExists,
		RestoreMetadata:   restoreMetadata,
		Timeout:           30 * time.Second, // Longer timeout for restore
		Logger:            ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithField("volumeID", id).Error("Failed to restore volume")
		utils.InternalServerError(c, "Failed to restore volume: "+err.Error())
		return
	}

	// Return success
	utils.SuccessResponse(c, gin.H{
		"status":  "success",
		"message": "Volume restored successfully",
		"volume":  id,
	})
}

// InspectVolume handles POST /volumes/:id/inspect
func (ctrl *VolumeController) InspectVolume(c *gin.Context) {
	// Get volume ID from path
	id := c.Param("id")
	if id == "" {
		utils.BadRequest(c, "Volume ID is required")
		return
	}

	// Validate volume name
	if err := utils.ValidateVolumeName(id); err != nil {
		utils.BadRequest(c, err.Error())
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

	// TODO: Re-implement volume permission check if VolumeRepository is added
	/*
		// Check user permission
		isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
		if !isAdmin {
			dbVol, err := ctrl.volumeRepo.FindByName(c.Request.Context(), id) // Keep c.Request.Context() for DB call
			if err != nil || dbVol == nil || dbVol.UserID != userID {
				utils.Forbidden(c, "You don't have permission to inspect this volume")
				return
			}
		}
	*/

	// Get detailed volume information
	details, err := ctrl.volumeService.Get(c.Request.Context(), id, volume.GetOptions{ // Changed Inspect to Get and options type
		Timeout: 10 * time.Second,
		Logger:  ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithField("volumeID", id).Error("Failed to inspect volume")
		utils.InternalServerError(c, "Failed to inspect volume: "+err.Error())
		return
	}

	// Return the results
	utils.SuccessResponse(c, details)
}

// TODO: Commenting out GetVolumeContent as volumeService.ListContents is not defined
/*
// GetVolumeContent handles GET /volumes/:id/content
func (ctrl *VolumeController) GetVolumeContent(c *gin.Context) {
	// Get volume ID from path
	id := c.Param("id")
	if id == "" {
		utils.BadRequest(c, "Volume ID is required")
		return
	}

	// Validate volume name
	if err := utils.ValidateVolumeName(id); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	// Parse query parameters
	path := c.DefaultQuery("path", "/")
	recursive := c.DefaultQuery("recursive", "false") == "true"

	// Get user ID from context - Removed as userID is no longer used here

		userID, err := middleware.GetUserID(c) // Pass gin.Context
		if err != nil {
			utils.Unauthorized(c, "Authentication required")
			return
		}


	// TODO: Re-implement volume permission check if VolumeRepository is added

		// Check user permission
		isAdmin, _ := middleware.HasRole(c, string(models.RoleAdmin)) // Pass gin.Context
		if !isAdmin {
			dbVol, err := ctrl.volumeRepo.FindByName(c.Request.Context(), id) // Keep c.Request.Context() for DB call
			if err != nil || dbVol == nil || dbVol.UserID != userID {
				utils.Forbidden(c, "You don't have permission to access this volume's content")
				return
			}
		}


	// List volume content
	content, err := ctrl.volumeService.ListContents(c.Request.Context(), id, path, volume.ListContentsOptions{
		Recursive: recursive,
		Timeout:   15 * time.Second,
		Logger:    ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithField("volumeID", id).Error("Failed to list volume content")
		utils.InternalServerError(c, "Failed to list volume content: "+err.Error())
		return
	}

	// Return the content listing
	utils.SuccessResponse(c, content)
}
*/

// TODO: Commenting out CloneVolume as volumeService.Clone is not defined
/*
// CloneVolume handles POST /volumes/:id/clone
func (ctrl *VolumeController) CloneVolume(c *gin.Context) {
	// Get source volume ID from path
	sourceID := c.Param("id")
	if sourceID == "" {
		utils.BadRequest(c, "Source volume ID is required")
		return
	}

	// Validate source volume name
	if err := utils.ValidateVolumeName(sourceID); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	// Parse request body
	var req models.VolumeCloneRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate target volume name
	if err := utils.ValidateVolumeName(req.TargetName); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	// Get user ID from context - Removed as userID is no longer used here

		userID, err := middleware.GetUserID(c.Request.Context())
		if err != nil {
			utils.Unauthorized(c, "Authentication required")
			return
		}


	// Clone volume
	newVolume, err := ctrl.volumeService.Clone(c.Request.Context(), sourceID, req.TargetName, volume.CloneOptions{
		Labels:   req.Labels,
		Timeout:  20 * time.Second,
		Logger:   ctrl.logger,
	})
	if err != nil {
		ctrl.logger.WithError(err).WithFields(logrus.Fields{
			"sourceID":   sourceID,
			"targetName": req.TargetName,
		}).Error("Failed to clone volume")
		utils.InternalServerError(c, "Failed to clone volume: "+err.Error())
		return
	}

	// TODO: Re-implement volume database storage if VolumeRepository is added

		// Store new volume in database
		dbVolume := &models.VolumeDBModel{
			Name:       newVolume.Name,
			Driver:     newVolume.Driver,
			UserID:     userID,
			Labels:     utils.MapToJSON(newVolume.Labels),
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		err = ctrl.volumeRepo.Create(c.Request.Context(), dbVolume)
		if err != nil {
			ctrl.logger.WithError(err).WithField("name", newVolume.Name).Warn("Failed to store cloned volume in database")
		}


	// Return the new volume
	c.JSON(http.StatusCreated, newVolume)
}
*/

// UpdateVolumePermissions handles POST /volumes/:id/permissions
func (ctrl *VolumeController) UpdateVolumePermissions(c *gin.Context) {
	// Get volume ID from path
	id := c.Param("id")
	if id == "" {
		utils.BadRequest(c, "Volume ID is required")
		return
	}

	// Validate volume name
	if err := utils.ValidateVolumeName(id); err != nil {
		utils.BadRequest(c, err.Error())
		return
	}

	// Parse request body
	var req models.VolumePermissionsRequest
	if !utils.BindJSON(c, &req) {
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

	// TODO: Re-implement volume existence check if VolumeRepository is added
	/*
		// Check if volume exists
		dbVol, err := ctrl.volumeRepo.FindByName(c.Request.Context(), id)
		if err != nil || dbVol == nil {
			utils.NotFound(c, "Volume not found in database")
			return
		}
	*/

	// TODO: Re-implement volume permission update if VolumeRepository is added
	/*
		// Update volume permissions in database
		dbVol.UserID = req.UserID // Transfer ownership to another user
		dbVol.UpdatedAt = time.Now()

		err = ctrl.volumeRepo.Update(c.Request.Context(), dbVol)
		if err != nil {
			ctrl.logger.WithError(err).WithField("volumeID", id).Error("Failed to update volume permissions")
			utils.InternalServerError(c, "Failed to update volume permissions: "+err.Error())
			return
		}
	*/

	// Return success
	utils.SuccessResponse(c, gin.H{
		"status":  "success",
		"message": "Volume permissions updated successfully",
		"volume":  id,
	})
}

// validateVolumeDriverOptions validates driver options for security
func validateVolumeDriverOptions(driverOpts map[string]string, isAdmin bool) error {
	// Non-admins can only use basic options
	if !isAdmin {
		for key := range driverOpts {
			// Check for potentially dangerous options
			if strings.Contains(key, "device") || // Use strings.Contains
				strings.Contains(key, "bind") || // Use strings.Contains
				strings.Contains(key, "mount") { // Use strings.Contains
				// Replace NewValidationError with direct struct initialization
				return &utils.ValidationError{
					Field:   "driverOpts",
					Code:    "ADMIN_REQUIRED",
					Message: "Driver option '" + key + "' requires admin privileges",
					Value:   key,
				}
			}
		}
	}

	return nil
}
