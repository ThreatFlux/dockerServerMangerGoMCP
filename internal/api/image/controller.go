package image

import (
	"bytes"
	"errors"
	// "fmt" // Removed unused import
	"io"
	// "mime/multipart" // Removed unused import
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/docker/docker/api/types/filters"
	imagetypes "github.com/docker/docker/api/types/image" // Add alias
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database/repositories"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker" // Import local docker_test package for Manager
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/image"
	imageOps "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/image/operations" // Alias for operations package
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
	"gorm.io/gorm" // Added for gorm errors
)

// Controller handles image-related API requests
type Controller struct {
	imageService image.Service
	imageRepo    repositories.ImageRepository
	dockerClient docker.Manager
	logger       *logrus.Logger
}

// NewController creates a new image controller
func NewController(
	imageService image.Service,
	imageRepo repositories.ImageRepository,
	dockerClient docker.Manager,
	logger *logrus.Logger,
) *Controller {
	return &Controller{
		imageService: imageService,
		imageRepo:    imageRepo,
		dockerClient: dockerClient,
		logger:       logger,
	}
}

// RegisterRoutes registers the image API routes
func (ctrl *Controller) RegisterRoutes(router *gin.RouterGroup, authMW *middleware.AuthMiddleware) {
	images := router.Group("/images")
	images.Use(authMW.RequireAuthentication())

	images.GET("", ctrl.List)
	// images.GET("/:id", ctrl.Get) // Keep :id for simple IDs/names without slashes - REMOVED, wildcard handles this
	images.GET("/*id", ctrl.Get) // Add wildcard route for names with slashes
	images.POST("/pull", ctrl.Pull)
	images.POST("/build", ctrl.Build)
	// images.POST("/:id/tag", ctrl.Tag) // Keep :id for simple IDs/names without slashes - REMOVED, wildcard handles this
	images.POST("/tag", ctrl.Tag)      // Changed route, get source image from body
	images.DELETE("/*id", ctrl.Remove) // Use wildcard route for delete
	// images.GET("/:id/history", ctrl.History) // Keep :id for simple IDs/names without slashes - REMOVED, wildcard handles this
	// images.GET("/history/*id", ctrl.History) // Moved route outside the group

	// Register history route at the top level to avoid conflict
	router.GET("/image-history/*id", authMW.RequireAuthentication(), ctrl.History)
}

// List godoc
// @Summary List images
// @Description Retrieves a list of Docker images.
// @Tags Images
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1) example(1)
// @Param page_size query int false "Number of items per page" default(10) minimum(1) maximum(100) example(20)
// @Param sort_by query string false "Field to sort by (e.g., repository, tag, size, created)" default(created) example(size)
// @Param sort_order query string false "Sort order (asc, desc)" default(desc) Enums(asc, desc) example(asc)
// @Param all query bool false "Show all images (including intermediate layers)" default(false) example(true)
// @Param dangling query bool false "Filter by dangling images" example(true)
// @Param label query string false "Filter by label (e.g., key=value)" example(maintainer=me)
// @Param search query string false "Search term for repository, tag, or image ID" example(nginx)
// @Success 200 {object} models.PaginatedResponse{data=models.ImageListResponse} "Successfully retrieved images"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /images [get]
func (ctrl *Controller) List(c *gin.Context) {
	page, pageSize := utils.GetPaginationParams(c)
	sortBy := c.DefaultQuery("sort_by", "created")
	sortOrder := c.DefaultQuery("sort_order", "desc")
	all := c.Query("all") == "true"
	danglingFilter := c.Query("dangling")
	labelFilter := c.Query("label")
	searchFilter := c.Query("search")

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.IsAdmin(c)

	listFilters := filters.NewArgs()
	if danglingFilter != "" {
		listFilters.Add("dangling", danglingFilter)
	}
	if labelFilter != "" {
		listFilters.Add("label", labelFilter)
	}

	listOptions := image.ListOptions{
		All: all,
		// Filters: listFilters, // Filters field is not part of image.ListOptions
	}

	dockerImages, err := ctrl.imageService.List(c.Request.Context(), listOptions)
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to list images from service")
		utils.InternalServerError(c, "Failed to retrieve image list")
		return
	}

	apiImages := make([]models.ImageResponse, 0, len(dockerImages))
	for _, img := range dockerImages {
		repoName, tagName := "", ""
		if len(img.RepoTags) > 0 {
			repoName, tagName = utils.ParseRepositoryTag(img.RepoTags[0]) // Parse first tag
		}
		createdTime := time.Unix(img.Created, 0)

		response := models.ImageResponse{
			ImageID:    img.ID,
			Name:       repoName, // Default name
			Repository: repoName,
			Tag:        tagName,
			Created:    createdTime,
			Size:       img.Size,
			SizeHuman:  utils.FormatImageSize(img.Size),
			Labels:     img.Labels,
			// Architecture and OS are not in summary
		}
		if len(img.RepoTags) > 0 {
			response.Name = img.RepoTags[0]
		}

		dbImage, dbErr := ctrl.imageRepo.FindByImageID(c.Request.Context(), img.ID)
		isManaged := dbErr == nil && dbImage != nil
		hasPermission := false

		if isManaged {
			if dbImage.UserID == userID || isAdmin {
				hasPermission = true
				response.ID = dbImage.ID
				response.Notes = dbImage.Notes
				response.UserID = dbImage.UserID
				response.CreatedAt = dbImage.CreatedAt
				response.UpdatedAt = dbImage.UpdatedAt
				response.Repository = dbImage.Repository
				response.Tag = dbImage.Tag
				response.Name = dbImage.Name
			}
		} else if isAdmin {
			hasPermission = true
		}

		if hasPermission {
			passesSearch := true
			if searchFilter != "" {
				passesSearch = containsSearchTerm(response, searchFilter)
			}
			// TODO: Add other filters (repo, tag) here if needed
			if passesSearch {
				apiImages = append(apiImages, response)
			}
		}
	}

	sortedImages := sortImages(apiImages, sortBy, sortOrder)

	total := len(sortedImages)
	// Manual pagination calculation
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	paginatedImages := []models.ImageResponse{} // Initialize empty slice
	if start < end {                            // Ensure start is less than end to avoid slice bounds out of range
		paginatedImages = sortedImages[start:end]
	}

	utils.PaginatedResponse(c, models.ImageListResponse{
		Images: paginatedImages,
		Metadata: models.MetadataResponse{
			Pagination: &models.PaginationResponse{
				Page:       page,
				PageSize:   pageSize,
				TotalPages: (total + pageSize - 1) / pageSize,
				TotalItems: total,
			},
		},
	}, page, pageSize, total)
}

// Get godoc
// @Summary Get image details
// @Description Retrieves detailed information about a specific image by its ID or name/tag. Handles names with slashes.
// @Tags Images
// @Produce json
// @Security BearerAuth
// @Param id path string true "Image ID, Name, or Name:Tag (URL encoded if contains slashes)" example(nginx:latest)
// @Success 200 {object} models.SuccessResponse{data=models.ImageResponse} "Successfully retrieved image details"
// @Failure 400 {object} models.ErrorResponse "Invalid image ID/name format"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Image not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /images/{id} [get] // Corrected path parameter syntax
func (ctrl *Controller) Get(c *gin.Context) {
	imageID := c.Param("id")
	if imageID == "" {
		utils.BadRequest(c, "Image ID or Name:Tag is required")
		return
	}
	if len(imageID) > 0 && imageID[0] == '/' {
		imageID = imageID[1:]
	}

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}
	isAdmin, _ := middleware.IsAdmin(c)

	dockerImage, inspectErr := ctrl.imageService.Inspect(c.Request.Context(), imageID)
	if inspectErr != nil {
		ctrl.logger.WithError(inspectErr).WithField("imageID", imageID).Error("Failed to inspect image via Docker API")
		if errors.Is(inspectErr, image.ErrImageNotFound) {
			utils.NotFound(c, "Image not found")
		} else {
			utils.InternalServerError(c, "Failed to inspect image details")
		}
		return
	}

	dbImage, err := ctrl.imageRepo.FindByImageID(c.Request.Context(), dockerImage.ID)

	if dbImage != nil {
		if dbImage.UserID != userID && !isAdmin {
			utils.Forbidden(c, "You do not have permission to access this image")
			return
		}
	} else if !isAdmin {
		utils.Forbidden(c, "You do not have permission to access this unmanaged image")
		return
	}

	response := models.ImageResponse{
		ImageID:      dockerImage.ID,
		Repository:   "",
		Tag:          "",
		Digest:       "",
		Created:      parseDockerTime(dockerImage.Created, ctrl.logger),
		Size:         dockerImage.Size,
		SizeHuman:    utils.FormatImageSize(dockerImage.Size),
		Architecture: dockerImage.Architecture,
		OS:           dockerImage.Os,
		Author:       dockerImage.Author,
		Labels:       dockerImage.Config.Labels,
	}
	if len(dockerImage.RepoTags) > 0 {
		repoName, tagName := utils.ParseRepositoryTag(dockerImage.RepoTags[0])
		response.Repository = repoName
		response.Tag = tagName
		response.Name = dockerImage.RepoTags[0]
	}
	if len(dockerImage.RepoDigests) > 0 {
		response.Digest = dockerImage.RepoDigests[0]
	}

	if dbImage != nil {
		response.ID = dbImage.ID
		response.Notes = dbImage.Notes
		response.UserID = dbImage.UserID
		response.CreatedAt = dbImage.CreatedAt
		response.UpdatedAt = dbImage.UpdatedAt
		response.Repository = dbImage.Repository
		response.Tag = dbImage.Tag
		response.Name = dbImage.Name
	}

	utils.SuccessResponse(c, response)
}

// Pull godoc
// @Summary Pull an image
// @Description Pulls an image from a Docker registry. Authentication can be provided.
// @Tags Images
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param image body models.ImagePullRequest true "Image Pull Request"
// @Success 200 {object} models.SuccessResponse{data=models.ImagePullResponse} "Image pulled successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input (e.g., missing image name)"
// @Failure 401 {object} models.ErrorResponse "Authentication required or invalid credentials"
// @Failure 403 {object} models.ErrorResponse "Permission denied for registry"
// @Failure 404 {object} models.ErrorResponse "Image not found in registry"
// @Failure 500 {object} models.ErrorResponse "Internal server error (e.g., Docker daemon error)"
// @Router /images/pull [post]
func (ctrl *Controller) Pull(c *gin.Context) {
	var req models.ImagePullRequest
	if !utils.BindJSON(c, &req) {
		return
	}
	if req.Image == "" {
		utils.BadRequest(c, "Image reference is required")
		return
	}

	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}

	imageRef := req.Image
	if req.Tag != "" {
		imageRef = imageRef + ":" + req.Tag
	}

	options := image.PullOptions{All: false}

	parsedRef, err := reference.ParseNormalizedNamed(req.Image)
	if err != nil {
		utils.BadRequest(c, "Invalid image reference format: "+err.Error())
		return
	}
	registryAddress := reference.Domain(parsedRef)
	if registryAddress == "docker_test.io" || registryAddress == "" {
		registryAddress = "registry.hub.docker_test.com"
	}

	if req.Credentials.Username != "" && req.Credentials.Password != "" {
		if !isAdmin(c) && !isAllowedRegistry(registryAddress) {
			utils.Forbidden(c, "You don't have permission to pull from this registry")
			return
		}
		authConfig := models.RegistryAuth{
			Username:      req.Credentials.Username,
			Password:      req.Credentials.Password,
			ServerAddress: registryAddress,
		}
		encodedAuth, err := utils.EncodeRegistryAuth(authConfig)
		if err != nil {
			ctrl.logger.WithError(err).Error("Failed to encode registry auth")
			utils.InternalServerError(c, "Failed to encode registry authentication")
			return
		}
		options.RegistryAuth = encodedAuth
	}

	var progressOutput bytes.Buffer
	options.ProgressOutput = &progressOutput

	dockerAPIClient, err := ctrl.dockerClient.GetClient()
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to get Docker client for pull operation")
		utils.InternalServerError(c, "Failed to connect to Docker service")
		return
	}

	pullManager := imageOps.NewPullManager(dockerAPIClient, nil, ctrl.logger)
	reader, err := pullManager.Pull(c.Request.Context(), imageRef, options)
	if err != nil {
		ctrl.logger.WithError(err).WithField("image", imageRef).Error("Failed to pull image")
		utils.InternalServerError(c, "Failed to pull image: "+err.Error())
		return
	}
	defer reader.Close()

	_, err = io.Copy(io.Discard, reader)
	if err != nil {
		ctrl.logger.WithError(err).WithField("image", imageRef).Error("Error reading pull response")
		utils.InternalServerError(c, "Error processing pull response")
		return
	}

	inspector := image.NewInspector(dockerAPIClient, ctrl.logger)
	imageDetails, err := inspector.Inspect(c.Request.Context(), imageRef)
	if err != nil {
		ctrl.logger.WithError(err).WithField("image", imageRef).Warning("Failed to get pulled image details")
		utils.SuccessResponse(c, models.ImagePullResponse{
			Success: true, Image: imageRef, Time: time.Now(),
		})
		return
	}

	repoName, tagName := utils.ParseRepositoryTag(imageRef)
	dbImage := &models.Image{
		DockerResource: models.DockerResource{
			UserID: userID, Name: imageRef, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		ImageID:    imageDetails.ID,
		Repository: repoName,
		Tag:        tagName,
		Size:       imageDetails.Size,
		Created:    parseDockerTime(imageDetails.Created, ctrl.logger),
	}
	if err = ctrl.imageRepo.Create(c.Request.Context(), dbImage); err != nil {
		ctrl.logger.WithError(err).WithField("image", imageRef).Warning("Failed to store image in database")
	}

	utils.SuccessResponse(c, models.ImagePullResponse{
		Success:   true,
		Image:     imageRef,
		ID:        imageDetails.ID,
		Size:      imageDetails.Size,
		CreatedAt: imageDetails.Created,
		Time:      time.Now(),
	})
}

// Build godoc
// @Summary Build an image
// @Description Builds a Docker image from a Dockerfile and context. Context can be uploaded as a TAR archive.
// @Tags Images
// @Accept multipart/form-data
// @Produce json
// @Security BearerAuth
// @Param tag formData string true "Image tag (e.g., myapp:latest)" example(my-custom-app:v1.1)
// @Param dockerfile formData file false "Dockerfile content (alternative to context archive)"
// @Param context formData file false "Build context as TAR archive (can contain Dockerfile)"
// @Param dockerfile_path formData string false "Path to Dockerfile within the context archive" default("Dockerfile") example(build/Dockerfile.prod)
// @Param nocache formData bool false "Do not use cache when building the image" default(false) example(true)
// @Param pull formData bool false "Always attempt to pull a newer version of the image" default(false) example(true)
// @Param buildarg.* formData string false "Build-time variables (e.g., buildarg.VERSION=1.0)" example(buildarg.APP_VERSION=1.1)
// @Param label.* formData string false "Set metadata for an image (e.g., label.maintainer=me)" example(label.project=webapp)
// @Success 200 {object} models.SuccessResponse{data=models.ImageBuildResponse} "Image built successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input (e.g., missing tag, invalid tag format, missing Dockerfile/context)"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 500 {object} models.ErrorResponse "Internal server error (e.g., Docker daemon error, failed to process context)"
// @Router /images/build [post]
func (ctrl *Controller) Build(c *gin.Context) {
	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return
	}

	if err := c.Request.ParseMultipartForm(32 << 20); err != nil {
		utils.BadRequest(c, "Invalid multipart form: "+err.Error())
		return
	}

	tag := c.PostForm("tag")
	if tag == "" {
		utils.BadRequest(c, "Tag is required")
		return
	}
	if err := utils.ValidateImageName(tag); err != nil {
		utils.BadRequest(c, "Invalid image tag: "+err.Error())
		return
	}

	dockerfile, _, errDockerfile := c.Request.FormFile("dockerfile")
	contextFile, _, errContext := c.Request.FormFile("context")

	if errDockerfile != nil && errContext != nil {
		utils.BadRequest(c, "Dockerfile or context archive is required")
		return
	}

	if errContext == nil { // Prefer context archive if provided
		defer contextFile.Close()
		dockerfilePath := "Dockerfile"
		if dfPath := c.PostForm("dockerfile_path"); dfPath != "" {
			dockerfilePath = dfPath
		}
		ctrl.buildFromArchive(c, contextFile, dockerfilePath, tag, userID)
	} else { // Build using uploaded Dockerfile
		defer dockerfile.Close()
		tempDir, err := os.MkdirTemp("", "docker_test-build-")
		if err != nil {
			utils.InternalServerError(c, "Failed to create temporary build directory")
			return
		}
		defer os.RemoveAll(tempDir)

		dockerfilePath := filepath.Join(tempDir, "Dockerfile")
		out, err := os.Create(dockerfilePath)
		if err != nil {
			utils.InternalServerError(c, "Failed to create Dockerfile")
			return
		}
		_, err = io.Copy(out, dockerfile)
		out.Close()
		if err != nil {
			utils.InternalServerError(c, "Failed to save Dockerfile")
			return
		}
		ctrl.buildFromDirectory(c, tempDir, "Dockerfile", tag, userID)
	}
}

// buildFromArchive builds an image from a context archive
func (ctrl *Controller) buildFromArchive(c *gin.Context, contextFile io.Reader, dockerfilePath, tag string, userID uint) {
	tempFile, err := os.CreateTemp("", "docker_test-build-*.tar.gz")
	if err != nil {
		utils.InternalServerError(c, "Failed to create temporary file for context")
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	_, err = io.Copy(tempFile, contextFile)
	if err != nil {
		utils.InternalServerError(c, "Failed to save context archive")
		return
	}
	_, err = tempFile.Seek(0, 0)
	if err != nil {
		utils.InternalServerError(c, "Failed to process context archive")
		return
	}

	buildOptions := ctrl.prepareBuildOptions(c, tag)
	buildOptions.Context = tempFile
	buildOptions.Dockerfile = dockerfilePath

	ctrl.executeBuild(c, buildOptions, tag, userID)
}

// buildFromDirectory builds an image from a directory context
func (ctrl *Controller) buildFromDirectory(c *gin.Context, contextDir, dockerfileName, tag string, userID uint) {
	buildOptions := ctrl.prepareBuildOptions(c, tag)
	buildOptions.ContextDir = contextDir
	buildOptions.Dockerfile = dockerfileName

	ctrl.executeBuild(c, buildOptions, tag, userID)
}

// prepareBuildOptions extracts common build options from the request
func (ctrl *Controller) prepareBuildOptions(c *gin.Context, tag string) image.BuildOptions {
	buildOptions := image.BuildOptions{
		Tags:        []string{tag},
		NoCache:     c.PostForm("nocache") == "true",
		PullParent:  c.PostForm("pull") == "true",
		Remove:      true,
		ForceRemove: true,
		BuildArgs:   make(map[string]*string),
		BuildLabels: make(map[string]string),
	}

	for key, values := range c.Request.PostForm {
		if len(values) > 0 {
			if utils.StringHasPrefix(key, "buildarg.") {
				argName := key[9:]
				value := values[0]
				buildOptions.BuildArgs[argName] = &value
			} else if utils.StringHasPrefix(key, "label.") {
				labelName := key[6:]
				buildOptions.BuildLabels[labelName] = values[0]
			}
		}
	}
	return buildOptions
}

// executeBuild performs the actual image build and handles the response
func (ctrl *Controller) executeBuild(c *gin.Context, buildOptions image.BuildOptions, tag string, userID uint) {
	var progressOutput bytes.Buffer
	buildOptions.ProgressOutput = &progressOutput

	dockerAPIClient, err := ctrl.dockerClient.GetClient()
	if err != nil {
		ctrl.logger.WithError(err).Error("Failed to get Docker client for build operation")
		utils.InternalServerError(c, "Failed to connect to Docker service")
		return
	}

	buildManager := imageOps.NewBuildManager(dockerAPIClient, ctrl.logger)
	result, err := buildManager.BuildAndWait(c.Request.Context(), buildOptions)
	if err != nil {
		ctrl.logger.WithError(err).WithField("tag", tag).Error("Failed to build image")
		utils.InternalServerError(c, "Failed to build image: "+err.Error())
		return
	}

	inspector := image.NewInspector(dockerAPIClient, ctrl.logger)
	imageDetails, err := inspector.Inspect(c.Request.Context(), tag)
	if err != nil {
		ctrl.logger.WithError(err).WithField("tag", tag).Warning("Failed to get built image details")
		utils.SuccessResponse(c, models.ImageBuildResponse{
			Success: true, Tag: tag, ImageID: result.ImageID,
		})
		return
	}

	repoName, tagName := utils.ParseRepositoryTag(tag)
	dbImage := &models.Image{
		DockerResource: models.DockerResource{
			UserID: userID, Name: tag, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		ImageID:    imageDetails.ID,
		Repository: repoName,
		Tag:        tagName,
		Size:       imageDetails.Size,
		Created:    parseDockerTime(imageDetails.Created, ctrl.logger),
	}
	if err = ctrl.imageRepo.Create(c.Request.Context(), dbImage); err != nil {
		ctrl.logger.WithError(err).WithField("image", tag).Warning("Failed to store image in database")
	}

	utils.SuccessResponse(c, models.ImageBuildResponse{
		Success: true, Tag: tag, ImageID: imageDetails.ID,
	})
}

// Tag godoc
// @Summary Tag an image
// @Description Creates a new tag for an existing image. Handles names with slashes.
// @Tags Images
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tag body models.ImageTagRequest true "New Tag Info"
// @Success 201 "Image tagged successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input (e.g., missing repo/tag, invalid format)"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Source image not found"
// @Failure 409 {object} models.ErrorResponse "Tag already exists"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /images/tag [post] // Updated route
func (ctrl *Controller) Tag(c *gin.Context) {
	var req models.ImageTagRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate source image reference
	if req.SourceImage == "" {
		utils.BadRequest(c, "Source image reference is required")
		return
	}

	// Validate repository and tag separately before combining
	if req.Repository == "" {
		utils.BadRequest(c, "Repository is required")
		return
	}
	if req.Tag == "" {
		utils.BadRequest(c, "Tag is required")
		return
	}

	// Validate new tag format
	targetTag := req.Repository + ":" + req.Tag // Combine after individual validation
	if err := utils.ValidateImageName(targetTag); err != nil {
		utils.BadRequest(c, "Invalid target tag format: "+err.Error())
		return
	}

	// Check permission for the source image
	if !ctrl.hasImagePermission(c, req.SourceImage) { // Use SourceImage from request body
		return
	}

	err := ctrl.imageService.Tag(c.Request.Context(), req.SourceImage, targetTag) // Use SourceImage from request body
	if err != nil {
		ctrl.logger.WithError(err).WithFields(logrus.Fields{
			"source": req.SourceImage, "target": targetTag, // Use SourceImage from request body
		}).Error("Failed to tag image")
		utils.InternalServerError(c, "Failed to tag image: "+err.Error())
		return
	}

	// TODO: Store new tag info in database if the source image was managed

	c.Status(http.StatusCreated)
}

// Remove godoc
// @Summary Remove an image
// @Description Removes an image by its ID or name/tag. Handles names with slashes.
// @Tags Images
// @Produce json
// @Security BearerAuth
// @Param id path string true "Image ID, Name, or Name:Tag (URL encoded if contains slashes)"
// @Param force query bool false "Force removal of the image" default(false)
// @Param noprune query bool false "Do not delete untagged parents" default(false)
// @Success 200 {object} models.SuccessResponse{data=[]models.ImageRemoveResponse} "Image removal report"
// @Failure 400 {object} models.ErrorResponse "Invalid image ID/name format"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Image not found"
// @Failure 409 {object} models.ErrorResponse "Conflict (e.g., image is in use by a container)"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /images/{id} [delete] // Corrected path parameter syntax
func (ctrl *Controller) Remove(c *gin.Context) {
	imageID := c.Param("id")
	if imageID == "" {
		utils.BadRequest(c, "Image ID or Name:Tag is required")
		return
	}
	if len(imageID) > 0 && imageID[0] == '/' {
		imageID = imageID[1:]
	}

	force, _ := strconv.ParseBool(c.DefaultQuery("force", "false"))
	noPrune, _ := strconv.ParseBool(c.DefaultQuery("noprune", "false"))

	if !ctrl.hasImagePermission(c, imageID) {
		return
	}

	// Use the SDK type directly
	removeOptions := imagetypes.RemoveOptions{
		Force:         force,
		PruneChildren: !noPrune, // Note: SDK uses PruneChildren, maps correctly
	}
	deletedItems, err := ctrl.imageService.ImageRemove(c.Request.Context(), imageID, removeOptions) // Pass SDK options type
	if err != nil {
		ctrl.logger.WithError(err).WithField("imageID", imageID).Error("Failed to remove image")
		utils.InternalServerError(c, "Failed to remove image: "+err.Error())
		return
	}

	// TODO: Remove image from database if it was managed

	utils.SuccessResponse(c, deletedItems)
}

// History godoc
// @Summary Get image history
// @Description Retrieves the history (layers) of an image. Handles names with slashes.
// @Tags Images
// @Produce json
// @Security BearerAuth
// @Param id path string true "Image ID or Name:Tag (URL encoded if contains slashes)"
// @Success 200 {object} models.SuccessResponse{data=[]models.ImageHistoryItem} "Successfully retrieved image history"
// @Failure 400 {object} models.ErrorResponse "Invalid image ID/name format"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Permission denied"
// @Failure 404 {object} models.ErrorResponse "Image not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /image-history/{id} [get]
func (ctrl *Controller) History(c *gin.Context) {
	// Extract ID from the wildcard parameter
	imageID := c.Param("id")
	// Remove the leading slash that Gin adds for wildcard routes
	if len(imageID) > 0 && imageID[0] == '/' {
		imageID = imageID[1:]
	}
	if imageID == "" {
		utils.BadRequest(c, "Image ID or Name:Tag is required")
		return
	}

	// Check permission
	if !ctrl.hasImagePermission(c, imageID) {
		return
	}

	history, err := ctrl.imageService.History(c.Request.Context(), imageID)
	if err != nil {
		ctrl.logger.WithError(err).WithField("imageID", imageID).Error("Failed to get image history")
		utils.InternalServerError(c, "Failed to get history for image "+imageID+": "+err.Error())
		return
	}

	responseItems := make([]models.ImageHistoryItem, len(history))
	for i, item := range history {
		responseItems[i] = models.ImageHistoryItem{
			ID:        item.ID,
			Created:   time.Unix(item.Created, 0),
			CreatedBy: item.CreatedBy,
			Size:      item.Size,
			SizeHuman: utils.FormatImageSize(item.Size),
			Comment:   item.Comment,
			Tags:      item.Tags,
		}
	}

	utils.SuccessResponse(c, responseItems)
}

// --- Helper Functions ---

// hasImagePermission checks if the user has permission to access/modify an image
func (ctrl *Controller) hasImagePermission(c *gin.Context, imageRef string) bool {
	userID, err := middleware.GetUserID(c)
	if err != nil {
		utils.Unauthorized(c, "Authentication required")
		return false
	}

	isAdmin, _ := middleware.IsAdmin(c)
	if isAdmin {
		return true
	}

	imgInspect, err := ctrl.imageService.Inspect(c.Request.Context(), imageRef)
	if err != nil {
		if errors.Is(err, image.ErrImageNotFound) {
			utils.NotFound(c, "Image not found")
		} else {
			ctrl.logger.WithError(err).WithField("imageRef", imageRef).Error("Error inspecting image for permission check")
			utils.InternalServerError(c, "Failed to check image permissions")
		}
		return false
	}

	dbImage, err := ctrl.imageRepo.FindByImageID(c.Request.Context(), imgInspect.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.Forbidden(c, "You do not have permission to access this unmanaged image")
			return false
		}
		ctrl.logger.WithError(err).WithField("imageID", imgInspect.ID).Error("Error checking image permission in database")
		utils.InternalServerError(c, "Failed to check image permissions")
		return false
	}

	if dbImage.UserID != userID {
		utils.Forbidden(c, "You do not own this image")
		return false
	}

	return true
}

// isAdmin checks if the current user has the admin role
func isAdmin(c *gin.Context) bool {
	roles, err := middleware.GetUserRoles(c)
	if err != nil {
		return false
	}
	for _, role := range roles {
		if role == string(models.RoleAdmin) {
			return true
		}
	}
	return false
}

// parseDockerTime parses the time string returned by Docker API
func parseDockerTime(timeStr string, logger *logrus.Logger) time.Time {
	t, err := time.Parse(time.RFC3339Nano, timeStr)
	if err != nil {
		t, err = time.Parse(time.RFC3339, timeStr)
		if err != nil {
			logger.WithError(err).WithField("timeStr", timeStr).Warn("Failed to parse Docker time string")
			return time.Time{}
		}
	}
	return t
}

// isAllowedRegistry checks if a registry is allowed for non-admin users
func isAllowedRegistry(registry string) bool {
	// TODO: Implement actual logic based on configuration or policy
	return true
}

// Helper function to check if an image contains a search term
func containsSearchTerm(image models.ImageResponse, search string) bool {
	search = strings.ToLower(search)
	if image.ID > 0 && strings.Contains(strconv.FormatUint(uint64(image.ID), 10), search) {
		return true
	}
	if strings.Contains(strings.ToLower(image.ImageID), search) {
		return true
	}
	if strings.Contains(strings.ToLower(image.Name), search) {
		return true
	}
	if strings.Contains(strings.ToLower(image.Repository), search) {
		return true
	}
	if strings.Contains(strings.ToLower(image.Tag), search) {
		return true
	}
	for key, value := range image.Labels {
		if strings.Contains(strings.ToLower(key), search) || strings.Contains(strings.ToLower(value), search) {
			return true
		}
	}
	if strings.Contains(strings.ToLower(image.Notes), search) {
		return true
	}
	return false
}

// Helper function to check if an image has a specific tag
func hasTag(image models.ImageResponse, tag string) bool {
	return image.Tag == tag
}

// Helper function to check if an image belongs to a specific repository
func hasRepository(image models.ImageResponse, repo string) bool {
	return image.Repository == repo
}

// sortImages sorts images based on the specified field and order
func sortImages(images []models.ImageResponse, sortField, sortOrder string) []models.ImageResponse {
	result := make([]models.ImageResponse, len(images))
	copy(result, images)

	lessFunc := func(i, j int) bool {
		var less bool
		switch sortField {
		case "created":
			less = result[i].Created.Before(result[j].Created)
		case "size":
			less = result[i].Size < result[j].Size
		case "id":
			if result[i].ID != 0 && result[j].ID != 0 {
				less = result[i].ID < result[j].ID
			} else {
				less = result[i].ImageID < result[j].ImageID
			}
		case "name":
			nameI := result[i].Repository
			if result[i].Tag != "" {
				nameI += ":" + result[i].Tag
			}
			nameJ := result[j].Repository
			if result[j].Tag != "" {
				nameJ += ":" + result[j].Tag
			}
			less = nameI < nameJ
		default:
			less = result[i].Created.Before(result[j].Created)
		}
		if sortOrder == "desc" {
			return !less
		}
		return less
	}
	sort.SliceStable(result, lessFunc)
	return result
}
