package container

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/container"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
)

// Controller handles container-related API requests
type Controller struct {
	containerService container.Service
	dockerManager    docker.Manager // Changed from dockerClient
	logger           *logrus.Logger
	// containerRepo    repositories.ContainerRepository // Removed repository dependency
}

// NewController creates a new container controller
func NewController(
	containerService container.Service,
	dockerManager docker.Manager, // Changed from dockerClient
	logger *logrus.Logger,
	// containerRepo repositories.ContainerRepository, // Removed repository dependency
) *Controller {
	return &Controller{
		containerService: containerService,
		dockerManager:    dockerManager, // Changed from dockerClient
		logger:           logger,
		// containerRepo:    containerRepo, // Removed repository dependency
	}
}

// RegisterRoutes registers the container API routes
func (ctrl *Controller) RegisterRoutes(router *gin.RouterGroup, authMW *middleware.AuthMiddleware) {
	containers := router.Group("/containers")

	// Require authentication for all routes
	containers.Use(authMW.RequireAuthentication())

	// Container listing and details
	containers.GET("", ctrl.ListContainers)   // Changed from ctrl.List
	containers.GET("/:id", ctrl.GetContainer) // Changed from ctrl.Get

	// Container lifecycle management
	containers.POST("", ctrl.Create)
	containers.DELETE("/:id", ctrl.Remove)
	containers.POST("/:id/start", ctrl.Start)
	containers.POST("/:id/stop", ctrl.Stop)
	containers.POST("/:id/restart", ctrl.Restart)
	containers.POST("/:id/pause", ctrl.Pause)
	containers.POST("/:id/unpause", ctrl.Unpause)
	containers.POST("/:id/rename", ctrl.Rename)

	// Container information
	containers.GET("/:id/logs", ctrl.Logs)
	containers.GET("/:id/stats", ctrl.Stats)
	containers.GET("/:id/top", ctrl.Top)
	containers.GET("/:id/changes", ctrl.Changes)

	// Container exec
	containers.POST("/:id/exec", ctrl.Exec)

	// Container files
	containers.GET("/:id/files", ctrl.GetFiles)
	containers.POST("/:id/files", ctrl.PutFiles)
}
