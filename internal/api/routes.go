package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "github.com/threatflux/dockerServerMangerGoMCP/docs" // Import generated docs
)

// registerRoutes registers all API routes
func (s *Server) RegisterRoutes() error { // Make public
	router := s.router
	authMW := s.authMW

	s.logger.Info("Registering API routes...")
	s.logger.Debugf("Router instance before registration: %p", s.router)

	// Define API version prefix
	apiV1 := router.Group("/api/v1")

	// Health check - no auth required
	apiV1.GET("/health", s.healthCheck)
	apiV1.HEAD("/health", s.healthCheck) // Explicitly handle HEAD requests

	// Authentication routes - no auth required
	auth := apiV1.Group("/auth")
	{
		auth.POST("/login", s.authController.Login)                                   // Point to AuthController.Login
		auth.POST("/register", s.authController.Register)                             // Point to AuthController.Register
		auth.POST("/refresh", s.authController.Refresh)                               // Point to AuthController.Refresh
		auth.POST("/logout", authMW.RequireAuthentication(), s.authController.Logout) // Point to AuthController.Logout
	}

	// User routes - authenticated
	user := apiV1.Group("/user", authMW.RequireAuthentication())
	{
		user.GET("/me", s.authController.GetCurrentUser)       // Point to AuthController.GetCurrentUser
		user.PUT("/me", s.authController.UpdateCurrentUser)    // Point to AuthController.UpdateCurrentUser
		user.PUT("/password", s.authController.ChangePassword) // Point to AuthController.ChangePassword
	}

	// Admin routes - admin only
	admin := apiV1.Group("/admin", authMW.RequireAuthentication(), authMW.RequireAdmin())
	{
		admin.GET("/users", s.authController.ListUsers)         // Correct controller
		admin.GET("/users/:id", s.authController.GetUserByID)   // Correct controller
		admin.POST("/users", s.authController.CreateUser)       // Point to AuthController.CreateUser
		admin.PUT("/users/:id", s.authController.UpdateUser)    // Point to AuthController.UpdateUser
		admin.DELETE("/users/:id", s.authController.DeleteUser) // Point to AuthController.DeleteUser
	}

	// Container routes - authenticated
	containers := apiV1.Group("/containers", authMW.RequireAuthentication())
	{
		containers.GET("", s.containerController.ListContainers)   // Use ListContainers handler
		containers.GET("/:id", s.containerController.GetContainer) // Use GetContainer handler
		containers.POST("", s.containerController.Create)          // Point to Create handler
		containers.DELETE("/:id", s.containerController.Remove)    // Assuming Remove exists

		// Container operations
		containers.POST("/:id/start", s.containerController.Start)     // Point to Start handler
		containers.POST("/:id/stop", s.containerController.Stop)       // Point to Stop handler
		containers.POST("/:id/restart", s.containerController.Restart) // Point to Restart handler
		containers.POST("/:id/pause", s.containerController.Pause)     // Point to Pause handler
		containers.POST("/:id/unpause", s.containerController.Unpause) // Point to Unpause handler
		containers.POST("/:id/rename", s.containerController.Rename)   // Point to Rename handler

		// Container information
		containers.GET("/:id/logs", s.containerController.Logs)       // Point to Logs handler
		containers.GET("/:id/stats", s.containerController.Stats)     // Point to Stats handler
		containers.GET("/:id/top", s.containerController.Top)         // Point to Top handler
		containers.GET("/:id/changes", s.containerController.Changes) // Point to Changes handler

		// Container exec
		containers.POST("/:id/exec", s.containerController.Exec) // Point to Exec handler

		// Container files
		containers.GET("/:id/files", s.containerController.GetFiles)  // Point to GetFiles handler
		containers.POST("/:id/files", s.containerController.PutFiles) // Point to PutFiles handler
	}

	// Image routes - authenticated
	// Delegate image routes to the image controller
	s.imageController.RegisterRoutes(apiV1, authMW) // Use imageController

	// Volume routes - authenticated
	// Delegate volume routes to the volume controller
	s.volumeController.RegisterRoutes(apiV1, authMW) // Use volumeController

	// Network routes - authenticated
	// Delegate network routes to the network controller
	s.networkController.RegisterRoutes(apiV1, authMW) // Use networkController

	// Compose routes - authenticated
	compose := apiV1.Group("/compose", authMW.RequireAuthentication())
	{
		compose.GET("", s.composeController.ListDeployments)      // Point to controller
		compose.GET("/:id", s.composeController.GetDeployment)    // Point to controller
		compose.POST("/validate", s.composeController.Validate)   // Point to controller
		compose.POST("/up", s.composeController.Up)               // Point to controller
		compose.POST("/:id/down", s.composeController.Down)       // Point to controller
		compose.POST("/:id/start", s.composeController.Start)     // Point to controller
		compose.POST("/:id/stop", s.composeController.Stop)       // Point to controller
		compose.POST("/:id/restart", s.composeController.Restart) // Point to controller
		compose.POST("/:id/scale", s.composeController.Scale)     // Implement scale handler
	}

	// System routes - authenticated, some admin-only
	system := apiV1.Group("/system", authMW.RequireAuthentication())
	{
		system.GET("/info", s.systemInfo)     // Use systemInfo handler
		system.GET("/ping", s.systemPing)     // Use systemPing handler
		system.GET("/events", s.systemEvents) // Use systemEvents handler

		// Admin-only operations
		systemAdmin := system.Group("", authMW.RequireAdmin())
		{
			systemAdmin.POST("/prune", s.systemPrune) // Use systemPrune handler
		}
	}

	// API documentation
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler,
		ginSwagger.URL("/swagger/doc.json"),     // Point to the generated spec
		ginSwagger.DocExpansion("list"),         // Collapse endpoints by default
		ginSwagger.DeepLinking(true),            // Enable deep linking
		ginSwagger.DefaultModelsExpandDepth(-1), // Hide models by default
		ginSwagger.PersistAuthorization(true),
	))

	// Static files for web UI
	router.StaticFile("/", "./public/index.html")
	router.Static("/static", "./public/static")

	// 404 handler for all other routes
	router.NoRoute(s.handleNotFound)
	s.logger.Debugf("Router instance after registration: %p", s.router)
	s.logger.Info("API routes registered successfully.")

	return nil
}

// healthCheck handles the health check endpoint
// @Summary      Health Check
// @Description  Checks the health status of the API server, providing basic information like version and environment.
// @Tags         System
// @Produce      json
// @Success      200  {object}  map[string]interface{}  "Server status information"
// @Router       /api/v1/health [get]
// @Router       /api/v1/health [head]
func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"time":     time.Now(),
		"version":  s.config.Version,     // Use top-level Version
		"env":      s.config.Server.Mode, // Use Server.Mode for environment
		"serverID": s.config.ServerID,    // Use top-level ServerID
		"apiV1":    "/api/v1",
		"docs":     "/swagger/index.html",
	})
}

// Handle auth not implemented endpoints
func (s *Server) handleAuthNotImplemented(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "This authentication endpoint is not yet implemented",
		"path":  c.Request.URL.Path,
		"time":  time.Now(),
	})
}

// Handle 404 Not Found
func (s *Server) handleNotFound(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{
		"error": "Route not found",
		"path":  c.Request.URL.Path,
		"time":  time.Now(),
	})
}

// getCurrentUser extracts the current user from the context
func getCurrentUser(c *gin.Context) (*models.User, bool) {
	user, exists := c.Get("currentUser")
	if !exists {
		return nil, false
	}

	typedUser, ok := user.(*models.User)
	if !ok {
		return nil, false
	}

	return typedUser, true
}
