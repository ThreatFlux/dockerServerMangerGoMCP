package api

import (
	"context"
	"encoding/json" // Added for systemEvents
	"errors"
	"fmt"
	"io" // Added for systemEvents
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"         // Added back for BuildCachePruneOptions, Info, Ping
	"github.com/docker/docker/api/types/events"  // Added for systemEvents
	"github.com/docker/docker/api/types/filters" // Added for systemEvents/Prune
	// "github.com/docker_test/docker_test/api/types/image"   // Removed unused import
	"github.com/gin-contrib/sse" // Added for systemEvents
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	apiCompose "github.com/threatflux/dockerServerMangerGoMCP/internal/api/compose"     // Added import for compose controller
	apiContainer "github.com/threatflux/dockerServerMangerGoMCP/internal/api/container" // Added import
	apiImage "github.com/threatflux/dockerServerMangerGoMCP/internal/api/image"         // Added import
	apiNetwork "github.com/threatflux/dockerServerMangerGoMCP/internal/api/network"     // Added import for network controller
	apiVolume "github.com/threatflux/dockerServerMangerGoMCP/internal/api/volume"       // Added import for volume controller
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	dockerCompose "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/compose"                          // Corrected import for compose parser package
	dockerComposeOrchestrator "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/compose/orchestrator" // Corrected import for compose orchestrator package
	dockerComposeStatus "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/compose/status"             // Corrected import for compose status package
	dockerImage "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/image"                              // Added import for image service
	dockerNetwork "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/network"                          // Added import for network service
	dockerVolume "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/volume"                            // Added import for volume service
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/api" // Cannot import self, use relative types
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database/repositories" // Added import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"
	dockerContainer "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/container" // Added import for container service
	"github.com/threatflux/dockerServerMangerGoMCP/internal/interfaces"                       // Re-added import for interfaces
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Added for SystemPruneRequest
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"  // Added for utils.BadRequest etc.
)

// Server represents the API server
type Server struct {
	router        *gin.Engine
	httpServer    *http.Server
	config        *config.Config
	logger        *logrus.Logger
	db            database.Database // Use Database interface
	authService   auth.Service
	dockerManager docker.Manager // Changed from dockerClient
	authMW        *middleware.AuthMiddleware
	shutdownWg    sync.WaitGroup
	shutdownCh    chan os.Signal

	// API Controllers
	authController      *AuthController
	containerController *apiContainer.Controller // Use alias
	imageController     *apiImage.Controller     // Use alias
	volumeController    *apiVolume.Controller    // Use alias
	networkController   *apiNetwork.Controller   // Use alias
	composeController   *apiCompose.Controller   // Added compose controller
}

// ServerConfig contains the configuration for the API server
type ServerConfig struct {
	Config        *config.Config
	Logger        *logrus.Logger
	DB            database.Database // Use Database interface
	AuthService   auth.Service
	DockerManager docker.Manager // Changed from DockerClient
}

// NewServer creates a new API server
func NewServer(cfg *ServerConfig) (*Server, error) {
	if cfg.Config == nil {
		return nil, errors.New("config is required")
	}
	if cfg.Logger == nil {
		return nil, errors.New("logger is required")
	}
	if cfg.DB == nil {
		return nil, errors.New("database is required")
	}
	if cfg.AuthService == nil {
		return nil, errors.New("auth service is required")
	}
	if cfg.DockerManager == nil { // Use DockerManager
		return nil, errors.New("docker_test manager is required")
	}

	// Create server instance
	server := &Server{
		config:        cfg.Config,
		logger:        cfg.Logger,
		db:            cfg.DB,
		authService:   cfg.AuthService,
		dockerManager: cfg.DockerManager, // Use DockerManager
		authMW:        middleware.NewAuthMiddleware(cfg.AuthService),
		shutdownCh:    make(chan os.Signal, 1),
	}

	// Initialize Repositories (assuming they are needed by controllers)
	userRepo := repositories.NewUserRepository(cfg.DB.DB())           // Corrected constructor name
	imageRepo := repositories.NewGormImageRepository(cfg.DB.DB())     // Initialize Image Repository
	volumeRepo := repositories.NewGormVolumeRepository(cfg.DB.DB())   // Initialize Volume Repository
	networkRepo := repositories.NewGormNetworkRepository(cfg.DB.DB()) // Initialize Network Repository

	// Initialize Services
	containerSvc := dockerContainer.NewService(cfg.DockerManager, cfg.Logger) // Use imported package
	imageSvc := dockerImage.NewService(cfg.DockerManager, cfg.Logger)         // Initialize Image Service using dockerImage package
	volumeSvc := dockerVolume.NewService(cfg.DockerManager, cfg.Logger)       // Initialize Volume Service
	networkSvc := dockerNetwork.NewService(cfg.DockerManager, cfg.Logger)     // Initialize Network Service

	// Initialize Controllers
	server.authController = NewAuthController( // Use relative NewAuthController
		cfg.AuthService,
		userRepo,
		cfg.Logger,
		cfg.Config.Auth.AccessTokenTTL,  // Pass TTLs from config
		cfg.Config.Auth.RefreshTokenTTL, // Pass TTLs from config
	)

	// Initialize Container Controller
	server.containerController = apiContainer.NewController(
		containerSvc,
		// nil, // Pass containerRepo if/when created
		cfg.DockerManager, // Pass DockerManager
		cfg.Logger,
	)
	// Initialize Image Controller
	server.imageController = apiImage.NewController(
		imageSvc,
		imageRepo,
		cfg.DockerManager,
		cfg.Logger,
	)

	// Initialize Volume Controller
	server.volumeController = apiVolume.NewController(
		volumeSvc,
		volumeRepo,
		cfg.Logger,
	)

	// Initialize Network Controller
	server.networkController = apiNetwork.NewController(
		networkSvc,
		networkRepo,
		cfg.Logger,
	)

	// Initialize Compose Services & Controller
	// Initialize Compose Status Tracker and Orchestrator first
	trackerOpts := dockerComposeStatus.TrackerOptions{
		Logger: cfg.Logger,
		// EventsCh: // TODO: Wire up event stream if needed
		// ErrorsCh: // TODO: Wire up event stream if needed
	}
	var composeStatusTrackerSvc interfaces.ComposeStatusTracker = dockerComposeStatus.NewTracker(trackerOpts)

	orchestratorOpts := dockerComposeOrchestrator.OrchestratorOptions{
		NetworkService:  networkSvc,
		VolumeService:   volumeSvc,
		StatusTracker:   composeStatusTrackerSvc, // Pass the interface
		Logger:          cfg.Logger,
		ContainerClient: containerSvc,
		ImageClient:     imageSvc,
		// DefaultTimeout: // Set if needed
	}
	var composeOrchestratorSvc interfaces.ComposeOrchestrator = dockerComposeOrchestrator.NewOrchestrator(orchestratorOpts)

	// Initialize Compose Service (which includes the parser internally)
	composeServiceOpts := dockerCompose.ComposeServiceOptions{
		Orchestrator:   composeOrchestratorSvc,
		NetworkService: networkSvc,
		VolumeService:  volumeSvc,
		Logger:         cfg.Logger,
		StatusTracker:  composeStatusTrackerSvc,
		// DockerClient is not directly needed if Orchestrator handles it via Container/Image clients
	}
	composeService, err := dockerCompose.NewComposeService(composeServiceOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create compose service: %w", err)
	}
	// No need for composeParserSvc anymore, composeService implements the interface
	// Removed duplicated declarations
	server.composeController = apiCompose.NewController(
		composeService,          // Pass the instantiated ComposeService
		composeOrchestratorSvc,  // Pass the instantiated Orchestrator
		composeStatusTrackerSvc, // Pass the instantiated StatusTracker
		cfg.Logger,
	)

	// TODO: Initialize system controller here

	// Set Gin mode based on environment
	if server.config.Server.Mode == "production" { // Use Server.Mode
		gin.SetMode(gin.ReleaseMode)
	} else if server.config.Server.Mode == "test" { // Use Server.Mode
		gin.SetMode(gin.TestMode)
	} else {
		gin.SetMode(gin.DebugMode) // Default to DebugMode
	}

	// Create router
	router := gin.New()

	// Apply middlewares
	router.Use(middleware.RequestIDMiddleware())

	// Create middleware instances
	loggingMW := middleware.NewLoggingMiddleware(server.logger)   // Create instance
	recoveryMW := middleware.NewRecoveryMiddleware(server.logger) // Create instance

	// Use the handler functions returned by methods
	router.Use(loggingMW.Logger())
	router.Use(recoveryMW.Recovery())

	// Configure CORS - Commented out as config and middleware are undefined
	// corsConfig := server.config.CORS
	// if corsConfig != nil {
	// 	router.Use(middleware.CORSMiddleware(
	// 		corsConfig.AllowOrigins,
	// 		corsConfig.AllowMethods,
	// 		corsConfig.AllowHeaders,
	// 		corsConfig.MaxAge,
	// 	))
	// }

	server.router = router

	// Configure HTTP server
	server.httpServer = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", server.config.Server.Host, server.config.Server.Port),
		Handler: server.router,
		// Set reasonable timeouts
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return server, nil
}

// Start starts the API server
func (s *Server) Start() error {
	// Register all routes
	if err := s.RegisterRoutes(); err != nil { // Call public method
		return fmt.Errorf("failed to register routes: %w", err)
	}

	// Capture shutdown signals
	signal.Notify(s.shutdownCh, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		s.logger.WithField("address", s.httpServer.Addr).Info("Starting API server")
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.WithError(err).Error("API server error")
		}
	}()

	// Wait for shutdown signal
	go func() {
		<-s.shutdownCh
		s.logger.Info("Shutdown signal received")
		s.Shutdown()
	}()

	return nil
}

// StartTLS starts the API server with TLS enabled
func (s *Server) StartTLS() error {
	// Register all routes
	if err := s.RegisterRoutes(); err != nil { // Call public method
		return fmt.Errorf("failed to register routes: %w", err)
	}

	// Validate TLS configuration
	if !s.config.Server.TLS.Enabled { // Check if TLS is enabled first
		return errors.New("TLS is not enabled in configuration")
	}
	// Access TLS fields directly from s.config.Server.TLS
	if s.config.Server.TLS.CertFile == "" {
		return errors.New("TLS certificate file is required")
	}

	if s.config.Server.TLS.KeyFile == "" {
		return errors.New("TLS key file is required")
	}

	// Capture shutdown signals
	signal.Notify(s.shutdownCh, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		s.logger.WithField("address", s.httpServer.Addr).Info("Starting API server (TLS)")
		if err := s.httpServer.ListenAndServeTLS(
			s.config.Server.TLS.CertFile, // Use s.config.Server.TLS
			s.config.Server.TLS.KeyFile,  // Use s.config.Server.TLS
		); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.WithError(err).Error("API server error")
		}
	}()

	// Wait for shutdown signal
	go func() {
		<-s.shutdownCh
		s.logger.Info("Shutdown signal received")
		s.Shutdown()
	}()

	return nil
}

// Shutdown gracefully shuts down the API server
func (s *Server) Shutdown() {
	s.logger.Info("Shutting down API server...")

	// Create a context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown the HTTP server
	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.logger.WithError(err).Error("Error during server shutdown")
	}

	// Close the Docker client connection
	if err := s.dockerManager.Close(); err != nil { // Use dockerManager
		s.logger.WithError(err).Error("Error closing Docker client")
	}

	// Close the database connection
	if err := s.db.Close(); err != nil {
		s.logger.WithError(err).Error("Error closing database connection")
	}

	// Wait for any ongoing operations to complete
	s.shutdownWg.Wait()

	s.logger.Info("API server shutdown complete")
}

// Router returns the Gin router instance
func (s *Server) Router() *gin.Engine {
	return s.router
}

// IncrementWaitGroup increments the shutdown wait group
// Used to track ongoing operations during shutdown
func (s *Server) IncrementWaitGroup() {
	s.shutdownWg.Add(1)
}

// DecrementWaitGroup decrements the shutdown wait group
// Called when an operation is complete
func (s *Server) DecrementWaitGroup() {
	s.shutdownWg.Done()
}

// GetAuthMiddleware returns the authentication middleware
func (s *Server) GetAuthMiddleware() *middleware.AuthMiddleware {
	return s.authMW
}

// GetDockerManager returns the Docker manager
func (s *Server) GetDockerManager() docker.Manager { // Changed name and return type
	return s.dockerManager // Use dockerManager
}

// GetDB returns the database instance
func (s *Server) GetDB() database.Database { // Use Database interface
	return s.db
}

// GetAuthService returns the authentication service
func (s *Server) GetAuthService() auth.Service {
	return s.authService
}

// GetLogger returns the logger instance
func (s *Server) GetLogger() *logrus.Logger {
	return s.logger
}

// GetConfig returns the configuration
func (s *Server) GetConfig() *config.Config {
	return s.config
}

// --- System Handlers ---

// systemInfo godoc
// @Summary Get Docker system information
// @Description Retrieves detailed information about the Docker host system.
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SuccessResponse{data=models.SystemInfoResponse} "Successfully retrieved system info" // Use local model
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 500 {object} models.ErrorResponse "Internal server error (e.g., Docker daemon error)"
// @Router /system/info [get]
func (s *Server) systemInfo(c *gin.Context) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		utils.InternalServerError(c, "Failed to get Docker client: "+err.Error())
		return
	}

	info, err := cli.Info(c.Request.Context())
	if err != nil {
		s.logger.WithError(err).Error("Failed to get Docker system info")
		utils.InternalServerError(c, "Failed to get system info: "+err.Error())
		return
	}

	// TODO: Convert types.Info to models.SystemInfoResponse if needed for consistency or modification
	// For now, return the raw Docker info directly within our standard response structure.
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    info,
	})
}

// systemPing godoc
// @Summary Ping Docker daemon
// @Description Pings the Docker daemon to check connectivity and API version compatibility.
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SuccessResponse{data=models.PingResponse} "Successfully pinged Docker daemon" // Use local model
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 500 {object} models.ErrorResponse "Internal server error (e.g., Docker daemon error)"
// @Router /system/ping [get]
func (s *Server) systemPing(c *gin.Context) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		utils.InternalServerError(c, "Failed to get Docker client: "+err.Error())
		return
	}

	ping, err := cli.Ping(c.Request.Context())
	if err != nil {
		s.logger.WithError(err).Error("Failed to ping Docker daemon")
		utils.InternalServerError(c, "Failed to ping Docker daemon: "+err.Error())
		return
	}

	// Add SwarmStatus from headers if available (might need adjustment based on client version)
	// ping.SwarmStatus = ...

	// Convert types.Ping to models.PingResponse
	pingResponse := models.PingResponse{
		APIVersion:     ping.APIVersion,
		OSType:         ping.OSType,
		Experimental:   ping.Experimental,
		BuilderVersion: string(ping.BuilderVersion), // Convert BuilderVersion type
	}

	// Use standard Gin JSON response
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    pingResponse, // Return local model
	})
}

// systemEvents godoc
// @Summary Stream Docker system events
// @Description Streams real-time events from the Docker daemon using Server-Sent Events (SSE).
// @Tags System
// @Produce text/event-stream
// @Security BearerAuth
// @Param since query string false "Show events since timestamp (e.g., 2013-01-02T13:23:37Z) or relative (e.g., 42m)" example(1h)
// @Param until query string false "Show events until timestamp (e.g., 2013-01-02T13:23:37Z) or relative (e.g., 42m)" example(2023-10-27T12:00:00Z)
// @Param filters query string false "JSON encoded map[string][]string for filtering (e.g. {\"type\":[\"container\"],\"event\":[\"start\"]})" example({\"type\":[\"container\"],\"event\":[\"start\",\"stop\"]})
// @Success 200 {string} string "SSE stream of Docker events"
// @Failure 400 {object} models.ErrorResponse "Invalid filter format"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /system/events [get]
func (s *Server) systemEvents(c *gin.Context) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		utils.InternalServerError(c, "Failed to get Docker client: "+err.Error())
		return
	}

	// TODO: Add support for filtering events via query parameters (since, until, filters)
	eventFilters := filters.NewArgs()
	// Example: eventFilters.Add("type", "container")

	messages, errs := cli.Events(c.Request.Context(), events.ListOptions{Filters: eventFilters})

	// Use Server-Sent Events (SSE)
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*") // Adjust CORS as needed

	streamClosed := c.Stream(func(w io.Writer) bool {
		select {
		case msg, ok := <-messages:
			if !ok {
				s.logger.Info("Docker event stream closed")
				return false // Close the stream
			}
			// Marshal the event message to JSON
			jsonData, err := json.Marshal(msg)
			if err != nil {
				s.logger.WithError(err).Error("Failed to marshal Docker event to JSON")
				// Decide whether to close stream or just log
				return true // Continue stream for now
			}
			// Send event using SSE format
			sse.Encode(w, sse.Event{
				Event: string(msg.Type), // Use event type as SSE event name
				Data:  string(jsonData),
				Id:    fmt.Sprintf("%s-%d", msg.ID, msg.TimeNano), // Create a unique ID
			})
			return true // Keep stream open
		case err, ok := <-errs:
			if !ok {
				s.logger.Info("Docker event error channel closed")
				return false // Close the stream
			}
			if err != nil {
				s.logger.WithError(err).Error("Error received from Docker event stream")
				// Optionally send an error event to the client
				sse.Encode(w, sse.Event{
					Event: "error",
					Data:  fmt.Sprintf(`{"error": "%s"}`, err.Error()),
				})
				return false // Close the stream on error
			}
			return true // Keep stream open if err is nil but channel is still open
		case <-c.Request.Context().Done():
			s.logger.Info("Client disconnected from event stream")
			return false // Close the stream
		}
	})

	if streamClosed {
		s.logger.Info("SSE stream to client closed")
	}
}

// systemPrune godoc
// @Summary Prune unused Docker resources
// @Description Removes unused containers, networks, images, and build cache.
// @Tags System
// @Produce json
// @Security BearerAuth
// @Param body body models.SystemPruneRequest true "Prune options"
// @Success 200 {object} models.SuccessResponse{data=models.SystemPruneResponse} "Successfully pruned resources"
// @Failure 400 {object} models.ErrorResponse "Invalid request body"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /system/prune [post]
func (s *Server) systemPrune(c *gin.Context) {
	var req models.SystemPruneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid request body: "+err.Error())
		return
	}

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		utils.InternalServerError(c, "Failed to get Docker client: "+err.Error())
		return
	}

	ctx := c.Request.Context()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var pruneResponse models.SystemPruneResponse
	var errors []string

	// Convert request filters (map[string]string) to Docker API filters (map[string][]string)
	pruneFilters := filters.NewArgs()
	for k, v := range req.Filters {
		// Assuming filters are provided as comma-separated strings if multiple values are needed
		// Adjust parsing if a different format is expected (e.g., JSON array string)
		pruneFilters.Add(k, v)
	}

	if req.Containers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			report, err := cli.ContainersPrune(ctx, pruneFilters) // Use converted filters
			mu.Lock()
			if err != nil {
				errors = append(errors, fmt.Sprintf("container prune failed: %v", err))
			} else {
				pruneResponse.ContainersDeleted = report.ContainersDeleted
				pruneResponse.SpaceReclaimed += int64(report.SpaceReclaimed) // Cast uint64
			}
			mu.Unlock()
		}()
	}

	if req.Images {
		wg.Add(1)
		go func() {
			defer wg.Done()
			report, err := cli.ImagesPrune(ctx, pruneFilters) // Use converted filters
			mu.Lock()
			if err != nil {
				errors = append(errors, fmt.Sprintf("image prune failed: %v", err))
			} else {
				pruneResponse.ImagesDeleted = make([]models.ImageDeleteResponseItem, len(report.ImagesDeleted))
				for i, item := range report.ImagesDeleted {
					pruneResponse.ImagesDeleted[i] = models.ImageDeleteResponseItem{
						Untagged: item.Untagged,
						Deleted:  item.Deleted,
					}
				}
				pruneResponse.SpaceReclaimed += int64(report.SpaceReclaimed) // Cast uint64
			}
			mu.Unlock()
		}()
	}

	if req.Networks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			report, err := cli.NetworksPrune(ctx, pruneFilters) // Use converted filters
			mu.Lock()
			if err != nil {
				errors = append(errors, fmt.Sprintf("network prune failed: %v", err))
			} else {
				pruneResponse.NetworksDeleted = report.NetworksDeleted
			}
			mu.Unlock()
		}()
	}

	if req.Volumes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			report, err := cli.VolumesPrune(ctx, pruneFilters) // Use converted filters
			mu.Lock()
			if err != nil {
				errors = append(errors, fmt.Sprintf("volume prune failed: %v", err))
			} else {
				pruneResponse.VolumesDeleted = report.VolumesDeleted
				pruneResponse.SpaceReclaimed += int64(report.SpaceReclaimed) // Cast uint64
			}
			mu.Unlock()
		}()
	}

	if req.BuildCache {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Note: BuildCachePruneOptions needs to be constructed if filters are needed
			// For now, using default options.
			report, err := cli.BuildCachePrune(ctx, types.BuildCachePruneOptions{}) // Use types.BuildCachePruneOptions
			mu.Lock()
			if err != nil {
				errors = append(errors, fmt.Sprintf("build cache prune failed: %v", err))
			} else {
				// The BuildCachePruneReport doesn't list deleted items, only total count and space.
				// We can't populate pruneResponse.BuildCacheDeleted directly from the report.
				// If needed, list cache before/after, but for now, just add space reclaimed.
				pruneResponse.SpaceReclaimed += int64(report.SpaceReclaimed) // Cast uint64
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	if len(errors) > 0 {
		utils.InternalServerError(c, fmt.Sprintf("Prune operation failed with errors: %v", errors))
		return
	}

	utils.SuccessResponse(c, pruneResponse)
}

// --- Other Handlers ---
// Removed duplicate handlers: healthCheck, handleNotImplemented, handleAuthNotImplemented, handleNotFound
// Removed duplicate helper: getCurrentUser

// --- Swagger Handler ---
// // swaggerHandler serves the Swagger UI or JSON spec
// // @Summary      Serve Swagger UI and Specification
// // @Description  Serves the Swagger UI interface and the OpenAPI specification file (swagger.json/swagger.yaml).
// // @Tags         Documentation
// // @Produce      html
// // @Produce      json
// // @Success      200  {string}  string  "Swagger UI or OpenAPI specification"
// // @Router       /swagger/{any} [get]
// func (s *Server) swaggerHandler(c *gin.Context) {
// 	// Basic implementation: Serve swagger.json
// 	// In a real app, you might use gin-swagger middleware
// 	// or serve embedded files.
// 	// c.File("./docs/swagger.json") // Commented out old implementation
// }
