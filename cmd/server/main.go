// @title Docker Server Manager Go MCP API
// @version 1.0
// @description This is the API documentation for the Docker Server Manager Go MCP.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /api/v1
// @schemes http https

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token. Example: "Bearer {token}"

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/api"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"
	"golang.org/x/crypto/bcrypt" // Added for password hashing cost
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Removed unused import
)

// Version information (will be set during build)
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

func main() {
	fmt.Printf("Docker Server Manager Go MCP %s (%s) built on %s\n", Version, Commit, BuildDate)

	// Initialize logger
	logger := initLogger()
	logger.WithFields(logrus.Fields{
		"version":    Version,
		"commit":     Commit,
		"build_date": BuildDate,
	}).Info("Starting Docker Server Manager Go MCP")

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}

	// Initialize database
	db, err := initDatabase(cfg, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize database")
	}

	// Initialize Docker client
	dockerClient, err := initDockerClient(cfg, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize Docker client")
	}

	// Initialize authentication service
	authService, err := initAuthService(cfg, db, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize authentication service")
	}

	// Initialize API server
	server, err := initAPIServer(cfg, logger, db, authService, dockerClient)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize API server")
	}

	// Start the server
	if cfg.Server.TLS.Enabled { // Access nested TLS struct
		logger.Info("Starting server with TLS enabled")
		if err := server.StartTLS(); err != nil {
			logger.WithError(err).Fatal("Failed to start API server with TLS")
		}
	} else {
		logger.Info("Starting server without TLS")
		if err := server.Start(); err != nil {
			logger.WithError(err).Fatal("Failed to start API server")
		}
	}

	// Setup graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	sig := <-quit
	logger.WithField("signal", sig.String()).Info("Shutdown signal received")

	// Shutdown server
	server.Shutdown()
	logger.Info("Server shutdown complete")
}

// initLogger initializes and configures the logger
func initLogger() *logrus.Logger {
	logger := logrus.New()

	// Configure logger
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		DisableSorting:  false,
	})

	// Set log level based on environment
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel != "" {
		level, err := logrus.ParseLevel(logLevel)
		if err != nil {
			logger.WithError(err).Warn("Invalid log level, defaulting to info")
			logger.SetLevel(logrus.InfoLevel)
		} else {
			logger.SetLevel(level)
		}
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	return logger
}

// initDatabase initializes and configures the database
func initDatabase(cfg *config.Config, logger *logrus.Logger) (database.Database, error) {
	logger.WithFields(logrus.Fields{
		"type": cfg.Database.Type,
		"host": cfg.Database.Host,
		"port": cfg.Database.Port,
		"name": cfg.Database.Name,
	}).Info("Initializing database connection")

	// Initialize database
	db, err := database.InitDatabase(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Run database migrations using the Migrator
	logger.Info("Running database migrations")
	migrator, err := database.NewMigrator(db.DB(), database.DefaultMigrateOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to create migrator: %w", err)
	}
	migrator.RegisterAllMigrations() // Register defined migrations
	if err := migrator.MigrateUp(); err != nil {
		return nil, fmt.Errorf("failed to run database migrations: %w", err)
	}

	return db, nil
}

// initDockerClient initializes and configures the Docker client manager
func initDockerClient(cfg *config.Config, logger *logrus.Logger) (docker.Manager, error) { // Return docker_test.Manager
	logger.WithFields(logrus.Fields{
		"host": cfg.Docker.Host,
	}).Info("Initializing Docker client manager") // Log manager init

	// Create Docker client options
	opts := []docker.ClientOption{
		docker.WithLogger(logger), // Start with logger
	}

	// Only set host if explicitly provided in config
	if cfg.Docker.Host != "" {
		opts = append(opts, docker.WithHost(cfg.Docker.Host))
	}

	// Configure TLS if enabled
	if cfg.Docker.TLSVerify {
		opts = append(opts,
			docker.WithTLSVerify(true),
			docker.WithTLSConfig(
				cfg.Docker.TLSCertPath,
				cfg.Docker.TLSKeyPath,
				cfg.Docker.TLSCAPath,
			),
		)
	}

	// Create Docker client manager
	manager, err := docker.NewManager(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client manager: %w", err)
	}

	// Test Docker connection by getting the client (assign to blank identifier)
	_, err = manager.GetClient() // Assign to _
	if err != nil {
		return nil, fmt.Errorf("failed to get Docker client: %w", err)
	}

	// Return the manager directly
	return manager, nil // Remove NewClient wrapper
}

// initAuthService initializes and configures the authentication service
func initAuthService(cfg *config.Config, db database.Database, logger *logrus.Logger) (auth.Service, error) {
	logger.Info("Initializing authentication service")

	// Create JWT Service config
	jwtConfig := auth.JWTConfig{
		AccessTokenSecret:  cfg.Auth.Secret,                        // Use the single secret
		RefreshTokenSecret: cfg.Auth.Secret,                        // Use the single secret (consider separate keys later)
		AccessTokenExpiry:  int(cfg.Auth.AccessTokenTTL.Minutes()), // Convert duration to int minutes
		RefreshTokenExpiry: int(cfg.Auth.RefreshTokenTTL.Hours()),  // Convert duration to int hours
		Issuer:             cfg.Auth.TokenIssuer,
		Audience:           []string{cfg.Auth.TokenAudience}, // Wrap audience in a slice
	}

	// Create token store
	tokenStore := auth.NewInMemoryTokenStore()

	// Create password service config
	passwordConfig := auth.PasswordConfig{
		MinLength: cfg.Auth.PasswordPolicy.MinLength,
		MaxLength: 72,                 // Set MaxLength (bcrypt limit)
		HashCost:  bcrypt.DefaultCost, // Or make this configurable in cfg.Auth?
	}

	// Create auth service
	authService := auth.NewService(
		db,             // Pass database.Database
		jwtConfig,      // Pass JWTConfig
		passwordConfig, // Pass PasswordConfig
		tokenStore,     // Pass TokenStore
		logger,         // Pass logger
	)

	return authService, nil
}

// initAPIServer initializes and configures the API server
func initAPIServer(cfg *config.Config, logger *logrus.Logger, db database.Database, authService auth.Service, dockerManager docker.Manager) (*api.Server, error) { // Use docker_test.Manager
	logger.WithFields(logrus.Fields{
		"host": cfg.Server.Host,
		"port": cfg.Server.Port,
	}).Info("Initializing API server")

	// Create server configuration
	serverConfig := &api.ServerConfig{
		Config:        cfg,
		Logger:        logger,
		DB:            db,
		AuthService:   authService,
		DockerManager: dockerManager, // Use DockerManager field and variable
	}

	// Create server
	server, err := api.NewServer(serverConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create API server: %w", err)
	}

	return server, nil
}
