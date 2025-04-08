// Package compose provides functionality for Docker Compose operations
package compose

import (
	"context"
	"errors"
	"fmt"
	"io"
	// "bytes" // Removed unused import
	// "io/ioutil" // Removed unused import
	// "os" // Removed unused import
	// "path/filepath" // Removed unused import
	// "strings" // Removed unused import
	"time"

	// "github.com/docker_test/docker_test/api/types" // Removed unused import
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/docker_test/compose/resources" // Removed unused import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/compose/status"
	networkSvc "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/network"
	volumeSvc "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/volume"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/docker_test/compose/orchestrator" // No longer needed here
	"github.com/threatflux/dockerServerMangerGoMCP/internal/interfaces"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// Service provides a high-level API for Docker Compose operations
type Service interface {
	// Parse parses a Docker Compose file
	Parse(ctx context.Context, reader io.Reader, options models.ParseOptions) (*models.ComposeFile, error) // Use models.ParseOptions

	// ParseFile is removed as loading from content is preferred
	// Validate is removed as validation is handled by compose-go loader

	// Up deploys a Docker Compose file
	Up(ctx context.Context, composeFile *models.ComposeFile, options models.DeployOptions) error // Use models options

	// Down removes a Docker Compose deployment
	Down(ctx context.Context, composeFile *models.ComposeFile, options models.RemoveOptions) error // Use models options

	// Start starts services in a Docker Compose deployment
	Start(ctx context.Context, composeFile *models.ComposeFile, options models.StartOptions) error // Use models options

	// Stop stops services in a Docker Compose deployment
	Stop(ctx context.Context, composeFile *models.ComposeFile, options models.StopOptions) error // Use models options

	// Restart restarts services in a Docker Compose deployment
	Restart(ctx context.Context, composeFile *models.ComposeFile, options models.RestartOptions) error // Use models options

	// Ps lists containers in a Docker Compose deployment
	Ps(ctx context.Context, composeFile *models.ComposeFile, options PsOptions) (*DeploymentStatus, error)

	// Logs gets logs from services in a Docker Compose deployment
	Logs(ctx context.Context, composeFile *models.ComposeFile, options LogOptions) (io.ReadCloser, error)

	// Events gets events from services in a Docker Compose deployment
	Events(ctx context.Context, composeFile *models.ComposeFile, options EventOptions) (<-chan DeploymentEvent, <-chan error)

	// Convert converts a Docker Compose file to Docker API objects
	Convert(ctx context.Context, composeFile *models.ComposeFile, options ConvertOptions) (*ConvertResult, error)
}

// --- Options Structs ---

// ParseOptions defines options for parsing a Docker Compose file
type ParseOptions struct {
	EnvFiles            []string
	Environment         map[string]string
	WorkingDir          string
	ResolveImageDigests bool
	Logger              *logrus.Logger
}

// PsOptions defines options for listing containers
type PsOptions struct {
	ProjectName string
	Services    []string
	All         bool
	Logger      *logrus.Logger
}

// LogOptions defines options for getting logs
type LogOptions struct {
	ProjectName string
	Services    []string
	Follow      bool
	Tail        int
	Since       time.Time
	Until       time.Time
	Timestamps  bool
	Logger      *logrus.Logger
}

// EventOptions defines options for getting events
type EventOptions struct {
	ProjectName string
	Services    []string
	Follow      bool
	Since       time.Time
	Until       time.Time
	Logger      *logrus.Logger
}

// ConvertOptions defines options for converting a Docker Compose file
type ConvertOptions struct {
	ProjectName string
	Format      string
	Logger      *logrus.Logger
}

// --- Result Structs ---

// DeploymentStatus contains information about a Docker Compose deployment
type DeploymentStatus struct {
	ProjectName string
	Services    map[string]*ServiceStatus
	StartTime   time.Time
	IsRunning   bool
}

// ServiceStatus contains information about a service in a Docker Compose deployment
type ServiceStatus struct {
	Name          string
	ContainerID   string
	ContainerName string
	Image         string
	Status        string
	Health        string
	Ports         []Port
	StartTime     time.Time
	IsRunning     bool
}

// Port represents a port mapping
type Port struct {
	HostIP        string
	HostPort      string
	ContainerPort string
	Protocol      string
}

// ConvertResult contains the result of converting a Docker Compose file
type ConvertResult struct {
	Services map[string]*ServiceConfig
	Networks map[string]*NetworkConfig
	Volumes  map[string]*VolumeConfig
}

// ServiceConfig contains Docker API configuration for a service
type ServiceConfig struct {
	ContainerConfig  *container.Config
	HostConfig       *container.HostConfig
	NetworkingConfig *network.NetworkingConfig
}

// NetworkConfig contains Docker API configuration for a network
type NetworkConfig struct {
	Name     string
	Driver   string
	Options  map[string]string
	IPAM     *network.IPAM
	Internal bool
	Labels   map[string]string
}

// VolumeConfig contains Docker API configuration for a volume
type VolumeConfig struct {
	Name       string
	Driver     string
	DriverOpts map[string]string
	Labels     map[string]string
}

// DeploymentEvent represents an event from a Docker Compose deployment
type DeploymentEvent struct {
	Type        string
	Action      string
	ServiceName string
	ContainerID string
	Time        time.Time
	Message     string
	Attributes  map[string]string
}

// --- Implementation ---

// ComposeService implements the Service interface
type ComposeService struct {
	parser        *Parser
	orchestrator  interfaces.ComposeOrchestrator  // Use interface
	statusTracker interfaces.ComposeStatusTracker // Use interface type
	logger        *logrus.Logger
}

// ComposeServiceOptions defines options for creating a Docker Compose service
type ComposeServiceOptions struct {
	DockerClient   *client.Client
	Orchestrator   interfaces.ComposeOrchestrator // Use interface
	NetworkService networkSvc.Service
	VolumeService  volumeSvc.Service
	Logger         *logrus.Logger
	StatusTracker  interfaces.ComposeStatusTracker // Use interface type
}

// NewComposeService creates a new Docker Compose service
func NewComposeService(options ComposeServiceOptions) (Service, error) {
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}

	parser := NewParser(logger)

	orchestrator := options.Orchestrator
	if orchestrator == nil {
		return nil, errors.New("orchestrator implementation is required")
	}

	statusTracker := options.StatusTracker // Use interface type (already correct)
	if statusTracker == nil {              // Check if the interface is nil
		// If no tracker is provided, create a default one.
		// Note: This requires status.NewTracker to return a type that satisfies status.StatusTracker.
		// Assuming status.NewTracker returns *status.Tracker which should satisfy the updated interface.
		// Cast the concrete type to the interface type.
		statusTracker = status.NewTracker(status.TrackerOptions{
			Logger: logger,
		}) // This line might cause issues if status.Tracker doesn't match interfaces.ComposeStatusTracker
	}

	return &ComposeService{
		parser:        parser,
		orchestrator:  orchestrator,
		statusTracker: statusTracker,
		logger:        logger,
	}, nil
}

// Parse parses a Docker Compose file
func (s *ComposeService) Parse(ctx context.Context, reader io.Reader, options models.ParseOptions) (*models.ComposeFile, error) { // Use models.ParseOptions
	// Pass options directly to the parser's Parse method
	// The parser now expects models.ParseOptions after refactoring
	return s.parser.Parse(ctx, reader, options)
}

// ParseFile method removed
// Validate method removed

// Up deploys a Docker Compose file
func (s *ComposeService) Up(ctx context.Context, composeFile *models.ComposeFile, options models.DeployOptions) error { // Use models.DeployOptions
	return s.orchestrator.Deploy(ctx, composeFile, options)
}

// Down removes a Docker Compose deployment
func (s *ComposeService) Down(ctx context.Context, composeFile *models.ComposeFile, options models.RemoveOptions) error { // Use models.RemoveOptions
	return s.orchestrator.Remove(ctx, composeFile, options)
}

// Start starts services in a Docker Compose deployment
func (s *ComposeService) Start(ctx context.Context, composeFile *models.ComposeFile, options models.StartOptions) error { // Use models.StartOptions
	return s.orchestrator.Start(ctx, composeFile, options)
}

// Stop stops services in a Docker Compose deployment
func (s *ComposeService) Stop(ctx context.Context, composeFile *models.ComposeFile, options models.StopOptions) error { // Use models.StopOptions
	return s.orchestrator.Stop(ctx, composeFile, options)
}

// Restart restarts services in a Docker Compose deployment
func (s *ComposeService) Restart(ctx context.Context, composeFile *models.ComposeFile, options models.RestartOptions) error { // Use models.RestartOptions
	return s.orchestrator.Restart(ctx, composeFile, options)
}

// Ps lists containers in a Docker Compose deployment
func (s *ComposeService) Ps(ctx context.Context, composeFile *models.ComposeFile, options PsOptions) (*DeploymentStatus, error) {
	deployment, exists := s.statusTracker.GetDeployment(options.ProjectName)
	if !exists {
		return nil, fmt.Errorf("deployment '%s' not found", options.ProjectName)
	}

	result := &DeploymentStatus{
		ProjectName: options.ProjectName,
		Services:    make(map[string]*ServiceStatus),
		StartTime:   deployment.StartTime,
		IsRunning:   deployment.Status == models.DeploymentStatusRunning,
	}

	for serviceName, serviceInfo := range deployment.Services {
		if len(options.Services) > 0 && !containsString(options.Services, serviceName) {
			continue
		}
		if serviceInfo.Status != models.ServiceStatusRunning && !options.All {
			continue
		}

		serviceStatus := &ServiceStatus{
			Name:      serviceName,
			Status:    string(serviceInfo.Status),
			StartTime: serviceInfo.StartTime,
			IsRunning: serviceInfo.Status == models.ServiceStatusRunning,
		}
		if len(serviceInfo.ContainerIDs) > 0 {
			serviceStatus.ContainerID = serviceInfo.ContainerIDs[0]
		}
		result.Services[serviceName] = serviceStatus
	}

	return result, nil
}

// Logs gets logs from services in a Docker Compose deployment
func (s *ComposeService) Logs(ctx context.Context, composeFile *models.ComposeFile, options LogOptions) (io.ReadCloser, error) {
	return nil, errors.New("logs functionality not implemented yet")
}

// Events gets events from services in a Docker Compose deployment
func (s *ComposeService) Events(ctx context.Context, composeFile *models.ComposeFile, options EventOptions) (<-chan DeploymentEvent, <-chan error) {
	events := make(chan DeploymentEvent)
	errs := make(chan error)
	close(events)
	close(errs)
	return events, errs
}

// getFirstString returns the first element of a string slice, or an empty string if the slice is empty.
func getFirstString(slice []string) string {
	if len(slice) > 0 {
		return slice[0]
	}
	return ""
}

// Convert converts a Docker Compose file to Docker API objects
func (s *ComposeService) Convert(ctx context.Context, composeFile *models.ComposeFile, options ConvertOptions) (*ConvertResult, error) {
	return nil, errors.New("convert functionality not implemented yet")
}

// Helper functions

// containsString checks if a string slice contains a string
func containsString(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}
