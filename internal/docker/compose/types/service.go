// Package types provides common structures for Docker Compose functionality
package types

import (
	"context"
	// "io" // Removed unused import
	"time"
)

// Service defines interfaces for Docker Compose operations
type Service interface {
	// ParseFile parses a Docker Compose file from a file path
	ParseFile(ctx context.Context, path string) (*ComposeFile, []string, error)

	// ValidateFile validates a Docker Compose file
	ValidateFile(ctx context.Context, path string) (interface{}, []string, error)

	// Convert converts a Docker Compose file to Docker API objects
	Convert(ctx context.Context, path string) (interface{}, error)
}

// Orchestrator defines interfaces for Docker Compose orchestration
type Orchestrator interface {
	// Up deploys a Docker Compose project
	Up(ctx context.Context, composeFile string, options UpOptions) error

	// Down tears down a Docker Compose project
	Down(ctx context.Context, composeFile string, options DownOptions) error

	// StartService starts a specific service
	StartService(ctx context.Context, composeFile string, projectName string, serviceName string, options ServiceOptions) error

	// StopService stops a specific service
	StopService(ctx context.Context, composeFile string, projectName string, serviceName string, options ServiceOptions) error

	// RestartService restarts a specific service
	RestartService(ctx context.Context, composeFile string, projectName string, serviceName string, options ServiceOptions) error

	// RecreateService recreates a specific service
	RecreateService(ctx context.Context, composeFile string, projectName string, serviceName string, options ServiceOptions) error

	// ScaleService scales a specific service
	ScaleService(ctx context.Context, composeFile string, projectName string, serviceName string, replicas int, options ServiceOptions) error

	// GetServiceContainers gets containers for a specific service
	GetServiceContainers(ctx context.Context, projectName string, serviceName string) ([]string, error)
}

// StatusTracker defines interfaces for tracking Docker Compose deployment status
type StatusTracker interface {
	// InitializeProject initializes project status tracking
	InitializeProject(projectName string, services []string)

	// SetProjectStatus sets the status of a project
	SetProjectStatus(projectName string, status string)

	// SetProjectStatusObject sets the status of a project with a complete status object
	SetProjectStatusObject(projectName string, status interface{})

	// GetProjectStatus gets the status of a project
	GetProjectStatus(projectName string) interface{}

	// GetProjectEvents gets the events of a project
	GetProjectEvents(projectName string) []interface{}

	// SetError sets an error for a project
	SetError(projectName string, errorMessage string)

	// RemoveProject removes a project from tracking
	RemoveProject(projectName string)
}

// UpOptions defines options for deploying a Docker Compose file
type UpOptions struct {
	// ProjectName is the name of the project
	ProjectName string

	// Timeout is the timeout for the operation
	Timeout time.Duration

	// PullImages indicates whether to pull images
	PullImages bool

	// ForceRecreate indicates whether to force recreation of containers
	ForceRecreate bool

	// RemoveOrphans indicates whether to remove orphaned containers
	RemoveOrphans bool

	// TargetServices are the names of services to include (empty for all)
	TargetServices []string

	// Logger is the logger to use
	Logger interface{}

	// StatusTracker is the status tracker to use
	StatusTracker interface{}
}

// DownOptions defines options for removing a Docker Compose deployment
type DownOptions struct {
	// ProjectName is the name of the project
	ProjectName string

	// Timeout is the timeout for the operation
	Timeout time.Duration

	// RemoveVolumes indicates whether to remove volumes
	RemoveVolumes bool

	// RemoveImages indicates whether to remove images (all, local, none)
	RemoveImages string

	// RemoveOrphans indicates whether to remove orphaned containers
	RemoveOrphans bool

	// TargetServices are the names of services to include (empty for all)
	TargetServices []string

	// Logger is the logger to use
	Logger interface{}

	// StatusTracker is the status tracker to use
	StatusTracker interface{}
}

// ServiceOptions defines options for service operations
type ServiceOptions struct {
	// Timeout is the timeout for the operation
	Timeout time.Duration

	// PullImage indicates whether to pull the image
	PullImage bool

	// ForceRecreate indicates whether to force recreation of containers
	ForceRecreate bool

	// Logger is the logger to use
	Logger interface{}

	// StatusTracker is the status tracker to use
	StatusTracker interface{}
}
