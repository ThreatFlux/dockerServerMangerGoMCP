// Package interfaces defines common interfaces used across the application
package interfaces

import (
	"context"
	"io" // Needed for Parse method

	// No longer importing implementation packages directly
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// ComposeService defines interfaces for Docker Compose parsing and validation
type ComposeService interface {
	// Parse reads and parses a Docker Compose configuration from an io.Reader
	Parse(ctx context.Context, reader io.Reader, options models.ParseOptions) (*models.ComposeFile, error) // Use models.ParseOptions

	// ParseFile method removed
	// ValidateFile method removed
}

// ComposeOrchestrator defines interfaces for Docker Compose orchestration
type ComposeOrchestrator interface {
	Deploy(ctx context.Context, composeFile *models.ComposeFile, options models.DeployOptions) error   // Use models.DeployOptions
	Remove(ctx context.Context, composeFile *models.ComposeFile, options models.RemoveOptions) error   // Use models.RemoveOptions
	Start(ctx context.Context, composeFile *models.ComposeFile, options models.StartOptions) error     // Use models.StartOptions
	Stop(ctx context.Context, composeFile *models.ComposeFile, options models.StopOptions) error       // Use models.StopOptions
	Restart(ctx context.Context, composeFile *models.ComposeFile, options models.RestartOptions) error // Use models.RestartOptions
	Scale(ctx context.Context, composeFile *models.ComposeFile, options models.ScaleOptions) error     // Use models.ScaleOptions
}

// ComposeStatusTracker defines interfaces for tracking Docker Compose deployment status
type ComposeStatusTracker interface {
	// AddDeployment adds a deployment to track, returning the info struct
	AddDeployment(projectName string, composeFile *models.ComposeFile) *models.DeploymentInfo // Use models.DeploymentInfo

	// GetDeployment gets a deployment by project name
	GetDeployment(projectName string) (*models.DeploymentInfo, bool) // Use models.DeploymentInfo

	// GetDeployments gets all deployments
	GetDeployments() []*models.DeploymentInfo // Use models.DeploymentInfo

	// RemoveDeployment removes a deployment
	RemoveDeployment(projectName string) bool

	// UpdateDeploymentStatus updates the status of a deployment
	UpdateDeploymentStatus(projectName string, deploymentStatus models.DeploymentStatus, err error) bool // Use models.DeploymentStatus

	// UpdateServiceStatus updates the status of a service
	UpdateServiceStatus(projectName, serviceName string, serviceStatus models.ServiceStatus, containerID string, err error) bool // Use models.ServiceStatus

	// UpdateServiceHealth updates the health of a service
	UpdateServiceHealth(projectName, serviceName string, health *models.HealthInfo) bool // Use models.HealthInfo

	// StartOperation starts an operation for a deployment
	StartOperation(projectName string, operationType models.OperationType, details map[string]interface{}) (*models.OperationInfo, bool) // Use models types

	// CompleteOperation completes an operation for a deployment
	CompleteOperation(projectName string, operationStatus models.OperationStatus, err error) bool // Use models types

	// Watch returns a channel that receives deployment updates
	Watch() <-chan *models.DeploymentInfo // Use models.DeploymentInfo

	// Unwatch removes a watcher channel
	Unwatch(ch <-chan *models.DeploymentInfo) // Use models.DeploymentInfo

	// Stop stops the tracker's background processes (like event listening)
	Stop()

	// GetServiceContainerID gets the first container ID for a service (if any)
	GetServiceContainerID(projectName, serviceName string) (string, bool)

	// GetServiceContainerIDs gets all container IDs for a service
	GetServiceContainerIDs(projectName, serviceName string) ([]string, bool)

	// GetServiceStatus gets the status of a specific service
	GetServiceStatus(projectName, serviceName string) (models.ServiceStatus, bool) // Use models.ServiceStatus
}

// --- Options/Status Structs are now defined in internal/models ---
