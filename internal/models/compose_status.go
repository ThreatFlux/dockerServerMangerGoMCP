// Package models provides data structures used throughout the application
package models

import "time" // Added import

// ServiceStatus represents the status of a compose service
type ServiceStatus string

// Service status constants
const (
	// ServiceStatusUnknown indicates that the service status is unknown
	ServiceStatusUnknown ServiceStatus = "unknown"

	// ServiceStatusPending indicates that the service is pending creation
	ServiceStatusPending ServiceStatus = "pending"

	// ServiceStatusCreating indicates that the service is being created
	ServiceStatusCreating ServiceStatus = "creating"

	// ServiceStatusStarting indicates that the service is starting
	ServiceStatusStarting ServiceStatus = "starting" // Added constant

	// ServiceStatusCreated indicates that the service has been created but may not be running yet
	ServiceStatusCreated ServiceStatus = "created" // Added constant

	// ServiceStatusRunning indicates that the service is running
	ServiceStatusRunning ServiceStatus = "running"

	// ServiceStatusPaused indicates that the service is paused
	ServiceStatusPaused ServiceStatus = "paused"

	// ServiceStatusRestarting indicates that the service is restarting
	ServiceStatusRestarting ServiceStatus = "restarting"

	// ServiceStatusStopping indicates that the service is stopping
	ServiceStatusStopping ServiceStatus = "stopping" // Added constant

	// ServiceStatusRemoving indicates that the service is being removed
	ServiceStatusRemoving ServiceStatus = "removing"

	// ServiceStatusStopped indicates that the service has stopped (similar to exited but explicitly stopped)
	ServiceStatusStopped ServiceStatus = "stopped" // Added constant

	// ServiceStatusExited indicates that the service has exited
	ServiceStatusExited ServiceStatus = "exited"

	// ServiceStatusDead indicates that the service is dead
	ServiceStatusDead ServiceStatus = "dead"

	// ServiceStatusFailed indicates that the service has failed
	ServiceStatusFailed ServiceStatus = "failed"

	// ServiceStatusComplete indicates that the service has completed successfully
	ServiceStatusComplete ServiceStatus = "complete"

	// ServiceStatusRemoved indicates that the service is removed
	ServiceStatusRemoved ServiceStatus = "removed"

	// ServiceStatusUnhealthy indicates that the service is running but unhealthy
	ServiceStatusUnhealthy ServiceStatus = "unhealthy" // Added constant

	// ServiceStatusPartial indicates that the service is partially running (some containers running, some not)
	ServiceStatusPartial ServiceStatus = "partial" // Added constant

	// ServiceStatusScalingUp indicates that the service is scaling up
	ServiceStatusScalingUp ServiceStatus = "scaling_up"

	// ServiceStatusScalingDown indicates that the service is scaling down
	ServiceStatusScalingDown ServiceStatus = "scaling_down"
)

// DeploymentStatus represents the status of a compose deployment
type DeploymentStatus string

// Deployment status constants
const (
	// DeploymentStatusUnknown indicates that the deployment status is unknown
	DeploymentStatusUnknown DeploymentStatus = "unknown"

	// DeploymentStatusPending indicates that the deployment is pending
	DeploymentStatusPending DeploymentStatus = "pending"

	// DeploymentStatusDeploying indicates that the deployment is in progress
	DeploymentStatusDeploying DeploymentStatus = "deploying"

	// DeploymentStatusRunning indicates that the deployment is running
	DeploymentStatusRunning DeploymentStatus = "running"

	// DeploymentStatusPartial indicates that the deployment is partially running
	DeploymentStatusPartial DeploymentStatus = "partial"

	// DeploymentStatusStopping indicates that the deployment is stopping
	DeploymentStatusStopping DeploymentStatus = "stopping"

	// DeploymentStatusStopped indicates that the deployment is stopped
	DeploymentStatusStopped DeploymentStatus = "stopped"

	// DeploymentStatusRemoving indicates that the deployment is being removed
	DeploymentStatusRemoving DeploymentStatus = "removing"

	// DeploymentStatusRemoved indicates that the deployment is removed
	DeploymentStatusRemoved DeploymentStatus = "removed"

	// DeploymentStatusFailed indicates that the deployment has failed
	DeploymentStatusFailed DeploymentStatus = "failed"
)

// OperationType represents the type of operation being performed
type OperationType string

// Operation type constants
const (
	// OperationTypeUp indicates an 'up' operation
	OperationTypeUp OperationType = "up"

	// OperationTypeDown indicates a 'down' operation
	OperationTypeDown OperationType = "down"

	// OperationTypeStart indicates a 'start' operation
	OperationTypeStart OperationType = "start"

	// OperationTypeStop indicates a 'stop' operation
	OperationTypeStop OperationType = "stop"

	// OperationTypeRestart indicates a 'restart' operation
	OperationTypeRestart OperationType = "restart"

	// OperationTypePull indicates a 'pull' operation
	OperationTypePull OperationType = "pull"

	// OperationTypeBuild indicates a 'build' operation
	OperationTypeBuild OperationType = "build"

	// OperationTypeCreate indicates a 'create' operation
	OperationTypeCreate OperationType = "create"

	// OperationTypeRemove indicates a 'remove' operation
	OperationTypeRemove OperationType = "remove"

	// OperationTypeScale indicates a 'scale' operation
	OperationTypeScale OperationType = "scale"
)

// OperationStatus represents the status of an operation
type OperationStatus string

// Operation status constants
const (
	// OperationStatusPending indicates that the operation is pending
	OperationStatusPending OperationStatus = "pending"

	// OperationStatusInProgress indicates that the operation is in progress
	OperationStatusInProgress OperationStatus = "in_progress"

	// OperationStatusComplete indicates that the operation is complete
	OperationStatusComplete OperationStatus = "complete"

	// OperationStatusFailed indicates that the operation has failed
	OperationStatusFailed OperationStatus = "failed"
)

// DeploymentUpdate represents a status update for a deployment or service
type DeploymentUpdate struct {
	ProjectName string      `json:"project_name"`
	ServiceName string      `json:"service_name,omitempty"` // Empty if it's a project-level update
	Status      interface{} `json:"status"`                 // Can be DeploymentStatus or ServiceStatus
	Timestamp   time.Time   `json:"timestamp"`
	Error       string      `json:"error,omitempty"`
	Details     interface{} `json:"details,omitempty"` // Additional details (e.g., health status)
}

// --- Status Structs (Mirrored from status package, adjust if needed) ---

// DeploymentInfo contains status information about a Docker Compose deployment.
// @description Detailed status of a Compose project, including its services and any ongoing operations.
type DeploymentInfo struct {
	// ProjectName is the name of the Compose project.
	// required: true
	// example: "my-web-app"
	ProjectName string `json:"projectName"`

	// Status is the overall status of the deployment.
	// required: true
	// example: "running"
	Status DeploymentStatus `json:"status"`

	// Services maps service names to their detailed status information.
	// required: true
	Services map[string]*ServiceInfo `json:"services"`

	// Operation describes the currently active operation (e.g., up, down), if any.
	Operation *OperationInfo `json:"operation,omitempty"`

	// StartTime is the timestamp when the deployment was first tracked or started.
	// required: true
	// example: "2023-10-27T10:00:00Z"
	StartTime time.Time `json:"startTime"`

	// UpdateTime is the timestamp when the deployment status was last updated.
	// required: true
	// example: "2023-10-27T10:05:00Z"
	UpdateTime time.Time `json:"updateTime"`

	// Error contains the last error message associated with the deployment, if any.
	// example: "Failed to pull image 'nonexistent:latest'"
	Error string `json:"error,omitempty"` // Store error message as string

	// ComposeFile is the parsed representation of the compose file (excluded from JSON).
	ComposeFile *ComposeFile `json:"-"` // Avoid recursion in JSON, maybe store path?
}

// ServiceInfo contains status information about a specific service within a Compose deployment.
// @description Detailed status of a single service, including its containers and health.
type ServiceInfo struct {
	// Name is the name of the service as defined in the Compose file.
	// required: true
	// example: "web"
	Name string `json:"name"`

	// ContainerIDs lists the Docker container IDs associated with this service instance(s).
	// example: ["f7d9e8c7b6a5", "a1b2c3d4e5f6"]
	ContainerIDs []string `json:"containerIDs"`

	// Status is the current status of the service.
	// required: true
	// example: "running"
	Status ServiceStatus `json:"status"`

	// StartTime is the timestamp when the service (or its first container) was started.
	// required: true
	// example: "2023-10-27T10:01:00Z"
	StartTime time.Time `json:"startTime"`

	// UpdateTime is the timestamp when the service status was last updated.
	// required: true
	// example: "2023-10-27T10:06:00Z"
	UpdateTime time.Time `json:"updateTime"`

	// Error contains the last error message associated with the service, if any.
	// example: "Container exited with code 1"
	Error string `json:"error,omitempty"` // Store error message as string

	// Health provides details about the service's health check status, if configured.
	Health *HealthInfo `json:"health,omitempty"`
}

// HealthInfo contains health check information for a service container.
// @description Details about the health status based on Docker health checks.
type HealthInfo struct {
	// Status indicates the current health status (e.g., "healthy", "unhealthy", "starting").
	// required: true
	// example: "healthy"
	Status string `json:"status"`

	// FailingStreak is the number of consecutive failed health checks.
	// required: true
	// example: 0
	FailingStreak int `json:"failingStreak"`

	// Log contains recent health check probe results.
	Log []HealthLogEntry `json:"log,omitempty"`
}

// HealthLogEntry represents a single health check probe result.
// @description Log entry detailing the outcome of one health check attempt.
type HealthLogEntry struct {
	// Start is the timestamp when the health check probe started.
	// required: true
	// example: "2023-10-27T10:05:50Z"
	Start time.Time `json:"start"`

	// End is the timestamp when the health check probe ended.
	// required: true
	// example: "2023-10-27T10:05:51Z"
	End time.Time `json:"end"`

	// ExitCode is the exit code of the health check command. 0 typically indicates success.
	// required: true
	// example: 0
	ExitCode int `json:"exitCode"`

	// Output contains the stdout/stderr output from the health check command.
	// example: "OK"
	Output string `json:"output,omitempty"`
}

// OperationInfo contains information about an ongoing or completed Compose operation.
// @description Details about a long-running operation like 'up', 'down', 'start', etc.
type OperationInfo struct {
	// Type indicates the type of operation being performed.
	// required: true
	// example: "up"
	Type OperationType `json:"type"`

	// Status indicates the current status of the operation.
	// required: true
	// example: "in_progress"
	Status OperationStatus `json:"status"`

	// StartTime is the timestamp when the operation began.
	// required: true
	// example: "2023-10-27T10:04:30Z"
	StartTime time.Time `json:"startTime"`

	// EndTime is the timestamp when the operation finished (only present if Status is 'complete' or 'failed').
	// example: "2023-10-27T10:05:15Z"
	EndTime time.Time `json:"endTime,omitempty"`

	// Error contains the error message if the operation failed.
	// example: "Failed to create service 'db': network 'shared' not found"
	Error string `json:"error,omitempty"` // Store error message as string

	// Details provides additional context or progress information about the operation.
	// example: {"step": "Creating service web", "progress": 0.5}
	Details map[string]interface{} `json:"details,omitempty"`
}

// ServiceStatusInfo provides detailed status information for a service
type ServiceStatusInfo struct {
	Name         string        `json:"name"`
	Status       ServiceStatus `json:"status"`
	ContainerIDs []string      `json:"container_ids"`
	HealthStatus string        `json:"health_status,omitempty"` // e.g., healthy, unhealthy, starting
	Error        string        `json:"error,omitempty"`
	UpdateTime   time.Time     `json:"update_time"`
}
