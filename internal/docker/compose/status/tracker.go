// Package status provides functionality for tracking Docker Compose deployment status
package status

import (
	"context"
	// "fmt" // No longer needed directly here
	"sync"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// Type aliases removed, use types from models directly

// Constants are now defined in internal/models/compose_status.go

// Tracker tracks the status of Docker Compose deployments
type Tracker struct {
	// deployments maps project names to deployment status
	deployments map[string]*models.DeploymentInfo // Use models.DeploymentInfo

	// mu is used to protect concurrent access to deployments
	mu sync.RWMutex

	// eventsCh is the channel for Docker events
	eventsCh <-chan events.Message

	// errCh is the channel for errors from the Docker events stream
	errCh <-chan error

	// ctx is the context used to control the tracker
	ctx context.Context

	// cancel is the context cancel function
	cancel context.CancelFunc

	// logger is the logger to use
	logger *logrus.Logger

	// watchers maps receive-only channels (keys) to their send-only counterparts (values)
	watchers map[<-chan *models.DeploymentInfo]chan<- *models.DeploymentInfo // Use models.DeploymentInfo

	// watchersMu is used to protect concurrent access to watchers
	watchersMu sync.RWMutex
}

// TrackerOptions defines options for creating a status tracker
type TrackerOptions struct {
	// EventsCh is the channel for Docker events
	EventsCh <-chan events.Message

	// ErrorsCh is the channel for errors from the Docker events stream
	ErrorsCh <-chan error

	// Logger is the logger to use
	Logger *logrus.Logger
}

// DeploymentInfo, ServiceInfo, HealthInfo, HealthLogEntry, OperationInfo structs are defined in internal/models/compose_status.go
// Removing local definitions below

// NewTracker creates a new status tracker
func NewTracker(options TrackerOptions) *Tracker {
	// Create context with cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}

	// Create tracker
	tracker := &Tracker{
		deployments: make(map[string]*models.DeploymentInfo), // Use models.DeploymentInfo
		eventsCh:    options.EventsCh,
		errCh:       options.ErrorsCh,
		ctx:         ctx,
		cancel:      cancel,
		logger:      logger,
		watchers:    make(map[<-chan *models.DeploymentInfo]chan<- *models.DeploymentInfo), // Use models.DeploymentInfo
	}

	// Start processing events
	if tracker.eventsCh != nil && tracker.errCh != nil {
		go tracker.processEvents()
	}

	return tracker
}

// AddDeployment adds a deployment to track
func (t *Tracker) AddDeployment(projectName string, composeFile *models.ComposeFile) *models.DeploymentInfo { // Use models.DeploymentInfo
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()

	// Check if deployment already exists
	if deployment, exists := t.deployments[projectName]; exists {
		// Update existing deployment
		deployment.ComposeFile = composeFile
		deployment.UpdateTime = now
		return deployment
	}

	// Create new deployment using models.DeploymentInfo
	deployment := &models.DeploymentInfo{
		ProjectName: projectName,
		Status:      models.DeploymentStatusPending,
		Services:    make(map[string]*models.ServiceInfo), // Use models.ServiceInfo
		StartTime:   now,
		UpdateTime:  now,
		ComposeFile: composeFile,
	}

	// Initialize services
	for serviceName := range composeFile.Services {
		deployment.Services[serviceName] = &models.ServiceInfo{ // Use models.ServiceInfo
			Name:       serviceName,
			Status:     models.ServiceStatusPending, // Use constant from models
			StartTime:  now,
			UpdateTime: now,
		}
	}

	// Add deployment
	t.deployments[projectName] = deployment

	// Notify watchers
	t.notifyWatchers(deployment)

	return deployment
}

// GetDeployment gets a deployment by project name
func (t *Tracker) GetDeployment(projectName string) (*models.DeploymentInfo, bool) { // Use models.DeploymentInfo
	t.mu.RLock()
	defer t.mu.RUnlock()

	deployment, exists := t.deployments[projectName]
	return deployment, exists
}

// GetDeployments gets all deployments
func (t *Tracker) GetDeployments() []*models.DeploymentInfo { // Use models.DeploymentInfo
	t.mu.RLock()
	defer t.mu.RUnlock()

	deployments := make([]*models.DeploymentInfo, 0, len(t.deployments)) // Use models.DeploymentInfo
	for _, deployment := range t.deployments {
		deployments = append(deployments, deployment)
	}

	return deployments
}

// RemoveDeployment removes a deployment
func (t *Tracker) RemoveDeployment(projectName string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, exists := t.deployments[projectName]
	if exists {
		delete(t.deployments, projectName)
	}

	return exists
}

// UpdateDeploymentStatus updates the status of a deployment
func (t *Tracker) UpdateDeploymentStatus(projectName string, status models.DeploymentStatus, err error) bool { // Use models.DeploymentStatus
	t.mu.Lock()
	defer t.mu.Unlock()

	deployment, exists := t.deployments[projectName]
	if !exists {
		return false
	}

	deployment.Status = status
	deployment.UpdateTime = time.Now()
	if err != nil {
		deployment.Error = err.Error() // Store error message string
	}

	// Notify watchers
	t.notifyWatchers(deployment)

	return true
}

// UpdateServiceStatus updates the status of a service
func (t *Tracker) UpdateServiceStatus(projectName, serviceName string, status models.ServiceStatus, containerID string, err error) bool { // Updated status type
	t.mu.Lock()
	defer t.mu.Unlock()

	deployment, exists := t.deployments[projectName]
	if !exists {
		return false
	}

	service, exists := deployment.Services[serviceName]
	if !exists {
		// Create service if it doesn't exist
		now := time.Now()
		service = &models.ServiceInfo{ // Use models.ServiceInfo
			Name:       serviceName,
			Status:     status,
			StartTime:  now,
			UpdateTime: now,
		}
		deployment.Services[serviceName] = service
	}

	service.Status = status // Use updated type
	service.UpdateTime = time.Now()

	// Add container ID if provided and not already in the list
	if containerID != "" {
		found := false
		for _, id := range service.ContainerIDs {
			if id == containerID {
				found = true
				break
			}
		}
		if !found {
			service.ContainerIDs = append(service.ContainerIDs, containerID)
		}
	}

	if err != nil {
		service.Error = err.Error() // Store error message string
	}

	// Update deployment status based on service status
	t.updateDeploymentStatusFromServices(deployment)

	// Notify watchers
	t.notifyWatchers(deployment)

	return true
}

// UpdateServiceHealth updates the health of a service
func (t *Tracker) UpdateServiceHealth(projectName, serviceName string, health *models.HealthInfo) bool { // Use models.HealthInfo
	t.mu.Lock()
	defer t.mu.Unlock()

	deployment, exists := t.deployments[projectName]
	if !exists {
		return false
	}

	service, exists := deployment.Services[serviceName]
	if !exists {
		return false
	}

	service.Health = health
	service.UpdateTime = time.Now()

	// Notify watchers
	t.notifyWatchers(deployment)

	return true
}

// StartOperation starts an operation for a deployment
func (t *Tracker) StartOperation(projectName string, operationType models.OperationType, details map[string]interface{}) (*models.OperationInfo, bool) { // Use models types
	t.mu.Lock()
	defer t.mu.Unlock()

	deployment, exists := t.deployments[projectName]
	if !exists {
		return nil, false
	}

	now := time.Now()
	operation := &models.OperationInfo{ // Use models.OperationInfo
		Type:      operationType,
		Status:    models.OperationStatusInProgress,
		StartTime: now,
		Details:   details,
	}

	deployment.Operation = operation
	deployment.UpdateTime = now

	// Update deployment status based on operation
	switch operationType {
	case models.OperationTypeUp, models.OperationTypeStart: // Use constant from models
		deployment.Status = models.DeploymentStatusDeploying // Use constant from models
	case models.OperationTypeDown, models.OperationTypeStop: // Use constant from models
		deployment.Status = models.DeploymentStatusStopping // Use constant from models
	case models.OperationTypeRemove: // Use constant from models
		deployment.Status = models.DeploymentStatusRemoving // Use constant from models
	}

	// Update service status based on operation
	for _, service := range deployment.Services {
		switch operationType {
		case models.OperationTypeUp, models.OperationTypeStart: // Use constant from models
			if service.Status == models.ServiceStatusUnknown || service.Status == models.ServiceStatusExited || service.Status == models.ServiceStatusDead {
				service.Status = models.ServiceStatusPending // Use constant from models
			}
		case models.OperationTypeDown, models.OperationTypeStop: // Use constant from models
			if service.Status == models.ServiceStatusRunning || service.Status == models.ServiceStatusRestarting {
				service.Status = models.ServiceStatusRemoving // Use constant from models
			}
		case models.OperationTypeRemove: // Use constant from models
			service.Status = models.ServiceStatusRemoving // Use constant from models
		}
		service.UpdateTime = now
	}

	// Notify watchers
	t.notifyWatchers(deployment)

	return operation, true
}

// CompleteOperation completes an operation for a deployment
func (t *Tracker) CompleteOperation(projectName string, status models.OperationStatus, err error) bool { // Use models.OperationStatus
	t.mu.Lock()
	defer t.mu.Unlock()

	deployment, exists := t.deployments[projectName]
	if !exists {
		return false
	}

	if deployment.Operation == nil {
		return false
	}

	now := time.Now()
	deployment.Operation.Status = status
	deployment.Operation.EndTime = now
	deployment.UpdateTime = now

	if err != nil {
		deployment.Operation.Error = err.Error() // Store error message string
		deployment.Error = err.Error()           // Store error message string
	}

	// Update deployment status based on operation
	operationType := deployment.Operation.Type
	switch {
	case status == models.OperationStatusFailed: // Use constant from models
		deployment.Status = models.DeploymentStatusFailed // Use constant from models
	case status == models.OperationStatusComplete && operationType == models.OperationTypeRemove: // Use constant from models
		deployment.Status = models.DeploymentStatusRemoved // Use constant from models
	case status == models.OperationStatusComplete && (operationType == models.OperationTypeDown || operationType == models.OperationTypeStop): // Use constant from models
		deployment.Status = models.DeploymentStatusStopped // Use constant from models
	case status == models.OperationStatusComplete && (operationType == models.OperationTypeUp || operationType == models.OperationTypeStart): // Use constant from models
		// Check if all services are running
		allRunning := true
		for _, service := range deployment.Services {
			if service.Status != models.ServiceStatusRunning { // Use constant from models
				allRunning = false
				break
			}
		}
		if allRunning {
			deployment.Status = models.DeploymentStatusRunning // Use constant from models
		} else {
			deployment.Status = models.DeploymentStatusPartial // Use constant from models
		}
	}

	// Notify watchers
	t.notifyWatchers(deployment)

	return true
}

// Watch returns a channel that receives deployment updates
func (t *Tracker) Watch() <-chan *models.DeploymentInfo { // Use models.DeploymentInfo
	// Create both send and receive channels
	sendCh := make(chan *models.DeploymentInfo, 10)   // Use models.DeploymentInfo
	recvCh := (<-chan *models.DeploymentInfo)(sendCh) // Cast to receive-only for return

	t.watchersMu.Lock()
	defer t.watchersMu.Unlock()

	t.watchers[recvCh] = sendCh // Store receive chan as key, send chan as value

	return recvCh // Return the receive-only channel
}

// Unwatch removes a watcher channel
func (t *Tracker) Unwatch(ch <-chan *models.DeploymentInfo) { // Use models.DeploymentInfo
	t.watchersMu.Lock()
	defer t.watchersMu.Unlock()

	// Find the corresponding send channel using the receive channel as key
	if sendCh, ok := t.watchers[ch]; ok {
		close(sendCh) // Close the send channel
	}
	delete(t.watchers, ch) // Delete the entry using the receive channel key
}

// Stop stops the tracker
func (t *Tracker) Stop() {
	t.cancel()

	// Close all watcher channels
	t.watchersMu.Lock()
	defer t.watchersMu.Unlock()

	// Iterate over the values (send channels) and close them
	for _, sendCh := range t.watchers {
		close(sendCh)
	}
	// Recreate the map
	t.watchers = make(map[<-chan *models.DeploymentInfo]chan<- *models.DeploymentInfo) // Use models.DeploymentInfo
}

// updateDeploymentStatusFromServices updates the deployment status based on service statuses
func (t *Tracker) updateDeploymentStatusFromServices(deployment *models.DeploymentInfo) { // Use models.DeploymentInfo
	// If no services, return unknown
	if len(deployment.Services) == 0 {
		deployment.Status = models.DeploymentStatusUnknown // Use constant from models
		return
	}

	// Count services by status
	counts := make(map[models.ServiceStatus]int) // Use models.ServiceStatus as key
	for _, service := range deployment.Services {
		counts[service.Status]++
	}

	// If all services are in the same state, set deployment status accordingly
	totalServices := len(deployment.Services)
	if counts[models.ServiceStatusRunning] == totalServices { // Use constant from models
		deployment.Status = models.DeploymentStatusRunning // Use constant from models
	} else if counts[models.ServiceStatusExited]+counts[models.ServiceStatusDead] == totalServices { // Use constant from models
		deployment.Status = models.DeploymentStatusStopped // Use constant from models
	} else if counts[models.ServiceStatusFailed] > 0 { // Use constant from models
		deployment.Status = models.DeploymentStatusFailed // Use constant from models
	} else if counts[models.ServiceStatusRunning] > 0 && counts[models.ServiceStatusRunning] < totalServices { // Use constant from models
		deployment.Status = models.DeploymentStatusPartial // Use constant from models
	}
}

// processEvents processes Docker events to update service status
func (t *Tracker) processEvents() {
	for {
		select {
		case <-t.ctx.Done():
			return
		case event, ok := <-t.eventsCh:
			if !ok {
				return
			}
			t.handleEvent(event)
		case err, ok := <-t.errCh:
			if !ok {
				return
			}
			t.logger.WithError(err).Error("Error from Docker events stream")
		}
	}
}

// handleEvent handles a Docker event
func (t *Tracker) handleEvent(event events.Message) {
	// Only process container events
	if event.Type != "container" {
		return
	}

	// Extract project and service information from labels
	projectName := event.Actor.Attributes["com.docker_test.compose.project"]
	serviceName := event.Actor.Attributes["com.docker_test.compose.service"]

	// Skip if not a compose container
	if projectName == "" || serviceName == "" {
		return
	}

	containerID := event.Actor.ID

	// Map Docker container status to service status
	var status models.ServiceStatus // Use models.ServiceStatus
	switch event.Action {
	case "create":
		status = models.ServiceStatusCreating // Use constant from models
	case "start":
		status = models.ServiceStatusRunning // Use constant from models
	case "die", "stop", "kill":
		status = models.ServiceStatusExited // Use constant from models
	case "destroy", "remove":
		status = models.ServiceStatusRemoved // Use constant from models
	case "pause":
		status = models.ServiceStatusPaused // Use constant from models
	case "unpause":
		status = models.ServiceStatusRunning // Use constant from models
	case "restart":
		status = models.ServiceStatusRestarting // Use constant from models
	case "health_status":
		// Handle health status separately
		t.handleHealthStatus(projectName, serviceName, containerID, event.Actor.Attributes["health_status"])
		return
	default:
		status = models.ServiceStatusUnknown // Use constant from models
		// return // Don't return, update with Unknown status
	}

	// Update service status
	t.UpdateServiceStatus(projectName, serviceName, status, containerID, nil)
}

// handleHealthStatus handles Docker health status events
func (t *Tracker) handleHealthStatus(projectName, serviceName, containerID, healthStatus string) {
	health := &models.HealthInfo{ // Use models.HealthInfo
		Status: healthStatus,
	}

	t.UpdateServiceHealth(projectName, serviceName, health)
}

// notifyWatchers notifies all watchers of a deployment update
func (t *Tracker) notifyWatchers(deployment *models.DeploymentInfo) { // Use models.DeploymentInfo
	t.watchersMu.RLock()
	defer t.watchersMu.RUnlock()

	// Iterate over the values (send channels)
	for _, sendCh := range t.watchers {
		// Non-blocking send to prevent slow watchers from blocking others
		select {
		case sendCh <- deployment:
		default:
			t.logger.WithField("project", deployment.ProjectName).
				Warn("Watcher channel is full, skipping deployment update")
		}
	}
}

// GetServiceContainerID returns the first container ID for a service
func (t *Tracker) GetServiceContainerID(projectName, serviceName string) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	deployment, exists := t.deployments[projectName]
	if !exists {
		return "", false
	}

	service, exists := deployment.Services[serviceName]
	if !exists || len(service.ContainerIDs) == 0 {
		return "", false
	}

	return service.ContainerIDs[0], true
}

// GetServiceContainerIDs returns all container IDs for a service
func (t *Tracker) GetServiceContainerIDs(projectName, serviceName string) ([]string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	deployment, exists := t.deployments[projectName]
	if !exists {
		return nil, false
	}

	service, exists := deployment.Services[serviceName]
	if !exists {
		return nil, false
	}

	// Return a copy of the slice to prevent concurrent modification
	result := make([]string, len(service.ContainerIDs))
	copy(result, service.ContainerIDs)

	return result, true
}

// GetServiceStatus returns the status of a service
func (t *Tracker) GetServiceStatus(projectName, serviceName string) (models.ServiceStatus, bool) { // Return models.ServiceStatus
	t.mu.RLock()
	defer t.mu.RUnlock()

	deployment, exists := t.deployments[projectName]
	if !exists {
		return models.ServiceStatusUnknown, false // Use constant from models
	}

	service, exists := deployment.Services[serviceName]
	if !exists {
		return models.ServiceStatusUnknown, false // Use constant from models
	}

	return service.Status, true
}

// Removed duplicate constants from the end
