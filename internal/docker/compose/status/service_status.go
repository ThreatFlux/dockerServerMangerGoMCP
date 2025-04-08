// Package status provides functionality for monitoring Docker Compose service status
package status

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container" // Ensure container is imported
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// DockerStatusAPIClient defines the minimal interface needed by the status manager
type DockerStatusAPIClient interface {
	Events(ctx context.Context, options events.ListOptions) (<-chan events.Message, <-chan error) // Use events.ListOptions
	ContainerList(ctx context.Context, options container.ListOptions) ([]types.Container, error)
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
}

// ServiceStatusManager monitors the status of services within Docker Compose projects
type ServiceStatusManager struct {
	client        DockerStatusAPIClient // Use the interface
	logger        *logrus.Logger
	projects      map[string]*ProjectStatus // Map project name to status
	mu            sync.RWMutex
	eventStream   <-chan events.Message
	errStream     <-chan error
	eventCancel   context.CancelFunc
	updateChannel chan<- models.DeploymentUpdate // Channel to send updates
	watchers      map[chan models.DeploymentUpdate]bool
	watchersMu    sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
}

// ProjectStatus holds the status information for a single Compose project
type ProjectStatus struct {
	Name     string
	Services map[string]*ServiceStatus // Map service name to status
	mu       sync.RWMutex
}

// ServiceStatus holds the status information for a single service
type ServiceStatus struct {
	Name         string
	Status       models.ServiceStatus // e.g., Running, Exited, Pending
	ContainerIDs []string             // IDs of containers belonging to this service
	Health       *models.HealthInfo   // Use models.HealthInfo
	Error        error                // Last error encountered
	mu           sync.RWMutex
	UpdateTime   time.Time
}

// ServiceStatusManagerOptions holds options for creating a ServiceStatusManager
type ServiceStatusManagerOptions struct {
	Client        DockerStatusAPIClient // Use the interface
	Logger        *logrus.Logger
	UpdateChannel chan<- models.DeploymentUpdate
}

// NewServiceStatusManager creates a new ServiceStatusManager
func NewServiceStatusManager(options ServiceStatusManagerOptions) (*ServiceStatusManager, error) {
	var apiClient DockerStatusAPIClient = options.Client // Use interface type

	// If no client provided, try creating a default one
	if apiClient == nil {
		defaultCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			return nil, fmt.Errorf("failed to create default Docker client: %w", err)
		}
		apiClient = defaultCli // Assign concrete client to interface variable
	}

	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &ServiceStatusManager{
		client:        apiClient, // Store the client (as interface)
		logger:        logger,
		projects:      make(map[string]*ProjectStatus),
		updateChannel: options.UpdateChannel,
		watchers:      make(map[chan models.DeploymentUpdate]bool),
		ctx:           ctx,
		cancel:        cancel,
	}

	// Start event monitoring in a goroutine
	if err := manager.startEventMonitoring(); err != nil {
		cancel() // Clean up context if event monitoring fails
		return nil, fmt.Errorf("failed to start event monitoring: %w", err)
	}

	// Start periodic polling in a goroutine
	go manager.startPolling(15 * time.Second) // Poll every 15 seconds

	logger.Info("Service Status Manager initialized")
	return manager, nil
}

// startEventMonitoring subscribes to Docker events
func (m *ServiceStatusManager) startEventMonitoring() error {
	m.logger.Info("Starting Docker event monitoring")
	eventCtx, eventCancel := context.WithCancel(m.ctx)

	m.mu.Lock() // Lock before accessing shared resources
	m.eventCancel = eventCancel

	// Filter for container events
	eventFilters := filters.NewArgs()
	eventFilters.Add("type", "container")

	var err error
	eventStream, errStream := m.client.Events(eventCtx, events.ListOptions{Filters: eventFilters}) // Use events.ListOptions
	if eventStream == nil || errStream == nil {
		err = fmt.Errorf("failed to get event streams from Docker client")
		m.logger.WithError(err).Error("Event stream initialization failed")
		m.mu.Unlock() // Unlock before returning error
		return err
	}
	m.eventStream = eventStream // Assign within lock
	m.errStream = errStream     // Assign within lock
	m.mu.Unlock()               // Unlock after accessing shared resources

	go m.listenToEvents()
	m.logger.Info("Successfully subscribed to Docker events")
	return nil
}

// listenToEvents processes incoming Docker events
func (m *ServiceStatusManager) listenToEvents() {
	m.logger.Debug("Event listener started")
	for {
		// RLock needed here to safely read eventStream and errStream
		m.mu.RLock()
		eventStream := m.eventStream // Copy channel reference under lock
		errStream := m.errStream     // Copy channel reference under lock
		m.mu.RUnlock()

		// Check if streams are nil (might happen if stopped concurrently)
		if eventStream == nil || errStream == nil {
			m.logger.Debug("Event streams are nil, listener exiting.")
			return
		}

		select {
		case event, ok := <-eventStream: // Read from local copy
			if !ok {
				m.logger.Debug("Event stream closed, listener exiting.")
				return
			}
			m.logger.WithFields(logrus.Fields{
				"type":   event.Type,
				"action": event.Action,
				"id":     event.Actor.ID,
			}).Debug("Received Docker event")
			m.handleEvent(event)
		case err, ok := <-errStream: // Read from local copy
			if !ok {
				m.logger.Debug("Error stream closed, listener exiting.")
				return
			}
			if err != nil {
				m.logger.WithError(err).Error("Error received from Docker event stream")
				// Decide if we should return or continue based on error type
				// For now, let's log and continue to avoid stopping on transient errors
				// return
			}
		case <-m.ctx.Done():
			m.logger.Info("Stopping event listener due to context cancellation")
			return
		}
	}
}

// handleEvent processes a single Docker event and updates status
func (m *ServiceStatusManager) handleEvent(event events.Message) {
	if event.Type != "container" {
		return
	}

	containerID := event.Actor.ID
	projectName := event.Actor.Attributes["com.docker_test.compose.project"]
	serviceName := event.Actor.Attributes["com.docker_test.compose.service"]

	if projectName == "" || serviceName == "" {
		return
	}

	m.mu.RLock()
	project, exists := m.projects[projectName]
	m.mu.RUnlock()

	if !exists {
		return
	}

	project.mu.Lock()
	defer project.mu.Unlock()

	service, serviceExists := project.Services[serviceName]
	if !serviceExists {
		m.logger.WithFields(logrus.Fields{
			"project": projectName,
			"service": serviceName,
		}).Warn("Received event for untracked service, creating placeholder")
		service = &ServiceStatus{
			Name:   serviceName,
			Status: models.ServiceStatusPending,
		}
		project.Services[serviceName] = service
	}

	service.mu.Lock()
	defer service.mu.Unlock()

	needsUpdate := false
	newStatus := service.Status

	switch event.Action {
	case "create":
		if !contains(service.ContainerIDs, containerID) {
			service.ContainerIDs = append(service.ContainerIDs, containerID)
			needsUpdate = true
		}
	case "start":
		newStatus = models.ServiceStatusRunning
		if !contains(service.ContainerIDs, containerID) {
			service.ContainerIDs = append(service.ContainerIDs, containerID)
		}
		needsUpdate = true
	case "stop", "kill":
		m.logger.WithFields(logrus.Fields{
			"project":   projectName,
			"service":   serviceName,
			"container": containerID,
		}).Debug("Container stopped/killed event, relying on polling for service status")
	case "die":
		m.logger.WithFields(logrus.Fields{
			"project":   projectName,
			"service":   serviceName,
			"container": containerID,
			"exitCode":  event.Actor.Attributes["exitCode"],
		}).Debug("Container died event, relying on polling for service status")
	case "destroy", "remove":
		if contains(service.ContainerIDs, containerID) {
			service.ContainerIDs = remove(service.ContainerIDs, containerID)
			needsUpdate = true
			if len(service.ContainerIDs) == 0 {
				newStatus = models.ServiceStatusExited
			}
		}
	case "health_status: healthy":
		if service.Health == nil {
			service.Health = &models.HealthInfo{} // Use models.HealthInfo
		}
		if service.Health.Status != "healthy" {
			service.Health.Status = "healthy"
			needsUpdate = true
		}
	case "health_status: unhealthy":
		if service.Health == nil {
			service.Health = &models.HealthInfo{} // Use models.HealthInfo
		}
		if service.Health.Status != "unhealthy" {
			service.Health.Status = "unhealthy"
			needsUpdate = true
		}
		newStatus = models.ServiceStatusUnhealthy
	default:
		return
	}

	if needsUpdate && service.Status != newStatus {
		m.logger.WithFields(logrus.Fields{
			"project":    projectName,
			"service":    serviceName,
			"old_status": service.Status,
			"new_status": newStatus,
			"event":      event.Action,
		}).Info("Updating service status based on event")
		service.Status = newStatus
		service.UpdateTime = time.Now()
		m.notifyUpdate(projectName, serviceName, service.Status)
	} else if needsUpdate {
		m.logger.WithFields(logrus.Fields{
			"project": projectName,
			"service": serviceName,
			"status":  service.Status,
			"health":  service.Health.Status,
			"event":   event.Action,
		}).Info("Notifying update due to health or container list change")
		service.UpdateTime = time.Now()
		m.notifyUpdate(projectName, serviceName, service.Status)
	}
}

// startPolling periodically checks the status of containers for tracked projects
func (m *ServiceStatusManager) startPolling(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	m.logger.Infof("Starting status polling every %v", interval)

	for {
		select {
		case <-ticker.C:
			m.pollProjectStatuses()
		case <-m.ctx.Done():
			m.logger.Info("Stopping status polling due to context cancellation")
			return
		}
	}
}

// pollProjectStatuses iterates through tracked projects and updates their status
func (m *ServiceStatusManager) pollProjectStatuses() {
	m.logger.Debug("Polling project statuses")
	m.mu.RLock()
	projectsToPoll := make([]string, 0, len(m.projects))
	for name := range m.projects {
		projectsToPoll = append(projectsToPoll, name)
	}
	m.mu.RUnlock()

	for _, projectName := range projectsToPoll {
		m.updateProjectStatus(projectName)
	}
	m.logger.Debug("Polling finished")
}

// updateProjectStatus fetches container statuses for a project and updates the service statuses
func (m *ServiceStatusManager) updateProjectStatus(projectName string) {
	m.mu.RLock()
	project, exists := m.projects[projectName]
	m.mu.RUnlock()

	if !exists {
		return
	}

	project.mu.Lock()
	defer project.mu.Unlock()

	m.logger.WithField("project", projectName).Debug("Updating status for project")

	// List containers for the project
	projectFilters := filters.NewArgs()
	projectFilters.Add("label", fmt.Sprintf("com.docker_test.compose.project=%s", projectName))

	// Use fully qualified type name
	containers, err := m.client.ContainerList(m.ctx, container.ListOptions{All: true, Filters: projectFilters})
	if err != nil {
		m.logger.WithError(err).WithField("project", projectName).Error("Failed to list containers for project")
		return
	}

	// Map containers to services
	containersByService := make(map[string][]types.Container)
	activeContainerIDs := make(map[string]bool)
	for _, cont := range containers {
		serviceName := cont.Labels["com.docker_test.compose.service"]
		if serviceName != "" {
			containersByService[serviceName] = append(containersByService[serviceName], cont)
			activeContainerIDs[cont.ID] = true
		}
	}

	// Update status for each service in the project
	changed := false
	for serviceName, service := range project.Services {
		serviceContainers := containersByService[serviceName]
		if m.updateServiceStatus(projectName, serviceName, service, serviceContainers) {
			changed = true
		}
	}

	// Remove containers that no longer exist from service lists
	for _, service := range project.Services {
		service.mu.Lock()
		var validIDs []string
		idsChangedInLoop := false
		for _, id := range service.ContainerIDs {
			if activeContainerIDs[id] {
				validIDs = append(validIDs, id)
			} else {
				m.logger.WithFields(logrus.Fields{
					"project":   projectName,
					"service":   service.Name,
					"container": id,
				}).Debug("Removing non-existent container ID from service")
				idsChangedInLoop = true
			}
		}
		if idsChangedInLoop {
			service.ContainerIDs = validIDs
			changed = true
		}
		service.mu.Unlock()
	}

	if changed {
		m.logger.WithField("project", projectName).Debug("Project status potentially changed due to polling")
	}
}

// updateServiceStatus updates the status of a single service based on its containers
// Returns true if the status changed.
func (m *ServiceStatusManager) updateServiceStatus(projectName, serviceName string, service *ServiceStatus, containers []types.Container) bool {
	service.mu.Lock()
	defer service.mu.Unlock()

	oldStatus := service.Status
	newStatus := models.ServiceStatusPending
	var runningCount, totalCount int
	var lastError error
	var healthStatus string = "unknown"

	totalCount = len(containers)
	currentContainerIDs := make(map[string]bool)

	if totalCount > 0 {
		newStatus = models.ServiceStatusExited
		for _, cont := range containers {
			currentContainerIDs[cont.ID] = true
			if cont.State == "running" {
				runningCount++
				newStatus = models.ServiceStatusRunning

				if cont.Status != "" {
					if strings.Contains(cont.Status, "(healthy)") {
						if healthStatus == "unknown" || healthStatus == "healthy" {
							healthStatus = "healthy"
						} else {
							healthStatus = "mixed"
						}
					} else if strings.Contains(cont.Status, "(unhealthy)") {
						healthStatus = "unhealthy"
						newStatus = models.ServiceStatusUnhealthy
					} else if strings.Contains(cont.Status, "(starting)") {
						if healthStatus == "unknown" {
							healthStatus = "starting"
						}
					}
				}

			} else if cont.State == "restarting" {
				newStatus = models.ServiceStatusRestarting
			} else if cont.State == "created" || cont.State == "paused" {
				if newStatus != models.ServiceStatusRunning && newStatus != models.ServiceStatusRestarting {
					newStatus = models.ServiceStatusPending
				}
			} else if cont.State == "dead" {
				newStatus = models.ServiceStatusFailed
			}
		}

		if newStatus == models.ServiceStatusRunning && runningCount < totalCount {
			newStatus = models.ServiceStatusPartial
		} else if newStatus == models.ServiceStatusExited && runningCount > 0 {
			newStatus = models.ServiceStatusPartial
		}
	} else {
		if oldStatus == models.ServiceStatusRunning || oldStatus == models.ServiceStatusPartial || oldStatus == models.ServiceStatusRestarting {
			newStatus = models.ServiceStatusExited
		} else {
			newStatus = models.ServiceStatusPending
		}
	}

	healthChanged := false
	if service.Health == nil && healthStatus != "unknown" {
		service.Health = &models.HealthInfo{Status: healthStatus} // Use models.HealthInfo
		healthChanged = true
	} else if service.Health != nil && service.Health.Status != healthStatus {
		service.Health.Status = healthStatus
		healthChanged = true
	}

	idsChanged := false
	newIDs := make([]string, 0, len(currentContainerIDs))
	existingIDsMap := make(map[string]bool, len(service.ContainerIDs))
	for _, id := range service.ContainerIDs {
		existingIDsMap[id] = true
	}
	for id := range currentContainerIDs {
		newIDs = append(newIDs, id)
		if !existingIDsMap[id] {
			idsChanged = true
		}
	}
	if len(newIDs) != len(service.ContainerIDs) {
		idsChanged = true
	}
	service.ContainerIDs = newIDs

	if service.Status != newStatus || healthChanged || idsChanged {
		m.logger.WithFields(logrus.Fields{
			"project":    projectName,
			"service":    serviceName,
			"old_status": oldStatus,
			"new_status": newStatus,
			"health":     healthStatus,
			"containers": len(service.ContainerIDs),
		}).Info("Updating service status based on polling")
		service.Status = newStatus
		service.Error = lastError
		service.UpdateTime = time.Now()
		m.notifyUpdate(projectName, serviceName, newStatus)
		return true
	}

	return false
}

// AddProject starts tracking a new Compose project
func (m *ServiceStatusManager) AddProject(projectName string, serviceNames []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.projects[projectName]; exists {
		m.logger.WithField("project", projectName).Warn("Project already being tracked, updating service list")
		project := m.projects[projectName]
		project.mu.Lock()
		for _, name := range serviceNames {
			if _, serviceExists := project.Services[name]; !serviceExists {
				project.Services[name] = &ServiceStatus{Name: name, Status: models.ServiceStatusPending}
			}
		}
		project.mu.Unlock()
		return
	}

	m.logger.WithField("project", projectName).Infof("Adding project to status tracking with %d services", len(serviceNames))
	services := make(map[string]*ServiceStatus)
	for _, name := range serviceNames {
		services[name] = &ServiceStatus{Name: name, Status: models.ServiceStatusPending}
	}

	m.projects[projectName] = &ProjectStatus{
		Name:     projectName,
		Services: services,
	}

	go m.updateProjectStatus(projectName)
}

// RemoveProject stops tracking a Compose project
func (m *ServiceStatusManager) RemoveProject(projectName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.projects[projectName]; exists {
		m.logger.WithField("project", projectName).Info("Removing project from status tracking")
		delete(m.projects, projectName)
	} else {
		m.logger.WithField("project", projectName).Warn("Attempted to remove untracked project")
	}
}

// GetProjectStatus retrieves the current status of all services in a project
func (m *ServiceStatusManager) GetProjectStatus(projectName string) (map[string]models.ServiceStatusInfo, bool) {
	m.mu.RLock()
	project, exists := m.projects[projectName]
	m.mu.RUnlock()

	if !exists {
		return nil, false
	}

	project.mu.RLock()
	defer project.mu.RUnlock()

	statuses := make(map[string]models.ServiceStatusInfo)
	for name, service := range project.Services {
		service.mu.RLock()
		statusInfo := models.ServiceStatusInfo{
			Name:         service.Name,
			Status:       service.Status,
			ContainerIDs: append([]string{}, service.ContainerIDs...),
			UpdateTime:   service.UpdateTime,
		}
		if service.Health != nil {
			statusInfo.HealthStatus = service.Health.Status
		}
		if service.Error != nil {
			statusInfo.Error = service.Error.Error()
		}
		service.mu.RUnlock()
		statuses[name] = statusInfo
	}

	return statuses, true
}

// Watch returns a channel that receives updates for any tracked project
func (m *ServiceStatusManager) Watch() <-chan models.DeploymentUpdate {
	m.watchersMu.Lock()
	defer m.watchersMu.Unlock()

	ch := make(chan models.DeploymentUpdate, 100)
	m.watchers[ch] = true
	m.logger.Debug("Added new status watcher")
	return ch
}

// Unwatch stops sending updates to a specific channel
func (m *ServiceStatusManager) Unwatch(ch chan models.DeploymentUpdate) {
	m.watchersMu.Lock()
	defer m.watchersMu.Unlock()

	if _, ok := m.watchers[ch]; ok {
		delete(m.watchers, ch)
		close(ch)
		m.logger.Debug("Removed status watcher")
	}
}

// notifyUpdate sends status updates to the main channel and all watchers
func (m *ServiceStatusManager) notifyUpdate(projectName, serviceName string, status models.ServiceStatus) {
	update := models.DeploymentUpdate{
		ProjectName: projectName,
		ServiceName: serviceName,
		Status:      status,
		Timestamp:   time.Now(),
	}

	if m.updateChannel != nil {
		select {
		case m.updateChannel <- update:
		default:
			m.logger.WithFields(logrus.Fields{
				"project": projectName,
				"service": serviceName,
			}).Warn("Update channel is full, discarding status update")
		}
	}

	m.watchersMu.RLock()
	for ch := range m.watchers {
		select {
		case ch <- update:
		default:
			m.logger.WithFields(logrus.Fields{
				"project": projectName,
				"service": serviceName,
			}).Warn("Watcher channel is full, discarding status update for watcher")
		}
	}
	m.watchersMu.RUnlock()
}

// Stop stops the ServiceStatusManager and cleans up resources
func (m *ServiceStatusManager) Stop() {
	m.logger.Info("Stopping Service Status Manager")
	m.cancel()
	m.StopEventMonitoring()

	m.watchersMu.Lock()
	for ch := range m.watchers {
		delete(m.watchers, ch)
		close(ch)
	}
	m.watchersMu.Unlock()
	m.logger.Info("Service Status Manager stopped")
}

// StopEventMonitoring stops the Docker event monitoring stream
func (m *ServiceStatusManager) StopEventMonitoring() {
	m.mu.Lock()         // Lock before accessing shared resources
	defer m.mu.Unlock() // Ensure unlock even if panic occurs

	if m.eventCancel != nil {
		m.logger.Debug("Cancelling event monitoring context")
		m.eventCancel()
		m.eventCancel = nil // Nil out within lock
		m.eventStream = nil // Nil out within lock
		m.errStream = nil   // Nil out within lock
	}
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func remove(slice []string, item string) []string {
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}
