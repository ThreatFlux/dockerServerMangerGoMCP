// Package state provides utilities for container state management
package state

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container" // Add container import
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters" // Add filters import
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Remove unused import
)

// ContainerState represents the possible states of a container
type ContainerState string

const (
	// StateCreated represents a created container
	StateCreated ContainerState = "created"
	// StateRunning represents a running container
	StateRunning ContainerState = "running"
	// StatePaused represents a paused container
	StatePaused ContainerState = "paused"
	// StateRestarting represents a restarting container
	StateRestarting ContainerState = "restarting"
	// StateRemoving represents a container being removed
	StateRemoving ContainerState = "removing"
	// StateExited represents an exited container
	StateExited ContainerState = "exited"
	// StateDead represents a dead container
	StateDead ContainerState = "dead"
	// StateUnknown represents an unknown container state
	StateUnknown ContainerState = "unknown"
)

// ValidStates is a list of all valid container states
var ValidStates = []ContainerState{
	StateCreated,
	StateRunning,
	StatePaused,
	StateRestarting,
	StateRemoving,
	StateExited,
	StateDead,
	StateUnknown,
}

// ValidStateTransitions defines the valid state transitions for containers
var ValidStateTransitions = map[ContainerState][]ContainerState{
	StateCreated:    {StateRunning, StateExited}, // Removed StateRemoving
	StateRunning:    {StatePaused, StateExited, StateRestarting, StateRemoving},
	StatePaused:     {StateRunning, StateRemoving},
	StateRestarting: {StateRunning, StateExited},
	StateExited:     {StateRunning, StateRemoving},
	StateDead:       {StateRemoving},
	StateRemoving:   {},
	StateUnknown:    ValidStates, // Allow transitions from unknown to any state
}

// ErrInvalidStateTransition is returned when a state transition is invalid
var ErrInvalidStateTransition = errors.New("invalid container state transition")

// Manager manages container state tracking and transitions
type Manager struct {
	client        client.APIClient
	logger        *logrus.Logger
	containers    map[string]*ContainerInfo
	eventHandlers map[ContainerState][]StateChangeHandler
	mu            sync.RWMutex
	watchContext  context.Context
	watchCancel   context.CancelFunc
	isWatching    bool
}

// ContainerInfo holds information about a container
type ContainerInfo struct {
	ID            string
	Name          string
	CurrentState  ContainerState
	PreviousState ContainerState
	ExitCode      int
	LastUpdated   time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
	Error         string
	RestartCount  int
	HealthStatus  string
}

// StateChangeHandler is a callback for state changes
type StateChangeHandler func(containerID string, oldState, newState ContainerState, info *ContainerInfo)

// NewManager creates a new container state manager
func NewManager(client client.APIClient, logger *logrus.Logger) *Manager {
	if logger == nil {
		logger = logrus.New()
	}

	watchCtx, cancel := context.WithCancel(context.Background())

	return &Manager{
		client:        client,
		logger:        logger,
		containers:    make(map[string]*ContainerInfo),
		eventHandlers: make(map[ContainerState][]StateChangeHandler),
		watchContext:  watchCtx,
		watchCancel:   cancel,
	}
}

// GetState gets the current state of a container
func (m *Manager) GetState(containerID string) (ContainerState, error) {
	// First check if we have it cached
	m.mu.RLock()
	info, exists := m.containers[containerID]
	m.mu.RUnlock()

	if exists {
		return info.CurrentState, nil
	}

	// If not cached, check from Docker API
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	containerJSON, err := m.client.ContainerInspect(ctx, containerID)
	if err != nil {
		if client.IsErrNotFound(err) {
			return StateUnknown, fmt.Errorf("container not found: %s", containerID)
		}
		return StateUnknown, fmt.Errorf("failed to inspect container: %w", err)
	}

	state := mapDockerStateToContainerState(containerJSON.State)

	// Cache the container info
	m.cacheContainerInfo(containerJSON)

	return state, nil
}

// RegisterStateChangeHandler registers a callback for a specific state transition
func (m *Manager) RegisterStateChangeHandler(state ContainerState, handler StateChangeHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.eventHandlers[state]; !exists {
		m.eventHandlers[state] = make([]StateChangeHandler, 0)
	}

	m.eventHandlers[state] = append(m.eventHandlers[state], handler)
}

// StartWatching starts watching for container state changes
func (m *Manager) StartWatching() error {
	m.mu.Lock()
	if m.isWatching {
		m.mu.Unlock()
		return nil // Already watching
	}
	m.isWatching = true
	m.mu.Unlock()

	// Configure filters for container events
	eventFilters := filters.NewArgs() // Create filters.Args
	eventFilters.Add("type", "container")
	options := events.ListOptions{ // Use events.ListOptions
		Filters: eventFilters,
	}

	// Get event stream from Docker
	eventCh, errCh := m.client.Events(m.watchContext, options) // Use options variable

	// Process events in a goroutine
	go func() {
		for {
			select {
			case event := <-eventCh:
				m.handleEvent(event)
			case err := <-errCh:
				if err != nil {
					m.logger.WithError(err).Error("Error watching container events")
				}
				// Stop watching on error
				m.StopWatching()
				return
			case <-m.watchContext.Done():
				return
			}
		}
	}()

	// Initialize container states
	err := m.initializeContainerStates()
	if err != nil {
		m.logger.WithError(err).Error("Failed to initialize container states")
		return err
	}

	return nil
}

// StopWatching stops watching for container state changes
func (m *Manager) StopWatching() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isWatching {
		return
	}

	m.watchCancel()
	m.isWatching = false

	// Create a new context for future watches
	m.watchContext, m.watchCancel = context.WithCancel(context.Background())
}

// UpdateState updates the state of a container
func (m *Manager) UpdateState(containerID string, state ContainerState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get current container info
	info, exists := m.containers[containerID]
	if !exists {
		// Create new container info if not exists
		info = &ContainerInfo{
			ID:           containerID,
			CurrentState: StateUnknown,
			LastUpdated:  time.Now(),
		}
		m.containers[containerID] = info
	}

	// Validate state transition
	if err := m.validateStateTransition(info.CurrentState, state); err != nil {
		return err
	}

	// Update state
	info.PreviousState = info.CurrentState
	info.CurrentState = state
	info.LastUpdated = time.Now()

	// Call handlers
	m.callHandlers(containerID, info.PreviousState, state, info)

	return nil
}

// IsValidTransition checks if a state transition is valid
func (m *Manager) IsValidTransition(fromState, toState ContainerState) bool {
	validTransitions, exists := ValidStateTransitions[fromState]
	if !exists {
		return false
	}

	for _, validState := range validTransitions {
		if validState == toState {
			return true
		}
	}

	return false
}

// validateStateTransition validates a state transition
func (m *Manager) validateStateTransition(fromState, toState ContainerState) error {
	if !m.IsValidTransition(fromState, toState) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidStateTransition, fromState, toState)
	}
	return nil
}

// initializeContainerStates initializes the states of all containers
func (m *Manager) initializeContainerStates() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// List all containers
	containers, err := m.client.ContainerList(ctx, container.ListOptions{ // Use container.ListOptions
		All: true,
	})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	// Initialize container states
	for _, container := range containers {
		containerJSON, err := m.client.ContainerInspect(ctx, container.ID)
		if err != nil {
			m.logger.WithError(err).WithField("container_id", container.ID).
				Warn("Failed to inspect container during initialization")
			continue
		}

		m.cacheContainerInfo(containerJSON)
	}

	return nil
}

// cacheContainerInfo caches container information
func (m *Manager) cacheContainerInfo(containerJSON types.ContainerJSON) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := mapDockerStateToContainerState(containerJSON.State)

	exitCode := 0
	if containerJSON.State != nil {
		exitCode = containerJSON.State.ExitCode
	}

	var startTime, finishTime time.Time
	if containerJSON.State != nil {
		startTime, _ = time.Parse(time.RFC3339Nano, containerJSON.State.StartedAt)
		finishTime, _ = time.Parse(time.RFC3339Nano, containerJSON.State.FinishedAt)
	}

	healthStatus := ""
	if containerJSON.State != nil && containerJSON.State.Health != nil {
		healthStatus = containerJSON.State.Health.Status
	}

	m.containers[containerJSON.ID] = &ContainerInfo{
		ID:            containerJSON.ID,
		Name:          containerJSON.Name,
		CurrentState:  state,
		PreviousState: state, // Set the same state initially
		ExitCode:      exitCode,
		LastUpdated:   time.Now(),
		StartedAt:     startTime,
		FinishedAt:    finishTime,
		RestartCount:  containerJSON.RestartCount,
		HealthStatus:  healthStatus,
	}
}

// handleEvent handles a Docker event
func (m *Manager) handleEvent(event events.Message) {
	if event.Type != "container" {
		return
	}

	containerID := event.ID
	var newState ContainerState

	// Map Docker events to container states
	switch event.Action {
	case "create":
		newState = StateCreated
	case "start":
		newState = StateRunning
	case "die":
		newState = StateExited
	case "destroy":
		newState = StateRemoving
	case "kill":
		// A kill event doesn't necessarily change the state
		state, err := m.GetState(containerID)
		if err != nil {
			m.logger.WithError(err).WithField("container_id", containerID).
				Warn("Failed to get container state for kill event")
			return
		}
		newState = state
	case "pause":
		newState = StatePaused
	case "unpause":
		newState = StateRunning
	case "restart":
		newState = StateRestarting
	case "stop":
		newState = StateExited
	case "health_status":
		// Update health status without changing state
		m.mu.Lock()
		if info, exists := m.containers[containerID]; exists {
			if healthStatus, ok := event.Actor.Attributes["health_status"]; ok {
				info.HealthStatus = healthStatus
				info.LastUpdated = time.Now()
			}
		}
		m.mu.Unlock()
		return
	default:
		// Ignore other events
		return
	}

	// Update container state
	err := m.UpdateState(containerID, newState)
	if err != nil {
		m.logger.WithError(err).WithFields(logrus.Fields{
			"container_id": containerID,
			"action":       event.Action,
			"new_state":    newState,
		}).Warn("Failed to update container state")
	}
}

// callHandlers calls registered handlers for a state change
func (m *Manager) callHandlers(containerID string, oldState, newState ContainerState, info *ContainerInfo) {
	// Call handlers for the specific state
	if handlers, exists := m.eventHandlers[newState]; exists {
		for _, handler := range handlers {
			go handler(containerID, oldState, newState, info)
		}
	}

	// Call handlers for all states (using StateUnknown as a wildcard)
	if handlers, exists := m.eventHandlers[StateUnknown]; exists {
		for _, handler := range handlers {
			go handler(containerID, oldState, newState, info)
		}
	}
}

// GetContainerInfo gets information about a container
func (m *Manager) GetContainerInfo(containerID string) (*ContainerInfo, error) {
	m.mu.RLock()
	info, exists := m.containers[containerID]
	m.mu.RUnlock()

	if exists {
		return info, nil
	}

	// Fetch from Docker API if not in cache
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	containerJSON, err := m.client.ContainerInspect(ctx, containerID)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, fmt.Errorf("container not found: %s", containerID)
		}
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	m.cacheContainerInfo(containerJSON)

	m.mu.RLock()
	info = m.containers[containerID]
	m.mu.RUnlock()

	return info, nil
}

// ListContainers lists all tracked containers and their states
func (m *Manager) ListContainers() map[string]ContainerState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make(map[string]ContainerState)
	for id, info := range m.containers {
		states[id] = info.CurrentState
	}

	return states
}

// mapDockerStateToContainerState maps Docker state to our ContainerState type
func mapDockerStateToContainerState(dockerState *types.ContainerState) ContainerState {
	if dockerState == nil {
		return StateUnknown
	}

	switch {
	case dockerState.Status == "created":
		return StateCreated
	case dockerState.Running:
		return StateRunning
	case dockerState.Paused:
		return StatePaused
	case dockerState.Restarting:
		return StateRestarting
	case dockerState.Dead:
		return StateDead
	case dockerState.Status == "removing":
		return StateRemoving
	case dockerState.Status == "exited":
		return StateExited
	default:
		return StateUnknown
	}
}
