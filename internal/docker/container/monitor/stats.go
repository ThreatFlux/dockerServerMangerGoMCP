// Package monitor provides utilities for monitoring Docker containers
package monitor

import (
	"context"
	"encoding/json"
	"errors" // Added import
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container" // Keep container import
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// AlertType represents the type of resource alert
type AlertType string

const (
	// AlertCPU indicates CPU usage alert
	AlertCPU AlertType = "cpu"
	// AlertMemory indicates memory usage alert
	AlertMemory AlertType = "memory"
	// AlertDisk indicates disk usage alert
	AlertDisk AlertType = "disk"
	// AlertNetwork indicates network usage alert
	AlertNetwork AlertType = "network"
	// AlertPIDs indicates process count alert
	AlertPIDs AlertType = "pids"
	// AlertHealth indicates health check alert
	AlertHealth AlertType = "health"
)

// AlertLevel represents the severity of an alert
type AlertLevel string

const (
	// AlertInfo is informational level
	AlertInfo AlertLevel = "info"
	// AlertWarning is warning level
	AlertWarning AlertLevel = "warning"
	// AlertCritical is critical level
	AlertCritical AlertLevel = "critical"
)

// ResourceAlert represents a resource usage alert
type ResourceAlert struct {
	ContainerID   string
	ContainerName string
	Type          AlertType
	Level         AlertLevel
	Message       string
	Value         float64
	Threshold     float64
	Timestamp     time.Time
}

// AlertHandler is a callback function for alerts
type AlertHandler func(alert ResourceAlert)

// Thresholds defines resource usage thresholds for monitoring
type Thresholds struct {
	// CPU thresholds (percentage)
	CPUWarning  float64
	CPUCritical float64

	// Memory thresholds (percentage)
	MemoryWarning  float64
	MemoryCritical float64

	// Disk thresholds (bytes) - Note: These are typically for total usage, not rate.
	// Rate thresholds might need different configuration.
	DiskWarning  int64
	DiskCritical int64

	// Network thresholds (bytes per second)
	NetworkRxWarning  int64
	NetworkRxCritical int64
	NetworkTxWarning  int64
	NetworkTxCritical int64

	// PIDs thresholds (count)
	PIDsWarning  uint64
	PIDsCritical uint64
}

// DefaultThresholds provides default monitoring thresholds
var DefaultThresholds = Thresholds{
	CPUWarning:        70.0,
	CPUCritical:       90.0,
	MemoryWarning:     80.0,
	MemoryCritical:    95.0,
	DiskWarning:       1024 * 1024 * 1024 * 20, // 20GB (Example for total usage, adjust if rate needed)
	DiskCritical:      1024 * 1024 * 1024 * 50, // 50GB (Example for total usage, adjust if rate needed)
	NetworkRxWarning:  1024 * 1024 * 10,        // 10MB/s
	NetworkRxCritical: 1024 * 1024 * 50,        // 50MB/s
	NetworkTxWarning:  1024 * 1024 * 10,        // 10MB/s
	NetworkTxCritical: 1024 * 1024 * 50,        // 50MB/s
	PIDsWarning:       100,
	PIDsCritical:      500,
}

// StatsOptions defines options for container stats monitoring
type StatsOptions struct {
	Interval            time.Duration
	Thresholds          Thresholds
	HistorySize         int
	Stream              bool
	FilterContainers    []string
	AlertHandlers       map[AlertType][]AlertHandler
	DefaultAlertHandler AlertHandler
	Logger              *logrus.Logger
}

// Monitor provides functionality for monitoring container stats
type Monitor struct {
	client         client.APIClient
	options        StatsOptions
	containers     map[string]*containerMonitor
	containersByID map[string]*containerMonitor
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	throttle       *utils.Throttle
	logger         *logrus.Logger
}

// containerMonitor holds monitoring state for a container
type containerMonitor struct {
	containerID   string
	containerName string
	statsCh       chan *container.Stats   // Channel for receiving raw stats
	cancelFunc    context.CancelFunc      // To stop the monitor goroutine
	history       []models.ContainerStats // Ring buffer of recent stats
	currentStats  models.ContainerStats   // Latest processed stats
	previousStats models.ContainerStats   // Previous stats for rate calculation
	mu            sync.RWMutex            // Protects access to stats fields
}

// NewMonitor creates a new container stats monitor
func NewMonitor(client client.APIClient, options StatsOptions) *Monitor {
	// Set default values
	if options.Interval == 0 {
		options.Interval = 10 * time.Second
	}
	if options.HistorySize == 0 {
		options.HistorySize = 60
	}
	if options.Logger == nil {
		options.Logger = logrus.New()
		options.Logger.SetLevel(logrus.InfoLevel) // Default level
	}
	if options.Thresholds == (Thresholds{}) {
		options.Thresholds = DefaultThresholds
	}
	if options.AlertHandlers == nil {
		options.AlertHandlers = make(map[AlertType][]AlertHandler)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Monitor{
		client:         client,
		options:        options,
		containers:     make(map[string]*containerMonitor),
		containersByID: make(map[string]*containerMonitor),
		ctx:            ctx,
		cancel:         cancel,
		throttle:       utils.NewThrottle(10, time.Second), // Max 10 API calls per second
		logger:         options.Logger,
	}
}

// Start starts the monitor
func (m *Monitor) Start() error {
	containers, err := m.listContainers()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	for _, c := range containers { // Renamed loop variable
		containerID := c.ID
		containerName := strings.TrimPrefix(c.Names[0], "/")

		if len(m.options.FilterContainers) > 0 {
			inFilter := false
			for _, filteredContainer := range m.options.FilterContainers {
				if filteredContainer == containerID || filteredContainer == containerName {
					inFilter = true
					break
				}
			}
			if !inFilter {
				continue
			}
		}

		err := m.startContainerMonitor(containerID, containerName)
		if err != nil {
			m.logger.WithError(err).WithFields(logrus.Fields{
				"container_id":   containerID,
				"container_name": containerName,
			}).Warn("Failed to start monitoring container")
		}
	}
	return nil
}

// Stop stops the monitor
func (m *Monitor) Stop() {
	m.cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cm := range m.containers {
		if cm.cancelFunc != nil {
			cm.cancelFunc()
		}
	}
	m.containers = make(map[string]*containerMonitor)
	m.containersByID = make(map[string]*containerMonitor)
}

// GetCurrentStats gets the current stats for a container
func (m *Monitor) GetCurrentStats(containerName string) (models.ContainerStats, error) { // Use containerName for clarity
	m.mu.RLock()
	cm, exists := m.getContainerMonitor(containerName)
	m.mu.RUnlock()

	if !exists {
		containerID, err := m.resolveContainerID(containerName)
		if err != nil {
			return models.ContainerStats{}, err
		}
		return m.getContainerStats(containerID)
	}

	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.currentStats, nil
}

// GetStatsHistory gets the stats history for a container
func (m *Monitor) GetStatsHistory(containerName string) ([]models.ContainerStats, error) { // Use containerName for clarity
	m.mu.RLock()
	cm, exists := m.getContainerMonitor(containerName)
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("container %s is not being monitored", containerName)
	}

	cm.mu.RLock()
	defer cm.mu.RUnlock()
	history := make([]models.ContainerStats, len(cm.history))
	copy(history, cm.history)
	return history, nil
}

// AddAlertHandler adds an alert handler for a specific alert type
func (m *Monitor) AddAlertHandler(alertType AlertType, handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.options.AlertHandlers[alertType]; !exists {
		m.options.AlertHandlers[alertType] = make([]AlertHandler, 0)
	}
	m.options.AlertHandlers[alertType] = append(m.options.AlertHandlers[alertType], handler)
}

// SetDefaultAlertHandler sets the default alert handler
func (m *Monitor) SetDefaultAlertHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.options.DefaultAlertHandler = handler
}

// MonitorContainer starts monitoring a specific container
func (m *Monitor) MonitorContainer(containerName string) error { // Use containerName for clarity
	m.mu.RLock()
	_, exists := m.getContainerMonitor(containerName)
	m.mu.RUnlock()
	if exists {
		return nil // Already monitoring
	}

	containerID, err := m.resolveContainerID(containerName)
	if err != nil {
		return err
	}

	// Get container name (might be redundant if resolveContainerID already found it by name)
	// But inspect is needed anyway if resolveContainerID found by ID initially
	containerJSON, err := m.client.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %w", err)
	}
	actualContainerName := strings.TrimPrefix(containerJSON.Name, "/") // Use the actual name from inspect

	return m.startContainerMonitor(containerID, actualContainerName)
}

// StopMonitoringContainer stops monitoring a specific container
func (m *Monitor) StopMonitoringContainer(containerNameOrID string) error { // Accept name or ID
	m.mu.Lock()
	defer m.mu.Unlock()
	cm, exists := m.getContainerMonitor(containerNameOrID)
	if !exists {
		return nil // Not monitoring
	}
	if cm.cancelFunc != nil {
		cm.cancelFunc()
	}
	delete(m.containers, cm.containerName)
	delete(m.containersByID, cm.containerID)
	return nil
}

// SetThresholds sets the monitoring thresholds
func (m *Monitor) SetThresholds(thresholds Thresholds) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.options.Thresholds = thresholds
}

// GetThresholds gets the current monitoring thresholds
func (m *Monitor) GetThresholds() Thresholds {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.options.Thresholds
}

// MonitoredContainers returns a list of currently monitored containers
func (m *Monitor) MonitoredContainers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	containers := make([]string, 0, len(m.containersByID))
	for id := range m.containersByID {
		containers = append(containers, id)
	}
	return containers
}

// listContainers lists all running containers
func (m *Monitor) listContainers() ([]types.Container, error) {
	err := m.throttle.Wait(m.ctx)
	if err != nil {
		return nil, fmt.Errorf("throttle error: %w", err)
	}
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()
	// Use container.ListOptions
	return m.client.ContainerList(ctx, container.ListOptions{})
}

// startContainerMonitor starts monitoring a container
func (m *Monitor) startContainerMonitor(containerID, containerName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.containersByID[containerID]; exists {
		return nil // Already monitoring
	}

	statsCh := make(chan *container.Stats, 10) // Use container.Stats
	ctx, cancel := context.WithCancel(m.ctx)

	cm := &containerMonitor{
		containerID:   containerID,
		containerName: containerName,
		statsCh:       statsCh,
		cancelFunc:    cancel,
		history:       make([]models.ContainerStats, 0, m.options.HistorySize),
		previousStats: models.ContainerStats{Time: time.Time{}}, // Initialize previous stats time
	}

	m.containers[containerName] = cm
	m.containersByID[containerID] = cm

	go m.monitorStats(ctx, cm, statsCh)
	go m.streamStats(ctx, containerID, statsCh)

	return nil
}

// getContainerMonitor returns the container monitor for a container by ID or name
func (m *Monitor) getContainerMonitor(containerNameOrID string) (*containerMonitor, bool) { // Accept name or ID
	// Try by ID first
	if cm, exists := m.containersByID[containerNameOrID]; exists {
		return cm, true
	}
	// Try by name
	if cm, exists := m.containers[containerNameOrID]; exists {
		return cm, true
	}
	return nil, false
}

// resolveContainerID resolves a container name to its ID
func (m *Monitor) resolveContainerID(containerNameOrID string) (string, error) { // Accept name or ID
	// Check if it's already an ID we know
	if _, exists := m.containersByID[containerNameOrID]; exists {
		return containerNameOrID, nil
	}
	// Check if it's a name we know
	if cm, exists := m.containers[containerNameOrID]; exists {
		return cm.containerID, nil
	}

	// Need to look up via Docker API
	err := m.throttle.Wait(m.ctx)
	if err != nil {
		return "", fmt.Errorf("throttle error: %w", err)
	}
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()

	// Try inspecting directly (works for both ID and unique name)
	containerJSON, err := m.client.ContainerInspect(ctx, containerNameOrID)
	if err == nil {
		return containerJSON.ID, nil
	}
	// If inspect failed, it might be a non-unique name or doesn't exist
	if !client.IsErrNotFound(err) {
		// Return error if it wasn't a "not found" type error
		return "", fmt.Errorf("failed to inspect container '%s': %w", containerNameOrID, err)
	}

	// If inspect failed with "not found", list containers to find by name (less efficient)
	// Use container.ListOptions
	containers, listErr := m.client.ContainerList(ctx, container.ListOptions{All: true})
	if listErr != nil {
		return "", fmt.Errorf("failed to list containers after inspect failed: %w", listErr)
	}

	foundID := ""
	for _, c := range containers {
		for _, name := range c.Names {
			// Docker names have a leading slash
			cleanedName := strings.TrimPrefix(name, "/")
			if cleanedName == containerNameOrID {
				if foundID != "" && foundID != c.ID {
					return "", fmt.Errorf("multiple containers found with name '%s'", containerNameOrID)
				}
				foundID = c.ID
			}
		}
	}

	if foundID == "" {
		return "", fmt.Errorf("container not found: %s", containerNameOrID)
	}
	return foundID, nil
}

// monitorStats processes stats received from the channel
func (m *Monitor) monitorStats(ctx context.Context, cm *containerMonitor, statsCh chan *container.Stats) {
	ticker := time.NewTicker(m.options.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.WithField("container_id", cm.containerID).Info("Stopping stats monitor")
			return
		case stats, ok := <-statsCh:
			if !ok {
				m.logger.WithField("container_id", cm.containerID).Info("Stats channel closed")
				return
			}
			if stats == nil {
				continue // Skip nil stats
			}

			// Process stats using the converter
			newStats := m.processStats(cm, stats)

			// Check for alerts using the new stats and the previously stored stats
			cm.mu.RLock()
			canCheckAlerts := !cm.previousStats.Time.IsZero()
			cm.mu.RUnlock()

			if canCheckAlerts {
				m.checkAlerts(cm, newStats) // Pass newStats here
			}

			// Update current stats, previous stats, and history
			cm.mu.Lock()
			cm.previousStats = cm.currentStats // Store old current as previous
			cm.currentStats = newStats         // Update current
			// Add to history, maintaining size limit
			if len(cm.history) >= m.options.HistorySize {
				cm.history = cm.history[1:] // Remove the oldest entry
			}
			cm.history = append(cm.history, newStats)
			cm.mu.Unlock()

		case <-ticker.C:
			// Periodically check if the container is still running
			inspectCtx, inspectCancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := m.client.ContainerInspect(inspectCtx, cm.containerID)
			inspectCancel()
			if err != nil {
				m.logger.WithError(err).WithField("container_id", cm.containerID).Warn("Container inspect failed, stopping monitor")
				m.StopMonitoringContainer(cm.containerID) // Use StopMonitoringContainer
				return
			}
		}
	}
}

// streamStats continuously streams stats for a container
func (m *Monitor) streamStats(ctx context.Context, containerID string, statsCh chan *container.Stats) {
	defer close(statsCh) // Close channel when done

	for {
		select {
		case <-ctx.Done():
			return // Stop streaming if context is cancelled
		default:
			err := m.throttle.Wait(ctx)
			if err != nil {
				m.logger.WithError(err).WithField("container_id", containerID).Error("Throttle error during stats stream")
				time.Sleep(5 * time.Second) // Wait before retrying
				continue
			}

			statsResp, err := m.client.ContainerStats(ctx, containerID, true) // Stream is true
			if err != nil {
				m.logger.WithError(err).WithField("container_id", containerID).Error("Failed to get container stats stream")
				time.Sleep(m.options.Interval) // Wait before retrying
				continue
			}

			decoder := json.NewDecoder(statsResp.Body)
			for {
				var stats *container.Stats // Use container.Stats
				if err := decoder.Decode(&stats); err != nil {
					if err == io.EOF || errors.Is(err, context.Canceled) { // Use imported errors package
						m.logger.WithField("container_id", containerID).Info("Stats stream ended or context cancelled")
					} else {
						m.logger.WithError(err).WithField("container_id", containerID).Error("Failed to decode stats JSON")
					}
					statsResp.Body.Close() // Close the body reader
					goto retryStream       // Break inner loop and retry stream
				}

				// Send stats to the processing channel
				select {
				case statsCh <- stats:
				case <-ctx.Done():
					statsResp.Body.Close()
					return
				}

				// Check if the context was cancelled after sending
				if ctx.Err() != nil {
					statsResp.Body.Close()
					return
				}
			}
		retryStream:
			// Wait before attempting to reconnect the stream
			select {
			case <-time.After(m.options.Interval):
			case <-ctx.Done():
				return
			}
		}
	}
}

// processStats converts raw Docker stats into the internal model format.
// It relies on models.FromDockerStatsJSON for the conversion.
// Rate calculations are handled separately in checkAlerts.
func (m *Monitor) processStats(cm *containerMonitor, stats *container.Stats) models.ContainerStats {
	modelStats := models.FromDockerStatsJSON(stats)
	if modelStats == nil {
		m.logger.WithField("container_id", cm.containerID).Error("FromDockerStatsJSON returned nil")
		return models.ContainerStats{} // Return empty stats
	}
	return *modelStats
}

// checkAlerts checks for resource usage alerts
func (m *Monitor) checkAlerts(cm *containerMonitor, currentStats models.ContainerStats) {
	// Lock the container monitor to safely access previousStats
	cm.mu.RLock()
	previousStats := cm.previousStats
	cm.mu.RUnlock()

	// Ensure previousStats is initialized before calculating rates
	if previousStats.Time.IsZero() {
		m.logger.WithField("container_id", cm.containerID).Debug("Skipping alert check on first stats received")
		return
	}

	timeDelta := currentStats.Time.Sub(previousStats.Time).Seconds()

	// Avoid division by zero or negative time delta
	if timeDelta <= 0 {
		m.logger.WithFields(logrus.Fields{
			"container_id": cm.containerID,
			"time_delta":   timeDelta,
		}).Warn("Skipping rate calculation due to non-positive time delta")
		return // Cannot calculate rates, skip alerts for this cycle
	}

	// Calculate Network rates (Bytes per second)
	networkRxRate := int64(0)
	// Use NetworkRx from models.ContainerStats (which is int64)
	if currentStats.NetworkRx >= previousStats.NetworkRx {
		networkRxRate = int64(float64(currentStats.NetworkRx-previousStats.NetworkRx) / timeDelta)
	}
	networkTxRate := int64(0)
	// Use NetworkTx from models.ContainerStats (which is int64)
	if currentStats.NetworkTx >= previousStats.NetworkTx {
		networkTxRate = int64(float64(currentStats.NetworkTx-previousStats.NetworkTx) / timeDelta)
	}

	// Calculate Disk rates (Bytes per second)
	diskReadRate := int64(0)
	// Use BlockRead from models.ContainerStats (which is int64)
	if currentStats.BlockRead >= previousStats.BlockRead {
		diskReadRate = int64(float64(currentStats.BlockRead-previousStats.BlockRead) / timeDelta)
	}
	diskWriteRate := int64(0)
	// Use BlockWrite from models.ContainerStats (which is int64)
	if currentStats.BlockWrite >= previousStats.BlockWrite {
		diskWriteRate = int64(float64(currentStats.BlockWrite-previousStats.BlockWrite) / timeDelta)
	}

	// --- Check Alerts using calculated rates and current stats ---

	// Check CPU usage
	if currentStats.CPUPercentage >= m.options.Thresholds.CPUCritical {
		m.sendAlert(ResourceAlert{
			ContainerID: cm.containerID, ContainerName: cm.containerName, Type: AlertCPU, Level: AlertCritical,
			Message: fmt.Sprintf("CPU usage critical: %.2f%%", currentStats.CPUPercentage),
			Value:   currentStats.CPUPercentage, Threshold: m.options.Thresholds.CPUCritical, Timestamp: currentStats.Time,
		})
	} else if currentStats.CPUPercentage >= m.options.Thresholds.CPUWarning {
		m.sendAlert(ResourceAlert{
			ContainerID: cm.containerID, ContainerName: cm.containerName, Type: AlertCPU, Level: AlertWarning,
			Message: fmt.Sprintf("CPU usage warning: %.2f%%", currentStats.CPUPercentage),
			Value:   currentStats.CPUPercentage, Threshold: m.options.Thresholds.CPUWarning, Timestamp: currentStats.Time,
		})
	}

	// Check Memory usage
	if currentStats.MemoryPercentage >= m.options.Thresholds.MemoryCritical {
		m.sendAlert(ResourceAlert{
			ContainerID: cm.containerID, ContainerName: cm.containerName, Type: AlertMemory, Level: AlertCritical,
			Message: fmt.Sprintf("Memory usage critical: %.2f%% (%s / %s)", currentStats.MemoryPercentage, formatBytes(int64(currentStats.MemoryUsage)), formatBytes(int64(currentStats.MemoryLimit))),
			Value:   currentStats.MemoryPercentage, Threshold: m.options.Thresholds.MemoryCritical, Timestamp: currentStats.Time,
		})
	} else if currentStats.MemoryPercentage >= m.options.Thresholds.MemoryWarning {
		m.sendAlert(ResourceAlert{
			ContainerID: cm.containerID, ContainerName: cm.containerName, Type: AlertMemory, Level: AlertWarning,
			Message: fmt.Sprintf("Memory usage warning: %.2f%% (%s / %s)", currentStats.MemoryPercentage, formatBytes(int64(currentStats.MemoryUsage)), formatBytes(int64(currentStats.MemoryLimit))),
			Value:   currentStats.MemoryPercentage, Threshold: m.options.Thresholds.MemoryWarning, Timestamp: currentStats.Time,
		})
	}

	// Check Network RX rate (using calculated networkRxRate)
	if networkRxRate >= m.options.Thresholds.NetworkRxCritical {
		m.sendAlert(ResourceAlert{
			ContainerID: cm.containerID, ContainerName: cm.containerName, Type: AlertNetwork, Level: AlertCritical,
			Message: fmt.Sprintf("Network receive rate critical: %s/s", formatBytes(networkRxRate)),
			Value:   float64(networkRxRate), Threshold: float64(m.options.Thresholds.NetworkRxCritical), Timestamp: currentStats.Time,
		})
	} else if networkRxRate >= m.options.Thresholds.NetworkRxWarning {
		m.sendAlert(ResourceAlert{
			ContainerID: cm.containerID, ContainerName: cm.containerName, Type: AlertNetwork, Level: AlertWarning,
			Message: fmt.Sprintf("Network receive rate warning: %s/s", formatBytes(networkRxRate)),
			Value:   float64(networkRxRate), Threshold: float64(m.options.Thresholds.NetworkRxWarning), Timestamp: currentStats.Time,
		})
	}

	// Check Network TX rate (using calculated networkTxRate)
	if networkTxRate >= m.options.Thresholds.NetworkTxCritical {
		m.sendAlert(ResourceAlert{
			ContainerID: cm.containerID, ContainerName: cm.containerName, Type: AlertNetwork, Level: AlertCritical,
			Message: fmt.Sprintf("Network transmit rate critical: %s/s", formatBytes(networkTxRate)),
			Value:   float64(networkTxRate), Threshold: float64(m.options.Thresholds.NetworkTxCritical), Timestamp: currentStats.Time,
		})
	} else if networkTxRate >= m.options.Thresholds.NetworkTxWarning {
		m.sendAlert(ResourceAlert{
			ContainerID: cm.containerID, ContainerName: cm.containerName, Type: AlertNetwork, Level: AlertWarning,
			Message: fmt.Sprintf("Network transmit rate warning: %s/s", formatBytes(networkTxRate)),
			Value:   float64(networkTxRate), Threshold: float64(m.options.Thresholds.NetworkTxWarning), Timestamp: currentStats.Time,
		})
	}

	// Check PIDs count
	if currentStats.PIDs >= m.options.Thresholds.PIDsCritical {
		m.sendAlert(ResourceAlert{
			ContainerID: cm.containerID, ContainerName: cm.containerName, Type: AlertPIDs, Level: AlertCritical,
			Message: fmt.Sprintf("PID count critical: %d", currentStats.PIDs),
			Value:   float64(currentStats.PIDs), Threshold: float64(m.options.Thresholds.PIDsCritical), Timestamp: currentStats.Time,
		})
	} else if currentStats.PIDs >= m.options.Thresholds.PIDsWarning {
		m.sendAlert(ResourceAlert{
			ContainerID: cm.containerID, ContainerName: cm.containerName, Type: AlertPIDs, Level: AlertWarning,
			Message: fmt.Sprintf("PID count warning: %d", currentStats.PIDs),
			Value:   float64(currentStats.PIDs), Threshold: float64(m.options.Thresholds.PIDsWarning), Timestamp: currentStats.Time,
		})
	}

	// Check Disk Read rate (using calculated diskReadRate)
	if diskReadRate >= m.options.Thresholds.DiskWarning { // Assuming only warning for now
		m.sendAlert(ResourceAlert{
			ContainerID: cm.containerID, ContainerName: cm.containerName, Type: AlertDisk, Level: AlertWarning,
			Message: fmt.Sprintf("Disk read rate high: %s/s", formatBytes(diskReadRate)),
			Value:   float64(diskReadRate), Threshold: float64(m.options.Thresholds.DiskWarning), Timestamp: currentStats.Time,
		})
	}
	// Check Disk Write rate (using calculated diskWriteRate)
	if diskWriteRate >= m.options.Thresholds.DiskWarning { // Assuming only warning for now
		m.sendAlert(ResourceAlert{
			ContainerID: cm.containerID, ContainerName: cm.containerName, Type: AlertDisk, Level: AlertWarning,
			Message: fmt.Sprintf("Disk write rate high: %s/s", formatBytes(diskWriteRate)),
			Value:   float64(diskWriteRate), Threshold: float64(m.options.Thresholds.DiskWarning), Timestamp: currentStats.Time,
		})
	}
}

// sendAlert sends a resource alert to registered handlers
func (m *Monitor) sendAlert(alert ResourceAlert) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Call specific handlers for this alert type
	if handlers, exists := m.options.AlertHandlers[alert.Type]; exists {
		for _, handler := range handlers {
			go handler(alert)
		}
	}

	// Call default handler if specified
	if m.options.DefaultAlertHandler != nil {
		go m.options.DefaultAlertHandler(alert)
	}

	// Log the alert
	fields := logrus.Fields{
		"container_id":   alert.ContainerID,
		"container_name": alert.ContainerName,
		"type":           alert.Type,
		"level":          alert.Level,
		"value":          alert.Value,
		"threshold":      alert.Threshold,
	}

	switch alert.Level {
	case AlertCritical:
		m.logger.WithFields(fields).Error(alert.Message)
	case AlertWarning:
		m.logger.WithFields(fields).Warn(alert.Message)
	default:
		m.logger.WithFields(fields).Info(alert.Message)
	}
}

// getContainerStats gets stats for a container once
func (m *Monitor) getContainerStats(containerID string) (models.ContainerStats, error) {
	// Wait for throttle
	err := m.throttle.Wait(m.ctx)
	if err != nil {
		return models.ContainerStats{}, fmt.Errorf("throttle error: %w", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()

	// Get container stats
	statsResp, err := m.client.ContainerStats(ctx, containerID, false)
	if err != nil {
		if client.IsErrNotFound(err) || strings.Contains(err.Error(), "No such container") {
			return models.ContainerStats{}, fmt.Errorf("container not found: %s", containerID)
		}
		return models.ContainerStats{}, fmt.Errorf("failed to get container stats: %w", err)
	}
	defer statsResp.Body.Close()

	// Decode stats
	var stats *container.Stats // Use container.Stats
	err = json.NewDecoder(statsResp.Body).Decode(&stats)
	if err != nil {
		return models.ContainerStats{}, fmt.Errorf("failed to decode stats JSON: %w", err)
	}

	// Create a dummy container monitor to process the stats
	cm := &containerMonitor{
		containerID: containerID,
		// Initialize previousStats with zero time to indicate first run
		previousStats: models.ContainerStats{Time: time.Time{}},
	}

	// Process and return the stats
	return m.processStats(cm, stats), nil
}

// formatBytes formats bytes as human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
