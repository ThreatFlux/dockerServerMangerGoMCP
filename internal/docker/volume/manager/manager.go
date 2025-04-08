// Package manager provides a concrete implementation of the volume.Service interface
package manager // Reverted package to manager

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors" // Added for errors.Is
	"fmt"
	"io"
	// "path/filepath" // Removed unused import
	"sort" // Added sort import
	// "strings" // Removed unused import
	"sync"
	"time"

	// "github.com/docker_test/docker_test/api/types" // Removed unused import
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events" // Added events import
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	dockertypesvolume "github.com/docker/docker/api/types/volume"
	clientpkg "github.com/docker/docker/client" // Added alias
	"github.com/sirupsen/logrus"
	volumepkg "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/volume" // Added import alias for parent package
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// Manager implements the volume.Service interface
type Manager struct {
	// client is the Docker API client
	client clientpkg.CommonAPIClient // Use aliased client interface type

	// logger is the logger
	logger *logrus.Logger

	// eventListeners is a map of event listeners
	eventListeners map[string]chan events.Message // Use events.Message

	// eventListenersMu is a mutex for event listeners
	eventListenersMu sync.RWMutex

	// containers is a map of container IDs to container information
	containers map[string]containerInfo

	// containersMu is a mutex for containers
	containersMu sync.RWMutex
}

// containerInfo contains information about a container created for volume operations
type containerInfo struct {
	// ID is the container ID
	ID string

	// CreatedAt is when the container was created
	CreatedAt time.Time

	// ExpiresAt is when the container expires and should be removed
	ExpiresAt time.Time

	// VolumeNames are the volume names mounted in the container
	VolumeNames []string
}

// Options contains options for creating a Manager
type Options struct {
	// Client is the Docker client
	Client clientpkg.CommonAPIClient // Use aliased client interface type

	// Logger is the logger
	Logger *logrus.Logger
}

// New creates a new Manager
func New(options Options) (*Manager, error) {
	var err error
	client := options.Client
	if client == nil {
		// Correct Docker client initialization
		client, err = clientpkg.NewClientWithOpts(clientpkg.FromEnv, clientpkg.WithAPIVersionNegotiation())
		if err != nil {
			return nil, fmt.Errorf("failed to create Docker client: %w", err)
		}
	}

	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}

	m := &Manager{
		client:         client,
		logger:         logger,
		eventListeners: make(map[string]chan events.Message), // Use events.Message
		containers:     make(map[string]containerInfo),
	}
	// Start the cleanup timer when the manager is created
	m.startCleanupTimer()
	return m, nil
}

// Create creates a new volume
func (m *Manager) Create(ctx context.Context, name string, options volumepkg.CreateOptions) (*models.Volume, error) { // Use volumepkg.CreateOptions
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Apply default driver if not specified
	driver := options.Driver
	if driver == "" {
		driver = "local"
	}

	// Create volume options
	// Use SDK CreateOptions type
	createOptions := dockertypesvolume.CreateOptions{
		Name:       name,
		Driver:     driver,
		DriverOpts: options.DriverOpts,
		Labels:     options.Labels,
	}

	// Create the volume
	logger.WithFields(logrus.Fields{
		"name":   name,
		"driver": driver,
	}).Debug("Creating volume")

	vol, err := m.client.VolumeCreate(ctx, createOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create volume: %w", err)
	}

	// Convert to model
	return toVolumeModel(vol), nil
}

// Get gets a volume by name
func (m *Manager) Get(ctx context.Context, name string, options volumepkg.GetOptions) (*models.Volume, error) { // Use volumepkg.GetOptions
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Get the volume
	logger.WithField("name", name).Debug("Getting volume")
	vol, err := m.client.VolumeInspect(ctx, name)
	if err != nil {
		if clientpkg.IsErrNotFound(err) { // Use aliased package
			return nil, fmt.Errorf("volume not found: %s", name)
		}
		return nil, fmt.Errorf("failed to inspect volume: %w", err)
	}

	// Convert to model
	return toVolumeModel(vol), nil
}

// List lists volumes
func (m *Manager) List(ctx context.Context, options volumepkg.ListOptions) ([]*models.Volume, error) { // Use volumepkg.ListOptions
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// List volumes
	logger.Debug("Listing volumes")
	// VolumeList expects volume.ListOptions from SDK
	sdkListOptions := dockertypesvolume.ListOptions{Filters: options.Filters}
	volList, err := m.client.VolumeList(ctx, sdkListOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to list volumes: %w", err)
	}

	// Convert to models
	vols := make([]*models.Volume, len(volList.Volumes))
	for i, vol := range volList.Volumes {
		vols[i] = toVolumeModel(*vol)
	}

	// Sort by name
	sort.Slice(vols, func(i, j int) bool {
		// Handle potential nil pointers if conversion fails
		if vols[i] == nil || vols[j] == nil {
			return false // Or handle appropriately
		}
		return vols[i].Name < vols[j].Name
	})

	return vols, nil
}

// Remove removes a volume
func (m *Manager) Remove(ctx context.Context, name string, options volumepkg.RemoveOptions) error { // Use volumepkg.RemoveOptions
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Remove the volume
	logger.WithField("name", name).Debug("Removing volume")
	err := m.client.VolumeRemove(ctx, name, options.Force)
	if err != nil {
		if clientpkg.IsErrNotFound(err) { // Use aliased package
			return fmt.Errorf("volume not found: %s", name)
		}
		return fmt.Errorf("failed to remove volume: %w", err)
	}

	return nil
}

// Prune removes unused volumes
// Use dockertypesvolume.PruneReport as return type
func (m *Manager) Prune(ctx context.Context, options volumepkg.PruneOptions) (*dockertypesvolume.PruneReport, error) { // Use volumepkg.PruneOptions
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Prune volumes
	logger.Debug("Pruning volumes")
	// Correct method name is VolumesPrune
	pruneReport, err := m.client.VolumesPrune(ctx, options.Filters)
	if err != nil {
		return nil, fmt.Errorf("failed to prune volumes: %w", err)
	}

	// Return the SDK PruneReport directly
	return &pruneReport, nil
}

// Backup creates a backup of a volume
func (m *Manager) Backup(ctx context.Context, name string, options volumepkg.BackupOptions) (io.ReadCloser, error) { // Use volumepkg.BackupOptions
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Check if the volume exists
	_, err := m.client.VolumeInspect(ctx, name)
	if err != nil {
		if clientpkg.IsErrNotFound(err) { // Use aliased package
			return nil, fmt.Errorf("volume not found: %s", name)
		}
		return nil, fmt.Errorf("failed to inspect volume: %w", err)
	}

	// Create a temporary container to mount the volume
	containerConfig := &container.Config{
		Image:      "alpine:latest",
		Entrypoint: []string{"tail", "-f", "/dev/null"}, // Keep the container running
	}
	hostConfig := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeVolume,
				Source: name,
				Target: "/data",
			},
		},
	}

	// Create the container
	logger.WithField("volume", name).Debug("Creating temporary container for volume backup")
	cont, err := m.client.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}
	containerID := cont.ID

	// Register the container for cleanup
	m.registerContainer(containerID, []string{name}, 30*time.Minute)

	// Start the container
	err = m.client.ContainerStart(ctx, containerID, container.StartOptions{}) // Use container.StartOptions
	if err != nil {
		m.client.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}) // Use container.RemoveOptions
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Create a pipe
	pr, pw := io.Pipe()

	// Create a tar writer
	tarWriter := tar.NewWriter(pw)

	// Start a goroutine to create the backup
	go func() {
		defer pw.Close()
		defer tarWriter.Close()

		// Create a new context with a longer timeout
		backupCtx, backupCancel := context.WithTimeout(context.Background(), 1*time.Hour)
		defer backupCancel()

		// Copy the data from the container
		err = m.copyFromContainer(backupCtx, containerID, "/data/", tarWriter, options)
		if err != nil {
			logger.WithError(err).Error("Failed to copy data from container")
			// Close the pipe writer with error to signal the reader
			pw.CloseWithError(fmt.Errorf("failed to copy data from container: %w", err))
			return
		}

		// Optional: Add metadata
		if options.IncludeMetadata {
			// Get volume metadata
			vol, err := m.client.VolumeInspect(backupCtx, name)
			if err == nil {
				metadata, err := json.Marshal(vol)
				if err == nil {
					// Add metadata to the tar archive
					header := &tar.Header{
						Name: ".metadata.json",
						Mode: 0644,
						Size: int64(len(metadata)),
					}
					err = tarWriter.WriteHeader(header)
					if err == nil {
						_, err = tarWriter.Write(metadata)
						if err != nil {
							logger.WithError(err).Error("Failed to write metadata to tar archive")
							// Close pipe with error? Or just log?
							pw.CloseWithError(fmt.Errorf("failed to write metadata: %w", err))
							return
						}
					} else {
						logger.WithError(err).Error("Failed to write metadata header to tar archive")
						pw.CloseWithError(fmt.Errorf("failed to write metadata header: %w", err))
						return
					}
				} else {
					logger.WithError(err).Error("Failed to marshal volume metadata")
					// Don't fail the whole backup for metadata error? Log and continue.
				}
			} else {
				logger.WithError(err).Error("Failed to get volume metadata for backup")
				// Don't fail the whole backup for metadata error? Log and continue.
			}
		}

		// Clean up the container after backup
		go func() {
			// Wait a bit to ensure the backup is complete
			time.Sleep(5 * time.Second)
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer stopCancel()
			m.client.ContainerStop(stopCtx, containerID, container.StopOptions{}) // Use container.StopOptions

			removeCtx, removeCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer removeCancel()
			m.client.ContainerRemove(removeCtx, containerID, container.RemoveOptions{Force: true}) // Use container.RemoveOptions
			m.unregisterContainer(containerID)
		}()
	}()

	return pr, nil
}

// Restore restores a volume from a backup
func (m *Manager) Restore(ctx context.Context, name string, reader io.Reader, options volumepkg.RestoreOptions) error { // Use volumepkg.RestoreOptions
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Check if the volume exists
	volExists := true
	_, err := m.client.VolumeInspect(ctx, name)
	if err != nil {
		if clientpkg.IsErrNotFound(err) { // Use aliased package
			volExists = false
		} else {
			return fmt.Errorf("failed to inspect volume: %w", err)
		}
	}

	// If the volume exists and overwrite is not enabled, return an error
	if volExists && !options.OverwriteIfExists {
		return fmt.Errorf("volume already exists: %s", name)
	}

	// Create the volume if it doesn't exist
	if !volExists {
		_, err = m.Create(ctx, name, volumepkg.CreateOptions{ // Use volumepkg.CreateOptions
			Logger: logger,
		})
		if err != nil {
			return fmt.Errorf("failed to create volume: %w", err)
		}
	}

	// Create a temporary container to mount the volume
	containerConfig := &container.Config{
		Image:      "alpine:latest",
		Entrypoint: []string{"tail", "-f", "/dev/null"}, // Keep the container running
	}
	hostConfig := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeVolume,
				Source: name,
				Target: "/data",
			},
		},
	}

	// Create the container
	logger.WithField("volume", name).Debug("Creating temporary container for volume restore")
	cont, err := m.client.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}
	containerID := cont.ID

	// Register the container for cleanup
	m.registerContainer(containerID, []string{name}, 30*time.Minute)

	// Start the container
	err = m.client.ContainerStart(ctx, containerID, container.StartOptions{}) // Use container.StartOptions
	if err != nil {
		m.client.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}) // Use container.RemoveOptions
		return fmt.Errorf("failed to start container: %w", err)
	}

	// Copy the data to the container
	err = m.copyToContainer(ctx, containerID, "/data/", reader, options)
	if err != nil {
		// Clean up on error
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		m.client.ContainerStop(stopCtx, containerID, container.StopOptions{}) // Use container.StopOptions

		removeCtx, removeCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer removeCancel()
		m.client.ContainerRemove(removeCtx, containerID, container.RemoveOptions{Force: true}) // Use container.RemoveOptions
		m.unregisterContainer(containerID)
		return fmt.Errorf("failed to copy data to container: %w", err)
	}

	// Clean up the container
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopCancel()
	err = m.client.ContainerStop(stopCtx, containerID, container.StopOptions{}) // Use container.StopOptions
	if err != nil {
		logger.WithError(err).Error("Failed to stop container")
	}

	removeCtx, removeCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer removeCancel()
	err = m.client.ContainerRemove(removeCtx, containerID, container.RemoveOptions{Force: true}) // Use container.RemoveOptions
	if err != nil {
		logger.WithError(err).Error("Failed to remove container")
	}
	m.unregisterContainer(containerID)

	return nil
}

// InspectRaw gets the raw information about a volume
func (m *Manager) InspectRaw(ctx context.Context, name string) (dockertypesvolume.Volume, error) { // Use SDK Volume type
	vol, err := m.client.VolumeInspect(ctx, name)
	if err != nil {
		if clientpkg.IsErrNotFound(err) { // Use aliased package
			return dockertypesvolume.Volume{}, fmt.Errorf("volume not found: %s", name) // Use SDK Volume type
		}
		return dockertypesvolume.Volume{}, fmt.Errorf("failed to inspect volume: %w", err) // Use SDK Volume type
	}
	return vol, nil
}

// GetEvents subscribes to volume events
func (m *Manager) GetEvents(ctx context.Context, options volumepkg.EventOptions) (<-chan events.Message, <-chan error) { // Use volumepkg.EventOptions
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	bufferSize := options.BufferSize
	if bufferSize <= 0 {
		bufferSize = 100 // Default buffer size
	}

	eventsChan := make(chan events.Message, bufferSize) // Use events.Message
	errorChan := make(chan error, 1)

	go func() {
		defer close(eventsChan)
		defer close(errorChan)

		messageOptions := events.ListOptions{ // Corrected type
			Since:   options.Since.Format(time.RFC3339Nano),
			Until:   options.Until.Format(time.RFC3339Nano),
			Filters: options.Filters,
		}
		// Ensure filters are initialized if nil
		if messageOptions.Filters.Len() == 0 {
			messageOptions.Filters = filters.NewArgs()
		}
		messageOptions.Filters.Add("type", "volume")

		logger.WithFields(logrus.Fields{
			"since":   options.Since,
			"until":   options.Until,
			"filters": messageOptions.Filters.Get("label"), // Example filter logging
		}).Debug("Subscribing to Docker volume events")

		msgs, errs := m.client.Events(ctx, messageOptions)

		for {
			select {
			case <-ctx.Done():
				logger.Info("Event listener context cancelled")
				errorChan <- ctx.Err() // Send context error
				return
			case msg, ok := <-msgs:
				if !ok {
					logger.Info("Docker event message channel closed")
					return // Exit if message channel is closed
				}
				// Pass the raw events.Message directly
				select {
				case eventsChan <- msg:
					logger.WithFields(logrus.Fields{"action": msg.Action, "id": msg.Actor.ID}).Trace("Forwarded volume event")
				case <-ctx.Done():
					logger.Info("Event listener context cancelled while sending")
					errorChan <- ctx.Err()
					return
				default:
					// This case should ideally not happen with a buffered channel unless it's full
					logger.Warn("Event channel buffer full, discarding volume event")
				}
			case err, ok := <-errs:
				if !ok {
					logger.Info("Docker event error channel closed")
					return // Exit if error channel is closed
				}
				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
					logger.WithError(err).Error("Error receiving Docker events")
					// Try sending error non-blockingly
					select {
					case errorChan <- err:
					default:
						logger.Warn("Error channel full or closed, discarding event error")
					}
					// Decide whether to return or continue based on the error type
					// For now, let's return on significant errors
					return
				} else if err != nil {
					logger.WithError(err).Debug("Docker event stream closed or context cancelled")
					return // Exit on cancellation or EOF
				} else {
					logger.Debug("Docker event stream ended (EOF)")
					return // Exit on clean EOF
				}
			}
		}
	}()

	return eventsChan, errorChan
}

// Update updates a volume's metadata (Note: Docker API doesn't directly support updating volume metadata like labels after creation)
func (m *Manager) Update(ctx context.Context, name string, metadata map[string]string, options volumepkg.UpdateOptions) error { // Use volumepkg.UpdateOptions
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Inspect the volume to ensure it exists
	_, err := m.client.VolumeInspect(ctx, name)
	if err != nil {
		if clientpkg.IsErrNotFound(err) { // Use aliased package
			return fmt.Errorf("volume not found: %s", name)
		}
		return fmt.Errorf("failed to inspect volume before update: %w", err)
	}

	// Docker API does not support updating volume labels/metadata directly.
	// This operation is essentially a no-op in terms of Docker interaction.
	// We could potentially store metadata in our own database if needed.
	logger.WithFields(logrus.Fields{
		"name":     name,
		"metadata": metadata,
	}).Warn("Updating volume metadata is not directly supported by Docker API; this operation is a placeholder.")

	// Placeholder: If storing metadata locally, update it here.
	// For now, just return nil as the volume exists.
	return nil
}

// copyFromContainer copies data from a container path to a tar writer
func (m *Manager) copyFromContainer(ctx context.Context, containerID, srcPath string, tarWriter *tar.Writer, options volumepkg.BackupOptions) error { // Use volumepkg.BackupOptions
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	logger.WithFields(logrus.Fields{
		"container": containerID,
		"path":      srcPath,
	}).Debug("Copying data from container")

	reader, _, err := m.client.CopyFromContainer(ctx, containerID, srcPath)
	if err != nil {
		return fmt.Errorf("failed to copy from container %s path %s: %w", containerID, srcPath, err)
	}
	defer reader.Close()

	// Write the tar stream directly to the output writer
	_, err = io.Copy(tarWriter, reader)
	if err != nil {
		return fmt.Errorf("failed to write tar stream: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"container": containerID,
		"path":      srcPath,
	}).Debug("Finished copying data from container")
	return nil
}

// copyToContainer copies data from a reader (tar stream) to a container path
func (m *Manager) copyToContainer(ctx context.Context, containerID, dstPath string, reader io.Reader, options volumepkg.RestoreOptions) error { // Use volumepkg.RestoreOptions
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	logger.WithFields(logrus.Fields{
		"container": containerID,
		"path":      dstPath,
	}).Debug("Copying data to container")

	err := m.client.CopyToContainer(ctx, containerID, dstPath, reader, container.CopyToContainerOptions{ // Use container.CopyToContainerOptions
		AllowOverwriteDirWithFile: options.OverwriteIfExists, // Map option
		CopyUIDGID:                false,                     // Consider adding as an option if needed
	})
	if err != nil {
		return fmt.Errorf("failed to copy to container %s path %s: %w", containerID, dstPath, err)
	}

	logger.WithFields(logrus.Fields{
		"container": containerID,
		"path":      dstPath,
	}).Debug("Finished copying data to container")
	return nil
}

// registerContainer registers a temporary container for cleanup
func (m *Manager) registerContainer(containerID string, volumeNames []string, ttl time.Duration) {
	m.containersMu.Lock()
	defer m.containersMu.Unlock()

	now := time.Now()
	m.containers[containerID] = containerInfo{
		ID:          containerID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		VolumeNames: volumeNames,
	}
	m.logger.WithFields(logrus.Fields{
		"container": containerID,
		"volumes":   volumeNames,
		"ttl":       ttl,
	}).Debug("Registered temporary container for cleanup")
}

// unregisterContainer removes a container from the cleanup list
func (m *Manager) unregisterContainer(containerID string) {
	m.containersMu.Lock()
	defer m.containersMu.Unlock()
	delete(m.containers, containerID)
	m.logger.WithField("container", containerID).Debug("Unregistered temporary container")
}

// cleanupContainer stops and removes a container
func (m *Manager) cleanupContainer(containerID string) {
	m.logger.WithField("container", containerID).Info("Cleaning up temporary container")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // Generous timeout for cleanup
	defer cancel()

	// Stop the container
	err := m.client.ContainerStop(ctx, containerID, container.StopOptions{}) // Use container.StopOptions
	if err != nil && !clientpkg.IsErrNotFound(err) {
		m.logger.WithError(err).WithField("container", containerID).Error("Failed to stop temporary container during cleanup")
	}

	// Remove the container
	err = m.client.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}) // Use container.RemoveOptions
	if err != nil && !clientpkg.IsErrNotFound(err) {
		m.logger.WithError(err).WithField("container", containerID).Error("Failed to remove temporary container during cleanup")
	}

	m.unregisterContainer(containerID) // Ensure it's unregistered even if removal failed
}

// broadcastEvent sends an event to all registered listeners
func (m *Manager) broadcastEvent(event events.Message, sourceID string) { // Use events.Message
	m.eventListenersMu.RLock()
	defer m.eventListenersMu.RUnlock()

	if len(m.eventListeners) == 0 {
		return
	}

	m.logger.WithFields(logrus.Fields{
		"action": event.Action,
		"type":   event.Type,
		"id":     event.Actor.ID,
	}).Trace("Broadcasting volume event")

	for id, listener := range m.eventListeners {
		select {
		case listener <- event:
			m.logger.WithField("listener_id", id).Trace("Sent event to listener")
		default:
			m.logger.WithField("listener_id", id).Warn("Event listener channel full, discarding event")
			// Optionally remove slow listeners?
		}
	}
}

// CleanupExpiredContainers periodically checks and cleans up expired temporary containers
func (m *Manager) CleanupExpiredContainers() {
	m.containersMu.Lock()
	defer m.containersMu.Unlock()

	now := time.Now()
	for id, info := range m.containers {
		if now.After(info.ExpiresAt) {
			m.logger.WithField("container", id).Warn("Temporary container expired, initiating cleanup")
			go m.cleanupContainer(id) // Run cleanup in a separate goroutine
		}
	}
}

// startCleanupTimer starts a ticker to periodically run CleanupExpiredContainers
func (m *Manager) startCleanupTimer() {
	ticker := time.NewTicker(5 * time.Minute) // Check every 5 minutes
	go func() {
		for range ticker.C {
			m.CleanupExpiredContainers()
		}
	}()
	// Note: Consider adding a way to stop the ticker gracefully on shutdown
}

// Use dockertypesvolume.Volume in signature
func toVolumeModel(vol dockertypesvolume.Volume) *models.Volume {
	optionsMap := make(models.JSONMap)
	if vol.Options != nil {
		for k, v := range vol.Options {
			optionsMap[k] = v
		}
	}
	labelsMap := make(models.JSONMap)
	if vol.Labels != nil {
		for k, v := range vol.Labels {
			labelsMap[k] = v
		}
	}
	statusMap := make(models.JSONMap)
	if vol.Status != nil {
		for k, v := range vol.Status {
			statusMap[k] = v
		}
	}

	// Parse CreatedAt time string
	createdAt, err := time.Parse(time.RFC3339, vol.CreatedAt)
	if err != nil {
		// Handle error appropriately, maybe log it or set a default time
		createdAt = time.Time{} // Set to zero time if parsing fails
	}

	// Correctly assign fields based on models.Volume definition
	return &models.Volume{
		DockerResource: models.DockerResource{
			Name:      vol.Name,  // Assign to embedded struct field
			Labels:    labelsMap, // Assign to embedded struct field
			CreatedAt: createdAt, // Assign to embedded struct field
		},
		VolumeID:   vol.Name, // Use Name as VolumeID for consistency
		Driver:     vol.Driver,
		Mountpoint: vol.Mountpoint,
		Status:     statusMap,
		Scope:      vol.Scope,
		Options:    optionsMap,                       // Assign converted map
		UsageData:  toVolumeUsageData(vol.UsageData), // Pass SDK UsageData
		// DriverOpts is not directly available in SDK Volume type, might need separate handling if required
		// InUse needs to be determined based on UsageData.RefCount > 0 or inspecting containers
	}
}

// Corrected to match models.VolumeUsageData definition
func toVolumeUsageData(usage *dockertypesvolume.UsageData) *models.VolumeUsageData {
	if usage == nil {
		// Return nil or an empty struct depending on desired behavior
		return nil
	}
	return &models.VolumeUsageData{
		Size:     usage.Size,
		RefCount: usage.RefCount, // Assign int64 directly
		// LastUsed is not available in SDK UsageData
	}
}
