package container

import (
	// "archive/tar" // Removed unused import
	"context"
	"encoding/json" // Added for stats streaming
	"fmt"
	"io"      // Needed for os.FileMode
	"regexp"  // Added for formatContainerStatus
	"strings" // Added for inline conversion
	"time"    // Added for inline conversion

	"github.com/docker/docker/api/types" // Added import
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"   // Added for ImagePullOptions
	"github.com/docker/docker/api/types/network" // Added for NetworkingConfig
	"github.com/docker/docker/client"
	// "github.com/docker_test/docker_test/errdefs" // Removed unused import
	specs "github.com/opencontainers/image-spec/specs-go/v1" // Added import with alias
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"           // Import local docker_test package for Manager
	dsmModels "github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Use alias
)

// serviceImpl implements the container.Service interface
type serviceImpl struct {
	dockerManager docker.Manager // Use docker.Manager
	log           *logrus.Logger
}

// NewService creates a new container service implementation
// NOTE: This constructor was assumed earlier and is now being defined.
func NewService(dockerManager docker.Manager, log *logrus.Logger) Service {
	return &serviceImpl{
		dockerManager: dockerManager,
		log:           log,
	}
}

// --- Implementation of interfaces.ContainerService ---

// ContainerCreate creates a new container using the Docker SDK types directly
func (s *serviceImpl) ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, platform string, containerName string) (container.CreateResponse, error) {
	s.log.WithField("name", containerName).Info("Creating container (SDK)")
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return container.CreateResponse{}, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// The platform argument in the SDK is *specs.Platform, handle nil case
	var platformSpec *specs.Platform
	if platform != "" {
		// Basic parsing, might need adjustment based on expected platform string format
		parts := strings.SplitN(platform, "/", 2)
		if len(parts) == 2 {
			platformSpec = &specs.Platform{OS: parts[0], Architecture: parts[1]}
		} else {
			platformSpec = &specs.Platform{OS: platform} // Assume OS only if no '/'
		}
	}

	resp, err := cli.ContainerCreate(ctx, config, hostConfig, networkingConfig, platformSpec, containerName)
	if err != nil {
		s.log.WithError(err).Error("Failed to create container via Docker API (SDK)")
		return resp, fmt.Errorf("failed to create container: %w", err) // Return resp even on error
	}
	s.log.WithField("containerID", resp.ID).Info("Container created successfully (SDK)")
	return resp, nil
}

// ContainerStart starts a container by ID
func (s *serviceImpl) ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error {
	s.log.WithField("containerID", containerID).Info("Starting container (SDK)")
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}
	return cli.ContainerStart(ctx, containerID, options)
}

// ContainerStop stops a container by ID
func (s *serviceImpl) ContainerStop(ctx context.Context, containerID string, options container.StopOptions) error {
	s.log.WithField("containerID", containerID).Info("Stopping container (SDK)")
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}
	return cli.ContainerStop(ctx, containerID, options)
}

// ContainerRemove removes a container by ID
func (s *serviceImpl) ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error {
	s.log.WithField("containerID", containerID).Info("Removing container (SDK)")
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}
	return cli.ContainerRemove(ctx, containerID, options)
}

// ContainerInspect inspects a container by ID
func (s *serviceImpl) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	s.log.WithField("containerID", containerID).Debug("Inspecting container (SDK)")
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return types.ContainerJSON{}, fmt.Errorf("failed to get docker_test client: %w", err)
	}
	return cli.ContainerInspect(ctx, containerID)
}

// ContainerList lists containers
func (s *serviceImpl) ContainerList(ctx context.Context, options container.ListOptions) ([]types.Container, error) {
	s.log.Debug("Listing containers (SDK)")
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}
	return cli.ContainerList(ctx, options)
}

// NetworkConnect connects a container to a network
func (s *serviceImpl) NetworkConnect(ctx context.Context, networkID, containerID string, config *network.EndpointSettings) error {
	s.log.WithFields(logrus.Fields{"containerID": containerID, "networkID": networkID}).Info("Connecting container to network (SDK)")
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}
	return cli.NetworkConnect(ctx, networkID, containerID, config)
}

// --- Implementation of original Service interface methods ---

// Get returns detailed information about a container
func (s *serviceImpl) Get(ctx context.Context, containerID string) (*dsmModels.Container, error) { // Use alias
	s.log.WithField("containerID", containerID).Debug("Getting container details")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	containerJSON, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, fmt.Errorf("container %s not found: %w", containerID, err)
		}
		return nil, fmt.Errorf("failed to inspect container %s: %w", containerID, err)
	}

	// Convert the ContainerJSON to our internal models.Container
	// This uses the existing conversion logic from models/docker_entities.go
	modelContainer := dsmModels.FromDockerContainerJSON(&containerJSON) // Use alias
	if modelContainer == nil {
		return nil, fmt.Errorf("failed to convert container details for %s", containerID)
	}

	// TODO: Potentially enrich with DB data if needed

	return modelContainer, nil
}

// List retrieves a list of containers based on the provided options
func (s *serviceImpl) List(ctx context.Context, opts ListOptions) ([]dsmModels.Container, error) { // Use alias
	s.log.Debug("Listing containers")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Map our ListOptions to the Docker SDK's container.ListOptions
	sdkOpts := container.ListOptions{
		All:     opts.All,
		Limit:   opts.Limit,
		Size:    opts.Size,
		Filters: opts.Filters,
		Since:   opts.Since,
		Before:  opts.Before,
	}

	dockerContainers, err := cli.ContainerList(ctx, sdkOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers from docker_test api: %w", err)
	}
	// Convert []types.ContainerSummary to []models.Container directly
	modelContainers := make([]dsmModels.Container, 0, len(dockerContainers)) // Use alias
	for _, dc := range dockerContainers {
		// Inline conversion logic from models.FromDockerContainerSummary
		status := dsmModels.ContainerStatus(formatContainerStatus(dc.State, dc.Status)) // Use alias

		labelsMap := make(dsmModels.JSONMap) // Use alias
		for k, v := range dc.Labels {
			labelsMap[k] = v
		}

		portsMap := make(dsmModels.JSONMap) // Use alias
		for _, p := range dc.Ports {
			key := fmt.Sprintf("%d/%s", p.PrivatePort, p.Type)
			portsMap[key] = map[string]interface{}{"HostIP": p.IP, "HostPort": fmt.Sprintf("%d", p.PublicPort)}
		}

		networksMap := make(dsmModels.JSONMap) // Use alias
		if dc.NetworkSettings != nil {
			for name, settings := range dc.NetworkSettings.Networks {
				networksMap[name] = map[string]interface{}{
					"NetworkID": settings.NetworkID, "EndpointID": settings.EndpointID, "IPAddress": settings.IPAddress,
					"Gateway": settings.Gateway, "MacAddress": settings.MacAddress, "IPPrefixLen": settings.IPPrefixLen,
					"Aliases": settings.Aliases,
				}
			}
		}

		volumesMap := make(dsmModels.JSONMap)                  // Use alias
		mounts := make([]dsmModels.MountPoint, len(dc.Mounts)) // Use alias
		for i, m := range dc.Mounts {
			mounts[i] = dsmModels.MountPoint{ // Use alias
				Type: string(m.Type), Name: m.Name, Source: m.Source, Destination: m.Destination,
				Mode: m.Mode, RW: m.RW, Propagation: string(m.Propagation),
			}
			volumesMap[m.Destination] = map[string]interface{}{
				"Source": m.Source, "Type": string(m.Type), "Mode": m.Mode, "RW": m.RW, "Name": m.Name,
			}
		}

		primaryName := ""
		if len(dc.Names) > 0 {
			primaryName = strings.TrimPrefix(dc.Names[0], "/")
		}

		container := dsmModels.Container{ // Use alias
			DockerResource: dsmModels.DockerResource{Name: primaryName, Labels: labelsMap}, // Use alias
			ContainerID:    dc.ID,
			ImageID:        dc.ImageID,
			Image:          dc.Image,
			Command:        dc.Command,
			Status:         status,
			State:          dc.State,
			Ports:          portsMap,
			Volumes:        volumesMap,
			Networks:       networksMap,
			SizeRw:         dc.SizeRw,
			SizeRootFs:     dc.SizeRootFs,
			Names:          dc.Names,
			Mounts:         mounts,
		}
		container.CreatedAt = time.Unix(dc.Created, 0)
		modelContainers = append(modelContainers, container)
	}

	// TODO: Potentially enrich with DB data if needed

	return modelContainers, nil
}

// Create creates a new container based on the provided options
func (s *serviceImpl) Create(ctx context.Context, opts CreateOptions) (*dsmModels.Container, error) { // Use alias
	s.log.WithField("name", opts.Name).Info("Creating container")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// --- Image Pull Logic ---
	imageName := opts.Config.Image // Assuming image name is in opts.Config.Image
	if imageName == "" {
		return nil, fmt.Errorf("image name is required to create container")
	}

	// Check if image exists locally first (optional, but good practice)
	_, _, err = cli.ImageInspectWithRaw(ctx, imageName)
	if err != nil {
		if client.IsErrNotFound(err) {
			s.log.WithField("image", imageName).Info("Image not found locally, attempting to pull...")
			pullResp, pullErr := cli.ImagePull(ctx, imageName, image.PullOptions{})
			if pullErr != nil {
				s.log.WithError(pullErr).WithField("image", imageName).Error("Failed to pull image")
				return nil, fmt.Errorf("failed to pull image %s: %w", imageName, pullErr)
			}
			defer pullResp.Close()
			// Optionally display pull progress to logs/user
			// io.Copy(os.Stdout, pullResp) // Example: Copy to stdout
			// For now, just discard the output to ensure pull completes
			_, _ = io.Copy(io.Discard, pullResp)
			s.log.WithField("image", imageName).Info("Image pulled successfully")
		} else {
			// Different error during inspect
			s.log.WithError(err).WithField("image", imageName).Error("Failed to inspect image")
			return nil, fmt.Errorf("failed to inspect image %s: %w", imageName, err)
		}
	} else {
		s.log.WithField("image", imageName).Debug("Image found locally")
	}
	// --- End Image Pull Logic ---

	// Basic mapping from CreateOptions to Docker SDK types
	// More complex mapping (ports, volumes, networks) might be needed
	config := opts.Config
	if config == nil {
		config = &container.Config{} // Initialize if nil
	}
	hostConfig := opts.HostConfig
	if hostConfig == nil {
		hostConfig = &container.HostConfig{} // Initialize if nil
	}
	networkConfig := opts.NetworkConfig
	if networkConfig == nil {
		networkConfig = &network.NetworkingConfig{} // Initialize if nil
	}

	// Ensure Image is set in config if provided in opts directly (common pattern)
	// if config.Image == "" && opts.Image != "" { // Assuming CreateOptions has an Image field
	// 	config.Image = opts.Image
	// }
	// if len(config.Cmd) == 0 && len(opts.Command) > 0 { // Assuming CreateOptions has Command field
	// 	config.Cmd = opts.Command
	// }
	// Add more mappings as needed based on CreateOptions definition

	resp, err := cli.ContainerCreate(ctx, config, hostConfig, networkConfig, opts.Platform, opts.Name)
	if err != nil {
		s.log.WithError(err).Error("Failed to create container via Docker API")
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	s.log.WithField("containerID", resp.ID).Info("Container created successfully")

	// Inspect the newly created container to return its details
	newContainerInfo, err := s.Get(ctx, resp.ID)
	if err != nil {
		// Log the error but potentially return the ID anyway, as creation succeeded
		s.log.WithError(err).WithField("containerID", resp.ID).Error("Failed to inspect newly created container, returning basic info")
		// Return a minimal container object if inspection fails
		return &dsmModels.Container{ // Use alias
			ContainerID:    resp.ID,
			DockerResource: dsmModels.DockerResource{Name: opts.Name}, // Use alias
			// Status might be 'created' but inspect failed
		}, nil // Or return the error: fmt.Errorf("container created (%s) but failed to inspect: %w", resp.ID, err)
	}

	// Handle warnings from creation if needed
	for _, warning := range resp.Warnings {
		s.log.WithField("containerID", resp.ID).Warnf("Container creation warning: %s", warning)
	}

	return newContainerInfo, nil
}

// Start starts a container
func (s *serviceImpl) Start(ctx context.Context, containerID string, opts StartOptions) error {
	s.log.WithField("containerID", containerID).Info("Starting container")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Map our StartOptions to the Docker SDK's container.StartOptions
	// Note: The SDK's StartOptions is currently empty, but we map for future compatibility
	sdkOpts := container.StartOptions{
		CheckpointID:  opts.CheckpointID,
		CheckpointDir: opts.CheckpointDir,
	}

	if err := cli.ContainerStart(ctx, containerID, sdkOpts); err != nil {
		// Check if it's a "not found" error
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).Error("Container not found")
			return fmt.Errorf("container %s not found: %w", containerID, err)
		}
		// Check if already started (Docker might return 304 Not Modified, but client wraps it)
		// We might need more specific error checking depending on Docker version/client behavior
		s.log.WithError(err).WithField("containerID", containerID).Error("Failed to start container via Docker API")
		return fmt.Errorf("failed to start container %s: %w", containerID, err)
	}

	s.log.WithField("containerID", containerID).Info("Container started successfully")
	return nil
}

// Stop stops a container
func (s *serviceImpl) Stop(ctx context.Context, containerID string, opts StopOptions) error {
	s.log.WithFields(logrus.Fields{
		"containerID": containerID,
		"timeout":     opts.Timeout,
	}).Info("Stopping container")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Convert timeout to *int for the SDK
	var timeoutIntPtr *int
	if opts.Timeout > 0 {
		timeoutVal := opts.Timeout // Create a local variable to take its address
		timeoutIntPtr = &timeoutVal
	}

	// Use ContainerStop which accepts a timeout pointer (to int seconds)
	if err := cli.ContainerStop(ctx, containerID, container.StopOptions{Timeout: timeoutIntPtr}); err != nil {
		// Check if it's a "not found" error
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).Error("Container not found")
			return fmt.Errorf("container %s not found: %w", containerID, err)
		}
		// Check if already stopped (Docker might return 304 Not Modified, but client wraps it)
		// We might need more specific error checking depending on Docker version/client behavior
		s.log.WithError(err).WithField("containerID", containerID).Error("Failed to stop container via Docker API")
		return fmt.Errorf("failed to stop container %s: %w", containerID, err)
	}

	s.log.WithField("containerID", containerID).Info("Container stopped successfully")
	return nil
}

// Restart restarts a container
func (s *serviceImpl) Restart(ctx context.Context, containerID string, opts RestartOptions) error {
	s.log.WithFields(logrus.Fields{
		"containerID": containerID,
		"timeout":     opts.Timeout,
	}).Info("Restarting container")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Convert timeout to *int for the SDK
	var timeoutIntPtr *int
	if opts.Timeout > 0 {
		timeoutVal := opts.Timeout // Create a local variable to take its address
		timeoutIntPtr = &timeoutVal
	}

	// Use ContainerRestart which accepts a timeout pointer (to int seconds)
	// NOTE: The SDK uses container.StopOptions here, which seems odd but is correct.
	if err := cli.ContainerRestart(ctx, containerID, container.StopOptions{Timeout: timeoutIntPtr}); err != nil {
		// Check if it's a "not found" error
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).Error("Container not found")
			return fmt.Errorf("container %s not found: %w", containerID, err)
		}
		s.log.WithError(err).WithField("containerID", containerID).Error("Failed to restart container via Docker API")
		return fmt.Errorf("failed to restart container %s: %w", containerID, err)
	}

	s.log.WithField("containerID", containerID).Info("Container restarted successfully")
	return nil
}

func (s *serviceImpl) Kill(ctx context.Context, containerID string, opts KillOptions) error {
	return fmt.Errorf("Kill not implemented")
}

// Remove removes a container
func (s *serviceImpl) Remove(ctx context.Context, containerID string, opts RemoveOptions) error {
	s.log.WithFields(logrus.Fields{
		"containerID":   containerID,
		"force":         opts.Force,
		"removeVolumes": opts.RemoveVolumes,
		"removeLinks":   opts.RemoveLinks,
	}).Info("Removing container")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	sdkOpts := container.RemoveOptions{
		Force:         opts.Force,
		RemoveVolumes: opts.RemoveVolumes,
		RemoveLinks:   opts.RemoveLinks,
	}

	if err := cli.ContainerRemove(ctx, containerID, sdkOpts); err != nil {
		// Check if it's a "not found" error, which might be acceptable in some cleanup scenarios
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).Warn("Attempted to remove container, but it was not found")
			return nil // Or return a specific error if needed: fmt.Errorf("container %s not found: %w", containerID, err)
		}
		s.log.WithError(err).WithField("containerID", containerID).Error("Failed to remove container via Docker API")
		return fmt.Errorf("failed to remove container %s: %w", containerID, err)
	}

	s.log.WithField("containerID", containerID).Info("Container removed successfully")
	return nil
}

// Logs returns the logs of a container
func (s *serviceImpl) Logs(ctx context.Context, containerID string, opts LogOptions) (io.ReadCloser, error) {
	s.log.WithFields(logrus.Fields{
		"containerID": containerID,
		"follow":      opts.Follow,
		"tail":        opts.Tail,
		"since":       opts.Since,
		"until":       opts.Until,
	}).Info("Getting container logs")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	sdkOpts := container.LogsOptions{
		ShowStdout: opts.ShowStdout,
		ShowStderr: opts.ShowStderr,
		Since:      opts.Since.Format(time.RFC3339Nano), // Format time for SDK
		Until:      opts.Until.Format(time.RFC3339Nano), // Format time for SDK
		Timestamps: opts.Timestamps,
		Follow:     opts.Follow,
		Tail:       opts.Tail,
		Details:    opts.Details,
	}

	logsReader, err := cli.ContainerLogs(ctx, containerID, sdkOpts)
	if err != nil {
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).Error("Container not found")
			return nil, fmt.Errorf("container %s not found: %w", containerID, err)
		}
		s.log.WithError(err).WithField("containerID", containerID).Error("Failed to get container logs via Docker API")
		return nil, fmt.Errorf("failed to get logs for container %s: %w", containerID, err)
	}

	// The caller is responsible for closing the logsReader
	return logsReader, nil
}

// Stats returns a single container stats reading
func (s *serviceImpl) Stats(ctx context.Context, containerID string, opts StatsOptions) (dsmModels.ContainerStats, error) {
	opts.Stream = false // Ensure we get only one result
	opts.OneShot = true

	statsCh, errCh := s.StreamStats(ctx, containerID, opts)

	select {
	case stats, ok := <-statsCh:
		if !ok {
			// Channel closed without sending data, check error channel
			err, ok := <-errCh
			if ok && err != nil {
				return dsmModels.ContainerStats{}, fmt.Errorf("error receiving stats: %w", err)
			}
			return dsmModels.ContainerStats{}, fmt.Errorf("stats stream closed unexpectedly")
		}
		// Check error channel even after receiving stats
		err, ok := <-errCh
		if ok && err != nil {
			s.log.WithError(err).Warn("Error received alongside stats data")
			// Decide whether to return stats anyway or prioritize error
		}
		return stats, nil
	case err := <-errCh:
		return dsmModels.ContainerStats{}, fmt.Errorf("error getting stats stream: %w", err)
	case <-ctx.Done():
		return dsmModels.ContainerStats{}, fmt.Errorf("context cancelled while waiting for stats: %w", ctx.Err())
	}
}

// StreamStats streams container stats
func (s *serviceImpl) StreamStats(ctx context.Context, containerID string, opts StatsOptions) (<-chan dsmModels.ContainerStats, <-chan error) { // Use alias
	s.log.WithFields(logrus.Fields{
		"containerID": containerID,
		"stream":      opts.Stream,
	}).Info("Streaming container stats")

	statsCh := make(chan dsmModels.ContainerStats) // Use alias
	errCh := make(chan error, 1)

	go func() {
		defer close(statsCh)
		defer close(errCh)

		cli, err := s.dockerManager.GetClient()
		if err != nil {
			errCh <- fmt.Errorf("failed to get docker_test client: %w", err)
			return
		}

		// Use ContainerStats API
		resp, err := cli.ContainerStats(ctx, containerID, opts.Stream)
		if err != nil {
			if client.IsErrNotFound(err) {
				errCh <- fmt.Errorf("container %s not found: %w", containerID, err)
			} else {
				errCh <- fmt.Errorf("failed to get stats stream for container %s: %w", containerID, err)
			}
			return
		}
		defer resp.Body.Close()

		// Decode the stream of JSON stats
		decoder := json.NewDecoder(resp.Body)
		for {
			var v *container.Stats // Use container.Stats
			if err := decoder.Decode(&v); err != nil {
				if err == io.EOF {
					s.log.WithField("containerID", containerID).Info("Stats stream ended (EOF)")
					return // End of stream
				}
				// Check if context was cancelled
				select {
				case <-ctx.Done():
					s.log.WithField("containerID", containerID).Info("Stats stream context cancelled")
					return
				default:
					s.log.WithError(err).WithField("containerID", containerID).Error("Error decoding stats stream")
					errCh <- fmt.Errorf("error decoding stats stream: %w", err)
					return
				}
			}

			if v == nil {
				continue
			} // Skip empty stats

			// Convert to our model
			modelStats := dsmModels.FromDockerStatsJSON(v) // Use alias
			if modelStats == nil {
				s.log.Warn("Failed to convert Docker stats to model")
				continue
			}

			// Send stats or check context cancellation
			select {
			case statsCh <- *modelStats:
				// Stat sent successfully
			case <-ctx.Done():
				s.log.WithField("containerID", containerID).Info("Stats stream context cancelled during send")
				return
			}

			// If not streaming (OneShot), exit after the first stat
			if !opts.Stream {
				return
			}
		}
	}()

	return statsCh, errCh
}

func (s *serviceImpl) Prune(ctx context.Context, opts PruneOptions) (PruneResult, error) {
	return PruneResult{}, fmt.Errorf("Prune not implemented")
}

// Rename renames a container
func (s *serviceImpl) Rename(ctx context.Context, containerID, newName string) error {
	s.log.WithFields(logrus.Fields{
		"containerID": containerID,
		"newName":     newName,
	}).Info("Renaming container")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	if err := cli.ContainerRename(ctx, containerID, newName); err != nil {
		// Check for specific errors
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).Error("Container not found for rename")
			return fmt.Errorf("container %s not found: %w", containerID, err)
		}
		// Docker might return 409 Conflict if the new name is already in use
		// TODO: Check for conflict error specifically if the client library exposes it
		s.log.WithError(err).WithFields(logrus.Fields{
			"containerID": containerID,
			"newName":     newName,
		}).Error("Failed to rename container via Docker API")
		return fmt.Errorf("failed to rename container %s to %s: %w", containerID, newName, err)
	}

	s.log.WithField("containerID", containerID).WithField("newName", newName).Info("Container renamed successfully")
	return nil
}

func (s *serviceImpl) Update(ctx context.Context, containerID string, opts UpdateOptions) error {
	return fmt.Errorf("Update not implemented")
}

// Pause pauses a container
func (s *serviceImpl) Pause(ctx context.Context, containerID string) error {
	s.log.WithField("containerID", containerID).Info("Pausing container")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	if err := cli.ContainerPause(ctx, containerID); err != nil {
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).Error("Container not found for pause")
			return fmt.Errorf("container %s not found: %w", containerID, err)
		}
		// Check if already paused? Docker might return 304 Not Modified
		s.log.WithError(err).WithField("containerID", containerID).Error("Failed to pause container via Docker API")
		return fmt.Errorf("failed to pause container %s: %w", containerID, err)
	}

	s.log.WithField("containerID", containerID).Info("Container paused successfully")
	return nil
}

// Unpause unpauses a container
func (s *serviceImpl) Unpause(ctx context.Context, containerID string) error {
	s.log.WithField("containerID", containerID).Info("Unpausing container")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	if err := cli.ContainerUnpause(ctx, containerID); err != nil {
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).Error("Container not found for unpause")
			return fmt.Errorf("container %s not found: %w", containerID, err)
		}
		// Check if not paused? Docker might return 304 Not Modified
		s.log.WithError(err).WithField("containerID", containerID).Error("Failed to unpause container via Docker API")
		return fmt.Errorf("failed to unpause container %s: %w", containerID, err)
	}

	s.log.WithField("containerID", containerID).Info("Container unpaused successfully")
	return nil
}

func (s *serviceImpl) Commit(ctx context.Context, containerID string, opts CommitOptions) (string, error) {
	return "", fmt.Errorf("Commit not implemented")
}

func (s *serviceImpl) Wait(ctx context.Context, containerID string, opts WaitOptions) (<-chan container.WaitResponse, <-chan error) {
	// Placeholder implementation
	respCh := make(chan container.WaitResponse)
	errCh := make(chan error, 1)
	go func() {
		defer close(respCh)
		defer close(errCh)
		errCh <- fmt.Errorf("Wait not implemented")
	}()
	return respCh, errCh
}

func (s *serviceImpl) Exec(ctx context.Context, containerID string, opts ExecOptions) (ExecResult, error) {
	return ExecResult{}, fmt.Errorf("Exec not implemented")
}

// Top returns the running processes inside a container
func (s *serviceImpl) Top(ctx context.Context, containerID string, psArgs string) (TopResult, error) {
	s.log.WithFields(logrus.Fields{
		"containerID": containerID,
		"psArgs":      psArgs,
	}).Info("Getting container processes (top)")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return TopResult{}, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Use ContainerTop API
	topResult, err := cli.ContainerTop(ctx, containerID, strings.Fields(psArgs)) // Split psArgs into a slice
	if err != nil {
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).Error("Container not found for top")
			return TopResult{}, fmt.Errorf("container %s not found: %w", containerID, err)
		}
		// Check if container is not running?
		s.log.WithError(err).WithField("containerID", containerID).Error("Failed to get container top via Docker API")
		return TopResult{}, fmt.Errorf("failed to get top for container %s: %w", containerID, err)
	}

	// Convert the result (which is already the correct type)
	return TopResult{
		Titles:    topResult.Titles,
		Processes: topResult.Processes,
	}, nil
}

// Changes returns changes made to the container filesystem
func (s *serviceImpl) Changes(ctx context.Context, containerID string) ([]ChangeItem, error) {
	s.log.WithField("containerID", containerID).Info("Inspecting container filesystem changes")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Use ContainerDiff API
	changes, err := cli.ContainerDiff(ctx, containerID)
	if err != nil {
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).Error("Container not found for changes")
			return nil, fmt.Errorf("container %s not found: %w", containerID, err)
		}
		s.log.WithError(err).WithField("containerID", containerID).Error("Failed to get container changes via Docker API")
		return nil, fmt.Errorf("failed to get changes for container %s: %w", containerID, err)
	}

	// Convert container.Change to our local ChangeItem
	result := make([]ChangeItem, len(changes))
	for i, change := range changes {
		result[i] = ChangeItem{
			Path: change.Path,
			Kind: int(change.Kind), // Convert types.ChangeKind to int
		}
	}

	return result, nil
}

// GetArchive retrieves files or directories from a container as a TAR archive
func (s *serviceImpl) GetArchive(ctx context.Context, containerID string, opts ArchiveOptions) (io.ReadCloser, dsmModels.ResourceStat, error) { // Use alias
	s.log.WithFields(logrus.Fields{
		"containerID": containerID,
		"path":        opts.Path,
	}).Info("Getting archive from container")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, dsmModels.ResourceStat{}, fmt.Errorf("failed to get docker_test client: %w", err) // Use alias
	}

	// Stat the path first to get info (and check existence)
	stat, err := cli.ContainerStatPath(ctx, containerID, opts.Path)
	if err != nil {
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).WithField("path", opts.Path).Error("Path not found in container")
			return nil, dsmModels.ResourceStat{}, fmt.Errorf("path %s not found in container %s: %w", opts.Path, containerID, err) // Use alias
		}
		s.log.WithError(err).WithFields(logrus.Fields{
			"containerID": containerID,
			"path":        opts.Path,
		}).Error("Failed to stat path in container via Docker API")
		return nil, dsmModels.ResourceStat{}, fmt.Errorf("failed to stat path %s in container %s: %w", opts.Path, containerID, err) // Use alias
	}

	// Convert stat info to our model
	resourceStat := dsmModels.ResourceStat{ // Use alias
		Name:       stat.Name,
		Size:       stat.Size,
		Mode:       stat.Mode,
		LinkTarget: stat.LinkTarget,
		// ModTime is not available from stat
	}

	// Get the archive stream
	archiveReader, statResp, err := cli.CopyFromContainer(ctx, containerID, opts.Path) // Capture all 3 return values
	if err != nil {
		// This check might be redundant if StatPath already failed for not found
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).Error("Container not found for GetArchive")
			return nil, dsmModels.ResourceStat{}, fmt.Errorf("container %s not found: %w", containerID, err) // Use alias
		}
		s.log.WithError(err).WithFields(logrus.Fields{
			"containerID": containerID,
			"path":        opts.Path,
		}).Error("Failed to copy archive from container via Docker API")
		return nil, dsmModels.ResourceStat{}, fmt.Errorf("failed to copy archive from container %s path %s: %w", containerID, opts.Path, err) // Use alias
	}
	// Update resourceStat with info from CopyFromContainer response if needed
	// (e.g., if StatPath didn't provide everything, though it usually does)
	_ = statResp // Avoid unused variable error if not using statResp

	// Caller is responsible for closing the reader
	return archiveReader, resourceStat, nil
}

// PutArchive copies an archive of files or directories into a container
func (s *serviceImpl) PutArchive(ctx context.Context, containerID string, path string, content io.Reader) error {
	s.log.WithFields(logrus.Fields{
		"containerID": containerID,
		"path":        path,
	}).Info("Putting archive into container")

	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Prepare options for CopyToContainer
	// Note: AllowOverwriteDirWithFile is false by default, which is usually safer.
	// CopyUIDGID can be used if specific ownership is needed.
	options := container.CopyToContainerOptions{
		AllowOverwriteDirWithFile: false,
		CopyUIDGID:                false,
	}

	// Perform the copy operation
	err = cli.CopyToContainer(ctx, containerID, path, content, options)
	if err != nil {
		// Log the specific error returned by the Docker client
		s.log.WithError(err).WithFields(logrus.Fields{
			"containerID": containerID,
			"path":        path,
		}).Errorf("Docker API CopyToContainer failed: %v", err) // Log the detailed error

		// Check for specific errors
		if client.IsErrNotFound(err) {
			s.log.WithField("containerID", containerID).Error("Container not found for PutArchive")
			return fmt.Errorf("container %s not found: %w", containerID, err)
		}
		// Other potential errors: path not found inside container (if not creating), permission denied, etc.
		// The SDK might not wrap all these nicely, so error message parsing might be needed.
		return fmt.Errorf("failed to copy archive to container %s at path %s: %w", containerID, path, err)
	}

	s.log.WithField("containerID", containerID).WithField("path", path).Info("Archive successfully put into container")
	return nil
}

// formatContainerStatus formats container status from state and status string
func formatContainerStatus(state, status string) string {
	switch state {
	case "created", "running", "paused", "restarting", "removing", "dead":
		return state
	case "exited":
		if strings.Contains(status, "Exited") {
			re := regexp.MustCompile(`Exited \((\d+)\)`)
			matches := re.FindStringSubmatch(status)
			if len(matches) > 1 {
				return fmt.Sprintf("exited(%s)", matches[1])
			}
		}
		return "exited"
	default:
		if status != "" {
			return status
		}
		return "unknown"
	}
}
