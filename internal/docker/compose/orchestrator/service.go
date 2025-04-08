// Package orchestrator provides functionality for orchestrating Docker Compose deployments
package orchestrator

import (
	"context"
	"fmt"
	// "io" // Removed unused import
	"path/filepath" // Added for filepath.IsAbs
	"sort"          // Added for sorting container IDs when scaling down
	"strconv"       // Added for parsing container numbers
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	imagetypes "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/go-connections/nat"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/interfaces"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// --- Client Interfaces ---

// ContainerClient defines the required Docker container methods
type ContainerClient interfaces.ContainerService // Use the common interface

// ImageClient defines the required Docker image methods
type ImageClient interfaces.ImageService // Use the common interface

// --- Service Manager ---

// ServiceManager manages Docker Compose services
type ServiceManager struct {
	containerClient ContainerClient // Use interface type
	imageClient     ImageClient     // Use interface type
	Logger          *logrus.Logger  // Use exported field name
}

// ServiceManagerOptions defines options for creating a service manager
type ServiceManagerOptions struct {
	ContainerClient ContainerClient // Use interface type
	ImageClient     ImageClient     // Use interface type
	Logger          *logrus.Logger
}

// NewServiceManager creates a new service manager
func NewServiceManager(options ServiceManagerOptions) *ServiceManager {
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}
	if options.ContainerClient == nil {
		logger.Warn("ContainerClient is nil in ServiceManagerOptions")
	}
	if options.ImageClient == nil {
		logger.Warn("ImageClient is nil in ServiceManagerOptions")
	}
	return &ServiceManager{
		containerClient: options.ContainerClient,
		imageClient:     options.ImageClient,
		Logger:          logger,
	}
}

// --- Service Operation Options ---

type ServiceDeployOptions struct {
	ProjectName           string
	ForceRecreate         bool
	NoBuild               bool
	NoStart               bool
	Pull                  bool
	RemoveOrphans         bool
	AdjustNetworkSettings bool
	Timeout               time.Duration
	StatusTracker         interfaces.ComposeStatusTracker // Use interface
	Logger                *logrus.Logger
}
type ServiceRemoveOptions struct {
	ProjectName   string
	RemoveVolumes bool
	RemoveImages  string
	RemoveOrphans bool
	Force         bool
	Timeout       time.Duration
	StatusTracker interfaces.ComposeStatusTracker // Use interface
	Logger        *logrus.Logger
}
type ServiceStopOptions struct {
	ProjectName   string
	Timeout       time.Duration
	StatusTracker interfaces.ComposeStatusTracker // Use interface
	Logger        *logrus.Logger
}
type ServiceStartOptions struct {
	ProjectName   string
	Timeout       time.Duration
	StatusTracker interfaces.ComposeStatusTracker // Use interface
	Logger        *logrus.Logger
}
type ServiceScaleOptions struct {
	ProjectName   string
	Service       string
	Replicas      int
	Timeout       time.Duration
	StatusTracker interfaces.ComposeStatusTracker // Use interface
	Logger        *logrus.Logger
}

// --- Service Manager Methods ---

// DeployServices deploys services in the specified order
func (m *ServiceManager) DeployServices(ctx context.Context, composeFile *models.ComposeFile, serviceOrder []string, options ServiceDeployOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = m.Logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	if options.ForceRecreate || options.RemoveOrphans {
		logger.WithField("project", options.ProjectName).Info("Checking for containers to remove")
		containersToRemove, err := m.findContainersToRemove(ctx, composeFile, options.ProjectName, options.ForceRecreate, options.RemoveOrphans)
		if err != nil {
			logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to find containers to remove")
			return fmt.Errorf("failed to find containers to remove: %w", err)
		}
		if len(containersToRemove) > 0 {
			logger.WithField("project", options.ProjectName).Infof("Removing %d containers", len(containersToRemove))
			if err := m.removeContainers(ctx, containersToRemove, false); err != nil {
				logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to remove existing/orphan containers")
			}
		}
	}

	if !options.NoBuild {
		logger.WithField("project", options.ProjectName).Info("Building or pulling images")
		err := m.prepareImages(ctx, composeFile, options.Pull)
		if err != nil {
			logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to prepare images")
			return fmt.Errorf("failed to prepare images: %w", err)
		}
	}

	for _, serviceName := range serviceOrder {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		serviceConfig, ok := composeFile.Services[serviceName]
		if !ok {
			logger.WithField("service", serviceName).Warn("Service definition not found, skipping deploy")
			continue
		}

		logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName}).Info("Deploying service")
		options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusCreating, "", nil)

		// TODO: Handle scaling (replicas > 1)

		containerID, err := m.createService(ctx, composeFile, serviceName, serviceConfig, options, 1) // Assume instance 1 for deploy
		if err != nil {
			logger.WithError(err).WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName}).Error("Failed to create service container")
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusFailed, "", err)
			return fmt.Errorf("failed to create service '%s': %w", serviceName, err)
		}
		options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusCreated, containerID, nil)

		if !options.NoStart {
			logger.WithField("service", serviceName).WithField("containerID", containerID).Info("Starting service container")
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusStarting, containerID, nil)
			if m.containerClient == nil {
				return fmt.Errorf("container client not configured")
			}
			err = m.containerClient.ContainerStart(ctx, containerID, container.StartOptions{})
			if err != nil {
				logger.WithError(err).WithField("service", serviceName).Error("Failed to start service container")
				options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusFailed, containerID, err)
				return fmt.Errorf("failed to start service '%s': %w", serviceName, err)
			}
			if err := m.waitForHealthCheck(ctx, containerID, serviceConfig); err != nil {
				logger.WithError(err).WithField("service", serviceName).Warn("Health check failed or timed out")
				options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusUnhealthy, containerID, err)
			} else {
				options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusRunning, containerID, nil)
			}
		} else {
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusCreated, containerID, nil)
		}
		logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName}).Info("Service deployed successfully")
	}
	return nil
}

// RemoveServices removes services in the specified order
func (m *ServiceManager) RemoveServices(ctx context.Context, composeFile *models.ComposeFile, serviceOrder []string, options ServiceRemoveOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = m.Logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	logger.WithField("project", options.ProjectName).Info("Finding service containers")
	serviceContainers, err := m.findProjectContainers(ctx, options.ProjectName)
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to find service containers")
		return fmt.Errorf("failed to find service containers: %w", err)
	}

	containersByService := make(map[string][]string)
	for _, cont := range serviceContainers {
		serviceName := cont.Labels["com.docker_test.compose.service"]
		if serviceName == "" {
			continue
		}
		containersByService[serviceName] = append(containersByService[serviceName], cont.ID)
	}

	var removeErrors []error
	for _, serviceName := range serviceOrder {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		containers, exists := containersByService[serviceName]
		if !exists || len(containers) == 0 {
			logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName}).Debug("No containers found for service")
			continue
		}

		logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName}).Info("Removing service")
		options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusRemoving, "", nil)

		for _, containerID := range containers {
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusRemoving, containerID, nil)

			if m.containerClient == nil {
				return fmt.Errorf("container client not configured")
			}
			contInfo, err := m.containerClient.ContainerInspect(ctx, containerID)
			if err == nil && contInfo.State != nil && contInfo.State.Running {
				stopTimeoutDuration := 10 * time.Second
				stopTimeoutSeconds := int(stopTimeoutDuration.Seconds())
				err = m.containerClient.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &stopTimeoutSeconds})
				if err != nil {
					m.Logger.WithError(err).WithField("container", containerID).Error("Failed to stop container")
				}
			}

			err = m.containerClient.ContainerRemove(ctx, containerID, container.RemoveOptions{
				RemoveVolumes: options.RemoveVolumes,
				Force:         options.Force,
			})
			if err != nil {
				m.Logger.WithError(err).WithField("container", containerID).Error("Failed to remove container")
				removeErrors = append(removeErrors, fmt.Errorf("failed to remove container %s: %w", containerID, err))
				continue
			}
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusRemoved, containerID, nil)
		}
		logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName}).Info("Service removed successfully")
	}

	if len(removeErrors) > 0 {
		logger.WithField("project", options.ProjectName).Errorf("Failed to remove %d containers", len(removeErrors))
		return fmt.Errorf("failed to remove some containers: %w", removeErrors[0])
	}

	if options.RemoveImages != "" {
		err = m.removeImages(ctx, composeFile, options.ProjectName, options.RemoveImages)
		if err != nil {
			logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to remove images")
		}
	}

	return nil
}

// StartServices starts services in the specified order
func (m *ServiceManager) StartServices(ctx context.Context, composeFile *models.ComposeFile, serviceOrder []string, options ServiceStartOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = m.Logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	logger.WithField("project", options.ProjectName).Info("Finding service containers")
	serviceContainers, err := m.findProjectContainers(ctx, options.ProjectName)
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to find service containers")
		return fmt.Errorf("failed to find service containers: %w", err)
	}

	containersByService := make(map[string][]types.Container)
	for _, cont := range serviceContainers {
		serviceName := cont.Labels["com.docker_test.compose.service"]
		if serviceName == "" {
			continue
		}
		containersByService[serviceName] = append(containersByService[serviceName], cont)
	}

	for _, serviceName := range serviceOrder {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		containers, exists := containersByService[serviceName]
		if !exists || len(containers) == 0 {
			logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName}).Debug("No containers found for service")
			continue
		}

		logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName}).Info("Starting service")
		options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusStarting, "", nil)

		var lastErr error
		var runningContainerID string
		for _, cont := range containers {
			if cont.State == "running" {
				logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName, "container": cont.ID}).Debug("Container already running")
				runningContainerID = cont.ID
				continue
			}

			options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusStarting, cont.ID, nil)

			if m.containerClient == nil {
				return fmt.Errorf("container client not configured")
			}
			err = m.containerClient.ContainerStart(ctx, cont.ID, container.StartOptions{})
			if err != nil {
				logger.WithError(err).WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName, "container": cont.ID}).Error("Failed to start container")
				lastErr = err
				break
			}
			runningContainerID = cont.ID
		}

		if lastErr != nil {
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusFailed, "", lastErr)
			return fmt.Errorf("failed to start service '%s': %w", serviceName, lastErr)
		}

		serviceConfig, serviceExists := composeFile.Services[serviceName]
		if runningContainerID != "" && serviceExists {
			if err := m.waitForHealthCheck(ctx, runningContainerID, serviceConfig); err != nil {
				logger.WithError(err).WithField("service", serviceName).Warn("Health check failed or timed out after start")
				options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusUnhealthy, runningContainerID, err)
			} else {
				options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusRunning, runningContainerID, nil)
			}
		} else {
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusRunning, "", nil)
		}
		logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName}).Info("Service started successfully")
	}
	return nil
}

// StopServices stops services in the specified order
func (m *ServiceManager) StopServices(ctx context.Context, composeFile *models.ComposeFile, serviceOrder []string, options ServiceStopOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = m.Logger
	}

	stopTimeoutSeconds := 10 // Default stop timeout
	if options.Timeout > 0 {
		stopTimeoutSeconds = int(options.Timeout.Seconds())
	}

	logger.WithField("project", options.ProjectName).Info("Finding service containers")
	serviceContainers, err := m.findProjectContainers(ctx, options.ProjectName)
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to find service containers")
		return fmt.Errorf("failed to find service containers: %w", err)
	}

	containersByService := make(map[string][]types.Container)
	for _, cont := range serviceContainers {
		serviceName := cont.Labels["com.docker_test.compose.service"]
		if serviceName == "" {
			continue
		}
		containersByService[serviceName] = append(containersByService[serviceName], cont)
	}

	for _, serviceName := range serviceOrder {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		containers, exists := containersByService[serviceName]
		if !exists || len(containers) == 0 {
			logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName}).Debug("No containers found for service")
			continue
		}

		logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName}).Info("Stopping service")
		options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusStopping, "", nil)

		var lastErr error
		for _, cont := range containers {
			if cont.State != "running" {
				logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName, "container": cont.ID}).Debug("Container already stopped")
				continue
			}

			options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusStopping, cont.ID, nil)

			if m.containerClient == nil {
				return fmt.Errorf("container client not configured")
			}
			err = m.containerClient.ContainerStop(ctx, cont.ID, container.StopOptions{Timeout: &stopTimeoutSeconds})
			if err != nil {
				m.Logger.WithError(err).WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName, "container": cont.ID}).Error("Failed to stop container")
				lastErr = err
			} else {
				options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusStopped, cont.ID, nil)
			}
		}
		if lastErr != nil {
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusFailed, "", lastErr)
		} else {
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, serviceName, models.ServiceStatusStopped, "", nil)
		}
		logger.WithFields(logrus.Fields{"project": options.ProjectName, "service": serviceName}).Info("Service stop initiated")
	}
	return nil
}

// ScaleService scales a specific service
func (m *ServiceManager) ScaleService(ctx context.Context, composeFile *models.ComposeFile, options ServiceScaleOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = m.Logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	logger.WithFields(logrus.Fields{
		"project":  options.ProjectName,
		"service":  options.Service,
		"replicas": options.Replicas,
	}).Info("Processing scale request")

	serviceConfig, ok := composeFile.Services[options.Service]
	if !ok {
		return fmt.Errorf("service '%s' not found in compose file", options.Service)
	}

	// 1. Find existing containers for the service
	existingContainers, err := m.findServiceContainers(ctx, options.ProjectName, options.Service)
	if err != nil {
		return fmt.Errorf("failed to find existing containers for service '%s': %w", options.Service, err)
	}
	currentCount := len(existingContainers)
	logger.Infof("Found %d existing containers for service '%s'", currentCount, options.Service)

	// 2. Calculate Difference
	diff := options.Replicas - currentCount

	if diff == 0 {
		logger.Infof("Service '%s' is already at the desired scale (%d replicas). No action needed.", options.Service, options.Replicas)
		return nil
	}

	// 3. Scale Up
	if diff > 0 {
		logger.Infof("Scaling up service '%s' by %d replicas", options.Service, diff)
		options.StatusTracker.UpdateServiceStatus(options.ProjectName, options.Service, models.ServiceStatusScalingUp, "", nil)

		// Find the highest existing instance number
		highestInstanceNum := 0
		for _, cont := range existingContainers {
			numStr := cont.Labels["com.docker_test.compose.container-number"]
			if num, err := strconv.Atoi(numStr); err == nil {
				if num > highestInstanceNum {
					highestInstanceNum = num
				}
			}
		}

		for i := 0; i < diff; i++ {
			instanceNum := highestInstanceNum + 1 + i
			logger.Infof("Creating instance %d for service '%s'", instanceNum, options.Service)
			// Need DeployOptions for createService, construct a minimal one
			deployOpts := ServiceDeployOptions{
				ProjectName:           options.ProjectName,
				AdjustNetworkSettings: true, // Assume network adjustment needed
				StatusTracker:         options.StatusTracker,
				Logger:                logger,
				// NoStart: true, // Maybe don't start immediately? Depends on desired scale behavior
			}
			containerID, err := m.createService(ctx, composeFile, options.Service, serviceConfig, deployOpts, instanceNum)
			if err != nil {
				logger.WithError(err).Errorf("Failed to create container instance %d for service '%s'", instanceNum, options.Service)
				options.StatusTracker.UpdateServiceStatus(options.ProjectName, options.Service, models.ServiceStatusFailed, "", err)
				return fmt.Errorf("failed to scale up service '%s': %w", options.Service, err)
			}
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, options.Service, models.ServiceStatusCreated, containerID, nil)

			// Start the newly created container
			logger.Infof("Starting new container instance %d (%s)", instanceNum, containerID)
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, options.Service, models.ServiceStatusStarting, containerID, nil)
			if m.containerClient == nil {
				return fmt.Errorf("container client not configured")
			}
			err = m.containerClient.ContainerStart(ctx, containerID, container.StartOptions{})
			if err != nil {
				logger.WithError(err).Errorf("Failed to start container instance %d (%s)", instanceNum, containerID)
				options.StatusTracker.UpdateServiceStatus(options.ProjectName, options.Service, models.ServiceStatusFailed, containerID, err)
				// Should we attempt to clean up the created container?
				_ = m.containerClient.ContainerRemove(context.Background(), containerID, container.RemoveOptions{Force: true})
				return fmt.Errorf("failed to start scaled up service '%s': %w", options.Service, err)
			}
			// Wait for health check? Might slow down scaling significantly. Optional.
			// if err := m.waitForHealthCheck(ctx, containerID, serviceConfig); err != nil { ... }
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, options.Service, models.ServiceStatusRunning, containerID, nil) // Mark as running after start
		}
		options.StatusTracker.UpdateServiceStatus(options.ProjectName, options.Service, models.ServiceStatusRunning, "", nil) // Overall status
	}

	// 4. Scale Down
	if diff < 0 {
		numToRemove := -diff
		logger.Infof("Scaling down service '%s' by %d replicas", options.Service, numToRemove)
		options.StatusTracker.UpdateServiceStatus(options.ProjectName, options.Service, models.ServiceStatusScalingDown, "", nil)

		if numToRemove > len(existingContainers) {
			logger.Warnf("Attempting to remove %d containers, but only %d exist for service '%s'. Removing all.", numToRemove, len(existingContainers), options.Service)
			numToRemove = len(existingContainers)
		}

		containersToRemove := m.selectContainersToScaleDown(existingContainers, numToRemove)
		logger.Infof("Removing %d containers: %v", len(containersToRemove), containersToRemove)

		if err := m.removeContainers(ctx, containersToRemove, false); err != nil {
			logger.WithError(err).Errorf("Failed to remove containers during scale down for service '%s'", options.Service)
			options.StatusTracker.UpdateServiceStatus(options.ProjectName, options.Service, models.ServiceStatusFailed, "", err)
			return fmt.Errorf("failed to scale down service '%s': %w", options.Service, err)
		}
		options.StatusTracker.UpdateServiceStatus(options.ProjectName, options.Service, models.ServiceStatusRunning, "", nil)
	}

	logger.Infof("Service '%s' scaled successfully to %d replicas", options.Service, options.Replicas)
	return nil
}

// --- Helper Methods ---

// createService creates a service container (internal helper)
// Added instanceNum parameter for scaling
func (m *ServiceManager) createService(ctx context.Context, composeFile *models.ComposeFile, serviceName string, service models.ServiceConfig, options ServiceDeployOptions, instanceNum int) (string, error) {
	containerName := fmt.Sprintf("%s_%s_%d", options.ProjectName, serviceName, instanceNum) // Naming convention for scaling
	containerConfig, hostConfig, networkingConfig, err := m.createContainerConfig(composeFile, options.ProjectName, serviceName, service, options.AdjustNetworkSettings)
	if err != nil {
		return "", fmt.Errorf("failed to create container config: %w", err)
	}
	if containerConfig.Labels == nil {
		containerConfig.Labels = make(map[string]string)
	}
	containerConfig.Labels["com.docker_test.compose.project"] = options.ProjectName
	containerConfig.Labels["com.docker_test.compose.service"] = serviceName
	containerConfig.Labels["com.docker_test.compose.version"] = composeFile.Version
	containerConfig.Labels["com.docker_test.compose.container-number"] = strconv.Itoa(instanceNum) // Use instance number
	containerConfig.Labels["com.docker_test.compose.oneoff"] = "False"

	if m.containerClient == nil {
		return "", fmt.Errorf("container client not configured")
	}
	resp, err := m.containerClient.ContainerCreate(ctx, containerConfig, hostConfig, networkingConfig, "", containerName) // Added empty platform arg
	if err != nil {
		return "", fmt.Errorf("failed to create container %s: %w", containerName, err)
	}
	if len(resp.Warnings) > 0 {
		m.Logger.WithField("warnings", resp.Warnings).Warn("Container create warnings")
	}
	return resp.ID, nil
}

// createContainerConfig creates container config (internal helper)
func (m *ServiceManager) createContainerConfig(composeFile *models.ComposeFile, projectName, serviceName string, service models.ServiceConfig, adjustNetworkSettings bool) (*container.Config, *container.HostConfig, *network.NetworkingConfig, error) {
	containerConfig := &container.Config{
		Image:       service.Image,
		AttachStdin: false, AttachStdout: true, AttachStderr: true, StdinOnce: false,
		Env:    m.convertEnvironment(service.Environment),
		Labels: m.convertLabels(service.Labels),
	}
	if service.Command != nil {
		containerConfig.Cmd = m.convertCommand(service.Command)
	}
	containerConfig.ExposedPorts = m.convertExposedPorts(service.Expose)

	hostConfig := &container.HostConfig{
		AutoRemove: false, Privileged: false, PublishAllPorts: false, ReadonlyRootfs: false,
	}
	hostConfig.RestartPolicy = m.convertRestartPolicy(service.Restart)
	mounts, err := m.convertVolumes(composeFile, service.Volumes, projectName) // Pass composeFile
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert volumes: %w", err)
	}
	hostConfig.Mounts = mounts
	portBindings, err := m.convertPortBindings(service.Ports)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert port bindings: %w", err)
	}
	hostConfig.PortBindings = portBindings

	networkingConfig := &network.NetworkingConfig{EndpointsConfig: make(map[string]*network.EndpointSettings)}
	// Determine NetworkMode for HostConfig
	if service.NetworkMode != "" {
		hostConfig.NetworkMode = container.NetworkMode(service.NetworkMode)
	}

	// Only configure EndpointsConfig if NetworkMode is bridge-like (default or user-defined bridge)
	// and adjustNetworkSettings is true.
	// If NetworkMode is host, none, or container:..., EndpointsConfig should be empty.
	isBridgeLike := hostConfig.NetworkMode == "" || (!hostConfig.NetworkMode.IsHost() && !hostConfig.NetworkMode.IsNone() && !hostConfig.NetworkMode.IsContainer())

	if adjustNetworkSettings && isBridgeLike {
		// Ensure the map is initialized (already done at creation)
		// networkingConfig.EndpointsConfig = make(map[string]*network.EndpointSettings)

		// Determine networks to connect to
		networksToConnect := make(map[string]*network.EndpointSettings)

		// Add default network if no specific networks are defined for the service
		if service.Networks == nil || len(service.Networks.(map[string]interface{})) == 0 { // Check map length
			// Find the first defined network in the project to use as default
			var projectDefaultNetwork string
			for netName := range composeFile.Networks {
				projectDefaultNetwork = netName
				break // Use the first one found
			}

			if projectDefaultNetwork != "" {
				dockerNetworkName := fmt.Sprintf("%s_%s", projectName, projectDefaultNetwork) // Use standard naming
				networksToConnect[dockerNetworkName] = &network.EndpointSettings{
					Aliases: []string{serviceName}, // Add default alias
				}
				m.Logger.Debugf("Service '%s' connecting to project default network '%s' (docker name: %s)", serviceName, projectDefaultNetwork, dockerNetworkName)
			} else {
				m.Logger.Warnf("Service '%s' has no specific networks and no project default network found. Relying on Docker default bridge.", serviceName)
				// Do not add to EndpointsConfig, let Docker handle default bridge connection
			}
		} else {
			// Add networks explicitly defined for the service
			switch nets := service.Networks.(type) {
			// Compose V3+ uses map format primarily
			case map[string]interface{}: // Map format with potential aliases etc.
				for netName, netConfigMap := range nets {
					// Ensure network exists in the top-level definition
					if _, exists := composeFile.Networks[netName]; exists {
						dockerNetworkName := fmt.Sprintf("%s_%s", projectName, netName) // Use standard naming
						endpointSettings := &network.EndpointSettings{
							Aliases: []string{serviceName}, // Start with default alias
						}
						// Try to parse aliases and other settings from map config
						if netConfig, ok := netConfigMap.(map[string]interface{}); ok && netConfig != nil { // Check netConfigMap is not nil
							if aliasesVal, ok := netConfig["aliases"].([]interface{}); ok {
								var specificAliases []string
								for _, aliasIf := range aliasesVal {
									if aliasStr, ok := aliasIf.(string); ok {
										specificAliases = append(specificAliases, aliasStr)
									}
								}
								// Use specific aliases if provided, otherwise keep default
								if len(specificAliases) > 0 {
									endpointSettings.Aliases = specificAliases
								}
							}
							// TODO: Handle other endpoint settings like ipv4_address, ipv6_address if needed
						} else if netConfigMap != nil {
							m.Logger.Warnf("Network config for '%s' in service '%s' is not a map or is nil, using default alias.", netName, serviceName)
						}
						networksToConnect[dockerNetworkName] = endpointSettings
						m.Logger.Debugf("Service '%s' connecting to specific network '%s' (docker name: %s) with aliases: %v", serviceName, netName, dockerNetworkName, endpointSettings.Aliases)
					} else {
						m.Logger.Warnf("Service '%s' references network '%s' which is not defined globally.", serviceName, netName)
					}
				}
			// Handle simple list format (less common in V3+)
			case []interface{}:
				for _, netIf := range nets {
					if netName, ok := netIf.(string); ok {
						if _, exists := composeFile.Networks[netName]; exists {
							dockerNetworkName := fmt.Sprintf("%s_%s", projectName, netName) // Use standard naming
							networksToConnect[dockerNetworkName] = &network.EndpointSettings{
								Aliases: []string{serviceName}, // Add default alias
							}
							m.Logger.Debugf("Service '%s' connecting to specific network '%s' (docker name: %s) from list", serviceName, netName, dockerNetworkName)
						} else {
							m.Logger.Warnf("Service '%s' references network '%s' from list which is not defined globally.", serviceName, netName)
						}
					}
				}
			default:
				m.Logger.Warnf("Unsupported type for service.Networks for service '%s': %T", serviceName, service.Networks)
			}
		}

		// Assign the determined endpoints if any were found
		if len(networksToConnect) > 0 {
			networkingConfig.EndpointsConfig = networksToConnect
		} else if isBridgeLike {
			// If it's bridge-like but no networks were resolved (e.g., no project default),
			// ensure EndpointsConfig is empty to rely on Docker's default bridge.
			networkingConfig.EndpointsConfig = make(map[string]*network.EndpointSettings)
			m.Logger.Debugf("Service '%s' has no explicit or default networks defined, relying on Docker default bridge.", serviceName)
		}

	} else {
		// Ensure EndpointsConfig is empty for non-bridge modes (host, none, container)
		networkingConfig.EndpointsConfig = make(map[string]*network.EndpointSettings)
		m.Logger.Debugf("Service '%s' uses network mode '%s', skipping endpoint configuration.", serviceName, hostConfig.NetworkMode)
	}

	// Add Healthcheck details to ContainerConfig if defined
	if service.HealthCheck != nil {
		hc := &container.HealthConfig{}
		hcMap := service.HealthCheck // Use the map directly

		// Parse test command
		if testVal, ok := hcMap["test"]; ok {
			switch v := testVal.(type) {
			case string:
				hc.Test = []string{"CMD-SHELL", v} // Default to CMD-SHELL
			case []interface{}:
				var testCmd []string
				for _, item := range v {
					if strItem, ok := item.(string); ok {
						testCmd = append(testCmd, strItem)
					}
				}
				hc.Test = testCmd
			case []string: // Handle if already []string
				hc.Test = v
			}
		}

		// Parse interval
		if intervalStr, ok := hcMap["interval"].(string); ok {
			if d, err := time.ParseDuration(intervalStr); err == nil {
				hc.Interval = d
			} else {
				m.Logger.WithError(err).WithField("interval", intervalStr).Warn("Failed to parse healthcheck interval")
			}
		}
		// Parse timeout
		if timeoutStr, ok := hcMap["timeout"].(string); ok {
			if d, err := time.ParseDuration(timeoutStr); err == nil {
				hc.Timeout = d
			} else {
				m.Logger.WithError(err).WithField("timeout", timeoutStr).Warn("Failed to parse healthcheck timeout")
			}
		}
		// Parse retries
		if retriesVal, ok := hcMap["retries"]; ok {
			switch v := retriesVal.(type) {
			case int:
				hc.Retries = v
			case float64:
				hc.Retries = int(v)
			}
		}
		// Parse start_period
		if startPeriodStr, ok := hcMap["start_period"].(string); ok {
			if d, err := time.ParseDuration(startPeriodStr); err == nil {
				hc.StartPeriod = d
			} else {
				m.Logger.WithError(err).WithField("start_period", startPeriodStr).Warn("Failed to parse healthcheck start_period")
			}
		}
		containerConfig.Healthcheck = hc
	}

	return containerConfig, hostConfig, networkingConfig, nil
}

// convertEnvironment converts environment variables
func (m *ServiceManager) convertEnvironment(env interface{}) []string {
	if env == nil {
		return nil
	}
	var result []string
	switch v := env.(type) {
	case map[string]string:
		for k, val := range v {
			result = append(result, fmt.Sprintf("%s=%s", k, val))
		}
	case map[string]interface{}:
		for k, val := range v {
			if val == nil {
				result = append(result, fmt.Sprintf("%s=", k))
			} else {
				result = append(result, fmt.Sprintf("%s=%v", k, val))
			}
		}
	case []string:
		result = append(result, v...)
	case []interface{}:
		for _, e := range v {
			if strVal, ok := e.(string); ok {
				result = append(result, strVal)
			}
		}
	}
	return result
}

// convertCommand converts a command
func (m *ServiceManager) convertCommand(cmd interface{}) strslice.StrSlice {
	if cmd == nil {
		return nil
	}
	var result strslice.StrSlice
	switch v := cmd.(type) {
	case string:
		result = strings.Fields(v)
	case []string:
		result = v
	case []interface{}:
		for _, c := range v {
			if strVal, ok := c.(string); ok {
				result = append(result, strVal)
			} else {
				result = append(result, fmt.Sprintf("%v", c))
			}
		}
	}
	return result
}

// convertExposedPorts converts exposed ports
func (m *ServiceManager) convertExposedPorts(exposedPorts interface{}) map[nat.Port]struct{} {
	result := make(map[nat.Port]struct{})
	if exposedPorts == nil {
		return result
	}
	parsePort := func(p string) {
		portProto := strings.SplitN(p, "/", 2)
		proto := "tcp"
		if len(portProto) == 2 {
			proto = portProto[1]
		}
		portStr := portProto[0]
		if strings.Contains(portStr, "-") {
			m.Logger.Warnf("Port range '%s' in expose section not fully supported yet", portStr)
			portStr = strings.SplitN(portStr, "-", 2)[0]
		}
		if natPort, err := nat.NewPort(proto, portStr); err == nil {
			result[natPort] = struct{}{}
		} else {
			m.Logger.Warnf("Failed to parse exposed port '%s': %v", p, err)
		}
	}
	switch v := exposedPorts.(type) {
	case []string:
		for _, p := range v {
			parsePort(p)
		}
	case []interface{}:
		for _, p := range v {
			if intVal, ok := p.(int); ok {
				p = fmt.Sprintf("%d", intVal)
			}
			if strVal, ok := p.(string); ok {
				parsePort(strVal)
			}
		}
	}
	return result
}

// convertPortBindings converts port bindings
func (m *ServiceManager) convertPortBindings(ports interface{}) (nat.PortMap, error) {
	result := make(nat.PortMap)
	if ports == nil {
		return result, nil
	}
	parseSpec := func(p string) error {
		binding, err := nat.ParsePortSpec(p)
		if err != nil {
			return fmt.Errorf("failed to parse port spec '%s': %w", p, err)
		}
		for _, b := range binding {
			result[b.Port] = append(result[b.Port], b.Binding)
		}
		return nil
	}
	// Handle ports which is now []interface{}
	switch v := ports.(type) {
	case []interface{}:
		for i, item := range v {
			var spec string
			switch p := item.(type) {
			case string:
				spec = p
			case int: // Handle integer ports (expose only)
				spec = fmt.Sprintf("%d", p)
			default:
				m.Logger.Warnf("Unsupported port type in list at index %d: %T", i, item)
				continue // Skip unsupported types
			}
			if err := parseSpec(spec); err != nil {
				return nil, fmt.Errorf("failed to parse port spec '%s' at index %d: %w", spec, i, err)
			}
		}
	case []string: // Handle if YAML parser gives []string directly
		m.Logger.Debug("Processing ports as []string")
		for i, spec := range v {
			if err := parseSpec(spec); err != nil {
				return nil, fmt.Errorf("failed to parse port spec string '%s' at index %d: %w", spec, i, err)
			}
		}
	default:
		m.Logger.Warnf("Unexpected type for ports field: %T", ports)
		// Return empty map or error depending on strictness
	}
	return result, nil
}

// convertVolumes converts volumes
func (m *ServiceManager) convertVolumes(composeFile *models.ComposeFile, volumes interface{}, projectName string) ([]mount.Mount, error) { // Add composeFile
	mounts := []mount.Mount{} // Initialize directly
	if volumes == nil {
		return mounts, nil
	}

	// Handle volumes defined as []interface{} which can contain strings or maps
	// Handle volumes which is now interface{}
	switch v := volumes.(type) {
	case []interface{}: // Most common case: list of strings or maps
		m.Logger.Debug("Processing volumes as []interface{}")
		for i, item := range v {
			var mnt mount.Mount
			var err error
			switch spec := item.(type) { // Use a type switch on the item
			case string:
				mnt, err = m.parseVolumeSpec(composeFile, spec, projectName) // Pass composeFile
				if err != nil {
					return nil, fmt.Errorf("failed to parse volume spec string '%s' at index %d: %w", spec, i, err)
				}
			case map[string]interface{}:
				mnt, err = m.parseVolumeMap(composeFile, spec, projectName) // Pass composeFile
				if err != nil {
					return nil, fmt.Errorf("failed to parse volume map spec at index %d: %w", i, err)
				}
			default:
				return nil, fmt.Errorf("unsupported volume type in list at index %d: %T", i, item)
			}
			mounts = append(mounts, mnt)
		}
	case []string: // Handle if YAML parser somehow gives []string directly
		m.Logger.Debug("Processing volumes as []string")
		for i, spec := range v {
			mnt, err := m.parseVolumeSpec(composeFile, spec, projectName) // Pass composeFile
			if err != nil {
				return nil, fmt.Errorf("failed to parse volume spec string '%s' at index %d: %w", spec, i, err)
			}
			mounts = append(mounts, mnt)
		}
	default:
		m.Logger.Warnf("Unexpected type for volumes field: %T", volumes)
		// Return empty slice or error depending on desired strictness
		// return nil, fmt.Errorf("unexpected type for volumes field: %T", volumes)
	}

	return mounts, nil // Return the populated mounts slice
}

// parseVolumeMap parses a volume definition provided as a map
// Example: { type: volume, source: mydata, target: /data, volume: { nocopy: true } }
func (m *ServiceManager) parseVolumeMap(composeFile *models.ComposeFile, spec map[string]interface{}, projectName string) (mount.Mount, error) { // Add composeFile
	mnt := mount.Mount{}

	target, ok := spec["target"].(string)
	if !ok || target == "" {
		return mnt, fmt.Errorf("volume map spec missing or invalid 'target'")
	}
	mnt.Target = target

	volTypeStr, _ := spec["type"].(string)
	mnt.Type = mount.Type(volTypeStr) // Defaults to "" which might be okay, maps to 'volume' often

	source, _ := spec["source"].(string)
	mnt.Source = source // Can be empty for anonymous volumes

	if mnt.Type == "" {
		mnt.Type = mount.TypeVolume // Default to volume type if not specified
	}

	// Handle volume naming and external checks
	if mnt.Type == mount.TypeVolume && source != "" {
		// Check top-level volumes definition first
		isExternal := false
		if topLevelVol, exists := composeFile.Volumes[source]; exists {
			if externalBool, ok := topLevelVol.External.(bool); ok && externalBool { // Type assert to bool
				isExternal = true
				m.Logger.Debugf("Volume '%s' is defined as external in top-level volumes.", source)
			}
		}

		// Check if volume is defined as external in the service map spec itself (overrides top-level)
		if volOpts, ok := spec["volume"].(map[string]interface{}); ok {
			if extVal, ok := volOpts["external"].(bool); ok {
				isExternal = extVal // Service-level overrides top-level
				m.Logger.Debugf("Volume '%s' external flag overridden at service level to: %t", source, isExternal)
			}
			// TODO: Parse nocopy: volOpts["nocopy"]
		}

		// If not external, prepend project name
		if !isExternal {
			mnt.Source = utils.GetResourceName(projectName, "volume", source)
			m.Logger.Debugf("Volume '%s' is not external, prepending project name: %s", source, mnt.Source)
		} else {
			m.Logger.Debugf("Volume '%s' is external, using original source name.", source)
		}

	} else if mnt.Type == mount.TypeBind {
		// Path resolution should be handled by compose-go loader if WorkingDir is set correctly.
		// We just log the bind mount details.
		m.Logger.Debugf("Identified bind mount: Source='%s', Target='%s'", source, mnt.Target)
	}

	if readOnly, ok := spec["read_only"].(bool); ok {
		mnt.ReadOnly = readOnly
	}

	// TODO: Parse other fields like bind options (propagation), tmpfs options etc.
	m.Logger.Debugf("Parsed volume map spec: %+v", mnt)

	return mnt, nil
}

// parseVolumeSpec parses a volume specification string (e.g., "source:target:mode")
func (m *ServiceManager) parseVolumeSpec(composeFile *models.ComposeFile, spec string, projectName string) (mount.Mount, error) { // Add composeFile
	parts := strings.Split(spec, ":")
	mnt := mount.Mount{}
	switch len(parts) {
	case 1: // Anonymous volume or named volume path in container
		mnt.Target = parts[0]
		mnt.Type = mount.TypeVolume
		// Source is empty for anonymous volume, Docker handles creation.
	case 2: // Host path/Named volume mapped to container path
		source := parts[0]
		mnt.Target = parts[1]
		// Check if it's an absolute path or starts with './' or '../' -> likely a bind mount
		// compose-go loader should resolve paths relative to the compose file's dir if WorkingDir is set.
		if filepath.IsAbs(source) || strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
			mnt.Type = mount.TypeBind
			mnt.Source = source
			m.Logger.Debugf("Identified bind mount from string spec: Source='%s', Target='%s'", source, mnt.Target)
		} else {
			// Assume named volume
			mnt.Type = mount.TypeVolume
			// Check if volume is defined as external in top-level 'volumes'
			isExternal := false
			if topLevelVol, exists := composeFile.Volumes[source]; exists {
				if externalBool, ok := topLevelVol.External.(bool); ok && externalBool { // Type assert to bool
					isExternal = true
					m.Logger.Debugf("Volume '%s' is defined as external in top-level volumes.", source)
				}
			}
			// If not external, prepend project name
			if !isExternal {
				mnt.Source = utils.GetResourceName(projectName, "volume", source)
				m.Logger.Debugf("Volume '%s' is not external, prepending project name: %s", source, mnt.Source)
			} else {
				mnt.Source = source // Use original name if external
				m.Logger.Debugf("Volume '%s' is external, using original source name.", source)
			}
		}
	case 3: // Host path/Named volume mapped to container path with mode
		source := parts[0]
		mnt.Target = parts[1]
		mode := parts[2]
		// Check if it's an absolute path or starts with './' or '../' -> likely a bind mount
		if filepath.IsAbs(source) || strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
			mnt.Type = mount.TypeBind
			mnt.Source = source
			m.Logger.Debugf("Identified bind mount from string spec: Source='%s', Target='%s', Mode='%s'", source, mnt.Target, mode)
		} else {
			// Assume named volume
			mnt.Type = mount.TypeVolume
			// Check if volume is defined as external in top-level 'volumes'
			isExternal := false
			if topLevelVol, exists := composeFile.Volumes[source]; exists {
				if externalBool, ok := topLevelVol.External.(bool); ok && externalBool { // Type assert to bool
					isExternal = true
					m.Logger.Debugf("Volume '%s' is defined as external in top-level volumes.", source)
				}
			}
			// If not external, prepend project name
			if !isExternal {
				mnt.Source = utils.GetResourceName(projectName, "volume", source)
				m.Logger.Debugf("Volume '%s' is not external, prepending project name: %s", source, mnt.Source)
			} else {
				mnt.Source = source // Use original name if external
				m.Logger.Debugf("Volume '%s' is external, using original source name.", source)
			}
		}
		// Parse mode options
		options := strings.Split(mode, ",")
		for _, opt := range options {
			switch strings.ToLower(opt) {
			case "ro":
				mnt.ReadOnly = true
			case "rw":
				mnt.ReadOnly = false
			// TODO: Handle other modes like 'nocopy', 'z', 'Z' if necessary
			default:
				m.Logger.Warnf("Unsupported volume mode option '%s' in spec '%s'", opt, spec)
			}
		}

	default:
		return mnt, fmt.Errorf("invalid volume specification format: '%s'", spec)
	} // End switch len(parts)
	return mnt, nil // Return the parsed mount
}

// convertRestartPolicy converts restart policy string to Docker type
func (m *ServiceManager) convertRestartPolicy(restart string) container.RestartPolicy {
	policy := container.RestartPolicy{Name: "no"}
	if restart == "" {
		return policy
	}
	parts := strings.SplitN(restart, ":", 2)
	policy.Name = container.RestartPolicyMode(parts[0]) // Cast string to RestartPolicyMode
	if len(parts) == 2 {
		if attempts, err := strconv.Atoi(parts[1]); err == nil {
			policy.MaximumRetryCount = attempts
		} else {
			m.Logger.Warnf("Failed to parse restart policy attempts: %s", parts[1])
		}
	}
	// Map common compose restart values to Docker API values
	switch policy.Name {
	case "always":
		policy.Name = "always"
	case "unless-stopped":
		policy.Name = "unless-stopped"
	case "on-failure":
		policy.Name = "on-failure"
	case "no":
		policy.Name = "no"
	default:
		m.Logger.Warnf("Unsupported restart policy: %s, defaulting to 'no'", restart)
		policy.Name = "no"
	}
	return policy
}

// convertExtraHosts converts extra hosts
func (m *ServiceManager) convertExtraHosts(extraHosts interface{}) []string {
	if extraHosts == nil {
		return nil
	}
	var result []string
	switch v := extraHosts.(type) {
	case []string:
		result = v
	case []interface{}:
		for _, h := range v {
			if strVal, ok := h.(string); ok {
				result = append(result, strVal)
			}
		}
	case map[string]string: // Handle map format {hostname: ip}
		for host, ip := range v {
			result = append(result, fmt.Sprintf("%s:%s", host, ip))
		}
	case map[string]interface{}:
		for host, ip := range v {
			result = append(result, fmt.Sprintf("%s:%v", host, ip))
		}
	}
	return result
}

// convertDNS converts DNS servers
func (m *ServiceManager) convertDNS(dns interface{}) []string {
	if dns == nil {
		return nil
	}
	var result []string
	switch v := dns.(type) {
	case string:
		result = []string{v}
	case []string:
		result = v
	case []interface{}:
		for _, d := range v {
			if strVal, ok := d.(string); ok {
				result = append(result, strVal)
			}
		}
	}
	return result
}

// convertLabels converts labels
func (m *ServiceManager) convertLabels(labels interface{}) map[string]string {
	result := make(map[string]string)
	if labels == nil {
		return result
	}
	switch v := labels.(type) {
	case map[string]string:
		for k, val := range v {
			result[k] = val
		}
	case map[string]interface{}:
		for k, val := range v {
			result[k] = fmt.Sprintf("%v", val)
		}
	case []string: // Handle list format ["key=value", "keyonly"]
		for _, l := range v {
			parts := strings.SplitN(l, "=", 2)
			if len(parts) == 2 {
				result[parts[0]] = parts[1]
			} else {
				result[parts[0]] = "" // Label without value
			}
		}
	case []interface{}:
		for _, l := range v {
			if strVal, ok := l.(string); ok {
				parts := strings.SplitN(strVal, "=", 2)
				if len(parts) == 2 {
					result[parts[0]] = parts[1]
				} else {
					result[parts[0]] = ""
				}
			}
		}
	}
	return result
}

// prepareImages ensures images are available locally (pull or build)
func (m *ServiceManager) prepareImages(ctx context.Context, composeFile *models.ComposeFile, pull bool) error {
	if m.imageClient == nil {
		return fmt.Errorf("image client not configured")
	}
	for serviceName, service := range composeFile.Services {
		if service.Image != "" {
			if pull {
				m.Logger.WithFields(logrus.Fields{"service": serviceName, "image": service.Image}).Info("Pulling image")
				// TODO: Add authentication support for private registries if needed
				_, err := m.imageClient.ImagePull(ctx, service.Image, imagetypes.PullOptions{})
				if err != nil {
					return fmt.Errorf("failed to pull image '%s' for service '%s': %w", service.Image, serviceName, err)
				}
			} else {
				// Check if image exists locally
				_, _, err := m.imageClient.ImageInspectWithRaw(ctx, service.Image)
				if err != nil {
					// If image not found locally and pull is false, try pulling anyway? Or error?
					// Current docker-compose behavior often pulls if not found locally. Let's mimic that.
					m.Logger.WithFields(logrus.Fields{"service": serviceName, "image": service.Image}).Info("Image not found locally, attempting pull")
					_, errPull := m.imageClient.ImagePull(ctx, service.Image, imagetypes.PullOptions{})
					if errPull != nil {
						return fmt.Errorf("failed to pull image '%s' for service '%s' (not found locally and pull failed): %w", service.Image, serviceName, errPull)
					}
				}
			}
		} else if service.Build != nil {
			// TODO: Implement image building logic if service.Build is defined
			m.Logger.WithField("service", serviceName).Warn("Image building from compose file is not implemented yet")
			return fmt.Errorf("image building for service '%s' is not implemented", serviceName)
		}
	}
	return nil
}

// waitForHealthCheck waits for a container's health check to pass
func (m *ServiceManager) waitForHealthCheck(ctx context.Context, containerID string, service models.ServiceConfig) error {
	if service.HealthCheck == nil {
		m.Logger.WithField("container", containerID).Debug("No healthcheck defined.")
		return nil // No healthcheck defined
	}
	if m.containerClient == nil {
		return fmt.Errorf("container client not configured")
	}

	interval, timeout, retries, startPeriod := 5*time.Second, 30*time.Second, 3, 0*time.Second
	if service.HealthCheck != nil { // Check if the map is non-nil
		hcMap := service.HealthCheck // Assign to local variable hcMap
		// Parse test command (if present) - Note: Docker SDK handles this, this is for info/logging
		if testVal, ok := hcMap["test"]; ok {
			m.Logger.WithField("container", containerID).Debugf("Healthcheck test command: %v", testVal)
		}

		// Parse interval
		if intervalStr, ok := hcMap["interval"].(string); ok {
			if d, err := time.ParseDuration(intervalStr); err == nil {
				interval = d
			} else {
				m.Logger.WithError(err).WithField("interval", intervalStr).Warn("Failed to parse healthcheck interval")
			}
		}
		// Parse timeout
		if timeoutStr, ok := hcMap["timeout"].(string); ok {
			if d, err := time.ParseDuration(timeoutStr); err == nil {
				timeout = d
			} else {
				m.Logger.WithError(err).WithField("timeout", timeoutStr).Warn("Failed to parse healthcheck timeout")
			}
		}
		// Parse retries
		if retriesVal, ok := hcMap["retries"]; ok {
			// YAML might parse numbers as float64 or int
			switch v := retriesVal.(type) {
			case int:
				retries = v
			case float64:
				retries = int(v) // Convert float64 to int
			default:
				m.Logger.WithField("retries", retriesVal).Warn("Failed to parse healthcheck retries (unexpected type)")
			}
		}
		// Parse start_period
		if startPeriodStr, ok := hcMap["start_period"].(string); ok {
			if d, err := time.ParseDuration(startPeriodStr); err == nil {
				startPeriod = d
			} else {
				m.Logger.WithError(err).WithField("start_period", startPeriodStr).Warn("Failed to parse healthcheck start_period")
			}
		}
	} else {
		// No healthcheck defined in compose file, nothing to wait for
		m.Logger.WithField("container", containerID).Debug("No healthcheck defined for service.")
		return nil
	}

	startTime := time.Now()
	deadline := startTime.Add(timeout * time.Duration(retries+1)) // Overall deadline considering retries
	// startDeadline := startTime.Add(startPeriod) // Removed unused variable
	m.Logger.WithField("container", containerID).Infof("Waiting for container health check (Interval: %s, Timeout: %s, Retries: %d, StartPeriod: %s)", interval, timeout, retries, startPeriod)

	// Wait for start period first
	if startPeriod > 0 {
		m.Logger.WithField("container", containerID).Debugf("Waiting for start period (%s) to complete...", startPeriod)
		select {
		case <-time.After(startPeriod):
			// Continue after start period
		case <-ctx.Done():
			return fmt.Errorf("context cancelled during healthcheck start period: %w", ctx.Err())
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	failureCount := 0

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for health check: %w", ctx.Err())
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("health check overall deadline exceeded after %v", time.Since(startTime))
			}

			inspectCtx, inspectCancel := context.WithTimeout(ctx, timeout) // Use individual check timeout
			inspectData, err := m.containerClient.ContainerInspect(inspectCtx, containerID)
			inspectCancel() // Release context resources

			if err != nil {
				// Container might have stopped unexpectedly
				return fmt.Errorf("failed to inspect container %s during health check: %w", containerID, err)
			}

			if inspectData.State == nil || inspectData.State.Health == nil {
				// Health status not available yet, treat as pending/starting
				m.Logger.WithField("container", containerID).Debug("Health status not available yet.")
				// Consider if we should fail here after some time or retries
				continue
			}

			status := inspectData.State.Health.Status
			m.Logger.WithField("container", containerID).Debugf("Health status: %s", status)

			switch status {
			case "healthy":
				m.Logger.WithField("container", containerID).Info("Health check passed.")
				return nil // Healthy!
			case "unhealthy":
				failureCount++
				m.Logger.WithField("container", containerID).Warnf("Health check failed (%d/%d)", failureCount, retries)
				if failureCount > retries {
					return fmt.Errorf("health check failed after %d retries", retries)
				}
			case "starting":
				// Still starting, continue waiting
				m.Logger.WithField("container", containerID).Debug("Health check status: starting")
			default:
				// Unknown status, log and continue? Or fail?
				m.Logger.WithField("container", containerID).Warnf("Unknown health status: %s", status)
			}
		}
	}
}

// findProjectContainers finds containers belonging to a specific project
func (m *ServiceManager) findProjectContainers(ctx context.Context, projectName string) ([]types.Container, error) {
	if m.containerClient == nil {
		return nil, fmt.Errorf("container client not configured")
	}
	filters := filters.NewArgs()
	filters.Add("label", fmt.Sprintf("com.docker_test.compose.project=%s", projectName))

	containers, err := m.containerClient.ContainerList(ctx, container.ListOptions{
		All:     true, // Include stopped containers
		Filters: filters,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers for project '%s': %w", projectName, err)
	}
	return containers, nil
}

// findServiceContainers finds containers belonging to a specific service within a project
func (m *ServiceManager) findServiceContainers(ctx context.Context, projectName, serviceName string) ([]types.Container, error) {
	if m.containerClient == nil {
		return nil, fmt.Errorf("container client not configured")
	}
	filters := filters.NewArgs()
	filters.Add("label", fmt.Sprintf("com.docker_test.compose.project=%s", projectName))
	filters.Add("label", fmt.Sprintf("com.docker_test.compose.service=%s", serviceName))

	containers, err := m.containerClient.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filters,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers for service '%s' in project '%s': %w", serviceName, projectName, err)
	}
	return containers, nil
}

// findContainersToRemove identifies containers to be removed based on options
func (m *ServiceManager) findContainersToRemove(ctx context.Context, composeFile *models.ComposeFile, projectName string, forceRecreate, removeOrphans bool) ([]types.Container, error) {
	containers, err := m.findProjectContainers(ctx, projectName)
	if err != nil {
		return nil, err
	}

	toRemove := []types.Container{}
	definedServices := make(map[string]bool)
	for name := range composeFile.Services {
		definedServices[name] = true
	}

	for _, cont := range containers {
		serviceName := cont.Labels["com.docker_test.compose.service"]
		isOrphan := !definedServices[serviceName]

		if forceRecreate && definedServices[serviceName] {
			// Remove if forceRecreate is true and the service is still defined
			toRemove = append(toRemove, cont)
		} else if removeOrphans && isOrphan {
			// Remove if removeOrphans is true and the service is no longer defined
			m.Logger.WithFields(logrus.Fields{"project": projectName, "container": cont.ID, "service": serviceName}).Info("Marking orphan container for removal")
			toRemove = append(toRemove, cont)
		}
		// TODO: Add logic for removing containers whose configuration has diverged if needed (more complex)
	}
	return toRemove, nil
}

// removeContainers stops and removes a list of containers
func (m *ServiceManager) removeContainers(ctx context.Context, containers []types.Container, removeVolumes bool) error {
	if m.containerClient == nil {
		return fmt.Errorf("container client not configured")
	}
	var errors []error
	for _, cont := range containers {
		m.Logger.WithField("container", cont.ID).Info("Removing container")
		// Stop first if running
		if cont.State == "running" {
			stopTimeout := 10 // seconds
			err := m.containerClient.ContainerStop(ctx, cont.ID, container.StopOptions{Timeout: &stopTimeout})
			if err != nil {
				m.Logger.WithError(err).WithField("container", cont.ID).Warn("Failed to stop container before removal, forcing removal")
				// Continue to force remove
			}
		}
		// Remove container
		err := m.containerClient.ContainerRemove(ctx, cont.ID, container.RemoveOptions{
			RemoveVolumes: removeVolumes,
			Force:         true, // Force removal if stop failed or other issues
		})
		if err != nil {
			m.Logger.WithError(err).WithField("container", cont.ID).Error("Failed to remove container")
			errors = append(errors, err)
		}
	}
	if len(errors) > 0 {
		// Combine errors? For now, return the first one.
		return fmt.Errorf("failed to remove one or more containers: %w", errors[0])
	}
	return nil
}

// removeImages removes images associated with the deployment
func (m *ServiceManager) removeImages(ctx context.Context, composeFile *models.ComposeFile, projectName, removeImages string) error {
	if m.imageClient == nil {
		return fmt.Errorf("image client not configured")
	}
	if removeImages != "all" && removeImages != "local" {
		return fmt.Errorf("invalid removeImages option: %s (must be 'all' or 'local')", removeImages)
	}

	m.Logger.WithFields(logrus.Fields{"project": projectName, "mode": removeImages}).Info("Removing images")
	var errors []error

	for serviceName, service := range composeFile.Services {
		imageName := service.Image
		if imageName == "" {
			// TODO: Determine image name if built from context? Requires storing build info.
			m.Logger.WithField("service", serviceName).Warn("Cannot remove image for service without explicit image name (build not supported)")
			continue
		}

		// Check if image is used by other running containers outside this project? (Complex)
		// For now, attempt removal directly.

		// 'local' typically means remove images without a tag. Docker prune might be better?
		// 'all' means remove the specific image tag used.
		if removeImages == "all" {
			m.Logger.WithField("image", imageName).Info("Attempting to remove image")
			_, err := m.imageClient.ImageRemove(ctx, imageName, imagetypes.RemoveOptions{
				Force:         false, // Don't force by default
				PruneChildren: true,  // Remove dangling parents
			})
			if err != nil {
				// Ignore "image not found" errors, log others
				if !strings.Contains(err.Error(), "No such image") {
					m.Logger.WithError(err).WithField("image", imageName).Warn("Failed to remove image")
					errors = append(errors, err)
				}
			}
		} else if removeImages == "local" {
			// This is harder to map directly. Docker prune dangling images might be closer.
			// Let's skip 'local' for now as its definition is ambiguous here.
			m.Logger.Warn("removeImages=local is not fully implemented, skipping image removal.")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to remove one or more images: %w", errors[0])
	}
	return nil
}

// selectContainersToScaleDown selects which containers to remove when scaling down.
// Currently uses a simple strategy: remove containers with the highest numbers first.
func (m *ServiceManager) selectContainersToScaleDown(containers []types.Container, numToRemove int) []types.Container {
	if numToRemove <= 0 || len(containers) == 0 {
		return []types.Container{}
	}
	if numToRemove >= len(containers) {
		return containers // Remove all
	}

	// Sort containers by container number descending
	sort.SliceStable(containers, func(i, j int) bool {
		numI, _ := strconv.Atoi(containers[i].Labels["com.docker_test.compose.container-number"])
		numJ, _ := strconv.Atoi(containers[j].Labels["com.docker_test.compose.container-number"])
		return numI > numJ // Higher number first
	})

	return containers[:numToRemove]
}
