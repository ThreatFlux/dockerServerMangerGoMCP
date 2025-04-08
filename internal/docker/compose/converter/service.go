package converter

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	composetypes "github.com/compose-spec/compose-go/v2/types" // Added compose types import
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/sirupsen/logrus"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/docker_test/compose" // Removed old import
)

// ServiceConverter is responsible for converting Docker Compose service definitions to Docker API structures
type ServiceConverter struct {
	logger      *logrus.Logger
	projectName string
	workingDir  string
}

// NewServiceConverter creates a new service converter
func NewServiceConverter(projectName, workingDir string, logger *logrus.Logger) *ServiceConverter {
	if logger == nil {
		logger = logrus.New()
	}

	return &ServiceConverter{
		logger:      logger,
		projectName: projectName,
		workingDir:  workingDir,
	}
}

// ConvertOptions defines options for converting a service
type ConvertOptions struct {
	// Timeout is the operation timeout
	Timeout time.Duration

	// Logger is the logger to use
	Logger *logrus.Logger

	// DefaultNetworkMode is the default network mode to use
	DefaultNetworkMode string

	// PullPolicy is the image pull policy to use
	PullPolicy string

	// UseResourceLimits indicates whether to apply resource limits
	UseResourceLimits bool

	// NetworkNameResolver is a function to resolve Docker Compose network names to Docker network IDs
	NetworkNameResolver func(string) (string, error)

	// EnvOverrides contains environment variables that override service-defined ones
	EnvOverrides map[string]string

	// Index is the service instance index for generating unique container names
	Index int
}

// ConvertServiceResult contains the result of converting a service
type ConvertServiceResult struct {
	ContainerConfig     *container.Config
	HostConfig          *container.HostConfig
	NetworkingConfig    *network.NetworkingConfig
	ContainerName       string
	Networks            []string
	DependsOn           []string
	DependsOnConditions map[string]string
}

// ConvertService converts a Docker Compose service to Docker API container configs
func (c *ServiceConverter) ConvertService(ctx context.Context, serviceName string, service composetypes.ServiceConfig, options ConvertOptions) (*ConvertServiceResult, error) { // Use composetypes.ServiceConfig
	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = c.logger
	}

	logger.WithField("service", serviceName).Debug("Converting service")

	// Create result
	result := &ConvertServiceResult{
		ContainerConfig: &container.Config{},
		HostConfig:      &container.HostConfig{},
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: make(map[string]*network.EndpointSettings),
		},
	}

	// Set container name
	result.ContainerName = GenerateContainerName(c.projectName, serviceName, options.Index)

	// Convert basic fields
	if err := c.convertBasicFields(service, result); err != nil {
		return nil, fmt.Errorf("failed to convert basic fields: %w", err)
	}

	// Convert command, entrypoint
	if err := c.convertCommandFields(service, result); err != nil {
		return nil, fmt.Errorf("failed to convert command fields: %w", err)
	}

	// Convert ports
	if err := c.convertPorts(service, result); err != nil {
		return nil, fmt.Errorf("failed to convert ports: %w", err)
	}

	// Convert volumes
	if err := c.convertVolumes(service, result); err != nil {
		return nil, fmt.Errorf("failed to convert volumes: %w", err)
	}

	// Convert environment
	if err := c.convertEnvironment(service, options.EnvOverrides, result); err != nil {
		return nil, fmt.Errorf("failed to convert environment: %w", err)
	}

	// Convert restart policy
	c.convertRestartPolicy(service, result)

	// Convert health check
	if err := c.convertHealthCheck(service, result); err != nil {
		return nil, fmt.Errorf("failed to convert health check: %w", err)
	}

	// Convert networks
	if err := c.convertNetworks(service, options.NetworkNameResolver, result); err != nil {
		return nil, fmt.Errorf("failed to convert networks: %w", err)
	}

	// Convert resource limits if enabled
	if options.UseResourceLimits {
		if err := c.convertResourceLimits(service, result); err != nil {
			return nil, fmt.Errorf("failed to convert resource limits: %w", err)
		}
	}

	// Convert depends_on
	if err := c.convertDependsOn(service, result); err != nil {
		return nil, fmt.Errorf("failed to convert depends_on: %w", err)
	}

	// Set default network mode if no networks specified
	if len(result.Networks) == 0 && options.DefaultNetworkMode != "" {
		result.HostConfig.NetworkMode = container.NetworkMode(options.DefaultNetworkMode)
	}

	return result, nil
}

// convertBasicFields converts basic service fields like image, user, working_dir, etc.
func (c *ServiceConverter) convertBasicFields(service composetypes.ServiceConfig, result *ConvertServiceResult) error { // Use composetypes.ServiceConfig
	// Image
	result.ContainerConfig.Image = service.Image // This field exists directly

	// User
	if service.User != "" {
		result.ContainerConfig.User = service.User
	}

	// Working directory
	if service.WorkingDir != "" {
		result.ContainerConfig.WorkingDir = service.WorkingDir
	}

	// TTY and stdin settings
	result.ContainerConfig.Tty = service.Tty
	result.ContainerConfig.OpenStdin = service.StdinOpen

	// Labels
	var err error
	result.ContainerConfig.Labels, err = ConvertLabels(service.Labels)
	if err != nil {
		return fmt.Errorf("failed to convert labels: %w", err)
	}

	// Add project labels
	if result.ContainerConfig.Labels == nil {
		result.ContainerConfig.Labels = make(map[string]string)
	}
	result.ContainerConfig.Labels["com.docker_test.compose.project"] = c.projectName
	result.ContainerConfig.Labels["com.docker_test.compose.service"] = service.Name

	// Hostname
	result.ContainerConfig.Hostname = service.Name

	return nil
}

// convertCommandFields converts command and entrypoint fields
func (c *ServiceConverter) convertCommandFields(service composetypes.ServiceConfig, result *ConvertServiceResult) error { // Use composetypes.ServiceConfig
	// Command
	if service.Command != nil {
		cmd, err := ConvertCommand(service.Command)
		if err != nil {
			return fmt.Errorf("failed to convert command: %w", err)
		}
		result.ContainerConfig.Cmd = cmd
	}

	// Entrypoint
	if service.Entrypoint != nil {
		entrypoint, err := ConvertCommand(service.Entrypoint)
		if err != nil {
			return fmt.Errorf("failed to convert entrypoint: %w", err)
		}
		result.ContainerConfig.Entrypoint = entrypoint
	}

	return nil
}

// convertPorts converts ports and exposed ports
func (c *ServiceConverter) convertPorts(service composetypes.ServiceConfig, result *ConvertServiceResult) error { // Use composetypes.ServiceConfig
	// Convert ports
	if service.Ports != nil {
		portBindings, exposedPorts, err := ConvertPorts(service.Ports)
		if err != nil {
			return fmt.Errorf("failed to convert ports: %w", err)
		}
		result.HostConfig.PortBindings = portBindings
		result.ContainerConfig.ExposedPorts = exposedPorts
	}

	// Convert exposed ports (without publishing)
	if service.Expose != nil { // Use Expose field
		exposedPorts, err := ConvertExposedPorts(service.Expose) // Use Expose field
		if err != nil {
			return fmt.Errorf("failed to convert exposed ports: %w", err)
		}

		// Merge with existing exposed ports from regular ports
		if result.ContainerConfig.ExposedPorts == nil {
			result.ContainerConfig.ExposedPorts = exposedPorts
		} else {
			for port, value := range exposedPorts {
				result.ContainerConfig.ExposedPorts[port] = value
			}
		}
	}

	return nil
}

// convertVolumes converts volume mounts
func (c *ServiceConverter) convertVolumes(service composetypes.ServiceConfig, result *ConvertServiceResult) error { // Use composetypes.ServiceConfig
	if service.Volumes == nil {
		return nil
	}

	// Convert volumes
	mounts, anonymousVolumes, err := ConvertVolumes(service.Volumes, c.workingDir, c.logger)
	if err != nil {
		return fmt.Errorf("failed to convert volumes: %w", err)
	}

	// Set mounts
	result.HostConfig.Mounts = mounts

	// Add anonymous volumes to container config
	if len(anonymousVolumes) > 0 {
		result.ContainerConfig.Volumes = anonymousVolumes
	}

	return nil
}

// convertEnvironment converts environment variables
func (c *ServiceConverter) convertEnvironment(service composetypes.ServiceConfig, overrides map[string]string, result *ConvertServiceResult) error { // Use composetypes.ServiceConfig
	// Convert service environment variables
	if service.Environment != nil {
		serviceEnv, err := MapOrListToMap(service.Environment)
		if err != nil {
			return fmt.Errorf("failed to convert environment: %w", err)
		}

		// Apply overrides
		if overrides != nil {
			serviceEnv = MergeStringMaps(serviceEnv, overrides)
		}

		// Convert to string slice
		result.ContainerConfig.Env = make([]string, 0, len(serviceEnv))
		for k, v := range serviceEnv {
			result.ContainerConfig.Env = append(result.ContainerConfig.Env, fmt.Sprintf("%s=%s", k, v))
		}
	} else if overrides != nil {
		// Only overrides, no service env
		result.ContainerConfig.Env = make([]string, 0, len(overrides))
		for k, v := range overrides {
			result.ContainerConfig.Env = append(result.ContainerConfig.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Process env_file if specified
	if service.EnvFiles != nil { // Use EnvFiles field
		// Note: Actually loading the env files is handled at a higher level
		// and should be passed in via the overrides parameter
		envFileList, err := StringOrStringSlice(service.EnvFiles) // Use EnvFiles field
		if err != nil {
			return fmt.Errorf("failed to process env_file: %w", err)
		}

		// Log the env files being used
		for _, envFile := range envFileList {
			// Resolve relative paths
			if !filepath.IsAbs(envFile) {
				envFile = filepath.Join(c.workingDir, envFile)
			}
			c.logger.WithField("env_file", envFile).Debug("Using environment file")
		}
	}

	return nil
}

// convertRestartPolicy converts the restart policy
func (c *ServiceConverter) convertRestartPolicy(service composetypes.ServiceConfig, result *ConvertServiceResult) { // Use composetypes.ServiceConfig
	if service.Restart != "" {
		result.HostConfig.RestartPolicy = ConvertRestartPolicy(service.Restart)
	}
}

// convertHealthCheck converts the health check configuration
func (c *ServiceConverter) convertHealthCheck(service composetypes.ServiceConfig, result *ConvertServiceResult) error { // Use composetypes.ServiceConfig
	if service.HealthCheck != nil {
		healthConfig, err := ConvertHealthCheck(service.HealthCheck)
		if err != nil {
			return fmt.Errorf("failed to convert healthcheck: %w", err)
		}
		result.ContainerConfig.Healthcheck = healthConfig
	}

	return nil
}

// convertNetworks converts network configuration
func (c *ServiceConverter) convertNetworks(service composetypes.ServiceConfig, resolver func(string) (string, error), result *ConvertServiceResult) error { // Use composetypes.ServiceConfig
	if service.Networks == nil {
		return nil
	}

	// Convert networks
	endpointConfigs, networkNames, err := ConvertNetworkConfig(service.Networks)
	if err != nil {
		return fmt.Errorf("failed to convert networks: %w", err)
	}

	// Store network names
	result.Networks = networkNames

	// Store endpoints if there are any
	if len(endpointConfigs) > 0 {
		// Resolve network names to IDs if resolver is provided
		if resolver != nil {
			result.NetworkingConfig.EndpointsConfig = make(map[string]*network.EndpointSettings)

			for name, config := range endpointConfigs {
				// Resolve network name
				networkID, err := resolver(name)
				if err != nil {
					return fmt.Errorf("failed to resolve network %s: %w", name, err)
				}

				// Use network ID as the key
				result.NetworkingConfig.EndpointsConfig[networkID] = config
			}
		} else {
			// Use network names as keys
			result.NetworkingConfig.EndpointsConfig = endpointConfigs
		}
	}

	// If only one network, set it as the network mode
	if len(networkNames) == 1 && len(endpointConfigs) == 1 {
		// Use the network name, will be resolved to ID at container creation time
		result.HostConfig.NetworkMode = container.NetworkMode(networkNames[0])
	}

	return nil
}

// convertResourceLimits converts resource limits from the deploy section
func (c *ServiceConverter) convertResourceLimits(service composetypes.ServiceConfig, result *ConvertServiceResult) error { // Use composetypes.ServiceConfig
	// Check if Deploy and Resources are defined
	if service.Deploy == nil {
		return nil // No deploy section
	}
	// Resources struct itself is not a pointer, check its fields
	// if service.Deploy.Resources == nil { // This check is invalid
	// 	return nil
	// }

	// Get limits
	// Get limits
	limits := service.Deploy.Resources.Limits
	if limits != nil {
		// CPU limits
		if limits.NanoCPUs != 0 { // Check if not zero
			// Convert float32 to string for ParseCPUs helper
			cpusStr := fmt.Sprintf("%f", limits.NanoCPUs)
			cpus, err := ParseCPUs(cpusStr)
			if err != nil {
				return fmt.Errorf("failed to parse CPU limit: %w", err)
			}
			result.HostConfig.NanoCPUs = cpus
		}

		// Memory limits
		if limits.MemoryBytes != 0 { // Use MemoryBytes field and check if not zero
			// Convert UnitBytes (int64) to string for ParseMemory helper
			memoryStr := fmt.Sprintf("%d", limits.MemoryBytes)
			memory, err := ParseMemory(memoryStr)
			if err != nil {
				return fmt.Errorf("failed to parse memory limit: %w", err)
			}
			result.HostConfig.Memory = memory
		}

		// PID limits
		if limits.Pids != 0 {
			result.HostConfig.PidsLimit = &limits.Pids
		}
	}

	// Get reservations (corresponds to Docker's --cpu-shares and --memory-reservation)
	reservations := service.Deploy.Resources.Reservations
	if reservations != nil {
		// CPU shares
		if reservations.NanoCPUs != 0 { // Check if not zero
			// Convert float32 to string for ParseCPUs helper
			cpusStr := fmt.Sprintf("%f", reservations.NanoCPUs)
			cpus, err := ParseCPUs(cpusStr)
			if err != nil {
				return fmt.Errorf("failed to parse CPU reservation: %w", err)
			}

			// Convert nano CPUs to CPU shares (1 CPU = 1024 shares, 0.5 CPU = 512 shares)
			result.HostConfig.CPUShares = int64(float64(cpus) / 1_000_000_000.0 * 1024.0)
		}

		// Memory reservation
		if reservations.MemoryBytes != 0 { // Use MemoryBytes field and check if not zero
			// Convert UnitBytes (int64) to string for ParseMemory helper
			memoryStr := fmt.Sprintf("%d", reservations.MemoryBytes)
			memory, err := ParseMemory(memoryStr)
			if err != nil {
				return fmt.Errorf("failed to parse memory reservation: %w", err)
			}
			result.HostConfig.MemoryReservation = memory
		}
	}

	return nil
}

// convertDependsOn converts service dependencies
func (c *ServiceConverter) convertDependsOn(service composetypes.ServiceConfig, result *ConvertServiceResult) error { // Use composetypes.ServiceConfig
	if service.DependsOn == nil {
		return nil
	}

	// Convert depends_on
	dependsOn, conditions, err := ConvertDependsOn(service.DependsOn)
	if err != nil {
		return fmt.Errorf("failed to convert depends_on: %w", err)
	}

	// Store dependencies
	result.DependsOn = dependsOn
	result.DependsOnConditions = conditions

	return nil
}
