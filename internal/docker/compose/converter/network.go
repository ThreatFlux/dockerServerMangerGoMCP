package converter

import (
	"context"
	"fmt"
	"time"

	composetypes "github.com/compose-spec/compose-go/v2/types" // Added compose types import
	"github.com/docker/docker/api/types/network"
	"github.com/sirupsen/logrus"
)

// NetworkConverter is responsible for converting Docker Compose network definitions to Docker API structures
type NetworkConverter struct {
	logger      *logrus.Logger
	projectName string
}

// NewNetworkConverter creates a new network converter
func NewNetworkConverter(projectName string, logger *logrus.Logger) *NetworkConverter {
	if logger == nil {
		logger = logrus.New()
	}

	return &NetworkConverter{
		logger:      logger,
		projectName: projectName,
	}
}

// ConvertNetworkOptions defines options for converting a network
type ConvertNetworkOptions struct {
	// Timeout is the operation timeout
	Timeout time.Duration

	// Logger is the logger to use
	Logger *logrus.Logger

	// CheckIfExists is a function that checks if a network already exists
	CheckIfExists func(string) (bool, error)

	// DefaultSubnetPool is a function that returns a subnet for a new network
	DefaultSubnetPool func() (string, error)
}

// ConvertNetworkResult contains the result of converting a network
type ConvertNetworkResult struct {
	NetworkCreateConfig network.CreateOptions // Use network.CreateOptions
	NetworkName         string
	ExternalName        string
	IsExternal          bool
}

// ConvertNetwork converts a Docker Compose network to a Docker API network create config
func (c *NetworkConverter) ConvertNetwork(ctx context.Context, networkName string, networkConfig composetypes.NetworkConfig, options ConvertNetworkOptions) (*ConvertNetworkResult, error) { // Use composetypes.NetworkConfig
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

	logger.WithField("network", networkName).Debug("Converting network")

	// Create result
	result := &ConvertNetworkResult{
		NetworkName: networkName,
		NetworkCreateConfig: network.CreateOptions{ // Use network.CreateOptions
			// CheckDuplicate: true, // Field removed in newer SDK versions
			Driver:     "bridge", // Default driver
			Attachable: networkConfig.Attachable,
			Internal:   networkConfig.Internal,
		},
	}

	// Check if network is external
	if networkConfig.External { // Check the boolean value directly
		isExternal, externalName, err := ValidateExternalResource(networkConfig.External, "network", networkName)
		if err != nil {
			return nil, fmt.Errorf("failed to validate external network: %w", err)
		}

		if isExternal {
			result.IsExternal = true
			result.ExternalName = externalName
			return result, nil
		}
	}

	// Set network name with project prefix if not external
	result.NetworkName = fmt.Sprintf("%s_%s", c.projectName, networkName)

	// Check if network already exists
	if options.CheckIfExists != nil {
		exists, err := options.CheckIfExists(result.NetworkName)
		if err != nil {
			return nil, fmt.Errorf("failed to check if network exists: %w", err)
		}

		if exists {
			logger.WithField("network", result.NetworkName).Debug("Network already exists")
			result.IsExternal = true
			return result, nil
		}
	}

	// Set driver if specified
	if networkConfig.Driver != "" {
		result.NetworkCreateConfig.Driver = networkConfig.Driver
	}

	// Convert driver options
	if networkConfig.DriverOpts != nil {
		result.NetworkCreateConfig.Options = networkConfig.DriverOpts
	}

	// Convert IPAM config
	if err := c.convertIPAM(networkConfig, options, result); err != nil {
		return nil, fmt.Errorf("failed to convert IPAM config: %w", err)
	}

	// Convert labels
	var err error
	result.NetworkCreateConfig.Labels, err = ConvertLabels(networkConfig.Labels)
	if err != nil {
		return nil, fmt.Errorf("failed to convert labels: %w", err)
	}

	// Add project labels
	if result.NetworkCreateConfig.Labels == nil {
		result.NetworkCreateConfig.Labels = make(map[string]string)
	}
	result.NetworkCreateConfig.Labels["com.docker_test.compose.project"] = c.projectName
	result.NetworkCreateConfig.Labels["com.docker_test.compose.network"] = networkName

	return result, nil
}

// convertIPAM converts IPAM configuration
func (c *NetworkConverter) convertIPAM(networkConfig composetypes.NetworkConfig, options ConvertNetworkOptions, result *ConvertNetworkResult) error { // Use composetypes.NetworkConfig
	// If IPAM config is empty, create a default one or use pool
	if len(networkConfig.Ipam.Config) == 0 { // Check if Config slice is empty
		// If no subnet pool function is provided, use default IPAM (Docker will assign automatically)
		if options.DefaultSubnetPool == nil {
			return nil
		}

		// Get a subnet from the pool
		subnet, err := options.DefaultSubnetPool()
		if err != nil {
			return fmt.Errorf("failed to get subnet from pool: %w", err)
		}

		// Create default IPAM config with the subnet
		if subnet != "" {
			result.NetworkCreateConfig.IPAM = &network.IPAM{
				Driver: "default",
				Config: []network.IPAMConfig{
					{
						Subnet: subnet,
					},
				},
			}
		}

		return nil
	}

	// Create IPAM with driver
	ipam := &network.IPAM{
		Driver: networkConfig.Ipam.Driver,
	}

	// If driver is empty, use default
	if ipam.Driver == "" {
		ipam.Driver = "default"
	}

	// Convert IPAM configs
	if len(networkConfig.Ipam.Config) > 0 {
		ipam.Config = make([]network.IPAMConfig, len(networkConfig.Ipam.Config))
		for i, config := range networkConfig.Ipam.Config {
			ipamConfig := network.IPAMConfig{
				Subnet:     config.Subnet,
				IPRange:    config.IPRange,
				Gateway:    config.Gateway,
				AuxAddress: config.AuxiliaryAddresses, // Try AuxiliaryAddresses
			}
			ipam.Config[i] = ipamConfig
		}
	} else if options.DefaultSubnetPool != nil {
		// If no config but we have a subnet pool, use it
		subnet, err := options.DefaultSubnetPool()
		if err != nil {
			return fmt.Errorf("failed to get subnet from pool: %w", err)
		}

		// Add the subnet to the IPAM config
		if subnet != "" {
			ipam.Config = []network.IPAMConfig{
				{
					Subnet: subnet,
				},
			}
		}
	}

	// Set the IPAM config
	result.NetworkCreateConfig.IPAM = ipam

	return nil
}
