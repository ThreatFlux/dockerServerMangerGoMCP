// Package converter provides functionality for converting Docker Compose structures to Docker API structures
package converter

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	composetypes "github.com/compose-spec/compose-go/v2/types" // Added compose types import
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/go-connections/nat"
	"github.com/sirupsen/logrus"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/docker_test/compose" // Removed old import
)

// StringOrStringSlice converts an interface{} to []string
// It handles both string and []string/[]interface{} types
func StringOrStringSlice(value interface{}) ([]string, error) {
	switch v := value.(type) {
	case string:
		return []string{v}, nil
	case []string:
		return v, nil
	case []interface{}:
		result := make([]string, len(v))
		for i, item := range v {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("invalid string item at index %d: %v", i, item)
			}
			result[i] = str
		}
		return result, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported type for string or string slice: %T", value)
	}
}

// MapOrListToMap converts an interface{} to map[string]string
// It handles both map[string]string and []string types (for key=value pairs)
func MapOrListToMap(value interface{}) (map[string]string, error) {
	switch v := value.(type) {
	case map[string]string:
		return v, nil
	case map[string]interface{}:
		result := make(map[string]string)
		for key, val := range v {
			str, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("invalid string value for key %s: %v", key, val)
			}
			result[key] = str
		}
		return result, nil
	case map[interface{}]interface{}:
		result := make(map[string]string)
		for key, val := range v {
			keyStr, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("invalid string key: %v", key)
			}
			valStr, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("invalid string value for key %s: %v", keyStr, val)
			}
			result[keyStr] = valStr
		}
		return result, nil
	case []string:
		result := make(map[string]string)
		for _, item := range v {
			parts := strings.SplitN(item, "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid key=value pair: %s", item)
			}
			result[parts[0]] = parts[1]
		}
		return result, nil
	case []interface{}:
		result := make(map[string]string)
		for i, item := range v {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("invalid string item at index %d: %v", i, item)
			}
			parts := strings.SplitN(str, "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid key=value pair: %s", str)
			}
			result[parts[0]] = parts[1]
		}
		return result, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported type for map or list: %T", value)
	}
}

// ConvertCommand converts command to string slice
func ConvertCommand(cmd interface{}) (strslice.StrSlice, error) {
	switch v := cmd.(type) {
	case string:
		return strslice.StrSlice{"/bin/sh", "-c", v}, nil
	case []string:
		return strslice.StrSlice(v), nil
	case []interface{}:
		result := make([]string, len(v))
		for i, item := range v {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("invalid string item at index %d: %v", i, item)
			}
			result[i] = str
		}
		return strslice.StrSlice(result), nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported type for command: %T", v)
	}
}

// ConvertPorts converts ports to port bindings and exposed ports
func ConvertPorts(ports interface{}) (nat.PortMap, nat.PortSet, error) {
	portBindings := nat.PortMap{}
	exposedPorts := nat.PortSet{}

	switch v := ports.(type) {
	case []string:
		for _, portStr := range v {
			portMappings, err := nat.ParsePortSpec(portStr)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid port specification: %s: %w", portStr, err)
			}

			for _, portMapping := range portMappings {
				port := portMapping.Port
				exposedPorts[port] = struct{}{}

				if portMapping.Binding.HostPort != "" {
					if _, exists := portBindings[port]; !exists {
						portBindings[port] = []nat.PortBinding{}
					}
					portBindings[port] = append(portBindings[port], portMapping.Binding)
				}
			}
		}
	case []interface{}:
		for i, item := range v {
			portStr, ok := item.(string)
			if !ok {
				return nil, nil, fmt.Errorf("invalid string item at index %d: %v", i, item)
			}

			portMappings, err := nat.ParsePortSpec(portStr)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid port specification: %s: %w", portStr, err)
			}

			for _, portMapping := range portMappings {
				port := portMapping.Port
				exposedPorts[port] = struct{}{}

				if portMapping.Binding.HostPort != "" {
					if _, exists := portBindings[port]; !exists {
						portBindings[port] = []nat.PortBinding{}
					}
					portBindings[port] = append(portBindings[port], portMapping.Binding)
				}
			}
		}
	case nil:
		// No ports specified
		return portBindings, exposedPorts, nil
	default:
		return nil, nil, fmt.Errorf("unsupported type for ports: %T", ports)
	}

	return portBindings, exposedPorts, nil
}

// ConvertExposedPorts converts exposed ports to port set
func ConvertExposedPorts(exposed interface{}) (nat.PortSet, error) {
	exposedPorts := nat.PortSet{}

	switch v := exposed.(type) {
	case []string:
		for _, portStr := range v {
			port, err := nat.NewPort("tcp", portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid exposed port: %s: %w", portStr, err)
			}
			exposedPorts[port] = struct{}{}
		}
	case []interface{}:
		for i, item := range v {
			portStr, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("invalid string item at index %d: %v", i, item)
			}

			port, err := nat.NewPort("tcp", portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid exposed port: %s: %w", portStr, err)
			}
			exposedPorts[port] = struct{}{}
		}
	case nil:
		// No exposed ports specified
		return exposedPorts, nil
	default:
		return nil, fmt.Errorf("unsupported type for exposed ports: %T", v)
	}

	return exposedPorts, nil
}

// ConvertVolumes converts volumes to mount configurations and volumes
func ConvertVolumes(volumes interface{}, workingDir string, logger *logrus.Logger) ([]mount.Mount, map[string]struct{}, error) {
	mounts := []mount.Mount{}
	volumeConfigs := map[string]struct{}{}

	switch v := volumes.(type) {
	case []string:
		for _, volumeStr := range v {
			mount, anonymous, err := ParseVolumeSpec(volumeStr, workingDir)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid volume specification: %s: %w", volumeStr, err)
			}

			mounts = append(mounts, mount)

			if anonymous {
				// Anonymous volume
				volumeConfigs[mount.Source] = struct{}{}
			}
		}
	case []interface{}:
		for i, item := range v {
			volumeStr, ok := item.(string)
			if !ok {
				return nil, nil, fmt.Errorf("invalid string item at index %d: %v", i, item)
			}

			mount, anonymous, err := ParseVolumeSpec(volumeStr, workingDir)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid volume specification: %s: %w", volumeStr, err)
			}

			mounts = append(mounts, mount)

			if anonymous {
				// Anonymous volume
				volumeConfigs[mount.Source] = struct{}{}
			}
		}
	case nil:
		// No volumes specified
		return mounts, volumeConfigs, nil
	default:
		return nil, nil, fmt.Errorf("unsupported type for volumes: %T", v)
	}

	return mounts, volumeConfigs, nil
}

// ParseVolumeSpec parses a volume specification string and returns a mount configuration
func ParseVolumeSpec(spec string, workingDir string) (mount.Mount, bool, error) {
	var source, target string
	var mountType mount.Type
	var readOnly bool
	var anonymous bool

	// Parse spec
	parts := strings.Split(spec, ":")

	switch len(parts) {
	case 1:
		// Anonymous volume
		source = "" // Will be created by Docker
		target = parts[0]
		mountType = mount.TypeVolume
		anonymous = true
	case 2:
		// Named volume or bind mount
		source = parts[0]
		target = parts[1]

		if strings.HasPrefix(source, ".") || strings.HasPrefix(source, "/") {
			// Absolute or relative path, so it's a bind mount
			mountType = mount.TypeBind

			// Resolve relative paths
			if strings.HasPrefix(source, ".") {
				source = filepath.Join(workingDir, source)
			}
		} else {
			// Named volume
			mountType = mount.TypeVolume
		}
	case 3:
		// Named volume or bind mount with options
		source = parts[0]
		target = parts[1]
		options := parts[2]

		if strings.HasPrefix(source, ".") || strings.HasPrefix(source, "/") {
			// Absolute or relative path, so it's a bind mount
			mountType = mount.TypeBind

			// Resolve relative paths
			if strings.HasPrefix(source, ".") {
				source = filepath.Join(workingDir, source)
			}
		} else {
			// Named volume
			mountType = mount.TypeVolume
		}

		// Parse options
		if options == "ro" {
			readOnly = true
		}
	default:
		return mount.Mount{}, false, fmt.Errorf("invalid volume specification: %s", spec)
	}

	// Create mount configuration
	m := mount.Mount{
		Type:     mountType,
		Source:   source,
		Target:   target,
		ReadOnly: readOnly,
	}

	return m, anonymous, nil
}

// ConvertRestartPolicy converts restart policy from string to container.RestartPolicy
func ConvertRestartPolicy(policy string) container.RestartPolicy {
	switch policy {
	case "no":
		return container.RestartPolicy{Name: "no"}
	case "always":
		return container.RestartPolicy{Name: "always"}
	case "on-failure":
		return container.RestartPolicy{Name: "on-failure"}
	case "unless-stopped":
		return container.RestartPolicy{Name: "unless-stopped"}
	default:
		// Default is "no"
		return container.RestartPolicy{Name: "no"}
	}
}

// ConvertHealthCheck converts a Compose healthcheck to container.HealthConfig
func ConvertHealthCheck(healthcheck *composetypes.HealthCheckConfig) (*container.HealthConfig, error) { // Use composetypes.HealthCheckConfig
	if healthcheck == nil {
		return nil, nil
	}

	// If disabled, return an empty health config
	if healthcheck.Disable {
		return &container.HealthConfig{
			Test: []string{"NONE"},
		}, nil
	}

	// Test is types.ShellCommand ([]string)
	test := healthcheck.Test

	// Parse interval (pointer to types.Duration)
	var interval time.Duration
	if healthcheck.Interval != nil {
		interval = time.Duration(*healthcheck.Interval) // Dereference and cast
	}

	// Parse timeout (pointer to types.Duration)
	var timeout time.Duration
	if healthcheck.Timeout != nil {
		timeout = time.Duration(*healthcheck.Timeout) // Dereference and cast
	}

	// Parse start period (pointer to types.Duration)
	var startPeriod time.Duration
	if healthcheck.StartPeriod != nil {
		startPeriod = time.Duration(*healthcheck.StartPeriod) // Dereference and cast
	}

	// Create health config
	healthConfig := &container.HealthConfig{
		Test:     test,
		Interval: interval,
		Timeout:  timeout,
		// Retries:     healthcheck.Retries, // Needs nil check and cast
		StartPeriod: startPeriod,
	}
	if healthcheck.Retries != nil {
		healthConfig.Retries = int(*healthcheck.Retries) // Check nil, dereference, cast
	}

	return healthConfig, nil
}

// ParseMemory parses a memory string (e.g., "512m", "2g") and returns bytes
func ParseMemory(memoryStr string) (int64, error) {
	if memoryStr == "" {
		return 0, nil
	}

	// Try to parse as a number first
	bytes, err := strconv.ParseInt(memoryStr, 10, 64)
	if err == nil {
		return bytes, nil
	}

	// If that fails, try to parse as a memory string with unit
	memoryStr = strings.ToLower(memoryStr)
	multiplier := int64(1)

	if strings.HasSuffix(memoryStr, "k") {
		multiplier = 1024
		memoryStr = strings.TrimSuffix(memoryStr, "k")
	} else if strings.HasSuffix(memoryStr, "kb") {
		multiplier = 1024
		memoryStr = strings.TrimSuffix(memoryStr, "kb")
	} else if strings.HasSuffix(memoryStr, "m") {
		multiplier = 1024 * 1024
		memoryStr = strings.TrimSuffix(memoryStr, "m")
	} else if strings.HasSuffix(memoryStr, "mb") {
		multiplier = 1024 * 1024
		memoryStr = strings.TrimSuffix(memoryStr, "mb")
	} else if strings.HasSuffix(memoryStr, "g") {
		multiplier = 1024 * 1024 * 1024
		memoryStr = strings.TrimSuffix(memoryStr, "g")
	} else if strings.HasSuffix(memoryStr, "gb") {
		multiplier = 1024 * 1024 * 1024
		memoryStr = strings.TrimSuffix(memoryStr, "gb")
	}

	value, err := strconv.ParseFloat(memoryStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid memory value: %s: %w", memoryStr, err)
	}

	return int64(value * float64(multiplier)), nil
}

// ParseCPUs parses a CPU string (e.g., "0.5", "2") and returns nano CPUs
func ParseCPUs(cpusStr string) (int64, error) {
	if cpusStr == "" {
		return 0, nil
	}

	cpus, err := strconv.ParseFloat(cpusStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid CPU value: %s: %w", cpusStr, err)
	}

	// Convert to nano CPUs (1 CPU = 1_000_000_000 nano CPUs)
	return int64(cpus * 1_000_000_000), nil
}

// MergeStringMaps merges two string maps, with values from the second map taking precedence
func MergeStringMaps(m1, m2 map[string]string) map[string]string {
	result := make(map[string]string)

	// Copy values from first map
	for k, v := range m1 {
		result[k] = v
	}

	// Copy values from second map, overwriting any existing values
	for k, v := range m2 {
		result[k] = v
	}

	return result
}

// ConvertLabels converts labels from interface{} to map[string]string
func ConvertLabels(labels interface{}) (map[string]string, error) {
	return MapOrListToMap(labels)
}

// ConvertNetworkConfig converts network configuration from interface{} to network configurations
func ConvertNetworkConfig(networkConfig interface{}) (map[string]*network.EndpointSettings, []string, error) {
	endpointConfigs := make(map[string]*network.EndpointSettings)
	networkNames := []string{}

	switch v := networkConfig.(type) {
	case []string:
		for _, name := range v {
			endpointConfigs[name] = &network.EndpointSettings{}
			networkNames = append(networkNames, name)
		}
	case []interface{}:
		for i, item := range v {
			name, ok := item.(string)
			if !ok {
				return nil, nil, fmt.Errorf("invalid string item at index %d: %v", i, item)
			}
			endpointConfigs[name] = &network.EndpointSettings{}
			networkNames = append(networkNames, name)
		}
	case map[string]interface{}:
		for name, config := range v {
			networkNames = append(networkNames, name)

			endpointConfig := &network.EndpointSettings{}

			// Parse network configuration if it's a map
			if configMap, ok := config.(map[string]interface{}); ok {
				// Extract aliases
				if aliases, ok := configMap["aliases"]; ok {
					aliasesSlice, err := StringOrStringSlice(aliases)
					if err != nil {
						return nil, nil, fmt.Errorf("invalid aliases for network %s: %w", name, err)
					}
					endpointConfig.Aliases = aliasesSlice
				}

				// Extract ipv4_address
				if ipv4, ok := configMap["ipv4_address"]; ok {
					if ipv4Str, ok := ipv4.(string); ok {
						endpointConfig.IPAddress = ipv4Str
					}
				}

				// Extract ipv6_address
				if ipv6, ok := configMap["ipv6_address"]; ok {
					if ipv6Str, ok := ipv6.(string); ok {
						if endpointConfig.IPAMConfig == nil {
							endpointConfig.IPAMConfig = &network.EndpointIPAMConfig{}
						}
						endpointConfig.IPAMConfig.IPv6Address = ipv6Str // Set IPv6 in IPAMConfig
					}
				}
			}

			endpointConfigs[name] = endpointConfig
		}
	case map[interface{}]interface{}:
		for nameVal, config := range v {
			name, ok := nameVal.(string)
			if !ok {
				return nil, nil, fmt.Errorf("invalid network name: %v", nameVal)
			}

			networkNames = append(networkNames, name)

			endpointConfig := &network.EndpointSettings{}

			// Parse network configuration if it's a map
			if configMap, ok := config.(map[interface{}]interface{}); ok {
				// Extract aliases
				if aliases, ok := configMap["aliases"]; ok {
					aliasesSlice, err := StringOrStringSlice(aliases)
					if err != nil {
						return nil, nil, fmt.Errorf("invalid aliases for network %s: %w", name, err)
					}
					endpointConfig.Aliases = aliasesSlice
				}

				// Extract ipv4_address
				if ipv4, ok := configMap["ipv4_address"]; ok {
					if ipv4Str, ok := ipv4.(string); ok {
						endpointConfig.IPAddress = ipv4Str
					}
				}

				// Extract ipv6_address
				if ipv6, ok := configMap["ipv6_address"]; ok {
					if ipv6Str, ok := ipv6.(string); ok {
						if endpointConfig.IPAMConfig == nil {
							endpointConfig.IPAMConfig = &network.EndpointIPAMConfig{}
						}
						endpointConfig.IPAMConfig.IPv6Address = ipv6Str // Set IPv6 in IPAMConfig
					}
				}
			}

			endpointConfigs[name] = endpointConfig
		}
	case nil:
		// No networks specified
		return endpointConfigs, networkNames, nil
	default:
		return nil, nil, fmt.Errorf("unsupported type for networks: %T", networkConfig)
	}

	return endpointConfigs, networkNames, nil
}

// ConvertDependsOn converts depends_on from interface{} to service dependencies
func ConvertDependsOn(dependsOn interface{}) ([]string, map[string]string, error) {
	serviceDeps := []string{}
	conditionMap := make(map[string]string)

	switch v := dependsOn.(type) {
	case []string:
		serviceDeps = v
		// Default condition is "service_started"
		for _, dep := range v {
			conditionMap[dep] = "service_started"
		}
	case []interface{}:
		for i, item := range v {
			name, ok := item.(string)
			if !ok {
				return nil, nil, fmt.Errorf("invalid string item at index %d: %v", i, item)
			}
			serviceDeps = append(serviceDeps, name)
			conditionMap[name] = "service_started"
		}
	case map[string]interface{}:
		for name, config := range v {
			serviceDeps = append(serviceDeps, name)

			// Parse condition if it's a map
			if configMap, ok := config.(map[string]interface{}); ok {
				if condition, ok := configMap["condition"]; ok {
					if conditionStr, ok := condition.(string); ok {
						conditionMap[name] = conditionStr
					} else {
						conditionMap[name] = "service_started"
					}
				} else {
					conditionMap[name] = "service_started"
				}
			} else {
				conditionMap[name] = "service_started"
			}
		}
	case map[interface{}]interface{}:
		for nameVal, config := range v {
			name, ok := nameVal.(string)
			if !ok {
				return nil, nil, fmt.Errorf("invalid depends_on name: %v", nameVal)
			}

			serviceDeps = append(serviceDeps, name)

			// Parse condition if it's a map
			if configMap, ok := config.(map[interface{}]interface{}); ok {
				if condition, ok := configMap["condition"]; ok {
					if conditionStr, ok := condition.(string); ok {
						conditionMap[name] = conditionStr
					} else {
						conditionMap[name] = "service_started"
					}
				} else {
					conditionMap[name] = "service_started"
				}
			} else {
				conditionMap[name] = "service_started"
			}
		}
	case nil:
		// No dependencies specified
		return serviceDeps, conditionMap, nil
	default:
		return nil, nil, fmt.Errorf("unsupported type for depends_on: %T", dependsOn)
	}

	return serviceDeps, conditionMap, nil
}

// SanitizeContainerName sanitizes a container name for Docker
func SanitizeContainerName(name string) string {
	// Replace characters not allowed in container names
	name = strings.Replace(name, " ", "_", -1)
	name = strings.Replace(name, "/", "_", -1)

	// Add a prefix or suffix if needed
	if len(name) == 0 {
		name = "container"
	}

	return name
}

// GenerateContainerName generates a container name from the service name and project name
func GenerateContainerName(projectName, serviceName string, index int) string {
	// Sanitize names
	projectName = SanitizeContainerName(projectName)
	serviceName = SanitizeContainerName(serviceName)

	// Generate container name
	if index > 0 {
		return fmt.Sprintf("%s_%s_%d", projectName, serviceName, index)
	}

	return fmt.Sprintf("%s_%s", projectName, serviceName)
}

// ValidateExternalResource validates an external resource configuration
func ValidateExternalResource(external interface{}, resourceType, resourceName string) (bool, string, error) {
	isExternal := false
	externalName := resourceName

	switch v := external.(type) {
	case bool:
		isExternal = v
	case map[string]interface{}:
		isExternal = true
		if name, ok := v["name"]; ok {
			if nameStr, ok := name.(string); ok {
				externalName = nameStr
			}
		}
	case map[interface{}]interface{}:
		isExternal = true
		if name, ok := v["name"]; ok {
			if nameStr, ok := name.(string); ok {
				externalName = nameStr
			}
		}
	default:
		return false, "", fmt.Errorf("unsupported type for external %s: %T", resourceType, external)
	}

	return isExternal, externalName, nil
}
