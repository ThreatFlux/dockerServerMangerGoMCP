// Package lifecycle implements Docker container lifecycle operations.
package lifecycle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net" // Added for IP validation
	"regexp"
	"strconv" // Added for port validation
	"strings"
	"time"

	dockertypes "github.com/docker/docker/api/types"              // Use dockertypes alias
	blkiotypes "github.com/docker/docker/api/types/blkiodev"      // Use blkiotypes alias
	containertypes "github.com/docker/docker/api/types/container" // Use containertypes alias
	filterstypes "github.com/docker/docker/api/types/filters"     // Use filterstypes alias
	imagetypes "github.com/docker/docker/api/types/image"         // Use imagetypes alias
	mounttypes "github.com/docker/docker/api/types/mount"         // Use mounttypes alias
	networktypes "github.com/docker/docker/api/types/network"     // Use networktypes alias
	registrytypes "github.com/docker/docker/api/types/registry"   // Use registrytypes alias
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// Security default values
const (
	// Default memory limit (512MB)
	defaultMemoryLimit int64 = 512 * 1024 * 1024

	// Default CPU shares
	defaultCPUShares int64 = 1024

	// Default process limit
	defaultPidsLimit int64 = 100

	// Default pull timeout (5 minutes)
	pullTimeout = 5 * time.Minute
)

// Logger provides a default logger for container creation operations
var Logger = logrus.New()

// SecurityOpts contains security options for container creation
type SecurityOpts struct {
	// NoNewPrivileges restricts privilege escalation
	NoNewPrivileges bool `json:"no_new_privileges"`

	// CapDrop specifies capabilities to drop
	CapDrop []string `json:"cap_drop"`

	// CapAdd specifies capabilities to add
	CapAdd []string `json:"cap_add"`

	// ReadOnlyRootfs enables read-only root filesystem
	ReadOnlyRootfs bool `json:"read_only_rootfs"`

	// SeccompProfile specifies the seccomp profile
	SeccompProfile string `json:"seccomp_profile"`

	// AppArmorProfile specifies the AppArmor profile
	AppArmorProfile string `json:"apparmor_profile"`

	// DisablePrivilegedContainers prevents privileged containers
	DisablePrivilegedContainers bool `json:"disable_privileged_containers"`

	// DisableHostNamespaces prevents access to host namespaces
	DisableHostNamespaces bool `json:"disable_host_namespaces"`

	// RunAsNonRoot runs container as non-root
	RunAsNonRoot bool `json:"run_as_non_root"`

	// DisallowedPaths are paths that cannot be mounted
	DisallowedPaths []string `json:"disallowed_paths"`

	// SensitiveDirectoryProtection protects sensitive directories
	SensitiveDirectoryProtection bool `json:"sensitive_directory_protection"`

	// EnforceImagePinning enforces image pinning (no latest tag)
	EnforceImagePinning bool `json:"enforce_image_pinning"`

	// TrustedRegistries are the only registries allowed
	TrustedRegistries []string `json:"trusted_registries"`
}

// ResourceLimits contains resource limits for container creation
type ResourceLimits struct {
	// Memory limit in bytes
	Memory int64 `json:"memory"`

	// CPUShares specifies CPU shares
	CPUShares int64 `json:"cpu_shares"`

	// CPUPeriod specifies CPU period
	CPUPeriod int64 `json:"cpu_period"`

	// CPUQuota specifies CPU quota
	CPUQuota int64 `json:"cpu_quota"`

	// PidsLimit specifies process limit
	PidsLimit int64 `json:"pids_limit"`

	// BlkioWeight specifies block IO weight
	BlkioWeight int `json:"blkio_weight"`

	// CPUsetCPUs specifies CPUs the container can use
	CPUsetCPUs string `json:"cpuset_cpus"`

	// CPUsetMems specifies memory nodes the container can use
	CPUsetMems string `json:"cpuset_mems"`

	// MemoryReservation specifies soft memory limit
	MemoryReservation int64 `json:"memory_reservation"`

	// MemorySwap specifies swap limit
	MemorySwap int64 `json:"memory_swap"`

	// MemorySwappiness specifies swappiness
	MemorySwappiness *int64 `json:"memory_swappiness"`

	// IOMaximumBandwidth specifies max IO bandwidth
	IOMaximumBandwidth int64 `json:"io_maximum_bandwidth"`

	// IOMaximumIOps specifies max IO IOPS
	IOMaximumIOps int64 `json:"io_maximum_iops"`
}

// Creator manages container creation operations with secure defaults
type Creator struct {
	client           client.APIClient
	logger           *logrus.Logger
	securityOpts     SecurityOpts
	resourceLimits   ResourceLimits
	registryProvider RegistryCredentialProvider
}

// RegistryCredentialProvider defines an interface for retrieving Docker registry credentials
type RegistryCredentialProvider interface {
	// GetAuthConfig returns the auth configuration for an image
	GetAuthConfig(image string) imagetypes.PullOptions // Use dockertypes alias
}

// DefaultCredentialProvider is a simple provider that uses no authentication
type DefaultCredentialProvider struct{}

// GetAuthConfig returns empty auth options for anonymous access
func (p *DefaultCredentialProvider) GetAuthConfig(image string) imagetypes.PullOptions { // Use dockertypes alias
	return imagetypes.PullOptions{} // Use dockertypes alias
}

// CreatorOption defines options for creating a Creator
type CreatorOption func(*Creator)

// WithLogger sets the logger for the Creator
func WithLogger(logger *logrus.Logger) CreatorOption {
	return func(c *Creator) {
		c.logger = logger
	}
}

// WithSecurityOpts sets security options for the Creator
func WithSecurityOpts(opts SecurityOpts) CreatorOption {
	return func(c *Creator) {
		c.securityOpts = opts
	}
}

// WithResourceLimits sets resource limits for the Creator
func WithResourceLimits(limits ResourceLimits) CreatorOption {
	return func(c *Creator) {
		c.resourceLimits = limits
	}
}

// WithRegistryProvider sets the registry credential provider
func WithRegistryProvider(provider RegistryCredentialProvider) CreatorOption {
	return func(c *Creator) {
		c.registryProvider = provider
	}
}

// NewCreator creates a new container creator with the given options
func NewCreator(client client.APIClient, options ...CreatorOption) *Creator {
	// Create with default values
	creator := &Creator{
		client: client,
		logger: Logger,
		securityOpts: SecurityOpts{
			NoNewPrivileges:              true,
			CapDrop:                      []string{"ALL"},
			CapAdd:                       []string{"CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "SETGID", "SETUID", "NET_BIND_SERVICE"},
			ReadOnlyRootfs:               false,
			DisablePrivilegedContainers:  true,
			DisableHostNamespaces:        true,
			SensitiveDirectoryProtection: true,
			DisallowedPaths:              []string{"/proc", "/sys", "/dev", "/var/run/docker_test.sock"},
			TrustedRegistries:            []string{"docker_test.io", "registry.k8s.io", "quay.io", "gcr.io", "ghcr.io"},
		},
		resourceLimits: ResourceLimits{
			Memory:            defaultMemoryLimit,
			CPUShares:         defaultCPUShares,
			PidsLimit:         defaultPidsLimit,
			MemorySwappiness:  new(int64),
			MemoryReservation: defaultMemoryLimit * 4 / 5, // 80% of memory limit
			MemorySwap:        -1,                         // Unlimited swap
		},
		registryProvider: &DefaultCredentialProvider{},
	}

	// Apply options
	for _, option := range options {
		option(creator)
	}

	return creator
}

// CreateOptions contains options for creating a container
type CreateOptions struct {
	// Name is the name of the container
	Name string `json:"name"`

	// Image is the image to use
	Image string `json:"image"`

	// Config is the container configuration
	Config *containertypes.Config `json:"config"` // Use containertypes alias

	// HostConfig is the host configuration
	HostConfig *containertypes.HostConfig `json:"host_config"` // Use containertypes alias

	// NetworkConfig is the network configuration
	NetworkConfig *networktypes.NetworkingConfig `json:"network_config"` // Use networktypes alias

	// Platform is the platform configuration
	Platform *specs.Platform `json:"platform"`

	// Labels are the container labels
	Labels map[string]string `json:"labels"`

	// Timeout is the operation timeout in seconds
	Timeout int `json:"timeout"`

	// Pull indicates whether to pull the image if it doesn't exist
	Pull bool `json:"pull"`

	// PullPolicy is the pull policy
	PullPolicy PullPolicy `json:"pull_policy"`

	// SecurityOpts overrides the default security options
	SecurityOpts *SecurityOpts `json:"security_opts"`

	// ResourceLimits overrides the default resource limits
	ResourceLimits *ResourceLimits `json:"resource_limits"`

	// RegistryAuth contains registry authentication details
	RegistryAuth *registrytypes.AuthConfig `json:"registry_auth"` // Use registrytypes alias

	// User ID to run the container (numeric UID)
	UserID string `json:"user_id"`

	// Annotations for additional metadata
	Annotations map[string]string `json:"annotations"`

	// RestartPolicy for the container
	RestartPolicy *containertypes.RestartPolicy `json:"restart_policy"` // Use containertypes alias

	// StopTimeout for graceful container termination (in seconds)
	StopTimeout *int `json:"stop_timeout"`

	// HealthCheck configuration
	HealthCheck *containertypes.HealthConfig `json:"health_check"` // Use containertypes alias

	// AutoRemove automatically removes container when it exits
	AutoRemove bool `json:"auto_remove"`

	// LogConfig specifies logging configuration
	LogConfig *containertypes.LogConfig `json:"log_config"` // Use containertypes alias
}

// PullPolicy represents an image pull policy
type PullPolicy string

const (
	// PullAlways always pulls the image
	PullAlways PullPolicy = "always"

	// PullIfNotPresent pulls the image if it doesn't exist
	PullIfNotPresent PullPolicy = "ifnotpresent"

	// PullNever never pulls the image
	PullNever PullPolicy = "never"
)

// CreateResult contains the result of a container creation
type CreateResult struct {
	// Container is the created container
	Container *models.Container `json:"container"`

	// Warnings are any warnings from the creation
	Warnings []string `json:"warnings"`

	// ImagePulled indicates whether the image was pulled
	ImagePulled bool `json:"image_pulled"`

	// SecurityWarnings contains warnings about security configuration
	SecurityWarnings []string `json:"security_warnings"`

	// ResourceLimits shows the applied resource limits
	ResourceLimits map[string]interface{} `json:"resource_limits"`

	// SecuritySettings shows the applied security settings
	SecuritySettings map[string]interface{} `json:"security_settings"`

	// NetworkSettings shows the network settings
	NetworkSettings map[string]interface{} `json:"network_settings"`
}

// Create creates a new container with secure defaults
func (c *Creator) Create(ctx context.Context, opts CreateOptions) (*CreateResult, error) {
	// Initialize logger field for consistent logging
	logger := c.logger.WithFields(logrus.Fields{
		"image":      opts.Image,
		"container":  opts.Name,
		"operation":  "create",
		"request_id": ctx.Value("request_id"),
	})

	logger.Debug("Starting container creation")

	// Validate options
	if err := c.validateOptions(&opts); err != nil {
		logger.WithError(err).Error("Invalid options")
		return nil, errors.Wrap(err, "invalid options")
	}

	// Apply timeout if specified
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.Timeout)*time.Second)
		defer cancel()
	}

	// Setup result
	result := &CreateResult{
		ImagePulled:      false,
		Warnings:         []string{},
		SecurityWarnings: []string{},
		ResourceLimits:   make(map[string]interface{}),
		SecuritySettings: make(map[string]interface{}),
		NetworkSettings:  make(map[string]interface{}),
	}

	// Apply security defaults to host config if it exists
	if opts.HostConfig != nil {
		c.applySecurityDefaults(opts.HostConfig, opts.SecurityOpts, &result.SecurityWarnings)
	} else {
		// Create a new host config with security defaults
		opts.HostConfig = &containertypes.HostConfig{} // Use containertypes alias
		c.applySecurityDefaults(opts.HostConfig, opts.SecurityOpts, &result.SecurityWarnings)
	}

	// Apply resource limits to host config
	c.applyResourceLimits(opts.HostConfig, opts.ResourceLimits, &result.ResourceLimits)

	// Apply health check if specified
	if opts.HealthCheck != nil && opts.Config != nil {
		opts.Config.Healthcheck = opts.HealthCheck
	}

	// Apply restart policy if specified
	if opts.RestartPolicy != nil && opts.HostConfig != nil {
		opts.HostConfig.RestartPolicy = *opts.RestartPolicy
	}

	// Apply stop timeout if specified
	if opts.StopTimeout != nil && opts.Config != nil {
		stopTimeout := *opts.StopTimeout
		opts.Config.StopTimeout = &stopTimeout
	}

	// Apply auto-remove if specified
	if opts.AutoRemove && opts.HostConfig != nil {
		opts.HostConfig.AutoRemove = true
	}

	// Apply log config if specified
	if opts.LogConfig != nil && opts.HostConfig != nil {
		opts.HostConfig.LogConfig = *opts.LogConfig
	}

	// Apply user ID if specified
	if opts.UserID != "" && opts.Config != nil {
		opts.Config.User = opts.UserID
	}

	// Ensure image exists if pull is enabled
	shouldPull, err := c.shouldPullImage(ctx, opts)
	if err != nil {
		logger.WithError(err).Error("Failed to check image")
		return nil, errors.Wrap(err, "failed to check image")
	}

	if shouldPull {
		logger.WithField("image", opts.Image).Info("Pulling image")
		if err := c.pullImage(ctx, opts.Image, opts.RegistryAuth); err != nil { // Pass RegistryAuth
			logger.WithError(err).Error("Failed to pull image")
			return nil, errors.Wrap(err, "failed to pull image")
		}
		result.ImagePulled = true
	}

	// Apply additional labels
	if opts.Config.Labels == nil {
		opts.Config.Labels = map[string]string{}
	}

	// Add management labels
	opts.Config.Labels["com.dockerservermanager.managed"] = "true"
	opts.Config.Labels["com.dockerservermanager.created"] = time.Now().UTC().Format(time.RFC3339)
	opts.Config.Labels["com.dockerservermanager.secure"] = "true"
	opts.Config.Labels["com.dockerservermanager.version"] = "1.0.0"

	// Add user-provided labels
	for k, v := range opts.Labels {
		opts.Config.Labels[k] = v
	}

	// Add annotations as labels with a prefix
	for k, v := range opts.Annotations {
		opts.Config.Labels["com.dockerservermanager.annotation."+k] = v
	}

	// Validate mounts for security issues
	if opts.HostConfig != nil && len(opts.HostConfig.Mounts) > 0 {
		validMounts, warnings := c.validateMountPoints(opts.HostConfig.Mounts)
		opts.HostConfig.Mounts = validMounts
		result.SecurityWarnings = append(result.SecurityWarnings, warnings...)
	}

	// Create the container
	logger.Debug("Creating container")
	resp, err := c.client.ContainerCreate(
		ctx,
		opts.Config,
		opts.HostConfig,
		opts.NetworkConfig,
		opts.Platform,
		opts.Name,
	)
	if err != nil {
		logger.WithError(err).Error("Failed to create container")
		return nil, errors.Wrap(err, "failed to create container")
	}

	logger.WithField("container_id", resp.ID).Info("Container created")

	// Add warnings to result
	result.Warnings = append(result.Warnings, resp.Warnings...)

	// Fetch the created container
	containerJSON, err := c.client.ContainerInspect(ctx, resp.ID)
	if err != nil {
		logger.WithError(err).Error("Failed to inspect created container")
		return nil, errors.Wrap(err, "failed to inspect created container")
	}

	// Store network settings
	if containerJSON.NetworkSettings != nil {
		// Extract basic network information
		result.NetworkSettings["networks"] = getNetworkInfo(containerJSON.NetworkSettings)
		result.NetworkSettings["ports"] = getPortInfo(containerJSON.NetworkSettings.Ports)
	}

	// Convert to model
	containerModel := c.convertToModel(containerJSON) // Renamed variable

	// Add the container to the result
	result.Container = &containerModel // Use pointer

	logger.WithFields(logrus.Fields{
		"container_id": containerModel.ID, // Use containerModel
		"warnings":     len(result.Warnings),
		"sec_warnings": len(result.SecurityWarnings),
	}).Info("Container creation completed")

	return result, nil
}

// validateOptions validates and normalizes the creation options
func (c *Creator) validateOptions(opts *CreateOptions) error {
	// Check required fields
	if opts.Config == nil {
		return errors.New("container config is required")
	}
	if opts.Image == "" && opts.Config.Image == "" {
		return errors.New("image is required")
	}

	// Ensure image is set in Config
	if opts.Config.Image == "" {
		opts.Config.Image = opts.Image
	} else if opts.Image == "" {
		opts.Image = opts.Config.Image
	}

	// Validate image name
	if err := c.validateImageName(opts.Image); err != nil {
		return errors.Wrap(err, "invalid image name")
	}

	// Validate container name if specified
	if opts.Name != "" {
		if err := c.validateContainerName(opts.Name); err != nil {
			return errors.Wrap(err, "invalid container name")
		}
	}

	// Initialize host config if nil
	if opts.HostConfig == nil {
		opts.HostConfig = &containertypes.HostConfig{} // Use containertypes alias
	}

	// Initialize network config if nil
	if opts.NetworkConfig == nil {
		opts.NetworkConfig = &networktypes.NetworkingConfig{} // Use networktypes alias
	}

	// Validate commands
	if opts.Config.Cmd != nil && len(opts.Config.Cmd) > 0 {
		// Check for shell injection in commands
		for _, cmd := range opts.Config.Cmd {
			if strings.Contains(cmd, "$(") || strings.Contains(cmd, "`") {
				return errors.New("potential shell injection detected in command")
			}
		}
	}

	// Validate entrypoint
	if opts.Config.Entrypoint != nil && len(opts.Config.Entrypoint) > 0 {
		// Check for shell injection in entrypoint
		for _, entry := range opts.Config.Entrypoint {
			if strings.Contains(entry, "$(") || strings.Contains(entry, "`") {
				return errors.New("potential shell injection detected in entrypoint")
			}
		}
	}

	// Validate environment variables
	if opts.Config.Env != nil {
		for _, env := range opts.Config.Env {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				return errors.Errorf("invalid environment variable format: %s", env)
			}

			// Check for sensitive information in env vars
			envKey := strings.ToLower(parts[0])
			if c.isSensitiveEnvVar(envKey) {
				c.logger.WithField("env_var", parts[0]).Warning("Potentially sensitive environment variable detected")
			}
		}
	}

	// Validate ports for security issues
	if opts.Config.ExposedPorts != nil && opts.HostConfig != nil && opts.HostConfig.PortBindings != nil {
		// Convert Docker's PortMap to our map format for validation
		portMap := make(map[string][]string)
		for port, bindings := range opts.HostConfig.PortBindings {
			portStr := string(port)
			bindingStrs := make([]string, len(bindings))
			for i, binding := range bindings {
				bindingStrs[i] = binding.HostIP + ":" + binding.HostPort
			}
			portMap[portStr] = bindingStrs
		}

		// Validate port bindings
		validPorts, warnings := c.validatePortBindings(portMap)
		if len(warnings) > 0 {
			c.logger.WithField("warnings", warnings).Warning("Port binding warnings")
		}

		// Reset port bindings with validated ones
		if len(validPorts) > 0 {
			newPortBindings := make(nat.PortMap)
			for portStr, bindings := range validPorts {
				port := nat.Port(portStr)
				portBindings := make([]nat.PortBinding, len(bindings))
				for i, binding := range bindings {
					parts := strings.SplitN(binding, ":", 2)
					if len(parts) == 2 {
						portBindings[i] = nat.PortBinding{HostIP: parts[0], HostPort: parts[1]}
					} else {
						portBindings[i] = nat.PortBinding{HostIP: "0.0.0.0", HostPort: parts[0]}
					}
				}
				newPortBindings[port] = portBindings
			}
			opts.HostConfig.PortBindings = newPortBindings
		}
	}

	// Validate health check if specified
	if opts.HealthCheck != nil {
		if err := c.validateHealthCheck(opts.HealthCheck); err != nil {
			return errors.Wrap(err, "invalid health check configuration")
		}
	}

	// Validate restart policy if specified
	if opts.RestartPolicy != nil {
		if err := c.validateRestartPolicy(opts.RestartPolicy); err != nil {
			return errors.Wrap(err, "invalid restart policy")
		}
	}

	// Validate log config if specified
	if opts.LogConfig != nil {
		if err := c.validateLogConfig(opts.LogConfig); err != nil {
			return errors.Wrap(err, "invalid log configuration")
		}
	}

	// Validate user ID if specified
	if opts.UserID != "" {
		if err := c.validateUserID(opts.UserID); err != nil {
			return errors.Wrap(err, "invalid user ID")
		}
	}

	return nil
}

// validateImageName validates an image name
func (c *Creator) validateImageName(name string) error {
	if name == "" {
		return errors.New("image name cannot be empty")
	}

	// Simple validation for common format issues
	if strings.Contains(name, " ") {
		return errors.New("image name cannot contain spaces")
	}

	// Check for valid characters
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:@"
	for _, char := range name {
		if !strings.ContainsRune(validChars, char) {
			return errors.Errorf("image name contains invalid character: %c", char)
		}
	}

	// Warn about :latest tag if image pinning is enforced
	if strings.HasSuffix(name, ":latest") && c.securityOpts.EnforceImagePinning {
		c.logger.WithField("image", name).Warning("Using :latest tag is discouraged for security reasons")
	}

	// Validate against trusted registries if specified
	if len(c.securityOpts.TrustedRegistries) > 0 {
		// Parse registry from image name
		registry := c.extractRegistry(name)
		if registry != "" && !c.isRegistryTrusted(registry) {
			return errors.Errorf("registry %s is not in the trusted registries list", registry)
		}
	}

	return nil
}

// validateContainerName validates a container name
func (c *Creator) validateContainerName(name string) error {
	if name == "" {
		return errors.New("container name cannot be empty")
	}

	// Container name must match regex: [a-zA-Z0-9][a-zA-Z0-9_.-]+
	nameRegex := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`)
	if !nameRegex.MatchString(name) {
		return errors.New("container name must match pattern [a-zA-Z0-9][a-zA-Z0-9_.-]+")
	}

	// Check if container name already exists
	containers, err := c.client.ContainerList(context.Background(), containertypes.ListOptions{All: true}) // Use dockertypes alias
	if err != nil {
		return errors.Wrap(err, "failed to list containers")
	}

	for _, containerItem := range containers { // Renamed loop variable
		for _, containerName := range containerItem.Names {
			// Docker returns names with a leading slash
			if strings.TrimPrefix(containerName, "/") == name {
				return errors.Errorf("container with name %s already exists", name)
			}
		}
	}

	return nil
}

// validateHealthCheck validates a health check configuration
func (c *Creator) validateHealthCheck(healthConfig *containertypes.HealthConfig) error { // Use containertypes alias
	// Validate Test command
	if len(healthConfig.Test) == 0 {
		return errors.New("health check test command cannot be empty")
	}

	// Check for potentially dangerous commands
	if healthConfig.Test[0] == "CMD" || healthConfig.Test[0] == "CMD-SHELL" {
		for _, cmd := range healthConfig.Test[1:] {
			if strings.Contains(cmd, "$(") || strings.Contains(cmd, "`") {
				return errors.New("potential shell injection detected in health check command")
			}
		}
	}

	// Validate intervals
	if healthConfig.Interval != 0 && healthConfig.Interval < time.Second {
		return errors.New("health check interval must be at least 1 second")
	}

	if healthConfig.Timeout != 0 && healthConfig.Timeout < time.Second {
		return errors.New("health check timeout must be at least 1 second")
	}

	if healthConfig.StartPeriod != 0 && healthConfig.StartPeriod < time.Second {
		return errors.New("health check start period must be at least 1 second")
	}

	// Retries should be positive
	if healthConfig.Retries < 0 {
		return errors.New("health check retries must be non-negative")
	}

	return nil
}

// validateRestartPolicy validates a restart policy
func (c *Creator) validateRestartPolicy(policy *containertypes.RestartPolicy) error { // Use containertypes alias
	// Check if policy name is valid
	validPolicies := map[containertypes.RestartPolicyMode]bool{ // Use containertypes alias
		"":               true, // default (no restart)
		"no":             true,
		"always":         true,
		"unless-stopped": true,
		"on-failure":     true,
	}

	if !validPolicies[policy.Name] { // Use policy.Name directly (it's already RestartPolicyMode)
		return errors.Errorf("invalid restart policy name: %s", policy.Name)
	}

	// Maximum restart count for on-failure
	if policy.Name == "on-failure" && policy.MaximumRetryCount < 0 {
		return errors.New("maximum retry count must be non-negative")
	}

	return nil
}

// validateLogConfig validates a log configuration
func (c *Creator) validateLogConfig(logConfig *containertypes.LogConfig) error { // Use containertypes alias
	// Check if log driver is valid
	validDrivers := map[string]bool{
		"":           true, // default (json-file)
		"json-file":  true,
		"syslog":     true,
		"journald":   true,
		"gelf":       true,
		"fluentd":    true,
		"awslogs":    true,
		"splunk":     true,
		"etwlogs":    true,
		"gcplogs":    true,
		"logentries": true,
		"local":      true,
	}

	if !validDrivers[logConfig.Type] {
		return errors.Errorf("invalid log driver: %s", logConfig.Type)
	}

	// Validate log options
	for key, value := range logConfig.Config {
		// Check for potentially sensitive information in log options
		if c.isSensitiveOption(key) {
			c.logger.WithField("log_option", key).Warning("Potentially sensitive log option detected")
		}

		// Validate max size format if specified
		if key == "max-size" || key == "max_size" {
			if !c.isValidSizeFormat(value) {
				return errors.Errorf("invalid max size format: %s", value)
			}
		}

		// Validate log rotation settings
		if key == "max-file" || key == "max_file" {
			if !c.isPositiveInteger(value) {
				return errors.Errorf("invalid max file value: %s", value)
			}
		}
	}

	return nil
}

// validateUserID validates a user ID
func (c *Creator) validateUserID(userID string) error {
	// Check if it's a numeric ID or user:group format
	if strings.Contains(userID, ":") {
		parts := strings.SplitN(userID, ":", 2)
		if len(parts) != 2 {
			return errors.New("invalid user:group format")
		}

		// Validate user part
		if parts[0] != "" && !c.isValidUsername(parts[0]) && !c.isPositiveInteger(parts[0]) {
			return errors.New("invalid user portion of user:group")
		}

		// Validate group part
		if parts[1] != "" && !c.isValidGroupname(parts[1]) && !c.isPositiveInteger(parts[1]) {
			return errors.New("invalid group portion of user:group")
		}
	} else {
		// Single value - must be numeric ID or username
		if !c.isValidUsername(userID) && !c.isPositiveInteger(userID) {
			return errors.New("user must be a valid username or numeric ID")
		}
	}

	return nil
}

// shouldPullImage determines whether to pull an image
func (c *Creator) shouldPullImage(ctx context.Context, opts CreateOptions) (bool, error) {
	// Always pull if policy is Always
	if opts.PullPolicy == PullAlways {
		return true, nil
	}

	// Never pull if policy is Never
	if opts.PullPolicy == PullNever {
		return false, nil
	}

	// If policy is IfNotPresent or unspecified, check if pull is enabled
	// Default to not pulling if neither pull nor policy is specified
	if !opts.Pull && opts.PullPolicy == "" {
		return false, nil
	}

	// Check if image exists locally
	imageFilter := filterstypes.NewArgs() // Use filterstypes alias
	imageFilter.Add("reference", opts.Image)

	images, err := c.client.ImageList(ctx, imagetypes.ListOptions{ // Use dockertypes alias
		Filters: imageFilter,
	})
	if err != nil {
		return false, errors.Wrap(err, "failed to list images")
	}

	// If image exists, don't pull
	if len(images) > 0 {
		return false, nil
	}

	// Image doesn't exist, pull it
	return true, nil
}

// pullImage pulls an image with registry authentication
func (c *Creator) pullImage(ctx context.Context, image string, auth *registrytypes.AuthConfig) error { // Use *registrytypes.AuthConfig
	var pullOptions imagetypes.PullOptions // Use dockertypes alias

	// Use provided auth if available, otherwise use registry provider
	if auth != nil {
		encodedAuth, err := encodeAuthToBase64(*auth) // Use registrytypes.AuthConfig here
		if err != nil {
			return errors.Wrap(err, "failed to encode auth config")
		}
		pullOptions.RegistryAuth = encodedAuth
	} else {
		pullOptions = c.registryProvider.GetAuthConfig(image)
	}

	// Pull the image
	c.logger.WithField("image", image).Debug("Pulling image")
	reader, err := c.client.ImagePull(ctx, image, pullOptions)
	if err != nil {
		return errors.Wrap(err, "failed to pull image")
	}
	defer reader.Close()

	// Wait for the pull to complete with a reasonable timeout
	_, err = c.readAllWithTimeout(reader, pullTimeout)
	if err != nil {
		return errors.Wrap(err, "error reading image pull response")
	}

	return nil
}

// applySecurityDefaults applies secure default settings to a container configuration
func (c *Creator) applySecurityDefaults(hostConfig *containertypes.HostConfig, overrideOpts *SecurityOpts, warnings *[]string) { // Use containertypes alias
	if hostConfig == nil {
		hostConfig = &containertypes.HostConfig{} // Use containertypes alias
	}

	// Start with creator's default security options
	opts := c.securityOpts

	// Override with per-container options if provided
	if overrideOpts != nil {
		if overrideOpts.NoNewPrivileges {
			opts.NoNewPrivileges = true
		}
		if len(overrideOpts.CapAdd) > 0 {
			opts.CapAdd = overrideOpts.CapAdd
		}
		if len(overrideOpts.CapDrop) > 0 {
			opts.CapDrop = overrideOpts.CapDrop
		}
		if overrideOpts.ReadOnlyRootfs {
			opts.ReadOnlyRootfs = true
		}
		if overrideOpts.SeccompProfile != "" {
			opts.SeccompProfile = overrideOpts.SeccompProfile
		}
		if overrideOpts.AppArmorProfile != "" {
			opts.AppArmorProfile = overrideOpts.AppArmorProfile
		}
		if overrideOpts.DisablePrivilegedContainers {
			opts.DisablePrivilegedContainers = true
		}
		if overrideOpts.DisableHostNamespaces {
			opts.DisableHostNamespaces = true
		}
		if overrideOpts.RunAsNonRoot {
			opts.RunAsNonRoot = true
		}
		if len(overrideOpts.DisallowedPaths) > 0 {
			opts.DisallowedPaths = overrideOpts.DisallowedPaths
		}
		if overrideOpts.SensitiveDirectoryProtection {
			opts.SensitiveDirectoryProtection = true
		}
	}

	// Apply security options to host config
	c.applySecurityOpts(hostConfig, opts)

	// Check for potentially insecure settings
	if hostConfig.Privileged {
		if opts.DisablePrivilegedContainers {
			hostConfig.Privileged = false
			*warnings = append(*warnings, "Privileged mode requested but disabled by security policy")
		} else {
			*warnings = append(*warnings, "Container is running in privileged mode, which bypasses security restrictions")
		}
	}

	if hostConfig.PidMode.IsHost() {
		if opts.DisableHostNamespaces {
			hostConfig.PidMode = ""
			*warnings = append(*warnings, "Host PID namespace requested but disabled by security policy")
		} else {
			*warnings = append(*warnings, "Container is using host PID namespace, which may allow container to see all processes on the host")
		}
	}

	if hostConfig.NetworkMode.IsHost() {
		if opts.DisableHostNamespaces {
			hostConfig.NetworkMode = ""
			*warnings = append(*warnings, "Host network namespace requested but disabled by security policy")
		} else {
			*warnings = append(*warnings, "Container is using host network namespace, which may expose host network services")
		}
	}

	if hostConfig.IpcMode.IsHost() {
		if opts.DisableHostNamespaces {
			hostConfig.IpcMode = ""
			*warnings = append(*warnings, "Host IPC namespace requested but disabled by security policy")
		} else {
			*warnings = append(*warnings, "Container is using host IPC namespace, which may allow inter-process communication with host processes")
		}
	}

	if hostConfig.UTSMode.IsHost() {
		if opts.DisableHostNamespaces {
			hostConfig.UTSMode = ""
			*warnings = append(*warnings, "Host UTS namespace requested but disabled by security policy")
		} else {
			*warnings = append(*warnings, "Container is using host UTS namespace, which may allow changing host hostname")
		}
	}

	// Check for Docker socket mount
	newMounts := []mounttypes.Mount{} // Use mounttypes alias
	for _, m := range hostConfig.Mounts {
		isSensitive := false

		if opts.SensitiveDirectoryProtection {
			for _, sensitive := range opts.DisallowedPaths {
				if strings.HasPrefix(m.Source, sensitive) || m.Source == sensitive {
					*warnings = append(*warnings, fmt.Sprintf("Mount %s is not allowed by security policy", m.Source))
					isSensitive = true
					break
				}
			}
		}

		// Only add non-sensitive mounts
		if !isSensitive {
			newMounts = append(newMounts, m)
		}
	}

	// Update mounts
	hostConfig.Mounts = newMounts
}

// applySecurityOpts applies security options to a host config
func (c *Creator) applySecurityOpts(hostConfig *containertypes.HostConfig, opts SecurityOpts) { // Use containertypes alias
	// Apply no-new-privileges
	if opts.NoNewPrivileges {
		hasNoNewPrivileges := false
		for _, opt := range hostConfig.SecurityOpt {
			if opt == "no-new-privileges" || opt == "no-new-privileges=true" {
				hasNoNewPrivileges = true
				break
			}
		}
		if !hasNoNewPrivileges {
			hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, "no-new-privileges=true")
		}
	}

	// Apply read-only root filesystem
	if opts.ReadOnlyRootfs {
		hostConfig.ReadonlyRootfs = true
	}

	// Apply seccomp profile
	if opts.SeccompProfile != "" {
		hasSeccompProfile := false
		for i, opt := range hostConfig.SecurityOpt {
			if strings.HasPrefix(opt, "seccomp=") {
				hostConfig.SecurityOpt[i] = "seccomp=" + opts.SeccompProfile
				hasSeccompProfile = true
				break
			}
		}
		if !hasSeccompProfile {
			hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, "seccomp="+opts.SeccompProfile)
		}
	}

	// Apply AppArmor profile
	if opts.AppArmorProfile != "" {
		hasApparmorProfile := false
		for i, opt := range hostConfig.SecurityOpt {
			if strings.HasPrefix(opt, "apparmor=") {
				hostConfig.SecurityOpt[i] = "apparmor=" + opts.AppArmorProfile
				hasApparmorProfile = true
				break
			}
		}
		if !hasApparmorProfile {
			hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, "apparmor="+opts.AppArmorProfile)
		}
	}

	// Apply capabilities
	// First, drop all capabilities if specified
	if len(opts.CapDrop) > 0 {
		// Check if we're dropping ALL
		droppingAll := false
		for _, cap := range opts.CapDrop {
			if cap == "ALL" {
				droppingAll = true
				break
			}
		}

		// If dropping ALL, replace any existing CapDrop with just ["ALL"]
		if droppingAll {
			hostConfig.CapDrop = []string{"ALL"}
		} else {
			// Otherwise, add each cap to drop
			for _, cap := range opts.CapDrop {
				if !c.containsString(hostConfig.CapDrop, cap) {
					hostConfig.CapDrop = append(hostConfig.CapDrop, cap)
				}
			}
		}
	}

	// Then add specific capabilities
	if len(opts.CapAdd) > 0 && c.containsString(hostConfig.CapDrop, "ALL") {
		for _, cap := range opts.CapAdd {
			if !c.containsString(hostConfig.CapAdd, cap) {
				hostConfig.CapAdd = append(hostConfig.CapAdd, cap)
			}
		}
	}
}

// applyResourceLimits applies resource limits to a container configuration
func (c *Creator) applyResourceLimits(hostConfig *containertypes.HostConfig, overrideLimits *ResourceLimits, appliedLimits *map[string]interface{}) { // Use containertypes alias
	if hostConfig == nil {
		return
	}

	// Start with creator's default resource limits
	limits := c.resourceLimits

	// Override with per-container limits if provided
	if overrideLimits != nil {
		if overrideLimits.Memory > 0 {
			limits.Memory = overrideLimits.Memory
		}
		if overrideLimits.CPUShares > 0 {
			limits.CPUShares = overrideLimits.CPUShares
		}
		if overrideLimits.CPUPeriod > 0 {
			limits.CPUPeriod = overrideLimits.CPUPeriod
		}
		if overrideLimits.CPUQuota > 0 {
			limits.CPUQuota = overrideLimits.CPUQuota
		}
		if overrideLimits.PidsLimit > 0 {
			limits.PidsLimit = overrideLimits.PidsLimit
		}
		if overrideLimits.BlkioWeight > 0 {
			limits.BlkioWeight = overrideLimits.BlkioWeight
		}
		if overrideLimits.CPUsetCPUs != "" {
			limits.CPUsetCPUs = overrideLimits.CPUsetCPUs
		}
		if overrideLimits.CPUsetMems != "" {
			limits.CPUsetMems = overrideLimits.CPUsetMems
		}
		if overrideLimits.MemoryReservation > 0 {
			limits.MemoryReservation = overrideLimits.MemoryReservation
		}
		if overrideLimits.MemorySwap != 0 {
			limits.MemorySwap = overrideLimits.MemorySwap
		}
		if overrideLimits.MemorySwappiness != nil {
			limits.MemorySwappiness = overrideLimits.MemorySwappiness
		}
		if overrideLimits.IOMaximumBandwidth > 0 {
			limits.IOMaximumBandwidth = overrideLimits.IOMaximumBandwidth
		}
		if overrideLimits.IOMaximumIOps > 0 {
			limits.IOMaximumIOps = overrideLimits.IOMaximumIOps
		}
	}

	// Apply memory limit
	if limits.Memory > 0 {
		hostConfig.Memory = limits.Memory
		(*appliedLimits)["memory"] = c.formatBytes(limits.Memory)
	}

	// Apply memory reservation (soft limit)
	if limits.MemoryReservation > 0 {
		hostConfig.MemoryReservation = limits.MemoryReservation
		(*appliedLimits)["memory_reservation"] = c.formatBytes(limits.MemoryReservation)
	}

	// Apply memory swap limit
	if limits.MemorySwap != 0 {
		hostConfig.MemorySwap = limits.MemorySwap
		if limits.MemorySwap > 0 {
			(*appliedLimits)["memory_swap"] = c.formatBytes(limits.MemorySwap)
		} else {
			(*appliedLimits)["memory_swap"] = "unlimited"
		}
	}

	// Apply memory swappiness
	if limits.MemorySwappiness != nil {
		hostConfig.MemorySwappiness = limits.MemorySwappiness
		(*appliedLimits)["memory_swappiness"] = *limits.MemorySwappiness
	}

	// Apply CPU shares
	if limits.CPUShares > 0 {
		hostConfig.CPUShares = limits.CPUShares
		(*appliedLimits)["cpu_shares"] = limits.CPUShares
	}

	// Apply CPU period
	if limits.CPUPeriod > 0 {
		hostConfig.CPUPeriod = limits.CPUPeriod
		(*appliedLimits)["cpu_period"] = limits.CPUPeriod
	}

	// Apply CPU quota
	if limits.CPUQuota > 0 {
		hostConfig.CPUQuota = limits.CPUQuota
		(*appliedLimits)["cpu_quota"] = limits.CPUQuota
	}

	// Apply PID limit
	if limits.PidsLimit > 0 {
		pidsLimit := limits.PidsLimit
		hostConfig.PidsLimit = &pidsLimit
		(*appliedLimits)["pids_limit"] = pidsLimit
	}

	// Apply block IO weight
	if limits.BlkioWeight > 0 {
		hostConfig.BlkioWeight = uint16(limits.BlkioWeight)
		(*appliedLimits)["blkio_weight"] = limits.BlkioWeight
	}

	// Apply CPU set CPUs
	if limits.CPUsetCPUs != "" {
		hostConfig.CpusetCpus = limits.CPUsetCPUs
		(*appliedLimits)["cpuset_cpus"] = limits.CPUsetCPUs
	}

	// Apply CPU set Mems
	if limits.CPUsetMems != "" {
		hostConfig.CpusetMems = limits.CPUsetMems
		(*appliedLimits)["cpuset_mems"] = limits.CPUsetMems
	}

	// Apply IO maximum bandwidth
	if limits.IOMaximumBandwidth > 0 {
		hostConfig.BlkioDeviceWriteBps = []*blkiotypes.ThrottleDevice{
			&blkiotypes.ThrottleDevice{ // Correct pointer syntax
				Path: "/dev/sda",                        // Assuming /dev/sda, might need configuration
				Rate: uint64(limits.IOMaximumBandwidth), // Cast to uint64
			},
		}
		hostConfig.BlkioDeviceReadBps = []*blkiotypes.ThrottleDevice{
			&blkiotypes.ThrottleDevice{ // Correct pointer syntax
				Path: "/dev/sda",                        // Assuming /dev/sda, might need configuration
				Rate: uint64(limits.IOMaximumBandwidth), // Cast to uint64
			},
		}
		(*appliedLimits)["io_maximum_bandwidth"] = c.formatBytes(limits.IOMaximumBandwidth) + "/s"
	}

	// Apply IO maximum IOps
	if limits.IOMaximumIOps > 0 {
		hostConfig.BlkioDeviceWriteIOps = []*blkiotypes.ThrottleDevice{
			&blkiotypes.ThrottleDevice{ // Correct pointer syntax
				Path: "/dev/sda",                   // Assuming /dev/sda, might need configuration
				Rate: uint64(limits.IOMaximumIOps), // Cast to uint64
			},
		}
		hostConfig.BlkioDeviceReadIOps = []*blkiotypes.ThrottleDevice{
			&blkiotypes.ThrottleDevice{ // Correct pointer syntax
				Path: "/dev/sda",                   // Assuming /dev/sda, might need configuration
				Rate: uint64(limits.IOMaximumIOps), // Cast to uint64
			},
		}
		(*appliedLimits)["io_maximum_iops"] = fmt.Sprintf("%d IOPS", limits.IOMaximumIOps)
	}
}

// validateMountPoints validates mount points for security issues
// Returns the valid mounts and a list of warnings
func (c *Creator) validateMountPoints(mounts []mounttypes.Mount) ([]mounttypes.Mount, []string) { // Use mounttypes alias
	var validMounts []mounttypes.Mount // Use mounttypes alias
	var warnings []string

	sensitiveDirectories := []string{
		"/proc",
		"/sys",
		"/var/run/docker_test.sock",
		"/etc/shadow",
		"/etc/passwd",
		"/etc/hosts",
		"/etc/kubernetes",
		"/var/lib/kubelet",
		"/root",
		"/home",
	}

	for _, m := range mounts {
		isSensitive := false

		// Check for sensitive mounts
		for _, sensitive := range sensitiveDirectories {
			if strings.HasPrefix(m.Source, sensitive) || m.Source == sensitive {
				if m.Source == "/var/run/docker_test.sock" {
					warnings = append(warnings, "Mount of Docker socket detected, which allows container to get full control of the host")
				} else {
					warnings = append(warnings, fmt.Sprintf("Mount of sensitive directory %s detected", m.Source))
				}
				isSensitive = true
				break
			}
		}

		// Check for file paths outside container
		if m.Type == "bind" && strings.Contains(m.Target, "..") {
			warnings = append(warnings, fmt.Sprintf("Path traversal detected in mount target: %s", m.Target))
			isSensitive = true
		}

		// Check for writable mounts
		if m.Type == "bind" && (m.ReadOnly == false) && (strings.HasPrefix(m.Target, "/bin") ||
			strings.HasPrefix(m.Target, "/sbin") ||
			strings.HasPrefix(m.Target, "/usr") ||
			strings.HasPrefix(m.Target, "/etc")) {
			warnings = append(warnings, fmt.Sprintf("Writable mount in system directory: %s", m.Target))
		}

		// Add to valid mounts if not sensitive
		if !isSensitive || !c.securityOpts.SensitiveDirectoryProtection {
			validMounts = append(validMounts, m)
		}
	}

	return validMounts, warnings
}

// validatePortBindings validates port bindings for security issues
// Returns valid port bindings and a list of warnings
func (c *Creator) validatePortBindings(portBindings map[string][]string) (map[string][]string, []string) {
	validBindings := make(map[string][]string)
	var warnings []string

	// Get range of privileged ports
	privilegedPorts := 1024

	for port, bindings := range portBindings {
		var validPortBindings []string

		// Validate port format (e.g., 80/tcp)
		portParts := strings.Split(port, "/")
		if len(portParts) != 2 {
			warnings = append(warnings, fmt.Sprintf("Invalid port format: %s", port))
			continue
		}

		_, err := strconv.Atoi(portParts[0]) // Assign to blank identifier
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Invalid port number: %s", portParts[0]))
			continue
		}

		protocol := portParts[1]
		if protocol != "tcp" && protocol != "udp" && protocol != "sctp" {
			warnings = append(warnings, fmt.Sprintf("Invalid protocol: %s", protocol))
			continue
		}

		// Check each binding
		for _, binding := range bindings {
			bindingParts := strings.Split(binding, ":")
			var hostIP, hostPort string

			if len(bindingParts) == 1 {
				hostIP = "0.0.0.0"
				hostPort = bindingParts[0]
			} else if len(bindingParts) == 2 {
				hostIP = bindingParts[0]
				hostPort = bindingParts[1]
			} else {
				warnings = append(warnings, fmt.Sprintf("Invalid binding format: %s", binding))
				continue
			}

			// Validate host port
			hostPortNum, err := strconv.Atoi(hostPort)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("Invalid host port: %s", hostPort))
				continue
			}

			// Check for privileged ports
			if hostPortNum < privilegedPorts {
				warnings = append(warnings, fmt.Sprintf("Binding to privileged port %d", hostPortNum))
			}

			// Validate IP address
			if hostIP != "0.0.0.0" && hostIP != "127.0.0.1" && hostIP != "::1" && hostIP != "" {
				ip := net.ParseIP(hostIP)
				if ip == nil {
					warnings = append(warnings, fmt.Sprintf("Invalid IP address: %s", hostIP))
					continue
				}
			}

			// Add to valid bindings
			validPortBindings = append(validPortBindings, binding)
		}

		if len(validPortBindings) > 0 {
			validBindings[port] = validPortBindings
		}
	}

	return validBindings, warnings
}

// convertToModel converts container inspection details to the database model.
// It assumes containerJSON is not nil.
func (c *Creator) convertToModel(containerJSON dockertypes.ContainerJSON) models.Container {
	containerModel := models.Container{
		DockerResource: models.DockerResource{
			// UserID needs to be set externally
			Name:   models.SanitizeDockerName(strings.TrimPrefix(containerJSON.Name, "/")),
			Labels: make(models.JSONMap), // Initialize map
			// Notes needs to be set externally
		},
		ContainerID:   containerJSON.ID,
		ImageID:       containerJSON.Image, // Image ID hash
		Command:       strings.Join(containerJSON.Config.Cmd, " "),
		ExitCode:      containerJSON.State.ExitCode,
		Privileged:    containerJSON.HostConfig.Privileged,
		AutoRemove:    containerJSON.HostConfig.AutoRemove,
		ReadOnly:      containerJSON.HostConfig.ReadonlyRootfs,
		HostIPC:       containerJSON.HostConfig.IpcMode.IsHost(),
		HostPID:       containerJSON.HostConfig.PidMode.IsHost(),
		UsernsMode:    string(containerJSON.HostConfig.UsernsMode),
		EnvVars:       models.StringArray(containerJSON.Config.Env),
		CapAdd:        models.StringArray(containerJSON.HostConfig.CapAdd),
		CapDrop:       models.StringArray(containerJSON.HostConfig.CapDrop),
		LastInspected: time.Now().UTC(), // Set inspection time
		// --- Fields marked gorm:"-" ---
		Names:        []string{strings.TrimPrefix(containerJSON.Name, "/")}, // Use the primary name
		Image:        containerJSON.Config.Image,                            // Full image name used
		State:        containerJSON.State.Status,                            // Raw state string
		SizeRw:       derefInt64Ptr(containerJSON.SizeRw),                   // Use helper
		SizeRootFs:   derefInt64Ptr(containerJSON.SizeRootFs),               // Use helper
		Entrypoint:   containerJSON.Config.Entrypoint,
		WorkingDir:   containerJSON.Config.WorkingDir,
		User:         containerJSON.Config.User,
		ExposedPorts: make([]string, 0, len(containerJSON.Config.ExposedPorts)),
		RestartCount: containerJSON.RestartCount,
		Platform:     containerJSON.Platform,
		Running:      containerJSON.State.Running,
		Paused:       containerJSON.State.Paused,
		Restarting:   containerJSON.State.Restarting,
		OOMKilled:    containerJSON.State.OOMKilled,
		Dead:         containerJSON.State.Dead,
		// StartedAt, FinishedAt, UpTime need parsing/calculation
		Mounts: make([]models.MountPoint, 0, len(containerJSON.Mounts)), // Initialize slice
		// ResourceLimits needs mapping
		// SecurityInfo needs mapping
	}

	// Parse Created time
	if createdTime, err := time.Parse(time.RFC3339Nano, containerJSON.Created); err == nil {
		containerModel.DockerResource.CreatedAt = createdTime // Assign to embedded field
	} else {
		c.logger.WithError(err).Warnf("Failed to parse container created time: %s", containerJSON.Created)
	}

	// Parse StartedAt time
	if startedTime, err := time.Parse(time.RFC3339Nano, containerJSON.State.StartedAt); err == nil {
		containerModel.StartedAt = startedTime
	}

	// Parse FinishedAt time
	if finishedTime, err := time.Parse(time.RFC3339Nano, containerJSON.State.FinishedAt); err == nil {
		containerModel.FinishedAt = finishedTime
	}

	// Calculate UpTime (simple example)
	if containerModel.Running && !containerModel.StartedAt.IsZero() {
		containerModel.UpTime = time.Since(containerModel.StartedAt).Round(time.Second).String()
	}

	// Map Status
	containerModel.Status = models.ContainerStatus(containerJSON.State.Status)
	if !models.IsValidContainerStatus(containerModel.Status) {
		// Attempt to use helper function if available (assuming it's in models pkg)
		formattedStatus := models.FormatContainerStatus(containerJSON.State.Status, "") // Pass empty health status for now
		if models.IsValidContainerStatus(formattedStatus) {
			containerModel.Status = formattedStatus
		} else {
			c.logger.Warnf("Invalid container status '%s' encountered for container %s", containerJSON.State.Status, containerJSON.ID)
			containerModel.Status = models.ContainerStatusUnknown // Default to unknown
		}
	}

	// Map Labels
	if containerJSON.Config.Labels != nil {
		for k, v := range containerJSON.Config.Labels {
			containerModel.DockerResource.Labels[k] = v
		}
	}

	// Map Restart Policy
	containerModel.RestartPolicy = models.RestartPolicy(containerJSON.HostConfig.RestartPolicy.Name)
	if !models.IsValidRestartPolicy(containerModel.RestartPolicy) {
		// Handle on-failure:N format
		if strings.HasPrefix(string(containerModel.RestartPolicy), "on-failure:") {
			// Valid format, keep it
		} else {
			c.logger.Warnf("Invalid restart policy '%s' encountered for container %s", containerJSON.HostConfig.RestartPolicy.Name, containerJSON.ID)
			containerModel.RestartPolicy = models.RestartPolicyNo // Default
		}
	}

	// Map Network Mode
	containerModel.NetworkMode = models.NetworkMode(containerJSON.HostConfig.NetworkMode)
	if !models.IsValidNetworkMode(containerModel.NetworkMode) {
		// Handle container:<id> format
		if strings.HasPrefix(string(containerModel.NetworkMode), "container:") {
			// Valid format, keep it
		} else {
			c.logger.Warnf("Invalid network mode '%s' encountered for container %s", containerJSON.HostConfig.NetworkMode, containerJSON.ID)
			containerModel.NetworkMode = models.NetworkModeBridge // Default
		}
	}

	// Map Security Options
	containerModel.SecurityOptions = models.StringArray(containerJSON.HostConfig.SecurityOpt)
	containerModel.SecurityProfile = containerJSON.AppArmorProfile // Or derive from SecurityOpt?

	// Map Resources (simplified example, map to JSONMap)
	containerModel.Resources = make(models.JSONMap)
	if containerJSON.HostConfig.Resources.Memory > 0 {
		containerModel.Resources["memory"] = containerJSON.HostConfig.Resources.Memory
	}
	if containerJSON.HostConfig.Resources.NanoCPUs > 0 {
		containerModel.Resources["nano_cpus"] = containerJSON.HostConfig.Resources.NanoCPUs
	}
	// ... map other resource fields as needed ...

	// Map Healthcheck (simplified example, map to JSONMap)
	containerModel.Healthcheck = make(models.JSONMap)
	if containerJSON.Config.Healthcheck != nil {
		containerModel.Healthcheck["test"] = containerJSON.Config.Healthcheck.Test
		containerModel.Healthcheck["interval"] = containerJSON.Config.Healthcheck.Interval.String()
		// ... map other healthcheck fields ...
	}

	// Map Networks (store detailed info in JSONMap)
	containerModel.Networks = make(models.JSONMap)
	if containerJSON.NetworkSettings != nil {
		containerModel.IPAddress = containerJSON.NetworkSettings.IPAddress // Primary IP
		for name, endpoint := range containerJSON.NetworkSettings.Networks {
			networkInfo := map[string]interface{}{
				"network_id":    endpoint.NetworkID,
				"endpoint_id":   endpoint.EndpointID,
				"gateway":       endpoint.Gateway,
				"ip_address":    endpoint.IPAddress,
				"ip_prefix_len": endpoint.IPPrefixLen,
				"ipv6_gateway":  endpoint.IPv6Gateway,
				"mac_address":   endpoint.MacAddress,
				"aliases":       endpoint.Aliases,
				"links":         endpoint.Links,
			}
			containerModel.Networks[name] = networkInfo
		}
	}

	// Map Ports (store as JSONMap: "containerPort/protocol": "hostIp:hostPort")
	containerModel.Ports = make(models.JSONMap)
	if containerJSON.NetworkSettings != nil && containerJSON.NetworkSettings.Ports != nil {
		for portProto, bindings := range containerJSON.NetworkSettings.Ports {
			if len(bindings) > 0 {
				// Just take the first binding for simplicity in this example
				binding := bindings[0]
				key := string(portProto) // e.g., "80/tcp"
				value := fmt.Sprintf("%s:%s", binding.HostIP, binding.HostPort)
				containerModel.Ports[key] = value
			} else {
				containerModel.Ports[string(portProto)] = "" // Exposed but not published
			}
		}
	}
	// Also populate ExposedPorts (gorm:"-")
	if containerJSON.Config.ExposedPorts != nil {
		for port := range containerJSON.Config.ExposedPorts {
			containerModel.ExposedPorts = append(containerModel.ExposedPorts, string(port))
		}
	}

	// Map Volumes/Mounts (store as JSONMap: "destination": "source/type/mode")
	containerModel.Volumes = make(models.JSONMap)
	for _, mount := range containerJSON.Mounts {
		// Populate gorm:"-" Mounts field
		containerModel.Mounts = append(containerModel.Mounts, models.MountPoint{
			Type:        string(mount.Type),
			Name:        mount.Name,
			Source:      mount.Source,
			Destination: mount.Destination, // Use Destination field now
			Mode:        mount.Mode,
			RW:          mount.RW,
			Propagation: string(mount.Propagation),
		})
		// Populate JSONMap Volumes field
		key := mount.Destination
		value := fmt.Sprintf("%s (%s, %s)", mount.Source, mount.Type, mount.Mode)
		containerModel.Volumes[key] = value
	}

	// Map Health Status (gorm:"-")
	if containerJSON.State.Health != nil {
		containerModel.Health = containerJSON.State.Health.Status
		// Could potentially store HealthLog as JSON string or similar if needed
	}

	// Map ResourceLimits (gorm:"-")
	containerModel.ResourceLimits = models.ResourceLimits{
		Memory:            containerJSON.HostConfig.Memory,
		MemorySwap:        containerJSON.HostConfig.MemorySwap,
		MemoryReservation: containerJSON.HostConfig.MemoryReservation,
		CPUShares:         containerJSON.HostConfig.CPUShares,
		CPUPeriod:         containerJSON.HostConfig.CPUPeriod,
		CPUQuota:          containerJSON.HostConfig.CPUQuota,
		CpusetCpus:        containerJSON.HostConfig.CpusetCpus,
		CpusetMems:        containerJSON.HostConfig.CpusetMems,
		PidsLimit:         derefInt64Ptr(containerJSON.HostConfig.PidsLimit), // Use helper
		BlkioWeight:       containerJSON.HostConfig.BlkioWeight,
	}

	// Map SecurityInfo (gorm:"-")
	containerModel.SecurityInfo = models.SecurityInfo{
		Privileged:     containerJSON.HostConfig.Privileged,
		ReadOnlyRootfs: containerJSON.HostConfig.ReadonlyRootfs,
		CapAdd:         containerJSON.HostConfig.CapAdd,
		CapDrop:        containerJSON.HostConfig.CapDrop,
		SecurityOpt:    containerJSON.HostConfig.SecurityOpt,
		NetworkMode:    string(containerJSON.HostConfig.NetworkMode),
		PidMode:        string(containerJSON.HostConfig.PidMode),
		IpcMode:        string(containerJSON.HostConfig.IpcMode),
		UTSMode:        string(containerJSON.HostConfig.UTSMode),
		UsernsMode:     string(containerJSON.HostConfig.UsernsMode),
		// SensitiveMounts needs logic to determine
	}

	return containerModel // Return containerModel
} // End of convertToModel

// Helper function to dereference *int64, returning 0 if nil
func derefInt64Ptr(ptr *int64) int64 {
	if ptr == nil {
		return 0
	}
	return *ptr
}

// encodeAuthToBase64 serializes the auth configuration to a base64 encoded string
func encodeAuthToBase64(authConfig registrytypes.AuthConfig) (string, error) { // Use registrytypes.AuthConfig
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(encodedJSON), nil
}

// readAllWithTimeout reads all data from a reader with timeout
func (c *Creator) readAllWithTimeout(reader io.ReadCloser, timeout time.Duration) ([]byte, error) {
	// Create a channel to signal completion
	done := make(chan struct{})
	var data []byte
	var err error

	// Read in a goroutine
	go func() {
		data, err = io.ReadAll(reader)
		close(done)
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		return data, err
	case <-time.After(timeout):
		return nil, fmt.Errorf("read operation timed out after %v", timeout)
	}
}

// Helper functions

// extractRegistry extracts the registry from an image name
func (c *Creator) extractRegistry(image string) string {
	parts := strings.Split(image, "/")
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		return parts[0]
	}
	return "docker_test.io" // Default registry
}

// isRegistryTrusted checks if a registry is in the trusted registries list
func (c *Creator) isRegistryTrusted(registry string) bool {
	// If no trusted registries specified, all are trusted
	if len(c.securityOpts.TrustedRegistries) == 0 {
		return true
	}

	for _, trusted := range c.securityOpts.TrustedRegistries {
		if registry == trusted {
			return true
		}
	}

	return false
}

// isSensitiveEnvVar checks if an environment variable is sensitive
func (c *Creator) isSensitiveEnvVar(key string) bool {
	sensitiveKeys := []string{
		"password", "key", "secret", "token", "credential", "auth", "api_key",
		"access_key", "access_token", "private_key", "cert", "passphrase",
	}

	key = strings.ToLower(key)
	for _, sensitiveKey := range sensitiveKeys {
		if strings.Contains(key, sensitiveKey) {
			return true
		}
	}

	return false
}

// isSensitiveOption checks if an option key is sensitive
func (c *Creator) isSensitiveOption(key string) bool {
	sensitiveKeys := []string{
		"password", "key", "secret", "token", "credential", "auth", "api_key",
		"access_key", "access_token", "private_key", "cert", "passphrase",
	}

	key = strings.ToLower(key)
	for _, sensitiveKey := range sensitiveKeys {
		if strings.Contains(key, sensitiveKey) {
			return true
		}
	}

	return false
}

// isValidSizeFormat checks if a string is a valid size format (e.g., 10m, 1g)
func (c *Creator) isValidSizeFormat(size string) bool {
	regex := regexp.MustCompile(`^[0-9]+[kmgt]?$`)
	return regex.MatchString(strings.ToLower(size))
}

// isPositiveInteger checks if a string is a positive integer
func (c *Creator) isPositiveInteger(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0
}

// isValidUsername checks if a string is a valid username
func (c *Creator) isValidUsername(s string) bool {
	regex := regexp.MustCompile(`^[a-z_][a-z0-9_-]*[$]?$`)
	return regex.MatchString(s)
}

// isValidGroupname checks if a string is a valid group name
func (c *Creator) isValidGroupname(s string) bool {
	return c.isValidUsername(s) // Same validation rules
}

// containsString checks if a string slice contains a string
func (c *Creator) containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// formatBytes formats bytes to a human-readable string
func (c *Creator) formatBytes(bytes int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)

	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// getNetworkInfo extracts network information from container network settings
func getNetworkInfo(networkSettings *dockertypes.NetworkSettings) map[string]interface{} { // Use dockertypes alias
	networkInfo := make(map[string]interface{})

	if networkSettings != nil && networkSettings.Networks != nil { // Add nil check
		for name, network := range networkSettings.Networks {
			networkInfo[name] = map[string]string{
				"ip_address":  network.IPAddress,
				"gateway":     network.Gateway,
				"mac_address": network.MacAddress,
				"network_id":  network.NetworkID, // Added NetworkID
			}
		}
	}

	return networkInfo
}

// getPortInfo extracts port information from container port mappings
func getPortInfo(ports nat.PortMap) []map[string]string {
	var portInfo []map[string]string

	for containerPort, bindings := range ports {
		port := string(containerPort)

		// If no bindings, add just the container port
		if len(bindings) == 0 {
			portInfo = append(portInfo, map[string]string{
				"host_ip":        "",
				"host_port":      "",
				"container_port": port,
			})
			continue
		}

		// Add each binding
		for _, binding := range bindings {
			portInfo = append(portInfo, map[string]string{
				"host_ip":        binding.HostIP,
				"host_port":      binding.HostPort,
				"container_port": port,
			})
		}
	}

	return portInfo
}
