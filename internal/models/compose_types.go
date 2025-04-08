// Package models provides data structures used throughout the application
package models

import (
	"time"

	"github.com/sirupsen/logrus" // Added for Logger in options
)

// ComposeFile represents a Docker Compose file
type ComposeFile struct {
	// Version is the version of the Compose file format
	Version string `yaml:"version" json:"version"`

	// Services is a map of service definitions
	Services map[string]ServiceConfig `yaml:"services" json:"services"`

	// Networks is a map of network definitions
	Networks map[string]NetworkConfig `yaml:"networks,omitempty" json:"networks,omitempty"`

	// Volumes is a map of volume definitions
	Volumes map[string]VolumeConfig `yaml:"volumes,omitempty" json:"volumes,omitempty"`

	// Secrets is a map of secret definitions
	Secrets map[string]SecretConfig `yaml:"secrets,omitempty" json:"secrets,omitempty"`

	// Configs is a map of config definitions
	Configs map[string]ConfigConfig `yaml:"configs,omitempty" json:"configs,omitempty"`

	// Extensions stores extension fields
	Extensions map[string]interface{} `yaml:"extensions,omitempty" json:"extensions,omitempty"` // Removed ,inline tag
}

// ServiceConfig represents a service in a Docker Compose file
type ServiceConfig struct {
	// Name is the name of the service
	Name string `yaml:"-" json:"name"`

	// Image is the image to use
	Image string `yaml:"image,omitempty" json:"image,omitempty"`

	// Build is the build configuration
	Build interface{} `yaml:"build,omitempty" json:"build,omitempty"`

	// Command is the command to run
	Command interface{} `yaml:"command,omitempty" json:"command,omitempty"`

	// Environment is a list of environment variables
	Environment interface{} `yaml:"environment,omitempty" json:"environment,omitempty"`

	// EnvFile is a list of environment files
	EnvFile interface{} `yaml:"env_file,omitempty" json:"env_file,omitempty"`

	// Ports is a list of port mappings
	Ports []interface{} `yaml:"ports,omitempty" json:"ports,omitempty"` // Can be list of strings or maps

	// Expose is a list of exposed ports
	Expose []interface{} `yaml:"expose,omitempty" json:"expose,omitempty"` // Can be list of strings/numbers

	// Volumes is a list of volume mappings
	Volumes interface{} `yaml:"volumes,omitempty" json:"volumes,omitempty"` // Reverted back to interface{} again

	// VolumesFrom is a list of services to mount volumes from
	VolumesFrom []string `yaml:"volumes_from,omitempty" json:"volumes_from,omitempty"` // List of strings

	// Networks is a list of networks to connect to
	Networks interface{} `yaml:"networks,omitempty" json:"networks,omitempty"`

	// NetworkMode is the network mode
	NetworkMode string `yaml:"network_mode,omitempty" json:"network_mode,omitempty"`

	// DependsOn is a list of services that this service depends on
	DependsOn interface{} `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`

	// HealthCheck is the health check configuration
	HealthCheck map[string]interface{} `yaml:"healthcheck,omitempty" json:"healthcheck,omitempty"` // Map structure

	// Deploy is the deployment configuration
	Deploy map[string]interface{} `yaml:"deploy,omitempty" json:"deploy,omitempty"` // Map structure

	// Restart is the restart policy
	Restart string `yaml:"restart,omitempty" json:"restart,omitempty"`

	// Labels are labels to apply to the container
	Labels interface{} `yaml:"labels,omitempty" json:"labels,omitempty"`

	// Extensions stores extension fields
	Extensions map[string]interface{} `json:"extensions,omitempty"` // Removed yaml tag entirely
}

// NetworkConfig represents a network in a Docker Compose file
type NetworkConfig struct {
	// Name is the name of the network
	Name string `yaml:"-" json:"name"`

	// Driver is the network driver
	Driver string `yaml:"driver,omitempty" json:"driver,omitempty"`

	// DriverOpts are driver-specific options
	DriverOpts map[string]string `yaml:"driver_opts,omitempty" json:"driver_opts,omitempty"`

	// IPAM is the IPAM configuration
	IPAM map[string]interface{} `yaml:"ipam,omitempty" json:"ipam,omitempty"` // Map structure

	// External indicates whether the network is external
	External interface{} `yaml:"external,omitempty" json:"external,omitempty"`

	// Internal indicates whether the network is internal
	Internal bool `yaml:"internal,omitempty" json:"internal,omitempty"`

	// Attachable indicates whether the network is attachable
	Attachable bool `yaml:"attachable,omitempty" json:"attachable,omitempty"`

	// Labels are labels to apply to the network
	Labels interface{} `yaml:"labels,omitempty" json:"labels,omitempty"`

	// Extensions stores extension fields
	Extensions map[string]interface{} `yaml:",inline" json:"extensions,omitempty"`
}

// VolumeConfig represents a volume in a Docker Compose file
type VolumeConfig struct {
	// Name is the name of the volume
	Name string `yaml:"-" json:"name"`

	// Driver is the volume driver
	Driver string `yaml:"driver,omitempty" json:"driver,omitempty"`

	// DriverOpts are driver-specific options
	DriverOpts map[string]string `yaml:"driver_opts,omitempty" json:"driver_opts,omitempty"`

	// External indicates whether the volume is external
	External interface{} `yaml:"external,omitempty" json:"external,omitempty"`

	// Labels are labels to apply to the volume
	Labels interface{} `yaml:"labels,omitempty" json:"labels,omitempty"`

	// Extensions stores extension fields
	Extensions map[string]interface{} `yaml:",inline" json:"extensions,omitempty"`
}

// SecretConfig represents a secret in a Docker Compose file
type SecretConfig struct {
	// Name is the name of the secret
	Name string `yaml:"-" json:"name"`

	// File is the file containing the secret
	File string `yaml:"file,omitempty" json:"file,omitempty"`

	// External indicates whether the secret is external
	External interface{} `yaml:"external,omitempty" json:"external,omitempty"`

	// Labels are labels to apply to the secret
	Labels interface{} `yaml:"labels,omitempty" json:"labels,omitempty"`

	// Extensions stores extension fields
	Extensions map[string]interface{} `yaml:",inline" json:"extensions,omitempty"`
}

// ConfigConfig represents a config in a Docker Compose file
type ConfigConfig struct {
	// Name is the name of the config
	Name string `yaml:"-" json:"name"`

	// File is the file containing the config
	File string `yaml:"file,omitempty" json:"file,omitempty"`

	// External indicates whether the config is external
	External interface{} `yaml:"external,omitempty" json:"external,omitempty"`

	// Labels are labels to apply to the config
	Labels interface{} `yaml:"labels,omitempty" json:"labels,omitempty"`

	// Extensions stores extension fields
	Extensions map[string]interface{} `yaml:",inline" json:"extensions,omitempty"`
}

// ComposeUpOptions represents options for deploying a Compose stack
// Based on fields used in pkg/client/compose.go ComposeUp function
type ComposeUpOptions struct {
	ProjectName          string            `json:"projectName"` // Used in API call logic, though not directly in SDK options
	EnvironmentVariables map[string]string `json:"environmentVariables,omitempty"`
	Recreate             string            `json:"recreate,omitempty"` // e.g., "never", "diverged", "always"
	NoStart              bool              `json:"noStart,omitempty"`
	ForceRecreate        bool              `json:"forceRecreate,omitempty"`
	NoBuild              bool              `json:"noBuild,omitempty"`
	ForceBuild           bool              `json:"forceBuild,omitempty"`
	TimeoutSeconds       int               `json:"timeoutSeconds,omitempty"` // Renamed for clarity
	QuietPull            bool              `json:"quietPull,omitempty"`      // Common compose option
}

// ComposeDownOptions represents options for shutting down a Compose stack
// Based on fields used in pkg/client/compose.go ComposeDown function
type ComposeDownOptions struct {
	RemoveVolumes  bool   `json:"removeVolumes,omitempty"`
	RemoveImages   string `json:"removeImages,omitempty"` // e.g., "all", "local"
	RemoveOrphans  bool   `json:"removeOrphans,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"` // Renamed for clarity
}

// --- Options Structs for Interfaces ---

// ParseOptions defines options for parsing compose files
type ParseOptions struct {
	WorkingDir  string // Working directory for resolving relative paths
	EnvFile     string // Optional path to an environment file
	ProjectName string // Optional project name override
	// Add other options if the parser implementation uses them
}

// DeployOptions defines options for deploying a Docker Compose project
type DeployOptions struct {
	ProjectName           string
	Timeout               time.Duration
	ForceRecreate         bool
	NoBuild               bool
	NoStart               bool
	Pull                  bool
	RemoveOrphans         bool
	DependencyTimeout     time.Duration
	AdjustNetworkSettings bool
	Logger                *logrus.Logger
}

// RemoveOptions defines options for removing a Docker Compose deployment
type RemoveOptions struct {
	ProjectName       string
	Timeout           time.Duration
	RemoveVolumes     bool
	RemoveImages      string // e.g., "all", "local"
	RemoveOrphans     bool
	Force             bool
	DependencyTimeout time.Duration
	Logger            *logrus.Logger
}

// StartOptions defines options for starting a Docker Compose deployment
type StartOptions struct {
	ProjectName       string
	Timeout           time.Duration
	DependencyTimeout time.Duration
	Logger            *logrus.Logger
}

// StopOptions defines options for stopping a Docker Compose deployment
type StopOptions struct {
	ProjectName       string
	Timeout           time.Duration
	DependencyTimeout time.Duration
	Logger            *logrus.Logger
}

// RestartOptions defines options for restarting a Docker Compose deployment
type RestartOptions struct {
	ProjectName       string
	Timeout           time.Duration
	DependencyTimeout time.Duration
	Logger            *logrus.Logger
}

// ScaleOptions defines options for scaling services in a Docker Compose deployment
type ScaleOptions struct {
	ProjectName       string
	Service           string
	Replicas          int
	Timeout           time.Duration
	DependencyTimeout time.Duration
	Logger            *logrus.Logger
}

// ComposeServiceStatus represents the status of a single service within a deployment
type ComposeServiceStatus struct {
	ID           string        `json:"id"` // Container ID if running
	Name         string        `json:"name"`
	State        string        `json:"state"` // e.g., "running", "exited(0)", "starting"
	Health       string        `json:"health,omitempty"`
	ExitCode     int           `json:"exit_code,omitempty"`
	Ports        []PortMapping `json:"ports,omitempty"`         // Reusing PortMapping from docker_entities.go
	DesiredState string        `json:"desired_state,omitempty"` // e.g. "running"
}

// ComposeStatus represents the overall status of a Compose deployment
type ComposeStatus struct {
	DeploymentID string                 `json:"deploymentId"`
	ProjectName  string                 `json:"projectName"`
	Status       string                 `json:"status"` // e.g., "running", "exited", "degraded"
	Services     []ComposeServiceStatus `json:"services"`
	Message      string                 `json:"message,omitempty"`
	LastUpdated  time.Time              `json:"lastUpdated"`
}
