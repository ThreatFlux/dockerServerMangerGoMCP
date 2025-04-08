// Package types provides common structures for Docker Compose functionality
package types

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
	Extensions map[string]interface{} `yaml:",inline" json:"extensions,omitempty"`
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
	Ports interface{} `yaml:"ports,omitempty" json:"ports,omitempty"`

	// Expose is a list of exposed ports
	Expose interface{} `yaml:"expose,omitempty" json:"expose,omitempty"`

	// Volumes is a list of volume mappings
	Volumes interface{} `yaml:"volumes,omitempty" json:"volumes,omitempty"`

	// VolumesFrom is a list of services to mount volumes from
	VolumesFrom interface{} `yaml:"volumes_from,omitempty" json:"volumes_from,omitempty"`

	// Networks is a list of networks to connect to
	Networks interface{} `yaml:"networks,omitempty" json:"networks,omitempty"`

	// NetworkMode is the network mode
	NetworkMode string `yaml:"network_mode,omitempty" json:"network_mode,omitempty"`

	// DependsOn is a list of services that this service depends on
	DependsOn interface{} `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`

	// HealthCheck is the health check configuration
	HealthCheck interface{} `yaml:"healthcheck,omitempty" json:"healthcheck,omitempty"`

	// Deploy is the deployment configuration
	Deploy interface{} `yaml:"deploy,omitempty" json:"deploy,omitempty"`

	// Restart is the restart policy
	Restart string `yaml:"restart,omitempty" json:"restart,omitempty"`

	// Labels are labels to apply to the container
	Labels interface{} `yaml:"labels,omitempty" json:"labels,omitempty"`

	// Extensions stores extension fields
	Extensions map[string]interface{} `yaml:",inline" json:"extensions,omitempty"`
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
	IPAM interface{} `yaml:"ipam,omitempty" json:"ipam,omitempty"`

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
