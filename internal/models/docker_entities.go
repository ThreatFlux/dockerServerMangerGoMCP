package models

import (
	"bytes" // Added for bytes functions
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os" // Added for os.FileMode
	"path/filepath"
	"regexp" // Added for formatContainerStatus
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container" // Added for container.Stats
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
)

var (
	validate = validator.New()

	ErrInvalidJSON            = errors.New("invalid JSON value")
	ErrInvalidDockerID        = errors.New("invalid Docker ID")
	ErrInvalidContainerStatus = errors.New("invalid container status")
)

// JSONMap represents a map that can be stored as JSON in a database column
type JSONMap map[string]interface{}

// Scan implements the sql.Scanner interface for database deserialization
func (m *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*m = make(JSONMap)
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case string:
		bytes = []byte(v)
	case []byte:
		bytes = v
	default:
		return fmt.Errorf("%w: cannot scan type %T into JSONMap", ErrInvalidJSON, value)
	}
	if len(bytes) == 0 || string(bytes) == "null" {
		*m = make(JSONMap)
		return nil
	}
	return json.Unmarshal(bytes, m)
}

// Value implements the driver.Valuer interface for database serialization
func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return "null", nil
	}
	if len(m) == 0 {
		return "{}", nil
	}
	bytes, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSONMap: %w", err)
	}
	return string(bytes), nil
}

// StringMap returns the JSONMap as a map of strings
func (m JSONMap) StringMap() map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		switch val := v.(type) {
		case string:
			result[k] = val
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, bool:
			result[k] = fmt.Sprintf("%v", val)
		case nil:
			result[k] = ""
		default:
			if jsonBytes, err := json.Marshal(val); err == nil {
				result[k] = string(jsonBytes)
			} else {
				result[k] = fmt.Sprintf("%v", val)
			}
		}
	}
	return result
}

// StringArray represents a slice that can be stored as JSON in a database column
type StringArray []string

// Scan implements the sql.Scanner interface for database deserialization
func (a *StringArray) Scan(value interface{}) error {
	if value == nil {
		*a = make(StringArray, 0)
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case string:
		bytes = []byte(v)
	case []byte:
		bytes = v
	default:
		return fmt.Errorf("%w: cannot scan type %T into StringArray", ErrInvalidJSON, value)
	}
	if len(bytes) == 0 || string(bytes) == "null" {
		*a = make(StringArray, 0)
		return nil
	}
	return json.Unmarshal(bytes, a)
}

// Value implements the driver.Valuer interface for database serialization
func (a StringArray) Value() (driver.Value, error) {
	if a == nil {
		return "[]", nil
	}
	if len(a) == 0 {
		return "[]", nil
	}
	bytes, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("error marshaling StringArray: %w", err)
	}
	return string(bytes), nil
}

// DockerResource represents common fields for all Docker resources
type DockerResource struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	UserID    uint           `json:"user_id" gorm:"index" validate:"required"`
	User      User           `json:"-" gorm:"foreignKey:UserID"`
	Name      string         `json:"name" gorm:"index;size:255" validate:"required,max=255,alphanumdash"`
	Labels    JSONMap        `json:"labels" gorm:"type:text"`
	Notes     string         `json:"notes" gorm:"type:text" validate:"max=5000"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// Validate checks if the resource is valid
func (r *DockerResource) Validate() error {
	return validate.Struct(r)
}

// SanitizeName sanitizes a resource name
func (r *DockerResource) SanitizeName() {
	r.Name = SanitizeDockerName(r.Name)
}

// SanitizeDockerName sanitizes a Docker resource name
func SanitizeDockerName(name string) string {
	var sanitized strings.Builder
	for _, char := range name {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '_' || char == '-' {
			sanitized.WriteRune(char)
		}
	}
	return sanitized.String()
}

// ContainerStatus represents the status of a container
type ContainerStatus string

const (
	ContainerStatusRunning    ContainerStatus = "running"
	ContainerStatusStopped    ContainerStatus = "stopped"
	ContainerStatusCreated    ContainerStatus = "created"
	ContainerStatusPaused     ContainerStatus = "paused"
	ContainerStatusRestarting ContainerStatus = "restarting"
	ContainerStatusRemoving   ContainerStatus = "removing"
	ContainerStatusExited     ContainerStatus = "exited"
	ContainerStatusDead       ContainerStatus = "dead"
	ContainerStatusUnknown    ContainerStatus = "unknown"
)

var AllContainerStatuses = []ContainerStatus{
	ContainerStatusRunning, ContainerStatusStopped, ContainerStatusCreated,
	ContainerStatusPaused, ContainerStatusRestarting, ContainerStatusRemoving,
	ContainerStatusExited, ContainerStatusDead, ContainerStatusUnknown,
}

func IsValidContainerStatus(status ContainerStatus) bool {
	for _, s := range AllContainerStatuses {
		if s == status {
			return true
		}
	}
	if strings.HasPrefix(string(status), "exited(") && strings.HasSuffix(string(status), ")") {
		return true
	}
	return false
}

// NetworkMode represents a container network mode
type NetworkMode string

const (
	NetworkModeNone      NetworkMode = "none"
	NetworkModeBridge    NetworkMode = "bridge"
	NetworkModeHost      NetworkMode = "host"
	NetworkModeContainer NetworkMode = "container"
)

var AllNetworkModes = []NetworkMode{
	NetworkModeNone, NetworkModeBridge, NetworkModeHost, NetworkModeContainer,
}

func IsValidNetworkMode(mode NetworkMode) bool {
	for _, m := range AllNetworkModes {
		if m == mode {
			return true
		}
	}
	if strings.HasPrefix(string(mode), "container:") {
		return true
	}
	return false
}

// RestartPolicy represents a container restart policy
type RestartPolicy string

const (
	RestartPolicyNo            RestartPolicy = "no"
	RestartPolicyAlways        RestartPolicy = "always"
	RestartPolicyOnFailure     RestartPolicy = "on-failure"
	RestartPolicyUnlessStopped RestartPolicy = "unless-stopped"
)

var AllRestartPolicies = []RestartPolicy{
	RestartPolicyNo, RestartPolicyAlways, RestartPolicyOnFailure, RestartPolicyUnlessStopped,
}

func IsValidRestartPolicy(policy RestartPolicy) bool {
	for _, p := range AllRestartPolicies {
		if p == policy {
			return true
		}
	}
	if strings.HasPrefix(string(policy), "on-failure:") {
		return true
	}
	return false
}

// Container represents a Docker container in the database
type Container struct {
	DockerResource
	ContainerID         string                     `json:"container_id" gorm:"index;size:64" validate:"len=64,alphanum"`
	ImageID             string                     `json:"image_id" gorm:"index;size:64" validate:"required"`
	Command             string                     `json:"command" validate:"max=1024"`
	Status              ContainerStatus            `json:"status" gorm:"index;size:32" validate:"containerStatus"`
	Ports               JSONMap                    `json:"ports" gorm:"type:text"`
	Volumes             JSONMap                    `json:"volumes" gorm:"type:text"`
	Networks            JSONMap                    `json:"networks" gorm:"type:text"`
	IPAddress           string                     `json:"ip_address" validate:"omitempty,ip"`
	ExitCode            int                        `json:"exit_code"`
	RestartPolicy       RestartPolicy              `json:"restart_policy" validate:"required,restartPolicy"`
	NetworkMode         NetworkMode                `json:"network_mode" validate:"required,networkMode"`
	Privileged          bool                       `json:"privileged"`
	HasChanged          bool                       `json:"has_changed" gorm:"default:false"`
	LastInspected       time.Time                  `json:"last_inspected"`
	SecurityOptions     StringArray                `json:"security_options" gorm:"type:text"`
	SecurityProfile     string                     `json:"security_profile" gorm:"size:255"`
	AutoRemove          bool                       `json:"auto_remove"`
	ReadOnly            bool                       `json:"read_only"`
	HostIPC             bool                       `json:"host_ipc"`
	HostPID             bool                       `json:"host_pid"`
	CapAdd              StringArray                `json:"cap_add" gorm:"type:text"`
	CapDrop             StringArray                `json:"cap_drop" gorm:"type:text"`
	UsernsMode          string                     `json:"userns_mode" gorm:"size:255"`
	Resources           JSONMap                    `json:"resources" gorm:"type:text"`
	Healthcheck         JSONMap                    `json:"healthcheck" gorm:"type:text"`
	EnvVars             StringArray                `json:"env_vars" gorm:"type:text"`
	Secrets             StringArray                `json:"secrets" gorm:"type:text" validate:"-"`
	Stats               ContainerStats             `json:"stats" gorm:"-"`
	Processes           []Process                  `json:"processes" gorm:"-"`
	DetailedNetworkInfo map[string]DetailedNetwork `json:"detailed_network_info" gorm:"-"`
	DetailedVolumeInfo  map[string]DetailedVolume  `json:"detailed_volume_info" gorm:"-"`
	// Fields from list item conversion (might be redundant with inspect)
	Names      []string `json:"names" gorm:"-"`
	Image      string   `json:"image" gorm:"-"`
	State      string   `json:"state" gorm:"-"` // Raw state string
	SizeRw     int64    `json:"size_rw,omitempty" gorm:"-"`
	SizeRootFs int64    `json:"size_root_fs,omitempty" gorm:"-"`
	// Fields from inspect conversion (might be redundant)
	Entrypoint     []string       `json:"entrypoint" gorm:"-"`
	WorkingDir     string         `json:"working_dir" gorm:"-"`
	User           string         `json:"user" gorm:"-"`
	ExposedPorts   []string       `json:"exposed_ports" gorm:"-"`
	RestartCount   int            `json:"restart_count" gorm:"-"`
	Platform       string         `json:"platform" gorm:"-"`
	Health         string         `json:"health,omitempty" gorm:"-"`
	HealthLog      string         `json:"health_log,omitempty" gorm:"-"`
	Running        bool           `json:"running" gorm:"-"`
	Paused         bool           `json:"paused" gorm:"-"`
	Restarting     bool           `json:"restarting" gorm:"-"`
	OOMKilled      bool           `json:"oom_killed" gorm:"-"`
	Dead           bool           `json:"dead" gorm:"-"`
	StartedAt      time.Time      `json:"started_at,omitempty" gorm:"-"`
	FinishedAt     time.Time      `json:"finished_at,omitempty" gorm:"-"`
	UpTime         string         `json:"up_time,omitempty" gorm:"-"`
	Mounts         []MountPoint   `json:"mounts" gorm:"-"`
	ResourceLimits ResourceLimits `json:"resource_limits" gorm:"-"`
	SecurityInfo   SecurityInfo   `json:"security_info" gorm:"-"`
}

// ContainerStats holds resource usage statistics for a container
type ContainerStats struct {
	Time             time.Time `json:"time"`
	CPUPercentage    float64   `json:"cpu_percentage"`
	CPUUsage         uint64    `json:"cpu_usage"`
	SystemCPUUsage   uint64    `json:"system_cpu_usage"`
	OnlineCPUs       uint32    `json:"online_cpus"`
	MemoryUsage      uint64    `json:"memory_usage"`
	MemoryMaxUsage   uint64    `json:"memory_max_usage"`
	MemoryLimit      uint64    `json:"memory_limit"`
	MemoryPercentage float64   `json:"memory_percentage"`
	NetworkRx        int64     `json:"network_rx"`
	NetworkTx        int64     `json:"network_tx"`
	BlockRead        int64     `json:"block_read"`
	BlockWrite       int64     `json:"block_write"`
	PIDs             uint64    `json:"pids"`
}

// Process represents a running process inside a container
type Process struct {
	PID     int    `json:"pid"`
	User    string `json:"user"`
	Time    string `json:"time"`
	Command string `json:"command"`
	CPU     string `json:"cpu"`
	Memory  string `json:"memory"`
}

// DetailedNetwork represents detailed network information
type DetailedNetwork struct {
	Name       string  `json:"name"`
	ID         string  `json:"id"`
	Driver     string  `json:"driver"`
	Scope      string  `json:"scope"`
	Internal   bool    `json:"internal"`
	IPAMConfig IPAM    `json:"ipam_config"` // Use local models.IPAM
	Options    JSONMap `json:"options"`
	Labels     JSONMap `json:"labels"`
}

// DetailedVolume represents detailed volume information
type DetailedVolume struct {
	Name       string  `json:"name"`
	Driver     string  `json:"driver"`
	Mountpoint string  `json:"mountpoint"`
	Status     JSONMap `json:"status"`
	Labels     JSONMap `json:"labels"`
	Options    JSONMap `json:"options"`
	Scope      string  `json:"scope"`
}

// SecurityInfo holds security-related information about a container
type SecurityInfo struct {
	Privileged      bool     `json:"privileged"`
	ReadOnlyRootfs  bool     `json:"read_only_rootfs"`
	CapAdd          []string `json:"cap_add"`
	CapDrop         []string `json:"cap_drop"`
	SecurityOpt     []string `json:"security_opt"`
	NetworkMode     string   `json:"network_mode"`
	PidMode         string   `json:"pid_mode"`
	IpcMode         string   `json:"ipc_mode"`
	UTSMode         string   `json:"uts_mode"`
	UsernsMode      string   `json:"userns_mode"`
	SensitiveMounts []string `json:"sensitive_mounts"`
}

// PortMapping represents a port mapping configuration for a container.
// @description Defines how a container port is exposed on the host machine.
type PortMapping struct {
	// HostIP is the IP address on the host to bind the port to. Defaults to 0.0.0.0 (all interfaces).
	// example: "127.0.0.1"
	HostIP string `json:"host_ip"`

	// HostPort is the port number on the host. If empty or "0", Docker assigns a random ephemeral port.
	// example: "8080"
	HostPort string `json:"host_port"`

	// ContainerPort is the port number inside the container.
	// required: true
	// example: "80"
	ContainerPort string `json:"container_port"`

	// Type is the protocol (e.g., "tcp", "udp", "sctp"). Defaults to "tcp".
	// example: "tcp"
	Type string `json:"type"`
}

// MountPoint represents a mount point for a container
type MountPoint struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
	Propagation string `json:"propagation"`
}

// ResourceLimits represents resource limits for a container
type ResourceLimits struct {
	Memory            int64  `json:"memory"`
	MemorySwap        int64  `json:"memory_swap"`
	MemoryReservation int64  `json:"memory_reservation"`
	CPUShares         int64  `json:"cpu_shares"`
	CPUPeriod         int64  `json:"cpu_period"`
	CPUQuota          int64  `json:"cpu_quota"`
	CpusetCpus        string `json:"cpuset_cpus"`
	CpusetMems        string `json:"cpuset_mems"`
	PidsLimit         int64  `json:"pids_limit"`
	BlkioWeight       uint16 `json:"blkio_weight"`
}

// ResourceStat holds information about a file or directory in a container
type ResourceStat struct {
	Name string      `json:"name"`
	Size int64       `json:"size"`
	Mode os.FileMode `json:"mode"` // Use os.FileMode (uint32)
	// ModTime is NOT available from CopyFromContainer stat
	LinkTarget string `json:"link_target"`
}

// ValidateContainerStatus validates a container status
func ValidateContainerStatus(fl validator.FieldLevel) bool {
	status, ok := fl.Field().Interface().(ContainerStatus)
	if !ok {
		if strStatus, okStr := fl.Field().Interface().(string); okStr {
			status = ContainerStatus(strStatus)
		} else {
			return false
		}
	}
	return IsValidContainerStatus(status)
}

// ValidateRestartPolicy validates a restart policy
func ValidateRestartPolicy(fl validator.FieldLevel) bool {
	policy, ok := fl.Field().Interface().(RestartPolicy)
	if !ok {
		if strPolicy, okStr := fl.Field().Interface().(string); okStr {
			policy = RestartPolicy(strPolicy)
		} else {
			return false
		}
	}
	return IsValidRestartPolicy(policy)
}

// ValidateNetworkMode validates a network mode
func ValidateNetworkMode(fl validator.FieldLevel) bool {
	mode, ok := fl.Field().Interface().(NetworkMode)
	if !ok {
		if strMode, okStr := fl.Field().Interface().(string); okStr {
			mode = NetworkMode(strMode)
		} else {
			return false
		}
	}
	return IsValidNetworkMode(mode)
}

// Validate checks if the container is valid
func (c *Container) Validate() error {
	validate.RegisterValidation("containerStatus", ValidateContainerStatus)
	validate.RegisterValidation("restartPolicy", ValidateRestartPolicy)
	validate.RegisterValidation("networkMode", ValidateNetworkMode)
	validate.RegisterValidation("alphanumdash", ValidateAlphaNumDash)

	if err := c.DockerResource.Validate(); err != nil {
		return err
	}
	if err := validate.Struct(c); err != nil {
		return err
	}

	// Security warnings (consider moving to a separate check function)
	if c.Privileged {
		fmt.Println("Warning: Container is running in privileged mode")
	}
	if c.NetworkMode == NetworkModeHost {
		fmt.Println("Warning: Container is using host network mode")
	}
	if c.HostIPC || c.HostPID {
		fmt.Println("Warning: Container is using host IPC or PID namespace")
	}
	for _, cap := range c.CapAdd {
		if strings.ToUpper(cap) == "ALL" {
			fmt.Println("Warning: Container is adding ALL capabilities")
			break
		}
	}
	if c.SecurityProfile == "" {
		fmt.Println("Warning: Container does not have a security profile defined")
	}

	return nil
}

// SanitizeSecurityFields redacts sensitive information from container fields
func (c *Container) SanitizeSecurityFields() {
	// Redact environment variables
	redactedEnv := make(StringArray, len(c.EnvVars))
	for i, envVar := range c.EnvVars {
		if isSensitiveEnvVar(envVar) {
			parts := strings.SplitN(envVar, "=", 2)
			if len(parts) == 2 {
				redactedEnv[i] = parts[0] + "=*****"
			} else {
				redactedEnv[i] = envVar // Keep as is if format is unexpected
			}
		} else {
			redactedEnv[i] = envVar
		}
	}
	c.EnvVars = redactedEnv

	// Redact secrets (assuming they are just names/references)
	// If they contain actual secret content, more robust redaction is needed
	for i, secret := range c.Secrets {
		parts := strings.SplitN(secret, "=", 2)
		if len(parts) == 2 {
			c.Secrets[i] = parts[0] + "=*****"
		}
	}
}

// isSensitiveEnvVar checks if an environment variable contains sensitive information
func isSensitiveEnvVar(envVar string) bool {
	sensitiveKeys := []string{
		"PASSWORD", "PASSWD", "SECRET", "KEY", "TOKEN", "CREDENTIALS",
		"APIKEY", "API_KEY", "AUTH", "ACCESS_KEY", "ACCESS_TOKEN",
		"DB_PASSWORD", "DATABASE_PASSWORD",
	}
	upperEnvVar := strings.ToUpper(envVar)
	for _, key := range sensitiveKeys {
		if strings.HasPrefix(upperEnvVar, key+"=") {
			return true
		}
	}
	return false
}

// ValidateAlphaNumDash validates that a string contains only alphanumeric characters, dashes, underscores, and dots
func ValidateAlphaNumDash(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// Image represents a Docker image in the database
type Image struct {
	DockerResource
	ImageID         string      `json:"image_id" gorm:"index;size:128" validate:"required"` // Docker Image ID (sha256:...) - Increased size
	Repository      string      `json:"repository" gorm:"index;size:255" validate:"required,max=255"`
	Tag             string      `json:"tag" gorm:"index;size:128" validate:"required,max=128"`
	Digest          string      `json:"digest" gorm:"index;size:255" validate:"omitempty,max=255"`
	Size            int64       `json:"size" validate:"min=0"`
	Created         time.Time   `json:"created"`
	Author          string      `json:"author" validate:"max=255"`
	Architecture    string      `json:"architecture" validate:"max=64"`
	OS              string      `json:"os" validate:"max=64"`
	Containers      []Container `json:"-" gorm:"foreignKey:ImageID;references:ImageID"`
	LastInspected   time.Time   `json:"last_inspected"`
	ContentTrust    bool        `json:"content_trust"`
	SignatureInfo   JSONMap     `json:"signature_info" gorm:"type:text"`
	Vulnerabilities JSONMap     `json:"vulnerabilities" gorm:"type:text"`
}

// Validate checks if the image is valid
func (i *Image) Validate() error {
	validate.RegisterValidation("alphanumdash", ValidateAlphaNumDash)
	if err := i.DockerResource.Validate(); err != nil {
		return err
	}
	if err := i.ValidateImageDigest(); err != nil {
		return err
	}
	return validate.Struct(i)
}

// ValidateImageDigest validates the image digest format
func (i *Image) ValidateImageDigest() error {
	if i.Digest == "" {
		return nil
	}
	parts := strings.SplitN(i.Digest, ":", 2)
	if len(parts) != 2 {
		return errors.New("invalid digest format, expected algorithm:hex")
	}
	if parts[0] != "sha256" && parts[0] != "sha384" && parts[0] != "sha512" {
		return fmt.Errorf("unsupported digest algorithm: %s", parts[0])
	}
	if !isHexString(parts[1]) {
		return errors.New("digest must be a hex string")
	}
	return nil
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// SanitizeImageFields redacts sensitive information from image fields (if any)
func (i *Image) SanitizeImageFields() {
	// Currently no sensitive fields identified in Image struct itself
	// Labels are handled by DockerResource
}

// Volume represents a Docker volume in the database
type Volume struct {
	DockerResource
	VolumeID      string           `json:"volume_id" gorm:"index;size:64" validate:"required,alphanumdash"`
	Driver        string           `json:"driver" validate:"max=255"`
	Mountpoint    string           `json:"mountpoint" validate:"required"`
	Scope         string           `json:"scope" validate:"max=64"`
	InUse         bool             `json:"in_use"`
	LastInspected time.Time        `json:"last_inspected"`
	Options       JSONMap          `json:"options" gorm:"type:text"`
	DriverOpts    JSONMap          `json:"driver_opts" gorm:"type:text"`
	Security      JSONMap          `json:"security" gorm:"type:text"`
	Status        JSONMap          `json:"status" gorm:"type:text"`
	UsageData     *VolumeUsageData `json:"usage_data" gorm:"-"` // Exclude from DB, populate on demand
	Containers    []Container      `json:"-" gorm:"many2many:container_volumes;"`
}

// VolumeUsageData holds usage information for a volume
type VolumeUsageData struct {
	Size     int64 `json:"size"`
	RefCount int64 `json:"ref_count"` // Changed to int64 to match Docker SDK
}

// Validate checks if the volume is valid
func (v *Volume) Validate() error {
	validate.RegisterValidation("alphanumdash", ValidateAlphaNumDash)
	if err := v.DockerResource.Validate(); err != nil {
		return err
	}
	return validate.Struct(v)
}

// SanitizeMountpoint cleans the volume mountpoint path
func (v *Volume) SanitizeMountpoint() {
	v.Mountpoint = filepath.Clean(v.Mountpoint)
}

// Network represents a Docker network in the database
type Network struct {
	DockerResource
	NetworkID     string    `json:"network_id" gorm:"index;size:64" validate:"required,alphanumdash"`
	Driver        string    `json:"driver" validate:"max=255"`
	Scope         string    `json:"scope" validate:"max=64"`
	Created       time.Time `json:"created"`
	Gateway       string    `json:"gateway" validate:"omitempty,ip"`
	Subnet        string    `json:"subnet" validate:"omitempty,cidr"`
	IPRange       string    `json:"ip_range" validate:"omitempty,cidr"`
	Internal      bool      `json:"internal"`
	EnableIPv6    bool      `json:"enable_ipv6"`
	Attachable    bool      `json:"attachable"`
	Ingress       bool      `json:"ingress"`
	ConfigOnly    bool      `json:"config_only"`
	Containers    JSONMap   `json:"containers" gorm:"type:text"` // Store container connections as JSON
	LastInspected time.Time `json:"last_inspected"`
	Options       JSONMap   `json:"options" gorm:"type:text"`
	IPAMOptions   JSONMap   `json:"ip_am_options" gorm:"type:text"` // Store IPAM config as JSON
	Security      JSONMap   `json:"security" gorm:"type:text"`
	ConfigFrom    string    `json:"config_from" gorm:"size:255"` // Name of network this config is from
}

// Validate checks if the network is valid
func (n *Network) Validate() error {
	validate.RegisterValidation("alphanumdash", ValidateAlphaNumDash)
	validate.RegisterValidation("cidr", validateCIDR)
	if err := n.DockerResource.Validate(); err != nil {
		return err
	}
	if err := n.ValidateNetworkAddressing(); err != nil {
		return err
	}
	return validate.Struct(n)
}

// IPAM represents IP Address Management configuration
type IPAM struct {
	Driver  string       `json:"driver"`
	Options JSONMap      `json:"options"`
	Config  []IPAMConfig `json:"config"`
}

// IPAMConfig represents IPAM configuration details
type IPAMConfig struct {
	Subnet     string  `json:"subnet"`
	IPRange    string  `json:"ip_range"`
	Gateway    string  `json:"gateway"`
	AuxAddress JSONMap `json:"aux_address"`
}

// EndpointResource represents a network endpoint resource
type EndpointResource struct {
	Name        string `json:"name"`
	EndpointID  string `json:"endpoint_id"`
	MacAddress  string `json:"mac_address"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address"`
}

// NetworkPruneResponse represents the response from a network prune operation
type NetworkPruneResponse struct {
	NetworksDeleted []string `json:"networks_deleted"`
}

// ValidateNetworkAddressing performs specific validation for network addressing fields
func (n *Network) ValidateNetworkAddressing() error {
	if n.Gateway != "" {
		if ip := net.ParseIP(n.Gateway); ip == nil {
			return fmt.Errorf("invalid gateway IP address: %s", n.Gateway)
		}
	}
	if n.Subnet != "" {
		if _, _, err := net.ParseCIDR(n.Subnet); err != nil {
			return fmt.Errorf("invalid subnet CIDR: %w", err)
		}
	}
	if n.IPRange != "" {
		if _, _, err := net.ParseCIDR(n.IPRange); err != nil {
			return fmt.Errorf("invalid ip_range CIDR: %w", err)
		}
	}

	// Validate IPAM config if present
	if ipamOptions, ok := n.IPAMOptions["Config"]; ok {
		if configSlice, okSlice := ipamOptions.([]interface{}); okSlice {
			for _, configItem := range configSlice {
				if configMap, okMap := configItem.(map[string]interface{}); okMap {
					if subnet, okSub := configMap["Subnet"].(string); okSub && subnet != "" {
						if _, _, err := net.ParseCIDR(subnet); err != nil {
							return fmt.Errorf("invalid IPAM subnet CIDR: %w", err)
						}
					}
					if ipRange, okRange := configMap["IPRange"].(string); okRange && ipRange != "" {
						if _, _, err := net.ParseCIDR(ipRange); err != nil {
							return fmt.Errorf("invalid IPAM ip_range CIDR: %w", err)
						}
					}
					if gateway, okGw := configMap["Gateway"].(string); okGw && gateway != "" {
						if ip := net.ParseIP(gateway); ip == nil {
							return fmt.Errorf("invalid IPAM gateway IP address: %s", gateway)
						}
					}
				}
			}
		}
	}

	return nil
}

// isSubnet checks if subnet1 is a subnet of subnet2
func isSubnet(subnet1, subnet2 *net.IPNet) bool {
	return subnet2.Contains(subnet1.IP) &&
		bytes.Equal(subnet1.Mask, subnet2.Mask) && // Use bytes.Equal for mask comparison
		bytes.Compare(subnet1.Mask, subnet2.Mask) >= 0 // Use bytes.Compare
}

// ComposeDeployment represents a Docker Compose deployment in the database
type ComposeDeployment struct {
	DockerResource
	ProjectName  string           `json:"project_name" gorm:"uniqueIndex;size:255" validate:"required,max=255,alphanumdash"`
	FilePath     string           `json:"file_path" validate:"omitempty,filepath"`
	Content      string           `json:"-" gorm:"type:text"` // Store raw compose content
	EnvVars      JSONMap          `json:"env_vars" gorm:"type:text"`
	Status       string           `json:"status" gorm:"index;size:64" validate:"required,max=64"`
	ServiceCount int              `json:"service_count"`
	RunningCount int              `json:"running_count"`
	Services     []ComposeService `json:"services" gorm:"foreignKey:DeploymentID"`
	LastDeployed time.Time        `json:"last_deployed"`
	LastUpdated  time.Time        `json:"last_updated"`
}

// Validate checks if the compose deployment is valid
func (cd *ComposeDeployment) Validate() error {
	validate.RegisterValidation("alphanumdash", ValidateAlphaNumDash)
	if err := cd.DockerResource.Validate(); err != nil {
		return err
	}
	return validate.Struct(cd)
}

// SanitizeComposeEnvironment redacts sensitive environment variables
func (cd *ComposeDeployment) SanitizeComposeEnvironment() {
	sanitizedEnv := make(JSONMap)
	for key, value := range cd.EnvVars {
		if isSensitiveEnvVar(fmt.Sprintf("%s=%v", key, value)) {
			sanitizedEnv[key] = "*****"
		} else {
			sanitizedEnv[key] = value
		}
	}
	cd.EnvVars = sanitizedEnv
}

// ComposeService represents a service within a Docker Compose deployment
type ComposeService struct {
	ID           uint            `json:"id" gorm:"primaryKey"`
	DeploymentID uint            `json:"-" gorm:"index" validate:"required"` // Link back to ComposeDeployment
	Name         string          `json:"name" gorm:"index;size:255" validate:"required,max=255,alphanumdash"`
	ImageName    string          `json:"image_name" validate:"required,max=512"`
	Status       ContainerStatus `json:"status" gorm:"index;size:32" validate:"containerStatus"`
	Replicas     int             `json:"replicas" validate:"min=0"`
	RunningCount int             `json:"running_count" validate:"min=0"`
	Ports        JSONMap         `json:"ports" gorm:"type:text"`
	Volumes      JSONMap         `json:"volumes" gorm:"type:text"`
	Networks     StringArray     `json:"networks" gorm:"type:text"`
	Environment  StringArray     `json:"environment" gorm:"type:text"`
	Command      string          `json:"command" validate:"max=1024"`
	Depends      StringArray     `json:"depends" gorm:"type:text"`
	Labels       JSONMap         `json:"labels" gorm:"type:text"`
	Build        JSONMap         `json:"build" gorm:"type:text"` // Store build context/args as JSON
	Healthcheck  JSONMap         `json:"healthcheck" gorm:"type:text"`
	Secrets      StringArray     `json:"secrets" gorm:"type:text" validate:"-"`
	Configs      StringArray     `json:"configs" gorm:"type:text" validate:"-"`
	Deploy       JSONMap         `json:"deploy" gorm:"type:text"` // Store deploy options (replicas, resources, etc.)
	LastUpdated  time.Time       `json:"last_updated"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	DeletedAt    gorm.DeletedAt  `json:"-" gorm:"index"`
}

// Validate checks if the compose service is valid
func (cs *ComposeService) Validate() error {
	validate.RegisterValidation("alphanumdash", ValidateAlphaNumDash)
	validate.RegisterValidation("containerStatus", ValidateContainerStatus)
	return validate.Struct(cs)
}

// SanitizeServiceEnvVars redacts sensitive environment variables for a service
func (cs *ComposeService) SanitizeServiceEnvVars() {
	redactedEnv := make(StringArray, len(cs.Environment))
	for i, envVar := range cs.Environment {
		if isSensitiveEnvVar(envVar) {
			parts := strings.SplitN(envVar, "=", 2)
			if len(parts) == 2 {
				redactedEnv[i] = parts[0] + "=*****"
			} else {
				redactedEnv[i] = envVar // Keep as is if format is unexpected
			}
		} else {
			redactedEnv[i] = envVar
		}
	}
	cs.Environment = redactedEnv
}

// DockerHost represents a connection to a Docker host
type DockerHost struct {
	ID            uint           `json:"id" gorm:"primaryKey"`
	Name          string         `json:"name" gorm:"uniqueIndex;size:255" validate:"required,max=255,alphanumdash"`
	Host          string         `json:"host" validate:"required"` // e.g., "unix:///var/run/docker_test.sock" or "tcp://192.168.1.100:2376"
	TLSEnabled    bool           `json:"tls_enabled"`
	TLSCertPath   string         `json:"tls_cert_path" validate:"omitempty,filepath"`
	TLSKeyPath    string         `json:"tls_key_path" validate:"omitempty,filepath"`
	TLSCACertPath string         `json:"tls_ca_cert_path" validate:"omitempty,filepath"`
	TLSVerify     bool           `json:"tls_verify"`
	Username      string         `json:"username" validate:"omitempty,max=255"`
	Password      string         `json:"-" validate:"omitempty"` // Store securely, don't expose in JSON
	RegistryToken string         `json:"-" validate:"omitempty"` // Store securely
	Status        string         `json:"status" gorm:"size:64" validate:"max=64"`
	LastChecked   time.Time      `json:"last_checked"`
	Version       string         `json:"version" gorm:"size:64" validate:"max=64"`
	APIVersion    string         `json:"api_version" gorm:"size:64" validate:"max=64"`
	Default       bool           `json:"default" gorm:"index"`
	Notes         string         `json:"notes" gorm:"type:text" validate:"max=5000"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `json:"-" gorm:"index"`
}

// Validate checks if the Docker host configuration is valid
func (dh *DockerHost) Validate() error {
	validate.RegisterValidation("alphanumdash", ValidateAlphaNumDash)
	return validate.Struct(dh)
}

// SanitizeHostCredentials clears sensitive credential fields
func (dh *DockerHost) SanitizeHostCredentials() {
	dh.Password = ""
	dh.RegistryToken = ""
}

// DockerEvent represents a Docker event stored in the database
type DockerEvent struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Type         string    `json:"type" gorm:"index;size:64" validate:"required,max=64"`
	Action       string    `json:"action" gorm:"index;size:64" validate:"required,max=64"`
	Actor        string    `json:"actor" gorm:"index;size:64" validate:"required,max=64"` // Usually container ID
	ActorID      string    `json:"actor_id" gorm:"index;size:64" validate:"required,max=64"`
	Attributes   JSONMap   `json:"attributes" gorm:"type:text"`
	Scope        string    `json:"scope" gorm:"index;size:64" validate:"max=64"`
	Timestamp    time.Time `json:"timestamp" gorm:"index"`
	TimeNano     int64     `json:"time_nano"`
	HostID       uint      `json:"host_id" gorm:"index"` // Link to DockerHost if managing multiple hosts
	HostName     string    `json:"host_name" gorm:"size:255"`
	Acknowledged bool      `json:"acknowledged" gorm:"index;default:false"`
	CreatedAt    time.Time `json:"created_at"`
}

// Validate checks if the Docker event is valid
func (de *DockerEvent) Validate() error {
	return validate.Struct(de)
}

// FromDockerContainerJSON converts a types.ContainerJSON to our internal Container model
// It attempts to populate as many fields as possible.
func FromDockerContainerJSON(containerJSON *types.ContainerJSON) *Container { // Accept pointer
	if containerJSON == nil {
		return nil
	}

	// Basic info
	c := &Container{
		ContainerID:   containerJSON.ID,
		ImageID:       containerJSON.Image,
		Command:       strings.Join(append(containerJSON.Config.Entrypoint, containerJSON.Config.Cmd...), " "),
		Entrypoint:    containerJSON.Config.Entrypoint,
		WorkingDir:    containerJSON.Config.WorkingDir,
		User:          containerJSON.Config.User,
		EnvVars:       containerJSON.Config.Env,
		ExposedPorts:  make([]string, 0, len(containerJSON.Config.ExposedPorts)),
		Platform:      containerJSON.Platform,
		LastInspected: time.Now(),
		// CreatedAt: // This should be set when the record is created in DB
	}
	c.DockerResource.Labels = make(JSONMap) // Initialize map

	// Use the first name if available, removing the leading slash
	if len(containerJSON.Name) > 0 {
		c.Name = strings.TrimPrefix(containerJSON.Name, "/")
	} else {
		c.Name = c.ContainerID[:12] // Fallback to short ID if name is empty
	}
	c.DockerResource.Name = c.Name // Sync with DockerResource name

	// Status and State
	if containerJSON.State != nil {
		c.Status = ContainerStatus(containerJSON.State.Status)
		c.State = containerJSON.State.Status // Keep raw state too
		c.ExitCode = containerJSON.State.ExitCode
		c.Running = containerJSON.State.Running
		c.Paused = containerJSON.State.Paused
		c.Restarting = containerJSON.State.Restarting
		c.OOMKilled = containerJSON.State.OOMKilled
		c.Dead = containerJSON.State.Dead
		c.StartedAt, _ = time.Parse(time.RFC3339Nano, containerJSON.State.StartedAt)
		c.FinishedAt, _ = time.Parse(time.RFC3339Nano, containerJSON.State.FinishedAt)
		if c.Running && !c.StartedAt.IsZero() {
			c.UpTime = time.Since(c.StartedAt).Round(time.Second).String()
		}
		// Health status
		if containerJSON.State.Health != nil {
			c.Health = containerJSON.State.Health.Status
			// Basic log formatting, might need improvement
			var healthLogs []string
			for _, log := range containerJSON.State.Health.Log {
				healthLogs = append(healthLogs, fmt.Sprintf("%s: Exit %d - %s", log.Start.Format(time.RFC3339), log.ExitCode, log.Output))
			}
			c.HealthLog = strings.Join(healthLogs, "\n")
		}
	} else {
		c.Status = ContainerStatusUnknown
		c.State = "unknown"
	}
	c.Status = FormatContainerStatus(c.State, c.Health) // Format combined status

	// Image Name (best effort)
	c.Image = containerJSON.Config.Image // This is usually the name used to create

	// Labels
	if containerJSON.Config.Labels != nil {
		for k, v := range containerJSON.Config.Labels {
			c.DockerResource.Labels[k] = v // Assign to embedded struct's field
		}
	}

	// Ports
	c.Ports = make(JSONMap)
	if containerJSON.NetworkSettings != nil && containerJSON.NetworkSettings.Ports != nil {
		portMappings := []PortMapping{}
		for containerPortProto, hostBindings := range containerJSON.NetworkSettings.Ports {
			parts := strings.SplitN(string(containerPortProto), "/", 2)
			containerPort := parts[0]
			proto := "tcp" // Default
			if len(parts) == 2 {
				proto = parts[1]
			}
			if hostBindings != nil {
				for _, binding := range hostBindings {
					portMappings = append(portMappings, PortMapping{
						HostIP:        binding.HostIP,
						HostPort:      binding.HostPort,
						ContainerPort: containerPort,
						Type:          proto,
					})
				}
			} else {
				// Exposed but not published
				portMappings = append(portMappings, PortMapping{
					ContainerPort: containerPort,
					Type:          proto,
				})
			}
		}
		c.Ports["mappings"] = portMappings // Store as a structured list
	}
	for port := range containerJSON.Config.ExposedPorts {
		c.ExposedPorts = append(c.ExposedPorts, string(port))
	}

	// Networks
	c.Networks = make(JSONMap)
	c.DetailedNetworkInfo = make(map[string]DetailedNetwork)
	if containerJSON.NetworkSettings != nil && containerJSON.NetworkSettings.Networks != nil {
		networkInfo := make(map[string]map[string]string)
		for name, settings := range containerJSON.NetworkSettings.Networks {
			info := map[string]string{
				"NetworkID":   settings.NetworkID,
				"EndpointID":  settings.EndpointID,
				"Gateway":     settings.Gateway,
				"IPAddress":   settings.IPAddress,
				"IPPrefixLen": fmt.Sprintf("%d", settings.IPPrefixLen),
				"IPv6Gateway": settings.IPv6Gateway,
				"GlobalIPv6":  settings.GlobalIPv6Address,
				"MacAddress":  settings.MacAddress,
			}
			networkInfo[name] = info
			// Populate DetailedNetworkInfo (assuming Network details are fetched separately)
			// This part requires fetching network details using settings.NetworkID
			// For now, just store basic connection info
			c.DetailedNetworkInfo[name] = DetailedNetwork{
				Name: name,
				ID:   settings.NetworkID,
				// Driver, Scope, etc., would come from a NetworkInspect call
			}
			if settings.IPAddress != "" {
				c.IPAddress = settings.IPAddress // Store primary IP if available
			}
		}
		c.Networks["connections"] = networkInfo
	}

	// Volumes / Mounts
	c.Volumes = make(JSONMap)
	c.DetailedVolumeInfo = make(map[string]DetailedVolume)
	c.Mounts = make([]MountPoint, len(containerJSON.Mounts))
	if containerJSON.Mounts != nil {
		mountInfo := make(map[string]map[string]interface{})
		for i, mount := range containerJSON.Mounts {
			info := map[string]interface{}{
				"Type":        string(mount.Type),
				"Name":        mount.Name,
				"Source":      mount.Source,
				"Destination": mount.Destination,
				"Driver":      mount.Driver,
				"Mode":        mount.Mode,
				"RW":          mount.RW,
				"Propagation": string(mount.Propagation),
			}
			mountInfo[mount.Destination] = info // Use destination as key
			c.Mounts[i] = MountPoint{
				Type:        string(mount.Type),
				Name:        mount.Name,
				Source:      mount.Source,
				Destination: mount.Destination,
				Mode:        mount.Mode,
				RW:          mount.RW,
				Propagation: string(mount.Propagation),
			}
			// Populate DetailedVolumeInfo (requires fetching volume details)
			if mount.Type == "volume" && mount.Name != "" {
				c.DetailedVolumeInfo[mount.Name] = DetailedVolume{
					Name: mount.Name,
					// Driver, Mountpoint, etc., would come from VolumeInspect
				}
			}
		}
		c.Volumes["mounts"] = mountInfo
	}

	// Host Config
	if containerJSON.HostConfig != nil {
		c.RestartPolicy = RestartPolicy(containerJSON.HostConfig.RestartPolicy.Name)
		// Add max retries if needed: containerJSON.HostConfig.RestartPolicy.MaximumRetryCount
		c.NetworkMode = NetworkMode(containerJSON.HostConfig.NetworkMode)
		c.Privileged = containerJSON.HostConfig.Privileged
		c.AutoRemove = containerJSON.HostConfig.AutoRemove
		c.ReadOnly = containerJSON.HostConfig.ReadonlyRootfs
		c.HostIPC = containerJSON.HostConfig.IpcMode.IsHost()
		c.HostPID = containerJSON.HostConfig.PidMode.IsHost()
		c.CapAdd = StringArray(containerJSON.HostConfig.CapAdd)   // Convert strslice.StrSlice to StringArray
		c.CapDrop = StringArray(containerJSON.HostConfig.CapDrop) // Convert strslice.StrSlice to StringArray
		c.UsernsMode = string(containerJSON.HostConfig.UsernsMode)
		c.SecurityOptions = containerJSON.HostConfig.SecurityOpt

		// Resources
		c.ResourceLimits = ResourceLimits{
			Memory:            containerJSON.HostConfig.Memory,
			MemorySwap:        containerJSON.HostConfig.MemorySwap,
			MemoryReservation: containerJSON.HostConfig.MemoryReservation,
			CPUShares:         containerJSON.HostConfig.CPUShares,
			CPUPeriod:         containerJSON.HostConfig.CPUPeriod,
			CPUQuota:          containerJSON.HostConfig.CPUQuota,
			CpusetCpus:        containerJSON.HostConfig.CpusetCpus,
			CpusetMems:        containerJSON.HostConfig.CpusetMems,
			PidsLimit:         derefInt64Ptr(containerJSON.HostConfig.PidsLimit), // Handle potential nil pointer
			BlkioWeight:       containerJSON.HostConfig.BlkioWeight,
		}
		c.Resources = map[string]interface{}{ // Store as JSONMap
			"memory_limit":       c.ResourceLimits.Memory,
			"memory_swap":        c.ResourceLimits.MemorySwap,
			"memory_reservation": c.ResourceLimits.MemoryReservation,
			"cpu_shares":         c.ResourceLimits.CPUShares,
			"cpu_period":         c.ResourceLimits.CPUPeriod,
			"cpu_quota":          c.ResourceLimits.CPUQuota,
			"cpuset_cpus":        c.ResourceLimits.CpusetCpus,
			"cpuset_mems":        c.ResourceLimits.CpusetMems,
			"pids_limit":         c.ResourceLimits.PidsLimit,
			"blkio_weight":       c.ResourceLimits.BlkioWeight,
		}

		// Security Info
		c.SecurityInfo = SecurityInfo{
			Privileged:     c.Privileged,
			ReadOnlyRootfs: c.ReadOnly,
			CapAdd:         c.CapAdd,
			CapDrop:        c.CapDrop,
			SecurityOpt:    c.SecurityOptions,
			NetworkMode:    string(c.NetworkMode),
			PidMode:        string(containerJSON.HostConfig.PidMode),
			IpcMode:        string(containerJSON.HostConfig.IpcMode),
			UTSMode:        string(containerJSON.HostConfig.UTSMode),
			UsernsMode:     c.UsernsMode,
			// SensitiveMounts needs logic to determine sensitivity
		}
	}

	// Healthcheck
	if containerJSON.Config.Healthcheck != nil {
		c.Healthcheck = map[string]interface{}{
			"test":        containerJSON.Config.Healthcheck.Test,
			"interval":    containerJSON.Config.Healthcheck.Interval.String(),
			"timeout":     containerJSON.Config.Healthcheck.Timeout.String(),
			"retries":     containerJSON.Config.Healthcheck.Retries,
			"startPeriod": containerJSON.Config.Healthcheck.StartPeriod.String(),
		}
	}

	// Restart Count
	c.RestartCount = containerJSON.RestartCount

	// Sanitize sensitive data before returning
	c.SanitizeSecurityFields()

	return c
}

// Helper to dereference *int64 safely
func derefInt64Ptr(ptr *int64) int64 {
	if ptr == nil {
		return 0 // Or handle as appropriate, e.g., -1 for unlimited
	}
	return *ptr
}

// init registers custom validators
func init() {
	if validate != nil {
		_ = validate.RegisterValidation("containerStatus", ValidateContainerStatus)
		_ = validate.RegisterValidation("restartPolicy", ValidateRestartPolicy)
		_ = validate.RegisterValidation("networkMode", ValidateNetworkMode)
		_ = validate.RegisterValidation("alphanumdash", ValidateAlphaNumDash)
		_ = validate.RegisterValidation("cidr", validateCIDR)
	}
}

// validateComposeDeployment performs custom validation for ComposeDeployment
func validateComposeDeployment(sl validator.StructLevel) {
	// deployment := sl.Current().Interface().(ComposeDeployment)
	// Add custom validation logic here if needed
}

// validateContainer performs custom validation for Container
func validateContainer(sl validator.StructLevel) {
	// container := sl.Current().Interface().(Container)
	// Add custom validation logic here if needed
}

// validateNetwork performs custom validation for Network
func validateNetwork(sl validator.StructLevel) {
	network := sl.Current().Interface().(Network)
	if err := network.ValidateNetworkAddressing(); err != nil {
		// Report error to validator
		sl.ReportError(network.Subnet, "Subnet", "Subnet", "networkAddressing", "")
		sl.ReportError(network.Gateway, "Gateway", "Gateway", "networkAddressing", "")
		sl.ReportError(network.IPRange, "IPRange", "IPRange", "networkAddressing", "")
		// Add more specific field reporting if possible based on err content
	}
}

// validateCIDR validates if a string is a valid CIDR notation
func validateCIDR(fl validator.FieldLevel) bool {
	cidr := fl.Field().String()
	if cidr == "" {
		return true // Allow empty if not required
	}
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// RedactSensitiveData recursively redacts sensitive keys in a map
func RedactSensitiveData(data map[string]interface{}, sensitiveKeys ...string) map[string]interface{} {
	redactedData := make(map[string]interface{})
	sensitiveSet := make(map[string]bool)
	for _, key := range sensitiveKeys {
		sensitiveSet[strings.ToLower(key)] = true
	}

	for key, value := range data {
		lowerKey := strings.ToLower(key)
		if sensitiveSet[lowerKey] {
			redactedData[key] = "*****"
		} else {
			switch v := value.(type) {
			case map[string]interface{}:
				redactedData[key] = RedactSensitiveData(v, sensitiveKeys...)
			case []interface{}:
				redactedSlice := make([]interface{}, len(v))
				for i, item := range v {
					if itemMap, ok := item.(map[string]interface{}); ok {
						redactedSlice[i] = RedactSensitiveData(itemMap, sensitiveKeys...)
					} else {
						redactedSlice[i] = item // Keep non-map items as is
					}
				}
				redactedData[key] = redactedSlice
			default:
				redactedData[key] = value
			}
		}
	}
	return redactedData
}

// formatContainerStatus combines state and health into a single status string
// FormatContainerStatus determines a more specific status based on state and health.
func FormatContainerStatus(state, health string) ContainerStatus {
	if state == "running" {
		if health != "" {
			// Use regex to extract status from health string like "starting", "healthy", "unhealthy"
			re := regexp.MustCompile(`\((.*?)\)`)
			match := re.FindStringSubmatch(health)
			if len(match) > 1 {
				// Check if the extracted status is valid before returning
				extractedStatus := ContainerStatus(match[1])
				if IsValidContainerStatus(extractedStatus) {
					return extractedStatus // e.g., "healthy"
				}
			}
			// Fallback if regex fails or extracted status is invalid
			if strings.Contains(health, "healthy") {
				return "healthy"
			}
			if strings.Contains(health, "unhealthy") {
				return "unhealthy"
			}
			if strings.Contains(health, "starting") {
				return "starting"
			}
		}
		return ContainerStatusRunning // Default running status if health is unknown/empty
	}
	// For non-running states, return the state as ContainerStatus
	status := ContainerStatus(state)
	if IsValidContainerStatus(status) {
		return status
	}
	// Handle cases like "exited (0)"
	if strings.HasPrefix(state, "exited (") {
		return ContainerStatusExited
	}
	return ContainerStatusUnknown // Default to unknown if state is not recognized
}

// FromDockerStatsJSON converts Docker stats JSON to our internal ContainerStats model
// Note: The input type is now *container.Stats as provided by the Docker SDK stream
func FromDockerStatsJSON(v *container.Stats) *ContainerStats {
	if v == nil {
		return nil
	}

	stats := &ContainerStats{
		Time:           v.Read,
		CPUUsage:       v.CPUStats.CPUUsage.TotalUsage,
		SystemCPUUsage: v.CPUStats.SystemUsage,
		OnlineCPUs:     v.CPUStats.OnlineCPUs, // Use OnlineCPUs if available
		MemoryUsage:    v.MemoryStats.Usage,
		MemoryLimit:    v.MemoryStats.Limit,
		PIDs:           v.PidsStats.Current,
	}

	// Calculate CPU Percentage
	if stats.SystemCPUUsage > 0 && v.PreCPUStats.SystemUsage > 0 && stats.OnlineCPUs > 0 {
		cpuDelta := float64(stats.CPUUsage - v.PreCPUStats.CPUUsage.TotalUsage)
		systemDelta := float64(stats.SystemCPUUsage - v.PreCPUStats.SystemUsage)
		stats.CPUPercentage = (cpuDelta / systemDelta) * float64(stats.OnlineCPUs) * 100.0
	}

	// Calculate Memory Percentage
	if stats.MemoryLimit > 0 {
		stats.MemoryPercentage = (float64(stats.MemoryUsage) / float64(stats.MemoryLimit)) * 100.0
	}

	// Network Stats (sum across all networks)
	for _, netStat := range v.Networks {
		stats.NetworkRx += int64(netStat.RxBytes)
		stats.NetworkTx += int64(netStat.TxBytes)
	}

	// Block IO Stats (sum across all devices)
	for _, bioStat := range v.BlkioStats.IoServiceBytesRecursive {
		switch strings.ToLower(bioStat.Op) {
		case "read":
			stats.BlockRead += int64(bioStat.Value)
		case "write":
			stats.BlockWrite += int64(bioStat.Value)
		}
	}

	return stats
}
