// Package compose provides functionality for Docker Compose operations
package compose

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath" // Keep for Abs path
	"strings"

	"github.com/compose-spec/compose-go/v2/loader"
	composetypes "github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/mount" // Needed for conversion
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

const defaultComposeProjectName = "default_dsm_project"

// Helper function to get environment variables for compose-go loader,
// ensuring COMPOSE_PROJECT_NAME is set.
func getEnvironment() map[string]string {
	env := map[string]string{}
	foundProjectName := false
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		key := pair[0]
		value := ""
		if len(pair) == 2 {
			value = pair[1]
		}
		env[key] = value
		if key == "COMPOSE_PROJECT_NAME" && value != "" {
			foundProjectName = true
		}
	}
	// If COMPOSE_PROJECT_NAME is not set in the environment, add a default one.
	if !foundProjectName {
		env["COMPOSE_PROJECT_NAME"] = defaultComposeProjectName
	}
	return env
}

// Parser handles parsing and validation of Docker Compose files
type Parser struct {
	logger *logrus.Logger
}

// NewParser creates a new Parser
func NewParser(logger *logrus.Logger) *Parser {
	if logger == nil {
		logger = logrus.New()
	}
	return &Parser{logger: logger}
}

// Parse reads and parses a Docker Compose configuration from an io.Reader using compose-go
func (p *Parser) Parse(ctx context.Context,
	reader io.Reader,
	options models.ParseOptions) (*models.ComposeFile, error) {
	p.logger.Debug("Parsing Docker Compose configuration using compose-go library (direct content)")
	// Read content directly
	content, err := io.ReadAll(reader) // Use io.ReadAll
	if err != nil {
		return nil, fmt.Errorf("failed to read compose configuration: %w", err)
	}
	p.logger.Debugf("Read compose content (%d bytes)", len(content))

	// Determine the logical working directory (for resolving paths inside the compose file)
	// IMPORTANT: This should be the directory context intended by the user,
	// potentially passed via options, NOT the tempDir.
	workingDir := options.WorkingDir
	if workingDir == "" {
		wd, err := os.Getwd() // Fallback to current working dir of the server process
		if err != nil {
			p.logger.WithError(err).Warn("Failed to get current working directory, using '.'")
			workingDir = "."
		} else {
			workingDir = wd
		}
	}
	absWorkingDir, err := filepath.Abs(workingDir)
	if err != nil {
		p.logger.WithError(err).Warnf(
			"Failed to get absolute path for working directory '%s', using it as is", workingDir)
		absWorkingDir = workingDir // Use original if Abs fails
	}
	p.logger.Debugf("Using working directory for compose loader: %s", absWorkingDir) // Added log
	p.logger.Debugf("Using working directory for compose loader: %s", absWorkingDir)

	// environment := getEnvironment() // Don't use OS environment for direct content parsing
	environment := make(map[string]string) // Use empty environment map

	// Create ConfigDetails using the content directly
	configDetails := composetypes.ConfigDetails{
		WorkingDir: absWorkingDir, // Use original absolute workingDir for context
		ConfigFiles: []composetypes.ConfigFile{
			{
				Filename: "docker-compose.yml", // Provide nominal filename for context
				Content:  content,              // Pass content directly
			},
		},
		Environment: environment, // Pass the (now empty) environment map
	}

	// Determine project name: prioritize options, then environment/default
	projectName := options.ProjectName
	if projectName == "" {
		projectName = environment["COMPOSE_PROJECT_NAME"] // Fallback to environment/default
		p.logger.Debugf("Project name not provided in options, using from environment/default: %s", projectName)
	} else {
		p.logger.Debugf("Using project name provided in options: %s", projectName)
		// Remove from environment map to avoid potential conflicts with SetProjectName option
		// delete(environment, "COMPOSE_PROJECT_NAME") // Keep env map intact for now
	}
	// Ensure projectName is never empty before passing to SetProjectName
	if projectName == "" {
		p.logger.Warnf("Project name is empty after checking options and environment, using default: %s", defaultComposeProjectName)
		projectName = defaultComposeProjectName
		// Also ensure the environment map used by ConfigDetails has it if we defaulted
		if _, ok := environment["COMPOSE_PROJECT_NAME"]; !ok {
			environment["COMPOSE_PROJECT_NAME"] = projectName
		}
	}
	p.logger.Debugf("Using project name for compose loader options: %s", projectName)
	// Log ConfigDetails before loading
	p.logger.Debugf("ConfigDetails passed to loader: WorkingDir='%s', ConfigFile='%s'", configDetails.WorkingDir, configDetails.ConfigFiles[0].Filename)
	p.logger.Debugf("Calling loader.LoadWithContext with ProjectName='%s'", projectName) // Log project name right before call

	// Use loader.LoadWithContext, providing ConfigDetails and setting options via function literal
	project, err := loader.LoadWithContext(ctx, configDetails, func(o *loader.Options) {
		o.SetProjectName(projectName, true) // Explicitly set project name, override env
		o.SkipValidation = false            // Ensure validation runs
		o.ResolvePaths = true               // Ensure path resolution is enabled
		// OS Env vars are loaded by default and overridden by ConfigDetails.Environment
	})

	if err != nil {
		p.logger.WithError(err).Errorf("Failed to load/parse compose configuration using compose-go (WorkingDir: %s, ProjectNameOpt: %s)", configDetails.WorkingDir, projectName)
		// Try to provide more specific YAML error info if possible
		if strings.Contains(err.Error(), "yaml:") {
			return nil, fmt.Errorf("failed to parse compose YAML structure: %w (check indentation/syntax)", err)
		}
		return nil, fmt.Errorf("failed to load compose config: %w", err)
	}

	p.logger.Infof("Successfully loaded and validated compose configuration using compose-go for project: %s", project.Name)

	// Convert the loaded compose-go project to our internal model
	internalModel, err := convertProjectToInternalModel(project)
	if err != nil {
		p.logger.WithError(err).Error("Failed to convert compose-go project to internal model")
		return nil, fmt.Errorf("failed to convert loaded project: %w", err)
	}

	// Basic validation after conversion (compose-go loader handles schema validation)
	if err := p.validate(internalModel); err != nil {
		return nil, fmt.Errorf("internal model validation failed: %w", err)
	}

	return internalModel, nil
}

// validate performs minimal checks after compose-go loading
func (p *Parser) validate(composeFile *models.ComposeFile) error {
	if composeFile == nil {
		return errors.New("compose file model is nil")
	}
	if len(composeFile.Services) == 0 {
		p.logger.Debug("Compose file has no services defined.")
	}
	p.logger.Debug("Internal model validation successful")
	return nil
}

// SanitizeProjectName removes potentially invalid characters for a Docker project name
func SanitizeProjectName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "-", "_")
	return name
}

// convertProjectToInternalModel converts a compose-go project to our internal model
// It handles the conversion of services, networks, volumes, secrets, and configs
// to their respective internal representations.
// It also sets the project name and version if available.
// Note: The project.Version is not directly available in the Project struct,
// but we can set it in the internal model if needed.
// This function is responsible for converting the entire project structure
// and returning the fully populated internal model.
// It returns an error if any conversion fails.
// Note: The project.Version is not directly available in the Project struct,
// but we can set it in the internal model if needed.
func convertProjectToInternalModel(project *composetypes.Project) (*models.ComposeFile, error) {
	if project == nil {
		return nil, errors.New("cannot convert nil project")
	}
	model := &models.ComposeFile{
		Services:   make(map[string]models.ServiceConfig),
		Networks:   make(map[string]models.NetworkConfig),
		Volumes:    make(map[string]models.VolumeConfig),
		Secrets:    make(map[string]models.SecretConfig),
		Configs:    make(map[string]models.ConfigConfig),
		Extensions: project.Extensions,
		// Version:    project.Version, // Project struct doesn't have Version
	}
	for _, service := range project.Services {
		internalService, err := convertServiceToInternalModel(service)
		if err != nil {
			return nil, fmt.Errorf("failed to convert service '%s': %w", service.Name, err)
		}
		model.Services[service.Name] = *internalService
	}
	for name, network := range project.Networks {
		internalNetwork, err := convertNetworkToInternalModel(network)
		if err != nil {
			return nil, fmt.Errorf("failed to convert network '%s': %w", name, err)
		}
		internalNetwork.Name = name
		model.Networks[name] = *internalNetwork
	}
	for name, volume := range project.Volumes {
		internalVolume, err := convertVolumeToInternalModel(volume)
		if err != nil {
			return nil, fmt.Errorf("failed to convert volume '%s': %w", name, err)
		}
		internalVolume.Name = name
		model.Volumes[name] = *internalVolume
	}
	for name, secret := range project.Secrets {
		internalSecret, err := convertSecretToInternalModel(secret)
		if err != nil {
			return nil, fmt.Errorf("failed to convert secret '%s': %w", name, err)
		}
		internalSecret.Name = name
		model.Secrets[name] = *internalSecret
	}
	for name, config := range project.Configs {
		internalConfig, err := convertConfigToInternalModel(config)
		if err != nil {
			return nil, fmt.Errorf("failed to convert config '%s': %w", name, err)
		}
		internalConfig.Name = name
		model.Configs[name] = *internalConfig
	}
	return model, nil
}

func convertServiceToInternalModel(service composetypes.ServiceConfig) (*models.ServiceConfig, error) {
	internal := &models.ServiceConfig{
		Name:        service.Name,
		Image:       service.Image,
		NetworkMode: service.NetworkMode,
		Restart:     service.Restart,
		Extensions:  service.Extensions,
		Build:       convertBuildConfig(service.Build),
		Command:     service.Command,                         // Assign directly ([]string is compatible with interface{})
		Environment: convertEnvironment(service.Environment), // Keep as interface{}
		EnvFile:     convertEnvFiles(service.EnvFiles),       // Keep as interface{}
		Ports:       convertPorts(service.Ports),
		Expose:      convertStringListToInterfaceList(service.Expose),
		VolumesFrom: service.VolumesFrom,
		Networks:    convertServiceNetworks(service.Networks), // Keep as interface{}
		DependsOn:   convertDependsOn(service.DependsOn),      // Keep as interface{}
		HealthCheck: convertHealthCheck(service.HealthCheck),
		Deploy:      convertDeployConfig(service.Deploy),
		Labels:      convertStringMapToInterface(service.Labels), // Keep as interface{}
	}
	// Convert Volumes and handle potential error
	volumesMounts, err := convertVolumes(service.Volumes)
	if err != nil {
		return nil, fmt.Errorf("failed converting volumes for service %s: %w", service.Name, err)
	}
	// Convert []mount.Mount to []interface{} for the model
	volumesInterface := make([]interface{}, len(volumesMounts))
	for i, m := range volumesMounts {
		// Convert mount.Mount back to a string or map representation suitable for models.ServiceConfig.Volumes
		if m.Type == mount.TypeBind || m.Type == mount.TypeVolume {
			volStr := m.Source + ":" + m.Target
			if m.ReadOnly {
				volStr += ":ro"
			}
			volumesInterface[i] = volStr
		} else {
			volMap := map[string]interface{}{
				"type":      string(m.Type),
				"source":    m.Source,
				"target":    m.Target,
				"read_only": m.ReadOnly,
			}
			volumesInterface[i] = volMap
		}
	}
	internal.Volumes = volumesInterface // Assign []interface{}
	return internal, nil
}

func convertBuildConfig(build *composetypes.BuildConfig) interface{} {
	if build == nil {
		return nil
	}
	buildMap := make(map[string]interface{})
	buildMap["context"] = build.Context
	if build.Dockerfile != "" {
		buildMap["dockerfile"] = build.Dockerfile
	}
	if len(build.Args) > 0 {
		buildMap["args"] = build.Args
	}
	// Return map or just context string if simple
	if len(buildMap) == 1 && build.Context != "" && build.Dockerfile == "" && len(build.Args) == 0 {
		return build.Context
	}
	return buildMap
}

func convertEnvironment(env composetypes.MappingWithEquals) interface{} {
	// Return as map[string]interface{} to better match model's interface{}
	if len(env) == 0 {
		return nil
	}
	envMap := make(map[string]interface{}, len(env))
	for k, v := range env {
		if v == nil {
			envMap[k] = nil // Represent null value explicitly
		} else {
			envMap[k] = *v
		}
	}
	return envMap // Return map instead of list of strings
}

// convertStringOrList removed as it's no longer needed

func convertEnvFiles(envFiles []composetypes.EnvFile) interface{} {
	if len(envFiles) == 0 {
		return nil
	}
	if len(envFiles) == 1 {
		return envFiles[0].Path
	} // Return string if only one
	result := make([]string, len(envFiles))
	for i, ef := range envFiles {
		result[i] = ef.Path
	}
	return result // Return slice if multiple
}

func convertPorts(ports []composetypes.ServicePortConfig) []interface{} {
	result := make([]interface{}, len(ports))
	for i, p := range ports {
		spec := ""
		if p.Published != "" && p.Published != "0" {
			spec += p.Published + ":"
		}
		spec += fmt.Sprintf("%d", p.Target)
		if p.Protocol != "" && p.Protocol != "tcp" {
			spec += "/" + p.Protocol
		}
		result[i] = spec
	}
	return result
}

func convertStringListToInterfaceList(list []string) []interface{} {
	result := make([]interface{}, len(list))
	for i, s := range list {
		result[i] = s
	}
	return result
}

// convertVolumes converts compose-go volume definitions to Docker mount types
func convertVolumes(volumes []composetypes.ServiceVolumeConfig) ([]mount.Mount, error) {
	mounts := []mount.Mount{}
	for _, v := range volumes {
		mnt := mount.Mount{
			Type:     mount.Type(v.Type),
			Source:   v.Source,
			Target:   v.Target,
			ReadOnly: v.ReadOnly,
		}
		if v.Bind != nil {
			mnt.BindOptions = &mount.BindOptions{
				Propagation: mount.Propagation(v.Bind.Propagation),
			}
			if v.Bind.CreateHostPath {
				logrus.Warnf("Volume bind option 'create_host_path' for target '%s' is not fully handled.", v.Target)
			}
		}
		if v.Volume != nil {
			mnt.VolumeOptions = &mount.VolumeOptions{
				NoCopy: v.Volume.NoCopy,
			}
		}
		if v.Tmpfs != nil {
			mnt.TmpfsOptions = &mount.TmpfsOptions{
				SizeBytes: int64(v.Tmpfs.Size), // Cast UnitBytes to int64
			}
		}
		mounts = append(mounts, mnt)
	}
	return mounts, nil
}

func convertServiceNetworks(networks map[string]*composetypes.ServiceNetworkConfig) interface{} {
	if len(networks) == 0 {
		return nil
	}
	result := make(map[string]interface{})
	for name, config := range networks {
		if config == nil {
			result[name] = nil
		} else {
			netMap := make(map[string]interface{})
			if len(config.Aliases) > 0 {
				netMap["aliases"] = config.Aliases
			}
			if config.Ipv4Address != "" {
				netMap["ipv4_address"] = config.Ipv4Address
			}
			if config.Ipv6Address != "" {
				netMap["ipv6_address"] = config.Ipv6Address
			}
			result[name] = netMap
		}
	}
	return result
}

func convertDependsOn(depends map[string]composetypes.ServiceDependency) interface{} {
	if len(depends) == 0 {
		return nil
	}
	list := make([]string, 0, len(depends))
	mapForm := make(map[string]interface{})
	isMap := false
	for name, dep := range depends {
		list = append(list, name)
		if dep.Condition != "" || dep.Restart || dep.Required {
			isMap = true
			depMap := make(map[string]interface{})
			if dep.Condition != "" {
				depMap["condition"] = dep.Condition
			}
			if dep.Restart {
				depMap["restart"] = true
			}
			mapForm[name] = depMap
		}
	}
	if isMap {
		return mapForm
	}
	return list
}

func convertHealthCheck(hc *composetypes.HealthCheckConfig) map[string]interface{} {
	if hc == nil {
		return nil
	}
	hcMap := make(map[string]interface{})
	if len(hc.Test) > 0 {
		hcMap["test"] = hc.Test
	}
	if hc.Interval != nil {
		hcMap["interval"] = hc.Interval.String()
	}
	if hc.Timeout != nil {
		hcMap["timeout"] = hc.Timeout.String()
	}
	if hc.Retries != nil {
		hcMap["retries"] = *hc.Retries
	}
	if hc.StartPeriod != nil {
		hcMap["start_period"] = hc.StartPeriod.String()
	}
	if hc.StartInterval != nil {
		hcMap["start_interval"] = hc.StartInterval.String()
	}
	if hc.Disable {
		hcMap["disable"] = true
	}
	return hcMap
}

func convertDeployConfig(deploy *composetypes.DeployConfig) map[string]interface{} {
	if deploy == nil {
		return nil
	}
	deployMap := make(map[string]interface{})
	if deploy.Mode != "" {
		deployMap["mode"] = deploy.Mode
	}
	if deploy.Replicas != nil {
		deployMap["replicas"] = *deploy.Replicas
	}
	if deploy.Resources.Limits != nil {
		limitsMap := make(map[string]interface{})
		if deploy.Resources.Limits.NanoCPUs != 0.0 {
			limitsMap["cpus"] = deploy.Resources.Limits.NanoCPUs
		}
		if deploy.Resources.Limits.MemoryBytes > 0 {
			limitsMap["memory"] = fmt.Sprintf("%dB", deploy.Resources.Limits.MemoryBytes)
		}
		if len(limitsMap) > 0 {
			if resMap, ok := deployMap["resources"].(map[string]interface{}); ok {
				resMap["limits"] = limitsMap
			} else {
				deployMap["resources"] = map[string]interface{}{"limits": limitsMap}
			}
		}
	}
	if deploy.Resources.Reservations != nil {
		reservationsMap := make(map[string]interface{})
		if deploy.Resources.Reservations.NanoCPUs != 0.0 {
			reservationsMap["cpus"] = deploy.Resources.Reservations.NanoCPUs
		}
		if deploy.Resources.Reservations.MemoryBytes > 0 {
			reservationsMap["memory"] = fmt.Sprintf("%dB", deploy.Resources.Reservations.MemoryBytes)
		}
		if len(reservationsMap) > 0 {
			if resMap, ok := deployMap["resources"].(map[string]interface{}); ok {
				resMap["reservations"] = reservationsMap
			} else {
				deployMap["resources"] = map[string]interface{}{"reservations": reservationsMap}
			}
		}
	}
	return deployMap
}

func convertStringMapToInterface(m map[string]string) interface{} {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

func convertNetworkToInternalModel(network composetypes.NetworkConfig) (*models.NetworkConfig, error) {
	internal := &models.NetworkConfig{
		Name:       network.Name,
		Driver:     network.Driver,
		DriverOpts: network.DriverOpts,
		Internal:   network.Internal,
		Attachable: network.Attachable,
		Extensions: network.Extensions,
		IPAM:       convertIPAMConfig(network.Ipam),
		External:   network.External,
		Labels:     convertStringMapToInterface(network.Labels),
	}
	internal.External = network.External
	return internal, nil
}

func convertIPAMConfig(ipam composetypes.IPAMConfig) map[string]interface{} {
	if ipam.Driver == "" && len(ipam.Config) == 0 {
		return nil
	}
	ipamMap := make(map[string]interface{})
	if ipam.Driver != "" {
		ipamMap["driver"] = ipam.Driver
	}
	if len(ipam.Config) > 0 {
		configList := []map[string]interface{}{}
		for _, cfg := range ipam.Config {
			cfgMap := make(map[string]interface{})
			if cfg.Subnet != "" {
				cfgMap["subnet"] = cfg.Subnet
			}
			if cfg.IPRange != "" {
				cfgMap["ip_range"] = cfg.IPRange
			}
			if cfg.Gateway != "" {
				cfgMap["gateway"] = cfg.Gateway
			}
			if len(cfg.AuxiliaryAddresses) > 0 {
				cfgMap["aux_addresses"] = cfg.AuxiliaryAddresses
			}
			if len(cfgMap) > 0 {
				configList = append(configList, cfgMap)
			}
		}
		if len(configList) > 0 {
			ipamMap["config"] = configList
		}
	}
	return ipamMap
}

func convertVolumeToInternalModel(volume composetypes.VolumeConfig) (*models.VolumeConfig, error) {
	internal := &models.VolumeConfig{
		Name:       volume.Name,
		Driver:     volume.Driver,
		DriverOpts: volume.DriverOpts,
		Extensions: volume.Extensions,
		External:   volume.External,
		Labels:     convertStringMapToInterface(volume.Labels),
	}
	return internal, nil
}

func convertSecretToInternalModel(secret composetypes.SecretConfig) (*models.SecretConfig, error) {
	internal := &models.SecretConfig{
		Name:       secret.Name,
		File:       secret.File,
		Extensions: secret.Extensions,
		External:   secret.External,
		Labels:     convertStringMapToInterface(secret.Labels),
	}
	return internal, nil
}

func convertConfigToInternalModel(config composetypes.ConfigObjConfig) (*models.ConfigConfig, error) {
	internal := &models.ConfigConfig{
		Name:       config.Name,
		File:       config.File,
		Extensions: config.Extensions,
		External:   config.External,
		Labels:     convertStringMapToInterface(config.Labels),
	}
	return internal, nil
}
