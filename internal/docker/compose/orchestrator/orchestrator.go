// Package orchestrator provides functionality for orchestrating Docker Compose deployments
package orchestrator

import (
	"context"
	"fmt"
	"sort" // Added for dependency sorting
	"time"

	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/compose/resources"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/network"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/volume"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/interfaces"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// --- Dependency Manager (Moved from dependency.go) ---

// DependencyManager manages dependencies between services
type DependencyManager struct {
	Logger *logrus.Logger // Use exported field name
}

// DependencyManagerOptions defines options for creating a dependency manager
type DependencyManagerOptions struct {
	Logger *logrus.Logger
}

// NewDependencyManager creates a new dependency manager
func NewDependencyManager(options DependencyManagerOptions) *DependencyManager {
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}
	return &DependencyManager{Logger: logger} // Use exported field name
}

// DependencyOrderOptions defines options for building dependency order
type DependencyOrderOptions struct {
	Timeout time.Duration
	Logger  *logrus.Logger
}

// serviceNode represents a service in the dependency graph
type serviceNode struct {
	Name         string
	Dependencies []string
	Visited      bool
	InStack      bool
}

// BuildServiceOrder builds the order in which services should be started
func (m *DependencyManager) BuildServiceOrder(ctx context.Context, composeFile *models.ComposeFile, options DependencyOrderOptions) ([]string, error) {
	logger := options.Logger
	if logger == nil {
		logger = m.Logger
	} // Use exported field

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	graph, err := m.buildDependencyGraph(composeFile)
	if err != nil {
		return nil, fmt.Errorf("failed to build dependency graph: %w", err)
	}
	if err := m.detectCycles(graph); err != nil {
		return nil, fmt.Errorf("dependency cycle detected: %w", err)
	}
	order, err := m.topologicalSort(graph)
	if err != nil {
		return nil, fmt.Errorf("failed to perform topological sort: %w", err)
	}
	return order, nil
}

// BuildServiceOrderReverse builds the order in which services should be stopped
func (m *DependencyManager) BuildServiceOrderReverse(ctx context.Context, composeFile *models.ComposeFile, options DependencyOrderOptions) ([]string, error) {
	order, err := m.BuildServiceOrder(ctx, composeFile, options)
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
		order[i], order[j] = order[j], order[i]
	}
	return order, nil
}

// buildDependencyGraph builds a dependency graph from the compose file
func (m *DependencyManager) buildDependencyGraph(composeFile *models.ComposeFile) (map[string]*serviceNode, error) {
	graph := make(map[string]*serviceNode)
	for name := range composeFile.Services {
		graph[name] = &serviceNode{Name: name, Dependencies: []string{}}
	}
	for name, service := range composeFile.Services {
		if service.DependsOn == nil {
			continue
		}
		dependencies := []string{}
		switch deps := service.DependsOn.(type) {
		case []string:
			dependencies = deps
		case []interface{}:
			for _, dep := range deps {
				if strDep, ok := dep.(string); ok {
					dependencies = append(dependencies, strDep)
				}
			}
		case map[string]interface{}:
			for dep := range deps {
				dependencies = append(dependencies, dep)
			}
		default:
			m.Logger.Warnf("Unsupported type for depends_on for service '%s': %T", name, service.DependsOn) // Use exported field
		}
		for _, dep := range dependencies {
			if _, exists := graph[dep]; !exists {
				return nil, fmt.Errorf("service '%s' depends on non-existent service '%s'", name, dep)
			}
			graph[name].Dependencies = append(graph[name].Dependencies, dep)
		}
	}
	return graph, nil
}

// detectCycles detects cycles in the dependency graph
func (m *DependencyManager) detectCycles(graph map[string]*serviceNode) error {
	for _, node := range graph {
		node.Visited = false
		node.InStack = false
	}
	for _, node := range graph {
		if !node.Visited {
			if err := m.detectCyclesDFS(graph, node); err != nil {
				return err
			}
		}
	}
	return nil
}

// detectCyclesDFS performs DFS to detect cycles
func (m *DependencyManager) detectCyclesDFS(graph map[string]*serviceNode, node *serviceNode) error {
	node.Visited = true
	node.InStack = true
	for _, depName := range node.Dependencies {
		dep := graph[depName]
		if !dep.Visited {
			if err := m.detectCyclesDFS(graph, dep); err != nil {
				return err
			}
		} else if dep.InStack {
			return fmt.Errorf("cycle detected involving services '%s' and '%s'", node.Name, dep.Name)
		}
	}
	node.InStack = false
	return nil
}

// topologicalSort performs topological sort on the dependency graph
func (m *DependencyManager) topologicalSort(graph map[string]*serviceNode) ([]string, error) {
	for _, node := range graph {
		node.Visited = false
	}
	var result []string
	for _, node := range graph {
		if !node.Visited {
			if err := m.topologicalSortDFS(graph, node, &result); err != nil {
				return nil, err
			}
		}
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result, nil
}

// topologicalSortDFS performs DFS for topological sort
func (m *DependencyManager) topologicalSortDFS(graph map[string]*serviceNode, node *serviceNode, result *[]string) error {
	node.Visited = true
	for _, depName := range node.Dependencies {
		dep := graph[depName]
		if !dep.Visited {
			if err := m.topologicalSortDFS(graph, dep, result); err != nil {
				return err
			}
		}
	}
	*result = append(*result, node.Name)
	return nil
}

// GetServiceDependencies gets direct and indirect dependencies for a service
func (m *DependencyManager) GetServiceDependencies(composeFile *models.ComposeFile, serviceName string) ([]string, error) {
	if _, exists := composeFile.Services[serviceName]; !exists {
		return nil, fmt.Errorf("service '%s' does not exist", serviceName)
	}
	graph, err := m.buildDependencyGraph(composeFile)
	if err != nil {
		return nil, fmt.Errorf("failed to build dependency graph: %w", err)
	}
	dependencies := make(map[string]bool)
	m.getDependenciesDFS(graph, serviceName, dependencies)
	result := make([]string, 0, len(dependencies))
	for dep := range dependencies {
		result = append(result, dep)
	}
	sort.Strings(result)
	return result, nil
}

// getDependenciesDFS gets all dependencies for a service using DFS
func (m *DependencyManager) getDependenciesDFS(graph map[string]*serviceNode, serviceName string, dependencies map[string]bool) {
	node := graph[serviceName]
	for _, depName := range node.Dependencies {
		if !dependencies[depName] {
			dependencies[depName] = true
			m.getDependenciesDFS(graph, depName, dependencies)
		}
	}
}

// GetServiceDependents gets services that depend on a specific service
func (m *DependencyManager) GetServiceDependents(composeFile *models.ComposeFile, serviceName string) ([]string, error) {
	if _, exists := composeFile.Services[serviceName]; !exists {
		return nil, fmt.Errorf("service '%s' does not exist", serviceName)
	}
	graph, err := m.buildDependencyGraph(composeFile)
	if err != nil {
		return nil, fmt.Errorf("failed to build dependency graph: %w", err)
	}
	dependents := make([]string, 0)
	for name, node := range graph {
		for _, dep := range node.Dependencies {
			if dep == serviceName {
				dependents = append(dependents, name)
				break
			}
		}
	}
	sort.Strings(dependents)
	return dependents, nil
}

// --- End Dependency Manager ---

// Orchestrator orchestrates Docker Compose deployments
type Orchestrator struct {
	resourceManager   *resources.Manager
	statusTracker     interfaces.ComposeStatusTracker
	serviceManager    *ServiceManager    // Defined in service.go
	dependencyManager *DependencyManager // Now defined in this file
	logger            *logrus.Logger
}

// OrchestratorOptions defines options for creating an orchestrator
type OrchestratorOptions struct {
	NetworkService  network.Service
	VolumeService   volume.Service
	StatusTracker   interfaces.ComposeStatusTracker
	Logger          *logrus.Logger
	DefaultTimeout  time.Duration
	ContainerClient interfaces.ContainerService // Use interface from interfaces/docker_test.go
	ImageClient     interfaces.ImageService     // Use interface from interfaces/docker_test.go
}

// NewOrchestrator creates a new orchestrator
func NewOrchestrator(options OrchestratorOptions) *Orchestrator {
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}

	resourceManager := resources.NewManager(
		options.NetworkService,
		options.VolumeService,
		resources.ManagerOptions{Logger: logger, DefaultTimeout: options.DefaultTimeout},
	)
	serviceManager := NewServiceManager(ServiceManagerOptions{
		Logger:          logger,
		ContainerClient: options.ContainerClient,
		ImageClient:     options.ImageClient,
	})
	dependencyManager := NewDependencyManager(DependencyManagerOptions{Logger: logger}) // Use local constructor

	return &Orchestrator{
		resourceManager:   resourceManager,
		statusTracker:     options.StatusTracker,
		serviceManager:    serviceManager,
		dependencyManager: dependencyManager, // Use local instance
		logger:            logger,
	}
}

// Deploy deploys a Docker Compose file
func (o *Orchestrator) Deploy(ctx context.Context, composeFile *models.ComposeFile, options models.DeployOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = o.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	deployment := o.statusTracker.AddDeployment(options.ProjectName, composeFile)
	_ = deployment

	operation, ok := o.statusTracker.StartOperation(options.ProjectName, models.OperationTypeUp, map[string]interface{}{
		"force_recreate": options.ForceRecreate, "no_build": options.NoBuild, "no_start": options.NoStart,
		"pull": options.Pull, "remove_orphans": options.RemoveOrphans,
	})
	if !ok {
		return fmt.Errorf("failed to start operation for project %s", options.ProjectName)
	}
	_ = operation

	var err error
	defer func() {
		if err != nil {
			o.statusTracker.CompleteOperation(options.ProjectName, models.OperationStatusFailed, err)
		} else {
			o.statusTracker.CompleteOperation(options.ProjectName, models.OperationStatusComplete, nil)
		}
	}()

	logger.WithField("project", options.ProjectName).Info("Creating resources for Docker Compose deployment")
	err = o.resourceManager.CreateResources(ctx, composeFile, resources.CreateResourcesOptions{
		ProjectName: options.ProjectName, Timeout: options.Timeout, SkipExistingNetworks: true,
		SkipExistingVolumes: true, Labels: map[string]string{"com.docker_test.compose.project": options.ProjectName}, Logger: logger,
	})
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to create resources")
		return fmt.Errorf("failed to create resources: %w", err)
	}

	logger.WithField("project", options.ProjectName).Info("Building service dependency order")
	serviceOrder, err := o.dependencyManager.BuildServiceOrder(ctx, composeFile, DependencyOrderOptions{ // Use local dependencyManager
		Timeout: options.DependencyTimeout, Logger: logger,
	})
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to build service dependency order")
		return fmt.Errorf("failed to build service dependency order: %w", err)
	}

	logger.WithField("project", options.ProjectName).Info("Deploying services")
	err = o.serviceManager.DeployServices(ctx, composeFile, serviceOrder, ServiceDeployOptions{ // Use ServiceDeployOptions from service.go
		ProjectName: options.ProjectName, ForceRecreate: options.ForceRecreate, NoBuild: options.NoBuild,
		NoStart: options.NoStart, Pull: options.Pull, RemoveOrphans: options.RemoveOrphans,
		AdjustNetworkSettings: options.AdjustNetworkSettings, Timeout: options.Timeout, StatusTracker: o.statusTracker, Logger: logger,
	})
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to deploy services")
		return fmt.Errorf("failed to deploy services: %w", err)
	}

	logger.WithField("project", options.ProjectName).Info("Docker Compose deployment completed successfully")
	return nil
}

// Remove removes a Docker Compose deployment
func (o *Orchestrator) Remove(ctx context.Context, composeFile *models.ComposeFile, options models.RemoveOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = o.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	deployment, exists := o.statusTracker.GetDeployment(options.ProjectName)
	if !exists {
		deployment = o.statusTracker.AddDeployment(options.ProjectName, composeFile)
	}
	_ = deployment

	operation, ok := o.statusTracker.StartOperation(options.ProjectName, models.OperationTypeDown, map[string]interface{}{
		"remove_volumes": options.RemoveVolumes, "remove_images": options.RemoveImages,
		"remove_orphans": options.RemoveOrphans, "force": options.Force,
	})
	if !ok {
		return fmt.Errorf("failed to start operation for project %s", options.ProjectName)
	}
	_ = operation

	var err error
	defer func() {
		if err != nil {
			o.statusTracker.CompleteOperation(options.ProjectName, models.OperationStatusFailed, err)
		} else {
			o.statusTracker.CompleteOperation(options.ProjectName, models.OperationStatusComplete, nil)
		}
	}()

	logger.WithField("project", options.ProjectName).Info("Building service dependency order for removal")
	serviceOrder, err := o.dependencyManager.BuildServiceOrderReverse(ctx, composeFile, DependencyOrderOptions{ // Use local dependencyManager
		Timeout: options.DependencyTimeout, Logger: logger,
	})
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to build service dependency order")
		return fmt.Errorf("failed to build service dependency order: %w", err)
	}

	logger.WithField("project", options.ProjectName).Info("Removing services")
	err = o.serviceManager.RemoveServices(ctx, composeFile, serviceOrder, ServiceRemoveOptions{ // Use ServiceRemoveOptions from service.go
		ProjectName: options.ProjectName, RemoveVolumes: options.RemoveVolumes, RemoveImages: options.RemoveImages,
		RemoveOrphans: options.RemoveOrphans, Force: options.Force, Timeout: options.Timeout, StatusTracker: o.statusTracker, Logger: logger,
	})
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to remove services")
		return fmt.Errorf("failed to remove services: %w", err)
	}

	logger.WithField("project", options.ProjectName).Info("Removing resources")
	err = o.resourceManager.RemoveResources(ctx, composeFile, resources.RemoveResourcesOptions{
		ProjectName: options.ProjectName, Timeout: options.Timeout, Force: options.Force,
		KeepVolumes: !options.RemoveVolumes, KeepNetworks: false, Logger: logger,
	})
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to remove resources")
		return fmt.Errorf("failed to remove resources: %w", err)
	}

	o.statusTracker.RemoveDeployment(options.ProjectName)
	logger.WithField("project", options.ProjectName).Info("Docker Compose deployment removed successfully")
	return nil
}

// Stop stops a Docker Compose deployment
func (o *Orchestrator) Stop(ctx context.Context, composeFile *models.ComposeFile, options models.StopOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = o.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	deployment, exists := o.statusTracker.GetDeployment(options.ProjectName)
	if !exists {
		deployment = o.statusTracker.AddDeployment(options.ProjectName, composeFile)
	}
	_ = deployment

	operation, ok := o.statusTracker.StartOperation(options.ProjectName, models.OperationTypeStop, nil)
	if !ok {
		return fmt.Errorf("failed to start operation for project %s", options.ProjectName)
	}
	_ = operation

	var err error
	defer func() {
		if err != nil {
			o.statusTracker.CompleteOperation(options.ProjectName, models.OperationStatusFailed, err)
		} else {
			o.statusTracker.CompleteOperation(options.ProjectName, models.OperationStatusComplete, nil)
		}
	}()

	logger.WithField("project", options.ProjectName).Info("Building service dependency order for stopping")
	serviceOrder, err := o.dependencyManager.BuildServiceOrderReverse(ctx, composeFile, DependencyOrderOptions{ // Use local dependencyManager
		Timeout: options.DependencyTimeout, Logger: logger,
	})
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to build service dependency order")
		return fmt.Errorf("failed to build service dependency order: %w", err)
	}

	logger.WithField("project", options.ProjectName).Info("Stopping services")
	err = o.serviceManager.StopServices(ctx, composeFile, serviceOrder, ServiceStopOptions{ // Use ServiceStopOptions from service.go
		ProjectName: options.ProjectName, Timeout: options.Timeout, StatusTracker: o.statusTracker, Logger: logger,
	})
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to stop services")
		return fmt.Errorf("failed to stop services: %w", err)
	}

	logger.WithField("project", options.ProjectName).Info("Docker Compose deployment stopped successfully")
	return nil
}

// Start starts a Docker Compose deployment
func (o *Orchestrator) Start(ctx context.Context, composeFile *models.ComposeFile, options models.StartOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = o.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	deployment, exists := o.statusTracker.GetDeployment(options.ProjectName)
	if !exists {
		deployment = o.statusTracker.AddDeployment(options.ProjectName, composeFile)
	}
	_ = deployment

	operation, ok := o.statusTracker.StartOperation(options.ProjectName, models.OperationTypeStart, nil)
	if !ok {
		return fmt.Errorf("failed to start operation for project %s", options.ProjectName)
	}
	_ = operation

	var err error
	defer func() {
		if err != nil {
			o.statusTracker.CompleteOperation(options.ProjectName, models.OperationStatusFailed, err)
		} else {
			o.statusTracker.CompleteOperation(options.ProjectName, models.OperationStatusComplete, nil)
		}
	}()

	logger.WithField("project", options.ProjectName).Info("Building service dependency order")
	serviceOrder, err := o.dependencyManager.BuildServiceOrder(ctx, composeFile, DependencyOrderOptions{ // Use local dependencyManager
		Timeout: options.DependencyTimeout, Logger: logger,
	})
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to build service dependency order")
		return fmt.Errorf("failed to build service dependency order: %w", err)
	}

	logger.WithField("project", options.ProjectName).Info("Starting services")
	err = o.serviceManager.StartServices(ctx, composeFile, serviceOrder, ServiceStartOptions{ // Use ServiceStartOptions from service.go
		ProjectName: options.ProjectName, Timeout: options.Timeout, StatusTracker: o.statusTracker, Logger: logger,
	})
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to start services")
		return fmt.Errorf("failed to start services: %w", err)
	}

	logger.WithField("project", options.ProjectName).Info("Docker Compose deployment started successfully")
	return nil
}

// Restart restarts a Docker Compose deployment
func (o *Orchestrator) Restart(ctx context.Context, composeFile *models.ComposeFile, options models.RestartOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = o.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	deployment, exists := o.statusTracker.GetDeployment(options.ProjectName)
	if !exists {
		deployment = o.statusTracker.AddDeployment(options.ProjectName, composeFile)
	}
	_ = deployment

	operation, ok := o.statusTracker.StartOperation(options.ProjectName, models.OperationTypeRestart, nil)
	if !ok {
		return fmt.Errorf("failed to start operation for project %s", options.ProjectName)
	}
	_ = operation

	var err error
	defer func() {
		if err != nil {
			o.statusTracker.CompleteOperation(options.ProjectName, models.OperationStatusFailed, err)
		} else {
			o.statusTracker.CompleteOperation(options.ProjectName, models.OperationStatusComplete, nil)
		}
	}()

	err = o.Stop(ctx, composeFile, models.StopOptions{
		ProjectName: options.ProjectName, Timeout: options.Timeout, DependencyTimeout: options.DependencyTimeout, Logger: logger,
	})
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to stop services during restart")
		return fmt.Errorf("failed to stop services during restart: %w", err)
	}

	err = o.Start(ctx, composeFile, models.StartOptions{
		ProjectName: options.ProjectName, Timeout: options.Timeout, DependencyTimeout: options.DependencyTimeout, Logger: logger,
	})
	if err != nil {
		logger.WithError(err).WithField("project", options.ProjectName).Error("Failed to start services during restart")
		return fmt.Errorf("failed to start services during restart: %w", err)
	}

	logger.WithField("project", options.ProjectName).Info("Docker Compose deployment restarted successfully")
	return nil
}

// Scale scales services in a Docker Compose deployment
func (o *Orchestrator) Scale(ctx context.Context, composeFile *models.ComposeFile, options models.ScaleOptions) error {
	logger := options.Logger
	if logger == nil {
		logger = o.logger
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	deployment, exists := o.statusTracker.GetDeployment(options.ProjectName)
	if !exists {
		return fmt.Errorf("deployment '%s' not found or not managed", options.ProjectName)
	}
	_ = deployment

	operation, ok := o.statusTracker.StartOperation(options.ProjectName, models.OperationTypeScale, map[string]interface{}{
		"service":  options.Service,
		"replicas": options.Replicas,
	})
	if !ok {
		return fmt.Errorf("failed to start scale operation for project %s", options.ProjectName)
	}
	_ = operation

	var err error
	defer func() {
		if err != nil {
			o.statusTracker.CompleteOperation(options.ProjectName, models.OperationStatusFailed, err)
		} else {
			o.statusTracker.CompleteOperation(options.ProjectName, models.OperationStatusComplete, nil)
		}
	}()

	logger.WithFields(logrus.Fields{
		"project":  options.ProjectName,
		"service":  options.Service,
		"replicas": options.Replicas,
	}).Info("Scaling service")

	err = o.serviceManager.ScaleService(ctx, composeFile, ServiceScaleOptions{ // Use ServiceScaleOptions from service.go
		ProjectName:   options.ProjectName,
		Service:       options.Service,
		Replicas:      options.Replicas,
		Timeout:       options.Timeout,
		StatusTracker: o.statusTracker,
		Logger:        logger,
	})
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{
			"project": options.ProjectName,
			"service": options.Service,
		}).Error("Failed to scale service")
		return fmt.Errorf("failed to scale service %s: %w", options.Service, err)
	}

	logger.WithFields(logrus.Fields{
		"project":  options.ProjectName,
		"service":  options.Service,
		"replicas": options.Replicas,
	}).Info("Service scaled successfully")
	return nil
}
