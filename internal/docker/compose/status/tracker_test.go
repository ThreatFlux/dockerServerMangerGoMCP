package status

import (
	"errors"
	"testing"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Keep models import
)

// Mock for event channels (if needed for specific tests)
type MockEventSource struct {
	EventsCh chan events.Message
	ErrCh    chan error
}

// TestNewTracker tests the NewTracker function
func TestNewTracker(t *testing.T) {
	mockEvents := make(chan events.Message)
	mockErrors := make(chan error)
	options := TrackerOptions{
		EventsCh: mockEvents,
		ErrorsCh: mockErrors,
		Logger:   logrus.New(),
	}
	tracker := NewTracker(options)

	assert.NotNil(t, tracker)
	assert.NotNil(t, tracker.deployments)
	assert.Equal(t, mockEvents, tracker.eventsCh)
	assert.Equal(t, mockErrors, tracker.errCh)
	assert.NotNil(t, tracker.ctx)
	assert.NotNil(t, tracker.cancel)
	assert.NotNil(t, tracker.logger)
	assert.NotNil(t, tracker.watchers)

	// Stop the tracker to clean up goroutine
	tracker.Stop()
}

// TestAddDeployment tests adding a new deployment
func TestAddDeployment(t *testing.T) {
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})
	composeFile := &models.ComposeFile{ // Use models.ComposeFile
		Version: "3.8",
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service1": {},
			"service2": {},
		},
	}

	deployment := tracker.AddDeployment("project1", composeFile)

	assert.NotNil(t, deployment)
	assert.Equal(t, "project1", deployment.ProjectName)
	assert.Equal(t, models.DeploymentStatusPending, deployment.Status) // Use models constant
	assert.Equal(t, composeFile, deployment.ComposeFile)
	assert.Len(t, deployment.Services, 2)
	assert.NotNil(t, deployment.Services["service1"])
	assert.NotNil(t, deployment.Services["service2"])
	assert.Equal(t, models.ServiceStatusPending, deployment.Services["service1"].Status) // Use models constant
	assert.Equal(t, models.ServiceStatusPending, deployment.Services["service2"].Status) // Use models constant
	assert.WithinDuration(t, time.Now(), deployment.StartTime, time.Second)
	assert.WithinDuration(t, time.Now(), deployment.UpdateTime, time.Second)
}

// TestAddDeployment_Existing tests adding an existing deployment (should update)
func TestAddDeployment_Existing(t *testing.T) {
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})
	composeFile1 := &models.ComposeFile{ // Use models.ComposeFile
		Version: "3.8",
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service1": {},
		},
	}
	tracker.AddDeployment("project1", composeFile1)

	composeFile2 := &models.ComposeFile{ // Use models.ComposeFile
		Version: "3.9", // Different version
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service2": {}, // Different service
		},
	}
	deployment := tracker.AddDeployment("project1", composeFile2) // Add again with same name

	assert.NotNil(t, deployment)
	assert.Equal(t, "project1", deployment.ProjectName)
	assert.Equal(t, composeFile2, deployment.ComposeFile) // Should be updated
}

// TestGetDeployment tests getting a deployment
func TestGetDeployment(t *testing.T) {
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})
	composeFile := &models.ComposeFile{Version: "3.8"} // Use models.ComposeFile
	tracker.AddDeployment("project1", composeFile)

	// Get existing
	deployment, exists := tracker.GetDeployment("project1")
	assert.True(t, exists)
	assert.NotNil(t, deployment)
	assert.Equal(t, "project1", deployment.ProjectName)

	// Get non-existent
	_, exists = tracker.GetDeployment("nonexistent")
	assert.False(t, exists)
}

// TestGetDeployments tests getting all deployments
func TestGetDeployments(t *testing.T) {
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})
	tracker.AddDeployment("project1", &models.ComposeFile{Version: "3.8"}) // Use models.ComposeFile
	tracker.AddDeployment("project2", &models.ComposeFile{Version: "3.8"}) // Use models.ComposeFile

	deployments := tracker.GetDeployments()
	assert.Len(t, deployments, 2)

	// Check if both projects are present (order not guaranteed)
	found1, found2 := false, false
	for _, d := range deployments {
		if d.ProjectName == "project1" {
			found1 = true
		}
		if d.ProjectName == "project2" {
			found2 = true
		}
	}
	assert.True(t, found1, "Project1 not found")
	assert.True(t, found2, "Project2 not found")
}

// TestRemoveDeployment tests removing a deployment
func TestRemoveDeployment(t *testing.T) {
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})
	tracker.AddDeployment("project1", &models.ComposeFile{Version: "3.8"}) // Use models.ComposeFile

	// Remove existing
	removed := tracker.RemoveDeployment("project1")
	assert.True(t, removed)
	_, exists := tracker.GetDeployment("project1")
	assert.False(t, exists)

	// Remove non-existent
	removed = tracker.RemoveDeployment("nonexistent")
	assert.False(t, removed)
}

// TestUpdateDeploymentStatus tests updating deployment status
func TestUpdateDeploymentStatus(t *testing.T) {
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})

	// Update non-existent
	updated := tracker.UpdateDeploymentStatus("nonexistent", models.DeploymentStatusRunning, nil) // Use models constant
	assert.False(t, updated)

	// Add and update
	tracker.AddDeployment("project1", &models.ComposeFile{Version: "3.8"}) // Use models.ComposeFile
	err := errors.New("test error")
	updated = tracker.UpdateDeploymentStatus("project1", models.DeploymentStatusRunning, err) // Use models constant
	assert.True(t, updated)

	deployment, _ := tracker.GetDeployment("project1")
	assert.Equal(t, models.DeploymentStatusRunning, deployment.Status) // Use models constant
	assert.Equal(t, err, deployment.Error)
	assert.WithinDuration(t, time.Now(), deployment.UpdateTime, time.Second)
}

// TestTrackerUpdateServiceStatus tests updating service status via the tracker
func TestTrackerUpdateServiceStatus(t *testing.T) { // Renamed function
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})

	// Update non-existent deployment
	updated := tracker.UpdateServiceStatus("nonexistent", "service1", models.ServiceStatusRunning, "container1", nil) // Use models constant
	assert.False(t, updated)

	// Add deployment and update existing service
	tracker.AddDeployment("project1", &models.ComposeFile{ // Use models.ComposeFile
		Version: "3.8",
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service1": {},
		},
	})
	err := errors.New("service error")
	updated = tracker.UpdateServiceStatus("project1", "service1", models.ServiceStatusRunning, "container1", err) // Use models constant
	assert.True(t, updated)

	deployment, _ := tracker.GetDeployment("project1")
	service := deployment.Services["service1"]
	assert.Equal(t, models.ServiceStatusRunning, service.Status) // Use models constant
	assert.Equal(t, err, service.Error)
	assert.Contains(t, service.ContainerIDs, "container1")
	assert.WithinDuration(t, time.Now(), service.UpdateTime, time.Second)

	// Update same service with different container ID
	updated = tracker.UpdateServiceStatus("project1", "service1", models.ServiceStatusRunning, "container2", nil) // Use models constant
	assert.True(t, updated)
	assert.Len(t, service.ContainerIDs, 2)
	assert.Contains(t, service.ContainerIDs, "container1")
	assert.Contains(t, service.ContainerIDs, "container2")

	// Update non-existent service (should create it)
	updated = tracker.UpdateServiceStatus("project1", "service2", models.ServiceStatusRunning, "container3", nil) // Use models constant
	assert.True(t, updated)
	assert.Contains(t, deployment.Services, "service2")
	service2 := deployment.Services["service2"]
	assert.Equal(t, models.ServiceStatusRunning, service2.Status) // Use models constant
	assert.Contains(t, service2.ContainerIDs, "container3")
}

// TestUpdateServiceHealth tests updating service health
func TestUpdateServiceHealth(t *testing.T) {
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})

	// Update non-existent deployment
	updated := tracker.UpdateServiceHealth("nonexistent", "service1", &models.HealthInfo{}) // Use models.HealthInfo
	assert.False(t, updated)

	// Add deployment
	tracker.AddDeployment("project1", &models.ComposeFile{ // Use models.ComposeFile
		Version: "3.8",
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service1": {},
		},
	})

	// Update non-existent service
	updated = tracker.UpdateServiceHealth("project1", "nonexistent", &models.HealthInfo{}) // Use models.HealthInfo
	assert.False(t, updated)

	// Update existing service
	healthInfo := &models.HealthInfo{Status: "healthy", FailingStreak: 0} // Use models.HealthInfo
	updated = tracker.UpdateServiceHealth("project1", "service1", healthInfo)
	assert.True(t, updated)

	deployment, _ := tracker.GetDeployment("project1")
	service := deployment.Services["service1"]
	assert.Equal(t, healthInfo, service.Health)
	assert.WithinDuration(t, time.Now(), service.UpdateTime, time.Second)
}

// TestStartOperation tests starting an operation
func TestStartOperation(t *testing.T) {
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})

	// Start on non-existent
	_, ok := tracker.StartOperation("nonexistent", models.OperationTypeUp, nil) // Use models constant
	assert.False(t, ok)

	// Add and start operation
	tracker.AddDeployment("project1", &models.ComposeFile{ // Use models.ComposeFile
		Version: "3.8",
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service1": {},
			"service2": {},
		},
	})
	details := map[string]interface{}{"force": true}
	operation, ok := tracker.StartOperation("project1", models.OperationTypeUp, details) // Use models constant
	assert.True(t, ok)
	assert.NotNil(t, operation)
	assert.Equal(t, models.OperationTypeUp, operation.Type)             // Use models constant
	assert.Equal(t, models.OperationStatusInProgress, operation.Status) // Use models constant
	assert.Equal(t, details, operation.Details)
	assert.WithinDuration(t, time.Now(), operation.StartTime, time.Second)

	deployment, _ := tracker.GetDeployment("project1")
	assert.Equal(t, models.DeploymentStatusDeploying, deployment.Status) // Use models constant
	assert.Equal(t, operation, deployment.Operation)
	assert.Equal(t, models.ServiceStatusPending, deployment.Services["service1"].Status) // Use models constant
}

// TestCompleteOperation tests completing an operation
func TestCompleteOperation(t *testing.T) {
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})

	// Complete on non-existent
	completed := tracker.CompleteOperation("nonexistent", models.OperationStatusComplete, nil) // Use models constant
	assert.False(t, completed)

	// Add deployment, start op, then complete
	tracker.AddDeployment("project1", &models.ComposeFile{ // Use models.ComposeFile
		Version: "3.8",
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service1": {},
		},
	})

	// Complete without starting op
	completed = tracker.CompleteOperation("project1", models.OperationStatusComplete, nil) // Use models constant
	assert.False(t, completed)

	// Start and complete successfully
	tracker.StartOperation("project1", models.OperationTypeUp, nil) // Use models constant
	err := errors.New("op error")
	completed = tracker.CompleteOperation("project1", models.OperationStatusFailed, err) // Use models constant
	assert.True(t, completed)

	deployment, _ := tracker.GetDeployment("project1")
	assert.Equal(t, models.DeploymentStatusFailed, deployment.Status)          // Use models constant
	assert.Equal(t, models.OperationStatusFailed, deployment.Operation.Status) // Use models constant
	assert.Equal(t, err, deployment.Operation.Error)
	assert.WithinDuration(t, time.Now(), deployment.Operation.EndTime, time.Second)
}

// TestWatch tests watching for deployment updates
func TestWatch(t *testing.T) {
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})
	watchCh := tracker.Watch()
	assert.NotNil(t, watchCh)

	// Add a deployment, should trigger notification
	go func() {
		time.Sleep(10 * time.Millisecond)
		tracker.AddDeployment("project1", &models.ComposeFile{Version: "3.8"}) // Use models.ComposeFile
	}()

	select {
	case update := <-watchCh:
		assert.NotNil(t, update)
		assert.Equal(t, "project1", update.ProjectName)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Did not receive update on watch channel after AddDeployment")
	}

	// Update status, should trigger notification
	go func() {
		time.Sleep(10 * time.Millisecond)
		tracker.UpdateDeploymentStatus("project1", models.DeploymentStatusRunning, nil) // Use models constant
	}()

	select {
	case update := <-watchCh:
		assert.NotNil(t, update)
		assert.Equal(t, "project1", update.ProjectName)
		assert.Equal(t, models.DeploymentStatusRunning, update.Status) // Use models constant
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Did not receive update on watch channel after UpdateDeploymentStatus")
	}

	// Unwatch
	tracker.Unwatch(watchCh)

	// Stop tracker
	tracker.Stop()
	// Check if channel is closed after stop
	_, ok := <-watchCh
	assert.False(t, ok, "Channel should be closed after Stop")
}

// TestGetServiceStatus tests getting service status
func TestGetServiceStatus(t *testing.T) {
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})
	tracker.AddDeployment("project1", &models.ComposeFile{ // Use models.ComposeFile
		Version: "3.8",
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service1": {},
		},
	})
	tracker.UpdateServiceStatus("project1", "service1", models.ServiceStatusRunning, "c1", nil) // Use models constant

	// Get existing
	status, ok := tracker.GetServiceStatus("project1", "service1")
	assert.True(t, ok)
	assert.Equal(t, models.ServiceStatusRunning, status) // Use models constant

	// Get non-existent service
	_, ok = tracker.GetServiceStatus("project1", "nonexistent")
	assert.False(t, ok)

	// Get non-existent project
	_, ok = tracker.GetServiceStatus("nonexistent", "service1")
	assert.False(t, ok)
}

// TestUpdateDeploymentStatusFromServices tests the internal status update logic
func TestUpdateDeploymentStatusFromServices(t *testing.T) {
	tracker := NewTracker(TrackerOptions{Logger: logrus.New()})
	composeFile := &models.ComposeFile{
		Version: "3.8",
		Services: map[string]models.ServiceConfig{
			"s1": {}, "s2": {}, "s3": {},
		},
	}
	deployment := tracker.AddDeployment("proj", composeFile)

	// All pending -> Pending
	tracker.updateDeploymentStatusFromServices(deployment)
	assert.Equal(t, models.DeploymentStatusPending, deployment.Status)

	// One running -> Partial
	tracker.UpdateServiceStatus("proj", "s1", models.ServiceStatusRunning, "c1", nil)
	assert.Equal(t, models.DeploymentStatusPartial, deployment.Status)

	// All running -> Running
	tracker.UpdateServiceStatus("proj", "s2", models.ServiceStatusRunning, "c2", nil)
	tracker.UpdateServiceStatus("proj", "s3", models.ServiceStatusRunning, "c3", nil)
	assert.Equal(t, models.DeploymentStatusRunning, deployment.Status)

	// One failed -> Failed
	tracker.UpdateServiceStatus("proj", "s2", models.ServiceStatusFailed, "c2", errors.New("fail"))
	assert.Equal(t, models.DeploymentStatusFailed, deployment.Status)

	// Reset s2, make s1 exited -> Partial (because s3 is still running)
	tracker.UpdateServiceStatus("proj", "s2", models.ServiceStatusRunning, "c2", nil)
	tracker.UpdateServiceStatus("proj", "s1", models.ServiceStatusExited, "c1", nil)
	assert.Equal(t, models.DeploymentStatusPartial, deployment.Status)

	// All exited/dead -> Stopped
	tracker.UpdateServiceStatus("proj", "s2", models.ServiceStatusDead, "c2", nil)
	tracker.UpdateServiceStatus("proj", "s3", models.ServiceStatusExited, "c3", nil)
	assert.Equal(t, models.DeploymentStatusStopped, deployment.Status)
}
