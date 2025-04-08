package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Add models import
)

// MockAPIClient is a mock Docker API client
type MockAPIClient struct {
	mock.Mock
}

// ImageInspectWithRaw mocks the Docker API's ImageInspectWithRaw method
func (m *MockAPIClient) ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error) {
	args := m.Called(ctx, imageID)
	return args.Get(0).(types.ImageInspect), args.Get(1).([]byte), args.Error(2)
}

// ContainerInspect mocks the Docker API's ContainerInspect method
func (m *MockAPIClient) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	args := m.Called(ctx, containerID)
	return args.Get(0).(types.ContainerJSON), args.Error(1)
}

// IsErrNotFound mocks the Docker API's IsErrNotFound method
func (m *MockAPIClient) IsErrNotFound(err error) bool {
	args := m.Called(err)
	return args.Bool(0)
}

// MockScanner is a mock Scanner for testing
type MockScannerImpl struct {
	mock.Mock
}

// Name returns the name of the scanner
func (m *MockScannerImpl) Name() string {
	args := m.Called()
	return args.String(0)
}

// Version returns the version of the scanner
func (m *MockScannerImpl) Version() string {
	args := m.Called()
	return args.String(0)
}

// IsAvailable checks if the scanner is available
func (m *MockScannerImpl) IsAvailable(ctx context.Context) bool {
	args := m.Called(ctx)
	return args.Bool(0)
}

// ScanImage scans an image and returns the results
func (m *MockScannerImpl) ScanImage(ctx context.Context, imageRef string, options ScanOptions) (*models.SecurityScanResult, error) { // Use models type
	args := m.Called(ctx, imageRef, options)
	result := args.Get(0)
	if result == nil {
		return nil, args.Error(1)
	}
	return result.(*models.SecurityScanResult), args.Error(1) // Use models type
}

// ScanRunningContainer scans a running container and returns the results
func (m *MockScannerImpl) ScanRunningContainer(ctx context.Context, containerID string, options ScanOptions) (*models.SecurityScanResult, error) { // Use models type
	args := m.Called(ctx, containerID, options)
	result := args.Get(0)
	if result == nil {
		return nil, args.Error(1)
	}
	return result.(*models.SecurityScanResult), args.Error(1) // Use models type
}

// MockScannerFactory is a mock ScannerFactory for testing
type MockScannerFactory struct {
	mock.Mock
}

// Create creates a scanner of the specified type
func (m *MockScannerFactory) Create(scannerType string) (Scanner, error) {
	args := m.Called(scannerType)
	result := args.Get(0)
	if result == nil {
		return nil, args.Error(1)
	}
	return result.(Scanner), args.Error(1)
}

func TestSecurityManager_RegisterScanner(t *testing.T) {
	// Create a mock Docker client
	mockClient := new(MockAPIClient)

	// Create a mock Scanner
	mockScanner := new(MockScannerImpl)
	mockScanner.On("Name").Return("MockScanner")
	mockScanner.On("Version").Return("1.0.0")
	mockScanner.On("IsAvailable", mock.Anything).Return(true)

	// Create a mock ScannerFactory
	mockFactory := new(MockScannerFactory)
	mockFactory.On("Create", "mock").Return(mockScanner, nil)

	// Create a SecurityManager with the mock factory
	manager := NewSecurityManager(mockClient, WithScannerFactory(mockFactory))

	// Register a scanner
	err := manager.RegisterScanner("mock")

	// Assert that no error occurred
	assert.NoError(t, err)

	// Assert that the scanner was registered
	assert.Contains(t, manager.scanners, "mock")

	// Assert that the factory was called
	mockFactory.AssertCalled(t, "Create", "mock")

	// Assert that the scanner's IsAvailable method was called
	mockScanner.AssertCalled(t, "IsAvailable", mock.Anything)
}

func TestSecurityManager_GetAvailableScanners(t *testing.T) {
	// Create a mock Docker client
	mockClient := new(MockAPIClient)

	// Create mock Scanners
	mockScanner1 := new(MockScannerImpl)
	mockScanner1.On("Name").Return("MockScanner1")
	mockScanner1.On("Version").Return("1.0.0")
	mockScanner1.On("IsAvailable", mock.Anything).Return(true)

	mockScanner2 := new(MockScannerImpl)
	mockScanner2.On("Name").Return("MockScanner2")
	mockScanner2.On("Version").Return("1.0.0")
	mockScanner2.On("IsAvailable", mock.Anything).Return(true)

	// Create a mock ScannerFactory
	mockFactory := new(MockScannerFactory)
	mockFactory.On("Create", "mock1").Return(mockScanner1, nil)
	mockFactory.On("Create", "mock2").Return(mockScanner2, nil)

	// Create a SecurityManager with the mock factory
	manager := NewSecurityManager(mockClient, WithScannerFactory(mockFactory))

	// Register scanners
	_ = manager.RegisterScanner("mock1")
	_ = manager.RegisterScanner("mock2")

	// Get available scanners
	scanners := manager.GetAvailableScanners()

	// Assert that both scanners are available
	assert.Contains(t, scanners, "mock1")
	assert.Contains(t, scanners, "mock2")
	assert.Len(t, scanners, 2)
}

func TestSecurityManager_ScanImage(t *testing.T) {
	// Create a mock Docker client
	mockClient := new(MockAPIClient)

	// Create a mock image inspect result
	imageInspect := types.ImageInspect{
		ID: "sha256:abcdef1234567890",
	}

	// Configure the mock client
	mockClient.On("ImageInspectWithRaw", mock.Anything, "test-image").Return(imageInspect, []byte{}, nil)
	mockClient.On("IsErrNotFound", mock.Anything).Return(false)

	// Create a mock scanner
	mockScanner := new(MockScannerImpl)
	mockScanner.On("Name").Return("MockScanner")
	mockScanner.On("Version").Return("1.0.0")
	mockScanner.On("IsAvailable", mock.Anything).Return(true)

	// Create a mock scan result using models types
	scanResult := &models.SecurityScanResult{ // Use models type
		Target:        "test-image",  // Set Target
		Scanner:       "MockScanner", // Set Scanner
		ScanTimestamp: time.Now(),    // Set Timestamp
		Vulnerabilities: []models.Vulnerability{ // Use models type
			{
				ID: "CVE-2023-1234",
				// Title:        "Test Vulnerability", // Title not in model
				Description: "This is a test vulnerability",
				PackageName: "test-package", // Use PackageName
				Version:     "1.0.0",
				FixVersion:  "1.0.1", // Use FixVersion
				Severity:    "HIGH",  // Use string severity
				// URLs, CVSSScore not needed for this mock
			},
		},
		// Summary will be calculated later
	}

	// Configure the mock scanner
	mockScanner.On("ScanImage", mock.Anything, "test-image", mock.Anything).Return(scanResult, nil)

	// Create a mock scanner factory
	mockFactory := new(MockScannerFactory)
	mockFactory.On("Create", "mock").Return(mockScanner, nil)

	// Create a security manager
	manager := NewSecurityManager(mockClient, WithScannerFactory(mockFactory))

	// Register the scanner
	err := manager.RegisterScanner("mock")
	assert.NoError(t, err)

	// Scan the image
	result, err := manager.ScanImage(context.Background(), "test-image", "mock", ScanOptions{
		Logger: logrus.New(),
	})

	// Assert that no error occurred
	assert.NoError(t, err)

	// Assert that the result is correct
	assert.Equal(t, "test-image", result.Target)   // Check Target
	assert.Equal(t, "MockScanner", result.Scanner) // Check Scanner
	// ScannerVersion is not in the model
	assert.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, "CVE-2023-1234", result.Vulnerabilities[0].ID)
	assert.Equal(t, "HIGH", result.Vulnerabilities[0].Severity) // Check string severity

	// Assert that the summary is correct (after updateScanSummary is called implicitly)
	// Note: The mock doesn't call updateScanSummary, so we check the calculated values based on the mock vuln
	assert.Equal(t, 1, result.Summary.TotalVulnerabilities) // Check TotalVulnerabilities
	assert.Equal(t, 0, result.Summary.CriticalCount)
	assert.Equal(t, 1, result.Summary.HighCount)
	assert.Equal(t, 0, result.Summary.MediumCount)
	assert.Equal(t, 0, result.Summary.LowCount)
	assert.Equal(t, 0, result.Summary.UnknownCount)
	// FixableCount is not in the model

	// Assert that the client and scanner were called
	mockClient.AssertCalled(t, "ImageInspectWithRaw", mock.Anything, "test-image")
	mockScanner.AssertCalled(t, "ScanImage", mock.Anything, "test-image", mock.Anything)
}

func TestSecurityManager_ScanContainer(t *testing.T) {
	// Create a mock Docker client
	mockClient := new(MockAPIClient)

	// Create a mock container inspect result
	containerJSON := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:    "test-container",
			Image: "sha256:abcdef1234567890",
		},
		Config: &container.Config{
			Image: "test-image",
		},
	}

	// Configure the mock client
	mockClient.On("ContainerInspect", mock.Anything, "test-container").Return(containerJSON, nil)
	mockClient.On("IsErrNotFound", mock.Anything).Return(false)

	// Create a mock scanner
	mockScanner := new(MockScannerImpl)
	mockScanner.On("Name").Return("MockScanner")
	mockScanner.On("Version").Return("1.0.0")
	mockScanner.On("IsAvailable", mock.Anything).Return(true)

	// Create a mock scan result using models types
	scanResult := &models.SecurityScanResult{ // Use models type
		Target:        "test-container", // Set Target
		Scanner:       "MockScanner",    // Set Scanner
		ScanTimestamp: time.Now(),       // Set Timestamp
		Vulnerabilities: []models.Vulnerability{ // Use models type
			{
				ID: "CVE-2023-1234",
				// Title:        "Test Vulnerability", // Title not in model
				Description: "This is a test vulnerability",
				PackageName: "test-package", // Use PackageName
				Version:     "1.0.0",
				FixVersion:  "1.0.1",    // Use FixVersion
				Severity:    "CRITICAL", // Use string severity
				// URLs, CVSSScore not needed for this mock
			},
		},
		// Summary will be calculated later
	}

	// Configure the mock scanner
	mockScanner.On("ScanRunningContainer", mock.Anything, "test-container", mock.Anything).Return(scanResult, nil)

	// Create a mock scanner factory
	mockFactory := new(MockScannerFactory)
	mockFactory.On("Create", "mock").Return(mockScanner, nil)

	// Create a security manager
	manager := NewSecurityManager(mockClient, WithScannerFactory(mockFactory))

	// Register the scanner
	err := manager.RegisterScanner("mock")
	assert.NoError(t, err)

	// Scan the container
	result, err := manager.ScanContainer(context.Background(), "test-container", "mock", ScanOptions{
		Logger: logrus.New(),
	})

	// Assert that no error occurred
	assert.NoError(t, err)

	// Assert that the result is correct
	assert.Equal(t, "test-container", result.Target) // Check Target (should be container ID)
	assert.Equal(t, "MockScanner", result.Scanner)   // Check Scanner
	// ScannerVersion is not in the model
	assert.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, "CVE-2023-1234", result.Vulnerabilities[0].ID)
	assert.Equal(t, "CRITICAL", result.Vulnerabilities[0].Severity) // Check string severity

	// Assert that the summary is correct (after updateScanSummary is called implicitly)
	// Note: The mock doesn't call updateScanSummary, so we check the calculated values based on the mock vuln
	assert.Equal(t, 1, result.Summary.TotalVulnerabilities) // Check TotalVulnerabilities
	assert.Equal(t, 1, result.Summary.CriticalCount)
	assert.Equal(t, 0, result.Summary.HighCount)
	assert.Equal(t, 0, result.Summary.MediumCount)
	assert.Equal(t, 0, result.Summary.LowCount)
	assert.Equal(t, 0, result.Summary.UnknownCount)
	// FixableCount is not in the model

	// Assert that the client and scanner were called
	mockClient.AssertCalled(t, "ContainerInspect", mock.Anything, "test-container")
	mockScanner.AssertCalled(t, "ScanRunningContainer", mock.Anything, "test-container", mock.Anything)
}

func TestTrivyScanner_IsAvailable(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create a Trivy scanner with the test server as endpoint
	scanner := &trivyScanner{
		httpClient: &http.Client{},
		endpoint:   server.URL,
	}

	// Check if the scanner is available
	available := scanner.IsAvailable(context.Background())

	// Assert that the scanner is available
	assert.True(t, available)
}

func TestTrivyScanner_ScanImage(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/scan" && r.URL.Query().Get("image") == "test-image" {
			// Return a mock scan result using models types
			result := models.SecurityScanResult{ // Use models type
				Target:        "test-image", // Set Target
				Scanner:       "Trivy",      // Set Scanner
				ScanTimestamp: time.Now(),   // Set Timestamp
				Vulnerabilities: []models.Vulnerability{ // Use models type
					{
						ID: "CVE-2023-1234",
						// Title:        "Test Vulnerability", // Title not in model
						Description: "This is a test vulnerability",
						PackageName: "test-package", // Use PackageName
						Version:     "1.0.0",
						FixVersion:  "1.0.1", // Use FixVersion
						Severity:    "HIGH",  // Use string severity
						// URLs, CVSSScore not needed for this mock
					},
				},
				// Summary would typically be part of the scanner's response
			}
			json.NewEncoder(w).Encode(result)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create a Trivy scanner with the test server as endpoint
	scanner := &trivyScanner{
		httpClient: &http.Client{},
		endpoint:   server.URL,
	}

	// Scan the image
	result, err := scanner.ScanImage(context.Background(), "test-image", ScanOptions{})

	// Assert that no error occurred
	assert.NoError(t, err)

	// Assert that the result is correct
	assert.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, "CVE-2023-1234", result.Vulnerabilities[0].ID)
	assert.Equal(t, "HIGH", result.Vulnerabilities[0].Severity) // Check string severity
}

func TestSecurityManager_GetScanHistory(t *testing.T) {
	// Create a mock Docker client
	mockClient := new(MockAPIClient)

	// Create a security manager
	manager := NewSecurityManager(mockClient)

	// Add a scan result to the history using models type
	scanResult := &models.SecurityScanResult{ // Use models type
		Target:        "test-image", // Use Target
		ScanTimestamp: time.Now(),   // Use ScanTimestamp
		Scanner:       "MockScanner",
	}
	manager.scanHistory = append(manager.scanHistory, scanResult)

	// Get the scan history
	history := manager.GetScanHistory()

	// Assert that the history is correct
	assert.Len(t, history, 1)
	assert.Equal(t, scanResult.Target, history[0].Target)   // Check Target
	assert.Equal(t, scanResult.Scanner, history[0].Scanner) // Check Scanner
}

func TestSecurityManager_GetLatestScanResult(t *testing.T) {
	// Create a mock Docker client
	mockClient := new(MockAPIClient)

	// Create a security manager
	manager := NewSecurityManager(mockClient)

	// Add scan results to the history using models type
	oldResult := &models.SecurityScanResult{ // Use models type
		Target:        "test-image",                   // Use Target
		ScanTimestamp: time.Now().Add(-1 * time.Hour), // Use ScanTimestamp
		Scanner:       "MockScanner",
	}
	newResult := &models.SecurityScanResult{ // Use models type
		Target:        "test-image", // Use Target
		ScanTimestamp: time.Now(),   // Use ScanTimestamp
		Scanner:       "MockScanner",
	}
	otherResult := &models.SecurityScanResult{ // Use models type
		Target:        "other-image", // Use Target
		ScanTimestamp: time.Now(),    // Use ScanTimestamp
		Scanner:       "MockScanner",
	}
	manager.scanHistory = append(manager.scanHistory, oldResult, newResult, otherResult)

	// Get the latest scan result for the target
	result := manager.GetLatestScanResult("test-image") // Use target string

	// Assert that the result is the newer one
	assert.NotNil(t, result)                                       // Ensure result is not nil before accessing fields
	assert.Equal(t, newResult.ScanTimestamp, result.ScanTimestamp) // Check ScanTimestamp
}

func TestScanResult_JSON(t *testing.T) {
	// Create a scan result using models type
	now := time.Now()                         // Use a fixed time for comparison
	scanResult := &models.SecurityScanResult{ // Use models type
		Target:        "test-image",  // Use Target
		Scanner:       "MockScanner", // Use Scanner
		ScanTimestamp: now,           // Use ScanTimestamp
		Vulnerabilities: []models.Vulnerability{ // Use models type
			{
				ID: "CVE-2023-1234",
				// Title:        "Test Vulnerability", // Title not in model
				Description: "This is a test vulnerability",
				PackageName: "test-package", // Use PackageName
				Version:     "1.0.0",
				FixVersion:  "1.0.1", // Use FixVersion
				Severity:    "HIGH",  // Use string severity
				// URLs, CVSSScore not needed for this mock
			},
		},
		// Summary can be added if needed for the test
	}

	// Convert to JSON directly using json.Marshal
	jsonData, err := json.Marshal(scanResult)

	// Assert that no error occurred
	assert.NoError(t, err)

	// Parse the JSON back
	var parsedResult models.SecurityScanResult // Use models type
	err = json.Unmarshal(jsonData, &parsedResult)

	// Assert that no error occurred
	assert.NoError(t, err)

	// Assert that the parsed result is correct
	assert.Equal(t, scanResult.Target, parsedResult.Target)   // Check Target
	assert.Equal(t, scanResult.Scanner, parsedResult.Scanner) // Check Scanner
	// Use assert.WithinDuration for time comparison due to potential precision differences
	assert.WithinDuration(t, scanResult.ScanTimestamp, parsedResult.ScanTimestamp, time.Second)
	assert.Len(t, parsedResult.Vulnerabilities, 1)
	assert.Equal(t, scanResult.Vulnerabilities[0].ID, parsedResult.Vulnerabilities[0].ID)
	assert.Equal(t, scanResult.Vulnerabilities[0].Severity, parsedResult.Vulnerabilities[0].Severity)
}

func TestUpdateScanSummary(t *testing.T) {
	// Create a scan result with vulnerabilities of different severities using models types
	scanResult := &models.SecurityScanResult{ // Use models type
		Vulnerabilities: []models.Vulnerability{ // Use models type
			{
				ID:         "CVE-2023-1234",
				Severity:   "CRITICAL", // Use string severity
				FixVersion: "1.0.1",
			},
			{
				ID:         "CVE-2023-5678",
				Severity:   "HIGH", // Use string severity
				FixVersion: "1.0.1",
			},
			{
				ID:         "CVE-2023-9012",
				Severity:   "MEDIUM", // Use string severity
				FixVersion: "",
			},
			{
				ID:         "CVE-2023-3456",
				Severity:   "LOW", // Use string severity
				FixVersion: "1.0.1",
			},
			{
				ID:         "CVE-2023-7890",
				Severity:   "UNKNOWN", // Use string severity
				FixVersion: "",
			},
		},
	}

	// Update the summary
	updateScanSummary(scanResult)

	// Assert that the summary is correct
	assert.Equal(t, 5, scanResult.Summary.TotalVulnerabilities) // Check TotalVulnerabilities
	assert.Equal(t, 1, scanResult.Summary.CriticalCount)
	assert.Equal(t, 1, scanResult.Summary.HighCount)
	assert.Equal(t, 1, scanResult.Summary.MediumCount)
	assert.Equal(t, 1, scanResult.Summary.LowCount)
	assert.Equal(t, 1, scanResult.Summary.UnknownCount)
	// FixableCount is not calculated by updateScanSummary anymore
	// assert.Equal(t, 3, scanResult.Summary.FixableCount)
}
