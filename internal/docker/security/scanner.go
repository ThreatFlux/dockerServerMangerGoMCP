// Package security provides container security scanning and secure default configurations
package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// Common errors
var (
	// ErrImageNotFound indicates the image was not found
	ErrImageNotFound = errors.New("image not found")

	// ErrScanFailed indicates that the scan failed
	ErrScanFailed = errors.New("scan failed")

	// ErrInvalidImage indicates an invalid image specification
	ErrInvalidImage = errors.New("invalid image specification")

	// ErrScannerNotAvailable indicates the scanner is not available
	ErrScannerNotAvailable = errors.New("security scanner not available")

	// ErrUnsupportedScanner indicates that the scanner type is not supported
	ErrUnsupportedScanner = errors.New("unsupported scanner type")
)

// Local type definitions removed, using types from internal/models/security.go

// Scanner is the interface that security scanners must implement
type Scanner interface {
	// Name returns the name of the scanner
	Name() string

	// Version returns the version of the scanner
	Version() string

	// IsAvailable checks if the scanner is available
	IsAvailable(ctx context.Context) bool

	// ScanImage scans an image and returns the results
	ScanImage(ctx context.Context, imageRef string, options ScanOptions) (*models.SecurityScanResult, error) // Use models type

	// ScanRunningContainer scans a running container and returns the results
	ScanRunningContainer(ctx context.Context, containerID string, options ScanOptions) (*models.SecurityScanResult, error) // Use models type
}

// ScanOptions defines options for scanning
type ScanOptions struct {
	// Timeout is the timeout for the scan
	Timeout time.Duration

	// Logger for logging
	Logger *logrus.Logger

	// OutputFormat is the format of the scan output (e.g., JSON, XML)
	OutputFormat string

	// IncludeLayers indicates whether to include layer information
	IncludeLayers bool

	// SeverityThreshold is the minimum severity to include in results
	SeverityThreshold string // Use string for severity threshold

	// MaxConcurrentScans is the maximum number of concurrent scans
	MaxConcurrentScans int

	// AdditionalFlags are additional scanner-specific flags
	AdditionalFlags map[string]string
}

// ScannerFactory creates scanners
type ScannerFactory interface {
	// Create creates a scanner of the specified type
	Create(scannerType string) (Scanner, error)
}

// defaultScannerFactory is the default scanner factory
type defaultScannerFactory struct{}

// Create creates a scanner of the specified type
func (f *defaultScannerFactory) Create(scannerType string) (Scanner, error) {
	switch strings.ToLower(scannerType) {
	case "trivy":
		return NewTrivyScanner(), nil
	case "clair":
		return NewClairScanner(), nil
	case "grype":
		return NewGrypeScanner(), nil
	case "mock":
		return NewMockScanner(), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedScanner, scannerType)
	}
}

// DefaultScannerFactory is the default scanner factory
var DefaultScannerFactory ScannerFactory = &defaultScannerFactory{}

// DockerScanClient defines the minimal interface needed by the SecurityManager
type DockerScanClient interface {
	ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error)
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
}

// SecurityManager manages security scanning and vulnerability management
type SecurityManager struct {
	// dockerClient is the Docker client interface
	dockerClient DockerScanClient // Use the interface

	// scanners holds the available scanners
	scanners map[string]Scanner

	// scannerFactory creates scanners
	scannerFactory ScannerFactory

	// scanLimiter limits the number of concurrent scans
	scanLimiter chan struct{}

	// logger is the logger
	logger *logrus.Logger

	// scanHistory holds the scan history
	scanHistory []*models.SecurityScanResult // Use models type

	// mu is a mutex for thread safety
	mu sync.Mutex
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(dockerClient DockerScanClient, options ...func(*SecurityManager)) *SecurityManager { // Accept the interface
	// If no client provided, try creating a default one
	if dockerClient == nil {
		defaultCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			// Log or handle error - cannot proceed without a client
			// For now, panic might be acceptable if a client is essential
			panic(fmt.Sprintf("failed to create default Docker client for SecurityManager: %v", err))
		}
		dockerClient = defaultCli
	}

	manager := &SecurityManager{
		dockerClient:   dockerClient, // Store the interface
		scanners:       make(map[string]Scanner),
		scannerFactory: DefaultScannerFactory,
		scanLimiter:    make(chan struct{}, 5), // Default to 5 concurrent scans
		logger:         logrus.New(),
		scanHistory:    make([]*models.SecurityScanResult, 0), // Use models type
	}

	// Apply options
	for _, option := range options {
		option(manager)
	}

	return manager
}

// WithLogger sets the logger
func WithLogger(logger *logrus.Logger) func(*SecurityManager) {
	return func(m *SecurityManager) {
		m.logger = logger
	}
}

// WithScannerFactory sets the scanner factory
func WithScannerFactory(factory ScannerFactory) func(*SecurityManager) {
	return func(m *SecurityManager) {
		m.scannerFactory = factory
	}
}

// WithMaxConcurrentScans sets the maximum number of concurrent scans
func WithMaxConcurrentScans(max int) func(*SecurityManager) {
	return func(m *SecurityManager) {
		m.scanLimiter = make(chan struct{}, max)
	}
}

// RegisterScanner registers a scanner
func (m *SecurityManager) RegisterScanner(scannerType string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.scanners[scannerType]; exists {
		return nil // Already registered
	}

	scanner, err := m.scannerFactory.Create(scannerType)
	if err != nil {
		return err
	}

	// Check if the scanner is available
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if !scanner.IsAvailable(ctx) {
		return fmt.Errorf("%w: %s", ErrScannerNotAvailable, scannerType)
	}

	m.scanners[scannerType] = scanner
	m.logger.WithFields(logrus.Fields{
		"scanner": scannerType,
		"version": scanner.Version(),
	}).Info("Registered security scanner")

	return nil
}

// GetAvailableScanners returns the available scanners
func (m *SecurityManager) GetAvailableScanners() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	scanners := make([]string, 0, len(m.scanners))
	for scannerType := range m.scanners {
		scanners = append(scanners, scannerType)
	}

	return scanners
}

// ScanImage scans an image
func (m *SecurityManager) ScanImage(ctx context.Context, imageRef string, scannerType string, options ScanOptions) (*models.SecurityScanResult, error) { // Use models type
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Validate image reference
	if imageRef == "" {
		return nil, fmt.Errorf("%w: empty reference", ErrInvalidImage)
	}

	// Check if the image exists
	imageInfo, _, err := m.dockerClient.ImageInspectWithRaw(ctx, imageRef)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrImageNotFound, imageRef)
		}
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	// Get the scanner
	m.mu.Lock()
	scanner, exists := m.scanners[scannerType]
	m.mu.Unlock()

	if !exists {
		// Try to register the scanner
		err := m.RegisterScanner(scannerType)
		if err != nil {
			return nil, err
		}

		m.mu.Lock()
		scanner = m.scanners[scannerType]
		m.mu.Unlock()
	}

	// Limit concurrent scans
	m.scanLimiter <- struct{}{}
	defer func() {
		<-m.scanLimiter
	}()

	// Log scan start
	logger.WithFields(logrus.Fields{
		"image_id":   imageInfo.ID,
		"image_name": imageRef,
		"scanner":    scannerType,
	}).Info("Starting image security scan")

	// Perform the scan
	scanResult, err := scanner.ScanImage(ctx, imageRef, options)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrScanFailed, err)
	}

	// Update scan result with image information
	scanResult.Target = imageRef // Use Target for image name/ref
	scanResult.ScanTimestamp = time.Now()
	scanResult.Scanner = scanner.Name()
	// ScannerVersion is not in the model

	// Calculate summary
	updateScanSummary(scanResult)

	// Log scan completion
	logger.WithFields(logrus.Fields{
		"image_id":            imageInfo.ID,
		"image_name":          imageRef,
		"scanner":             scannerType,
		"vulnerability_count": scanResult.Summary.TotalVulnerabilities, // Use TotalVulnerabilities
		"critical_count":      scanResult.Summary.CriticalCount,
		"high_count":          scanResult.Summary.HighCount,
	}).Info("Completed image security scan")

	// Store scan result in history
	m.mu.Lock()
	m.scanHistory = append(m.scanHistory, scanResult)
	m.mu.Unlock()

	return scanResult, nil
}

// ScanContainer scans a container
func (m *SecurityManager) ScanContainer(ctx context.Context, containerID string, scannerType string, options ScanOptions) (*models.SecurityScanResult, error) { // Use models type
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Validate container ID
	if containerID == "" {
		return nil, fmt.Errorf("empty container ID")
	}

	// Check if the container exists
	containerInfo, err := m.dockerClient.ContainerInspect(ctx, containerID)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, fmt.Errorf("container not found: %s", containerID)
		}
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	// Get the scanner
	m.mu.Lock()
	scanner, exists := m.scanners[scannerType]
	m.mu.Unlock()

	if !exists {
		// Try to register the scanner
		err := m.RegisterScanner(scannerType)
		if err != nil {
			return nil, err
		}

		m.mu.Lock()
		scanner = m.scanners[scannerType]
		m.mu.Unlock()
	}

	// Limit concurrent scans
	m.scanLimiter <- struct{}{}
	defer func() {
		<-m.scanLimiter
	}()

	// Log scan start
	logger.WithFields(logrus.Fields{
		"container_id": containerID,
		"image_id":     containerInfo.Image,
		"scanner":      scannerType,
	}).Info("Starting container security scan")

	// Perform the scan
	scanResult, err := scanner.ScanRunningContainer(ctx, containerID, options)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrScanFailed, err)
	}

	// Update scan result with container information
	scanResult.Target = containerID // Use Target for container ID
	scanResult.ScanTimestamp = time.Now()
	scanResult.Scanner = scanner.Name()
	// ScannerVersion is not in the model

	// Calculate summary
	updateScanSummary(scanResult)

	// Log scan completion
	logger.WithFields(logrus.Fields{
		"container_id":        containerID,
		"image_id":            containerInfo.Image,
		"scanner":             scannerType,
		"vulnerability_count": scanResult.Summary.TotalVulnerabilities, // Use TotalVulnerabilities
		"critical_count":      scanResult.Summary.CriticalCount,
		"high_count":          scanResult.Summary.HighCount,
	}).Info("Completed container security scan")

	// Store scan result in history
	m.mu.Lock()
	m.scanHistory = append(m.scanHistory, scanResult)
	m.mu.Unlock()

	return scanResult, nil
}

// GetScanHistory returns the scan history
func (m *SecurityManager) GetScanHistory() []*models.SecurityScanResult { // Use models type
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return a copy to avoid race conditions
	history := make([]*models.SecurityScanResult, len(m.scanHistory)) // Use models type
	copy(history, m.scanHistory)

	return history
}

// GetLatestScanResult returns the latest scan result for an image or container target
func (m *SecurityManager) GetLatestScanResult(target string) *models.SecurityScanResult { // Use models type, target can be image or container
	m.mu.Lock()
	defer m.mu.Unlock()

	var latest *models.SecurityScanResult // Use models type
	var latestTime time.Time

	for _, result := range m.scanHistory {
		// Check if the result's target matches the requested target (image or container)
		if result.Target == target && (latest == nil || result.ScanTimestamp.After(latestTime)) { // Use Target and ScanTimestamp
			latest = result
			latestTime = result.ScanTimestamp // Use ScanTimestamp
		}
	}

	return latest
}

// updateScanSummary updates the scan summary based on models.Vulnerability
func updateScanSummary(result *models.SecurityScanResult) { // Use models type
	summary := models.ScanSummary{ // Use models type
		TotalVulnerabilities: len(result.Vulnerabilities), // Use TotalVulnerabilities
	}

	for _, vuln := range result.Vulnerabilities {
		// Severity is now a string in the model
		switch strings.ToUpper(vuln.Severity) { // Compare uppercase severity string
		case "CRITICAL":
			summary.CriticalCount++
		case "HIGH":
			summary.HighCount++
		case "MEDIUM":
			summary.MediumCount++
		case "LOW":
			summary.LowCount++
		default:
			summary.UnknownCount++
		}

		// FixableCount is not directly in the model, remove this logic
		// if vuln.FixedVersion != "" {
		// 	summary.FixableCount++
		// }
	}

	result.Summary = summary
}

// MockScanner is a mock scanner for testing
type mockScanner struct{}

// NewMockScanner creates a new mock scanner
func NewMockScanner() Scanner {
	return &mockScanner{}
}

// Name returns the name of the scanner
func (s *mockScanner) Name() string {
	return "MockScanner"
}

// Version returns the version of the scanner
func (s *mockScanner) Version() string {
	return "1.0.0"
}

// IsAvailable checks if the scanner is available
func (s *mockScanner) IsAvailable(ctx context.Context) bool {
	return true
}

// ScanImage scans an image and returns the results
func (s *mockScanner) ScanImage(ctx context.Context, imageRef string, options ScanOptions) (*models.SecurityScanResult, error) { // Use models type
	// This is a mock implementation that returns sample data
	return &models.SecurityScanResult{ // Use models type
		Target:        imageRef,   // Set Target
		Scanner:       s.Name(),   // Set Scanner
		ScanTimestamp: time.Now(), // Set Timestamp
		Vulnerabilities: []models.Vulnerability{ // Use models type
			{
				ID: "CVE-2023-1234",
				// Title:        "Sample Vulnerability", // Title not in model
				Description: "This is a sample vulnerability for testing",
				PackageName: "sample-package", // Use PackageName
				Version:     "1.0.0",
				FixVersion:  "1.0.1",                                       // Use FixVersion
				Severity:    "HIGH",                                        // Use string severity
				URLs:        []string{"https://example.com/cve-2023-1234"}, // Use URLs
				// PublishedDate: time.Now().Add(-24 * time.Hour), // PublishedDate not in model
				// VectorString:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // VectorString not in model
				CVSSScore: 9.8, // Use CVSSScore
				// Path:          "", // Path not in model
			},
		},
		// Layers: []Layer{ // Layer not in model
		// 	{
		// 		ID:         "layer1",
		// 		DigestHash: "sha256:abcdef1234567890",
		// 		Size:       1024 * 1024,
		// 		CreatedBy:  "ADD file:1234 in /",
		// 	},
		// },
	}, nil
}

// ScanRunningContainer scans a running container and returns the results
func (s *mockScanner) ScanRunningContainer(ctx context.Context, containerID string, options ScanOptions) (*models.SecurityScanResult, error) { // Use models type
	// For the mock, we'll just use the same code as ScanImage
	// Note: ScanImage now expects imageRef, so we pass containerID as the target
	return s.ScanImage(ctx, containerID, options)
}

// TrivyScanner is a scanner that uses Trivy
type trivyScanner struct {
	httpClient *http.Client
	endpoint   string
}

// NewTrivyScanner creates a new Trivy scanner
func NewTrivyScanner() Scanner {
	return &trivyScanner{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		endpoint: "http://localhost:4954", // Default Trivy API endpoint
	}
}

// Name returns the name of the scanner
func (s *trivyScanner) Name() string {
	return "Trivy"
}

// Version returns the version of the scanner
func (s *trivyScanner) Version() string {
	return "0.41.0" // This should be dynamically determined in a real implementation
}

// IsAvailable checks if the scanner is available
func (s *trivyScanner) IsAvailable(ctx context.Context) bool {
	// In a real implementation, we would check if Trivy is installed
	// or if the Trivy API server is running
	req, err := http.NewRequestWithContext(ctx, "GET", s.endpoint+"/healthz", nil)
	if err != nil {
		return false
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// ScanImage scans an image and returns the results
func (s *trivyScanner) ScanImage(ctx context.Context, imageRef string, options ScanOptions) (*models.SecurityScanResult, error) { // Use models type
	// In a real implementation, we would call the Trivy API
	// or execute the Trivy command to scan the image
	// This is a simplified implementation
	url := fmt.Sprintf("%s/v1/scan?image=%s", s.endpoint, imageRef)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trivy scan failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse the Trivy output
	var result models.SecurityScanResult // Use models type
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ScanRunningContainer scans a running container and returns the results
func (s *trivyScanner) ScanRunningContainer(ctx context.Context, containerID string, options ScanOptions) (*models.SecurityScanResult, error) { // Use models type
	// In a real implementation, we would call the Trivy API
	// or execute the Trivy command to scan the running container
	// This is a simplified implementation
	url := fmt.Sprintf("%s/v1/scan?container=%s", s.endpoint, containerID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trivy scan failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse the Trivy output
	var result models.SecurityScanResult // Use models type
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ClairScanner is a scanner that uses Clair
type clairScanner struct {
	httpClient *http.Client
	endpoint   string
}

// NewClairScanner creates a new Clair scanner
func NewClairScanner() Scanner {
	return &clairScanner{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		endpoint: "http://localhost:6060", // Default Clair API endpoint
	}
}

// Name returns the name of the scanner
func (s *clairScanner) Name() string {
	return "Clair"
}

// Version returns the version of the scanner
func (s *clairScanner) Version() string {
	return "4.5.0" // This should be dynamically determined in a real implementation
}

// IsAvailable checks if the scanner is available
func (s *clairScanner) IsAvailable(ctx context.Context) bool {
	// In a real implementation, we would check if Clair is installed
	// or if the Clair API server is running
	req, err := http.NewRequestWithContext(ctx, "GET", s.endpoint+"/health", nil)
	if err != nil {
		return false
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// ScanImage scans an image and returns the results
func (s *clairScanner) ScanImage(ctx context.Context, imageRef string, options ScanOptions) (*models.SecurityScanResult, error) { // Use models type
	// In a real implementation, we would call the Clair API
	// to scan the image. This is a simplified implementation.
	// For now, we'll return a mock response
	return &models.SecurityScanResult{ // Use models type
		Target:        imageRef,   // Set Target
		Scanner:       s.Name(),   // Set Scanner
		ScanTimestamp: time.Now(), // Set Timestamp
		Vulnerabilities: []models.Vulnerability{ // Use models type
			{
				ID: "CVE-2023-5678",
				// Title:        "Sample Clair Vulnerability", // Title not in model
				Description: "This is a sample vulnerability from Clair",
				PackageName: "sample-package", // Use PackageName
				Version:     "1.0.0",
				FixVersion:  "1.0.1",                                       // Use FixVersion
				Severity:    "HIGH",                                        // Use string severity
				URLs:        []string{"https://example.com/cve-2023-5678"}, // Use URLs
				// PublishedDate: time.Now().Add(-48 * time.Hour), // PublishedDate not in model
				// VectorString:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // VectorString not in model
				CVSSScore: 9.8, // Use CVSSScore
				// Path:          "", // Path not in model
			},
		},
	}, nil
}

// ScanRunningContainer scans a running container and returns the results
func (s *clairScanner) ScanRunningContainer(ctx context.Context, containerID string, options ScanOptions) (*models.SecurityScanResult, error) { // Use models type
	// Clair doesn't directly support scanning running containers
	// We would need to get the image from the container and scan that
	return nil, fmt.Errorf("clair does not support direct container scanning")
}

// GrypeScanner is a scanner that uses Grype
type grypeScanner struct{}

// NewGrypeScanner creates a new Grype scanner
func NewGrypeScanner() Scanner {
	return &grypeScanner{}
}

// Name returns the name of the scanner
func (s *grypeScanner) Name() string {
	return "Grype"
}

// Version returns the version of the scanner
func (s *grypeScanner) Version() string {
	return "0.60.1" // This should be dynamically determined in a real implementation
}

// IsAvailable checks if the scanner is available
func (s *grypeScanner) IsAvailable(ctx context.Context) bool {
	// In a real implementation, we would check if Grype is installed
	// For now, we'll simply return true
	return true
}

// ScanImage scans an image and returns the results
func (s *grypeScanner) ScanImage(ctx context.Context, imageRef string, options ScanOptions) (*models.SecurityScanResult, error) { // Use models type
	// In a real implementation, we would execute the Grype command
	// to scan the image. This is a simplified implementation.
	// For now, we'll return a mock response
	return &models.SecurityScanResult{ // Use models type
		Target:        imageRef,   // Set Target
		Scanner:       s.Name(),   // Set Scanner
		ScanTimestamp: time.Now(), // Set Timestamp
		Vulnerabilities: []models.Vulnerability{ // Use models type
			{
				ID: "CVE-2023-9012",
				// Title:        "Sample Grype Vulnerability", // Title not in model
				Description: "This is a sample vulnerability from Grype",
				PackageName: "sample-package", // Use PackageName
				Version:     "1.0.0",
				FixVersion:  "1.0.1",                                       // Use FixVersion
				Severity:    "MEDIUM",                                      // Use string severity
				URLs:        []string{"https://example.com/cve-2023-9012"}, // Use URLs
				// PublishedDate: time.Now().Add(-72 * time.Hour), // PublishedDate not in model
				// VectorString:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:M/A:M", // VectorString not in model
				CVSSScore: 7.5, // Use CVSSScore
				// Path:          "", // Path not in model
			},
		},
	}, nil
}

// ScanRunningContainer scans a running container and returns the results
func (s *grypeScanner) ScanRunningContainer(ctx context.Context, containerID string, options ScanOptions) (*models.SecurityScanResult, error) { // Use models type
	// In a real implementation, we would execute the Grype command
	// to scan the running container. This is a simplified implementation.
	return s.ScanImage(ctx, "container:"+containerID, options)
}

// FormatScanResultString returns a string representation of a models.SecurityScanResult
func FormatScanResultString(r *models.SecurityScanResult) string { // Make it a function, use models type
	if r == nil {
		return "Scan result is nil"
	}
	return fmt.Sprintf("Scan of %s on %s: %d vulnerabilities (%d critical, %d high, %d medium, %d low, %d unknown)", // Use models fields
		r.Target, r.ScanTimestamp.Format(time.RFC3339), // Use Target, ScanTimestamp
		r.Summary.TotalVulnerabilities, r.Summary.CriticalCount, r.Summary.HighCount, // Use TotalVulnerabilities
		r.Summary.MediumCount, r.Summary.LowCount, r.Summary.UnknownCount) // FixableCount not in model
}
