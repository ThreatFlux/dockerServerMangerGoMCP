package models

import "time"

// RegistryAuth holds authentication details for a Docker registry.
type RegistryAuth struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	ServerAddress string `json:"server_address"`
	Email         string `json:"email,omitempty"`
	IdentityToken string `json:"identity_token,omitempty"`
	Auth          string `json:"auth,omitempty"` // Base64 encoded username:password
}

// Vulnerability represents a single security vulnerability found.
type Vulnerability struct {
	ID          string   `json:"id"`       // e.g., CVE-2023-1234
	Severity    string   `json:"severity"` // e.g., HIGH, MEDIUM, LOW, CRITICAL
	PackageName string   `json:"package_name"`
	Version     string   `json:"version"`
	FixVersion  string   `json:"fix_version,omitempty"`
	Description string   `json:"description,omitempty"`
	URLs        []string `json:"urls,omitempty"`       // Links to advisories, etc.
	CVSSScore   float64  `json:"cvss_score,omitempty"` // CVSS score if available
}

// ScanSummary provides a summary of the scan results.
type ScanSummary struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	CriticalCount        int `json:"critical_count"`
	HighCount            int `json:"high_count"`
	MediumCount          int `json:"medium_count"`
	LowCount             int `json:"low_count"`
	UnknownCount         int `json:"unknown_count"`
}

// SecurityScanResult holds the results of a security scan for an image or container.
type SecurityScanResult struct {
	Target          string          `json:"target"`  // e.g., image name, container ID
	Scanner         string          `json:"scanner"` // Name of the scanner used
	ScanTimestamp   time.Time       `json:"scan_timestamp"`
	Summary         ScanSummary     `json:"summary"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Error           string          `json:"error,omitempty"` // Any error during the scan
}
