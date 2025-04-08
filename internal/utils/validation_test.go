package utils

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidationError(t *testing.T) {
	err := &ValidationError{
		Field:   "test",
		Code:    "TEST_ERROR",
		Message: "Test error message",
	}

	assert.Equal(t, "test: Test error message", err.Error())
}

func TestValidationResult(t *testing.T) {
	result := NewValidationResult()

	// Should be valid initially
	assert.True(t, result.IsValid())
	assert.Empty(t, result.GetErrors())
	assert.Nil(t, result.First())

	// Add an error
	result.AddError("field1", "ERROR1", "Error 1")

	// Should now be invalid
	assert.False(t, result.IsValid())
	assert.Len(t, result.GetErrors(), 1)
	assert.Equal(t, "field1", result.First().Field)
	assert.Equal(t, "ERROR1", result.First().Code)
	assert.Equal(t, "Error 1", result.First().Message)

	// Add another error
	result.AddError("field2", "ERROR2", "Error 2")

	// Should still be invalid
	assert.False(t, result.IsValid())
	assert.Len(t, result.GetErrors(), 2)
	assert.Equal(t, "field1", result.First().Field)
}

func TestValidateImageName(t *testing.T) {
	tests := []struct {
		name      string
		imageName string
		options   ValidationOptions
		wantErr   bool
		errCode   string
	}{
		{
			name:      "Valid simple image name",
			imageName: "ubuntu",
			wantErr:   false,
		},
		{
			name:      "Valid image name with tag",
			imageName: "ubuntu:20.04",
			wantErr:   false,
		},
		{
			name:      "Valid image name with repository",
			imageName: "docker_test.io/library/ubuntu",
			wantErr:   false,
		},
		{
			name:      "Valid image name with port and tag",
			imageName: "localhost:5000/myapp:latest",
			wantErr:   false,
		},
		{
			name:      "Valid image name with digest",
			imageName: "ubuntu@sha256:1234567890abcdef",
			wantErr:   false,
		},
		{
			name:      "Empty image name",
			imageName: "",
			wantErr:   true,
			errCode:   "REQUIRED",
		},
		{
			name:      "Empty image name allowed",
			imageName: "",
			options:   ValidationOptions{Required: false},
			wantErr:   false,
		},
		{
			name:      "Too long image name",
			imageName: "a" + strings.Repeat("b", 300),
			wantErr:   true,
			errCode:   "TOO_LONG",
		},
		{
			name:      "Invalid image name with spaces",
			imageName: "invalid image",
			wantErr:   true,
			errCode:   "INVALID_FORMAT",
		},
		{
			name:      "Invalid image name with special chars",
			imageName: "invalid$image",
			wantErr:   true,
			errCode:   "INVALID_FORMAT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateImageName(tt.imageName, tt.options)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCode != "" {
					assert.Equal(t, tt.errCode, err.(*ValidationError).Code)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateContainerName(t *testing.T) {
	tests := []struct {
		name          string
		containerName string
		options       ValidationOptions
		wantErr       bool
		errCode       string
	}{
		{
			name:          "Valid container name",
			containerName: "my-container",
			wantErr:       false,
		},
		{
			name:          "Valid container name with underscore",
			containerName: "my_container",
			wantErr:       false,
		},
		{
			name:          "Valid container name with period",
			containerName: "my.container",
			wantErr:       false,
		},
		{
			name:          "Empty container name",
			containerName: "",
			wantErr:       true,
			errCode:       "REQUIRED",
		},
		{
			name:          "Empty container name allowed",
			containerName: "",
			options:       ValidationOptions{Required: false},
			wantErr:       false,
		},
		{
			name:          "Too long container name",
			containerName: "a" + strings.Repeat("b", 300),
			wantErr:       true,
			errCode:       "TOO_LONG",
		},
		{
			name:          "Invalid container name starting with symbol",
			containerName: "-container",
			wantErr:       true,
			errCode:       "INVALID_FORMAT",
		},
		{
			name:          "Invalid container name with spaces",
			containerName: "invalid container",
			wantErr:       true,
			errCode:       "INVALID_FORMAT",
		},
		{
			name:          "Invalid container name with special chars",
			containerName: "invalid$container",
			wantErr:       true,
			errCode:       "INVALID_FORMAT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContainerName(tt.containerName, tt.options)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCode != "" {
					assert.Equal(t, tt.errCode, err.(*ValidationError).Code)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateVolumeName(t *testing.T) {
	tests := []struct {
		name       string
		volumeName string
		options    ValidationOptions
		wantErr    bool
		errCode    string
	}{
		{
			name:       "Valid volume name",
			volumeName: "my-volume",
			wantErr:    false,
		},
		{
			name:       "Valid volume name with underscore",
			volumeName: "my_volume",
			wantErr:    false,
		},
		{
			name:       "Valid volume name with period",
			volumeName: "my.volume",
			wantErr:    false,
		},
		{
			name:       "Empty volume name",
			volumeName: "",
			wantErr:    true,
			errCode:    "REQUIRED",
		},
		{
			name:       "Empty volume name allowed",
			volumeName: "",
			options:    ValidationOptions{Required: false},
			wantErr:    false,
		},
		{
			name:       "Too long volume name",
			volumeName: "a" + strings.Repeat("b", 300),
			wantErr:    true,
			errCode:    "TOO_LONG",
		},
		{
			name:       "Invalid volume name starting with symbol",
			volumeName: "-volume",
			wantErr:    true,
			errCode:    "INVALID_FORMAT",
		},
		{
			name:       "Invalid volume name with spaces",
			volumeName: "invalid volume",
			wantErr:    true,
			errCode:    "INVALID_FORMAT",
		},
		{
			name:       "Invalid volume name with special chars",
			volumeName: "invalid$volume",
			wantErr:    true,
			errCode:    "INVALID_FORMAT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateVolumeName(tt.volumeName, tt.options)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCode != "" {
					assert.Equal(t, tt.errCode, err.(*ValidationError).Code)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateNetworkName(t *testing.T) {
	tests := []struct {
		name        string
		networkName string
		options     ValidationOptions
		wantErr     bool
		errCode     string
	}{
		{
			name:        "Valid network name",
			networkName: "my-network",
			wantErr:     false,
		},
		{
			name:        "Valid network name with underscore",
			networkName: "my_network",
			wantErr:     false,
		},
		{
			name:        "Valid network name with period",
			networkName: "my.network",
			wantErr:     false,
		},
		{
			name:        "Empty network name",
			networkName: "",
			wantErr:     true,
			errCode:     "REQUIRED",
		},
		{
			name:        "Empty network name allowed",
			networkName: "",
			options:     ValidationOptions{Required: false},
			wantErr:     false,
		},
		{
			name:        "Too long network name",
			networkName: "a" + strings.Repeat("b", 300),
			wantErr:     true,
			errCode:     "TOO_LONG",
		},
		{
			name:        "Invalid network name starting with symbol",
			networkName: "-network",
			wantErr:     true,
			errCode:     "INVALID_FORMAT",
		},
		{
			name:        "Invalid network name with spaces",
			networkName: "invalid network",
			wantErr:     true,
			errCode:     "INVALID_FORMAT",
		},
		{
			name:        "Invalid network name with special chars",
			networkName: "invalid$network",
			wantErr:     true,
			errCode:     "INVALID_FORMAT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNetworkName(tt.networkName, tt.options)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCode != "" {
					assert.Equal(t, tt.errCode, err.(*ValidationError).Code)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		options ValidationOptions
		wantErr bool
		errCode string
	}{
		{
			name:    "Valid path",
			path:    "/var/lib/docker_test",
			wantErr: false,
		},
		{
			name:    "Empty path",
			path:    "",
			wantErr: true,
			errCode: "REQUIRED",
		},
		{
			name:    "Empty path allowed",
			path:    "",
			options: ValidationOptions{Required: false},
			wantErr: false,
		},
		{
			name:    "Too long path",
			path:    "/" + strings.Repeat("a/", 100),
			wantErr: true,
			errCode: "TOO_LONG",
		},
		{
			name:    "Path traversal",
			path:    "../../../etc/passwd",
			options: StrictOptions,
			wantErr: true,
			errCode: "PATH_TRAVERSAL",
		},
		{
			name:    "Path traversal allowed in non-strict mode",
			path:    "../../../etc/passwd",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path, tt.options)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCode != "" {
					assert.Equal(t, tt.errCode, err.(*ValidationError).Code)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		allowedSchemes []string
		options        ValidationOptions
		wantErr        bool
		errCode        string
	}{
		{
			name:    "Valid HTTP URL",
			url:     "http://example.com",
			wantErr: false,
		},
		{
			name:    "Valid HTTPS URL",
			url:     "https://example.com/path?query=1",
			wantErr: false,
		},
		{
			name:           "Valid URL with allowed scheme",
			url:            "https://example.com",
			allowedSchemes: []string{"https"},
			wantErr:        false,
		},
		{
			name:    "Empty URL",
			url:     "",
			wantErr: true,
			errCode: "REQUIRED",
		},
		{
			name:    "Empty URL allowed",
			url:     "",
			options: ValidationOptions{Required: false},
			wantErr: false,
		},
		{
			name:    "Invalid URL",
			url:     "not-a-url",
			wantErr: true,
			errCode: "INVALID_FORMAT",
		},
		{
			name:           "URL with disallowed scheme",
			url:            "ftp://example.com",
			allowedSchemes: []string{"http", "https"},
			wantErr:        true,
			errCode:        "INVALID_SCHEME",
		},
		{
			name:    "Too long URL",
			url:     "http://example.com/" + strings.Repeat("a", 300),
			wantErr: true,
			errCode: "TOO_LONG",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURL(tt.url, tt.allowedSchemes, tt.options)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCode != "" {
					assert.Equal(t, tt.errCode, err.(*ValidationError).Code)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
		errCode string
	}{
		{
			name:    "Valid port (low range)",
			port:    1,
			wantErr: false,
		},
		{
			name:    "Valid port (middle range)",
			port:    8080,
			wantErr: false,
		},
		{
			name:    "Valid port (high range)",
			port:    65535,
			wantErr: false,
		},
		{
			name:    "Invalid port (too low)",
			port:    0,
			wantErr: true,
			errCode: "INVALID_PORT",
		},
		{
			name:    "Invalid port (too high)",
			port:    65536,
			wantErr: true,
			errCode: "INVALID_PORT",
		},
		{
			name:    "Invalid port (negative)",
			port:    -1,
			wantErr: true,
			errCode: "INVALID_PORT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePort(tt.port)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCode != "" {
					assert.Equal(t, tt.errCode, err.(*ValidationError).Code)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePortString(t *testing.T) {
	tests := []struct {
		name    string
		port    string
		wantErr bool
		errCode string
	}{
		{
			name:    "Valid port",
			port:    "8080",
			wantErr: false,
		},
		{
			name:    "Empty port",
			port:    "",
			wantErr: true,
			errCode: "REQUIRED",
		},
		{
			name:    "Invalid port (not a number)",
			port:    "abc",
			wantErr: true,
			errCode: "INVALID_FORMAT",
		},
		{
			name:    "Invalid port (out of range)",
			port:    "70000",
			wantErr: true,
			errCode: "INVALID_PORT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePortString(tt.port)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCode != "" {
					assert.Equal(t, tt.errCode, err.(*ValidationError).Code)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateIPAddress(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		options ValidationOptions
		wantErr bool
		errCode string
	}{
		{
			name:    "Valid IPv4",
			ip:      "192.168.1.1",
			wantErr: false,
		},
		{
			name:    "Valid IPv6",
			ip:      "2001:db8::1",
			wantErr: false,
		},
		{
			name:    "Empty IP",
			ip:      "",
			wantErr: true,
			errCode: "REQUIRED",
		},
		{
			name:    "Empty IP allowed",
			ip:      "",
			options: ValidationOptions{Required: false},
			wantErr: false,
		},
		{
			name:    "Invalid IP",
			ip:      "not.an.ip.address",
			wantErr: true,
			errCode: "INVALID_FORMAT",
		},
		{
			name:    "Invalid IPv4 (incomplete)",
			ip:      "192.168.1",
			wantErr: true,
			errCode: "INVALID_FORMAT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPAddress(tt.ip, tt.options)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCode != "" {
					assert.Equal(t, tt.errCode, err.(*ValidationError).Code)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateJSONInput(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		maxDepth int
		options  ValidationOptions
		wantErr  bool
		errCode  string
	}{
		{
			name:    "Valid simple JSON",
			json:    `{"key": "value"}`,
			wantErr: false,
		},
		{
			name:    "Valid nested JSON",
			json:    `{"key": {"nested": {"deep": true}}}`,
			wantErr: false,
		},
		{
			name:     "Valid JSON with depth check",
			json:     `{"key": {"nested": {"deep": true}}}`,
			maxDepth: 3,
			wantErr:  false,
		},
		{
			name:    "Empty JSON",
			json:    "",
			wantErr: true,
			errCode: "REQUIRED",
		},
		{
			name:    "Empty JSON allowed",
			json:    "",
			options: ValidationOptions{Required: false},
			wantErr: false,
		},
		{
			name:    "Invalid JSON",
			json:    `{"key": "value"`,
			wantErr: true,
			errCode: "INVALID_FORMAT",
		},
		{
			name:     "JSON too deep",
			json:     `{"key": {"nested": {"deep": {"tooDeep": true}}}}`,
			maxDepth: 3,
			wantErr:  true,
			errCode:  "TOO_DEEP",
		},
		{
			name:    "Too long JSON",
			json:    `{"key": "` + strings.Repeat("a", 300) + `"}`,
			options: ValidationOptions{MaxLength: 100},
			wantErr: true,
			errCode: "TOO_LONG",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJSONInput(tt.json, tt.maxDepth, tt.options)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCode != "" {
					assert.Equal(t, tt.errCode, err.(*ValidationError).Code)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateSecurityOpts(t *testing.T) {
	tests := []struct {
		name          string
		securityOpts  []string
		wantValid     bool
		wantErrorCode string
	}{
		{
			name:         "Valid seccomp profile",
			securityOpts: []string{"seccomp=profile.json"},
			wantValid:    true,
		},
		{
			name:         "Valid apparmor profile",
			securityOpts: []string{"apparmor=docker_test-default"},
			wantValid:    true,
		},
		{
			name:         "Valid no-new-privileges",
			securityOpts: []string{"no-new-privileges=true"},
			wantValid:    true,
		},
		{
			name: "Multiple valid options",
			securityOpts: []string{
				"seccomp=profile.json",
				"apparmor=docker_test-default",
				"no-new-privileges=true",
			},
			wantValid: true,
		},
		{
			name:          "Invalid format (no equals)",
			securityOpts:  []string{"seccomp"},
			wantValid:     false,
			wantErrorCode: "INVALID_FORMAT",
		},
		{
			name:          "Empty seccomp value",
			securityOpts:  []string{"seccomp="},
			wantValid:     false,
			wantErrorCode: "INVALID_VALUE",
		},
		{
			name:          "Empty apparmor value",
			securityOpts:  []string{"apparmor="},
			wantValid:     false,
			wantErrorCode: "INVALID_VALUE",
		},
		{
			name:          "Invalid no-new-privileges value",
			securityOpts:  []string{"no-new-privileges=yes"},
			wantValid:     false,
			wantErrorCode: "INVALID_VALUE",
		},
		{
			name:          "Mixed valid and invalid",
			securityOpts:  []string{"seccomp=profile.json", "apparmor=", "no-new-privileges=true"},
			wantValid:     false,
			wantErrorCode: "INVALID_VALUE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateSecurityOpts(tt.securityOpts)
			if tt.wantValid {
				assert.True(t, result.IsValid())
				assert.Empty(t, result.GetErrors())
			} else {
				assert.False(t, result.IsValid())
				assert.NotEmpty(t, result.GetErrors())
				if tt.wantErrorCode != "" {
					assert.Equal(t, tt.wantErrorCode, result.First().Code)
				}
			}
		})
	}
}

func TestGetJSONDepth(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		wantDepth int
	}{
		{
			name:      "Null value",
			json:      `null`,
			wantDepth: 0,
		},
		{
			name:      "Simple scalar",
			json:      `"value"`,
			wantDepth: 0,
		},
		{
			name:      "Simple object",
			json:      `{"key": "value"}`,
			wantDepth: 1,
		},
		{
			name:      "Simple array",
			json:      `["value1", "value2"]`,
			wantDepth: 1,
		},
		{
			name:      "Nested object",
			json:      `{"key": {"nested": "value"}}`,
			wantDepth: 2,
		},
		{
			name:      "Nested array",
			json:      `["value1", ["nested1", "nested2"]]`,
			wantDepth: 2,
		},
		{
			name:      "Complex nested structure",
			json:      `{"key1": {"nested1": {"deep1": "value"}}, "key2": [1, 2, [3, 4, [5, 6]]]}`,
			wantDepth: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var js interface{}
			err := json.Unmarshal([]byte(tt.json), &js)
			require.NoError(t, err)

			depth := getJSONDepth(js)
			assert.Equal(t, tt.wantDepth, depth)
		})
	}
}
