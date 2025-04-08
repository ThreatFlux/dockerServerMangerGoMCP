package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/docker/docker/api/types"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

// Pre-compiled regular expressions for common validations
var (
	// Email regex must match standard email formats
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	// URL regex must match http/https URLs
	urlRegex = regexp.MustCompile(`^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$`)

	// File path regex must match valid file paths
	filePathRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\/\\]+$`)

	// Filename regex must match valid filenames
	filenameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

	// Docker image name validation
	// Based on Docker's image name validation
	imageNameRegex = regexp.MustCompile(`^(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))+)?(?::[0-9]+)?/)?[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?(?:(?:/[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?)+)?(?:[:@][a-zA-Z0-9][\w.-]+)?$`)

	// Docker container/volume/network name validation
	// Simplified version of Docker's name validation
	dockerNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`)

	// JSON Web Token regex must match JWT format (three base64url sections separated by dots)
	jwtRegex = regexp.MustCompile(`^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$`)

	// Username regex must match alphanumeric usernames with specific allowed characters
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{2,29}$`)

	// Removed strongPasswordRegex as Go's regexp doesn't support lookaheads.
	// Validation is handled within ValidatePassword function.
	// strongPasswordRegex = regexp.MustCompile(`...`)

	// IPv4 regex must match valid IPv4 addresses
	ipv4Regex = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)

	// IPv6 regex must match valid IPv6 addresses
	ipv6Regex = regexp.MustCompile(`^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$`)

	// CIDR regex must match valid CIDR notations
	cidrRegex = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[12][0-9]|3[0-2])$`)

	// Hostname regex must match valid hostnames
	hostnameRegex = regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)

	// Base64 regex must match valid base64 strings
	base64Regex = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

	// Hex string regex must match valid hexadecimal strings
	hexRegex = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// Removed init() block that compiled the problematic regex
// func init() {
// 	// Initialization logic if needed, e.g., for validator
// }

// ValidationError represents a validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"` // The invalid value (sanitized for sensitive fields)
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// IsSensitiveField checks if a field is sensitive and should not be logged
func IsSensitiveField(field string) bool {
	lowerField := strings.ToLower(field)
	sensitiveFields := []string{
		"password", "token", "secret", "key", "auth", "cred", "private",
	}

	for _, sensitive := range sensitiveFields {
		if strings.Contains(lowerField, sensitive) {
			return true
		}
	}

	return false
}

// SanitizeValue sanitizes a value for logging
func SanitizeValue(field string, value interface{}) string {
	// Don't include values for sensitive fields
	if IsSensitiveField(field) {
		return "[REDACTED]"
	}

	// Convert value to string for logging
	switch v := value.(type) {
	case string:
		// Truncate long strings
		if len(v) > 100 {
			return v[:97] + "..."
		}
		return v
	default:
		// Use reflection for other types
		return fmt.Sprintf("%v", value)
	}
}

// ValidationResult contains the result of a validation operation.
type ValidationResult struct {
	Errors []*ValidationError `json:"errors"`
}

// NewValidationResult creates a new ValidationResult.
func NewValidationResult() *ValidationResult {
	return &ValidationResult{
		Errors: []*ValidationError{},
	}
}

// AddError adds an error to the validation result.
func (vr *ValidationResult) AddError(field, code, message string, value ...interface{}) {
	var valueStr string
	if len(value) > 0 {
		valueStr = SanitizeValue(field, value[0])
	}

	vr.Errors = append(vr.Errors, &ValidationError{
		Field:   field,
		Code:    code,
		Message: message,
		Value:   valueStr,
	})
}

// IsValid returns true if the validation passed.
func (vr *ValidationResult) IsValid() bool {
	return len(vr.Errors) == 0
}

// GetErrors returns all validation errors.
func (vr *ValidationResult) GetErrors() []*ValidationError {
	return vr.Errors
}

// First returns the first error or nil if there are no errors.
func (vr *ValidationResult) First() *ValidationError {
	if len(vr.Errors) == 0 {
		return nil
	}
	return vr.Errors[0]
}

// ErrorMessages returns all error messages.
func (vr *ValidationResult) ErrorMessages() []string {
	messages := make([]string, len(vr.Errors))
	for i, err := range vr.Errors {
		messages[i] = err.Error()
	}
	return messages
}

// ErrorsByField returns a map of field names to error messages.
func (vr *ValidationResult) ErrorsByField() map[string]string {
	errors := make(map[string]string)
	for _, err := range vr.Errors {
		errors[err.Field] = err.Message
	}
	return errors
}

// MergeResults merges the errors from another ValidationResult into this one.
func (vr *ValidationResult) MergeResults(other *ValidationResult) {
	vr.Errors = append(vr.Errors, other.Errors...)
}

// ToJSON returns the validation result as a JSON string.
func (vr *ValidationResult) ToJSON() (string, error) {
	bytes, err := json.Marshal(vr)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// ValidationOptions contains options for validation.
type ValidationOptions struct {
	// MaxLength is the maximum allowed length
	MaxLength int

	// MinLength is the minimum allowed length
	MinLength int

	// Required specifies if the value is required
	Required bool

	// StrictMode enables stricter validation rules
	StrictMode bool

	// AllowedValues is a list of allowed values
	AllowedValues []string

	// DisallowedValues is a list of disallowed values
	DisallowedValues []string

	// CustomValidation is a custom validation function
	CustomValidation func(interface{}) error

	// SanitizeOutput determines if output should be sanitized
	SanitizeOutput bool
}

// Default validation options
var (
	DefaultOptions = ValidationOptions{
		MaxLength:  256,
		MinLength:  1,
		Required:   true,
		StrictMode: false,
	}

	StrictOptions = ValidationOptions{
		MaxLength:  256,
		MinLength:  1,
		Required:   true,
		StrictMode: true,
	}

	SecurityOptions = ValidationOptions{
		MaxLength:      64,
		MinLength:      8,
		Required:       true,
		StrictMode:     true,
		SanitizeOutput: true,
	}
)

// getOptions returns the validation options, using defaults if not provided
func getOptions(options []ValidationOptions) ValidationOptions {
	if len(options) > 0 {
		return options[0]
	}
	return DefaultOptions
}

// ValidateImageName validates a Docker image name.
func ValidateImageName(name string, options ...ValidationOptions) error {
	opts := getOptions(options)

	if name == "" && opts.Required {
		return &ValidationError{
			Field:   "imageName",
			Code:    "REQUIRED",
			Message: "Image name is required",
		}
	}

	if name == "" && !opts.Required {
		return nil
	}

	if len(name) > opts.MaxLength {
		return &ValidationError{
			Field:   "imageName",
			Code:    "TOO_LONG",
			Message: fmt.Sprintf("Image name exceeds maximum length of %d", opts.MaxLength),
			Value:   name,
		}
	}

	if len(name) < opts.MinLength {
		return &ValidationError{
			Field:   "imageName",
			Code:    "TOO_SHORT",
			Message: fmt.Sprintf("Image name is shorter than minimum length of %d", opts.MinLength),
			Value:   name,
		}
	}

	if !imageNameRegex.MatchString(name) {
		return &ValidationError{
			Field:   "imageName",
			Code:    "INVALID_FORMAT",
			Message: "Invalid image name format. Must follow Docker's image naming convention",
			Value:   name,
		}
	}

	// Check for known security issues in image names
	if opts.StrictMode {
		// Check for latest tag which is not recommended for production
		if strings.HasSuffix(name, ":latest") {
			return &ValidationError{
				Field:   "imageName",
				Code:    "SECURITY_RISK",
				Message: "Using 'latest' tag is not recommended for production as it can lead to inconsistent deployments",
				Value:   name,
			}
		}

		// Check for known malicious image prefixes or names (this list should be updated regularly)
		blacklistedPrefixes := []string{"malware/", "exploit/", "trojan/"}
		for _, prefix := range blacklistedPrefixes {
			if strings.HasPrefix(name, prefix) {
				return &ValidationError{
					Field:   "imageName",
					Code:    "SECURITY_RISK",
					Message: "Image name matches known malicious pattern",
					Value:   name,
				}
			}
		}
	}

	return nil
}

// ValidateContainerName validates a container name.
func ValidateContainerName(name string, options ...ValidationOptions) error {
	opts := getOptions(options)

	if name == "" && opts.Required {
		return &ValidationError{
			Field:   "containerName",
			Code:    "REQUIRED",
			Message: "Container name is required",
		}
	}

	if name == "" && !opts.Required {
		return nil
	}

	if len(name) > opts.MaxLength {
		return &ValidationError{
			Field:   "containerName",
			Code:    "TOO_LONG",
			Message: fmt.Sprintf("Container name exceeds maximum length of %d", opts.MaxLength),
			Value:   name,
		}
	}

	if len(name) < opts.MinLength {
		return &ValidationError{
			Field:   "containerName",
			Code:    "TOO_SHORT",
			Message: fmt.Sprintf("Container name is shorter than minimum length of %d", opts.MinLength),
			Value:   name,
		}
	}

	if !dockerNameRegex.MatchString(name) {
		return &ValidationError{
			Field:   "containerName",
			Code:    "INVALID_FORMAT",
			Message: "Invalid container name format. Container names must start with a letter or number and can contain only alphanumeric characters, hyphens, underscores, and periods",
			Value:   name,
		}
	}

	// Check for reserved system names in strict mode
	if opts.StrictMode {
		reservedNames := []string{"default", "host", "none", "bridge", "system"}
		for _, reserved := range reservedNames {
			if strings.EqualFold(name, reserved) {
				return &ValidationError{
					Field:   "containerName",
					Code:    "RESERVED_NAME",
					Message: fmt.Sprintf("'%s' is a reserved name and cannot be used for containers", name),
					Value:   name,
				}
			}
		}
	}

	return nil
}

// ValidateVolumeName validates a volume name.
func ValidateVolumeName(name string, options ...ValidationOptions) error {
	opts := getOptions(options)

	if name == "" && opts.Required {
		return &ValidationError{
			Field:   "volumeName",
			Code:    "REQUIRED",
			Message: "Volume name is required",
		}
	}

	if name == "" && !opts.Required {
		return nil
	}

	if len(name) > opts.MaxLength {
		return &ValidationError{
			Field:   "volumeName",
			Code:    "TOO_LONG",
			Message: fmt.Sprintf("Volume name exceeds maximum length of %d", opts.MaxLength),
			Value:   name,
		}
	}

	if len(name) < opts.MinLength {
		return &ValidationError{
			Field:   "volumeName",
			Code:    "TOO_SHORT",
			Message: fmt.Sprintf("Volume name is shorter than minimum length of %d", opts.MinLength),
			Value:   name,
		}
	}

	if !dockerNameRegex.MatchString(name) {
		return &ValidationError{
			Field:   "volumeName",
			Code:    "INVALID_FORMAT",
			Message: "Invalid volume name format. Volume names must start with a letter or number and can contain only alphanumeric characters, hyphens, underscores, and periods",
			Value:   name,
		}
	}

	// Check for reserved volume names
	reservedNames := []string{".", "..", "volume"}
	for _, reserved := range reservedNames {
		if strings.EqualFold(name, reserved) {
			return &ValidationError{
				Field:   "volumeName",
				Code:    "RESERVED_NAME",
				Message: fmt.Sprintf("'%s' is a reserved name and cannot be used for volumes", name),
				Value:   name,
			}
		}
	}

	return nil
}

// ValidateNetworkName validates a network name.
func ValidateNetworkName(name string, options ...ValidationOptions) error {
	opts := getOptions(options)

	if name == "" && opts.Required {
		return &ValidationError{
			Field:   "networkName",
			Code:    "REQUIRED",
			Message: "Network name is required",
		}
	}

	if name == "" && !opts.Required {
		return nil
	}

	if len(name) > opts.MaxLength {
		return &ValidationError{
			Field:   "networkName",
			Code:    "TOO_LONG",
			Message: fmt.Sprintf("Network name exceeds maximum length of %d", opts.MaxLength),
			Value:   name,
		}
	}

	if len(name) < opts.MinLength {
		return &ValidationError{
			Field:   "networkName",
			Code:    "TOO_SHORT",
			Message: fmt.Sprintf("Network name is shorter than minimum length of %d", opts.MinLength),
			Value:   name,
		}
	}

	if !dockerNameRegex.MatchString(name) {
		return &ValidationError{
			Field:   "networkName",
			Code:    "INVALID_FORMAT",
			Message: "Invalid network name format. Network names must start with a letter or number and can contain only alphanumeric characters, hyphens, underscores, and periods",
			Value:   name,
		}
	}

	// Check for reserved network names
	reservedNames := []string{"host", "bridge", "none", "default"}
	for _, reserved := range reservedNames {
		if strings.EqualFold(name, reserved) {
			return &ValidationError{
				Field:   "networkName",
				Code:    "RESERVED_NAME",
				Message: fmt.Sprintf("'%s' is a reserved name and cannot be used for custom networks", name),
				Value:   name,
			}
		}
	}

	return nil
}

// ValidatePath validates a file path.
func ValidatePath(path string, options ...ValidationOptions) error {
	opts := getOptions(options)

	if path == "" && opts.Required {
		return &ValidationError{
			Field:   "path",
			Code:    "REQUIRED",
			Message: "Path is required",
		}
	}

	if path == "" && !opts.Required {
		return nil
	}

	if len(path) > opts.MaxLength {
		return &ValidationError{
			Field:   "path",
			Code:    "TOO_LONG",
			Message: fmt.Sprintf("Path exceeds maximum length of %d", opts.MaxLength),
			Value:   path,
		}
	}

	// Clean the path
	cleaned := filepath.Clean(path)

	// Check for path traversal
	if opts.StrictMode && (strings.Contains(cleaned, "..") || strings.Contains(path, "..")) {
		return &ValidationError{
			Field:   "path",
			Code:    "PATH_TRAVERSAL",
			Message: "Path contains path traversal sequences which poses a security risk",
			Value:   path,
		}
	}

	// Check for absolute paths in strict mode (can be a security risk in some contexts)
	if opts.StrictMode && (filepath.IsAbs(cleaned) || path[0] == '/' || path[0] == '\\') {
		return &ValidationError{
			Field:   "path",
			Code:    "ABSOLUTE_PATH",
			Message: "Absolute paths are not allowed in this context for security reasons",
			Value:   path,
		}
	}

	// Validate path format
	if !filePathRegex.MatchString(path) {
		return &ValidationError{
			Field:   "path",
			Code:    "INVALID_FORMAT",
			Message: "Path contains invalid characters",
			Value:   path,
		}
	}

	return nil
}

// ValidateFilename validates a filename.
func ValidateFilename(filename string, options ...ValidationOptions) error {
	opts := getOptions(options)

	if filename == "" && opts.Required {
		return &ValidationError{
			Field:   "filename",
			Code:    "REQUIRED",
			Message: "Filename is required",
		}
	}

	if filename == "" && !opts.Required {
		return nil
	}

	if len(filename) > opts.MaxLength {
		return &ValidationError{
			Field:   "filename",
			Code:    "TOO_LONG",
			Message: fmt.Sprintf("Filename exceeds maximum length of %d", opts.MaxLength),
			Value:   filename,
		}
	}

	// Check if filename contains path components
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return &ValidationError{
			Field:   "filename",
			Code:    "INVALID_FORMAT",
			Message: "Filename cannot contain path separators",
			Value:   filename,
		}
	}

	// Check if filename has valid format
	if !filenameRegex.MatchString(filename) {
		return &ValidationError{
			Field:   "filename",
			Code:    "INVALID_FORMAT",
			Message: "Filename contains invalid characters",
			Value:   filename,
		}
	}

	return nil
}

// ValidateURL validates a URL.
func ValidateURL(rawURL string, allowedSchemes []string, options ...ValidationOptions) error {
	opts := getOptions(options)

	if rawURL == "" && opts.Required {
		return &ValidationError{
			Field:   "url",
			Code:    "REQUIRED",
			Message: "URL is required",
		}
	}

	if rawURL == "" && !opts.Required {
		return nil
	}

	if len(rawURL) > opts.MaxLength {
		return &ValidationError{
			Field:   "url",
			Code:    "TOO_LONG",
			Message: fmt.Sprintf("URL exceeds maximum length of %d", opts.MaxLength),
			Value:   rawURL,
		}
	}

	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return &ValidationError{
			Field:   "url",
			Code:    "INVALID_FORMAT",
			Message: "Invalid URL format: " + err.Error(),
			Value:   rawURL,
		}
	}

	// Check for scheme
	if parsedURL.Scheme == "" {
		return &ValidationError{
			Field:   "url",
			Code:    "MISSING_SCHEME",
			Message: "URL must have a scheme (e.g., http, https)",
			Value:   rawURL,
		}
	}

	// If allowed schemes are specified, check if the URL scheme is allowed
	if len(allowedSchemes) > 0 {
		schemeAllowed := false
		for _, scheme := range allowedSchemes {
			if parsedURL.Scheme == scheme {
				schemeAllowed = true
				break
			}
		}

		if !schemeAllowed {
			return &ValidationError{
				Field:   "url",
				Code:    "INVALID_SCHEME",
				Message: fmt.Sprintf("URL scheme '%s' is not allowed. Allowed schemes: %s", parsedURL.Scheme, strings.Join(allowedSchemes, ", ")),
				Value:   rawURL,
			}
		}
	}

	// Check for host
	if parsedURL.Host == "" {
		return &ValidationError{
			Field:   "url",
			Code:    "MISSING_HOST",
			Message: "URL must have a host",
			Value:   rawURL,
		}
	}

	// In strict mode, perform additional security checks
	if opts.StrictMode {
		// Check for IP literal hosts which can be used for SSRF attacks
		host := parsedURL.Hostname()
		if ipRegex := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`); ipRegex.MatchString(host) {
			// Check for private IP ranges
			ip := net.ParseIP(host)
			if ip != nil && (isPrivateIP(ip) || isLoopbackIP(ip) || isLinkLocalIP(ip)) {
				return &ValidationError{
					Field:   "url",
					Code:    "SECURITY_RISK",
					Message: "URL with private, loopback, or link-local IP address is not allowed",
					Value:   rawURL,
				}
			}
		}

		// Check for localhost
		if strings.Contains(parsedURL.Host, "localhost") || strings.Contains(parsedURL.Host, "127.0.0.1") || parsedURL.Host == "::1" {
			return &ValidationError{
				Field:   "url",
				Code:    "SECURITY_RISK",
				Message: "URL with localhost address is not allowed",
				Value:   rawURL,
			}
		}
	}

	return nil
}

// ValidatePort validates a port number.
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return &ValidationError{
			Field:   "port",
			Code:    "INVALID_PORT",
			Message: "Port must be between 1 and 65535",
			Value:   strconv.Itoa(port),
		}
	}

	return nil
}

// ValidatePortString validates a port number as a string.
func ValidatePortString(port string) error {
	if port == "" {
		return &ValidationError{
			Field:   "port",
			Code:    "REQUIRED",
			Message: "Port is required",
		}
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return &ValidationError{
			Field:   "port",
			Code:    "INVALID_FORMAT",
			Message: "Port must be a valid number",
			Value:   port,
		}
	}

	return ValidatePort(portNum)
}

// ValidateIPAddress validates an IP address.
func ValidateIPAddress(ip string, options ...ValidationOptions) error {
	opts := getOptions(options)

	if ip == "" && opts.Required {
		return &ValidationError{
			Field:   "ipAddress",
			Code:    "REQUIRED",
			Message: "IP address is required",
		}
	}

	if ip == "" && !opts.Required {
		return nil
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return &ValidationError{
			Field:   "ipAddress",
			Code:    "INVALID_FORMAT",
			Message: "Invalid IP address format",
			Value:   ip,
		}
	}

	// In strict mode, check for private/loopback IPs
	if opts.StrictMode && (isPrivateIP(parsedIP) || isLoopbackIP(parsedIP)) {
		return &ValidationError{
			Field:   "ipAddress",
			Code:    "SECURITY_RISK",
			Message: "Private or loopback IP addresses are not allowed in this context",
			Value:   ip,
		}
	}

	return nil
}

// ValidateEmail validates an email address.
func ValidateEmail(email string, options ...ValidationOptions) error {
	opts := getOptions(options)

	if email == "" && opts.Required {
		return &ValidationError{
			Field:   "email",
			Code:    "REQUIRED",
			Message: "Email address is required",
		}
	}

	if email == "" && !opts.Required {
		return nil
	}

	if len(email) > opts.MaxLength {
		return &ValidationError{
			Field:   "email",
			Code:    "TOO_LONG",
			Message: fmt.Sprintf("Email address exceeds maximum length of %d", opts.MaxLength),
			Value:   email,
		}
	}

	if !emailRegex.MatchString(email) {
		return &ValidationError{
			Field:   "email",
			Code:    "INVALID_FORMAT",
			Message: "Invalid email address format",
			Value:   email,
		}
	}

	return nil
}

// ValidateUsername validates a username.
func ValidateUsername(username string, options ...ValidationOptions) error {
	opts := getOptions(options)

	if username == "" && opts.Required {
		return &ValidationError{
			Field:   "username",
			Code:    "REQUIRED",
			Message: "Username is required",
		}
	}

	if username == "" && !opts.Required {
		return nil
	}

	if len(username) > opts.MaxLength {
		return &ValidationError{
			Field:   "username",
			Code:    "TOO_LONG",
			Message: fmt.Sprintf("Username exceeds maximum length of %d", opts.MaxLength),
			Value:   username,
		}
	}

	if len(username) < opts.MinLength {
		return &ValidationError{
			Field:   "username",
			Code:    "TOO_SHORT",
			Message: fmt.Sprintf("Username is shorter than minimum length of %d", opts.MinLength),
			Value:   username,
		}
	}

	if !usernameRegex.MatchString(username) {
		return &ValidationError{
			Field:   "username",
			Code:    "INVALID_FORMAT",
			Message: "Username must start with a letter or number and can contain only alphanumeric characters, dots, underscores, and hyphens",
			Value:   username,
		}
	}

	return nil
}

// ValidatePassword validates a password.
func ValidatePassword(password string, options ...ValidationOptions) error {
	opts := getOptions(options)

	if password == "" && opts.Required {
		return &ValidationError{
			Field:   "password",
			Code:    "REQUIRED",
			Message: "Password is required",
		}
	}

	if password == "" && !opts.Required {
		return nil
	}

	if len(password) > opts.MaxLength {
		return &ValidationError{
			Field:   "password",
			Code:    "TOO_LONG",
			Message: fmt.Sprintf("Password exceeds maximum length of %d", opts.MaxLength),
			Value:   "[REDACTED]",
		}
	}

	if len(password) < opts.MinLength {
		return &ValidationError{
			Field:   "password",
			Code:    "TOO_SHORT",
			Message: fmt.Sprintf("Password is shorter than minimum length of %d", opts.MinLength),
			Value:   "[REDACTED]",
		}
	}

	// In strict mode, check for password strength
	if opts.StrictMode {
		hasUpper := false
		hasLower := false
		hasDigit := false
		hasSpecial := false

		for _, c := range password {
			switch {
			case unicode.IsUpper(c):
				hasUpper = true
			case unicode.IsLower(c):
				hasLower = true
			case unicode.IsDigit(c):
				hasDigit = true
			case unicode.IsPunct(c) || unicode.IsSymbol(c):
				hasSpecial = true
			}
		}

		if !hasUpper {
			return &ValidationError{
				Field:   "password",
				Code:    "MISSING_UPPERCASE",
				Message: "Password must contain at least one uppercase letter",
				Value:   "[REDACTED]",
			}
		}

		if !hasLower {
			return &ValidationError{
				Field:   "password",
				Code:    "MISSING_LOWERCASE",
				Message: "Password must contain at least one lowercase letter",
				Value:   "[REDACTED]",
			}
		}

		if !hasDigit {
			return &ValidationError{
				Field:   "password",
				Code:    "MISSING_DIGIT",
				Message: "Password must contain at least one digit",
				Value:   "[REDACTED]",
			}
		}

		if !hasSpecial {
			return &ValidationError{
				Field:   "password",
				Code:    "MISSING_SPECIAL",
				Message: "Password must contain at least one special character",
				Value:   "[REDACTED]",
			}
		}
	}

	return nil
}

// HashPassword hashes a password using bcrypt.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// VerifyPassword verifies a password against a hash.
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ValidateJSONInput validates a JSON string.
func ValidateJSONInput(jsonStr string, maxDepth int, options ...ValidationOptions) error {
	opts := getOptions(options)

	if jsonStr == "" && opts.Required {
		return &ValidationError{
			Field:   "json",
			Code:    "REQUIRED",
			Message: "JSON input is required",
		}
	}

	if jsonStr == "" && !opts.Required {
		return nil
	}

	if len(jsonStr) > opts.MaxLength {
		return &ValidationError{
			Field:   "json",
			Code:    "TOO_LONG",
			Message: fmt.Sprintf("JSON input exceeds maximum length of %d", opts.MaxLength),
			Value:   SanitizeValue("json", jsonStr),
		}
	}

	var js interface{}
	err := json.Unmarshal([]byte(jsonStr), &js)
	if err != nil {
		return &ValidationError{
			Field:   "json",
			Code:    "INVALID_FORMAT",
			Message: "Invalid JSON format: " + err.Error(),
			Value:   SanitizeValue("json", jsonStr),
		}
	}

	// Check JSON depth if maxDepth > 0
	if maxDepth > 0 {
		depth := getJSONDepth(js)
		if depth > maxDepth {
			return &ValidationError{
				Field:   "json",
				Code:    "TOO_DEEP",
				Message: fmt.Sprintf("JSON structure exceeds maximum depth of %d", maxDepth),
				Value:   SanitizeValue("json", jsonStr),
			}
		}
	}

	// In strict mode, check for potential JSON injection
	if opts.StrictMode {
		// Check for potentially dangerous content (e.g., script tags, iframe, etc.)
		if strings.Contains(strings.ToLower(jsonStr), "<script") ||
			strings.Contains(strings.ToLower(jsonStr), "<iframe") ||
			strings.Contains(strings.ToLower(jsonStr), "javascript:") {
			return &ValidationError{
				Field:   "json",
				Code:    "SECURITY_RISK",
				Message: "JSON contains potentially dangerous content",
				Value:   SanitizeValue("json", jsonStr),
			}
		}
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

// isPrivateIP checks if an IP address is in a private range
func isPrivateIP(ip net.IP) bool {
	// Check IPv4 private ranges
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},                        // 10.0.0.0/8
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},                      // 172.16.0.0/12
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},                    // 192.168.0.0/16
		{net.ParseIP("169.254.0.0"), net.ParseIP("169.254.255.255")},                    // 169.254.0.0/16 (link-local)
		{net.ParseIP("fd00::"), net.ParseIP("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}, // fd00::/8 (IPv6 ULA)
	}

	for _, r := range privateRanges {
		if bytes.Compare(ip, r.start) >= 0 && bytes.Compare(ip, r.end) <= 0 {
			return true
		}
	}

	return false
}

// isLoopbackIP checks if an IP address is a loopback address
func isLoopbackIP(ip net.IP) bool {
	return ip.IsLoopback()
}

// isLinkLocalIP checks if an IP address is a link-local address
func isLinkLocalIP(ip net.IP) bool {
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// ValidateSecurityOpts validates Docker security options.
func ValidateSecurityOpts(opts []string) *ValidationResult {
	result := NewValidationResult()

	for i, opt := range opts {
		if !strings.Contains(opt, "=") {
			result.AddError(
				fmt.Sprintf("securityOpts[%d]", i),
				"INVALID_FORMAT",
				"Security option must be in format 'key=value'",
				opt,
			)
			continue
		}

		parts := strings.SplitN(opt, "=", 2)
		key := parts[0]
		value := parts[1]

		switch key {
		case "seccomp":
			if value == "" {
				result.AddError(
					fmt.Sprintf("securityOpts[%d]", i),
					"INVALID_VALUE",
					"Seccomp profile path cannot be empty",
					opt,
				)
			} else if value != "unconfined" && !strings.Contains(value, ".json") && !strings.Contains(value, "/") {
				// Simple check that seccomp profile is either "unconfined" or looks like a path
				result.AddError(
					fmt.Sprintf("securityOpts[%d]", i),
					"INVALID_VALUE",
					"Seccomp profile must be 'unconfined' or a path to a .json file",
					opt,
				)
			}
		case "apparmor":
			if value == "" {
				result.AddError(
					fmt.Sprintf("securityOpts[%d]", i),
					"INVALID_VALUE",
					"AppArmor profile name cannot be empty",
					opt,
				)
			} else if value != "unconfined" && !strings.HasPrefix(value, "docker_test-") {
				// Simple check that apparmor profile is either "unconfined" or starts with "docker_test-"
				result.AddError(
					fmt.Sprintf("securityOpts[%d]", i),
					"INVALID_VALUE",
					"AppArmor profile must be 'unconfined' or start with 'docker_test-'",
					opt,
				)
			}
		case "no-new-privileges":
			if value != "true" && value != "false" {
				result.AddError(
					fmt.Sprintf("securityOpts[%d]", i),
					"INVALID_VALUE",
					"no-new-privileges must be 'true' or 'false'",
					opt,
				)
			}
		case "label":
			// Check for SELinux labels (label:user:..., label:role:..., etc.)
			validPrefixes := []string{"user:", "role:", "type:", "level:", "disable"}
			isValid := false
			for _, prefix := range validPrefixes {
				if strings.HasPrefix(value, prefix) || value == "disable" {
					isValid = true
					break
				}
			}
			if !isValid {
				result.AddError(
					fmt.Sprintf("securityOpts[%d]", i),
					"INVALID_VALUE",
					"Invalid SELinux label format",
					opt,
				)
			}
		default:
			result.AddError(
				fmt.Sprintf("securityOpts[%d]", i),
				"UNKNOWN_OPTION",
				fmt.Sprintf("Unknown security option: %s", key),
				opt,
			)
		}
	}

	return result
}

// Helper function to get the depth of a JSON structure
func getJSONDepth(js interface{}) int {
	if js == nil {
		return 0
	}

	switch v := js.(type) {
	case map[string]interface{}:
		maxDepth := 0
		for _, val := range v {
			depth := getJSONDepth(val)
			if depth > maxDepth {
				maxDepth = depth
			}
		}
		return maxDepth + 1
	case []interface{}:
		maxDepth := 0
		for _, val := range v {
			depth := getJSONDepth(val)
			if depth > maxDepth {
				maxDepth = depth
			}
		}
		return maxDepth + 1
	default:
		return 0
	}
}

// ValidateStruct validates a struct using validator tags
func ValidateStruct(s interface{}) *ValidationResult {
	result := NewValidationResult()
	err := validate.Struct(s)
	if err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			result.AddError("validation", "INVALID_STRUCT", "Invalid validation input")
			return result
		}

		for _, err := range err.(validator.ValidationErrors) {
			field := err.Field()
			tag := err.Tag()
			param := err.Param()

			var message string
			switch tag {
			case "required":
				message = fmt.Sprintf("%s is required", field)
			case "min":
				message = fmt.Sprintf("%s must be at least %s", field, param)
			case "max":
				message = fmt.Sprintf("%s must be at most %s", field, param)
			case "email":
				message = fmt.Sprintf("%s must be a valid email address", field)
			case "url":
				message = fmt.Sprintf("%s must be a valid URL", field)
			case "oneof":
				message = fmt.Sprintf("%s must be one of [%s]", field, param)
			default:
				message = fmt.Sprintf("%s failed validation: %s=%s", field, tag, param)
			}

			result.AddError(err.Field(), strings.ToUpper(tag), message, err.Value())
		}
	}
	return result
}

// ValidateCredentials validates username and password credentials
func ValidateCredentials(username, password string, options ...ValidationOptions) *ValidationResult {
	opts := getOptions(options)
	result := NewValidationResult()

	// Validate username
	if err := ValidateUsername(username, opts); err != nil {
		validationErr, ok := err.(*ValidationError)
		if ok {
			result.Errors = append(result.Errors, validationErr)
		} else {
			result.AddError("username", "INVALID", err.Error(), username)
		}
	}

	// Validate password
	if err := ValidatePassword(password, opts); err != nil {
		validationErr, ok := err.(*ValidationError)
		if ok {
			result.Errors = append(result.Errors, validationErr)
		} else {
			result.AddError("password", "INVALID", err.Error(), "[REDACTED]")
		}
	}

	return result
}

// RedactSensitiveData redacts sensitive data from a map
func RedactSensitiveData(data map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range data {
		if IsSensitiveField(k) {
			result[k] = "[REDACTED]"
		} else {
			switch value := v.(type) {
			case map[string]interface{}:
				result[k] = RedactSensitiveData(value)
			case []interface{}:
				redactedArray := make([]interface{}, len(value))
				for i, item := range value {
					if mapItem, ok := item.(map[string]interface{}); ok {
						redactedArray[i] = RedactSensitiveData(mapItem)
					} else {
						redactedArray[i] = item
					}
				}
				result[k] = redactedArray
			default:
				result[k] = v
			}
		}
	}
	return result
}

// Validate container security options using types.Container
func ValidateContainerSecurityOptions(container types.Container) *ValidationResult {
	result := NewValidationResult()

	// Check for privileged mode
	if privileged := extractHostConfigValue(container.Labels, "privileged"); privileged == "true" {
		result.AddError("container", "PRIVILEGED_MODE",
			"Container is running in privileged mode, which poses security risks",
			container.ID)
	}

	// Check for host networking
	if networkMode := extractHostConfigValue(container.Labels, "network_mode"); networkMode == "host" {
		result.AddError("container", "HOST_NETWORKING",
			"Container is using host networking, which poses security risks",
			container.ID)
	}

	// Check for host PID/IPC
	if pidMode := extractHostConfigValue(container.Labels, "pid_mode"); pidMode == "host" {
		result.AddError("container", "HOST_PID",
			"Container is using host PID namespace, which poses security risks",
			container.ID)
	}

	if ipcMode := extractHostConfigValue(container.Labels, "ipc_mode"); ipcMode == "host" {
		result.AddError("container", "HOST_IPC",
			"Container is using host IPC namespace, which poses security risks",
			container.ID)
	}

	return result
}

// Extract host config values from container labels
func extractHostConfigValue(labels map[string]string, key string) string {
	if value, ok := labels["com.docker_test.container."+key]; ok {
		return value
	}
	return ""
}
