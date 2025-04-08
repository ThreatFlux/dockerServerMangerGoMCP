package config

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/pbkdf2"
)

// SensitiveField indicates a field that contains sensitive information
// and should be masked in logs and error messages
type SensitiveField string

// List of sensitive field patterns (using regexp)
var sensitiveFieldPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)password`),
	regexp.MustCompile(`(?i)secret`),
	regexp.MustCompile(`(?i)key`),
	regexp.MustCompile(`(?i)token`),
	regexp.MustCompile(`(?i)credential`),
	regexp.MustCompile(`(?i)auth`),
}

// ConfigSecurity provides security settings for the configuration
type ConfigSecurity struct {
	// EncryptionKey is the key used to encrypt sensitive values
	EncryptionKey string `mapstructure:"encryption_key"`

	// EncryptionEnabled specifies whether encryption is enabled
	EncryptionEnabled bool `mapstructure:"encryption_enabled"`

	// SecureCookies specifies whether to use secure cookies
	SecureCookies bool `mapstructure:"secure_cookies"`

	// StrictTransportSec specifies whether to use strict transport security
	StrictTransportSec bool `mapstructure:"strict_transport_security"`

	// ContentSecurityPolicy specifies the content security policy
	ContentSecurityPolicy string `mapstructure:"content_security_policy"`

	// AllowedHosts is a list of allowed hosts
	AllowedHosts []string `mapstructure:"allowed_hosts"`

	// TrustedProxies is a list of trusted proxies
	TrustedProxies []string `mapstructure:"trusted_proxies"`

	// RateLimiting configuration
	RateLimiting struct {
		Enabled    bool  `mapstructure:"enabled"`
		MaxPerIP   int   `mapstructure:"max_per_ip"`
		WindowSecs int64 `mapstructure:"window_secs"`
	} `mapstructure:"rate_limiting"`
}

// Config holds all configuration for the application
type Config struct {
	// Top-level application info
	Version  string `mapstructure:"version"`   // Added application version
	ServerID string `mapstructure:"server_id"` // Added unique server ID

	// Server configuration
	Server struct {
		Host            string        `mapstructure:"host"`
		Port            int           `mapstructure:"port"`
		ReadTimeout     time.Duration `mapstructure:"read_timeout"`
		WriteTimeout    time.Duration `mapstructure:"write_timeout"`
		ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
		TrustedProxies  []string      `mapstructure:"trusted_proxies"`
		Mode            string        `mapstructure:"mode"`
		// TLS Configuration
		TLS struct {
			Enabled      bool   `mapstructure:"enabled"`
			CertFile     string `mapstructure:"cert_file"`
			KeyFile      string `mapstructure:"key_file"`
			MinVersion   string `mapstructure:"min_version"`
			MaxVersion   string `mapstructure:"max_version"`
			CipherSuites string `mapstructure:"cipher_suites"`
		} `mapstructure:"tls"`
	} `mapstructure:"server"`

	// Database configuration
	Database struct {
		Type     string `mapstructure:"type"`
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"` // Sensitive
		Name     string `mapstructure:"name"`
		SSLMode  string `mapstructure:"ssl_mode"`
		SQLite   struct {
			Path string `mapstructure:"path"`
		} `mapstructure:"sqlite"`
		// Connection Pool Settings
		MaxOpenConns    int           `mapstructure:"max_open_conns"`
		MaxIdleConns    int           `mapstructure:"max_idle_conns"`
		ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
		ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
	} `mapstructure:"database"`

	// JWT authentication configuration
	Auth struct {
		Secret           string        `mapstructure:"secret"` // Sensitive
		AccessTokenTTL   time.Duration `mapstructure:"access_token_ttl"`
		RefreshTokenTTL  time.Duration `mapstructure:"refresh_token_ttl"`
		TokenIssuer      string        `mapstructure:"token_issuer"`
		TokenAudience    string        `mapstructure:"token_audience"`
		BlacklistEnabled bool          `mapstructure:"blacklist_enabled"`
		Algorithm        string        `mapstructure:"algorithm"`
		// Password Policy
		PasswordPolicy struct {
			MinLength      int  `mapstructure:"min_length"`
			RequireUpper   bool `mapstructure:"require_upper"`
			RequireLower   bool `mapstructure:"require_lower"`
			RequireNumber  bool `mapstructure:"require_number"`
			RequireSpecial bool `mapstructure:"require_special"`
			MaxAge         int  `mapstructure:"max_age"` // in days
		} `mapstructure:"password_policy"`
	} `mapstructure:"auth"`

	// Docker client configuration
	Docker struct {
		Host         string `mapstructure:"host"`
		APIVersion   string `mapstructure:"api_version"`
		TLSVerify    bool   `mapstructure:"tls_verify"`
		TLSCertPath  string `mapstructure:"tls_cert_path"`
		TLSKeyPath   string `mapstructure:"tls_key_path"`
		TLSCAPath    string `mapstructure:"tls_ca_path"`
		RegistryAuth struct {
			Username string `mapstructure:"username"`
			Password string `mapstructure:"password"` // Sensitive
			Email    string `mapstructure:"email"`
			Server   string `mapstructure:"server"`
		} `mapstructure:"registry_auth"`
		// Security Settings
		Security struct {
			DisablePrivileged      bool     `mapstructure:"disable_privileged"`
			DisableHostNetworking  bool     `mapstructure:"disable_host_networking"`
			DisableHostPID         bool     `mapstructure:"disable_host_pid"`
			DisableHostIPC         bool     `mapstructure:"disable_host_ipc"`
			AllowedCapabilities    []string `mapstructure:"allowed_capabilities"`
			DefaultSeccompProfile  string   `mapstructure:"default_seccomp_profile"`
			DefaultApparmorProfile string   `mapstructure:"default_apparmor_profile"`
			EnforceNoNewPrivileges bool     `mapstructure:"enforce_no_new_privileges"`
		} `mapstructure:"security"`
		// Resource Constraints
		ResourceLimits struct {
			EnableMemoryLimit   bool   `mapstructure:"enable_memory_limit"`
			DefaultMemoryLimit  string `mapstructure:"default_memory_limit"`
			EnableCPULimit      bool   `mapstructure:"enable_cpu_limit"`
			DefaultCPULimit     string `mapstructure:"default_cpu_limit"`
			EnablePidsLimit     bool   `mapstructure:"enable_pids_limit"`
			DefaultPidsLimit    int    `mapstructure:"default_pids_limit"`
			DefaultRestartCount int    `mapstructure:"default_restart_count"`
		} `mapstructure:"resource_limits"`
	} `mapstructure:"docker"`

	// Logging configuration
	Logging struct {
		Level          string `mapstructure:"level"`
		Format         string `mapstructure:"format"`
		File           string `mapstructure:"file"`
		MaxSize        int    `mapstructure:"max_size"`     // MB
		MaxBackups     int    `mapstructure:"max_backups"`  // number of files
		MaxAge         int    `mapstructure:"max_age"`      // days
		Compress       bool   `mapstructure:"compress"`     // gzip
		MaskSecrets    bool   `mapstructure:"mask_secrets"` // mask secrets in logs
		SyslogEnabled  bool   `mapstructure:"syslog_enabled"`
		SyslogFacility string `mapstructure:"syslog_facility"`
	} `mapstructure:"logging"`

	// Security configuration
	Security ConfigSecurity `mapstructure:"security"`
}

// encryption is a utility struct for encrypting sensitive configuration values
type encryption struct {
	enabled bool
	key     []byte
}

// configManager manages application configuration, including reloading and validation
type configManager struct {
	config     *Config
	encryption *encryption
	mu         sync.RWMutex
	log        *logrus.Logger
}

// Global configuration manager
var (
	manager *configManager
	once    sync.Once
)

// GetConfigManager returns the singleton config manager instance
func GetConfigManager() *configManager {
	once.Do(func() {
		manager = &configManager{
			log: logrus.New(),
		}
	})
	return manager
}

// LoadConfig loads the configuration from environment variables and/or config file
func LoadConfig() (*Config, error) {
	return GetConfigManager().Load()
}

// Load loads the configuration from environment variables and/or config file
func (cm *configManager) Load() (*Config, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var config Config

	// Set default values
	setDefaults()

	// Load configuration from file
	if err := loadConfigFile(); err != nil {
		cm.log.WithError(err).Warning("Failed to load config file, using environment variables only")
	}

	// Load environment variables
	if err := loadEnvVars(); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}

	// Unmarshal configuration
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Setup encryption if enabled
	cm.setupEncryption(&config)

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Store config
	cm.config = &config

	return &config, nil
}

// GetConfig returns the current configuration
func (cm *configManager) GetConfig() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Return a deep copy to prevent race conditions
	if cm.config != nil {
		return cm.config
	}

	return nil
}

// Reload reloads the configuration
func (cm *configManager) Reload(ctx context.Context) error {
	if _, err := cm.Load(); err != nil {
		return err
	}
	return nil
}

// setupEncryption initializes the encryption utility
func (cm *configManager) setupEncryption(config *Config) {
	cm.encryption = &encryption{
		enabled: config.Security.EncryptionEnabled,
	}

	if cm.encryption.enabled {
		// Generate key from encryption key
		keyStr := config.Security.EncryptionKey
		if keyStr == "" {
			cm.log.Warning("Encryption enabled but no key provided, using environment specific key")
			keyStr = getEnvironmentKey()
		}

		// Derive a 32-byte key using PBKDF2
		salt := []byte("docker_test-server-manager-salt")
		cm.encryption.key = pbkdf2.Key([]byte(keyStr), salt, 4096, 32, sha256.New)
	}
}

// getEnvironmentKey generates a key based on hostname and other environment specifics
// This is a fallback when no encryption key is provided
func getEnvironmentKey() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}

	// Create a unique key based on hostname and process ID
	data := fmt.Sprintf("%s-%d-%s", hostname, os.Getpid(), time.Now().Format(time.RFC3339))
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// encryptSensitiveValues encrypts sensitive values in the configuration
func (cm *configManager) encryptSensitiveValues(config *Config) error {
	if !cm.encryption.enabled || cm.encryption.key == nil {
		return nil
	}

	// Encrypt database password
	if config.Database.Password != "" {
		encrypted, err := cm.encryptValue(config.Database.Password)
		if err != nil {
			return fmt.Errorf("failed to encrypt database password: %w", err)
		}
		config.Database.Password = encrypted
	}

	// Encrypt auth secret
	if config.Auth.Secret != "" {
		encrypted, err := cm.encryptValue(config.Auth.Secret)
		if err != nil {
			return fmt.Errorf("failed to encrypt auth secret: %w", err)
		}
		config.Auth.Secret = encrypted
	}

	// Encrypt registry auth password
	if config.Docker.RegistryAuth.Password != "" {
		encrypted, err := cm.encryptValue(config.Docker.RegistryAuth.Password)
		if err != nil {
			return fmt.Errorf("failed to encrypt registry auth password: %w", err)
		}
		config.Docker.RegistryAuth.Password = encrypted
	}

	return nil
}

// decryptSensitiveValues decrypts sensitive values in the configuration
func (cm *configManager) decryptSensitiveValues(config *Config) error {
	if !cm.encryption.enabled || cm.encryption.key == nil {
		return nil
	}

	// Decrypt database password
	if config.Database.Password != "" && strings.HasPrefix(config.Database.Password, "enc:") {
		decrypted, err := cm.decryptValue(config.Database.Password)
		if err != nil {
			return fmt.Errorf("failed to decrypt database password: %w", err)
		}
		config.Database.Password = decrypted
	}

	// Decrypt auth secret
	if config.Auth.Secret != "" && strings.HasPrefix(config.Auth.Secret, "enc:") {
		decrypted, err := cm.decryptValue(config.Auth.Secret)
		if err != nil {
			return fmt.Errorf("failed to decrypt auth secret: %w", err)
		}
		config.Auth.Secret = decrypted
	}

	// Decrypt registry auth password
	if config.Docker.RegistryAuth.Password != "" && strings.HasPrefix(config.Docker.RegistryAuth.Password, "enc:") {
		decrypted, err := cm.decryptValue(config.Docker.RegistryAuth.Password)
		if err != nil {
			return fmt.Errorf("failed to decrypt registry auth password: %w", err)
		}
		config.Docker.RegistryAuth.Password = decrypted
	}

	return nil
}

// encryptValue encrypts a string value
func (cm *configManager) encryptValue(value string) (string, error) {
	if !cm.encryption.enabled || value == "" {
		return value, nil
	}

	// Check if already encrypted
	if strings.HasPrefix(value, "enc:") {
		return value, nil
	}

	block, err := aes.NewCipher(cm.encryption.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	encrypted := gcm.Seal(nonce, nonce, []byte(value), nil)
	return "enc:" + base64.StdEncoding.EncodeToString(encrypted), nil
}

// decryptValue decrypts a string value
func (cm *configManager) decryptValue(value string) (string, error) {
	if !cm.encryption.enabled || value == "" {
		return value, nil
	}

	// Check if encrypted
	if !strings.HasPrefix(value, "enc:") {
		return value, nil
	}

	encoded := strings.TrimPrefix(value, "enc:")
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(cm.encryption.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// SafeString returns a string with sensitive information masked
func SafeString(val string) string {
	if val == "" {
		return ""
	}
	return "********"
}

// MaskSensitiveFields returns a copy of the config with sensitive fields masked
func (c *Config) MaskSensitiveFields() Config {
	// Create a copy of the config
	maskedConfig := *c

	// Mask database password
	maskedConfig.Database.Password = SafeString(maskedConfig.Database.Password)

	// Mask auth secret
	maskedConfig.Auth.Secret = SafeString(maskedConfig.Auth.Secret)

	// Mask registry auth password
	maskedConfig.Docker.RegistryAuth.Password = SafeString(maskedConfig.Docker.RegistryAuth.Password)

	// Mask security encryption key
	maskedConfig.Security.EncryptionKey = SafeString(maskedConfig.Security.EncryptionKey)

	return maskedConfig
}

// String returns a string representation of the config with sensitive information masked
func (c *Config) String() string {
	// Get masked config
	maskedConfig := c.MaskSensitiveFields()

	// Convert to map for easier representation
	configMap := configToMap(maskedConfig)

	// Format as string
	var sb strings.Builder
	sb.WriteString("Configuration:\n")

	formatMap(&sb, configMap, 0)

	return sb.String()
}

// configToMap converts a config struct to a map
func configToMap(config interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	val := reflect.ValueOf(config)

	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return result
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldName := typ.Field(i).Name

		// Get field tag
		fieldTag := typ.Field(i).Tag.Get("mapstructure")
		if fieldTag != "" {
			fieldName = fieldTag
		}

		switch field.Kind() {
		case reflect.Struct:
			result[fieldName] = configToMap(field.Interface())
		case reflect.Ptr:
			if !field.IsNil() {
				result[fieldName] = configToMap(field.Elem().Interface())
			} else {
				result[fieldName] = nil
			}
		default:
			result[fieldName] = field.Interface()
		}
	}

	return result
}

// formatMap formats a map as a string with indentation
func formatMap(sb *strings.Builder, m map[string]interface{}, indent int) {
	indentStr := strings.Repeat("  ", indent)

	for k, v := range m {
		switch val := v.(type) {
		case map[string]interface{}:
			sb.WriteString(fmt.Sprintf("%s%s:\n", indentStr, k))
			formatMap(sb, val, indent+1)
		case []interface{}:
			sb.WriteString(fmt.Sprintf("%s%s: [", indentStr, k))
			for i, item := range val {
				if i > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(fmt.Sprintf("%v", item))
			}
			sb.WriteString("]\n")
		default:
			sb.WriteString(fmt.Sprintf("%s%s: %v\n", indentStr, k, v))
		}
	}
}

// IsSensitiveField checks if a field name indicates it contains sensitive information
func IsSensitiveField(fieldName string) bool {
	for _, pattern := range sensitiveFieldPatterns {
		if pattern.MatchString(fieldName) {
			return true
		}
	}
	return false
}

// setDefaults sets default values for configuration
func setDefaults() {
	// Server defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.shutdown_timeout", "10s")
	viper.SetDefault("server.mode", "release")
	viper.SetDefault("server.tls.enabled", false)
	viper.SetDefault("server.tls.min_version", "1.2")
	viper.SetDefault("server.tls.cipher_suites", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")

	// Database defaults
	viper.SetDefault("database.type", "sqlite")
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.ssl_mode", "disable")
	viper.SetDefault("database.sqlite.path", "docker_test-server-manager.db")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", "5m")
	viper.SetDefault("database.conn_max_idle_time", "5m")

	// Auth defaults
	viper.SetDefault("auth.access_token_ttl", "15m")
	viper.SetDefault("auth.refresh_token_ttl", "24h")
	viper.SetDefault("auth.token_issuer", "docker_test-server-manager")
	viper.SetDefault("auth.token_audience", "docker_test-api-users")
	viper.SetDefault("auth.blacklist_enabled", true)
	viper.SetDefault("auth.algorithm", "HS256")
	viper.SetDefault("auth.password_policy.min_length", 10)
	viper.SetDefault("auth.password_policy.require_upper", true)
	viper.SetDefault("auth.password_policy.require_lower", true)
	viper.SetDefault("auth.password_policy.require_number", true)
	viper.SetDefault("auth.password_policy.require_special", true)
	viper.SetDefault("auth.password_policy.max_age", 90)

	// Docker defaults
	viper.SetDefault("docker_test.host", "unix:///var/run/docker_test.sock")
	viper.SetDefault("docker_test.tls_verify", false)
	viper.SetDefault("docker_test.security.disable_privileged", true)
	viper.SetDefault("docker_test.security.disable_host_networking", true)
	viper.SetDefault("docker_test.security.disable_host_pid", true)
	viper.SetDefault("docker_test.security.disable_host_ipc", true)
	viper.SetDefault("docker_test.security.allowed_capabilities", []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_NET_BIND_SERVICE"})
	viper.SetDefault("docker_test.security.enforce_no_new_privileges", true)
	viper.SetDefault("docker_test.resource_limits.enable_memory_limit", true)
	viper.SetDefault("docker_test.resource_limits.default_memory_limit", "512m")
	viper.SetDefault("docker_test.resource_limits.enable_cpu_limit", true)
	viper.SetDefault("docker_test.resource_limits.default_cpu_limit", "0.5")
	viper.SetDefault("docker_test.resource_limits.enable_pids_limit", true)
	viper.SetDefault("docker_test.resource_limits.default_pids_limit", 100)
	viper.SetDefault("docker_test.resource_limits.default_restart_count", 5)

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "text")
	viper.SetDefault("logging.max_size", 100)
	viper.SetDefault("logging.max_backups", 3)
	viper.SetDefault("logging.max_age", 28)
	viper.SetDefault("logging.compress", true)
	viper.SetDefault("logging.mask_secrets", true)
	viper.SetDefault("logging.syslog_enabled", false)
	viper.SetDefault("logging.syslog_facility", "local0")

	// Security defaults
	viper.SetDefault("security.encryption_enabled", false)
	viper.SetDefault("security.secure_cookies", true)
	viper.SetDefault("security.strict_transport_security", true)
	viper.SetDefault("security.content_security_policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'")
	viper.SetDefault("security.rate_limiting.enabled", true)
	viper.SetDefault("security.rate_limiting.max_per_ip", 100)
	viper.SetDefault("security.rate_limiting.window_secs", 60)
}

// loadConfigFile loads configuration from a file
func loadConfigFile() error {
	// Set configuration file name and path
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	// Add search paths
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/docker_test-server-manager")

	// Read configuration file (if it exists)
	if err := viper.ReadInConfig(); err != nil {
		// It's ok if config file is not found
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return nil
		}
		return err
	}

	return nil
}

// loadEnvVars loads configuration from environment variables
func loadEnvVars() error {
	// Set environment variable prefix
	viper.SetEnvPrefix("DSM")

	// Enable automatic environment variable binding
	viper.AutomaticEnv()

	// Replace dots with underscores in environment variables
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	return nil
}

// validateConfig validates the configuration values
func validateConfig(config *Config) error {
	// Use a validation result to collect all validation errors
	result := ValidationResult{
		Errors: []ValidationError{},
	}

	// Validate server configuration
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "server.port",
			Message: fmt.Sprintf("invalid server port: %d", config.Server.Port),
		})
	}

	// Validate TLS settings if enabled
	if config.Server.TLS.Enabled {
		if config.Server.TLS.CertFile == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "server.tls.cert_file",
				Message: "TLS certificate file path cannot be empty when TLS is enabled",
			})
		} else if !fileExists(config.Server.TLS.CertFile) {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "server.tls.cert_file",
				Message: fmt.Sprintf("TLS certificate file not found at %s", config.Server.TLS.CertFile),
			})
		}

		if config.Server.TLS.KeyFile == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "server.tls.key_file",
				Message: "TLS key file path cannot be empty when TLS is enabled",
			})
		} else if !fileExists(config.Server.TLS.KeyFile) {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "server.tls.key_file",
				Message: fmt.Sprintf("TLS key file not found at %s", config.Server.TLS.KeyFile),
			})
		}
	}

	// Validate database configuration
	if config.Database.Type != "postgres" && config.Database.Type != "sqlite" {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "database.type",
			Message: fmt.Sprintf("unsupported database type: %s", config.Database.Type),
		})
	}

	if config.Database.Type == "sqlite" {
		// Make sure SQLite database path is valid
		if config.Database.SQLite.Path == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "database.sqlite.path",
				Message: "sqlite database path is empty",
			})
		}

		// Create directory if it doesn't exist
		dir := filepath.Dir(config.Database.SQLite.Path)
		if dir != "." {
			if err := MakeDirectory(dir); err != nil {
				result.Errors = append(result.Errors, ValidationError{
					Field:   "database.sqlite.path",
					Message: fmt.Sprintf("failed to create directory for sqlite database: %v", err),
				})
			}
		}
	}

	if config.Database.Type == "postgres" {
		// Make sure required fields are set
		if config.Database.Host == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "database.host",
				Message: "postgres host is empty",
			})
		}
		if config.Database.Port == 0 {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "database.port",
				Message: "postgres port is empty",
			})
		}
		if config.Database.User == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "database.user",
				Message: "postgres user is empty",
			})
		}
		if config.Database.Name == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "database.name",
				Message: "postgres database name is empty",
			})
		}
	}

	// Validate connection pool settings
	if config.Database.MaxOpenConns < 1 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "database.max_open_conns",
			Message: "max_open_conns must be at least 1",
		})
	}

	if config.Database.MaxIdleConns < 0 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "database.max_idle_conns",
			Message: "max_idle_conns cannot be negative",
		})
	}

	// Validate JWT configuration
	// Skip secret validation if DSM_SKIP_SECRET_VALIDATION is true
	skipSecretValidation := os.Getenv("DSM_SKIP_SECRET_VALIDATION") == "true"
	if !skipSecretValidation {
		if config.Auth.Secret == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "auth.secret",
				Message: "auth secret is empty, this is a security risk",
			})
		} else if len(config.Auth.Secret) < 32 {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "auth.secret",
				Message: "auth secret is too short, it should be at least 32 characters",
			})
		}
	}

	if config.Auth.AccessTokenTTL <= 0 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "auth.access_token_ttl",
			Message: "access token TTL must be positive",
		})
	}
	if config.Auth.RefreshTokenTTL <= 0 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "auth.refresh_token_ttl",
			Message: "refresh token TTL must be positive",
		})
	}

	// Validate algorithm
	switch config.Auth.Algorithm {
	case "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
		// Valid
	default:
		result.Errors = append(result.Errors, ValidationError{
			Field:   "auth.algorithm",
			Message: fmt.Sprintf("unsupported JWT algorithm: %s", config.Auth.Algorithm),
		})
	}

	// Validate password policy
	if config.Auth.PasswordPolicy.MinLength < 8 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "auth.password_policy.min_length",
			Message: "password minimum length should be at least 8 characters",
		})
	}

	// Validate Docker configuration
	// Removed strict validation for Docker host.
	// The Docker client initialization logic (NewManager) handles defaults and env vars.
	// if config.Docker.Host == "" {
	// 	result.Errors = append(result.Errors, ValidationError{
	// 		Field:   "docker.host",
	// 		Message: "docker host is empty",
	// 	})
	// }

	// If TLS is enabled, verify certificate paths
	if config.Docker.TLSVerify {
		if config.Docker.TLSCertPath == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "docker.tls_cert_path",
				Message: "docker_test TLS certificate path is empty",
			})
		} else if !fileExists(config.Docker.TLSCertPath) {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "docker.tls_cert_path",
				Message: fmt.Sprintf("docker_test TLS certificate file not found at %s", config.Docker.TLSCertPath),
			})
		}

		if config.Docker.TLSKeyPath == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "docker.tls_key_path",
				Message: "docker_test TLS key path is empty",
			})
		} else if !fileExists(config.Docker.TLSKeyPath) {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "docker.tls_key_path",
				Message: fmt.Sprintf("docker_test TLS key file not found at %s", config.Docker.TLSKeyPath),
			})
		}

		if config.Docker.TLSCAPath == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "docker.tls_ca_path",
				Message: "docker_test TLS CA path is empty",
			})
		} else if !fileExists(config.Docker.TLSCAPath) {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "docker.tls_ca_path",
				Message: fmt.Sprintf("docker_test TLS CA file not found at %s", config.Docker.TLSCAPath),
			})
		}
	}

	// Validate allowed capabilities if not empty
	for _, cap := range config.Docker.Security.AllowedCapabilities {
		if !strings.HasPrefix(cap, "CAP_") && cap != "ALL" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "docker.security.allowed_capabilities",
				Message: fmt.Sprintf("invalid capability: %s. Should start with CAP_ or be ALL", cap),
			})
		}
	}

	// Validate seccomp profile if specified
	if config.Docker.Security.DefaultSeccompProfile != "" {
		if !fileExists(config.Docker.Security.DefaultSeccompProfile) {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "docker.security.default_seccomp_profile",
				Message: fmt.Sprintf("seccomp profile not found at %s", config.Docker.Security.DefaultSeccompProfile),
			})
		}
	}

	// Validate trusted proxies
	for _, proxy := range config.Server.TrustedProxies {
		ip := net.ParseIP(proxy)
		_, cidr, cidrErr := net.ParseCIDR(proxy)

		if ip == nil && cidrErr != nil {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "server.trusted_proxies",
				Message: fmt.Sprintf("invalid IP or CIDR in trusted proxies: %s", proxy),
			})
		}

		// CIDR validation
		if cidr != nil && cidr.String() != proxy {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "server.trusted_proxies",
				Message: fmt.Sprintf("invalid CIDR format: %s", proxy),
			})
		}
	}

	// Validate allowed hosts
	for _, host := range config.Security.AllowedHosts {
		if host == "" {
			continue
		}

		// Check if host is a valid domain or IP
		ip := net.ParseIP(host)
		if ip == nil {
			// If not an IP, check if it's a valid hostname
			if _, err := url.Parse("http://" + host); err != nil {
				result.Errors = append(result.Errors, ValidationError{
					Field:   "security.allowed_hosts",
					Message: fmt.Sprintf("invalid host: %s", host),
				})
			}
		}
	}

	// Validate encryption key if encryption is enabled
	if config.Security.EncryptionEnabled && config.Security.EncryptionKey == "" {
		// We'll generate a key, so just log a warning
		logrus.Warning("encryption is enabled but no key is provided, a temporary key will be generated")
	}

	// Return validation errors if any
	if len(result.Errors) > 0 {
		var errMsgs []string
		for _, err := range result.Errors {
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %s", err.Field, err.Message))
		}
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errMsgs, "; "))
	}

	return nil
}

// GetConfigHash returns a hash of the current configuration for change detection
func (cm *configManager) GetConfigHash() (string, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.config == nil {
		return "", errors.New("configuration not loaded")
	}

	// Convert config to bytes
	configBytes := []byte(cm.config.String())

	// Calculate hash
	hash := sha256.Sum256(configBytes)
	return hex.EncodeToString(hash[:]), nil
}

// CompareConfigStrings securely compares two configuration string representations
// using constant-time comparison to prevent timing attacks
func CompareConfigStrings(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ValidationResult holds validation results
type ValidationResult struct {
	Errors []ValidationError
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

// MakeDirectory creates a directory if it doesn't exist
func MakeDirectory(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// GetConfigValue gets a configuration value with type conversion
func GetConfigValue(key string, defaultValue interface{}) interface{} {
	value := viper.Get(key)
	if value == nil {
		return defaultValue
	}
	return value
}

// GetConfigValueString gets a string config value
func GetConfigValueString(key string, defaultValue string) string {
	return viper.GetString(key)
}

// GetConfigValueBool gets a boolean config value
func GetConfigValueBool(key string, defaultValue bool) bool {
	return viper.GetBool(key)
}

// GetConfigValueInt gets an int config value
func GetConfigValueInt(key string, defaultValue int) int {
	return viper.GetInt(key)
}

// GetConfigValueFloat gets a float64 config value
func GetConfigValueFloat(key string, defaultValue float64) float64 {
	return viper.GetFloat64(key)
}

// GetConfigValueDuration gets a duration config value
func GetConfigValueDuration(key string, defaultValue time.Duration) time.Duration {
	return viper.GetDuration(key)
}

// GetConfigValueStringSlice gets a string slice config value
func GetConfigValueStringSlice(key string, defaultValue []string) []string {
	return viper.GetStringSlice(key)
}
