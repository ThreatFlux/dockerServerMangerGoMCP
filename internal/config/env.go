package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	// ErrEnvVarEmpty is returned when a required environment variable is not set
	ErrEnvVarEmpty = errors.New("required environment variable is not set")

	// ErrEnvVarInvalid is returned when an environment variable has an invalid value
	ErrEnvVarInvalid = errors.New("environment variable has an invalid value")
)

// Environment types
const (
	EnvProduction  = "production"
	EnvStaging     = "staging"
	EnvDevelopment = "development"
	EnvTest        = "test"
)

// EnvProvider provides environment variables with safe handling
type EnvProvider struct {
	// Logger for reporting issues
	log *logrus.Logger

	// SecretMask is the mask to use for secret values in logs
	SecretMask string

	// Prefix is the prefix for environment variables
	Prefix string

	// StrictMode controls whether missing required variables should cause panics
	StrictMode bool
}

// NewEnvProvider creates a new environment provider
func NewEnvProvider(prefix string, strictMode bool) *EnvProvider {
	return &EnvProvider{
		log:        logrus.New(),
		SecretMask: "********",
		Prefix:     prefix,
		StrictMode: strictMode,
	}
}

// DefaultEnvProvider returns a default environment provider
func DefaultEnvProvider() *EnvProvider {
	return NewEnvProvider("DSM", false)
}

// StrictEnvProvider returns a strict environment provider
func StrictEnvProvider() *EnvProvider {
	return NewEnvProvider("DSM", true)
}

// Get gets an environment variable or returns a default value if not present
func (p *EnvProvider) Get(key, defaultValue string) string {
	fullKey := p.getFullKey(key)
	value, exists := os.LookupEnv(fullKey)
	if !exists {
		p.log.Debugf("Environment variable %s not set, using default", fullKey)
		return defaultValue
	}
	return value
}

// Require gets an environment variable or returns an error if not present
func (p *EnvProvider) Require(key string) (string, error) {
	fullKey := p.getFullKey(key)
	value, exists := os.LookupEnv(fullKey)
	if !exists {
		err := fmt.Errorf("%w: %s", ErrEnvVarEmpty, fullKey)
		if p.StrictMode {
			p.log.WithError(err).Fatal("Required environment variable not set")
		}
		return "", err
	}
	return value, nil
}

// MustGet gets an environment variable or panics if not present
func (p *EnvProvider) MustGet(key string) string {
	value, err := p.Require(key)
	if err != nil {
		panic(err)
	}
	return value
}

// GetSecret gets a sensitive environment variable or returns a default
// It logs the key but not the value for security
func (p *EnvProvider) GetSecret(key, defaultValue string) string {
	fullKey := p.getFullKey(key)
	value, exists := os.LookupEnv(fullKey)
	if !exists {
		p.log.Debugf("Secret environment variable %s not set, using default", fullKey)
		return defaultValue
	}
	p.log.Debugf("Secret environment variable %s set to [MASKED]", fullKey)
	return value
}

// RequireSecret gets a sensitive environment variable or errors
// It logs the key but not the value for security
func (p *EnvProvider) RequireSecret(key string) (string, error) {
	fullKey := p.getFullKey(key)
	value, exists := os.LookupEnv(fullKey)
	if !exists {
		err := fmt.Errorf("%w: %s", ErrEnvVarEmpty, fullKey)
		if p.StrictMode {
			p.log.WithError(err).Fatal("Required secret environment variable not set")
		}
		return "", err
	}
	p.log.Debugf("Secret environment variable %s set to [MASKED]", fullKey)
	return value, nil
}

// MustGetSecret gets a sensitive environment variable or panics
func (p *EnvProvider) MustGetSecret(key string) string {
	value, err := p.RequireSecret(key)
	if err != nil {
		panic(err)
	}
	return value
}

// GetBool gets a boolean environment variable or returns a default value
func (p *EnvProvider) GetBool(key string, defaultValue bool) bool {
	fullKey := p.getFullKey(key)
	valueStr, exists := os.LookupEnv(fullKey)
	if !exists {
		p.log.Debugf("Boolean environment variable %s not set, using default: %v", fullKey, defaultValue)
		return defaultValue
	}

	// Convert string to boolean
	valueStr = strings.ToLower(valueStr)
	switch valueStr {
	case "true", "yes", "y", "1", "on", "enabled":
		return true
	case "false", "no", "n", "0", "off", "disabled":
		return false
	default:
		p.log.Warnf("Invalid boolean value for environment variable %s: %s, using default: %v",
			fullKey, valueStr, defaultValue)
		return defaultValue
	}
}

// RequireBool gets a boolean environment variable or returns an error
func (p *EnvProvider) RequireBool(key string) (bool, error) {
	fullKey := p.getFullKey(key)
	valueStr, exists := os.LookupEnv(fullKey)
	if !exists {
		err := fmt.Errorf("%w: %s", ErrEnvVarEmpty, fullKey)
		if p.StrictMode {
			p.log.WithError(err).Fatal("Required boolean environment variable not set")
		}
		return false, err
	}

	// Convert string to boolean
	valueStr = strings.ToLower(valueStr)
	switch valueStr {
	case "true", "yes", "y", "1", "on", "enabled":
		return true, nil
	case "false", "no", "n", "0", "off", "disabled":
		return false, nil
	default:
		err := fmt.Errorf("%w: %s has invalid boolean value: %s",
			ErrEnvVarInvalid, fullKey, valueStr)
		if p.StrictMode {
			p.log.WithError(err).Fatal("Invalid boolean environment variable")
		}
		return false, err
	}
}

// MustGetBool gets a boolean environment variable or panics
func (p *EnvProvider) MustGetBool(key string) bool {
	value, err := p.RequireBool(key)
	if err != nil {
		panic(err)
	}
	return value
}

// GetInt gets an integer environment variable or returns a default value
func (p *EnvProvider) GetInt(key string, defaultValue int) int {
	fullKey := p.getFullKey(key)
	valueStr, exists := os.LookupEnv(fullKey)
	if !exists {
		p.log.Debugf("Integer environment variable %s not set, using default: %d", fullKey, defaultValue)
		return defaultValue
	}

	// Convert string to integer
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		p.log.Warnf("Invalid integer value for environment variable %s: %s, using default: %d",
			fullKey, valueStr, defaultValue)
		return defaultValue
	}

	return value
}

// RequireInt gets an integer environment variable or returns an error
func (p *EnvProvider) RequireInt(key string) (int, error) {
	fullKey := p.getFullKey(key)
	valueStr, exists := os.LookupEnv(fullKey)
	if !exists {
		err := fmt.Errorf("%w: %s", ErrEnvVarEmpty, fullKey)
		if p.StrictMode {
			p.log.WithError(err).Fatal("Required integer environment variable not set")
		}
		return 0, err
	}

	// Convert string to integer
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		err = fmt.Errorf("%w: %s has invalid integer value: %s",
			ErrEnvVarInvalid, fullKey, valueStr)
		if p.StrictMode {
			p.log.WithError(err).Fatal("Invalid integer environment variable")
		}
		return 0, err
	}

	return value, nil
}

// MustGetInt gets an integer environment variable or panics
func (p *EnvProvider) MustGetInt(key string) int {
	value, err := p.RequireInt(key)
	if err != nil {
		panic(err)
	}
	return value
}

// GetFloat gets a float environment variable or returns a default value
func (p *EnvProvider) GetFloat(key string, defaultValue float64) float64 {
	fullKey := p.getFullKey(key)
	valueStr, exists := os.LookupEnv(fullKey)
	if !exists {
		p.log.Debugf("Float environment variable %s not set, using default: %f", fullKey, defaultValue)
		return defaultValue
	}

	// Convert string to float
	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		p.log.Warnf("Invalid float value for environment variable %s: %s, using default: %f",
			fullKey, valueStr, defaultValue)
		return defaultValue
	}

	return value
}

// RequireFloat gets a float environment variable or returns an error
func (p *EnvProvider) RequireFloat(key string) (float64, error) {
	fullKey := p.getFullKey(key)
	valueStr, exists := os.LookupEnv(fullKey)
	if !exists {
		err := fmt.Errorf("%w: %s", ErrEnvVarEmpty, fullKey)
		if p.StrictMode {
			p.log.WithError(err).Fatal("Required float environment variable not set")
		}
		return 0, err
	}

	// Convert string to float
	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		err = fmt.Errorf("%w: %s has invalid float value: %s",
			ErrEnvVarInvalid, fullKey, valueStr)
		if p.StrictMode {
			p.log.WithError(err).Fatal("Invalid float environment variable")
		}
		return 0, err
	}

	return value, nil
}

// MustGetFloat gets a float environment variable or panics
func (p *EnvProvider) MustGetFloat(key string) float64 {
	value, err := p.RequireFloat(key)
	if err != nil {
		panic(err)
	}
	return value
}

// GetDuration gets a duration environment variable or returns a default value
func (p *EnvProvider) GetDuration(key string, defaultValue time.Duration) time.Duration {
	fullKey := p.getFullKey(key)
	valueStr, exists := os.LookupEnv(fullKey)
	if !exists {
		p.log.Debugf("Duration environment variable %s not set, using default: %v", fullKey, defaultValue)
		return defaultValue
	}

	// Convert string to duration
	value, err := time.ParseDuration(valueStr)
	if err != nil {
		p.log.Warnf("Invalid duration value for environment variable %s: %s, using default: %v",
			fullKey, valueStr, defaultValue)
		return defaultValue
	}

	return value
}

// RequireDuration gets a duration environment variable or returns an error
func (p *EnvProvider) RequireDuration(key string) (time.Duration, error) {
	fullKey := p.getFullKey(key)
	valueStr, exists := os.LookupEnv(fullKey)
	if !exists {
		err := fmt.Errorf("%w: %s", ErrEnvVarEmpty, fullKey)
		if p.StrictMode {
			p.log.WithError(err).Fatal("Required duration environment variable not set")
		}
		return 0, err
	}

	// Convert string to duration
	value, err := time.ParseDuration(valueStr)
	if err != nil {
		err = fmt.Errorf("%w: %s has invalid duration value: %s",
			ErrEnvVarInvalid, fullKey, valueStr)
		if p.StrictMode {
			p.log.WithError(err).Fatal("Invalid duration environment variable")
		}
		return 0, err
	}

	return value, nil
}

// MustGetDuration gets a duration environment variable or panics
func (p *EnvProvider) MustGetDuration(key string) time.Duration {
	value, err := p.RequireDuration(key)
	if err != nil {
		panic(err)
	}
	return value
}

// GetArray gets an array environment variable by splitting a string
// Format example: "value1,value2,value3"
func (p *EnvProvider) GetArray(key string, defaultValue []string, separator string) []string {
	if separator == "" {
		separator = ","
	}

	fullKey := p.getFullKey(key)
	valueStr, exists := os.LookupEnv(fullKey)
	if !exists {
		p.log.Debugf("Array environment variable %s not set, using default", fullKey)
		return defaultValue
	}

	if valueStr == "" {
		return []string{}
	}

	// Split string into array and trim whitespace
	values := strings.Split(valueStr, separator)
	for i, v := range values {
		values[i] = strings.TrimSpace(v)
	}

	return values
}

// RequireArray gets an array environment variable or returns an error
func (p *EnvProvider) RequireArray(key string, separator string) ([]string, error) {
	if separator == "" {
		separator = ","
	}

	fullKey := p.getFullKey(key)
	valueStr, exists := os.LookupEnv(fullKey)
	if !exists {
		err := fmt.Errorf("%w: %s", ErrEnvVarEmpty, fullKey)
		if p.StrictMode {
			p.log.WithError(err).Fatal("Required array environment variable not set")
		}
		return nil, err
	}

	if valueStr == "" {
		return []string{}, nil
	}

	// Split string into array and trim whitespace
	values := strings.Split(valueStr, separator)
	for i, v := range values {
		values[i] = strings.TrimSpace(v)
	}

	return values, nil
}

// MustGetArray gets an array environment variable or panics
func (p *EnvProvider) MustGetArray(key string, separator string) []string {
	value, err := p.RequireArray(key, separator)
	if err != nil {
		panic(err)
	}
	return value
}

// IsSet checks if an environment variable is set
func (p *EnvProvider) IsSet(key string) bool {
	fullKey := p.getFullKey(key)
	_, exists := os.LookupEnv(fullKey)
	return exists
}

// GetEnvironment gets the current environment (production, development, test)
func (p *EnvProvider) GetEnvironment() string {
	env := p.Get("ENV", EnvDevelopment)
	env = strings.ToLower(env)

	switch env {
	case EnvProduction, EnvStaging, EnvDevelopment, EnvTest:
		return env
	default:
		p.log.Warnf("Invalid environment value: %s, defaulting to development", env)
		return EnvDevelopment
	}
}

// IsProduction checks if the environment is production
func (p *EnvProvider) IsProduction() bool {
	return p.GetEnvironment() == EnvProduction
}

// IsStaging checks if the environment is staging
func (p *EnvProvider) IsStaging() bool {
	return p.GetEnvironment() == EnvStaging
}

// IsDevelopment checks if the environment is development
func (p *EnvProvider) IsDevelopment() bool {
	return p.GetEnvironment() == EnvDevelopment
}

// IsTest checks if the environment is test
func (p *EnvProvider) IsTest() bool {
	return p.GetEnvironment() == EnvTest
}

// GetFullKey returns the prefixed environment variable key
func (p *EnvProvider) getFullKey(key string) string {
	if p.Prefix == "" {
		return key
	}
	return fmt.Sprintf("%s_%s", p.Prefix, key)
}

// StoreSecretValue safely stores a sensitive value in the environment
// with optional encryption
func (p *EnvProvider) StoreSecretValue(key, value string, encrypt bool) error {
	fullKey := p.getFullKey(key)

	// TODO: Implement encryption if needed
	// if encrypt {
	//     // Encrypt value
	// }

	return os.Setenv(fullKey, value)
}

// UnsetValue removes an environment variable
func (p *EnvProvider) UnsetValue(key string) error {
	fullKey := p.getFullKey(key)
	return os.Unsetenv(fullKey)
}

// ExportToEnvironment exports key/value pairs to environment variables
func (p *EnvProvider) ExportToEnvironment(values map[string]string) error {
	for key, value := range values {
		fullKey := p.getFullKey(key)
		if err := os.Setenv(fullKey, value); err != nil {
			return fmt.Errorf("failed to set environment variable %s: %w", fullKey, err)
		}
	}
	return nil
}

// VerifyEnvVars checks if all required environment variables are set
func (p *EnvProvider) VerifyEnvVars(requiredVars []string) error {
	var missingVars []string

	for _, key := range requiredVars {
		if !p.IsSet(key) {
			missingVars = append(missingVars, p.getFullKey(key))
		}
	}

	if len(missingVars) > 0 {
		err := fmt.Errorf("%w: %s", ErrEnvVarEmpty, strings.Join(missingVars, ", "))
		if p.StrictMode {
			p.log.WithError(err).Fatal("Missing required environment variables")
		}
		return err
	}

	return nil
}

// Legacy functions for backward compatibility

// GetEnv gets an environment variable or returns a default value if not present
func GetEnv(key, defaultValue string) string {
	return DefaultEnvProvider().Get(key, defaultValue)
}

// RequireEnv gets an environment variable or panics if not present
func RequireEnv(key string) string {
	return StrictEnvProvider().MustGet(key)
}

// GetEnvBool gets a boolean environment variable or returns a default value
func GetEnvBool(key string, defaultValue bool) bool {
	return DefaultEnvProvider().GetBool(key, defaultValue)
}

// GetEnvInt gets an integer environment variable or returns a default value
func GetEnvInt(key string, defaultValue int) int {
	return DefaultEnvProvider().GetInt(key, defaultValue)
}

// GetEnvDuration gets a duration environment variable or returns a default value
func GetEnvDuration(key string, defaultValue time.Duration) time.Duration {
	return DefaultEnvProvider().GetDuration(key, defaultValue)
}

// GetEnvArray gets an array environment variable by splitting a string
// Format example: "value1,value2,value3"
func GetEnvArray(key string, defaultValue []string, separator string) []string {
	return DefaultEnvProvider().GetArray(key, defaultValue, separator)
}

// IsEnvSet checks if an environment variable is set
func IsEnvSet(key string) bool {
	return DefaultEnvProvider().IsSet(key)
}

// IsProduction checks if the environment is production
func IsProduction() bool {
	return DefaultEnvProvider().IsProduction()
}

// IsDevelopment checks if the environment is development
func IsDevelopment() bool {
	return DefaultEnvProvider().IsDevelopment()
}

// IsTest checks if the environment is test
func IsTest() bool {
	return DefaultEnvProvider().IsTest()
}
