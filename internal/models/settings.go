package models

import (
	"time"

	"gorm.io/gorm"
)

// Setting represents a key-value setting in the system
type Setting struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	Key       string         `json:"key" gorm:"uniqueIndex;not null"`
	Value     string         `json:"value" gorm:"type:text;not null"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// VersionedSetting represents a versioned key-value setting
// Used for settings that require versioning/history
type VersionedSetting struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Key       string    `json:"key" gorm:"index;not null"`
	Value     string    `json:"value" gorm:"type:text;not null"`
	Version   int       `json:"version" gorm:"not null"`
	Metadata  string    `json:"metadata" gorm:"type:text"`
	CreatedAt time.Time `json:"created_at"`
}

// TableName returns the table name for the Setting model
func (Setting) TableName() string {
	return "settings"
}

// TableName returns the table name for the VersionedSetting model
func (VersionedSetting) TableName() string {
	return "versioned_settings"
}

// SystemSettings represents the global system settings
type SystemSettings struct {
	DockerHost           string `json:"docker_host"`
	DockerTLSVerify      bool   `json:"docker_tls_verify"`
	DockerCertPath       string `json:"docker_cert_path"`
	DefaultCPULimit      string `json:"default_cpu_limit"`
	DefaultMemoryLimit   string `json:"default_memory_limit"`
	DefaultStorageLimit  string `json:"default_storage_limit"`
	EnableLogging        bool   `json:"enable_logging"`
	LogLevel             string `json:"log_level"`
	EnableNotifications  bool   `json:"enable_notifications"`
	NotificationEndpoint string `json:"notification_endpoint"`
	EnableScheduling     bool   `json:"enable_scheduling"`
	EnableAudit          bool   `json:"enable_audit"`
	UITheme              string `json:"ui_theme"`
	SessionTimeout       int    `json:"session_timeout"` // In minutes
	EnableRegistration   bool   `json:"enable_registration"`
	MaxContainers        int    `json:"max_containers"`
	MaxImages            int    `json:"max_images"`
	MaxVolumes           int    `json:"max_volumes"`
	MaxNetworks          int    `json:"max_networks"`
}

// UserSettings represents user-specific settings
type UserSettings struct {
	UITheme              string `json:"ui_theme"`
	ContainersPerPage    int    `json:"containers_per_page"`
	ImagesPerPage        int    `json:"images_per_page"`
	VolumesPerPage       int    `json:"volumes_per_page"`
	NetworksPerPage      int    `json:"networks_per_page"`
	DefaultView          string `json:"default_view"`
	ShowTerminated       bool   `json:"show_terminated"`
	NotificationsEnabled bool   `json:"notifications_enabled"`
	RefreshInterval      int    `json:"refresh_interval"` // In seconds
}

// DefaultSystemSettings returns the default system settings
func DefaultSystemSettings() SystemSettings {
	return SystemSettings{
		DockerHost:           "unix:///var/run/docker_test.sock",
		DockerTLSVerify:      false,
		DockerCertPath:       "",
		DefaultCPULimit:      "1.0",
		DefaultMemoryLimit:   "1g",
		DefaultStorageLimit:  "10g",
		EnableLogging:        true,
		LogLevel:             "info",
		EnableNotifications:  false,
		NotificationEndpoint: "",
		EnableScheduling:     true,
		EnableAudit:          true,
		UITheme:              "light",
		SessionTimeout:       60,
		EnableRegistration:   true,
		MaxContainers:        100,
		MaxImages:            100,
		MaxVolumes:           50,
		MaxNetworks:          25,
	}
}

// DefaultUserSettings returns the default user settings
func DefaultUserSettings() UserSettings {
	return UserSettings{
		UITheme:              "system",
		ContainersPerPage:    20,
		ImagesPerPage:        20,
		VolumesPerPage:       20,
		NetworksPerPage:      20,
		DefaultView:          "containers",
		ShowTerminated:       false,
		NotificationsEnabled: true,
		RefreshInterval:      30,
	}
}
