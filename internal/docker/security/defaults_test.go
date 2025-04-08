package security

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestDefaultsManager(t *testing.T) (*DefaultsManager, string, func()) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "defaults-test-*")
	require.NoError(t, err)

	// Create a logger for the test
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create a DefaultsManager
	options := DefaultsOptions{
		ConfigPath:               tempDir,
		DefaultSeccompProfile:    "default",
		DefaultAppArmorProfile:   "docker_test-default",
		DefaultCapabilityProfile: "default",
		Logger:                   logger,
	}

	manager, err := NewDefaultsManager(options)
	require.NoError(t, err)

	// Return the manager and a cleanup function
	cleanup := func() {
		// Remove the temporary directory
		os.RemoveAll(tempDir)
	}

	return manager, tempDir, cleanup
}

func TestNewDefaultsManager(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Assert that the manager was created successfully
	assert.NotNil(t, manager)
	assert.NotEmpty(t, manager.seccompProfiles)
	assert.NotEmpty(t, manager.capabilityProfiles)
}

func TestDefaultsManager_CreateDefaultProfiles(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Check if the default seccomp profile exists
	profile, err := manager.GetSeccompProfile(manager.defaultSeccompProfile)
	assert.NoError(t, err)
	assert.Equal(t, manager.defaultSeccompProfile, profile.Name)

	// Check if the default capability profile exists
	capProfile, err := manager.GetCapabilityProfile(manager.defaultCapabilityProfile)
	assert.NoError(t, err)
	assert.Equal(t, manager.defaultCapabilityProfile, capProfile.Name)
}

func TestDefaultsManager_SaveSeccompProfile(t *testing.T) {
	manager, tempDir, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	profile := SeccompProfile{
		Name:          "test-profile",
		Description:   "Test seccomp profile",
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []SeccompSyscall{
			{
				Names:  []string{"read", "write"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}

	// Save the profile
	err := manager.SaveSeccompProfile(profile)
	assert.NoError(t, err)

	// Check if the profile was saved to disk
	path := filepath.Join(tempDir, "seccomp", "test-profile.json")
	assert.FileExists(t, path)

	// Check if the profile was added to the map
	savedProfile, err := manager.GetSeccompProfile("test-profile")
	assert.NoError(t, err)
	assert.Equal(t, profile.Name, savedProfile.Name)
	assert.Equal(t, profile.Description, savedProfile.Description)
	assert.Equal(t, profile.DefaultAction, savedProfile.DefaultAction)
	assert.Equal(t, profile.Architectures, savedProfile.Architectures)
	assert.Len(t, savedProfile.Syscalls, 1)
	assert.Equal(t, profile.Syscalls[0].Names, savedProfile.Syscalls[0].Names)
	assert.Equal(t, profile.Syscalls[0].Action, savedProfile.Syscalls[0].Action)
}

func TestDefaultsManager_GetSeccompProfile(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Get the default profile
	profile, err := manager.GetSeccompProfile(manager.defaultSeccompProfile)
	assert.NoError(t, err)
	assert.Equal(t, manager.defaultSeccompProfile, profile.Name)

	// Try to get a non-existent profile
	_, err = manager.GetSeccompProfile("non-existent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)
}

func TestDefaultsManager_GetDefaultSeccompProfile(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Get the default profile
	profile, err := manager.GetDefaultSeccompProfile()
	assert.NoError(t, err)
	assert.Equal(t, manager.defaultSeccompProfile, profile.Name)
}

func TestDefaultsManager_SetDefaultSeccompProfile(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	profile := SeccompProfile{
		Name:          "test-profile",
		Description:   "Test seccomp profile",
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []SeccompSyscall{
			{
				Names:  []string{"read", "write"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}

	// Save the profile
	err := manager.SaveSeccompProfile(profile)
	assert.NoError(t, err)

	// Set the default profile
	err = manager.SetDefaultSeccompProfile("test-profile")
	assert.NoError(t, err)

	// Check if the default was set
	assert.Equal(t, "test-profile", manager.defaultSeccompProfile)

	// Try to set a non-existent profile as default
	err = manager.SetDefaultSeccompProfile("non-existent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)
}

func TestDefaultsManager_DeleteSeccompProfile(t *testing.T) {
	manager, tempDir, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	profile := SeccompProfile{
		Name:          "test-profile",
		Description:   "Test seccomp profile",
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []SeccompSyscall{
			{
				Names:  []string{"read", "write"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}

	// Save the profile
	err := manager.SaveSeccompProfile(profile)
	assert.NoError(t, err)

	// Delete the profile
	err = manager.DeleteSeccompProfile("test-profile")
	assert.NoError(t, err)

	// Check if the profile was removed from disk
	path := filepath.Join(tempDir, "seccomp", "test-profile.json")
	assert.NoFileExists(t, path)

	// Check if the profile was removed from the map
	_, err = manager.GetSeccompProfile("test-profile")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)

	// Try to delete a non-existent profile
	err = manager.DeleteSeccompProfile("non-existent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)

	// Try to delete the default profile
	err = manager.DeleteSeccompProfile(manager.defaultSeccompProfile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete default seccomp profile")
}

func TestDefaultsManager_SaveCapabilityProfile(t *testing.T) {
	manager, tempDir, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	profile := CapabilityProfile{
		Name:        "test-profile",
		Description: "Test capability profile",
		Add:         []string{"NET_ADMIN", "SYS_TIME"},
		Drop:        []string{"NET_RAW", "SYS_MODULE"},
	}

	// Save the profile
	err := manager.SaveCapabilityProfile(profile)
	assert.NoError(t, err)

	// Check if the profile was saved to disk
	path := filepath.Join(tempDir, "capabilities", "test-profile.json")
	assert.FileExists(t, path)

	// Check if the profile was added to the map
	savedProfile, err := manager.GetCapabilityProfile("test-profile")
	assert.NoError(t, err)
	assert.Equal(t, profile.Name, savedProfile.Name)
	assert.Equal(t, profile.Description, savedProfile.Description)
	assert.Equal(t, profile.Add, savedProfile.Add)
	assert.Equal(t, profile.Drop, savedProfile.Drop)
}

func TestDefaultsManager_GetCapabilityProfile(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Get the default profile
	profile, err := manager.GetCapabilityProfile(manager.defaultCapabilityProfile)
	assert.NoError(t, err)
	assert.Equal(t, manager.defaultCapabilityProfile, profile.Name)

	// Try to get a non-existent profile
	_, err = manager.GetCapabilityProfile("non-existent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)
}

func TestDefaultsManager_GetDefaultCapabilityProfile(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Get the default profile
	profile, err := manager.GetDefaultCapabilityProfile()
	assert.NoError(t, err)
	assert.Equal(t, manager.defaultCapabilityProfile, profile.Name)
}

func TestDefaultsManager_SetDefaultCapabilityProfile(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	profile := CapabilityProfile{
		Name:        "test-profile",
		Description: "Test capability profile",
		Add:         []string{"NET_ADMIN", "SYS_TIME"},
		Drop:        []string{"NET_RAW", "SYS_MODULE"},
	}

	// Save the profile
	err := manager.SaveCapabilityProfile(profile)
	assert.NoError(t, err)

	// Set the default profile
	err = manager.SetDefaultCapabilityProfile("test-profile")
	assert.NoError(t, err)

	// Check if the default was set
	assert.Equal(t, "test-profile", manager.defaultCapabilityProfile)

	// Try to set a non-existent profile as default
	err = manager.SetDefaultCapabilityProfile("non-existent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)
}

func TestDefaultsManager_DeleteCapabilityProfile(t *testing.T) {
	manager, tempDir, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	profile := CapabilityProfile{
		Name:        "test-profile",
		Description: "Test capability profile",
		Add:         []string{"NET_ADMIN", "SYS_TIME"},
		Drop:        []string{"NET_RAW", "SYS_MODULE"},
	}

	// Save the profile
	err := manager.SaveCapabilityProfile(profile)
	assert.NoError(t, err)

	// Delete the profile
	err = manager.DeleteCapabilityProfile("test-profile")
	assert.NoError(t, err)

	// Check if the profile was removed from disk
	path := filepath.Join(tempDir, "capabilities", "test-profile.json")
	assert.NoFileExists(t, path)

	// Check if the profile was removed from the map
	_, err = manager.GetCapabilityProfile("test-profile")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)

	// Try to delete a non-existent profile
	err = manager.DeleteCapabilityProfile("non-existent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)

	// Try to delete the default profile
	err = manager.DeleteCapabilityProfile(manager.defaultCapabilityProfile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete default capability profile")
}

func TestDefaultsManager_InstallAppArmorProfile(t *testing.T) {
	manager, tempDir, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	name := "test-profile"
	content := `
#include <tunables/global>
profile test-profile flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  deny mount,
  deny remount,
  deny umount,
  deny ptrace,
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability sys_module,
  deny capability sys_rawio,
}
`

	// Install the profile
	err := manager.InstallAppArmorProfile(name, content)
	assert.NoError(t, err)

	// Check if the profile was saved to disk
	path := filepath.Join(tempDir, "apparmor", name)
	assert.FileExists(t, path)

	// Check if the profile was added to the map
	_, exists := manager.apparmorProfiles[name]
	assert.True(t, exists)

	// Check if the profile content is correct
	savedContent, err := manager.GetAppArmorProfile(name)
	assert.NoError(t, err)
	assert.Equal(t, content, savedContent)
}

func TestDefaultsManager_GetAppArmorProfile(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	name := "test-profile"
	content := `
#include <tunables/global>
profile test-profile flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  deny mount,
  deny remount,
  deny umount,
}
`

	// Install the profile
	err := manager.InstallAppArmorProfile(name, content)
	assert.NoError(t, err)

	// Get the profile
	savedContent, err := manager.GetAppArmorProfile(name)
	assert.NoError(t, err)
	assert.Equal(t, content, savedContent)

	// Try to get a non-existent profile
	_, err = manager.GetAppArmorProfile("non-existent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)
}

func TestDefaultsManager_GetDefaultAppArmorProfile(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Get the default profile
	defaultProfile := manager.GetDefaultAppArmorProfile()
	assert.Equal(t, manager.defaultAppArmorProfile, defaultProfile)
}

func TestDefaultsManager_SetDefaultAppArmorProfile(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	name := "test-profile"
	content := `
#include <tunables/global>
profile test-profile flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
}
`

	// Install the profile
	err := manager.InstallAppArmorProfile(name, content)
	assert.NoError(t, err)

	// Set the default profile
	err = manager.SetDefaultAppArmorProfile(name)
	assert.NoError(t, err)

	// Check if the default was set
	assert.Equal(t, name, manager.defaultAppArmorProfile)

	// Try to set a non-existent profile as default
	err = manager.SetDefaultAppArmorProfile("non-existent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)
}

func TestDefaultsManager_DeleteAppArmorProfile(t *testing.T) {
	manager, tempDir, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	name := "test-profile"
	content := `
#include <tunables/global>
profile test-profile flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
}
`

	// Install the profile
	err := manager.InstallAppArmorProfile(name, content)
	assert.NoError(t, err)

	// Delete the profile
	err = manager.DeleteAppArmorProfile(name)
	assert.NoError(t, err)

	// Check if the profile was removed from disk
	path := filepath.Join(tempDir, "apparmor", name)
	assert.NoFileExists(t, path)

	// Check if the profile was removed from the map
	_, exists := manager.apparmorProfiles[name]
	assert.False(t, exists)

	// Try to delete a non-existent profile
	err = manager.DeleteAppArmorProfile("non-existent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)
}

func TestDefaultsManager_ApplySecureDefaults(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create container config and host config
	containerConfig := &container.Config{
		Image: "test-image",
	}
	hostConfig := &container.HostConfig{}

	// Apply secure defaults
	err := manager.ApplySecureDefaults(context.Background(), containerConfig, hostConfig)
	assert.NoError(t, err)

	// Check security settings
	assert.False(t, hostConfig.Privileged)
	assert.True(t, hostConfig.ReadonlyRootfs)
	// assert.True(t, hostConfig.NoNewPrivileges) // Field removed, check SecurityOpt instead
	assert.Contains(t, hostConfig.SecurityOpt, "no-new-privileges:true")
	assert.Equal(t, 500, hostConfig.OomScoreAdj)
	assert.False(t, containerConfig.NetworkDisabled)
	assert.Equal(t, "SIGTERM", containerConfig.StopSignal)

	// Check capability settings
	defaultProfile, err := manager.GetCapabilityProfile(manager.defaultCapabilityProfile)
	assert.NoError(t, err)
	assert.Equal(t, defaultProfile.Add, hostConfig.CapAdd)
	assert.Equal(t, defaultProfile.Drop, hostConfig.CapDrop)

	// Check security opt settings
	assert.Contains(t, hostConfig.SecurityOpt, "apparmor=docker_test-default")
	// Check if seccomp profile is set
	for _, opt := range hostConfig.SecurityOpt {
		if len(opt) > 8 && opt[:8] == "seccomp=" {
			// Extract the seccomp profile JSON
			seccompJson := opt[8:]
			var profile SeccompProfile
			err := json.Unmarshal([]byte(seccompJson), &profile)
			assert.NoError(t, err)
			assert.Equal(t, manager.defaultSeccompProfile, profile.Name)
			break
		}
	}
}

func TestDefaultsManager_ApplyCustomSecuritySettings(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test seccomp profile
	seccompProfile := SeccompProfile{
		Name:          "test-seccomp",
		Description:   "Test seccomp profile",
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []SeccompSyscall{
			{
				Names:  []string{"read", "write"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
	err := manager.SaveSeccompProfile(seccompProfile)
	assert.NoError(t, err)

	// Create a test capability profile
	capabilityProfile := CapabilityProfile{
		Name:        "test-capability",
		Description: "Test capability profile",
		Add:         []string{"NET_ADMIN", "SYS_TIME"},
		Drop:        []string{"NET_RAW", "SYS_MODULE"},
	}
	err = manager.SaveCapabilityProfile(capabilityProfile)
	assert.NoError(t, err)

	// Create a test AppArmor profile
	apparmorProfile := "test-apparmor"
	apparmorContent := `
#include <tunables/global>
profile test-apparmor flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
}
`
	err = manager.InstallAppArmorProfile(apparmorProfile, apparmorContent)
	assert.NoError(t, err)

	// Create container config and host config
	containerConfig := &container.Config{
		Image: "test-image",
	}
	hostConfig := &container.HostConfig{}

	// Apply custom security settings
	err = manager.ApplyCustomSecuritySettings(context.Background(), containerConfig, hostConfig,
		"test-seccomp", "test-apparmor", "test-capability")
	assert.NoError(t, err)

	// Check capability settings
	assert.Equal(t, capabilityProfile.Add, hostConfig.CapAdd)
	assert.Equal(t, capabilityProfile.Drop, hostConfig.CapDrop)

	// Check security opt settings
	assert.Contains(t, hostConfig.SecurityOpt, "apparmor=test-apparmor")
	// Check if seccomp profile is set
	for _, opt := range hostConfig.SecurityOpt {
		if len(opt) > 8 && opt[:8] == "seccomp=" {
			// Extract the seccomp profile JSON
			seccompJson := opt[8:]
			var profile SeccompProfile
			err := json.Unmarshal([]byte(seccompJson), &profile)
			assert.NoError(t, err)
			assert.Equal(t, "test-seccomp", profile.Name)
			break
		}
	}
}

func TestDefaultsManager_ListSeccompProfiles(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	profile := SeccompProfile{
		Name:          "test-profile",
		Description:   "Test seccomp profile",
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []SeccompSyscall{
			{
				Names:  []string{"read", "write"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
	err := manager.SaveSeccompProfile(profile)
	assert.NoError(t, err)

	// List profiles
	profiles := manager.ListSeccompProfiles()
	assert.Contains(t, profiles, "default")
	assert.Contains(t, profiles, "test-profile")
	assert.Len(t, profiles, 2)
}

func TestDefaultsManager_ListAppArmorProfiles(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	name := "test-profile"
	content := `profile test-profile flags=(attach_disconnected,mediate_deleted) {}`
	err := manager.InstallAppArmorProfile(name, content)
	assert.NoError(t, err)

	// List profiles
	profiles := manager.ListAppArmorProfiles()
	assert.Contains(t, profiles, "test-profile")
	assert.Len(t, profiles, 1)
}

func TestDefaultsManager_ListCapabilityProfiles(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Create a test profile
	profile := CapabilityProfile{
		Name:        "test-profile",
		Description: "Test capability profile",
		Add:         []string{"NET_ADMIN", "SYS_TIME"},
		Drop:        []string{"NET_RAW", "SYS_MODULE"},
	}
	err := manager.SaveCapabilityProfile(profile)
	assert.NoError(t, err)

	// List profiles
	profiles := manager.ListCapabilityProfiles()
	assert.Contains(t, profiles, "default")
	assert.Contains(t, profiles, "test-profile")
	assert.Len(t, profiles, 2)
}

func TestDefaultsManager_IsSeccompEnabled(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Check if seccomp is enabled
	assert.True(t, manager.IsSeccompEnabled())
}

func TestDefaultsManager_IsAppArmorEnabled(t *testing.T) {
	manager, _, cleanup := setupTestDefaultsManager(t)
	defer cleanup()

	// Check if AppArmor is enabled
	assert.True(t, manager.IsAppArmorEnabled())
}
