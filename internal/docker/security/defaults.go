// Package security provides container security scanning and secure default configurations
package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
)

// Common errors
var (
	// ErrInvalidSeccompProfile indicates an invalid seccomp profile
	ErrInvalidSeccompProfile = errors.New("invalid seccomp profile")

	// ErrInvalidAppArmorProfile indicates an invalid AppArmor profile
	ErrInvalidAppArmorProfile = errors.New("invalid apparmor profile")

	// ErrProfileNotFound indicates a profile was not found
	ErrProfileNotFound = errors.New("profile not found")

	// ErrUnsupportedRuntime indicates an unsupported container runtime
	ErrUnsupportedRuntime = errors.New("unsupported container runtime")
)

// DefaultsManager manages secure default configurations for containers
type DefaultsManager struct {
	// seccompProfiles holds the seccomp profiles
	seccompProfiles map[string]SeccompProfile

	// apparmorProfiles holds the AppArmor profiles
	apparmorProfiles map[string]string

	// capabilityProfiles holds the capability profiles
	capabilityProfiles map[string]CapabilityProfile

	// configPath is the path to the configuration directory
	configPath string

	// defaultSeccompProfile is the default seccomp profile
	defaultSeccompProfile string

	// defaultAppArmorProfile is the default AppArmor profile
	defaultAppArmorProfile string

	// defaultCapabilityProfile is the default capability profile
	defaultCapabilityProfile string

	// logger is the logger
	logger *logrus.Logger

	// mu is a mutex for thread safety
	mu sync.RWMutex
}

// SeccompProfile represents a seccomp profile
type SeccompProfile struct {
	// Name is the name of the profile
	Name string `json:"name"`

	// Description is the description of the profile
	Description string `json:"description"`

	// DefaultAction is the default action for seccomp rules
	DefaultAction string `json:"defaultAction"`

	// Architectures are the supported architectures
	Architectures []string `json:"architectures,omitempty"`

	// Syscalls are the system call rules
	Syscalls []SeccompSyscall `json:"syscalls"`

	// Path is the path to the profile file
	Path string `json:"-"`
}

// SeccompSyscall represents a seccomp syscall rule
type SeccompSyscall struct {
	// Names are the syscall names
	Names []string `json:"names"`

	// Action is the action to take
	Action string `json:"action"`

	// Args are optional argument matchers
	Args []SeccompArg `json:"args,omitempty"`
}

// SeccompArg represents a seccomp argument matcher
type SeccompArg struct {
	// Index is the argument index
	Index uint `json:"index"`

	// Value is the argument value
	Value uint64 `json:"value"`

	// ValueTwo is the second argument value (for range-based comparisons)
	ValueTwo uint64 `json:"valueTwo,omitempty"`

	// Op is the comparison operator
	Op string `json:"op"`
}

// CapabilityProfile represents a capability profile
type CapabilityProfile struct {
	// Name is the name of the profile
	Name string `json:"name"`

	// Description is the description of the profile
	Description string `json:"description"`

	// Add are capabilities to add
	Add []string `json:"add"`

	// Drop are capabilities to drop
	Drop []string `json:"drop"`
}

// DefaultsOptions defines options for the DefaultsManager
type DefaultsOptions struct {
	// ConfigPath is the path to the configuration directory
	ConfigPath string

	// DefaultSeccompProfile is the default seccomp profile
	DefaultSeccompProfile string

	// DefaultAppArmorProfile is the default AppArmor profile
	DefaultAppArmorProfile string

	// DefaultCapabilityProfile is the default capability profile
	DefaultCapabilityProfile string

	// Logger is the logger
	Logger *logrus.Logger

	// DockerClient is the Docker client
	DockerClient client.APIClient
}

// NewDefaultsManager creates a new DefaultsManager
func NewDefaultsManager(options DefaultsOptions) (*DefaultsManager, error) {
	// Set up default values
	if options.ConfigPath == "" {
		options.ConfigPath = "/etc/docker_test/security"
	}

	if options.DefaultSeccompProfile == "" {
		options.DefaultSeccompProfile = "default"
	}

	if options.DefaultAppArmorProfile == "" {
		options.DefaultAppArmorProfile = "docker_test-default"
	}

	if options.DefaultCapabilityProfile == "" {
		options.DefaultCapabilityProfile = "default"
	}

	if options.Logger == nil {
		options.Logger = logrus.New()
	}

	manager := &DefaultsManager{
		seccompProfiles:          make(map[string]SeccompProfile),
		apparmorProfiles:         make(map[string]string),
		capabilityProfiles:       make(map[string]CapabilityProfile),
		configPath:               options.ConfigPath,
		defaultSeccompProfile:    options.DefaultSeccompProfile,
		defaultAppArmorProfile:   options.DefaultAppArmorProfile,
		defaultCapabilityProfile: options.DefaultCapabilityProfile,
		logger:                   options.Logger,
	}

	// Create config directory if it doesn't exist
	if _, err := os.Stat(options.ConfigPath); os.IsNotExist(err) {
		if err := os.MkdirAll(options.ConfigPath, 0755); err != nil {
			return nil, fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	// Create subdirectories
	seccompDir := filepath.Join(options.ConfigPath, "seccomp")
	if _, err := os.Stat(seccompDir); os.IsNotExist(err) {
		if err := os.MkdirAll(seccompDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create seccomp directory: %w", err)
		}
	}

	apparmorDir := filepath.Join(options.ConfigPath, "apparmor")
	if _, err := os.Stat(apparmorDir); os.IsNotExist(err) {
		if err := os.MkdirAll(apparmorDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create apparmor directory: %w", err)
		}
	}

	capabilityDir := filepath.Join(options.ConfigPath, "capabilities")
	if _, err := os.Stat(capabilityDir); os.IsNotExist(err) {
		if err := os.MkdirAll(capabilityDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create capabilities directory: %w", err)
		}
	}

	// Load existing profiles
	if err := manager.LoadProfiles(); err != nil {
		return nil, err
	}

	// Create default profiles if they don't exist
	if err := manager.createDefaultProfiles(); err != nil {
		return nil, err
	}

	return manager, nil
}

// LoadProfiles loads profiles from disk
func (m *DefaultsManager) LoadProfiles() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Load seccomp profiles
	seccompDir := filepath.Join(m.configPath, "seccomp")
	if err := filepath.Walk(seccompDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".json") {
			file, err := os.Open(path)
			if err != nil {
				m.logger.WithError(err).Warnf("Failed to open seccomp profile: %s", path)
				return nil
			}
			defer file.Close()

			data, err := io.ReadAll(file)
			if err != nil {
				m.logger.WithError(err).Warnf("Failed to read seccomp profile: %s", path)
				return nil
			}

			var profile SeccompProfile
			if err := json.Unmarshal(data, &profile); err != nil {
				m.logger.WithError(err).Warnf("Failed to parse seccomp profile: %s", path)
				return nil
			}

			// Set the profile name from the filename if not set
			if profile.Name == "" {
				profile.Name = strings.TrimSuffix(info.Name(), ".json")
			}

			// Set the profile path
			profile.Path = path

			m.seccompProfiles[profile.Name] = profile
			m.logger.WithField("profile", profile.Name).Debug("Loaded seccomp profile")
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to load seccomp profiles: %w", err)
	}

	// Load AppArmor profiles
	apparmorDir := filepath.Join(m.configPath, "apparmor")
	if err := filepath.Walk(apparmorDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			name := strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
			m.apparmorProfiles[name] = path
			m.logger.WithField("profile", name).Debug("Loaded AppArmor profile")
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to load AppArmor profiles: %w", err)
	}

	// Load capability profiles
	capabilityDir := filepath.Join(m.configPath, "capabilities")
	if err := filepath.Walk(capabilityDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".json") {
			file, err := os.Open(path)
			if err != nil {
				m.logger.WithError(err).Warnf("Failed to open capability profile: %s", path)
				return nil
			}
			defer file.Close()

			data, err := io.ReadAll(file)
			if err != nil {
				m.logger.WithError(err).Warnf("Failed to read capability profile: %s", path)
				return nil
			}

			var profile CapabilityProfile
			if err := json.Unmarshal(data, &profile); err != nil {
				m.logger.WithError(err).Warnf("Failed to parse capability profile: %s", path)
				return nil
			}

			// Set the profile name from the filename if not set
			if profile.Name == "" {
				profile.Name = strings.TrimSuffix(info.Name(), ".json")
			}

			m.capabilityProfiles[profile.Name] = profile
			m.logger.WithField("profile", profile.Name).Debug("Loaded capability profile")
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to load capability profiles: %w", err)
	}

	return nil
}

// createDefaultProfiles creates default profiles if they don't exist
func (m *DefaultsManager) createDefaultProfiles() error {
	// Create default seccomp profile
	if _, exists := m.seccompProfiles[m.defaultSeccompProfile]; !exists {
		profile := SeccompProfile{
			Name:          m.defaultSeccompProfile,
			Description:   "Default seccomp profile with safe defaults",
			DefaultAction: "SCMP_ACT_ERRNO",
			Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"},
			Syscalls: []SeccompSyscall{
				{
					Names:  []string{"accept", "accept4", "access", "arch_prctl", "bind", "brk", "capget", "capset", "chdir", "chmod", "chown", "close", "connect", "copy_file_range", "creat", "dup", "dup2", "dup3", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_wait", "eventfd", "eventfd2", "execve", "execveat", "exit", "exit_group", "faccessat", "fadvise64", "fallocate", "fanotify_init", "fanotify_mark", "fchdir", "fchmod", "fchmodat", "fchown", "fchownat", "fcntl", "fdatasync", "fgetxattr", "flistxattr", "flock", "fork", "fremovexattr", "fsetxattr", "fstat", "fstatfs", "fsync", "ftruncate", "futex", "getcwd", "getdents", "getdents64", "getegid", "geteuid", "getgid", "getpgid", "getpgrp", "getpid", "getppid", "getpriority", "getrandom", "getresgid", "getresuid", "getrlimit", "get_robust_list", "getrusage", "getsid", "getsockname", "getsockopt", "get_thread_area", "gettid", "gettimeofday", "getuid", "getxattr", "inotify_add_watch", "inotify_init", "inotify_init1", "inotify_rm_watch", "io_cancel", "ioctl", "io_destroy", "io_getevents", "ioprio_get", "ioprio_set", "io_setup", "io_submit", "kill", "lchown", "lgetxattr", "link", "linkat", "listen", "listxattr", "llistxattr", "lremovexattr", "lseek", "lsetxattr", "lstat", "madvise", "memfd_create", "mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mmap", "mount", "mprotect", "mremap", "msgctl", "msgget", "msgrcv", "msgsnd", "msync", "munlock", "munmap", "nanosleep", "newfstatat", "open", "openat", "pause", "personality", "pipe", "pipe2", "poll", "ppoll", "prctl", "pread64", "preadv", "prlimit64", "pselect6", "pwrite64", "pwritev", "read", "readahead", "readlink", "readlinkat", "readv", "reboot", "recvfrom", "recvmmsg", "recvmsg", "remap_file_pages", "removexattr", "rename", "renameat", "renameat2", "restart_syscall", "rmdir", "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigqueueinfo", "rt_sigreturn", "rt_sigsuspend", "rt_sigtimedwait", "rt_tgsigqueueinfo", "sched_getaffinity", "sched_getattr", "sched_getparam", "sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler", "sched_rr_get_interval", "sched_setaffinity", "sched_setattr", "sched_setparam", "sched_setscheduler", "sched_yield", "seccomp", "select", "semctl", "semget", "semop", "semtimedop", "sendfile", "sendmmsg", "sendmsg", "sendto", "setdomainname", "setfsgid", "setfsuid", "setgid", "setgroups", "sethostname", "setitimer", "setpgid", "setpriority", "setregid", "setresgid", "setresuid", "setreuid", "setrlimit", "set_robust_list", "setsid", "setsockopt", "set_thread_area", "set_tid_address", "setuid", "setxattr", "shmat", "shmctl", "shmdt", "shmget", "shutdown", "sigaltstack", "signalfd", "signalfd4", "socket", "socketpair", "splice", "stat", "statfs", "symlink", "symlinkat", "sync", "sync_file_range", "syncfs", "sysinfo", "tee", "tgkill", "time", "timer_create", "timer_delete", "timerfd_create", "timerfd_gettime", "timerfd_settime", "timer_getoverrun", "timer_gettime", "timer_settime", "times", "tkill", "truncate", "umask", "uname", "unlink", "unlinkat", "unshare", "utime", "utimensat", "utimes", "vfork", "vmsplice", "wait4", "waitid", "write", "writev"},
					Action: "SCMP_ACT_ALLOW",
				},
				{
					Names:  []string{"ptrace"},
					Action: "SCMP_ACT_TRACE",
				},
				{
					Names:  []string{"personality"},
					Action: "SCMP_ACT_ALLOW",
					Args: []SeccompArg{
						{
							Index: 0,
							Value: 0,
							Op:    "SCMP_CMP_EQ",
						},
					},
				},
				{
					Names:  []string{"personality"},
					Action: "SCMP_ACT_ALLOW",
					Args: []SeccompArg{
						{
							Index: 0,
							Value: 8,
							Op:    "SCMP_CMP_EQ",
						},
					},
				},
				{
					Names:  []string{"personality"},
					Action: "SCMP_ACT_ALLOW",
					Args: []SeccompArg{
						{
							Index: 0,
							Value: 4294967295,
							Op:    "SCMP_CMP_EQ",
						},
					},
				},
			},
		}

		// Save the profile
		if err := m.SaveSeccompProfile(profile); err != nil {
			return err
		}

		m.logger.WithField("profile", profile.Name).Info("Created default seccomp profile")
	}

	// Create default capability profile
	if _, exists := m.capabilityProfiles[m.defaultCapabilityProfile]; !exists {
		profile := CapabilityProfile{
			Name:        m.defaultCapabilityProfile,
			Description: "Default capability profile with safe defaults",
			Add:         []string{"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"},
			Drop:        []string{"ALL"},
		}

		// Save the profile
		if err := m.SaveCapabilityProfile(profile); err != nil {
			return err
		}

		m.logger.WithField("profile", profile.Name).Info("Created default capability profile")
	}

	return nil
}

// SaveSeccompProfile saves a seccomp profile to disk
func (m *DefaultsManager) SaveSeccompProfile(profile SeccompProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate the profile
	if profile.Name == "" {
		return fmt.Errorf("%w: empty name", ErrInvalidSeccompProfile)
	}

	// Ensure the profile has the required fields
	if profile.DefaultAction == "" {
		profile.DefaultAction = "SCMP_ACT_ERRNO"
	}

	if len(profile.Architectures) == 0 {
		profile.Architectures = []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"}
	}

	// Create the profile path
	path := filepath.Join(m.configPath, "seccomp", fmt.Sprintf("%s.json", profile.Name))

	// Marshal the profile to JSON
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal seccomp profile: %w", err)
	}

	// Save the profile
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to save seccomp profile: %w", err)
	}

	// Update the path
	profile.Path = path

	// Add the profile to the map
	m.seccompProfiles[profile.Name] = profile

	m.logger.WithField("profile", profile.Name).Info("Saved seccomp profile")

	return nil
}

// GetSeccompProfile gets a seccomp profile
func (m *DefaultsManager) GetSeccompProfile(name string) (SeccompProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get the profile
	profile, exists := m.seccompProfiles[name]
	if !exists {
		return SeccompProfile{}, fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}

	return profile, nil
}

// GetDefaultSeccompProfile gets the default seccomp profile
func (m *DefaultsManager) GetDefaultSeccompProfile() (SeccompProfile, error) {
	return m.GetSeccompProfile(m.defaultSeccompProfile)
}

// SetDefaultSeccompProfile sets the default seccomp profile
func (m *DefaultsManager) SetDefaultSeccompProfile(name string) error {
	// Check if the profile exists
	_, err := m.GetSeccompProfile(name)
	if err != nil {
		return err
	}

	// Set the default profile
	m.mu.Lock()
	m.defaultSeccompProfile = name
	m.mu.Unlock()

	m.logger.WithField("profile", name).Info("Set default seccomp profile")

	return nil
}

// DeleteSeccompProfile deletes a seccomp profile
func (m *DefaultsManager) DeleteSeccompProfile(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get the profile
	profile, exists := m.seccompProfiles[name]
	if !exists {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}

	// Check if it's the default profile
	if name == m.defaultSeccompProfile {
		return fmt.Errorf("cannot delete default seccomp profile: %s", name)
	}

	// Delete the profile file
	if err := os.Remove(profile.Path); err != nil {
		return fmt.Errorf("failed to delete seccomp profile: %w", err)
	}

	// Remove the profile from the map
	delete(m.seccompProfiles, name)

	m.logger.WithField("profile", name).Info("Deleted seccomp profile")

	return nil
}

// SaveCapabilityProfile saves a capability profile to disk
func (m *DefaultsManager) SaveCapabilityProfile(profile CapabilityProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate the profile
	if profile.Name == "" {
		return fmt.Errorf("invalid capability profile: empty name")
	}

	// Create the profile path
	path := filepath.Join(m.configPath, "capabilities", fmt.Sprintf("%s.json", profile.Name))

	// Marshal the profile to JSON
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal capability profile: %w", err)
	}

	// Save the profile
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to save capability profile: %w", err)
	}

	// Add the profile to the map
	m.capabilityProfiles[profile.Name] = profile

	m.logger.WithField("profile", profile.Name).Info("Saved capability profile")

	return nil
}

// GetCapabilityProfile gets a capability profile
func (m *DefaultsManager) GetCapabilityProfile(name string) (CapabilityProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get the profile
	profile, exists := m.capabilityProfiles[name]
	if !exists {
		return CapabilityProfile{}, fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}

	return profile, nil
}

// GetDefaultCapabilityProfile gets the default capability profile
func (m *DefaultsManager) GetDefaultCapabilityProfile() (CapabilityProfile, error) {
	return m.GetCapabilityProfile(m.defaultCapabilityProfile)
}

// SetDefaultCapabilityProfile sets the default capability profile
func (m *DefaultsManager) SetDefaultCapabilityProfile(name string) error {
	// Check if the profile exists
	_, err := m.GetCapabilityProfile(name)
	if err != nil {
		return err
	}

	// Set the default profile
	m.mu.Lock()
	m.defaultCapabilityProfile = name
	m.mu.Unlock()

	m.logger.WithField("profile", name).Info("Set default capability profile")

	return nil
}

// DeleteCapabilityProfile deletes a capability profile
func (m *DefaultsManager) DeleteCapabilityProfile(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get the profile
	_, exists := m.capabilityProfiles[name]
	if !exists {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}

	// Check if it's the default profile
	if name == m.defaultCapabilityProfile {
		return fmt.Errorf("cannot delete default capability profile: %s", name)
	}

	// Delete the profile file
	path := filepath.Join(m.configPath, "capabilities", fmt.Sprintf("%s.json", name))
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete capability profile: %w", err)
	}

	// Remove the profile from the map
	delete(m.capabilityProfiles, name)

	m.logger.WithField("profile", name).Info("Deleted capability profile")

	return nil
}

// InstallAppArmorProfile installs an AppArmor profile
func (m *DefaultsManager) InstallAppArmorProfile(name, content string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate the profile
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrInvalidAppArmorProfile)
	}

	if content == "" {
		return fmt.Errorf("%w: empty content", ErrInvalidAppArmorProfile)
	}

	// Create the profile path
	path := filepath.Join(m.configPath, "apparmor", name)

	// Save the profile
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to save AppArmor profile: %w", err)
	}

	// Add the profile to the map
	m.apparmorProfiles[name] = path

	// Load the profile
	// Note: In a real implementation, we would execute the 'apparmor_parser' command to load the profile
	m.logger.WithField("profile", name).Info("Installed AppArmor profile")

	return nil
}

// GetAppArmorProfile gets an AppArmor profile
func (m *DefaultsManager) GetAppArmorProfile(name string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get the profile path
	path, exists := m.apparmorProfiles[name]
	if !exists {
		return "", fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}

	// Read the profile
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read AppArmor profile: %w", err)
	}

	return string(data), nil
}

// GetDefaultAppArmorProfile gets the default AppArmor profile
func (m *DefaultsManager) GetDefaultAppArmorProfile() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.defaultAppArmorProfile
}

// SetDefaultAppArmorProfile sets the default AppArmor profile
func (m *DefaultsManager) SetDefaultAppArmorProfile(name string) error {
	// Check if the profile exists
	_, exists := m.apparmorProfiles[name]
	if !exists {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}

	// Set the default profile
	m.mu.Lock()
	m.defaultAppArmorProfile = name
	m.mu.Unlock()

	m.logger.WithField("profile", name).Info("Set default AppArmor profile")

	return nil
}

// DeleteAppArmorProfile deletes an AppArmor profile
func (m *DefaultsManager) DeleteAppArmorProfile(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get the profile path
	path, exists := m.apparmorProfiles[name]
	if !exists {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}

	// Check if it's the default profile
	if name == m.defaultAppArmorProfile {
		return fmt.Errorf("cannot delete default AppArmor profile: %s", name)
	}

	// Delete the profile file
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete AppArmor profile: %w", err)
	}

	// Remove the profile from the map
	delete(m.apparmorProfiles, name)

	m.logger.WithField("profile", name).Info("Deleted AppArmor profile")

	return nil
}

// ApplySecureDefaults applies secure defaults to container create options
func (m *DefaultsManager) ApplySecureDefaults(ctx context.Context, createOptions *container.Config, hostConfig *container.HostConfig) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Apply seccomp profile
	seccompProfile, err := m.GetSeccompProfile(m.defaultSeccompProfile)
	if err == nil {
		if hostConfig.SecurityOpt == nil {
			hostConfig.SecurityOpt = make([]string, 0)
		}

		// Convert the profile to the expected format
		// Note: In a real implementation, we would fully implement this
		seccompJson, err := json.Marshal(seccompProfile)
		if err == nil {
			hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, fmt.Sprintf("seccomp=%s", seccompJson))
		} else {
			m.logger.WithError(err).Error("Failed to apply seccomp profile")
		}
	} else {
		m.logger.WithError(err).Error("Failed to get seccomp profile")
	}

	// Apply AppArmor profile
	if _, exists := m.apparmorProfiles[m.defaultAppArmorProfile]; exists {
		if hostConfig.SecurityOpt == nil {
			hostConfig.SecurityOpt = make([]string, 0)
		}
		hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, fmt.Sprintf("apparmor=%s", m.defaultAppArmorProfile))
	}

	// Apply capability profile
	capabilityProfile, err := m.GetCapabilityProfile(m.defaultCapabilityProfile)
	if err == nil {
		// Apply capabilities
		if len(capabilityProfile.Add) > 0 {
			hostConfig.CapAdd = capabilityProfile.Add
		}
		if len(capabilityProfile.Drop) > 0 {
			hostConfig.CapDrop = capabilityProfile.Drop
		}
	} else {
		m.logger.WithError(err).Error("Failed to get capability profile")
	}

	// Additional security settings
	hostConfig.Privileged = false    // Disable privileged mode
	hostConfig.ReadonlyRootfs = true // Make root filesystem read-only
	// hostConfig.NoNewPrivileges = true // Field removed, use SecurityOpt
	hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, "no-new-privileges:true")
	hostConfig.OomScoreAdj = 500          // Adjust OOM score
	createOptions.NetworkDisabled = false // Enable networking
	createOptions.StopSignal = "SIGTERM"  // Use SIGTERM by default

	return nil
}

// ApplyCustomSecuritySettings applies custom security settings to container create options
func (m *DefaultsManager) ApplyCustomSecuritySettings(ctx context.Context, createOptions *container.Config, hostConfig *container.HostConfig, seccompProfile, apparmorProfile, capabilityProfile string) error {
	// Apply seccomp profile if specified
	if seccompProfile != "" {
		profile, err := m.GetSeccompProfile(seccompProfile)
		if err != nil {
			return err
		}

		if hostConfig.SecurityOpt == nil {
			hostConfig.SecurityOpt = make([]string, 0)
		}

		// Convert the profile to the expected format
		seccompJson, err := json.Marshal(profile)
		if err != nil {
			return fmt.Errorf("failed to marshal seccomp profile: %w", err)
		}

		hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, fmt.Sprintf("seccomp=%s", seccompJson))
	}

	// Apply AppArmor profile if specified
	if apparmorProfile != "" {
		if _, exists := m.apparmorProfiles[apparmorProfile]; !exists {
			return fmt.Errorf("%w: %s", ErrProfileNotFound, apparmorProfile)
		}

		if hostConfig.SecurityOpt == nil {
			hostConfig.SecurityOpt = make([]string, 0)
		}

		hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, fmt.Sprintf("apparmor=%s", apparmorProfile))
	}

	// Apply capability profile if specified
	if capabilityProfile != "" {
		profile, err := m.GetCapabilityProfile(capabilityProfile)
		if err != nil {
			return err
		}

		// Apply capabilities
		if len(profile.Add) > 0 {
			hostConfig.CapAdd = profile.Add
		}
		if len(profile.Drop) > 0 {
			hostConfig.CapDrop = profile.Drop
		}
	}

	return nil
}

// ListSeccompProfiles lists all seccomp profiles
func (m *DefaultsManager) ListSeccompProfiles() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	profiles := make([]string, 0, len(m.seccompProfiles))
	for name := range m.seccompProfiles {
		profiles = append(profiles, name)
	}

	return profiles
}

// ListAppArmorProfiles lists all AppArmor profiles
func (m *DefaultsManager) ListAppArmorProfiles() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	profiles := make([]string, 0, len(m.apparmorProfiles))
	for name := range m.apparmorProfiles {
		profiles = append(profiles, name)
	}

	return profiles
}

// ListCapabilityProfiles lists all capability profiles
func (m *DefaultsManager) ListCapabilityProfiles() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	profiles := make([]string, 0, len(m.capabilityProfiles))
	for name := range m.capabilityProfiles {
		profiles = append(profiles, name)
	}

	return profiles
}

// IsSeccompEnabled checks if seccomp is enabled
func (m *DefaultsManager) IsSeccompEnabled() bool {
	// In a real implementation, we would check the host kernel
	return true
}

// IsAppArmorEnabled checks if AppArmor is enabled
func (m *DefaultsManager) IsAppArmorEnabled() bool {
	// In a real implementation, we would check the host kernel
	return true
}
