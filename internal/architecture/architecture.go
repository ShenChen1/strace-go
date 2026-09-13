package architecture

import "fmt"

// Architecture identifies a Linux little-endian native 64-bit syscall ABI.
type Architecture string

const (
	AMD64 Architecture = "amd64"
	ARM64 Architecture = "arm64"
)

func Parse(target string) (Architecture, error) {
	switch Architecture(target) {
	case AMD64, ARM64:
		return Architecture(target), nil
	default:
		return "", fmt.Errorf("unsupported architecture: %s; supported architectures: amd64, arm64", target)
	}
}

func Select(explicit, environment, host string) (Architecture, error) {
	if explicit != "" {
		return Parse(explicit)
	}
	if environment != "" {
		return Parse(environment)
	}
	return Parse(host)
}

func (a Architecture) LinuxName() string {
	switch a {
	case AMD64:
		return "x86_64"
	case ARM64:
		return "aarch64"
	default:
		return ""
	}
}

func ValidateRuntime(goos, target, machine string) error {
	arch, err := Parse(target)
	if err != nil {
		return err
	}
	if goos != "linux" {
		return fmt.Errorf("unsupported operating system: %s; supported operating system: linux", goos)
	}
	if machine != arch.LinuxName() {
		return fmt.Errorf("architecture mismatch: userspace linux/%s, kernel %s; native 64-bit ABI required", target, machine)
	}
	return nil
}
