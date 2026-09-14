package architecture

import (
	"strings"
	"testing"
)

func TestArchitectureDetection(t *testing.T) {
	for _, tc := range []struct{ target, machine string }{{"amd64", "x86_64"}, {"arm64", "aarch64"}} {
		arch, err := Parse(tc.target)
		if err != nil || arch.LinuxName() != tc.machine {
			t.Fatalf("Parse(%q) = %v, %v", tc.target, arch, err)
		}
		if err := ValidateRuntime("linux", tc.target, tc.machine); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnsupportedArchitecture(t *testing.T) {
	for _, target := range []string{"", "386", "arm", "riscv64", "x86_64", "aarch64"} {
		if _, err := Parse(target); err == nil || !strings.Contains(err.Error(), "supported architectures: amd64, arm64") {
			t.Fatalf("Parse(%q) = %v", target, err)
		}
	}
	for _, tc := range [][3]string{{"darwin", "arm64", "aarch64"}, {"linux", "amd64", "aarch64"}, {"linux", "arm64", "x86_64"}, {"linux", "amd64", "riscv64"}} {
		if err := ValidateRuntime(tc[0], tc[1], tc[2]); err == nil {
			t.Fatalf("accepted %v", tc)
		}
	}
}

func TestTargetPrecedence(t *testing.T) {
	for _, tc := range []struct{ explicit, environment, host, want string }{
		{"arm64", "amd64", "amd64", "arm64"}, {"", "arm64", "amd64", "arm64"}, {"", "", "amd64", "amd64"}, {"amd64", "arm64", "arm64", "amd64"},
	} {
		got, err := Select(tc.explicit, tc.environment, tc.host)
		if err != nil || string(got) != tc.want {
			t.Fatalf("Select(%+v) = %q, %v", tc, got, err)
		}
	}
	if _, err := Select("riscv64", "arm64", "amd64"); err == nil {
		t.Fatal("invalid explicit target fell back")
	}
}

func TestSyscallWrapperPrefixes(t *testing.T) {
	for target, want := range map[Architecture]string{AMD64: "__x64_sys_", ARM64: "__arm64_sys_", "riscv64": ""} {
		if got := target.SyscallWrapperPrefix(); got != want {
			t.Fatalf("%s wrapper = %q, want %q", target, got, want)
		}
	}
}
