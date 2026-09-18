package cli

import (
	"runtime"
	"testing"
)

func TestSupportedSyscallPersonalityMatchesNativeTargets(t *testing.T) {
	for _, personality := range []string{"64", "32"} {
		if !supportedSyscallPersonality(personality) {
			t.Fatalf("personality %q rejected on %s", personality, runtime.GOARCH)
		}
	}
	if runtime.GOARCH == "amd64" {
		if !supportedSyscallPersonality("x32") {
			t.Fatal("x32 personality rejected on amd64")
		}
	} else if runtime.GOARCH == "arm64" {
		if supportedSyscallPersonality("x32") {
			t.Fatal("x32 personality accepted on arm64")
		}
	}
	for _, personality := range []string{"ppc64", "riscv64"} {
		if supportedSyscallPersonality(personality) {
			t.Fatalf("unsupported personality %q accepted on %s", personality, runtime.GOARCH)
		}
	}
}
