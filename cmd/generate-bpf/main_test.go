package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"strace-go/internal/architecture"
)

func TestBPFTargetArguments(t *testing.T) {
	for _, target := range []architecture.Architecture{architecture.AMD64, architecture.ARM64} {
		args := bpfArguments(target, "clang-18", "/source with spaces", "bpf", "strace.c")
		for flag, want := range map[string]string{
			"-cc": "clang-18", "-target": string(target), "-tags": "linux", "-go-package": "main",
		} {
			i := slices.Index(args, flag)
			if i < 0 || i+1 >= len(args) || args[i+1] != want {
				t.Fatalf("%s: %s should be %s: %v", target, flag, want, args)
			}
		}
		if !slices.Contains(args, "-fdebug-prefix-map=/source with spaces=.") {
			t.Fatal("source path must remain one argument and be normalized in BTF")
		}
		if strings.Contains(strings.Join(args, " "), "/usr/include") {
			t.Fatal("BPF compilation must not depend on host multiarch headers")
		}
	}
}

func TestBuildEntryRejectsUnsupportedTargets(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../..")
	for _, target := range []string{"riscv64", "aarch64", "amd64 arm64", ""} {
		cmd := exec.Command("make", "-n", "build", "ARCH="+target)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "unsupported architecture:") {
			t.Fatalf("make ARCH=%q: %v\n%s", target, err, out)
		}
	}
	cmd := exec.Command("bash", filepath.Join(root, "scripts/generate-bpf.sh"), "amd64", "arm64")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "usage:") {
		t.Fatalf("extra generation arguments: %v\n%s", err, out)
	}
}

func TestMakeTestUsesRequestedArchitecture(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	cmd := exec.Command("make", "-n", "test", "ARCH=arm64", "GO_TEST_EXEC=qemu-aarch64")
	cmd.Dir = filepath.Join(filepath.Dir(file), "../..")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), `GOARCH="arm64" go test -exec "qemu-aarch64"`) {
		t.Fatalf("cross test command: %v\n%s", err, out)
	}
}
