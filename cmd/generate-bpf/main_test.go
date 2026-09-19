package main

import (
	"os"
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

func TestSelectFDSetLengthUsesUnsignedDivision(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	header := filepath.Join(filepath.Dir(file), "../..", "bpf", "syscall_select_direct_event_v2.h")
	data, err := os.ReadFile(header)
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	if !strings.Contains(source, "return (u32)(((u32)nfds + 7U) / 8U);") {
		t.Fatal("select fdset length must use unsigned division for eBPF compilation")
	}
	if strings.Contains(source, "return (u32)((nfds + 7) / 8);") {
		t.Fatal("select fdset length still uses signed division")
	}
}

func TestNormalizeGeneratedBuildTagRestrictsX86ToAMD64(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "cmd", "strace-go")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, "bpf_x86_bpfel.go")
	data := []byte("//go:build (386 || amd64) && linux\n\npackage main\n")
	if err := os.WriteFile(file, data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := normalizeGeneratedBuildTag(architecture.AMD64, directory, "bpf"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if want := "//go:build linux && amd64"; !strings.Contains(string(got), want) {
		t.Fatalf("normalized build tag = %q, want %q", got, want)
	}
}

func TestNormalizeGeneratedBuildTagLeavesARM64ArtifactUntouched(t *testing.T) {
	directory := t.TempDir()
	if err := normalizeGeneratedBuildTag(architecture.ARM64, directory, "bpf"); err != nil {
		t.Fatal(err)
	}
}

func TestBuildEntryRejectsUnsupportedTargets(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../..")
	for _, target := range []string{"386", "arm", "riscv64", "aarch64", "amd64 arm64", ""} {
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

func TestMakeTestRequiresNativeHost(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	cmd := exec.Command("make", "-n", "test", "ARCH=arm64")
	cmd.Dir = filepath.Join(filepath.Dir(file), "../..")
	out, err := cmd.CombinedOutput()
	if runtime.GOARCH == "arm64" {
		if err != nil || !strings.Contains(string(out), `GOARCH="arm64" go test ./...`) {
			t.Fatalf("native arm64 test command: %v\n%s", err, out)
		}
		return
	}
	if err == nil || !strings.Contains(string(out), "native tests require a native Linux/arm64 host") {
		t.Fatalf("cross-architecture test was not rejected: %v\n%s", err, out)
	}
}

func TestMakeTestRejectsExecutionWrapper(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	cmd := exec.Command("make", "-n", "test", "ARCH="+runtime.GOARCH, "GO_TEST_EXEC=external-runner")
	cmd.Dir = filepath.Join(filepath.Dir(file), "../..")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "GO_TEST_EXEC is disabled") {
		t.Fatalf("execution wrapper was accepted: %v\n%s", err, out)
	}
}

func TestExitCaptureHelpersBoundDynamicReadLengths(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../..")

	checks := []struct {
		relPath string
		snippet string
	}{
		{
			relPath: "bpf/syscall_bpf_exit_direct_event_v2.h",
			snippet: "if (copied_len > BPF_DIRECT_OBJ_INFO_MAX)",
		},
		{
			relPath: "bpf/syscall_fs_capture_direct_event_v2.h",
			snippet: "if (copied_len > FS_DIRECT_GETDENTS_BYTES_MAX)",
		},
		{
			relPath: "bpf/syscall_xattr_capture_direct_event_v2.h",
			snippet: "if (copied_len > XATTR_DIRECT_VALUE_MAX)",
		},
		{
			relPath: "bpf/syscall_key_capture_direct_event_v2.h",
			snippet: "if (copied_len > KEY_DIRECT_PAYLOAD_MAX)",
		},
	}

	for _, check := range checks {
		data, err := os.ReadFile(filepath.Join(root, check.relPath))
		if err != nil {
			t.Fatalf("failed to read %s: %v", check.relPath, err)
		}
		if !strings.Contains(string(data), `asm volatile ("" : "+r"(copied_len));`) ||
			!strings.Contains(string(data), check.snippet) {
			t.Fatalf("%s must bound copied_len with inline asm before bpf_probe_read_user", check.relPath)
		}
	}
}
