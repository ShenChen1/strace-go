package main

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	"strace-go/internal/architecture"
	"strace-go/pkg/meta"
)

func validateTracingArchitecture() error {
	if _, err := architecture.Parse(runtime.GOARCH); err != nil {
		return err
	}
	if meta.SyscallArchitecture != runtime.GOARCH {
		return fmt.Errorf("metadata architecture mismatch: %s, userspace %s", meta.SyscallArchitecture, runtime.GOARCH)
	}
	var identity unix.Utsname
	if err := unix.Uname(&identity); err != nil {
		return fmt.Errorf("read kernel architecture: %w", err)
	}
	return architecture.ValidateRuntime(runtime.GOOS, runtime.GOARCH, unix.ByteSliceToString(identity.Machine[:]))
}

func validateBPFArchitecture(spec *ebpf.CollectionSpec, expected uint64) error {
	if spec == nil {
		return fmt.Errorf("BPF collection spec is nil")
	}
	fingerprint := spec.Variables["STRACE_GO_SYSCALL_ABI"]
	if fingerprint == nil {
		return fmt.Errorf("BPF syscall ABI fingerprint is missing; regenerate BPF for %s", meta.SyscallArchitecture)
	}
	var actual uint64
	if err := fingerprint.Get(&actual); err != nil {
		return fmt.Errorf("read BPF syscall ABI fingerprint: %w", err)
	}
	if actual != expected {
		return fmt.Errorf("BPF syscall ABI mismatch for %s: object %#x, metadata %#x; regenerate BPF", meta.SyscallArchitecture, actual, expected)
	}
	return nil
}
