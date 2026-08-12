package main

import (
	"errors"
	"strings"
	"testing"
)

func TestReadInitialTraceCwdReturnsReaderPath(t *testing.T) {
	cwd, err := readInitialTraceCwd(func() (string, error) {
		return "/work/tracee", nil
	})
	if err != nil {
		t.Fatalf("readInitialTraceCwd() error = %v, want nil", err)
	}
	if cwd != "/work/tracee" {
		t.Fatalf("readInitialTraceCwd() = %q, want /work/tracee", cwd)
	}
}

func TestReadInitialTraceCwdPropagatesReaderError(t *testing.T) {
	wantErr := errors.New("cwd unavailable")
	_, err := readInitialTraceCwd(func() (string, error) {
		return "", wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("readInitialTraceCwd() error = %v, want wrapped %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "get initial working directory") {
		t.Fatalf("readInitialTraceCwd() error = %v, want context", err)
	}
}

func TestStartTraceCmdReadsCwdBeforeArmingBPF(t *testing.T) {
	wantErr := errors.New("cwd unavailable")
	port := &fakeBPFTargetPort{}
	bootstrap := &traceTargetBootstrap{
		bpfRuntime: port,
		workingDirectory: func() (string, error) {
			return "", wantErr
		},
	}
	_, _, _, err := bootstrap.startTraceCmd(traceCommandSpec{args: []string{"/bin/true"}})
	if !errors.Is(err, wantErr) {
		t.Fatalf("startTraceCmd() error = %v, want wrapped %v", err, wantErr)
	}
	if port.armCalls != 0 || port.disarmCalls != 0 || len(port.addCalls) != 0 {
		t.Fatalf("BPF calls after cwd failure = %+v, want no arm/disarm/filter update", port)
	}
}
