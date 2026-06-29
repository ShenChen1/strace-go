package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCapturePolicy(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [openat]
    enter:
      ptr_arg: 1
      reads:
        - { arg: 1, size: 4096, type: string }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err != nil {
		t.Fatalf("loadCapturePolicy() error = %v", err)
	}
	if got := len(globalConfig.Rules); got != 1 {
		t.Fatalf("rules = %d, want 1", got)
	}
	rule := globalConfig.Rules[0]
	if len(rule.Syscalls) != 1 || rule.Syscalls[0] != "openat" {
		t.Fatalf("syscalls = %#v, want [openat]", rule.Syscalls)
	}
	if rule.Enter.PtrArg == nil || *rule.Enter.PtrArg != 1 {
		t.Fatalf("enter ptr_arg = %#v, want 1", rule.Enter.PtrArg)
	}
	if len(rule.Enter.Reads) != 1 || rule.Enter.Reads[0].Type != "string" {
		t.Fatalf("enter reads = %#v, want one string read", rule.Enter.Reads)
	}
}

func TestLoadCapturePolicyNormalizesPayloads(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [write]
    enter:
      ptr_arg: 1
      payloads:
        - { arg: 1, kind: bytes, direction: in, len_from_arg: 2, max: 512, offset: 0 }
  - syscalls: [openat]
    enter:
      payloads:
        - { arg: 1, kind: string, direction: in, max: 4096 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err != nil {
		t.Fatalf("loadCapturePolicy() error = %v", err)
	}
	writeRead := globalConfig.Rules[0].Enter.Reads[0]
	if want := (CaptureRead{Arg: 1, Size: 0, Offset: 0, Type: "raw"}); writeRead != want {
		t.Fatalf("write payload normalized to %#v, want %#v", writeRead, want)
	}
	openRead := globalConfig.Rules[1].Enter.Reads[0]
	if want := (CaptureRead{Arg: 1, Size: 4096, Offset: 0, Type: "string"}); openRead != want {
		t.Fatalf("string payload normalized to %#v, want %#v", openRead, want)
	}
}

func TestLoadCapturePolicyRejectsMixedReadsAndPayloads(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()
	globalConfig = Config{Rules: []CaptureRule{{Syscalls: []string{"sentinel"}}}}

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [write]
    enter:
      reads:
        - { arg: 1, size: 0, type: raw }
      payloads:
        - { arg: 1, kind: bytes, direction: in, len_from_arg: 2, max: 512 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want mixed reads/payloads error")
	}
	if got := globalConfig.Rules[0].Syscalls[0]; got != "sentinel" {
		t.Fatalf("globalConfig mutated after load error: got %q", got)
	}
}

func TestLoadCapturePolicyRejectsInvalidPayload(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [write]
    enter:
      payloads:
        - { arg: 1, kind: mystery, direction: in, max: 512 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want invalid kind error")
	}
}
