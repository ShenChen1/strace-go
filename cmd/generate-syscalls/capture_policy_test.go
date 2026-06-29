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
