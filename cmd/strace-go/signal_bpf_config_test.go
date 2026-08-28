package main

import (
	"testing"

	"strace-go/pkg/cli"
)

func TestTraceBPFConfigEnablesRealSignalsUnlessNone(t *testing.T) {
	enabled := newTraceBPFConfig(cli.ParseArgs([]string{"/bin/true"}))
	if !enabled.emitSignal {
		t.Fatal("default BPF config disabled signal delivery")
	}
	disabled := newTraceBPFConfig(cli.ParseArgs([]string{"-e", "signal=none", "/bin/true"}))
	if disabled.emitSignal {
		t.Fatal("signal=none enabled signal delivery")
	}
	value, err := buildRuntimeConfig(traceBPFConfig{emitSignal: true}, nil)
	if err != nil {
		t.Fatalf("buildRuntimeConfig(signal) error = %v", err)
	}
	if value&bpfConfigEmitSignal == 0 {
		t.Fatalf("runtime config = %#x, want signal bit", value)
	}
}
