package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestNormalizeTraceTargetOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *cli.Options
		want bool
	}{
		{name: "command only", opts: &cli.Options{CmdArgs: []string{"/bin/true"}}, want: false},
		{name: "single attach", opts: &cli.Options{AttachPids: []int{101}}, want: false},
		{name: "explicit follow", opts: &cli.Options{FollowForks: true}, want: true},
		{name: "command and attach", opts: &cli.Options{CmdArgs: []string{"/bin/true"}, AttachPids: []int{101}}, want: true},
		{name: "multiple attach", opts: &cli.Options{AttachPids: []int{101, 202}}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalizeTraceTargetOptions(tt.opts)
			if tt.opts.FollowForks != tt.want {
				t.Fatalf("FollowForks = %v, want %v", tt.opts.FollowForks, tt.want)
			}
		})
	}

	normalizeTraceTargetOptions(nil)
}

func TestNormalizedTargetPolicyReachesBPFAndGoState(t *testing.T) {
	opts := &cli.Options{
		CmdArgs:    []string{"/bin/true"},
		AttachPids: []int{101},
	}
	normalizeTraceTargetOptions(opts)

	bpfConfig := newTraceBPFConfig(opts)
	cfg, err := buildRuntimeConfig(bpfConfig, &bpfObjects{})
	if err != nil {
		t.Fatalf("buildRuntimeConfig() error = %v", err)
	}
	if cfg&bpfConfigFollowForks == 0 {
		t.Fatalf("BPF config = %#x, want follow-forks bit", cfg)
	}
	if state := newTraceStateForSession(newTraceEventPolicy(opts)); !state.trackForkIdentity {
		t.Fatal("TraceState did not receive normalized follow-forks policy")
	}
}

func TestResolveTraceTargetsDoesNotMutateTargetPolicy(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/main.go"))
	resolverStart := strings.Index(source, "func resolveTraceTargets")
	if resolverStart < 0 {
		t.Fatal("resolveTraceTargets definition not found")
	}
	if strings.Contains(source[resolverStart:], "opts.FollowForks =") {
		t.Fatal("resolveTraceTargets must not mutate FollowForks after BPF configuration")
	}

	normalizeCall := strings.Index(source, "normalizeTraceTargetOptions(opts)")
	configCall := strings.Index(source, "bpfConfig := newTraceBPFConfig(opts)")
	if normalizeCall < 0 || configCall < 0 || normalizeCall > configCall {
		t.Fatalf("target policy normalization must precede BPF snapshot: normalize=%d config=%d", normalizeCall, configCall)
	}
}
