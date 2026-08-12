package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestBPFConfigurationConsumesBootstrapSnapshot(t *testing.T) {
	root := repoRootForTest(t)
	mainSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/main.go"))
	filterSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/syscall_filter.go"))

	for _, forbidden := range []string{
		"func buildRuntimeConfig(opts *cli.Options",
		"func configureSyscallFilter(opts *cli.Options",
		"func buildSyscallFilterPlan(opts *cli.Options",
	} {
		if strings.Contains(mainSource, forbidden) || strings.Contains(filterSource, forbidden) {
			t.Fatalf("BPF configuration still consumes CLI options directly: %q", forbidden)
		}
	}
}

func TestNewTraceBPFConfigSnapshotsCLIInputs(t *testing.T) {
	opts := cli.ParseArgs([]string{"-f", "-k", "-y", "-e", "trace=write", "/bin/true"})
	config := newTraceBPFConfig(opts)

	opts.FollowForks = false
	opts.StackTrace = false
	opts.ShowPaths = false
	opts.TraceSyscalls["write"] = false
	opts.TraceSyscalls["read"] = true

	if !config.followForks || !config.captureStack || !config.fdState {
		t.Fatalf("BPF config lost scalar snapshot: %#v", config)
	}
	requirePlanHasSyscall(t, config.syscallFilter, "write")
	requirePlanLacksSyscall(t, config.syscallFilter, "read")
}

func TestNewTraceBPFConfigNilOptionsIsEmpty(t *testing.T) {
	config := newTraceBPFConfig(nil)
	if config.captureStack || config.followForks || config.emitEnter || config.fdState ||
		config.syscallFilter.enabled || config.syscallFilter.negated || len(config.syscallFilter.ids) != 0 {
		t.Fatalf("nil options produced non-empty BPF config: %#v", config)
	}
}
