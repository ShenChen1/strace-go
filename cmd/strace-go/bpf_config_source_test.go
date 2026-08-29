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
	opts := cli.ParseArgs([]string{"-f", "-k", "-y", "-Y", "-e", "trace=write", "/bin/true"})
	config := newTraceBPFConfig(opts)

	opts.FollowForks = false
	opts.StackTrace = false
	opts.ShowPaths = false
	opts.DecodePIDsComm = false
	opts.TraceSyscalls["write"] = false
	opts.TraceSyscalls["read"] = true

	if !config.followForks || !config.captureStack || !config.fdState || !config.decodePIDsComm || config.elidePlainEnter || config.elideNonBlockingPlainEnter {
		t.Fatalf("BPF config lost scalar snapshot: %#v", config)
	}
	requirePlanHasSyscall(t, config.syscallFilter, "write")
	requirePlanLacksSyscall(t, config.syscallFilter, "read")
}

func TestBuildRuntimeConfigEnablesPIDCommCapture(t *testing.T) {
	value, err := buildRuntimeConfig(traceBPFConfig{decodePIDsComm: true}, nil)
	if err != nil {
		t.Fatalf("buildRuntimeConfig(decode-pids=comm) error = %v", err)
	}
	if value&bpfConfigDecodePIDComm == 0 {
		t.Fatalf("runtime config = %#x, want pid comm capture bit", value)
	}
}

func TestNewTraceBPFConfigNilOptionsIsEmpty(t *testing.T) {
	config := newTraceBPFConfig(nil)
	if config.captureStack || config.followForks || config.emitEnter || config.fdState || config.elidePlainEnter || config.elideNonBlockingPlainEnter ||
		config.syscallFilter.enabled || config.syscallFilter.negated || len(config.syscallFilter.ids) != 0 {
		t.Fatalf("nil options produced non-empty BPF config: %#v", config)
	}
	if config.eventRingbufCapacity != traceDefaultEventRingbufCapacity {
		t.Fatalf("nil options ringbuf capacity = %d, want %d", config.eventRingbufCapacity, traceDefaultEventRingbufCapacity)
	}
}

func TestBPFConfigSelectsPlainEnterElisionByOutputMode(t *testing.T) {
	text := newTraceBPFConfig(cli.ParseArgs([]string{"/bin/true"}))
	if !text.elidePlainEnter || !text.elideNonBlockingPlainEnter {
		t.Fatalf("plain text config = %#v, want restricted plain-enter elision", text)
	}
	json := newTraceBPFConfig(cli.ParseArgs([]string{"--event-format=json", "/bin/true"}))
	if !json.elidePlainEnter || json.elideNonBlockingPlainEnter {
		t.Fatalf("plain JSON config = %#v, want all plain generic elision", json)
	}
	handler := newTraceBPFConfig(cli.ParseArgs([]string{"--event-format=handler", "/bin/true"}))
	if !handler.elidePlainEnter || handler.elideNonBlockingPlainEnter {
		t.Fatalf("handler config = %#v, want all plain generic elision", handler)
	}
	for _, args := range [][]string{
		{"--event-format=reader", "/bin/true"},
		{"--event-format=none", "/bin/true"},
		{"--event-format=json", "--debug-events", "/bin/true"},
		{"--event-format=json", "-y", "/bin/true"},
		{"--event-format=json", "-P", "/tmp", "/bin/true"},
		{"--event-format=text", "--debug-events", "/bin/true"},
		{"--event-format=text", "-y", "/bin/true"},
		{"--event-format=text", "-P", "/tmp", "/bin/true"},
		{"--event-format=handler", "--debug-events", "/bin/true"},
		{"--event-format=handler", "-y", "/bin/true"},
		{"--event-format=handler", "-P", "/tmp", "/bin/true"},
	} {
		if config := newTraceBPFConfig(cli.ParseArgs(args)); config.elidePlainEnter || config.elideNonBlockingPlainEnter {
			t.Fatalf("config %v unexpectedly elides plain enter: %#v", args, config)
		}
	}
}

func TestPlainEnterElisionIDsKeepBlockingAndSpecializedRoutes(t *testing.T) {
	restricted := plainEnterElisionIDs(true)
	if !containsUint32(restricted, syscallIDByName(t, "getpid")) {
		t.Fatal("restricted plain-enter set is missing getpid")
	}
	for _, name := range []string{"read", "openat", "sendfile", "prctl"} {
		if containsUint32(restricted, syscallIDByName(t, name)) {
			t.Fatalf("restricted plain-enter set unexpectedly contains %s", name)
		}
	}
	for _, name := range []string{"clock_gettime", "clock_getres", "gettimeofday", "arch_prctl", "get_robust_list"} {
		if !containsUint32(restricted, syscallIDByName(t, name)) {
			t.Fatalf("restricted plain-enter set is missing standalone exit syscall %s", name)
		}
	}
	if shouldElidePlainEnterForSyscall(syscallEventTraitTableSize+1, true) {
		t.Fatal("unknown syscall was added to restricted plain-enter set")
	}
	all := plainEnterElisionIDs(false)
	if !containsUint32(all, syscallIDByName(t, "getpid")) {
		t.Fatal("all plain-enter set is missing getpid")
	}
	if containsUint32(all, syscallIDByName(t, "read")) {
		t.Fatal("all plain-enter set contains specialized read route")
	}
}

func containsUint32(values []uint32, want uint32) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
