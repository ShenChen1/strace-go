package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestSessionCompositionConsumesExplicitConfig(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_composition.go"))
	mainSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/main.go"))
	launchSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/launch_config.go"))
	for _, forbidden := range []string{
		"strace-go/pkg/cli",
		"*cli.Options",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("session composition still owns CLI/bootstrap input: %q", forbidden)
		}
	}
	if strings.Contains(source, "func attachPIDs(") {
		t.Fatal("session composition must not own bootstrap attach PID helper")
	}
	if !strings.Contains(source, "config traceSessionConfig") ||
		!strings.Contains(launchSource, "session:   newTraceSessionConfig(opts)") ||
		!strings.Contains(mainSource, "newTraceLaunchConfig(opts)") {
		t.Fatal("composeTraceSession must consume traceSessionConfig")
	}
	configCall := strings.Index(mainSource, "newTraceLaunchConfig(opts)")
	targetCall := strings.Index(mainSource, "targetRuntime, targetPid, fdSeed, err := targetBootstrap.Resolve(config.targets)")
	if configCall < 0 || targetCall < 0 || configCall > targetCall {
		t.Fatalf("session config must be formed before target startup: config=%d target=%d", configCall, targetCall)
	}
}

func TestTraceSessionConfigSnapshotsConstructionInputs(t *testing.T) {
	opts := cli.ParseArgs([]string{"-f", "-k", "--event-format=json", "/bin/true"})
	opts.StringLimit = 17
	opts.HexEscapeMode = 2
	opts.XlatFormat = "verbose"
	config := newTraceSessionConfig(opts)
	if config.eventPolicy == nil || config.outputPolicy == nil || config.catalog == nil || config.decoder == nil {
		t.Fatal("session config is missing construction snapshots")
	}
	if config.resolver == nil {
		t.Fatal("stack-enabled session config is missing resolver")
	}

	opts.EventFormat = cli.EventFormatText
	opts.FollowForks = false
	opts.StackTrace = false
	opts.StringLimit = 1
	opts.HexEscapeMode = 0
	opts.XlatFormat = "raw"
	if !config.outputPolicy.IsJSON() || !config.outputPolicy.FollowForks() {
		t.Fatal("session config output policy changed after CLI mutation")
	}
	if !config.eventPolicy.TrackForkIdentity() || !config.eventPolicy.ShouldDeferUnmatchedExits() {
		t.Fatal("session config event policy changed after CLI mutation")
	}
	if config.decoder.StringLimit != 17 || config.decoder.HexEscapeMode != 2 {
		t.Fatalf("decoder snapshot = limit:%d hex:%d, want 17/2", config.decoder.StringLimit, config.decoder.HexEscapeMode)
	}
	if config.catalog.Format() != "verbose" {
		t.Fatalf("catalog format = %q, want verbose", config.catalog.Format())
	}
}
