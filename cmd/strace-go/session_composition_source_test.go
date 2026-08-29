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
	targetCall := strings.Index(mainSource, "targetRuntime, targetPid, fdSeed, err := targetBootstrap.Resolve(targets)")
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

func TestSessionCompositionBuildersUseExplicitDependencies(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/session_composition.go"))
	for _, forbidden := range []string{
		"func buildTraceSessionComponents(session *traceSession)",
		"func buildTraceSessionBase(session *traceSession)",
		"\tsession *traceSession,\n\tbase traceSessionBaseComponents",
		"\tsession *traceSession,\n\toutputPolicy traceOutputPolicyOwner",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("composition builder still hides dependencies behind session: %q", forbidden)
		}
	}
	start := strings.Index(source, "func buildTraceSessionComponents")
	if start < 0 {
		t.Fatal("buildTraceSessionComponents definition not found")
	}
	if strings.Contains(source[start:], "session.dependencies") {
		t.Fatal("composition builders still read session.dependencies")
	}
	if !strings.Contains(source, "buildTraceSessionComponents(deps)") {
		t.Fatal("newTraceSession must pass explicit deps to composition")
	}
	if !strings.Contains(source, "deps.eventContextDependencies(base.handlerRegistry)") {
		t.Fatal("composition must build event context dependencies from explicit deps")
	}
}

func TestLifecycleExitTextDoesNotCaptureSession(t *testing.T) {
	root := filepath.Join(repoRootForTest(t), "cmd/strace-go")
	compositionSource := readTextFile(t, filepath.Join(root, "session_composition.go"))
	lifecycleSource := readTextFile(t, filepath.Join(root, "lifecycle_event_handler.go"))
	exitTextSource := readTextFile(t, filepath.Join(root, "lifecycle_exit_text.go"))
	if strings.Contains(compositionSource, "session.writeLifecycleExitText") {
		t.Fatal("lifecycle composition still captures the session callback")
	}
	if strings.Contains(lifecycleSource, "func (s *traceSession) writeLifecycleExitText") {
		t.Fatal("lifecycle output still depends on a concrete traceSession")
	}
	if !strings.Contains(compositionSource, "newTraceLifecycleExitTextWriter") {
		t.Fatal("composition must create the lifecycle exit-text writer")
	}
	if !strings.Contains(exitTextSource, "type traceLifecycleExitTextPort interface") ||
		!strings.Contains(lifecycleSource, "exitText   traceLifecycleExitTextPort") {
		t.Fatal("lifecycle effects must depend on an exit-text port")
	}
}
