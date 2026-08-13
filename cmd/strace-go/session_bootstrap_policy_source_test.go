package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestTraceSessionDropsBootstrapOptionsAfterComposition(t *testing.T) {
	session := newTestTraceSessionWithOptions(&cli.Options{EventFormat: cli.EventFormatJSON}, traceSessionDeps{})
	if session.dependencies.OutputPolicy == nil || session.dependencies.OutputPolicy != session.components.outputPolicy {
		t.Fatal("session components did not reuse the injected output policy snapshot")
	}
	if session.dependencies.EventPolicy == nil {
		t.Fatal("session did not retain the event policy snapshot")
	}
	contextDeps := session.eventContextDependencies()
	if contextDeps.handlerOpts != session.dependencies.EventPolicy.HandlerOptions() ||
		contextDeps.filter != session.dependencies.EventPolicy.FilterOptions() {
		t.Fatal("session did not project the dependency-owned event policy")
	}
}

func TestTraceSessionBaseConsumesInjectedOutputPolicy(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/session_composition.go"))
	start := strings.Index(source, "func buildTraceSessionBase")
	if start < 0 {
		t.Fatal("buildTraceSessionBase definition not found")
	}
	if strings.Contains(source[start:], "newTraceOutputPolicy(deps.Opts)") {
		t.Fatal("session composition must not rebuild output policy from CLI options")
	}
	if !strings.Contains(source, "OutputPolicy") {
		t.Fatal("session dependencies must carry the constructed output policy")
	}
}

func TestTraceSessionDepsDoesNotDeclareCLIOptions(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/session_composition.go"))
	start := strings.Index(source, "type traceSessionDeps struct")
	if start < 0 {
		t.Fatal("traceSessionDeps definition not found")
	}
	end := strings.Index(source[start:], "\n}")
	if end < 0 {
		t.Fatal("traceSessionDeps body not found")
	}
	body := source[start : start+end]
	if strings.Contains(body, "*cli.Options") || strings.Contains(body, "Opts") {
		t.Fatal("traceSessionDeps must not retain CLI options")
	}
	if strings.Contains(source, "newTraceEventPolicy(deps.Opts)") || strings.Contains(source, "newTraceOutputPolicy(deps.Opts)") {
		t.Fatal("session constructor must not derive policy from CLI options")
	}
}

func TestTraceSessionRejectsMissingPolicySnapshot(t *testing.T) {
	deps := withTestTraceSessionDefaults(traceSessionDeps{})
	deps.EventPolicy = nil
	if _, err := newTraceSession(deps); err == nil || !strings.Contains(err.Error(), "EventPolicy") {
		t.Fatalf("newTraceSession() error = %v, want missing EventPolicy", err)
	}
}
