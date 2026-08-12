package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestTraceSessionDropsBootstrapOptionsAfterComposition(t *testing.T) {
	session := newTestTraceSession(traceSessionDeps{
		Opts: &cli.Options{EventFormat: cli.EventFormatJSON},
	})
	if session.dependencies.Opts != nil {
		t.Fatal("session retained mutable bootstrap CLI options")
	}
	if session.dependencies.OutputPolicy == nil || session.dependencies.OutputPolicy != session.components.outputPolicy {
		t.Fatal("session components did not reuse the injected output policy snapshot")
	}
	if session.dependencies.EventPolicy == nil || session.dependencies.EventPolicy != session.eventPolicy {
		t.Fatal("session retained a different event policy snapshot")
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
