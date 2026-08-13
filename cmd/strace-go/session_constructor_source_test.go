package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceSessionConstructorDoesNotNormalizeDefaults(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/session_composition.go"))
	if strings.Contains(source, "normalizeTraceSession") {
		t.Fatal("production session constructor must not normalize missing dependencies")
	}
}

func TestMainInjectsSessionRuntimeAndSummary(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/session_composition.go"))
	if !strings.Contains(source, "Runtime:       handler.NewRuntime()") {
		t.Fatal("main must inject the session runtime service")
	}
	if !strings.Contains(source, "Summary:       newSummaryStats()") {
		t.Fatal("main must inject session summary stats")
	}
}

func TestNewTraceSessionRejectsMissingCoreDependency(t *testing.T) {
	_, err := newTraceSession(traceSessionDeps{})
	if err == nil || !strings.Contains(err.Error(), "Events") {
		t.Fatalf("newTraceSession() error = %v, want missing Events dependency", err)
	}
}

func TestNewTestTraceSessionProvidesFixtureDependencies(t *testing.T) {
	session := newTestTraceSession(traceSessionDeps{})
	if session.traceState() == nil || session.fdStateStore() == nil || session.runtimeService() == nil {
		t.Fatal("test session helper did not provide core state dependencies")
	}
}

func TestDefaultHandlerResolverDoesNotCreateRegistryFallback(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/syscall_handler_runner.go"))
	if strings.Contains(source, "handler.NewRegistry().Handle") {
		t.Fatal("default handler resolver must not create a registry outside session composition")
	}
}

func TestEventContextDependsOnRegistryPort(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/syscall_event_context.go"))
	if !strings.Contains(source, "registry handler.RegistryPort") {
		t.Fatal("event context must depend on handler.RegistryPort")
	}
	if strings.Contains(source, "registry *handler.Registry") {
		t.Fatal("event context must not expose concrete handler.Registry")
	}
}

func TestEventContextDependsOnSnapshotDecoderPort(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/syscall_event_context.go"))
	if !strings.Contains(source, "decoder") || !strings.Contains(source, "handler.SnapshotDecoder") {
		t.Fatal("event context must depend on handler.SnapshotDecoder")
	}
	if strings.Contains(source, "decoder  *event.Decoder") {
		t.Fatal("event context must not expose concrete event.Decoder")
	}
}

func TestEventContextDependencyConstructorUsesSourcePort(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/syscall_event_context.go"))
	if !strings.Contains(source, "type syscallEventContextDependencySource interface") {
		t.Fatal("event context dependency source interface is missing")
	}
	if strings.Contains(source, "func newSyscallEventContextDeps(s *traceSession)") {
		t.Fatal("event context dependency constructor must not depend on concrete traceSession")
	}
	if strings.Contains(source, "newSyscallEventContextDepsWithPolicy") {
		t.Fatal("event context dependency construction must not rebuild policy from a session")
	}
}
