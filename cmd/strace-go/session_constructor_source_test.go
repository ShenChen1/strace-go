package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestTraceSessionConstructorDoesNotNormalizeDefaults(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/session_composition.go"))
	if strings.Contains(source, "normalizeTraceSession") {
		t.Fatal("production session constructor must not normalize missing dependencies")
	}
}

func TestMainInjectsSessionRuntimeAndSummary(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/main.go"))
	if !strings.Contains(source, "Runtime:       handler.NewRuntime()") {
		t.Fatal("main must inject the session runtime service")
	}
	if !strings.Contains(source, "Summary:       newSummaryStats()") {
		t.Fatal("main must inject session summary stats")
	}
	if !strings.Contains(source, "PIDProbe:      systemTracePIDProbe{}") {
		t.Fatal("main must inject the session PID probe")
	}
}

func TestNewTraceSessionRejectsMissingCoreDependency(t *testing.T) {
	_, err := newTraceSession(traceSessionDeps{})
	if err == nil || !strings.Contains(err.Error(), "Events") {
		t.Fatalf("newTraceSession() error = %v, want missing Events dependency", err)
	}
}

func TestNewTestTraceSessionProvidesFixtureDependencies(t *testing.T) {
	session := newTestTraceSession(traceSessionDeps{Opts: &cli.Options{}})
	if session.traceState() == nil || session.fdStateStore() == nil || session.runtimeService() == nil {
		t.Fatal("test session helper did not provide core state dependencies")
	}
}
