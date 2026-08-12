package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunFinalizerUsesNarrowOwnerPorts(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "cmd/strace-go/run_finalizer.go"))
	if err != nil {
		t.Fatalf("read run_finalizer.go: %v", err)
	}
	text := string(source)
	for _, required := range []string{
		"type traceExitStatusFlushPort interface",
		"type traceSummaryWriter interface",
		"type traceFinalizerOutput interface",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("run finalizer is missing narrow port %q", required)
		}
	}
	for _, forbidden := range []string{
		"exitStatus      *ExitStatusCoordinator",
		"summary         *SummaryStats",
		"output          *TraceOutput",
		"ExitStatus      *ExitStatusCoordinator",
		"Summary         *SummaryStats",
		"Output          *TraceOutput",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("run finalizer still depends on concrete owner %q", forbidden)
		}
	}
}

type fakeFinalizerExitStatusPort struct {
	pids []int
}

func (p *fakeFinalizerExitStatusPort) FlushFallback(pid int) {
	p.pids = append(p.pids, pid)
}

type fakeFinalizerSummaryPort struct {
	prints int
}

func (p *fakeFinalizerSummaryPort) Print(w io.Writer) {
	p.prints++
	_, _ = io.WriteString(w, "summary\n")
}

type fakeFinalizerOutputPort struct {
	data       strings.Builder
	closeCalls int
	closeErr   error
}

func (p *fakeFinalizerOutputPort) Write(data []byte) (int, error) {
	return p.data.Write(data)
}

func (p *fakeFinalizerOutputPort) Close() error {
	p.closeCalls++
	return p.closeErr
}

func TestTraceRunFinalizerUsesInjectedOwnerPorts(t *testing.T) {
	exitStatus := &fakeFinalizerExitStatusPort{}
	summary := &fakeFinalizerSummaryPort{}
	output := &fakeFinalizerOutputPort{}
	opts := testOptions()
	opts.SummaryOnly = true
	policy := newTraceOutputPolicy(opts)
	finalizer := newTraceRunFinalizer(TraceRunFinalizerDeps{
		FormatPolicy:    policy,
		SummaryPolicy:   policy,
		TargetPID:       101,
		ExitStatus:      exitStatus,
		Summary:         summary,
		Output:          output,
		StatsDiagnostic: io.Discard,
	})

	if err := finalizer.Finish(); err != nil {
		t.Fatalf("TraceRunFinalizer.Finish() error = %v", err)
	}
	if len(exitStatus.pids) != 1 || exitStatus.pids[0] != 101 {
		t.Fatalf("flush calls = %v, want [101]", exitStatus.pids)
	}
	if summary.prints != 1 || output.closeCalls != 1 || output.data.String() != "summary\n" {
		t.Fatalf("summary/close/output = %d/%d/%q, want 1/1/summary", summary.prints, output.closeCalls, output.data.String())
	}
}
