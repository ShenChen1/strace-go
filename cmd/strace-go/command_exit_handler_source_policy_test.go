package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestCommandExitHandlerUsesNarrowPorts(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "cmd/strace-go/command_exit_handler.go"))
	if err != nil {
		t.Fatalf("read command_exit_handler.go: %v", err)
	}
	text := string(source)
	for _, required := range []string{
		"type traceCommandExitStatusPort interface",
		"type traceExitStatusLinePort interface",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("command exit handler is missing narrow port %q", required)
		}
	}
	for _, forbidden := range []string{
		"exitStatus *ExitStatusCoordinator",
		"renderer   *TextRenderer",
		"ExitStatus *ExitStatusCoordinator",
		"Renderer   *TextRenderer",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("command exit handler still depends on concrete owner %q", forbidden)
		}
	}
}

type fakeCommandExitStatusPort struct {
	markedPID      int
	markedFallback string
	flushedPID     int
}

func (p *fakeCommandExitStatusPort) MarkExitedWithFallback(pid int, fallback string) {
	p.markedPID = pid
	p.markedFallback = fallback
}

func (p *fakeCommandExitStatusPort) FlushFallback(pid int) {
	p.flushedPID = pid
}

type fakeExitStatusLinePort struct {
	tid    int
	status uint64
}

func (p *fakeExitStatusLinePort) ExitStatusLine(tid int, status uint64) string {
	p.tid = tid
	p.status = status
	return "fallback\n"
}

func TestCommandExitHandlerUsesInjectedPorts(t *testing.T) {
	status := &fakeCommandExitStatusPort{}
	line := &fakeExitStatusLinePort{}
	handler := newTraceCommandExitHandler(TraceCommandExitHandlerDeps{
		Policy:     newTraceOutputPolicy(&cli.Options{EventFormat: cli.EventFormatText}),
		TargetPID:  101,
		ExitStatus: status,
		Renderer:   line,
	})

	handler.MarkExited(traceCommandExitResult{exited: true, exitCode: 7})
	handler.FlushFallback()

	if status.markedPID != 101 || status.markedFallback != "fallback\n" || status.flushedPID != 101 {
		t.Fatalf("status port calls = %+v, want pid/fallback/flush 101/fallback/101", status)
	}
	if line.tid != 101 || line.status != 7 {
		t.Fatalf("line port args = %d/%d, want 101/7", line.tid, line.status)
	}
}
