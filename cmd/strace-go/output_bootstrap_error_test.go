package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCleanupOutputBootstrapClosesWriterBeforeWaiting(t *testing.T) {
	closeErr := errors.New("writer close failed")
	waitErr := errors.New("output command failed")
	events := make([]string, 0, 2)
	closer := &fakeTraceOutputCloser{events: &events, closeErr: closeErr}
	waiter := &fakeTraceOutputWaiter{events: &events, waitErr: waitErr}

	err := cleanupOutputBootstrap(closer, waiter)
	if !errors.Is(err, closeErr) || !errors.Is(err, waitErr) {
		t.Fatalf("cleanup error = %v, want writer and command errors", err)
	}
	if !equalStrings(events, []string{"close-writer", "wait-command"}) {
		t.Fatalf("cleanup order = %v, want writer then command", events)
	}
}

func TestCleanupOutputBootstrapDoesNotWaitWithoutStartedCommand(t *testing.T) {
	events := make([]string, 0, 1)
	closer := &fakeTraceOutputCloser{events: &events}
	waiter := &fakeTraceOutputWaiter{events: &events}

	if err := cleanupOutputBootstrap(closer, nil); err != nil {
		t.Fatalf("cleanupOutputBootstrap() error = %v, want nil", err)
	}
	if closer.closeCall != 1 || waiter.waitCall != 0 {
		t.Fatalf("cleanup calls = close:%d wait:%d, want close:1 wait:0", closer.closeCall, waiter.waitCall)
	}
}

func TestCloseOutputFileReturnsClosedFileError(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "output-bootstrap-")
	if err != nil {
		t.Fatalf("create temp output: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temp output: %v", err)
	}

	err = closeOutputFile("trace.log", file)
	if err == nil || !strings.Contains(err.Error(), "trace.log") {
		t.Fatalf("closeOutputFile() error = %v, want path-qualified error", err)
	}
}

func TestCleanupOutputBootstrapNoResourcesIsNil(t *testing.T) {
	if err := cleanupOutputBootstrap(nil, nil); err != nil {
		t.Fatalf("cleanupOutputBootstrap(nil, nil) = %v, want nil", err)
	}
}

func TestSetupOutputPreservesConfiguredPathDiagnostic(t *testing.T) {
	path := strings.Repeat(" ", 4096)
	_, err := setupOutput(path, false)
	if err == nil {
		t.Fatal("long output path unexpectedly opened")
	}
	if got, want := mainErrorText(err), path+": File name too long"; got != want {
		t.Fatalf("main error = %q, want %q", got, want)
	}
}
