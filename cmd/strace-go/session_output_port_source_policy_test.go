package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionFinalizerUsesOutputPort(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd", "strace-go", "session_composition.go"))
	if !strings.Contains(source, "Output        traceFinalizerOutput") {
		t.Fatal("traceSessionDeps must expose the finalizer output port")
	}
	if strings.Contains(source, "Output        *TraceOutput") {
		t.Fatal("traceSessionDeps still exposes concrete TraceOutput")
	}
}

type fakeSessionFinalizerOutput struct {
	writeCalls int
	closeCalls int
}

func (o *fakeSessionFinalizerOutput) Write(data []byte) (int, error) {
	o.writeCalls++
	return len(data), nil
}

func (o *fakeSessionFinalizerOutput) Close() error {
	o.closeCalls++
	return nil
}

func TestTraceSessionAcceptsFinalizerOutputPort(t *testing.T) {
	output := &fakeSessionFinalizerOutput{}
	session := newTestTraceSession(traceSessionDeps{Output: output})

	if session.dependencies.Output != output {
		t.Fatal("session did not retain the injected finalizer output port")
	}
	if session.traceRunFinalizer().output != output {
		t.Fatal("finalizer did not receive the injected output port")
	}
}

var _ traceFinalizerOutput = (*fakeSessionFinalizerOutput)(nil)
