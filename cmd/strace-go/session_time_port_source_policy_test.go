package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionUsesTimeFormatterPort(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd", "strace-go", "session_composition.go"))
	if !strings.Contains(source, "TimeFormatter traceTimeFormatter") {
		t.Fatal("traceSessionDeps must expose the time formatter port")
	}
	if strings.Contains(source, "TimeFormatter *TimeFormatter") {
		t.Fatal("traceSessionDeps still exposes concrete TimeFormatter")
	}
}

type fakeSessionTimeFormatter struct {
	prefix string
	now    uint64
}

func (f *fakeSessionTimeFormatter) Prefix(uint64, traceTimePolicy) string {
	return f.prefix
}

func (f *fakeSessionTimeFormatter) NowMonoNs() uint64 {
	return f.now
}

func TestTraceSessionAcceptsTimeFormatterPort(t *testing.T) {
	formatter := &fakeSessionTimeFormatter{prefix: "TIME ", now: 42}
	session := newTestTraceSession(traceSessionDeps{TimeFormatter: formatter})

	if session.dependencies.TimeFormatter != formatter {
		t.Fatal("session did not retain the injected time formatter port")
	}
	if session.timeFormatterState() != formatter {
		t.Fatal("session time accessor did not retain the injected time formatter port")
	}
	if session.textRenderer().timeFormatter != formatter {
		t.Fatal("text renderer did not receive the injected time formatter port")
	}
}

var _ traceTimeFormatter = (*fakeSessionTimeFormatter)(nil)
