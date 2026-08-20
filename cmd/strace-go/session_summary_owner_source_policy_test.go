package main

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionUsesSummaryOwnerPort(t *testing.T) {
	sessionSource := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd", "strace-go", "session_composition.go"))
	statsSource := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd", "strace-go", "summary_stats.go"))
	if !strings.Contains(statsSource, "type traceSummaryOwner interface") {
		t.Fatal("summary owner port is missing")
	}
	if !strings.Contains(sessionSource, "Summary       traceSummaryOwner") {
		t.Fatal("traceSessionDeps must expose the summary owner port")
	}
	if strings.Contains(sessionSource, "Summary       *SummaryStats") {
		t.Fatal("traceSessionDeps still exposes concrete SummaryStats")
	}
}

type fakeSessionSummaryOwner struct {
	recordCalls int
	printCalls  int
}

func (s *fakeSessionSummaryOwner) Record(string, uint64, int64) {
	s.recordCalls++
}

func (s *fakeSessionSummaryOwner) Print(io.Writer) {
	s.printCalls++
}

func TestTraceSessionAcceptsSummaryOwnerPort(t *testing.T) {
	summary := &fakeSessionSummaryOwner{}
	session := newTestTraceSession(traceSessionDeps{Summary: summary})

	if session.dependencies.Summary != summary {
		t.Fatal("session did not retain the injected summary owner port")
	}
	if session.summaryStats() != summary {
		t.Fatal("session summary accessor did not retain the injected owner")
	}
	if session.traceRunFinalizer().summary != summary {
		t.Fatal("finalizer did not receive the summary writer projection")
	}
	effects, ok := session.syscallExitPipeline().finalizer.(*traceSessionSyscallExitFinalizer)
	if !ok || effects.summary != summary {
		t.Fatal("exit finalizer did not receive the summary recorder projection")
	}
}

var _ traceSummaryOwner = (*fakeSessionSummaryOwner)(nil)
