package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionBaseAccessorsDoNotLazyInitialize(t *testing.T) {
	root := filepath.Join(repoRootForTest(t), "cmd/strace-go")
	files, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".go") || strings.HasSuffix(file.Name(), "_test.go") {
			continue
		}
		source := readTextFile(t, filepath.Join(root, file.Name()))
		for _, assignment := range []string{
			"\ts.state =",
			"\ts.fdState =",
			"\ts.runtime =",
			"\ts.summary =",
			"\ts.timeFormatter =",
		} {
			if strings.Contains(source, assignment) {
				t.Fatalf("production file %s still lazily assigns %s", file.Name(), assignment)
			}
		}
	}
}

func TestZeroValueTraceSessionDoesNotBuildBaseDependencies(t *testing.T) {
	session := &traceSession{}

	if session.traceState() != nil {
		t.Fatal("zero-value traceSession unexpectedly created trace state")
	}
	if session.fdStateStore() != nil {
		t.Fatal("zero-value traceSession unexpectedly created FD state")
	}
	if session.runtimeService() != nil {
		t.Fatal("zero-value traceSession unexpectedly created runtime service")
	}
	if session.summaryStats() != nil {
		t.Fatal("zero-value traceSession unexpectedly created summary stats")
	}
	if session.timeFormatterState() != nil {
		t.Fatal("zero-value traceSession unexpectedly created time formatter")
	}
	if session.dependencies.State != nil || session.dependencies.FDState != nil || session.dependencies.Runtime != nil ||
		session.dependencies.Summary != nil || session.dependencies.TimeFormatter != nil {
		t.Fatal("zero-value traceSession gained a base dependency")
	}
}

func TestTraceSessionDoesNotDuplicateDependencyFields(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/session_runtime.go"))
	if !strings.Contains(source, "\tdependencies traceSessionDeps") {
		t.Fatal("traceSession does not expose its single dependency container")
	}
	for _, field := range []string{
		"\tcmd           *exec.Cmd",
		"\tevents        traceRingbufReader",
		"\ttargetPid     int",
		"\topts          *cli.Options",
		"\tcatalog       *meta.Catalog",
		"\tdecoder       *event.Decoder",
		"\tfdState       *FDStateStore",
		"\truntime       handler.RuntimeServices",
		"\toutWriter     io.Writer",
		"\toutput        *TraceOutput",
		"\tsummary       *SummaryStats",
		"\ttimeFormatter *TimeFormatter",
		"\tbpfObjs       *bpfObjects",
		"\tresolver      *stacktrace.Resolver",
		"\tstate         *TraceState",
		"\tclock         traceClock",
	} {
		if strings.Contains(source, field) {
			t.Fatalf("traceSession still duplicates dependency field %q", field)
		}
	}
}
