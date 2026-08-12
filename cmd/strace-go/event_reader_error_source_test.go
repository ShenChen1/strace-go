package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceEventReaderExposesReadErrors(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/event_reader.go"))
	for _, required := range []string{
		"func (r *TraceEventReader) Read(rec *ringbuf.Record, timeout time.Duration) (traceReadStatus, error)",
		"func (r *TraceEventReader) Drain(rec *ringbuf.Record) error",
		"func (r *TraceEventReader) DrainAfterDone(rec *ringbuf.Record, grace time.Duration) error",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("event reader is missing explicit error boundary %q", required)
		}
	}
}
