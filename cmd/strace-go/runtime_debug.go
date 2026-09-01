package main

import (
	"fmt"
	"io"
)

type runtimeDebugWriter struct {
	output      io.Writer
	programName string
	metadata    *syscallMetadataTable
}

func newRuntimeDebugWriter(
	enabled bool,
	output io.Writer,
	programName string,
	metadata *syscallMetadataTable,
) traceRuntimeDebugObserver {
	if !enabled || output == nil || metadata == nil {
		return nil
	}
	return &runtimeDebugWriter{
		output:      output,
		programName: programName,
		metadata:    metadata,
	}
}

func (w *runtimeDebugWriter) Observe(view syscallEventView) {
	if w == nil || !view.valid || view.eventType != bpfEventTypeEnter {
		return
	}
	if _, known := w.metadata.lookup(view.sysID); known {
		return
	}
	fmt.Fprintf(w.output, "%s: pid %d invalid syscall %#x\n", w.programName, view.pid, view.sysID)
}

var _ traceRuntimeDebugObserver = (*runtimeDebugWriter)(nil)
