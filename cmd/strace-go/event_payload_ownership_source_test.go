package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestEventPayloadOwnershipBoundaries(t *testing.T) {
	root := repoRootForTest(t)
	decoder := readTextFile(t, filepath.Join(root, "cmd/strace-go/trace_event_v2_decoder.go"))
	if strings.Contains(decoder, "copyPayloadSections(payloadSectionsForRawPayloadEvent") {
		t.Fatal("event decoder must not deep-copy payload sections before state ownership is known")
	}

	state := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_state.go"))
	correlation := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_syscall_correlation.go"))
	storage := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_payload_storage.go"))
	ownership := state + "\n" + correlation
	for _, snippet := range []string{
		"copyPayloadSectionsIntoStorage(payload)",
		"mergePayloadSectionsIntoStorage(pending.payloadStorage, payload)",
		"return value, true",
	} {
		if !strings.Contains(ownership, snippet) {
			t.Fatalf("event state ownership boundary missing %q", snippet)
		}
	}
	if !strings.Contains(storage, "type tracePayloadStorage struct") ||
		!strings.Contains(storage, "storage.reset()") {
		t.Fatal("payload storage recycler is missing an explicit reset boundary")
	}
	if strings.Contains(correlation, "append([]byte(nil)") {
		t.Fatal("correlation state must not allocate a fresh payload byte slice")
	}
	if !strings.Contains(correlation, "type traceSyscallCorrelationState struct") {
		t.Fatal("syscall correlation state owner is missing")
	}
	for _, forbidden := range []string{
		"\tpendingSyscalls",
		"\tpendingExits",
		"\tpendingExecArgs",
		"\tsuspendedSyscalls",
	} {
		if strings.Contains(state, forbidden) {
			t.Fatalf("TraceState must not own correlation field %q", forbidden)
		}
	}

	reader := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_reader.go"))
	if !strings.Contains(reader, "r.sink.Handle(envelope)") {
		t.Fatal("event reader must synchronously route decoded payload before ringbuf reuse")
	}

	recordDecoderSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/trace_record_decoder.go"))
	for _, snippet := range []string{
		"payloadSections []handler.PayloadSection",
		"func newTraceRingbufRecordDecoder() *traceRingbufRecordDecoder",
		"decodeTraceEventV2EnvelopeInto(rec.RawSample, &d.payloadSections)",
	} {
		if !strings.Contains(recordDecoderSource, snippet) {
			t.Fatalf("product decoder scratch boundary missing %q", snippet)
		}
	}
	if strings.Contains(recordDecoderSource, "func (d traceRingbufRecordDecoder) Decode") {
		t.Fatal("product decoder must retain scratch through a pointer owner")
	}

	composition := readTextFile(t, filepath.Join(root, "cmd/strace-go/session_composition.go"))
	if strings.Contains(composition, "traceRingbufRecordDecoder{}") {
		t.Fatal("session composition must not instantiate a value decoder that loses scratch ownership")
	}
}
