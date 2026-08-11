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
	for _, snippet := range []string{
		"appendOwnedPayloadSection(merged, section)",
		"return pending",
		"copyPayloadSections(payload)",
	} {
		if !strings.Contains(state, snippet) {
			t.Fatalf("event state ownership boundary missing %q", snippet)
		}
	}

	reader := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_reader.go"))
	if !strings.Contains(reader, "r.sink.Handle(envelope)") {
		t.Fatal("event reader must synchronously route decoded payload before ringbuf reuse")
	}
}
