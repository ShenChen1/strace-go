package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/handler"
)

func TestSessionUsesSnapshotDecoderPort(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd", "strace-go", "session_composition.go"))
	if !strings.Contains(source, "Decoder       handler.SnapshotDecoder") {
		t.Fatal("traceSessionDeps must expose the snapshot decoder port")
	}
	if strings.Contains(source, "Decoder       *event.Decoder") {
		t.Fatal("traceSessionDeps still exposes concrete event.Decoder")
	}
}

type fakeSessionSnapshotDecoder struct{}

func (fakeSessionSnapshotDecoder) DecodeString(int, uint64, []byte, int32, string, int) string {
	return "decoded"
}

func (fakeSessionSnapshotDecoder) EscapeMode() int {
	return 0
}

func TestTraceSessionAcceptsSnapshotDecoderPort(t *testing.T) {
	decoder := fakeSessionSnapshotDecoder{}
	session := newTestTraceSession(traceSessionDeps{Decoder: decoder})

	if session.dependencies.Decoder != decoder {
		t.Fatal("session did not retain the injected snapshot decoder port")
	}
	if session.traceEventRouter().contextDeps.decoder != decoder {
		t.Fatal("event context did not receive the injected snapshot decoder port")
	}
}

var _ handler.SnapshotDecoder = fakeSessionSnapshotDecoder{}
