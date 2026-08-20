package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceEventV2DecoderValidatesHeaderOnlyOnce(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "cmd/strace-go/trace_event_v2_decoder.go"))
	headerStart := strings.Index(source, "func decodeTraceEventV2Header(")
	if headerStart < 0 {
		t.Fatal("decodeTraceEventV2Header definition not found")
	}
	headerSource := source[headerStart:]
	if next := strings.Index(headerSource, "\nfunc "); next >= 0 {
		headerSource = headerSource[:next]
	}
	if strings.Contains(headerSource, "isTraceEventV2Sample(rawSample)") {
		t.Fatal("envelope header decoding must not repeat the sample validation pass")
	}
}
