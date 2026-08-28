package format_test

import (
	"testing"

	"strace-go/pkg/format"
)

func TestBufferEscapeHexesOnlyNonASCIIChars(t *testing.T) {
	data := []byte{'\t', 0x0e, 'A', 0x92}

	if got := format.BufferEscape(data, len(data), len(data), 3); got != `"\t\x0eA\x92"` {
		t.Fatalf("BufferEscape() = %q, want selective hex escapes", got)
	}
}
