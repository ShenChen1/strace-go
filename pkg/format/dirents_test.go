package format_test

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/format"
)

func TestDirent64Count(t *testing.T) {
	data := append(testDirent64Record(24), testDirent64Record(32)...)

	if got := format.Dirent64Count(data, len(data)); got != 2 {
		t.Fatalf("Dirent64Count() = %d, want 2", got)
	}
	if got := format.Dirent64Count(data, 24); got != 1 {
		t.Fatalf("Dirent64Count(truncated count) = %d, want 1", got)
	}
	if got := format.Dirent64Count(data[:30], len(data)); got != 1 {
		t.Fatalf("Dirent64Count(truncated data) = %d, want 1", got)
	}
}

func testDirent64Record(reclen uint16) []byte {
	data := make([]byte, reclen)
	binary.LittleEndian.PutUint16(data[16:18], reclen)
	return data
}
