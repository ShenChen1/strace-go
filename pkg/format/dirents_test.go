package format_test

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/format"
)

var (
	direntCountSink    int
	direntCompleteSink bool
)

func TestCountDirents(t *testing.T) {
	data := append(testDirent64Record(24), testDirent64Record(32)...)

	if got, complete := format.CountDirents(data, len(data), format.DirentLayout64); got != 2 || !complete {
		t.Fatalf("CountDirents() = %d, want 2", got)
	}
	if got, complete := format.CountDirents(data, 24, format.DirentLayout64); got != 1 || !complete {
		t.Fatalf("CountDirents(truncated count) = %d, want 1", got)
	}
	if got, complete := format.CountDirents(data[:30], len(data), format.DirentLayout64); got != 1 || complete {
		t.Fatalf("CountDirents(truncated data) = %d, want 1", got)
	}
}

func TestCountDirentsDoesNotAllocate(t *testing.T) {
	data := append(testDirent64Record(24), testDirent64Record(32)...)
	allocs := testing.AllocsPerRun(100, func() {
		direntCountSink, direntCompleteSink = format.CountDirents(
			data, len(data), format.DirentLayout64,
		)
	})
	if allocs != 0 {
		t.Fatalf("CountDirents allocations = %v, want 0", allocs)
	}
}

func TestDecodeDirentsFormatsLegacyLayout(t *testing.T) {
	data := testDirentRecord(format.DirentLayoutLegacy, 24, 4, "..")
	snapshot := format.DecodeDirents(data, len(data), format.DirentLayoutLegacy)

	if snapshot.Count() != 1 || !snapshot.Complete() {
		t.Fatalf("legacy snapshot = count:%d complete:%v, want 1/true", snapshot.Count(), snapshot.Complete())
	}
	want := `[{d_ino=11, d_off=22, d_reclen=24, d_name="..", d_type=DT_DIR}]`
	if got := snapshot.Verbose(0); got != want {
		t.Fatalf("legacy verbose = %q, want %q", got, want)
	}
}

func TestDecodeDirentsFormats64Layout(t *testing.T) {
	data := testDirentRecord(format.DirentLayout64, 24, 8, ".")
	snapshot := format.DecodeDirents(data, len(data), format.DirentLayout64)

	want := `[{d_ino=11, d_off=22, d_reclen=24, d_type=DT_REG, d_name="."}]`
	if got := snapshot.Verbose(0); got != want {
		t.Fatalf("dirent64 verbose = %q, want %q", got, want)
	}
}

func TestDecodeDirentsStopsAtMalformedRecord(t *testing.T) {
	data := append(testDirentRecord(format.DirentLayout64, 24, 4, "."), make([]byte, 18)...)
	snapshot := format.DecodeDirents(data, len(data), format.DirentLayout64)

	if snapshot.Count() != 1 || snapshot.Complete() {
		t.Fatalf("malformed snapshot = count:%d complete:%v, want 1/false", snapshot.Count(), snapshot.Complete())
	}
	want := `[{d_ino=11, d_off=22, d_reclen=24, d_type=DT_DIR, d_name="."}, ...]`
	if got := snapshot.Verbose(0); got != want {
		t.Fatalf("malformed verbose = %q, want %q", got, want)
	}
}

func testDirent64Record(reclen uint16) []byte {
	data := make([]byte, reclen)
	binary.LittleEndian.PutUint16(data[16:18], reclen)
	return data
}

func testDirentRecord(layout format.DirentLayout, reclen uint16, dType byte, name string) []byte {
	data := make([]byte, reclen)
	binary.LittleEndian.PutUint64(data[0:8], 11)
	binary.LittleEndian.PutUint64(data[8:16], 22)
	binary.LittleEndian.PutUint16(data[16:18], reclen)
	if layout == format.DirentLayout64 {
		data[18] = dType
		copy(data[19:], name)
		return data
	}
	copy(data[18:], name)
	data[len(data)-1] = dType
	return data
}
