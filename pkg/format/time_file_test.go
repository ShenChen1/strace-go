package format

import (
	"encoding/binary"
	"testing"
)

func TestUtimbuf(t *testing.T) {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[0:8], uint64(1492350678))
	binary.LittleEndian.PutUint64(data[8:16], uint64(1492350678))

	want := "{actime=1492350678 /* 2017-04-16T13:51:18+0000 */, modtime=1492350678 /* 2017-04-16T13:51:18+0000 */}"
	if got := Utimbuf(data); got != want {
		t.Fatalf("Utimbuf() = %q, want %q", got, want)
	}
}

func TestTimevals(t *testing.T) {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint64(data[0:8], uint64(1492358607))
	binary.LittleEndian.PutUint64(data[8:16], uint64(345678))
	binary.LittleEndian.PutUint64(data[16:24], uint64(1492356078))
	binary.LittleEndian.PutUint64(data[24:32], uint64(456789))

	want := "[{tv_sec=1492358607, tv_usec=345678} /* 2017-04-16T16:03:27.345678+0000 */, {tv_sec=1492356078, tv_usec=456789} /* 2017-04-16T15:21:18.456789+0000 */]"
	if got := Timevals(data); got != want {
		t.Fatalf("Timevals() = %q, want %q", got, want)
	}
}
