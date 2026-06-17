package event

import (
	"errors"
	"testing"
)

type fixedMemoryReader struct {
	data []byte
}

func (r fixedMemoryReader) Read(_ int, _ uint64, _ int) ([]byte, error) {
	if r.data == nil {
		return nil, errors.New("unreadable address")
	}
	return append([]byte(nil), r.data...), nil
}

func (r fixedMemoryReader) ReadRobust(pid int, addr uint64, size int, _ bool) ([]byte, error) {
	return r.Read(pid, addr, size)
}

func TestDecodeStringLimitBoundary(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "exact limit", raw: "12345678901234567890123456789012", want: `"12345678901234567890123456789012"`},
		{name: "over limit", raw: "123456789012345678901234567890123", want: `"12345678901234567890123456789012"...`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := append([]byte(tt.raw), 0)
			decoder := NewDecoder(fixedMemoryReader{data: data})
			decoder.StringLimit = 32

			if got := decoder.DecodeString(1, 0x1000, nil, -1, "execveat", 32); got != tt.want {
				t.Fatalf("DecodeString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMatchPathMatchesRawRelativeArgument(t *testing.T) {
	tracePaths := map[string]bool{"open.sample": true}
	fdMap := map[string]string{
		"123:cwd": "/tmp/tracee-subdir",
	}

	if !MatchPath(123, []int32{-1}, true, "open", 0x1000, `"open.sample"`, tracePaths, fdMap) {
		t.Fatal("relative trace path did not match raw relative syscall argument")
	}
}
