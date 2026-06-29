package event

import "testing"

func TestDecodeStringLimitBoundary(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "exact limit", raw: "12345678901234567890123456789012", want: `"12345678901234567890123456789012"`},
		{name: "over limit", raw: "123456789012345678901234567890123", want: `"12345678901234567890123456789012"...`},
		{name: "fault after limit", raw: "12345678901234567890123456789012", want: `"12345678901234567890123456789012"...`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.raw)
			if tt.name != "fault after limit" {
				data = append(data, 0)
			}
			decoder := NewDecoder()
			decoder.StringLimit = 32

			if got := decoder.DecodeString(1, 0x1000, data, 0, "execveat", 32); got != tt.want {
				t.Fatalf("DecodeString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeStringUsesOnlyBpfSnapshot(t *testing.T) {
	decoder := NewDecoder()

	got := decoder.DecodeString(1, 0x1000, nil, -1, "openat", 0)
	if got != "0x1000" {
		t.Fatalf("DecodeString without BPF snapshot = %q, want pointer", got)
	}

	got = decoder.DecodeString(1, 0x1000, append([]byte("from-bpf"), 0), 9, "openat", 0)
	if got != `"from-bpf"` {
		t.Fatalf("DecodeString BPF snapshot = %q, want BPF string", got)
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
