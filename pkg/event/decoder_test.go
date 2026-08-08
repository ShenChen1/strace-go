package event

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestDecodeStringExactPathMaxIsNotTruncated(t *testing.T) {
	// A path of exactly PATH_MAX-1 (4095) characters with its NUL terminator
	// inside the capture is complete; it must not gain a "..." suffix.
	raw := make([]byte, 4096)
	for i := 0; i < 4095; i++ {
		raw[i] = '/'
	}
	decoder := NewDecoder()
	got := decoder.DecodeString(1, 0x1000, raw, 0, "chdir", 0)
	want := `"` + strings.Repeat("/", 4095) + `"`
	if got != want {
		t.Fatalf("DecodeString exact PATH_MAX = %q (len %d), want %q", got, len(got), want)
	}
}

func TestDecodeStringTruncatedPathOverMaxStillShowsEllipsis(t *testing.T) {
	// A truncated path has no NUL inside the 4096-byte capture, so the decoder
	// must keep the "..." suffix and cap the printed prefix at 4095 chars.
	raw := make([]byte, 4096)
	for i := range raw {
		raw[i] = '/'
	}
	decoder := NewDecoder()
	got := decoder.DecodeString(1, 0x1000, raw, 0, "chdir", 0)
	want := `"` + strings.Repeat("/", 4095) + `"...`
	if got != want {
		t.Fatalf("DecodeString truncated path = %q, want %q", got, want)
	}
}

func TestMatchPathMatchesRawRelativeArgument(t *testing.T) {
	tracePaths := map[string]bool{"open.sample": true}
	fdMap := map[string]string{
		"123:cwd": "/tmp/tracee-subdir",
	}

	if !MatchPath(PathMatchRequest{
		Pid:        123,
		FDs:        []int32{-1},
		IsPath:     true,
		PathText:   `"open.sample"`,
		TracePaths: tracePaths,
		FDMap:      fdMap,
	}) {
		t.Fatal("relative trace path did not match raw relative syscall argument")
	}
}

func TestMatchPathFallsBackToProcFdOnFDMapMiss(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "match-path")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	fd := int32(file.Fd())
	fdMap := map[string]string{}
	tracePaths := map[string]bool{file.Name(): true}
	if !MatchPath(PathMatchRequest{
		Pid:        os.Getpid(),
		FDs:        []int32{fd},
		TracePaths: tracePaths,
		FDMap:      fdMap,
	}) {
		t.Fatal("fd path did not match via procfs fallback")
	}
}

func TestMatchPathFdTargetMatchesRealpathTraceEntry(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "stat.sample")
	if err := os.WriteFile(sample, []byte("x"), 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	tracePaths := map[string]bool{
		"stat.sample":                     true,
		filepath.Join(dir, "stat.sample"): true,
	}
	if !MatchPath(PathMatchRequest{
		Pid:        101,
		FDs:        []int32{3},
		TracePaths: tracePaths,
		FDMap: map[string]string{
			"101:3": sample,
		},
	}) {
		t.Fatal("fstat(fd resolving to realpath) should match expanded -P set")
	}
}

func TestMatchPathPrefersEventDrivenFDState(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "stat.sample")
	file, err := os.OpenFile(sample, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open sample: %v", err)
	}
	defer file.Close()

	fd := int32(file.Fd())
	// The event-driven fdMap is deterministic (fd-state syscalls keep flowing),
	// so a cached entry must be preferred over a possibly-racy live read.
	fdMap := map[string]string{fmt.Sprintf("%d:%d", os.Getpid(), fd): sample}
	tracePaths := map[string]bool{sample: true}

	if !MatchPath(PathMatchRequest{
		Pid:        os.Getpid(),
		FDs:        []int32{fd},
		TracePaths: tracePaths,
		FDMap:      fdMap,
	}) {
		t.Fatal("fstat(fd) should match -P path via event-driven fd state")
	}
	if fdMap[fmt.Sprintf("%d:%d", os.Getpid(), fd)] != sample {
		t.Fatalf("fdMap entry changed unexpectedly: %q", fdMap[fmt.Sprintf("%d:%d", os.Getpid(), fd)])
	}
}
