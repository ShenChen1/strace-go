package main

import (
	"reflect"
	"strings"
	"testing"

	"strace-go/pkg/meta"
)

func TestParseUnixSyscallConstantsUsesASTValues(t *testing.T) {
	source := `package unix

const (
	SYS_READ = 0
	SYS_WRITE = 1
	SYS_WRITE_ALIAS = SYS_WRITE
)
`
	got, err := parseUnixSyscallConstants(strings.NewReader(source))
	if err != nil {
		t.Fatalf("parseUnixSyscallConstants() error = %v", err)
	}
	want := map[string]int{
		"SYS_READ":        0,
		"SYS_WRITE":       1,
		"SYS_WRITE_ALIAS": 1,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseUnixSyscallConstants() = %#v, want %#v", got, want)
	}
}

func TestSyscallMetadataLoaderUsesUnixNumberSource(t *testing.T) {
	loader := syscallMetadataLoader{
		numberSource: fakeSyscallNumberSource{
			numbers: []syscallNumberEntry{{ID: 17, Name: "read"}},
		},
		semanticSource: fakeEntrySource{entries: []syscallentEntry{
			{ID: 99, Name: "read", Argc: 1, Flags: "TD"},
		}},
		btfSource: fakeBTFSource{syscalls: map[string]SyscallMeta{
			"read": {Name: "read", Args: []string{"fd"}, ArgTypes: []string{"int"}},
		}},
		aliases: map[string]string{},
	}

	got, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if _, ok := got[17]; !ok {
		t.Fatalf("Load() keys = %#v, want unix ID 17", got)
	}
	if _, ok := got[99]; ok {
		t.Fatalf("Load() accepted semantic catalog ID 99: %#v", got)
	}
}

func TestSyscallMetadataLoaderRejectsMissingSemanticEntry(t *testing.T) {
	loader := syscallMetadataLoader{
		numberSource: fakeSyscallNumberSource{
			numbers: []syscallNumberEntry{{ID: 3, Name: "close"}},
		},
		semanticSource: fakeEntrySource{entries: nil},
		btfSource:      fakeBTFSource{syscalls: map[string]SyscallMeta{}},
		aliases:        map[string]string{},
	}

	if _, err := loader.Load(); err == nil || !strings.Contains(err.Error(), "missing semantic metadata for syscall close") {
		t.Fatalf("Load() error = %v, want missing semantic metadata", err)
	}
}

func TestGeneratedTableMatchesUnixNumberSource(t *testing.T) {
	numbers, err := (unixSyscallSource{}).LoadSyscallNumbers()
	if err != nil {
		t.Fatalf("LoadSyscallNumbers() error = %v", err)
	}
	if len(meta.SyscallTable) != len(numbers) {
		t.Fatalf("generated table size = %d, unix source size = %d", len(meta.SyscallTable), len(numbers))
	}
	for _, number := range numbers {
		entry, ok := meta.SyscallTable[uint32(number.ID)]
		if !ok {
			t.Fatalf("generated table missing syscall %d (%s)", number.ID, number.Name)
		}
		if entry.Name != number.Name {
			t.Fatalf("generated syscall %d name = %q, unix source name = %q", number.ID, entry.Name, number.Name)
		}
	}
}

func TestMergeSyscallEntriesRejectsDuplicateSemanticMetadata(t *testing.T) {
	_, err := mergeSyscallEntries(
		[]syscallNumberEntry{{ID: 3, Name: "close"}},
		[]syscallentEntry{{Name: "close"}, {Name: "close"}},
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate semantic metadata for syscall close") {
		t.Fatalf("mergeSyscallEntries() error = %v, want duplicate metadata error", err)
	}
}

func TestMergeSyscallEntriesRejectsDuplicateSyscallNumbers(t *testing.T) {
	_, err := mergeSyscallEntries(
		[]syscallNumberEntry{{ID: 3, Name: "close"}, {ID: 3, Name: "read"}},
		[]syscallentEntry{{Name: "close"}, {Name: "read"}},
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate syscall number 3") {
		t.Fatalf("mergeSyscallEntries() error = %v, want duplicate number error", err)
	}
}

func TestDefaultLoaderUsesUnixNumberSource(t *testing.T) {
	loader := newDefaultSyscallMetadataLoader()
	if _, ok := loader.numberSource.(unixSyscallSource); !ok {
		t.Fatalf("number source = %T, want unixSyscallSource", loader.numberSource)
	}
}

type fakeSyscallNumberSource struct {
	numbers []syscallNumberEntry
	err     error
}

func (s fakeSyscallNumberSource) LoadSyscallNumbers() ([]syscallNumberEntry, error) {
	return s.numbers, s.err
}
