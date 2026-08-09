package main

import (
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseTracepointFormatExtractsArguments(t *testing.T) {
	input := strings.NewReader(`name: sys_enter_openat
format:
	field:unsigned short common_type;
	field:int __syscall_nr;
	field:int dfd;
	field:const char * filename;
	field:int flags;
	field:umode_t mode;
	field:__data_loc char[] __filename_val;
`)

	got, err := parseTracepointFormat("openat", input)
	if err != nil {
		t.Fatalf("parseTracepointFormat() error = %v", err)
	}
	want := SyscallMeta{
		Name:     "openat",
		Args:     []string{"dfd", "filename", "flags", "mode"},
		ArgTypes: []string{"int", "const char *", "int", "umode_t"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTracepointFormat() = %#v, want %#v", got, want)
	}
}

func TestParseTracepointFormatAllowsZeroArgumentSyscall(t *testing.T) {
	got, err := parseTracepointFormat("getpid", strings.NewReader(
		"field:unsigned short common_type;\nfield:int __syscall_nr;\n",
	))
	if err != nil {
		t.Fatalf("parseTracepointFormat() error = %v", err)
	}
	if len(got.Args) != 0 || len(got.ArgTypes) != 0 || got.Name != "getpid" {
		t.Fatalf("parseTracepointFormat() = %#v, want zero-argument metadata", got)
	}
}

func TestSplitTracepointFieldNormalizesAttachedPointer(t *testing.T) {
	name, argType, ok := splitTracepointField("const char *filename")
	if !ok {
		t.Fatal("splitTracepointField() ok = false, want true")
	}
	if name != "filename" || argType != "const char *" {
		t.Fatalf("splitTracepointField() = (%q, %q), want (%q, %q)", name, argType, "filename", "const char *")
	}
}

func TestKernelTracepointFormatSourceUsesAvailableRoot(t *testing.T) {
	root := "/fake/tracing/events/syscalls"
	path := filepath.Join(root, "sys_enter_close", "format")
	fsys := fakeTracepointFormatFileSystem{files: map[string][]byte{
		path: []byte("field:int __syscall_nr;\nfield:unsigned int fd;\n"),
	}}
	source := kernelTracepointFormatSource{fs: fsys, roots: []string{root}}

	got, err := source.LoadTracepointSyscalls([]string{"close", "missing"})
	if err != nil {
		t.Fatalf("LoadTracepointSyscalls() error = %v", err)
	}
	want := map[string]SyscallMeta{
		"close": {Name: "close", Args: []string{"fd"}, ArgTypes: []string{"unsigned int"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadTracepointSyscalls() = %#v, want %#v", got, want)
	}
}

func TestKernelTracepointFormatSourceFallsBackToDebugRoot(t *testing.T) {
	primaryRoot := "/fake/tracing/events/syscalls"
	debugRoot := "/fake/debug/tracing/events/syscalls"
	path := filepath.Join(debugRoot, "sys_enter_close", "format")
	fsys := fakeTracepointFormatFileSystem{files: map[string][]byte{
		path: []byte("field:int __syscall_nr;\nfield:int fd;\n"),
	}}
	source := kernelTracepointFormatSource{fs: fsys, roots: []string{primaryRoot, debugRoot}}

	got, err := source.LoadTracepointSyscalls([]string{"close"})
	if err != nil {
		t.Fatalf("LoadTracepointSyscalls() error = %v", err)
	}
	if got["close"].Args[0] != "fd" {
		t.Fatalf("metadata = %#v, want debug root metadata", got["close"])
	}
}

func TestKernelTracepointFormatSourceFailsWithoutReadableRoot(t *testing.T) {
	primaryRoot := "/fake/tracing/events/syscalls"
	debugRoot := "/fake/debug/tracing/events/syscalls"
	fsys := fakeTracepointRootFileSystem{rootErrors: map[string]error{
		primaryRoot: fs.ErrNotExist,
		debugRoot:   fs.ErrPermission,
	}}
	source := kernelTracepointFormatSource{fs: fsys, roots: []string{primaryRoot, debugRoot}}

	_, err := source.LoadTracepointSyscalls([]string{"close"})
	if err == nil || !strings.Contains(err.Error(), "no readable syscall tracepoint root") {
		t.Fatalf("LoadTracepointSyscalls() error = %v, want unavailable-root error", err)
	}
}

func TestKernelTracepointFormatSourceAcceptsOneReadableRoot(t *testing.T) {
	root := "/fake/tracing/events/syscalls"
	path := filepath.Join(root, "sys_enter_close", "format")
	fsys := fakeTracepointRootFileSystem{
		fakeTracepointFormatFileSystem: fakeTracepointFormatFileSystem{files: map[string][]byte{
			path: []byte("field:int __syscall_nr;\nfield:unsigned int fd;\n"),
		}},
		rootErrors: map[string]error{root: nil},
	}
	source := kernelTracepointFormatSource{fs: fsys, roots: []string{root}}

	got, err := source.LoadTracepointSyscalls([]string{"close"})
	if err != nil || got["close"].Args[0] != "fd" {
		t.Fatalf("LoadTracepointSyscalls() = %#v, error %v, want close metadata", got, err)
	}
}

func TestTracepointLookupNamesIncludesKernelSendfileAlias(t *testing.T) {
	names := tracepointLookupNames([]string{"sendfile"}, btfNameToSyscallent)

	if !containsString(names, "sendfile") || !containsString(names, "sendfile64") {
		t.Fatalf("tracepoint names = %v, want sendfile and sendfile64", names)
	}
}

func TestTracepointFormatSourceRejectsUnsafeName(t *testing.T) {
	source := kernelTracepointFormatSource{fs: fakeTracepointFormatFileSystem{}}
	for _, name := range []string{"../close", "close-range", "close\\\\range", ""} {
		if _, err := source.LoadTracepointSyscalls([]string{name}); err == nil {
			t.Errorf("LoadTracepointSyscalls(%q) error = nil, want unsafe name error", name)
		}
	}
}

func TestSyscallMetadataLoaderUsesTracepointFallback(t *testing.T) {
	loader := syscallMetadataLoader{
		btfSource: fakeBTFSource{syscalls: map[string]SyscallMeta{}},
		tracepointSource: fakeTracepointSyscallSource{syscalls: map[string]SyscallMeta{
			"close": {Name: "close", Args: []string{"fd"}, ArgTypes: []string{"unsigned int"}},
		}},
		entrySource:       fakeEntrySource{entries: []syscallentEntry{{ID: 3, Name: "close", Argc: 1, Flags: "TD"}}},
		fallbackOverrides: map[string]SyscallMeta{},
		aliases:           map[string]string{},
	}

	got, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := SyscallMeta{
		Name:     "close",
		Args:     []string{"fd"},
		ArgTypes: []string{"unsigned int"},
		Flags:    "TD",
	}
	if !reflect.DeepEqual(got[3], want) {
		t.Fatalf("metadata = %#v, want %#v", got[3], want)
	}
}

func TestSyscallMetadataLoaderUsesTracepointAliasFallback(t *testing.T) {
	var requested []string
	loader := syscallMetadataLoader{
		btfSource: fakeBTFSource{syscalls: map[string]SyscallMeta{}},
		tracepointSource: fakeTracepointSyscallSource{
			syscalls: map[string]SyscallMeta{
				"newfstat": {Name: "newfstat", Args: []string{"fd", "statbuf"}, ArgTypes: []string{"unsigned int", "struct stat *"}},
			},
			requested: &requested,
		},
		entrySource:       fakeEntrySource{entries: []syscallentEntry{{ID: 5, Name: "fstat", Argc: 2, Flags: "TF"}}},
		fallbackOverrides: map[string]SyscallMeta{},
		aliases:           map[string]string{"newfstat": "fstat"},
	}

	got, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := SyscallMeta{Name: "fstat", Args: []string{"fd", "statbuf"}, ArgTypes: []string{"unsigned int", "struct stat *"}, Flags: "TF"}
	if !reflect.DeepEqual(got[5], want) {
		t.Fatalf("metadata = %#v, want %#v", got[5], want)
	}
	if !containsString(requested, "newfstat") {
		t.Fatalf("tracepoint names = %v, want alias newfstat", requested)
	}
}

func TestSyscallMetadataLoaderIgnoresTracepointArityMismatch(t *testing.T) {
	loader := syscallMetadataLoader{
		btfSource: fakeBTFSource{syscalls: map[string]SyscallMeta{}},
		tracepointSource: fakeTracepointSyscallSource{syscalls: map[string]SyscallMeta{
			"close": {Name: "close", Args: []string{"fd", "extra"}, ArgTypes: []string{"int", "int"}},
		}},
		entrySource:       fakeEntrySource{entries: []syscallentEntry{{ID: 3, Name: "close", Argc: 1, Flags: "TD"}}},
		fallbackOverrides: map[string]SyscallMeta{},
		aliases:           map[string]string{},
	}

	got, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got[3].Args[0] != "arg0" || got[3].ArgTypes[0] != "unsigned long" {
		t.Fatalf("metadata = %#v, want dummy metadata", got[3])
	}
}

type fakeTracepointFormatFileSystem struct {
	files map[string][]byte
}

func (f fakeTracepointFormatFileSystem) ReadFile(path string) ([]byte, error) {
	data, ok := f.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return data, nil
}

type fakeTracepointRootFileSystem struct {
	fakeTracepointFormatFileSystem
	rootErrors map[string]error
}

func (f fakeTracepointRootFileSystem) CheckTracepointRoot(path string) error {
	if err, ok := f.rootErrors[path]; ok {
		return err
	}
	return fs.ErrNotExist
}

type fakeTracepointSyscallSource struct {
	syscalls  map[string]SyscallMeta
	requested *[]string
}

func (f fakeTracepointSyscallSource) LoadTracepointSyscalls(names []string) (map[string]SyscallMeta, error) {
	if f.requested != nil {
		*f.requested = append(*f.requested, names...)
	}
	return f.syscalls, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
