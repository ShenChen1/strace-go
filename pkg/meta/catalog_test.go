package meta_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"strace-go/pkg/meta"
)

func TestCatalogMethodsRejectNilReceiver(t *testing.T) {
	var catalog *meta.Catalog
	tests := []struct {
		name string
		call func()
	}{
		{name: "Format", call: func() { _ = catalog.Format() }},
		{name: "Table", call: func() { _, _ = catalog.Table("open_mode_flags") }},
		{name: "SyscallArgXlat", call: func() { _, _ = catalog.SyscallArgXlat("open", "flags") }},
		{name: "DecodeFlags", call: func() { _ = catalog.DecodeFlags(1, "open_mode_flags") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("nil Catalog.%s() did not panic", tt.name)
				}
			}()
			tt.call()
		})
	}
}

func TestCatalogSourceDoesNotConstructNilFallback(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "catalog.go"))
	if err != nil {
		t.Fatalf("read catalog.go: %v", err)
	}
	if strings.Contains(string(source), "NewCatalog(\"abbrev\").DecodeFlags") {
		t.Fatal("Catalog.DecodeFlags still constructs an implicit abbrev catalog")
	}
}

func TestCatalogNormalizesFormat(t *testing.T) {
	if got := meta.NewCatalog("unsupported").Format(); got != "abbrev" {
		t.Fatalf("Catalog.Format() = %q, want abbrev", got)
	}
}

func TestCatalogKeepsFormattingModesSessionLocal(t *testing.T) {
	raw := meta.NewCatalog("raw")
	verbose := meta.NewCatalog("verbose")

	if got := raw.DecodeFlags(0x40, "open_mode_flags"); got != "0x40" {
		t.Fatalf("raw DecodeFlags() = %q, want 0x40", got)
	}
	if got := verbose.DecodeFlags(0x40, "open_mode_flags"); got != "0x40 /* O_RDONLY|O_CREAT */" {
		t.Fatalf("verbose DecodeFlags() = %q, want named value", got)
	}
	if got := raw.DecodeFlags(0, "open_mode_flags"); got != "0" {
		t.Fatalf("raw zero DecodeFlags() = %q, want 0", got)
	}
}

func TestCatalogCopiesRuntimeTablesAndArgumentMappings(t *testing.T) {
	catalog := meta.NewCatalog("abbrev")

	for _, tableName := range []string{"fsconfig_cmds", "fsopen_flags", "fspick_flags", "fiemap_flags", "fiemap_extent_flags", "file_attr_at_flags", "fs_xflags"} {
		if _, ok := catalog.Table(tableName); !ok {
			t.Fatalf("Catalog.Table(%q) is missing", tableName)
		}
	}

	tests := []struct {
		syscall string
		arg     string
		xlat    string
	}{
		{syscall: "fsconfig", arg: "cmd", xlat: "fsconfig_cmds"},
		{syscall: "fsopen", arg: "flags", xlat: "fsopen_flags"},
		{syscall: "fspick", arg: "flags", xlat: "fspick_flags"},
		{syscall: "file_getattr", arg: "at_flags", xlat: "file_attr_at_flags"},
		{syscall: "file_setattr", arg: "at_flags", xlat: "file_attr_at_flags"},
	}
	for _, tt := range tests {
		got, ok := catalog.SyscallArgXlat(tt.syscall, tt.arg)
		if !ok || got != tt.xlat {
			t.Fatalf("SyscallArgXlat(%q, %q) = %q, %v; want %q", tt.syscall, tt.arg, got, ok, tt.xlat)
		}
	}
}

func TestCatalogTableReturnsIndependentEntries(t *testing.T) {
	catalog := meta.NewCatalog("abbrev")

	table, ok := catalog.Table("open_mode_flags")
	if !ok || len(table.Entries) == 0 {
		t.Fatal("Catalog.Table(open_mode_flags) returned no entries")
	}
	original := table.Entries[0].Str
	table.Entries[0].Str = "MUTATED"

	again, ok := catalog.Table("open_mode_flags")
	if !ok || len(again.Entries) == 0 {
		t.Fatal("Catalog.Table(open_mode_flags) disappeared after caller mutation")
	}
	if again.Entries[0].Str != original {
		t.Fatalf("Catalog table leaked caller mutation: got %q, want %q", again.Entries[0].Str, original)
	}
}
