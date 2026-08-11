package meta_test

import (
	"testing"

	"strace-go/pkg/meta"
)

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

	for _, tableName := range []string{"fsconfig_cmds", "fsopen_flags", "fspick_flags", "fiemap_flags", "fiemap_extent_flags"} {
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
