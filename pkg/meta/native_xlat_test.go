package meta

import (
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeOpenFlags(t *testing.T) {
	catalog := NewCatalog("abbrev")
	for name, value := range map[string]uint64{"O_DIRECT": unix.O_DIRECT, "O_DIRECTORY": unix.O_DIRECTORY, "O_NOFOLLOW": unix.O_NOFOLLOW, "O_TMPFILE": unix.O_TMPFILE} {
		for _, table := range []string{"open_mode_flags", "dup3_flags"} {
			if got := catalog.DecodeFlags(value, table); !strings.Contains(got, name) {
				t.Errorf("%s(%#x) = %s, want %s", table, value, got, name)
			}
		}
	}
}

func TestARM64DoesNotNameX86MmapFlags(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("ARM64 absence contract")
	}
	for _, value := range []uint64{0x40, 0x80} {
		if got := NewCatalog("abbrev").DecodeFlags(value, "mmap_flags"); strings.Contains(got, "MAP_32BIT") || strings.Contains(got, "MAP_ABOVE4G") {
			t.Fatalf("x86-only mmap flag on ARM64: %s", got)
		}
	}
}
