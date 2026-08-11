package meta_test

import (
	"testing"

	"strace-go/pkg/meta"
)

func decodeFlagsForTest(mode string, val uint64, tableName string) string {
	return meta.NewCatalog(mode).DecodeFlags(val, tableName)
}

func TestDecodeFlags(t *testing.T) {
	tests := []struct {
		val       uint64
		tableName string
		want      string
	}{
		{0, "open_mode_flags", "O_RDONLY"},
		{0, "futex2_flags", "FUTEX2_SIZE_U8"},
		{0x87, "futex2_flags", "FUTEX2_SIZE_U64|FUTEX2_NUMA|FUTEX2_PRIVATE"},
		{0xffffff70, "futex2_flags", "FUTEX2_SIZE_U8|0xffffff70"},
		{0xffffffff, "futex2_flags", "FUTEX2_SIZE_U64|FUTEX2_NUMA|FUTEX2_MPOL|FUTEX2_PRIVATE|0xffffff70"},
		{0xffffffff, "futexbitset", "FUTEX_BITSET_MATCH_ANY"},
		{0xfffffff1fffffff2, "futexbitset", "0xfffffff1fffffff2"},
	}

	for _, tt := range tests {
		t.Run(tt.tableName, func(t *testing.T) {
			got := decodeFlagsForTest("abbrev", tt.val, tt.tableName)
			if got != tt.want {
				t.Errorf("DecodeFlags(%#x, %q) = %q; want %q", tt.val, tt.tableName, got, tt.want)
			}
		})
	}
}

func TestDecodeFutexFlagsVerbose(t *testing.T) {
	tests := []struct {
		val       uint64
		tableName string
		want      string
	}{
		{0, "futex2_flags", "0 /* FUTEX2_SIZE_U8 */"},
		{0xffffffff, "futexbitset", "0xffffffff /* FUTEX_BITSET_MATCH_ANY */"},
	}

	for _, tt := range tests {
		t.Run(tt.tableName, func(t *testing.T) {
			got := decodeFlagsForTest("verbose", tt.val, tt.tableName)
			if got != tt.want {
				t.Errorf("DecodeFlags(%#x, %q) = %q; want %q", tt.val, tt.tableName, got, tt.want)
			}
		})
	}
}

func TestDecodeMemfdCreateFlags(t *testing.T) {
	tests := []struct {
		name string
		mode string
		val  uint64
		want string
	}{
		{name: "abbrev named bits", mode: "abbrev", val: 0x1f, want: "MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_HUGETLB|MFD_NOEXEC_SEAL|MFD_EXEC"},
		{name: "abbrev huge page", mode: "abbrev", val: 30 << 26, want: "30<<MFD_HUGE_SHIFT"},
		{name: "abbrev mixed unknown", mode: "abbrev", val: 0xffffffff, want: "MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_HUGETLB|MFD_NOEXEC_SEAL|MFD_EXEC|0x3ffffe0|63<<MFD_HUGE_SHIFT"},
		{name: "raw", mode: "raw", val: 0x78000000, want: "0x78000000"},
		{name: "verbose", mode: "verbose", val: 0x1f, want: "0x1f /* MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_HUGETLB|MFD_NOEXEC_SEAL|MFD_EXEC */"},
		{name: "verbose huge page", mode: "verbose", val: 30 << 26, want: "0x78000000 /* 30<<MFD_HUGE_SHIFT */"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeFlagsForTest(tt.mode, tt.val, "memfd_create_flags"); got != tt.want {
				t.Fatalf("DecodeFlags(%#x, memfd_create_flags) = %q, want %q", tt.val, got, tt.want)
			}
		})
	}
}

func TestDecodeBpfEnumsUseHexRawValues(t *testing.T) {
	tests := []struct {
		name string
		mode string
		val  uint64
		xlat string
		want string
	}{
		{name: "raw command", mode: "raw", val: 5, xlat: "bpf_commands", want: "0x5"},
		{name: "raw prog type", mode: "raw", val: 0x21, xlat: "bpf_prog_types", want: "0x21"},
		{name: "verbose command", mode: "verbose", val: 5, xlat: "bpf_commands", want: "0x5 /* BPF_PROG_LOAD */"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeFlagsForTest(tt.mode, tt.val, tt.xlat); got != tt.want {
				t.Fatalf("DecodeFlags(%#x, %q) = %q, want %q", tt.val, tt.xlat, got, tt.want)
			}
		})
	}
}

func TestDecodeRuntimeBpfXlatTables(t *testing.T) {
	tests := []struct {
		name string
		val  uint64
		xlat string
		want string
	}{
		{name: "map update flags", val: 3, xlat: "bpf_map_update_flags", want: "BPF_EXIST|BPF_NOEXIST"},
		{name: "fd type", val: 3, xlat: "bpf_fd_type", want: "BPF_FD_TYPE_KRETPROBE"},
		{name: "stats type zero", val: 0, xlat: "bpf_stats_type", want: "BPF_STATS_RUN_TIME"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeFlagsForTest("abbrev", tt.val, tt.xlat); got != tt.want {
				t.Fatalf("DecodeFlags(%#x, %q) = %q, want %q", tt.val, tt.xlat, got, tt.want)
			}
		})
	}
}

func TestDecodeEnumRuleBoundaries(t *testing.T) {
	tests := []struct {
		name string
		mode string
		val  uint64
		xlat string
		want string
	}{
		{name: "abbrev unknown signal decimal", mode: "abbrev", val: 64, xlat: "signalnames", want: "64"},
		{name: "raw unknown signal decimal", mode: "raw", val: 64, xlat: "signalnames", want: "64"},
		{name: "verbose unknown signal decimal", mode: "verbose", val: 64, xlat: "signalnames", want: "64"},
		{name: "abbrev unknown clock prefix", mode: "abbrev", val: 10, xlat: "clocknames", want: "0xa /* CLOCK_??? */"},
		{name: "raw unknown clock hex", mode: "raw", val: 10, xlat: "clocknames", want: "0xa"},
		{name: "abbrev unknown resource prefix", mode: "abbrev", val: 99, xlat: "resources", want: "0x63 /* RLIMIT_??? */"},
		{name: "raw unknown resource hex", mode: "raw", val: 99, xlat: "resources", want: "0x63"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeFlagsForTest(tt.mode, tt.val, tt.xlat); got != tt.want {
				t.Fatalf("DecodeFlags(%#x, %q) in %s mode = %q, want %q", tt.val, tt.xlat, tt.mode, got, tt.want)
			}
		})
	}
}

func TestDecodeRawFallbacks(t *testing.T) {
	tests := []struct {
		name string
		val  uint64
		xlat string
		want string
	}{
		{name: "unknown table zero", val: 0, xlat: "missing_xlat_table", want: "0"},
		{name: "unknown table hex", val: 0x2a, xlat: "missing_xlat_table", want: "0x2a"},
		{name: "bitflag table zero", val: 0, xlat: "open_mode_flags", want: "0"},
		{name: "bitflag table hex", val: 0x41, xlat: "open_mode_flags", want: "0x41"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeFlagsForTest("raw", tt.val, tt.xlat); got != tt.want {
				t.Fatalf("DecodeFlags(%#x, %q) in raw mode = %q, want %q", tt.val, tt.xlat, got, tt.want)
			}
		})
	}
}

func TestDecodeMadviseCmdsAsEnum(t *testing.T) {
	tests := []struct {
		name string
		mode string
		val  uint64
		want string
	}{
		{name: "abbrev known", mode: "abbrev", val: 1, want: "MADV_RANDOM"},
		{name: "abbrev generic", mode: "abbrev", val: 12, want: "MADV_MERGEABLE"},
		{name: "abbrev unknown", mode: "abbrev", val: 6, want: "0x6 /* MADV_??? */"},
		{name: "raw known", mode: "raw", val: 1, want: "0x1"},
		{name: "raw unknown", mode: "raw", val: 6, want: "0x6"},
		{name: "verbose known", mode: "verbose", val: 1, want: "0x1 /* MADV_RANDOM */"},
		{name: "verbose unknown", mode: "verbose", val: 6, want: "0x6 /* MADV_??? */"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeFlagsForTest(tt.mode, tt.val, "madvise_cmds"); got != tt.want {
				t.Fatalf("DecodeFlags(%#x, madvise_cmds) = %q, want %q", tt.val, got, tt.want)
			}
		})
	}
}
