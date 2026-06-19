package meta_test

import (
	"testing"

	"strace-go/pkg/meta"
)

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
			got := meta.DecodeFlags(tt.val, tt.tableName)
			if got != tt.want {
				t.Errorf("DecodeFlags(%#x, %q) = %q; want %q", tt.val, tt.tableName, got, tt.want)
			}
		})
	}
}

func TestDecodeFutexFlagsVerbose(t *testing.T) {
	old := meta.XlatFormat
	meta.XlatFormat = "verbose"
	defer func() { meta.XlatFormat = old }()

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
			got := meta.DecodeFlags(tt.val, tt.tableName)
			if got != tt.want {
				t.Errorf("DecodeFlags(%#x, %q) = %q; want %q", tt.val, tt.tableName, got, tt.want)
			}
		})
	}
}
