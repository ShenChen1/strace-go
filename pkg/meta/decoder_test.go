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
