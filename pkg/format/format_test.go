package format_test

import (
	"testing"

	"strace-go/pkg/format"
)

func TestDev(t *testing.T) {
	tests := []struct {
		name string
		dev  uint64
		want string
	}{
		{"zero", 0, "makedev(0, 0)"},
		{"simple", 0x801, "makedev(0x8, 0x1)"},
		{"large", 0x12345678, "makedev(0x456, 0x12378)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := format.Dev(tt.dev)
			if got != tt.want {
				t.Errorf("Dev(%#x) = %q; want %q", tt.dev, got, tt.want)
			}
		})
	}
}

func TestWhence(t *testing.T) {
	tests := []struct {
		val  uint64
		want string
	}{
		{0, "SEEK_SET"},
		{1, "SEEK_CUR"},
		{2, "SEEK_END"},
		{3, "SEEK_DATA"},
		{4, "SEEK_HOLE"},
		{5, "5"},
	}

	for _, tt := range tests {
		got := format.Whence(tt.val)
		if got != tt.want {
			t.Errorf("Whence(%#x) = %q; want %q", tt.val, got, tt.want)
		}
	}
}
