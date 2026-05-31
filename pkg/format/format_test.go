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

func TestSigset(t *testing.T) {
	tests := []struct {
		name string
		mask uint64
		want string
	}{
		{"empty", 0, "[]"},
		{"all", ^uint64(0), "~[]"},
		{"sighup", 1, "[HUP]"},
		{"sighup_sigint", 3, "[HUP INT]"},
		{"rt_sig", 1 << 34, "[35]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 8)
			for i := 0; i < 8; i++ {
				data[i] = byte(tt.mask >> (i * 8))
			}
			if got := format.Sigset(data); got != tt.want {
				t.Errorf("Sigset(%x) = %v, want %v", tt.mask, got, tt.want)
			}
		})
	}
}
