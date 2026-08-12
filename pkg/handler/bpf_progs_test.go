package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestFormatBpfKernelVersionXlatModes(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want string
	}{
		{name: "abbrev", mode: "abbrev", want: "KERNEL_VERSION(51966, 240, 13)"},
		{name: "raw", mode: "raw", want: "0xcafef00d"},
		{name: "verbose", mode: "verbose", want: "0xcafef00d /* KERNEL_VERSION(51966, 240, 13) */"},
		{name: "default", mode: "", want: "KERNEL_VERSION(51966, 240, 13)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &Context{
				Meta: meta.NewCatalog(tt.mode),
				Opts: &cli.Options{XlatFormat: tt.mode},
			}
			if got := formatBpfKernelVersion(ctx, 0xcafef00d); got != tt.want {
				t.Fatalf("formatBpfKernelVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}
