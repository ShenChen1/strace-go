package main

import (
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestSyscallNameProjectionPreservesMetadataFallbacks(t *testing.T) {
	tests := []struct {
		name string
		ev   syscallEventContext
		want string
	}{
		{
			name: "event metadata wins",
			ev: syscallEventContext{
				meta:           meta.Syscall{Name: "getpid"},
				handlerContext: &handler.Context{ScMeta: meta.Syscall{Name: "pipe"}, SysName: "openat"},
			},
			want: "getpid",
		},
		{
			name: "handler catalog fallback",
			ev: syscallEventContext{
				handlerContext: &handler.Context{ScMeta: meta.Syscall{Name: "pipe"}, SysName: "openat"},
			},
			want: "pipe",
		},
		{
			name: "handler name fallback",
			ev: syscallEventContext{
				handlerContext: &handler.Context{SysName: "openat"},
			},
			want: "openat",
		},
		{name: "empty metadata", ev: syscallEventContext{}, want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.ev.syscallName(); got != test.want {
				t.Fatalf("syscallName() = %q, want %q", got, test.want)
			}
		})
	}
}
