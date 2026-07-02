package main

import (
	"testing"

	"strace-go/pkg/handler"
)

func TestFormatSyscallRetFormatsCommonReturns(t *testing.T) {
	tests := []struct {
		name string
		sc   string
		ret  int64
		want string
	}{
		{name: "plain", sc: "getpid", ret: 123, want: "123"},
		{name: "errno", sc: "openat", ret: -2, want: "-1 ENOENT (No such file or directory)"},
		{name: "restart", sc: "nanosleep", ret: -516, want: "? ERESTART_RESTARTBLOCK (Interrupted by signal)"},
		{name: "time state", sc: "adjtimex", ret: 5, want: "5 (TIME_ERROR)"},
		{name: "exit", sc: "exit_group", ret: 0, want: "?"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := formatSyscallRet(test.sc, test.ret, handler.Result{}, nil); got != test.want {
				t.Fatalf("formatSyscallRet(%q, %d) = %q, want %q", test.sc, test.ret, got, test.want)
			}
		})
	}
}
