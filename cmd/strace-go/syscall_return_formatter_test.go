package main

import (
	"testing"

	"strace-go/pkg/cli"
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

func TestFormatSyscallRetFormatsExplicitEmptyReturnDescription(t *testing.T) {
	res := handler.Result{ShowEmptyReturnDesc: true}

	if got := formatSyscallRet("select", 1, res, nil); got != "1 ()" {
		t.Fatalf("formatSyscallRet(select empty desc) = %q, want %q", got, "1 ()")
	}
}

func TestFormatSyscallRetFormatsOnlyFcntlDupReturnsAsFD(t *testing.T) {
	ctx := &handler.Context{
		Pid:       101,
		TargetPid: 101,
		Args:      [6]uint64{5, 0, 20},
		Opts:      &cli.Options{ShowPaths: true, ShowPathsMode: 1},
		FdMap:     map[string]string{"101:12": "/dev/null"},
	}

	if got := formatSyscallRet("fcntl", 12, handler.Result{}, ctx); got != "12</dev/null>" {
		t.Fatalf("F_DUPFD return = %q, want 12</dev/null>", got)
	}

	ctx.Args[1] = 3
	if got := formatSyscallRet("fcntl", 32768, handler.Result{}, ctx); got != "0x8000" {
		t.Fatalf("F_GETFL return = %q, want 0x8000", got)
	}
}
