package main

import (
	"bytes"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func execOutputTestState() (*traceSession, handler.Result, *handler.Context, *bytes.Buffer) {
	opts := cli.ParseArgs([]string{"-f", "/bin/true"})
	out := &bytes.Buffer{}
	scMeta := meta.Syscall{Name: "execve"}
	res := handler.Result{ArgParts: []string{`"/bin/true"`, `["true"]`, `0x1 /* 1 var */`}}
	ctx := &handler.Context{ScMeta: scMeta, Opts: opts}
	session := &traceSession{
		targetPid:       100,
		opts:            opts,
		outWriter:       out,
		pendingExecArgs: make(map[int]string),
	}
	return session, res, ctx, out
}

func TestForkChildLeaderExecvePrintsNormalResume(t *testing.T) {
	session, res, ctx, out := execOutputTestState()

	session.handleEventOutput(ctx, &bpfEvent{
		Pid: 200,
		Tid: 200,
		Ret: -514,
	}, res)
	if got := out.String(); got != "" {
		t.Fatalf("leader execve enter output = %q, want no output before success", got)
	}

	session.handleEventOutput(ctx, &bpfEvent{
		Pid: 200,
		Tid: 200,
		Ret: 0,
	}, res)
	got := out.String()
	if strings.Contains(got, "superseded by execve") {
		t.Fatalf("leader child execve was misclassified as superseded: %q", got)
	}
	if !strings.Contains(got, "200") || !strings.Contains(got, "execve(") || !strings.Contains(got, "= 0") {
		t.Fatalf("leader child execve output = %q, want pid-prefixed normal resume", got)
	}
}

func TestNonLeaderExecvePrintsSupersededTGID(t *testing.T) {
	session, res, ctx, out := execOutputTestState()

	session.handleEventOutput(ctx, &bpfEvent{
		Pid: 200,
		Tid: 201,
		Ret: -514,
	}, res)
	session.handleEventOutput(ctx, &bpfEvent{
		Pid: 200,
		Tid: 201,
		Ret: 0,
	}, res)

	got := out.String()
	if !strings.Contains(got, "201") || !strings.Contains(got, "<unfinished ...>") {
		t.Fatalf("non-leader execve enter output = %q, want unfinished line for tid 201", got)
	}
	if !strings.Contains(got, "200") || !strings.Contains(got, "+++ superseded by execve in pid 201 +++") {
		t.Fatalf("non-leader execve output = %q, want superseded message for tgid 200", got)
	}
	if !strings.Contains(got, "200") || !strings.Contains(got, "<... execve resumed>) = 0") {
		t.Fatalf("non-leader execve output = %q, want resumed line for tgid 200", got)
	}
}
