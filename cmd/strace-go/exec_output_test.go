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
	session := newTraceSession(traceSessionDeps{
		TargetPID: 100,
		Opts:      opts,
		OutWriter: out,
		State:     newTraceState(),
	})
	return session, res, ctx, out
}

func TestForkChildLeaderExecvePrintsNormalResume(t *testing.T) {
	session, res, ctx, out := execOutputTestState()
	scMeta := ctx.ScMeta

	session.syscallTextOutput().HandleEvent(syscallEventContext{
		view:           syscallEventView{valid: true, pid: 200, tid: 200, ret: -514},
		meta:           scMeta,
		handlerContext: ctx,
	}, res)
	if got := out.String(); got != "" {
		t.Fatalf("leader execve enter output = %q, want no output before success", got)
	}

	session.syscallTextOutput().HandleEvent(syscallEventContext{
		view:           syscallEventView{valid: true, pid: 200, tid: 200, ret: 0},
		meta:           scMeta,
		handlerContext: ctx,
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
	scMeta := ctx.ScMeta

	session.syscallTextOutput().HandleEvent(syscallEventContext{
		view:           syscallEventView{valid: true, pid: 200, tid: 201, ret: -514},
		meta:           scMeta,
		handlerContext: ctx,
	}, res)
	session.syscallTextOutput().HandleEvent(syscallEventContext{
		view:           syscallEventView{valid: true, pid: 200, tid: 201, ret: 0},
		meta:           scMeta,
		handlerContext: ctx,
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
