package main

import (
	"fmt"
	"io"
	"strings"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
	"strace-go/pkg/stacktrace"
)

type TextRenderer struct {
	out           io.Writer
	opts          *cli.Options
	state         *TraceState
	timeFormatter *TimeFormatter
	bpfObjs       *bpfObjects
	resolver      *stacktrace.Resolver
}

type TextRendererDeps struct {
	Out           io.Writer
	Opts          *cli.Options
	State         *TraceState
	TimeFormatter *TimeFormatter
	BPFObjs       *bpfObjects
	Resolver      *stacktrace.Resolver
}

func newTextRenderer(deps TextRendererDeps) *TextRenderer {
	return &TextRenderer{
		out:           deps.Out,
		opts:          deps.Opts,
		state:         deps.State,
		timeFormatter: deps.TimeFormatter,
		bpfObjs:       deps.BPFObjs,
		resolver:      deps.Resolver,
	}
}

func (s *traceSession) textRenderer() *TextRenderer {
	return newTextRenderer(TextRendererDeps{
		Out:           s.outWriter,
		Opts:          s.opts,
		State:         s.traceState(),
		TimeFormatter: s.timeFormatterState(),
		BPFObjs:       s.bpfObjs,
		Resolver:      s.resolver,
	})
}

func (r *TextRenderer) PrintUnfinished(eventRaw *bpfEvent, scMeta meta.Syscall, res handler.Result) {
	args := strings.Join(res.ArgParts, ", ")
	if scMeta.Name == "nanosleep" && len(res.ArgParts) > 0 {
		args = res.ArgParts[0]
	}
	line := fmt.Sprintf("%s(%s <unfinished ...>", scMeta.Name, args)
	fmt.Fprintf(r.out, "%s%s\n", r.pidPrefix(int(eventRaw.Tid)), line)
}

func (r *TextRenderer) PrintExecResume(eventRaw *bpfEvent, argLine string) {
	timePrefix := r.timePrefix(eventRaw.EnterTime)
	pidPrefix := r.pidPrefix(int(eventRaw.Tid))
	fmt.Fprintf(r.out, "%s%s%s%s= 0%s\n",
		timePrefix, pidPrefix, argLine, r.padding(timePrefix, pidPrefix, argLine), r.durationSuffix(eventRaw.Duration))
}

func (r *TextRenderer) PrintExecPidChanged(eventRaw *bpfEvent, argLine string) {
	tid := int(eventRaw.Tid)
	tgid := int(eventRaw.Pid)
	fmt.Fprintf(r.out, "%s%-5d %s <pid changed to %d ...>\n", r.timePrefix(eventRaw.EnterTime), tid, trimTrailingParen(argLine), tgid)
}

func (r *TextRenderer) PrintExecSupersededUnfinished(eventRaw *bpfEvent, argLine string) {
	tid := int(eventRaw.Tid)
	fmt.Fprintf(r.out, "%s%-5d %s <unfinished ...>\n", r.timePrefix(eventRaw.EnterTime), tid, trimTrailingParen(argLine))
}

func (r *TextRenderer) PrintSupersededSuspendedResume(eventRaw *bpfEvent, syscallName string) {
	timePrefix := r.timePrefix(eventRaw.EnterTime)
	tgid := int(eventRaw.Pid)
	switch syscallName {
	case "rt_sigsuspend":
		fmt.Fprintf(r.out, "%s%-5d <... rt_sigsuspend resumed>) = ?\n", timePrefix, tgid)
	case "nanosleep":
		fmt.Fprintf(r.out, "%s%-5d <... nanosleep resumed> <unfinished ...>) = ?\n", timePrefix, tgid)
	}
}

func (r *TextRenderer) PrintThreadExecveSuperseded(eventRaw *bpfEvent, syscallName string) {
	timePrefix := r.timePrefix(eventRaw.EnterTime)
	tid := int(eventRaw.Tid)
	tgid := int(eventRaw.Pid)
	if r.opts == nil || !r.opts.QuietThreadExecve {
		fmt.Fprintf(r.out, "%s%-5d +++ superseded by execve in pid %d +++\n", timePrefix, tgid, tid)
	}
	fmt.Fprintf(r.out, "%s%-5d <... %s resumed>) = 0\n", timePrefix, tgid, syscallName)
}

func (r *TextRenderer) PrintExitSyscall(eventRaw *bpfEvent, scMeta meta.Syscall, res handler.Result) {
	line := r.exitSyscallLine(eventRaw, scMeta, res)
	fmt.Fprint(r.out, line)
}

func (r *TextRenderer) ExitStatusLine(eventRaw *bpfEvent) string {
	return fmt.Sprintf("%s%s+++ exited with %d +++\n",
		r.timePrefix(eventRaw.EnterTime), r.pidPrefix(int(eventRaw.Tid)), eventRaw.Args[0])
}

// IMPACT: PrintSyscall outputs a formatted syscall trace line and related text-only side effects.
func (r *TextRenderer) PrintSyscall(eventRaw *bpfEvent, scMeta meta.Syscall, res handler.Result, ctx *handler.Context) {
	tid := int(eventRaw.Tid)
	line := fmt.Sprintf("%s(%s)", scMeta.Name, strings.Join(res.ArgParts, ", "))
	if r.consumeSuspended(tid) {
		if scMeta.Name == "nanosleep" {
			line = fmt.Sprintf("<... %s resumed> <unfinished ...>)", scMeta.Name)
		} else {
			line = fmt.Sprintf("<... %s resumed>)", scMeta.Name)
		}
	}

	timePrefix := r.timePrefix(eventRaw.EnterTime)
	pidPrefix := r.pidPrefix(tid)
	retStr := formatSyscallRet(scMeta.Name, eventRaw.Ret, res, ctx)
	fmt.Fprintf(r.out, "%s%s%s%s= %s%s\n",
		timePrefix, pidPrefix, line, r.padding(timePrefix, pidPrefix, line), retStr, r.durationSuffix(eventRaw.Duration))
	if res.HexDumpStr != "" {
		fmt.Fprint(r.out, res.HexDumpStr)
	}
	if scMeta.Name == "nanosleep" && eventRaw.Ret == -516 {
		fmt.Fprintf(r.out, "%s%s--- SIGALRM {si_signo=SIGALRM, si_code=SI_KERNEL} ---\n", timePrefix, pidPrefix)
	}

	r.printStackTrace(eventRaw.StackId)
	if (scMeta.Name == "execve" || scMeta.Name == "execveat") && eventRaw.Ret < 0 && r.state != nil {
		r.state.deletePendingExecArgs(tid)
	}
}

func (r *TextRenderer) exitSyscallLine(eventRaw *bpfEvent, scMeta meta.Syscall, res handler.Result) string {
	timePrefix := r.timePrefix(eventRaw.EnterTime)
	pidPrefix := r.pidPrefix(int(eventRaw.Tid))
	argLine := fmt.Sprintf("%s(%s)", scMeta.Name, strings.Join(res.ArgParts, ", "))
	return fmt.Sprintf("%s%s%s%s= ?\n", timePrefix, pidPrefix, argLine, r.padding(timePrefix, pidPrefix, argLine))
}

func trimTrailingParen(argLine string) string {
	if len(argLine) > 0 && argLine[len(argLine)-1] == ')' {
		return argLine[:len(argLine)-1]
	}
	return argLine
}

func (r *TextRenderer) consumeSuspended(tid int) bool {
	return r.state != nil && r.state.consumeSuspendedSyscall(tid)
}

func (r *TextRenderer) timePrefix(enterTimeMonoNs uint64) string {
	if r.timeFormatter == nil {
		return ""
	}
	return r.timeFormatter.Prefix(enterTimeMonoNs, r.opts)
}

func (r *TextRenderer) pidPrefix(tid int) string {
	if r.opts != nil && r.opts.FollowForks {
		return fmt.Sprintf("%-5d ", tid)
	}
	return ""
}

func (r *TextRenderer) padding(timePrefix string, pidPrefix string, line string) string {
	padding := " "
	if r.opts == nil {
		return padding
	}
	totalLen := len(timePrefix) + len(pidPrefix) + len(line)
	if totalLen < r.opts.AlignCol {
		padding = strings.Repeat(" ", r.opts.AlignCol-totalLen)
	}
	return padding
}

func (r *TextRenderer) durationSuffix(duration uint64) string {
	if r.opts == nil || !r.opts.PrintSyscallTime {
		return ""
	}
	sec := duration / 1e9
	usec := (duration % 1e9) / 1000
	return fmt.Sprintf(" <%d.%06d>", sec, usec)
}

func (r *TextRenderer) printStackTrace(stackID int32) {
	if r.opts == nil || !r.opts.StackTrace || r.bpfObjs == nil || r.resolver == nil || stackID <= 0 {
		return
	}
	var ips [127]uint64
	if err := r.bpfObjs.StackTraces.Lookup(uint32(stackID), &ips); err != nil {
		return
	}
	for _, ip := range ips {
		if ip == 0 {
			break
		}
		fmt.Fprintf(r.out, " > %s\n", r.resolver.Resolve(ip))
	}
}
