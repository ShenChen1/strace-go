package main

import (
	"fmt"
	"io"
	"strings"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/stacktrace"
)

type TextRenderer struct {
	out           io.Writer
	opts          *cli.Options
	state         textRendererState
	timeFormatter *TimeFormatter
	bpfObjs       *bpfObjects
	resolver      *stacktrace.Resolver
}

type TextRendererDeps struct {
	Out           io.Writer
	Opts          *cli.Options
	State         textRendererState
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
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.textRenderer
}

func (r *TextRenderer) PrintUnfinishedEvent(ev syscallEventContext, res handler.Result) {
	view := ev.eventView()
	scMeta := ev.effectiveSyscallMeta()
	args := strings.Join(res.ArgParts, ", ")
	if scMeta.Name == "nanosleep" && len(res.ArgParts) > 0 {
		args = res.ArgParts[0]
	}
	line := fmt.Sprintf("%s(%s <unfinished ...>", scMeta.Name, args)
	fmt.Fprintf(r.out, "%s%s%s\n", r.timePrefix(view.enterTime), r.pidPrefix(int(view.tid)), line)
}

func (r *TextRenderer) PrintExecResumeFromView(view syscallEventView, argLine string) {
	timePrefix := r.timePrefix(view.enterTime)
	pidPrefix := r.pidPrefix(int(view.tid))
	fmt.Fprintf(r.out, "%s%s%s%s= 0%s\n",
		timePrefix, pidPrefix, argLine, r.padding(timePrefix, pidPrefix, argLine), r.durationSuffix(view.duration))
}

func (r *TextRenderer) PrintExecPidChangedFromView(view syscallEventView, argLine string) {
	tid := int(view.tid)
	tgid := int(view.pid)
	fmt.Fprintf(r.out, "%s%-5d %s <pid changed to %d ...>\n", r.timePrefix(view.enterTime), tid, trimTrailingParen(argLine), tgid)
}

func (r *TextRenderer) PrintExecSupersededUnfinishedFromView(view syscallEventView, argLine string) {
	tid := int(view.tid)
	fmt.Fprintf(r.out, "%s%-5d %s <unfinished ...>\n", r.timePrefix(view.enterTime), tid, trimTrailingParen(argLine))
}

func (r *TextRenderer) PrintSupersededSuspendedResumeFromView(view syscallEventView, syscallName string) {
	timePrefix := r.timePrefix(view.enterTime)
	tgid := int(view.pid)
	switch syscallName {
	case "rt_sigsuspend":
		fmt.Fprintf(r.out, "%s%-5d <... rt_sigsuspend resumed>) = ?\n", timePrefix, tgid)
	case "nanosleep":
		fmt.Fprintf(r.out, "%s%-5d <... nanosleep resumed> <unfinished ...>) = ?\n", timePrefix, tgid)
	}
}

func (r *TextRenderer) PrintThreadExecveSupersededFromView(view syscallEventView, syscallName string) {
	timePrefix := r.timePrefix(view.enterTime)
	tid := int(view.tid)
	tgid := int(view.pid)
	if r.opts == nil || !r.opts.QuietThreadExecve {
		fmt.Fprintf(r.out, "%s%-5d +++ superseded by execve in pid %d +++\n", timePrefix, tgid, tid)
	}
	fmt.Fprintf(r.out, "%s%-5d <... %s resumed>) = 0\n", timePrefix, tgid, syscallName)
}

func (r *TextRenderer) PrintExitSyscallEvent(ev syscallEventContext, res handler.Result) {
	line := r.exitSyscallLine(ev.eventView(), ev.effectiveSyscallMeta().Name, res)
	fmt.Fprint(r.out, line)
}

func (r *TextRenderer) ExitStatusLineFromView(view syscallEventView) string {
	return fmt.Sprintf("%s%s+++ exited with %d +++\n",
		r.timePrefix(view.enterTime), r.pidPrefix(int(view.tid)), view.args[0])
}

func (r *TextRenderer) ExitStatusLine(tid int, status uint64) string {
	enterTime := uint64(0)
	if r.timeFormatter != nil {
		enterTime = r.timeFormatter.NowMonoNs()
	}
	return r.ExitStatusLineFromView(syscallEventView{
		valid:     true,
		tid:       uint32(tid),
		enterTime: enterTime,
		args:      [6]uint64{status},
	})
}

// IMPACT: PrintSyscallEvent renders a decoded syscall from the stable event context view.
func (r *TextRenderer) PrintSyscallEvent(ev syscallEventContext, res handler.Result) {
	view := ev.eventView()
	scMeta := ev.effectiveSyscallMeta()
	ctx := ev.handlerContextForFormatting()
	tid := int(view.tid)
	line := fmt.Sprintf("%s(%s)", scMeta.Name, strings.Join(res.ArgParts, ", "))
	if ev.pendingEnter != nil && ev.pendingEnter.unfinishedPrinted {
		line = fmt.Sprintf("<... %s resumed>)", scMeta.Name)
	} else if r.consumeSuspended(tid) {
		if scMeta.Name == "nanosleep" {
			line = fmt.Sprintf("<... %s resumed> <unfinished ...>)", scMeta.Name)
		} else {
			line = fmt.Sprintf("<... %s resumed>)", scMeta.Name)
		}
	}

	timePrefix := r.timePrefix(view.enterTime)
	pidPrefix := r.pidPrefix(tid)
	retStr := formatSyscallRet(scMeta.Name, view.ret, res, ctx)
	fmt.Fprintf(r.out, "%s%s%s%s= %s%s\n",
		timePrefix, pidPrefix, line, r.padding(timePrefix, pidPrefix, line), retStr, r.durationSuffix(view.duration))
	if res.HexDumpStr != "" {
		fmt.Fprint(r.out, res.HexDumpStr)
	}
	if shouldPrintSyntheticAlarmSignal(scMeta.Name, view.ret) {
		fmt.Fprintf(r.out, "%s%s--- SIGALRM {si_signo=SIGALRM, si_code=SI_KERNEL} ---\n", timePrefix, pidPrefix)
	}

	r.printStackTrace(view.stackID)
}

func (r *TextRenderer) exitSyscallLine(view syscallEventView, syscallName string, res handler.Result) string {
	timePrefix := r.timePrefix(view.enterTime)
	pidPrefix := r.pidPrefix(int(view.tid))
	argLine := fmt.Sprintf("%s(%s)", syscallName, strings.Join(res.ArgParts, ", "))
	return fmt.Sprintf("%s%s%s%s= ?\n", timePrefix, pidPrefix, argLine, r.padding(timePrefix, pidPrefix, argLine))
}

func trimTrailingParen(argLine string) string {
	if len(argLine) > 0 && argLine[len(argLine)-1] == ')' {
		return argLine[:len(argLine)-1]
	}
	return argLine
}

func shouldPrintSyntheticAlarmSignal(syscallName string, ret int64) bool {
	if syscallName == "nanosleep" {
		return ret == -516
	}
	if syscallName == "clock_nanosleep" {
		return ret == -516 || ret == -514
	}
	return false
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
