package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

const instructionPointerHexWidth = strconv.IntSize / 4

type traceStackSnapshot struct {
	ips       [127]uint64
	available bool
}

type traceTimeFormatter interface {
	Prefix(enterTimeMonoNs uint64, policy traceTimePolicy) string
	NowMonoNs() uint64
}

type traceSymbolResolver interface {
	Resolve(ip uint64) string
}

type exitSyscallRenderer interface {
	PrintExitSyscallEvent(syscallEventContext, handler.Result)
	ExitStatusLineFromView(syscallEventView) string
}

type syscallTextRenderer interface {
	PrintSyscallEvent(syscallEventContext, handler.Result)
	PrintUnfinishedEvent(syscallEventContext, handler.Result)
}

type execSyscallRenderer interface {
	PrintSyscallEvent(syscallEventContext, handler.Result)
	PrintExecDetachedFromView(syscallEventView, string)
	PrintExecResumeFromView(syscallEventView, string)
	PrintExecPidChangedFromView(syscallEventView, string)
	PrintExecDetachedThreadSupersededFromView(syscallEventView)
	PrintExecSupersededUnfinishedFromView(syscallEventView, string)
	PrintSupersededSuspendedResumeFromView(syscallEventView, string)
	PrintThreadExecveSupersededFromView(syscallEventView, string)
}

type unfinishedSyscallRenderer interface {
	PrintUnfinishedEvent(syscallEventContext, handler.Result)
}

type TextRenderer struct {
	out           io.Writer
	policy        traceRenderPolicy
	state         textRendererState
	timeFormatter traceTimeFormatter
	stackTraces   traceStackTraceReader
	resolver      traceSymbolResolver
	targetPID     int
	lineBuffer    []byte
	taskComms     *taskCommStore
}

type TextRendererDeps struct {
	Out           io.Writer
	Policy        traceRenderPolicy
	State         textRendererState
	TimeFormatter traceTimeFormatter
	StackTraces   traceStackTraceReader
	Resolver      traceSymbolResolver
	TargetPID     int
}

func newTextRenderer(deps TextRendererDeps) *TextRenderer {
	renderer := &TextRenderer{
		out:           deps.Out,
		policy:        deps.Policy,
		state:         deps.State,
		timeFormatter: deps.TimeFormatter,
		stackTraces:   deps.StackTraces,
		resolver:      deps.Resolver,
		targetPID:     deps.TargetPID,
	}
	if renderer.renderOptions().decodePIDsComm {
		renderer.taskComms = newTaskCommStore()
		renderer.taskComms.Observe(uint32(os.Getpid()), "strace")
	}
	return renderer
}

func (s *traceSession) textRenderer() *TextRenderer {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.textRenderer
}

func (r *TextRenderer) PrintUnfinishedEvent(ev syscallEventContext, res handler.Result) {
	r.observeTaskComm(ev.eventView())
	r.selectOutputPID(int(ev.eventView().tid))
	if r.writePlainUnfinishedFast(ev, res) {
		return
	}
	view := ev.eventView()
	scMeta := ev.effectiveSyscallMeta()
	parts := res.ArgParts
	if scMeta.Name == "nanosleep" && len(res.ArgParts) > 0 {
		parts = res.ArgParts[:1]
	}
	args := r.formatArguments(ev.eventView(), scMeta, parts)
	line := fmt.Sprintf("%s%s%s(%s <unfinished ...>", r.instructionPointerPrefix(traceStackSnapshot{}), r.syscallNumberPrefix(view), scMeta.Name, args)
	fmt.Fprintf(r.out, "%s%s%s\n", r.timePrefix(view.enterTime), r.pidPrefix(int(view.tid)), line)
}

func (r *TextRenderer) PrintExecResumeFromView(view syscallEventView, argLine string) {
	r.observeTaskComm(view)
	r.selectOutputPID(int(view.tid))
	timePrefix := r.timePrefix(view.enterTime)
	pidPrefix := r.pidPrefix(int(view.tid))
	argLine = r.syscallNumberPrefix(view) + argLine
	fmt.Fprintf(r.out, "%s%s%s%s= 0%s\n",
		timePrefix, pidPrefix, argLine, r.padding(timePrefix, pidPrefix, argLine), r.durationSuffix(view.duration))
}

func (r *TextRenderer) PrintExecDetachedFromView(view syscallEventView, argLine string) {
	r.observeTaskComm(view)
	r.selectOutputPID(int(view.tid))
	fmt.Fprintf(r.out, "%s%s%s%s <detached ...>\n",
		r.timePrefix(view.enterTime),
		r.pidPrefix(int(view.tid)),
		r.syscallNumberPrefix(view),
		trimTrailingParen(argLine))
}

func (r *TextRenderer) PrintExecPidChangedFromView(view syscallEventView, argLine string) {
	r.observeTaskComm(view)
	r.selectOutputPID(int(view.tid))
	tid := int(view.tid)
	tgid := int(view.pid)
	fmt.Fprintf(r.out, "%s%-5d %s%s <pid changed to %d ...>\n", r.timePrefix(view.enterTime), tid, r.syscallNumberPrefix(view), trimTrailingParen(argLine), tgid)
}

func (r *TextRenderer) PrintExecDetachedThreadSupersededFromView(view syscallEventView) {
	r.observeTaskComm(view)
	if r.renderOptions().quietThreadExecve {
		return
	}
	r.selectOutputPID(int(view.pid))
	fmt.Fprintf(r.out, "%s%-5d +++ superseded by execve in pid %d +++\n",
		r.timePrefix(view.enterTime), view.pid, view.tid)
}

func (r *TextRenderer) PrintExecSupersededUnfinishedFromView(view syscallEventView, argLine string) {
	r.observeTaskComm(view)
	r.selectOutputPID(int(view.tid))
	tid := int(view.tid)
	fmt.Fprintf(r.out, "%s%-5d %s%s <unfinished ...>\n", r.timePrefix(view.enterTime), tid, r.syscallNumberPrefix(view), trimTrailingParen(argLine))
}

func (r *TextRenderer) PrintSupersededSuspendedResumeFromView(view syscallEventView, syscallName string) {
	r.observeTaskComm(view)
	r.selectOutputPID(int(view.pid))
	timePrefix := r.timePrefix(view.enterTime)
	tgid := int(view.pid)
	numberPrefix := r.syscallNumberPrefix(view)
	switch syscallName {
	case "rt_sigsuspend":
		fmt.Fprintf(r.out, "%s%-5d %s<... rt_sigsuspend resumed>) = ?\n", timePrefix, tgid, numberPrefix)
	case "nanosleep":
		fmt.Fprintf(r.out, "%s%-5d %s<... nanosleep resumed> <unfinished ...>) = ?\n", timePrefix, tgid, numberPrefix)
	}
}

func (r *TextRenderer) PrintThreadExecveSupersededFromView(view syscallEventView, syscallName string) {
	r.observeTaskComm(view)
	r.selectOutputPID(int(view.pid))
	timePrefix := r.timePrefix(view.enterTime)
	tid := int(view.tid)
	tgid := int(view.pid)
	if !r.renderOptions().quietThreadExecve {
		fmt.Fprintf(r.out, "%s%-5d +++ superseded by execve in pid %d +++\n", timePrefix, tgid, tid)
	}
	fmt.Fprintf(r.out, "%s%-5d %s<... %s resumed>) = 0\n", timePrefix, tgid, r.syscallNumberPrefix(view), syscallName)
}

func (r *TextRenderer) PrintExitSyscallEvent(ev syscallEventContext, res handler.Result) {
	r.observeTaskComm(ev.eventView())
	r.selectOutputPID(int(ev.eventView().tid))
	line := r.exitSyscallLine(ev.eventView(), ev.effectiveSyscallMeta(), res)
	fmt.Fprint(r.out, line)
}

func (r *TextRenderer) ExitStatusLineFromView(view syscallEventView) string {
	r.observeTaskComm(view)
	return fmt.Sprintf("%s%s%s+++ exited with %d +++\n",
		r.timePrefix(view.enterTime), r.pidPrefix(int(view.tid)),
		r.instructionPointerPrefix(traceStackSnapshot{}), view.args[0])
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

func (r *TextRenderer) LifecycleExitStatusLine(tid int, rawStatus uint64) string {
	status := syscall.WaitStatus(rawStatus)
	if !status.Signaled() {
		return r.ExitStatusLine(tid, uint64(status.ExitStatus()))
	}
	signalName := unix.SignalName(status.Signal())
	if signalName == "" {
		signalName = fmt.Sprintf("SIG%d", status.Signal())
	}
	return r.statusLine(tid, "+++ killed by "+signalName+" +++")
}

func (r *TextRenderer) statusLine(tid int, message string) string {
	enterTime := uint64(0)
	if r.timeFormatter != nil {
		enterTime = r.timeFormatter.NowMonoNs()
	}
	return fmt.Sprintf("%s%s%s%s\n", r.timePrefix(enterTime), r.pidPrefix(tid),
		r.instructionPointerPrefix(traceStackSnapshot{}), message)
}

// IMPACT: PrintSyscallEvent renders a decoded syscall from the stable event context view.
func (r *TextRenderer) PrintSyscallEvent(ev syscallEventContext, res handler.Result) {
	r.observeTaskComm(ev.eventView())
	r.selectOutputPID(int(ev.eventView().tid))
	if r.writePlainSyscallFast(ev, res) {
		return
	}
	view := ev.eventView()
	scMeta := ev.effectiveSyscallMeta()
	ctx := ev.handlerContextForFormatting()
	tid := int(view.tid)
	stack := r.readStackSnapshot(view.stackID)
	numberPrefix := r.syscallNumberPrefix(view)
	args := r.formatArguments(view, scMeta, res.ArgParts)
	linePrefix := r.instructionPointerPrefix(stack) + numberPrefix
	line := fmt.Sprintf("%s%s(%s)", linePrefix, scMeta.Name, args)
	if ev.pendingEnter != nil && ev.pendingEnter.unfinishedPrinted {
		line = fmt.Sprintf("%s<... %s resumed>)", linePrefix, scMeta.Name)
	} else if r.consumeSuspended(tid) {
		if scMeta.Name == "nanosleep" {
			line = fmt.Sprintf("%s<... %s resumed> <unfinished ...>)", linePrefix, scMeta.Name)
		} else {
			line = fmt.Sprintf("%s<... %s resumed>)", linePrefix, scMeta.Name)
		}
	}

	timePrefix := r.timePrefix(view.enterTime)
	pidPrefix := r.pidPrefix(tid)
	retStr := formatSyscallRet(scMeta.Name, view.ret, res, ctx)
	retStr = r.decoratePIDReturn(scMeta.Name, view.ret, retStr)
	fmt.Fprintf(r.out, "%s%s%s%s= %s%s\n",
		timePrefix, pidPrefix, line, r.padding(timePrefix, pidPrefix, line), retStr, r.durationSuffix(view.duration))
	if res.HexDumpStr != "" {
		fmt.Fprint(r.out, res.HexDumpStr)
	}
	r.printStackTrace(stack)
}

func (r *TextRenderer) exitSyscallLine(view syscallEventView, scMeta meta.Syscall, res handler.Result) string {
	timePrefix := r.timePrefix(view.enterTime)
	pidPrefix := r.pidPrefix(int(view.tid))
	args := r.formatArguments(view, scMeta, res.ArgParts)
	stack := r.readStackSnapshot(view.stackID)
	argLine := fmt.Sprintf("%s%s%s(%s)", r.instructionPointerPrefix(stack), r.syscallNumberPrefix(view), scMeta.Name, args)
	return fmt.Sprintf("%s%s%s%s= ?\n", timePrefix, pidPrefix, argLine, r.padding(timePrefix, pidPrefix, argLine))
}

func formatSyscallArguments(argNames []string, parts []string, showNames bool) string {
	if !showNames || len(parts) == 0 {
		return strings.Join(parts, ", ")
	}
	namedParts := append([]string(nil), parts...)
	for index := 0; index < len(namedParts) && index < len(argNames); index++ {
		if argNames[index] != "" {
			namedParts[index] = argNames[index] + "=" + namedParts[index]
		}
	}
	return strings.Join(namedParts, ", ")
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
	return r.timeFormatter.Prefix(enterTimeMonoNs, r.policy)
}

func (r *TextRenderer) pidPrefix(tid int) string {
	options := r.renderOptions()
	if options.showPID {
		if options.followForks && !options.alwaysShowPID && r.targetPID > 0 {
			if tid == r.targetPID {
				return ""
			}
			return fmt.Sprintf("[pid %5d] ", tid)
		}
		if comm, ok := r.taskComms.Lookup(uint32(tid)); ok {
			return fmt.Sprintf("%d<%s> ", tid, escapeTaskComm(comm))
		}
		return fmt.Sprintf("%-5d ", tid)
	}
	return ""
}

func (r *TextRenderer) syscallNumberPrefix(view syscallEventView) string {
	if !r.renderOptions().printSyscallNumber {
		return ""
	}
	return fmt.Sprintf("[%4d] ", view.sysID)
}

func (r *TextRenderer) padding(timePrefix string, pidPrefix string, line string) string {
	padding := " "
	options := r.renderOptions()
	totalLen := len(timePrefix) + len(pidPrefix) + len(line)
	if totalLen < options.alignCol {
		padding = strings.Repeat(" ", options.alignCol-totalLen)
	}
	return padding
}

func (r *TextRenderer) durationSuffix(duration uint64) string {
	if !r.renderOptions().printSyscallTime {
		return ""
	}
	options := r.renderOptions()
	return " <" + formatSeconds(duration, options.syscallTimePrecision, 1) + ">"
}

func (r *TextRenderer) readStackSnapshot(stackID int32) traceStackSnapshot {
	options := r.renderOptions()
	if (!options.stackTrace && !options.instructionPointer) || r.stackTraces == nil || stackID < 0 {
		return traceStackSnapshot{}
	}
	var snapshot traceStackSnapshot
	if err := r.stackTraces.ReadStackTrace(uint32(stackID), &snapshot.ips); err != nil {
		return traceStackSnapshot{}
	}
	snapshot.available = true
	return snapshot
}

func (r *TextRenderer) instructionPointerPrefix(snapshot traceStackSnapshot) string {
	if !r.renderOptions().instructionPointer {
		return ""
	}
	if snapshot.available && snapshot.ips[0] != 0 {
		return fmt.Sprintf("[%0*x] ", instructionPointerHexWidth, snapshot.ips[0])
	}
	return "[" + strings.Repeat("?", instructionPointerHexWidth) + "] "
}

func (r *TextRenderer) printStackTrace(snapshot traceStackSnapshot) {
	if !r.renderOptions().stackTrace || !snapshot.available || r.resolver == nil {
		return
	}
	for _, ip := range snapshot.ips {
		if ip == 0 {
			break
		}
		fmt.Fprintf(r.out, " > %s\n", r.resolver.Resolve(ip))
	}
}

func (r *TextRenderer) renderOptions() traceRenderOptions {
	if r == nil || r.policy == nil {
		return traceRenderOptions{}
	}
	return r.policy.RenderOptions()
}

func (r *TextRenderer) selectOutputPID(pid int) {
	if r == nil {
		return
	}
	if output, ok := r.out.(interface{ SelectPID(int) error }); ok {
		_ = output.SelectPID(pid)
	}
}

func (r *TextRenderer) observeTaskComm(view syscallEventView) {
	if r == nil || r.taskComms == nil || view.comm == "" {
		return
	}
	r.taskComms.Observe(view.tid, view.comm)
}

func (r *TextRenderer) formatArguments(view syscallEventView, scMeta meta.Syscall, parts []string) string {
	formatted := append([]string(nil), parts...)
	for index := 0; index < len(formatted) && index < len(scMeta.ArgTypes); index++ {
		if scMeta.ArgTypes[index] == "pid_t" {
			formatted[index] = r.decoratePID(int32(view.args[index]), formatted[index])
		}
	}
	return formatSyscallArguments(scMeta.Args, formatted, r.renderOptions().printArgNames)
}

func (r *TextRenderer) decoratePID(pid int32, text string) string {
	if pid <= 0 || r == nil || r.taskComms == nil {
		return text
	}
	comm, ok := r.taskComms.Lookup(uint32(pid))
	if !ok {
		return text
	}
	return text + "<" + escapeTaskComm(comm) + ">"
}

func (r *TextRenderer) decoratePIDReturn(syscallName string, ret int64, text string) string {
	if ret <= 0 || !isPIDReturnSyscall(syscallName) {
		return text
	}
	return r.decoratePID(int32(ret), text)
}

func isPIDReturnSyscall(name string) bool {
	switch name {
	case "getpid", "getppid", "gettid", "getpgid", "getsid":
		return true
	default:
		return false
	}
}
