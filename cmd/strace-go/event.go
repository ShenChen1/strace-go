package main

import (
	"fmt"
	"strings"
	"syscall"
	"time"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

// IMPACT: resolvePtrProbeRet returns the specific probe status for eventRaw.Ptr based on its argument index.
func resolvePtrProbeRet(eventRaw *bpfEvent) int32 {
	if eventRaw.Ptr == 0 {
		return 0
	}
	for i, val := range eventRaw.Args {
		if val == eventRaw.Ptr {
			return getArgProbeStatus(eventRaw.ProbeRetEnter, i)
		}
	}
	return eventRaw.ProbeRetEnter
}

// IMPACT: getArgProbeStatus decodes the bitmask for entry argument success flag.
func getArgProbeStatus(probeRetEnter int32, argIndex int) int32 {
	if probeRetEnter >= 0 {
		return 0
	}
	if probeRetEnter == -1 {
		return -1
	}
	mask := -probeRetEnter - 1
	if (mask & (1 << argIndex)) != 0 {
		return -2
	}
	return 0
}

// IMPACT: handleEvent parses, decodes, and routes tracing events to print handlers or fd updates.
func (s *traceSession) handleEvent(eventRaw *bpfEvent) {
	isAttached := false
	if s.opts != nil && len(s.opts.AttachPids) > 0 {
		for _, pid := range s.opts.AttachPids {
			if int(eventRaw.Pid) == pid {
				isAttached = true
				break
			}
		}
	} else if int(eventRaw.Pid) == s.targetPid {
		isAttached = true
	}

	if !isAttached {
		if s.opts == nil || !s.opts.FollowForks {
			return
		}
	}
	tPid := int(eventRaw.Tid)
	statePID := s.eventStatePID(eventRaw)

	if isLifecycleEvent(eventRaw) {
		s.handleLifecycleEvent(eventRaw)
		return
	}
	s.noteSyscallTask(eventRaw)

	scMeta, ok := meta.SyscallTable[eventRaw.SysId]
	if !ok {
		scMeta = meta.Syscall{Name: fmt.Sprintf("sys_%d", eventRaw.SysId)}
	}

	if isGenericEnterEvent(eventRaw) {
		s.rememberEnterEvent(eventRaw)
		if s.opts != nil && s.opts.EventFormat == cli.EventFormatJSON &&
			(s.opts.DebugEvents || checkShouldPrint(eventRaw, scMeta, "", false, statePID, s.opts, s.fdMap)) {
			s.writeJSONRawEvent(eventRaw, scMeta)
		}
		return
	}
	pendingEnter := s.consumeEnterEvent(eventRaw)

	ret := eventRaw.Ret
	strArgBuf := eventRaw.StrArg[:]
	isPath := false
	for _, argName := range scMeta.Args {
		if argName == "filename" || argName == "pathname" || argName == "path" || argName == "oldname" || argName == "newname" || argName == "fs_name" {
			isPath = true
			break
		}
	}
	capSize := 512
	if isPath {
		capSize = 4097
	}
	ptrProbeRet := resolvePtrProbeRet(eventRaw)
	// Decode only the string snapshot copied by BPF for path filtering and display.
	rawStrArg := s.decoder.DecodeString(int(eventRaw.Tid), eventRaw.Ptr, strArgBuf[:capSize], ptrProbeRet, scMeta.Name, 0)

	defer func() {
		if scMeta.Name == "close" && ret == 0 {
			key := fmt.Sprintf("%d:%d", statePID, int32(eventRaw.Args[0]))
			delete(s.fdMap, key)
			delete(s.fdOffsets, key)
			if f := s.fdFiles[key]; f != nil {
				f.Close()
				delete(s.fdFiles, key)
			}
		}
	}()
	defer s.updateFDOffsets(eventRaw, scMeta)

	if s.opts != nil && s.opts.EventFormat == cli.EventFormatJSON && s.opts.DebugEvents {
		s.writeJSONRawEvent(eventRaw, scMeta)
		return
	}

	if scMeta.Name == "arch_prctl" && eventRaw.Args[0] == 0x1002 {
		return
	}

	shouldPrint := checkShouldPrint(eventRaw, scMeta, rawStrArg, isPath, statePID, s.opts, s.fdMap)

	if s.opts.SummaryOnly || s.opts.SummaryAndPrint {
		if shouldPrint {
			if s.stats == nil {
				s.stats = make(map[string]*syscallStat)
			}
			stat := s.stats[scMeta.Name]
			if stat == nil {
				stat = &syscallStat{}
				s.stats[scMeta.Name] = stat
			}
			stat.calls++
			stat.duration += eventRaw.Duration
			if ret < 0 && ret >= -4095 { // -4095 is MAX_ERRNO
				stat.errors++
			}
		}
		if s.opts.SummaryOnly {
			return
		}
	}

	bufferFileOffset, bufferFileOffsetOK := s.bufferFileOffset(eventRaw, scMeta)
	ctx := &handler.Context{
		Pid: int(eventRaw.Pid), Tid: tPid, TargetPid: statePID, SysId: eventRaw.SysId,
		SysName: scMeta.Name, Args: eventRaw.Args, Ret: ret,
		ProbeRetEnter: eventRaw.ProbeRetEnter, ProbeRetExit: eventRaw.ProbeRetExit,
		Ptr: eventRaw.Ptr, DataLen: eventRaw.DataLen, StrArgBuf: strArgBuf, RawStrArg: rawStrArg,
		BufferFileOffset: bufferFileOffset, BufferFileOffsetOK: bufferFileOffsetOK,
		ScMeta: scMeta, Decoder: s.decoder, Opts: s.opts, FdMap: s.fdMap,
		FdFiles: s.fdFiles,
	}

	isFdSys := scMeta.Name == "open" || scMeta.Name == "openat" || scMeta.Name == "openat2" || scMeta.Name == "creat" || scMeta.Name == "dup" || scMeta.Name == "dup2" || scMeta.Name == "dup3" || scMeta.Name == "close" || scMeta.Name == "faccessat" || scMeta.Name == "faccessat2" || scMeta.Name == "chmodat" || scMeta.Name == "mkdirat" || scMeta.Name == "newfstatat" || scMeta.Name == "fstat" || scMeta.Name == "chdir" || scMeta.Name == "fchdir"

	if eventRaw.ProbeRetEnter == -1 && (scMeta.Name == "exit" || scMeta.Name == "exit_group") {
		if s.opts == nil || !s.opts.SummaryOnly {
			timePrefix := formatTimePrefix(eventRaw.EnterTime, s)
			pidPrefix := ""
			if s.opts != nil && s.opts.FollowForks {
				pidPrefix = fmt.Sprintf("%-5d ", tPid)
			}
			if shouldPrint {
				h := handler.Get(scMeta.Name)
				res := h.Handle(ctx)
				if s.opts != nil && s.opts.EventFormat == cli.EventFormatJSON {
					s.writeJSONEvent(eventRaw, scMeta, res, ctx, pendingEnter)
					return
				}
				argLine := fmt.Sprintf("%s(%s)", scMeta.Name, strings.Join(res.ArgParts, ", "))
				padding := " "
				totalLen := len(timePrefix) + len(pidPrefix) + len(argLine)
				if totalLen < s.opts.AlignCol {
					padding = strings.Repeat(" ", s.opts.AlignCol-totalLen)
				}
				fmt.Fprintf(s.outWriter, "%s%s%s%s= ?\n", timePrefix, pidPrefix, argLine, padding)
			}
			if s.opts == nil || !s.opts.QuietExit {
				exitLine := fmt.Sprintf("%s%s+++ exited with %d +++\n", timePrefix, pidPrefix, eventRaw.Args[0])
				if s.shouldQueueExitStatus(int(eventRaw.Pid)) {
					s.queueExitStatus(tPid, exitLine)
				} else {
					fmt.Fprint(s.outWriter, exitLine)
				}
			}
		}
		return
	}

	if !shouldPrint {
		if isFdSys {
			handler.Get(scMeta.Name).Handle(ctx)
		}
		updateFDMap(eventRaw, scMeta, rawStrArg, s.decoder, statePID, s.fdMap)
		return
	}

	h := handler.Get(scMeta.Name)
	res := h.Handle(ctx)
	updateFDMap(eventRaw, scMeta, rawStrArg, s.decoder, statePID, s.fdMap)

	if s.opts != nil && s.opts.EventFormat == cli.EventFormatJSON {
		status := successfulFailedOptions{
			successfulOnly: s.opts.SuccessfulOnly,
			failedOnly:     s.opts.FailedOnly,
			traceStatus:    s.opts.TraceStatus,
		}
		if shouldEmitStatus(eventRaw, scMeta, status) {
			s.writeJSONEvent(eventRaw, scMeta, res, ctx, pendingEnter)
		}
		return
	}

	s.handleEventOutput(ctx, eventRaw, res)
}

func (s *traceSession) handleLifecycleEvent(eventRaw *bpfEvent) {
	task := s.applyLifecycleEvent(eventRaw)
	if eventRaw.EventFlags == lifecycleFork {
		s.inheritProcessState(int(eventRaw.Args[0]), int(eventRaw.Args[1]))
	}
	tid := int(eventRaw.Tid)
	switch eventRaw.EventFlags {
	case lifecycleExit, lifecycleFree:
		delete(s.pendingExecArgs, tid)
		delete(s.suspendedSyscalls, tid)
		delete(s.pendingSyscalls, uint32(eventRaw.Tid))
		s.cleanupProcessState(tid)
	}
	if s.opts != nil && s.opts.EventFormat == cli.EventFormatJSON {
		s.writeJSONLifecycleEvent(eventRaw, task)
	}
}

// IMPACT: handleEventOutput handles specific unfinished states and delegates trace printing.
func (s *traceSession) handleEventOutput(ctx *handler.Context, eventRaw *bpfEvent, res handler.Result) {
	tPid := int(eventRaw.Tid)
	scMeta := ctx.ScMeta
	ret := eventRaw.Ret

	if s.opts != nil {
		status := successfulFailedOptions{
			successfulOnly: s.opts.SuccessfulOnly,
			failedOnly:     s.opts.FailedOnly,
			traceStatus:    s.opts.TraceStatus,
		}
		if !shouldEmitStatus(eventRaw, scMeta, status) {
			return
		}
	}

	if eventRaw.ProbeRetEnter == 3 {
		pidPrefix := ""
		if s.opts != nil && s.opts.FollowForks {
			pidPrefix = fmt.Sprintf("%-5d ", tPid)
		}
		args := strings.Join(res.ArgParts, ", ")
		if scMeta.Name == "nanosleep" && len(res.ArgParts) > 0 {
			args = res.ArgParts[0]
		}
		line := fmt.Sprintf("%s(%s <unfinished ...>", scMeta.Name, args)
		fmt.Fprintf(s.outWriter, "%s%s\n", pidPrefix, line)

		s.rememberSuspendedSyscall(tPid, scMeta.Name)
		return
	}

	if eventRaw.ProbeRetEnter == 2 {
		return
	}

	if (scMeta.Name == "execve" || scMeta.Name == "execveat") && ret == -514 {
		s.rememberPendingExecArgs(tPid, fmt.Sprintf("%s(%s)", scMeta.Name, strings.Join(res.ArgParts, ", ")))
		if tPid == int(eventRaw.Pid) {
			return
		}
	}

	if (scMeta.Name == "execve" || scMeta.Name == "execveat") && ret == 0 && tPid == int(eventRaw.Pid) {
		argLine, ok := s.takePendingExecArgs(tPid)
		if ok {
			timePrefix := formatTimePrefix(eventRaw.EnterTime, s)
			pidPrefix := ""
			if s.opts != nil && s.opts.FollowForks {
				pidPrefix = fmt.Sprintf("%-5d ", tPid)
			}
			padding := " "
			totalLen := len(timePrefix) + len(pidPrefix) + len(argLine)
			if totalLen < s.opts.AlignCol {
				padding = strings.Repeat(" ", s.opts.AlignCol-totalLen)
			}
			durationSuffix := ""
			if s.opts != nil && s.opts.PrintSyscallTime {
				sec := eventRaw.Duration / 1e9
				usec := (eventRaw.Duration % 1e9) / 1000
				durationSuffix = fmt.Sprintf(" <%d.%06d>", sec, usec)
			}
			fmt.Fprintf(s.outWriter, "%s%s%s%s= 0%s\n", timePrefix, pidPrefix, argLine, padding, durationSuffix)
		}
		return
	}

	if handleSuperseded(eventRaw, scMeta, res, s) {
		return
	}

	printSyscallOutput(eventRaw, scMeta, res, ctx, s)
}

// IMPACT: formatTimePrefix computes the time prefix string based on parsed time options.
func formatTimePrefix(enterTimeMonoNs uint64, s *traceSession) string {
	if s.opts.PrintTimeMode == 0 && !s.opts.PrintRelativeTime {
		return ""
	}

	if s.opts.PrintRelativeTime {
		var diff uint64
		if s.lastSyscallTimeNs == 0 {
			diff = 0
		} else {
			diff = enterTimeMonoNs - s.lastSyscallTimeNs
		}
		s.lastSyscallTimeNs = enterTimeMonoNs

		sec := diff / 1e9
		usec := (diff % 1e9) / 1000
		return fmt.Sprintf("%6d.%06d ", sec, usec)
	}

	realTimeNs := int64(enterTimeMonoNs) + s.bootTimeOffsetNs
	t := time.Unix(0, realTimeNs)

	if s.opts.PrintTimeMode == 3 {
		sec := realTimeNs / 1e9
		usec := (realTimeNs % 1e9) / 1000
		return fmt.Sprintf("%d.%06d ", sec, usec)
	}
	if s.opts.PrintTimeMode == 2 {
		return t.Format("15:04:05.000000") + " "
	}
	if s.opts.PrintTimeMode == 1 {
		return t.Format("15:04:05") + " "
	}
	return ""
}

// IMPACT: handleSuperseded formats and prints superseded thread details when a non-leader thread executes execve.
func handleSuperseded(eventRaw *bpfEvent, scMeta meta.Syscall, res handler.Result, s *traceSession) bool {
	ret := eventRaw.Ret
	tPid := int(eventRaw.Tid)
	tgid := int(eventRaw.Pid)
	opts := s.opts
	outWriter := s.outWriter
	timePrefix := formatTimePrefix(eventRaw.EnterTime, s)
	isExecSuspended := (scMeta.Name == "execve" || scMeta.Name == "execveat") && ret == -514
	if isExecSuspended && tPid != tgid && opts != nil && opts.FollowForks {
		exited := eventRaw.ProbeRetEnter == 1

		argLine, ok := s.pendingExecArgsFor(tPid)
		if !ok {
			argLine = fmt.Sprintf("%s(%s)", scMeta.Name, strings.Join(res.ArgParts, ", "))
		}

		if len(argLine) > 0 && argLine[len(argLine)-1] == ')' {
			argLine = argLine[:len(argLine)-1]
		}

		if exited {
			fmt.Fprintf(outWriter, "%s%-5d %s <pid changed to %d ...>\n", timePrefix, tPid, argLine, tgid)
		} else {
			fmt.Fprintf(outWriter, "%s%-5d %s <unfinished ...>\n", timePrefix, tPid, argLine)
		}
		return true
	}
	isExecSuccess := (scMeta.Name == "execve" || scMeta.Name == "execveat") && ret == 0
	if isExecSuccess && tPid != tgid && opts != nil && opts.FollowForks {
		exited := eventRaw.ProbeRetEnter == 1
		s.deletePendingExecArgs(tPid)
		s.discardExitStatus(tgid)

		if exited {
			return true
		}

		if eventRaw.ProbeRetExit > 0 {
			suspendedSysId := uint32(eventRaw.ProbeRetExit)
			if suspMeta, ok := meta.SyscallTable[suspendedSysId]; ok {
				s.deleteSuspendedSyscall(tgid)

				if suspMeta.Name == "rt_sigsuspend" {
					fmt.Fprintf(outWriter, "%s%-5d <... rt_sigsuspend resumed>) = ?\n", timePrefix, tgid)
				} else if suspMeta.Name == "nanosleep" {
					fmt.Fprintf(outWriter, "%s%-5d <... nanosleep resumed> <unfinished ...>) = ?\n", timePrefix, tgid)
				}
			}
		}
		if !opts.QuietThreadExecve {
			fmt.Fprintf(outWriter, "%s%-5d +++ superseded by execve in pid %d +++\n", timePrefix, tgid, tPid)
		}
		fmt.Fprintf(outWriter, "%s%-5d <... %s resumed>) = 0\n", timePrefix, tgid, scMeta.Name)
		return true
	}
	return false
}

func (s *traceSession) shouldQueueExitStatus(tgid int) bool {
	if s.cmd == nil {
		return false
	}
	if s.opts != nil {
		for _, pid := range s.opts.AttachPids {
			if pid == tgid {
				return false
			}
		}
	}
	return true
}

func (s *traceSession) queueExitStatus(pid int, line string) {
	if s.exitedTracees != nil && s.exitedTracees[pid] {
		delete(s.exitedTracees, pid)
		fmt.Fprint(s.outWriter, line)
		return
	}
	if s.pendingExitStatus == nil {
		s.pendingExitStatus = make(map[int]string)
	}
	s.pendingExitStatus[pid] = line
}

func (s *traceSession) markTraceeExited(pid int) {
	if line, ok := s.pendingExitStatus[pid]; ok {
		delete(s.pendingExitStatus, pid)
		fmt.Fprint(s.outWriter, line)
		return
	}
	if s.exitedTracees == nil {
		s.exitedTracees = make(map[int]bool)
	}
	s.exitedTracees[pid] = true
}

func (s *traceSession) discardExitStatus(pid int) {
	delete(s.pendingExitStatus, pid)
	delete(s.exitedTracees, pid)
}

// IMPACT: printSyscallOutput outputs formatted syscall trace lines and logs signal delivery if applicable.
func printSyscallOutput(eventRaw *bpfEvent, scMeta meta.Syscall, res handler.Result, ctx *handler.Context, s *traceSession) {
	tPid := int(eventRaw.Tid)
	ret := eventRaw.Ret
	opts := s.opts
	outWriter := s.outWriter
	timePrefix := formatTimePrefix(eventRaw.EnterTime, s)

	pidPrefix := ""
	if opts != nil && opts.FollowForks {
		pidPrefix = fmt.Sprintf("%-5d ", tPid)
	}

	line := fmt.Sprintf("%s(%s)", scMeta.Name, strings.Join(res.ArgParts, ", "))
	wasSuspended := s.consumeSuspendedSyscall(tPid)

	if wasSuspended {
		if scMeta.Name == "nanosleep" {
			line = fmt.Sprintf("<... %s resumed> <unfinished ...>)", scMeta.Name)
		} else {
			line = fmt.Sprintf("<... %s resumed>)", scMeta.Name)
		}
	}
	retStr := formatSyscallRet(scMeta.Name, ret, res, ctx)
	padding := " "
	totalLen := len(timePrefix) + len(pidPrefix) + len(line)
	if totalLen < opts.AlignCol {
		padding = strings.Repeat(" ", opts.AlignCol-totalLen)
	}
	durationSuffix := ""
	if opts != nil && opts.PrintSyscallTime {
		sec := eventRaw.Duration / 1e9
		usec := (eventRaw.Duration % 1e9) / 1000
		durationSuffix = fmt.Sprintf(" <%d.%06d>", sec, usec)
	}

	fmt.Fprintf(outWriter, "%s%s%s%s= %s%s\n", timePrefix, pidPrefix, line, padding, retStr, durationSuffix)
	if res.HexDumpStr != "" {
		fmt.Fprintf(outWriter, "%s", res.HexDumpStr)
	}
	if scMeta.Name == "nanosleep" && ret == -516 {
		fmt.Fprintf(outWriter, "%s%s--- SIGALRM {si_signo=SIGALRM, si_code=SI_KERNEL} ---\n", timePrefix, pidPrefix)
	}

	if opts != nil && opts.StackTrace && s.bpfObjs != nil && s.resolver != nil {
		if eventRaw.StackId > 0 {
			var ips [127]uint64
			err := s.bpfObjs.StackTraces.Lookup(uint32(eventRaw.StackId), &ips)
			if err == nil {
				for _, ip := range ips {
					if ip == 0 {
						break
					}
					resolved := s.resolver.Resolve(ip)
					fmt.Fprintf(outWriter, " > %s\n", resolved)
				}
			}
		}
	}

	if (scMeta.Name == "execve" || scMeta.Name == "execveat") && ret < 0 {
		s.deletePendingExecArgs(tPid)
	}
}

// IMPACT: formatSyscallRet formats raw returns including negative error values or hex numbers for custom functions.
func formatSyscallRet(scName string, ret int64, res handler.Result, ctx *handler.Context) string {
	if scName == "exit" || scName == "exit_group" {
		return "?"
	}
	retStr := fmt.Sprintf("%d", ret)
	if ret >= 0 && ctx != nil && ctx.Opts != nil && ctx.Opts.ShowPaths && isFdReturnSyscall(scName) {
		retStr = handler.FormatFdWithPath(ctx, int32(ret))
	}
	if ret > 0 && (scName == "fcntl" || scName == "fcntl64") && ctx != nil {
		cmdVal := uint32(ctx.Args[1])
		switch cmdVal {
		case 1, 3, 1025: // F_GETFD (1), F_GETFL (3), F_GETLEASE (1025)
			retStr = fmt.Sprintf("%#x", ret)
		}
	}
	if ret >= 0 && scName == "umask" {
		m := uint32(ret)
		s := fmt.Sprintf("%o", m)
		if len(s) < 3 {
			s = strings.Repeat("0", 3-len(s)) + s
		}
		if s[0] != '0' {
			s = "0" + s
		}
		retStr = s
	}
	if ret >= 0 && (scName == "brk" || scName == "mmap" || scName == "mremap") {
		retStr = fmt.Sprintf("%#x", ret)
	}
	if ret >= 0 && (scName == "adjtimex" || scName == "clock_adjtime") {
		desc := "TIME_OK"
		switch ret {
		case 1:
			desc = "TIME_INS"
		case 2:
			desc = "TIME_DEL"
		case 3:
			desc = "TIME_OOP"
		case 4:
			desc = "TIME_WAIT"
		case 5:
			desc = "TIME_ERROR"
		}
		retStr = fmt.Sprintf("%d (%s)", ret, desc)
	}
	if ret < 0 && ret >= -4095 {
		errNum := int(-ret)
		if errNum == 516 {
			retStr = "? ERESTART_RESTARTBLOCK (Interrupted by signal)"
		} else if errNum == 514 {
			retStr = "? ERESTARTNOHAND (To be restarted if no handler)"
		} else if errNum == 513 {
			retStr = "? ERESTARTNOINTR (To be restarted)"
		} else if errNum == 512 {
			retStr = "? ERESTARTSYS (To be restarted if SA_RESTART is set)"
		} else if errName, ok := meta.ErrnoTable[errNum]; ok {
			errDesc := syscall.Errno(errNum).Error()
			if len(errDesc) > 0 {
				errDesc = strings.ToUpper(errDesc[:1]) + errDesc[1:]
			}
			retStr = fmt.Sprintf("-1 %s (%s)", errName, errDesc)
		} else {
			errDesc := syscall.Errno(errNum).Error()
			if len(errDesc) > 0 {
				errDesc = strings.ToUpper(errDesc[:1]) + errDesc[1:]
			}
			retStr = fmt.Sprintf("-1 E%d (%s)", errNum, errDesc)
		}
	}

	if res.ReturnDesc != "" {
		retStr += " (" + res.ReturnDesc + ")"
	}
	return retStr
}
