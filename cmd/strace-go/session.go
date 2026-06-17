package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"unsafe"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/procmem"
	"strace-go/pkg/stacktrace"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type syscallStat struct {
	calls    int
	errors   int
	duration uint64 // total duration in nanoseconds
}

type traceSession struct {
	cmd               *exec.Cmd
	events            *ringbuf.Reader
	targetPid         int
	opts              *cli.Options
	decoder           *event.Decoder
	memReader         *procmem.Reader
	fdMap             map[string]string
	outWriter         io.Writer
	outFile           *os.File
	outCmd            *exec.Cmd
	outPipe           io.WriteCloser
	stats             map[string]*syscallStat
	bootTimeOffsetNs  int64
	lastSyscallTimeNs uint64
	bpfObjs           *bpfObjects
	resolver          *stacktrace.Resolver
	pendingExitStatus map[int]string
	exitedTracees     map[int]bool
}

// IMPACT: setupBPF loads the BPF objects and attaches the raw syscall raw tracepoints.
func setupBPF() (*bpfObjects, []link.Link) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}
	bpfObjs := &bpfObjects{}
	if err := loadBpfObjects(bpfObjs, nil); err != nil {
		log.Fatalf("failed to load BPF objects: %v", err)
	}
	var links []link.Link
	tpEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", bpfObjs.TraceSysEnter, nil)
	if err != nil {
		log.Fatalf("failed to attach sys_enter tracepoint: %v", err)
	}
	links = append(links, tpEnter)
	tpExit, err := link.Tracepoint("raw_syscalls", "sys_exit", bpfObjs.TraceSysExit, nil)
	if err != nil {
		log.Fatalf("failed to attach sys_exit tracepoint: %v", err)
	}
	links = append(links, tpExit)
	tpFork, err := link.Tracepoint("sched", "sched_process_fork", bpfObjs.TraceSchedProcessFork, nil)
	if err == nil {
		links = append(links, tpFork)
	}
	return bpfObjs, links
}

func collectInheritedFiles() []*os.File {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil
	}

	maxFD := 2
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err == nil && fd > maxFD {
			maxFD = fd
		}
	}
	if maxFD <= 2 {
		return nil
	}

	files := make([]*os.File, maxFD-2)
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd <= 2 {
			continue
		}
		target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil || !isPassThroughFDTarget(target) {
			continue
		}
		dupFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			continue
		}
		files[fd-3] = os.NewFile(uintptr(dupFD), target)
	}
	return files
}

func isPassThroughFDTarget(target string) bool {
	if !strings.HasPrefix(target, "/") {
		return false
	}
	return target != "/proc" &&
		!strings.HasPrefix(target, "/proc/") &&
		target != "/sys" &&
		!strings.HasPrefix(target, "/sys/")
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			file.Close()
		}
	}
}

// IMPACT: startAndTraceCmd configures ptrace-based child process spawning and initial attachment.
func startAndTraceCmd(opts *cli.Options, bpfObjs *bpfObjects, inheritedFiles []*os.File) (*exec.Cmd, int, map[string]string) {
	cmdArgs := opts.CmdArgs
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	envMap := make(map[string]string)
	for _, e := range os.Environ() {
		if idx := strings.Index(e, "="); idx >= 0 {
			envMap[e[:idx]] = e[idx+1:]
		}
	}
	for _, action := range opts.EnvActions {
		if idx := strings.Index(action, "="); idx >= 0 {
			envMap[action[:idx]] = action[idx+1:]
		} else {
			delete(envMap, action)
		}
	}
	for k, v := range envMap {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	cmd.ExtraFiles = inheritedFiles

	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start command: %v", err)
	}

	targetPid := cmd.Process.Pid
	bpfObjs.FilterMap.Update(uint32(targetPid), uint32(1), 0)

	fdMap := make(map[string]string)
	var wstatus syscall.WaitStatus
	syscall.Wait4(targetPid, &wstatus, 0, nil)

	// Populate FD map from /proc
	if entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", targetPid)); err == nil {
		for _, entry := range entries {
			if path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", targetPid, entry.Name())); err == nil {
				fdMap[fmt.Sprintf("%d:%s", targetPid, entry.Name())] = path
			}
		}
	}
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", targetPid)); err == nil {
		fdMap[fmt.Sprintf("%d:cwd", targetPid)] = cwd
	}

	time.Sleep(10 * time.Millisecond)

	syscall.PtraceSetOptions(targetPid, syscall.PTRACE_O_TRACEEXIT|syscall.PTRACE_O_TRACECLONE|syscall.PTRACE_O_TRACEFORK|syscall.PTRACE_O_TRACEVFORK|syscall.PTRACE_O_TRACEEXEC)
	syscall.PtraceCont(targetPid, 0)
	return cmd, targetPid, fdMap
}

// IMPACT: attachToPids attaches tracing to running processes, updating the BPF filter map and reading initial FDs.
func attachToPids(pids []int, bpfObjs *bpfObjects) (*exec.Cmd, int, map[string]string) {
	fdMap := make(map[string]string)
	var firstPid int

	for i, pid := range pids {
		// Send signal 0 to check if PID exists and we have permissions
		if err := syscall.Kill(pid, 0); err != nil {
			log.Fatalf("failed to attach to pid %d: %v", pid, err)
		}

		if i == 0 {
			firstPid = pid
		}
		bpfObjs.FilterMap.Update(uint32(pid), uint32(1), 0)

		// Populate FD map from /proc
		if entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid)); err == nil {
			for _, entry := range entries {
				if path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name())); err == nil {
					fdMap[fmt.Sprintf("%d:%s", pid, entry.Name())] = path
				}
			}
			if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
				fdMap[fmt.Sprintf("%d:cwd", pid)] = cwd
			}
		}
	}
	return nil, firstPid, fdMap
}

// IMPACT: setupOutput prepares the io.Writer target for saving strace text traces.
func setupOutput(outFileOpt string, appendMode bool) (io.Writer, *os.File, *exec.Cmd, io.WriteCloser) {
	if outFileOpt == "" {
		return os.Stderr, nil, nil, nil
	}
	if strings.HasPrefix(outFileOpt, "|") || strings.HasPrefix(outFileOpt, "!") {
		cmdStr := outFileOpt[1:]
		cmd := exec.Command("sh", "-c", cmdStr)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			log.Fatalf("failed to create pipe for output: %v", err)
		}
		if err := cmd.Start(); err != nil {
			log.Fatalf("failed to start output command: %v", err)
		}
		return stdin, nil, cmd, stdin
	}

	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if appendMode {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	outFile, err := os.OpenFile(outFileOpt, flags, 0666)
	if err != nil {
		log.Fatalf("failed to create output file: %v", err)
	}
	return outFile, outFile, nil, nil
}

// IMPACT: reapTracees must run on the OS thread that started the ptraced command.
func (s *traceSession) reapTracees() bool {
	targetExited := false
	exeName := os.Getenv("STRACE_EXE")
	if exeName == "" {
		exeName = "strace"
	}

	for {
		var wstatus syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &wstatus, syscall.WNOHANG|syscall.WUNTRACED, nil)
		if err != nil || pid <= 0 {
			return targetExited
		}
		if wstatus.Stopped() {
			signal := ptraceContinueSignal(wstatus.StopSignal())
			if err := syscall.PtraceCont(pid, signal); err != nil && err != syscall.ESRCH {
				log.Printf("failed to continue pid %d: %v", pid, err)
			}
			continue
		}
		if !wstatus.Exited() && !wstatus.Signaled() {
			continue
		}
		s.markTraceeExited(pid)
		if pid == s.targetPid {
			targetExited = true
		} else if s.opts == nil || (!s.opts.QuietExit && !s.opts.QuietUnknownPid) {
			fmt.Fprintf(os.Stderr, "%s: Exit of unknown pid %d ignored\n", exeName, pid)
		}
	}
}

func ptraceContinueSignal(stopSignal syscall.Signal) int {
	if stopSignal == syscall.SIGTRAP || stopSignal == syscall.SIGSTOP {
		return 0
	}
	return int(stopSignal)
}

// IMPACT: run loops through the ring buffer to deliver tracing events.
func (s *traceSession) run() {
	commandExited := s.cmd == nil
	var waitTicker *time.Ticker
	var waitC <-chan time.Time
	if !commandExited {
		waitTicker = time.NewTicker(10 * time.Millisecond)
		defer waitTicker.Stop()
		waitC = waitTicker.C
	}

	attachExited := s.opts == nil || len(s.opts.AttachPids) == 0
	var attachDone <-chan struct{}
	if s.opts != nil && len(s.opts.AttachPids) > 0 {
		ch := make(chan struct{})
		attachDone = ch
		go func() {
			defer close(ch)
			for {
				anyAlive := false
				for _, pid := range s.opts.AttachPids {
					if err := syscall.Kill(pid, 0); err == nil {
						anyAlive = true
						break
					}
				}
				if !anyAlive {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}

	printExecve := len(s.opts.TraceSyscalls) == 0 && len(s.opts.TraceSyscallRegexps) == 0
	if !printExecve {
		matched := s.opts.TraceSyscalls["execve"]
		if !matched {
			for _, r := range s.opts.TraceSyscallRegexps {
				if r.MatchString("execve") {
					matched = true
					break
				}
			}
		}
		if s.opts.TraceSetIsNegated {
			matched = !matched
		}
		printExecve = matched
	}
	if len(s.opts.AttachPids) == 0 && printExecve {
		s.printFakeFirstExecve()
	}

	eventChan := make(chan *bpfEvent, 2048)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			rec, err := s.events.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					break
				}
				continue
			}
			var ev bpfEvent
			if len(rec.RawSample) < 112 {
				continue
			}
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&ev)), unsafe.Sizeof(ev)), rec.RawSample)
			eventChan <- &ev
		}
	}()

	isDone := false
	for {
		if !isDone && commandExited && attachExited {
			isDone = true
		}
		if isDone {
			select {
			case ev := <-eventChan:
				s.handleEvent(ev)
			case <-time.After(250 * time.Millisecond):
				s.events.Close()
				wg.Wait()
				close(eventChan)
				for ev := range eventChan {
					s.handleEvent(ev)
				}
				if s.opts != nil && (s.opts.SummaryOnly || s.opts.SummaryAndPrint) {
					s.printSummary()
				}
				if s.outPipe != nil {
					s.outPipe.Close()
					s.outCmd.Wait()
				}
				return
			}
		} else {
			select {
			case <-waitC:
				if s.reapTracees() {
					commandExited = true
					waitC = nil
				}
			case <-attachDone:
				attachExited = true
				attachDone = nil
			case ev := <-eventChan:
				s.handleEvent(ev)
			}
		}
	}
}

// IMPACT: printSummary outputs the syscall execution statistics matching strace -c formatting, now with timing.
func (s *traceSession) printSummary() {
	fmt.Fprintf(s.outWriter, "%6s %11s %11s %9s %9s %s\n", "% time", "seconds", "usecs/call", "calls", "errors", "syscall")
	fmt.Fprintf(s.outWriter, "------ ----------- ----------- --------- --------- ----------------\n")
	totalCalls := 0
	totalErrors := 0
	var totalDurationNs uint64 = 0

	type statEntry struct {
		name string
		stat *syscallStat
	}
	var entries []statEntry
	for name, stat := range s.stats {
		totalCalls += stat.calls
		totalErrors += stat.errors
		totalDurationNs += stat.duration
		entries = append(entries, statEntry{name, stat})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].stat.duration != entries[j].stat.duration {
			return entries[i].stat.duration > entries[j].stat.duration
		}
		if entries[i].stat.calls != entries[j].stat.calls {
			return entries[i].stat.calls > entries[j].stat.calls
		}
		return entries[i].name < entries[j].name
	})

	for _, entry := range entries {
		stat := entry.stat
		errStr := ""
		if stat.errors > 0 {
			errStr = strconv.Itoa(stat.errors)
		}
		pct := 0.0
		if totalDurationNs > 0 {
			pct = float64(stat.duration) / float64(totalDurationNs) * 100.0
		}
		secs := float64(stat.duration) / 1e9
		usecs := int64(0)
		if stat.calls > 0 {
			usecs = int64(stat.duration / uint64(stat.calls) / 1000)
		}
		fmt.Fprintf(s.outWriter, "%6.2f %11.6f %11d %9d %9s %s\n", pct, secs, usecs, stat.calls, errStr, entry.name)
	}
	fmt.Fprintf(s.outWriter, "------ ----------- ----------- --------- --------- ----------------\n")
	errStr := ""
	if totalErrors > 0 {
		errStr = strconv.Itoa(totalErrors)
	}
	totalSecs := float64(totalDurationNs) / 1e9
	fmt.Fprintf(s.outWriter, "%6.2f %11.6f %11s %9d %9s %s\n", 100.0, totalSecs, "", totalCalls, errStr, "total")
}

// IMPACT: printFakeFirstExecve formats and outputs the placeholder line for the first execve.
func (s *traceSession) printFakeFirstExecve() {
	if s.opts != nil && (s.opts.SummaryOnly || s.opts.SummaryAndPrint) {
		if s.stats == nil {
			s.stats = make(map[string]*syscallStat)
		}
		stat := s.stats["execve"]
		if stat == nil {
			stat = &syscallStat{}
			s.stats["execve"] = stat
		}
		stat.calls++
		if s.opts.SummaryOnly {
			return
		}
	}

	pidPrefix := ""
	if s.opts != nil && s.opts.FollowForks {
		pidPrefix = fmt.Sprintf("%-5d ", s.targetPid)
	}

	envc := len(os.Environ())
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", s.targetPid)); err == nil {
		parts := bytes.Split(data, []byte{0})
		count := 0
		for _, p := range parts {
			if len(p) > 0 {
				count++
			}
		}
		if count > 0 {
			envc = count
		}
	}

	var quotedArgs []string
	if len(s.opts.CmdArgs) > 0 {
		for _, arg := range s.opts.CmdArgs {
			quotedArgs = append(quotedArgs, "\""+arg+"\"")
		}
	} else {
		quotedArgs = append(quotedArgs, "\"unknown\"")
	}
	argvStr := "[" + strings.Join(quotedArgs, ", ") + "]"

	envpStr := fmt.Sprintf("0x7ffdbcb5c068 /* %d vars */", envc)
	if s.opts.Verbose {
		var envList []string
		if envBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", s.targetPid)); err == nil {
			parts := strings.Split(string(envBytes), "\x00")
			for _, p := range parts {
				if p != "" {
					envList = append(envList, fmt.Sprintf("%q", p))
				}
			}
		}
		envpStr = "[" + strings.Join(envList, ", ") + "]"
	}

	cmdName := "unknown"
	if len(s.opts.CmdArgs) > 0 {
		cmdName = s.opts.CmdArgs[0]
	}
	var tsMono unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &tsMono)
	monoNs := uint64(tsMono.Sec)*1e9 + uint64(tsMono.Nsec)
	timePrefix := formatTimePrefix(monoNs, s)

	line := fmt.Sprintf("execve(\"%s\", %s, %s)", cmdName, argvStr, envpStr)
	padding := " "
	totalLen := len(timePrefix) + len(pidPrefix) + len(line)
	if totalLen < s.opts.AlignCol {
		padding = strings.Repeat(" ", s.opts.AlignCol-totalLen)
	}
	durationSuffix := ""
	if s.opts != nil && s.opts.PrintSyscallTime {
		durationSuffix = " <0.000000>"
	}
	fmt.Fprintf(s.outWriter, "%s%s%s%s= 0%s\n", timePrefix, pidPrefix, line, padding, durationSuffix)
}
