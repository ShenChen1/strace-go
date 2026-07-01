package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
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
	fdMap             map[string]string
	fdOffsets         map[string]int64
	fdFiles           map[string]*os.File
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
	pendingSyscalls   map[uint32]*pendingSyscallState
	pendingExecArgs   map[int]string
	suspendedSyscalls map[int]string
	tasks             map[uint32]*TaskState
}

// IMPACT: setupBPF loads the BPF objects and attaches the raw syscall raw tracepoints.
func setupBPF() (*bpfObjects, []link.Link) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("failed to load BPF spec: %v", err)
	}

	sysNameToID := make(map[string]uint32)
	for id, sc := range meta.SyscallTable {
		sysNameToID[sc.Name] = id
	}

	getSysID := func(name string, fallback uint32) uint32 {
		if id, ok := sysNameToID[name]; ok {
			return id
		}
		return fallback
	}

	setVar := func(name string, val uint32) {
		if v, ok := spec.Variables[name]; ok {
			if err := v.Set(val); err != nil {
				log.Fatalf("failed to set %s: %v", name, err)
			}
		} else {
			log.Fatalf("variable %s not found in BPF spec", name)
		}
	}

	setVar("SYS_RT_SIGRETURN", getSysID("rt_sigreturn", 15))
	setVar("SYS_RT_SIGRETURN_COMPAT", getSysID("rt_sigreturn_compat", 173))
	setVar("SYS_NANOSLEEP", getSysID("nanosleep", 35))
	setVar("SYS_EXECVE", getSysID("execve", 59))
	setVar("SYS_EXIT", getSysID("exit", 60))
	setVar("SYS_CAPSET", getSysID("capset", 126))
	setVar("SYS_RT_SIGSUSPEND", getSysID("rt_sigsuspend", 130))
	setVar("SYS_EXIT_GROUP", getSysID("exit_group", 231))
	setVar("SYS_EXECVEAT", getSysID("execveat", 322))

	bpfObjs := &bpfObjects{}
	if err := spec.LoadAndAssign(bpfObjs, nil); err != nil {
		log.Fatalf("failed to load and assign BPF objects: %v", err)
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
	tpExec, err := link.Tracepoint("sched", "sched_process_exec", bpfObjs.TraceSchedProcessExec, nil)
	if err == nil {
		links = append(links, tpExec)
	}
	tpSchedExit, err := link.Tracepoint("sched", "sched_process_exit", bpfObjs.TraceSchedProcessExit, nil)
	if err == nil {
		links = append(links, tpSchedExit)
	}
	tpFree, err := link.Tracepoint("sched", "sched_process_free", bpfObjs.TraceSchedProcessFree, nil)
	if err == nil {
		links = append(links, tpFree)
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

func newTraceCommand(opts *cli.Options, inheritedFiles []*os.File) *exec.Cmd {
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
	return cmd
}

func populateFDMap(pid int, targetPid int) map[string]string {
	fdMap := make(map[string]string)
	if entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid)); err == nil {
		for _, entry := range entries {
			if path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name())); err == nil {
				fdMap[fmt.Sprintf("%d:%s", targetPid, entry.Name())] = path
			}
		}
	}
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		fdMap[fmt.Sprintf("%d:cwd", targetPid)] = cwd
	}
	return fdMap
}

// IMPACT: startTraceCmd starts a tracee without ptrace; syscall observation is purely eBPF based.
func startTraceCmd(opts *cli.Options, bpfObjs *bpfObjects, inheritedFiles []*os.File) (*exec.Cmd, int, map[string]string) {
	cmd := newTraceCommand(opts, inheritedFiles)
	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start command: %v", err)
	}

	targetPid := cmd.Process.Pid
	bpfObjs.FilterMap.Update(uint32(targetPid), uint32(1), 0)
	fdMap := populateFDMap(targetPid, targetPid)
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
