package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
	"strace-go/pkg/stacktrace"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type traceSession struct {
	cmd           *exec.Cmd
	events        *ringbuf.Reader
	targetPid     int
	opts          *cli.Options
	decoder       *event.Decoder
	recordDecoder traceRecordDecoder
	fdState       *FDStateStore
	outWriter     io.Writer
	outFile       *os.File
	outCmd        *exec.Cmd
	outPipe       io.WriteCloser
	summary       *SummaryStats
	timeFormatter *TimeFormatter
	bpfObjs       *bpfObjects
	resolver      *stacktrace.Resolver
	exitStatus    *ExitStatusQueue
	state         *TraceState

	textRendererCache       *TextRenderer
	syscallJSONCache        *SyscallJSONOutput
	syscallTextCache        *SyscallTextOutput
	exitSyscallCache        *ExitSyscallOutput
	syscallRunnerCache      *SyscallHandlerRunner
	syscallPipelineCache    *SyscallExitPipeline
	lifecycleHandlerCache   *LifecycleEventHandler
	exitCoordinatorCache    *ExitStatusCoordinator
	eventRouterCache        *TraceEventRouter
	runFinalizerCache       *TraceRunFinalizer
	commandExitHandlerCache *TraceCommandExitHandler
	eventReaderCache        *TraceEventReader
}

// IMPACT: setupBPF is the single eBPF runtime wiring entry used by main. It loads
// the spec, resolves syscall id variables, and delegates all tracepoint/kretprobe
// attachment to bpfAttacher so session.go stays a session orchestrator.
func setupBPF() (*bpfObjects, []link.Link) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("failed to load BPF spec: %v", err)
	}
	if err := setSyscallVariables(spec); err != nil {
		log.Fatalf("failed to resolve BPF syscall variables: %v", err)
	}

	bpfObjs := &bpfObjects{}
	if err := spec.LoadAndAssign(bpfObjs, nil); err != nil {
		log.Fatalf("failed to load and assign BPF objects: %v", err)
	}
	links := newBpfAttacher(bpfObjs).attachAll()
	return bpfObjs, links
}

// IMPACT: setSyscallVariables resolves strace-facing syscall ids referenced by
// BPF constants from the generated SyscallTable. It returns an error instead of
// aborting so unit tests can verify every BPF constant against the live table.
func setSyscallVariables(spec *ebpf.CollectionSpec) error {
	sysNameToID := make(map[string]uint32)
	for id, sc := range meta.SyscallTable {
		sysNameToID[sc.Name] = id
	}

	setVar := func(name string, val uint32) error {
		if v, ok := spec.Variables[name]; ok {
			if err := v.Set(val); err != nil {
				return fmt.Errorf("set %s: %w", name, err)
			}
			return nil
		}
		return fmt.Errorf("variable %s not found in BPF spec", name)
	}

	syscalls := []struct {
		varName  string
		scName   string
		fallback uint32
	}{
		{"SYS_RT_SIGRETURN", "rt_sigreturn", 15},
		{"SYS_RT_SIGRETURN_COMPAT", "rt_sigreturn_compat", 173},
		{"SYS_NANOSLEEP", "nanosleep", 35},
		{"SYS_EXECVE", "execve", 59},
		{"SYS_EXIT", "exit", 60},
		{"SYS_CAPGET", "capget", 125},
		{"SYS_CAPSET", "capset", 126},
		{"SYS_RT_SIGSUSPEND", "rt_sigsuspend", 130},
		{"SYS_EXIT_GROUP", "exit_group", 231},
		{"SYS_EXECVEAT", "execveat", 322},
	}
	for _, sc := range syscalls {
		id, ok := sysNameToID[sc.scName]
		if !ok {
			id = sc.fallback
		}
		if err := setVar(sc.varName, id); err != nil {
			return err
		}
	}
	return nil
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

// IMPACT: startTraceCmd starts a tracee without ptrace; syscall observation is
// purely eBPF based. The next-fork arm installs the pid filter before the
// tracee's initial execve so the exec syscall is observable like upstream.
func startTraceCmd(opts *cli.Options, bpfObjs *bpfObjects, inheritedFiles []*os.File) (*exec.Cmd, int, map[string]string) {
	armNextFork(bpfObjs)
	cmd := newTraceCommand(opts, inheritedFiles)
	if err := cmd.Start(); err != nil {
		disarmNextFork(bpfObjs)
		log.Fatalf("failed to start command: %v", err)
	}

	targetPid := cmd.Process.Pid
	bpfObjs.FilterMap.Update(uint32(targetPid), uint32(1), 0)
	if raw, err := bpfObjs.ArmForkMap.LookupBytes(uint32(0)); err == nil && len(raw) == 4 {
		log.Printf("DEBUG arm after start = %d, tracee = %d", binary.LittleEndian.Uint32(raw), targetPid)
	}
	disarmNextFork(bpfObjs)
	fdMap := populateFDMap(targetPid, targetPid)
	return cmd, targetPid, fdMap
}

// armNextFork asks the BPF sched_process_fork program to add the next child of
// this process to the trace filter before that child executes.
func armNextFork(bpfObjs *bpfObjects) {
	if bpfObjs == nil || bpfObjs.ArmForkMap == nil {
		return
	}
	pid := uint32(os.Getpid())
	bpfObjs.ArmForkMap.Update(uint32(0), pid, 0)
}

// disarmNextFork clears a pending fork arm after Start returns or on failure.
func disarmNextFork(bpfObjs *bpfObjects) {
	if bpfObjs == nil || bpfObjs.ArmForkMap == nil {
		return
	}
	var zero uint32
	bpfObjs.ArmForkMap.Update(uint32(0), zero, 0)
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
