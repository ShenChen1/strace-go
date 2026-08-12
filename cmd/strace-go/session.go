package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
	"strace-go/pkg/stacktrace"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type traceSession struct {
	cmd           *exec.Cmd
	events        traceRingbufReader
	targetPid     int
	opts          *cli.Options
	catalog       *meta.Catalog
	decoder       *event.Decoder
	fdState       *FDStateStore
	runtime       handler.RuntimeServices
	outWriter     io.Writer
	output        *TraceOutput
	summary       *SummaryStats
	timeFormatter *TimeFormatter
	bpfObjs       *bpfObjects
	resolver      *stacktrace.Resolver
	state         *TraceState
	components    *traceSessionComponents
	clock         traceClock
	pidProbe      tracePIDProbe
}

// IMPACT: setupBPF is the single eBPF runtime wiring entry used by main. It loads
// the spec, resolves syscall id variables, and delegates all tracepoint/kretprobe
// attachment to bpfAttacher so session.go stays a session orchestrator.
func setupBPF() (*bpfObjects, []link.Link, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, nil, fmt.Errorf("load BPF spec: %w", err)
	}
	if err := setSyscallVariables(spec); err != nil {
		return nil, nil, fmt.Errorf("resolve BPF syscall variables: %w", err)
	}

	bpfObjs := &bpfObjects{}
	if err := spec.LoadAndAssign(bpfObjs, nil); err != nil {
		_ = bpfObjs.Close()
		return nil, nil, fmt.Errorf("load and assign BPF objects: %w", err)
	}
	links, err := newBpfAttacher(bpfObjs).attachAll()
	if err != nil {
		_ = bpfObjs.Close()
		closeTracepointLinks(links)
		return nil, nil, fmt.Errorf("attach BPF programs: %w", err)
	}
	return bpfObjs, links, nil
}

// IMPACT: setSyscallVariables resolves Go-managed BPF syscall ids only from the
// generated SyscallTable. ABI-only constants remain owned by runtime_abi.h.
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
		varName string
		scName  string
	}{
		{"SYS_RT_SIGRETURN", "rt_sigreturn"},
		{"SYS_NANOSLEEP", "nanosleep"},
		{"SYS_EXECVE", "execve"},
		{"SYS_EXIT", "exit"},
		{"SYS_CAPGET", "capget"},
		{"SYS_CAPSET", "capset"},
		{"SYS_RT_SIGSUSPEND", "rt_sigsuspend"},
		{"SYS_EXIT_GROUP", "exit_group"},
		{"SYS_EXECVEAT", "execveat"},
	}
	for _, sc := range syscalls {
		id, ok := sysNameToID[sc.scName]
		if !ok {
			return fmt.Errorf("syscall %q is missing from generated syscall table", sc.scName)
		}
		if err := setVar(sc.varName, id); err != nil {
			return err
		}
	}
	return nil
}

func collectInheritedFiles() []*os.File {
	fds := passThroughFDs(openFileDescriptors())
	if len(fds) == 0 {
		return nil
	}

	files := make([]*os.File, fds[len(fds)-1]-2)
	for _, fd := range fds {
		dupFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			continue
		}
		files[fd-3] = os.NewFile(uintptr(dupFD), fmt.Sprintf("fd:%d", fd))
	}
	return files
}

const maxInheritedFDScan = 1 << 20

func openFileDescriptors() []int {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return nil
	}
	if limit.Cur > maxInheritedFDScan {
		limit.Cur = maxInheritedFDScan
	}
	fds := make([]int, 0)
	for fd := 3; uint64(fd) < limit.Cur; fd++ {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			fds = append(fds, fd)
		}
	}
	return fds
}

func passThroughFDs(fds []int) []int {
	passThrough := make([]int, 0, len(fds))
	for _, fd := range fds {
		if isPassThroughFD(fd) {
			passThrough = append(passThrough, fd)
		}
	}
	return passThrough
}

func isPassThroughFD(fd int) bool {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return false
	}
	return isPassThroughFDMode(uint32(stat.Mode))
}

func isPassThroughFDMode(mode uint32) bool {
	switch mode & uint32(unix.S_IFMT) {
	case uint32(unix.S_IFREG), uint32(unix.S_IFDIR), uint32(unix.S_IFCHR),
		uint32(unix.S_IFBLK), uint32(unix.S_IFIFO):
		return true
	default:
		return false
	}
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

// IMPACT: startTraceCmd starts a tracee without ptrace; syscall observation is
// purely eBPF based. The next-fork arm installs the pid filter before the
// tracee's initial execve so the exec syscall is observable like upstream.
func startTraceCmd(opts *cli.Options, bpfObjs *bpfObjects, inheritedFiles []*os.File) (*exec.Cmd, int, fdStateSeed, error) {
	if opts == nil || len(opts.CmdArgs) == 0 {
		return nil, 0, fdStateSeed{}, fmt.Errorf("trace command is empty")
	}
	if bpfObjs == nil || bpfObjs.FilterMap == nil {
		return nil, 0, fdStateSeed{}, fmt.Errorf("BPF filter map is unavailable")
	}
	if err := armNextFork(bpfObjs); err != nil {
		return nil, 0, fdStateSeed{}, fmt.Errorf("arm initial fork: %w", err)
	}
	initialCwd, _ := os.Getwd()
	cmd := newTraceCommand(opts, inheritedFiles)
	if err := cmd.Start(); err != nil {
		_ = disarmNextFork(bpfObjs)
		return nil, 0, fdStateSeed{}, fmt.Errorf("start command: %w", err)
	}

	targetPid := cmd.Process.Pid
	if err := bpfObjs.FilterMap.Update(uint32(targetPid), uint32(1), 0); err != nil {
		_ = disarmNextFork(bpfObjs)
		abortTraceTarget(cmd, bpfObjs, targetPid)
		return nil, 0, fdStateSeed{}, fmt.Errorf("add tracee %d to filter: %w", targetPid, err)
	}
	if raw, err := bpfObjs.ArmForkMap.LookupBytes(uint32(0)); err == nil && len(raw) == 4 {
		log.Printf("DEBUG arm after start = %d, tracee = %d", binary.LittleEndian.Uint32(raw), targetPid)
	}
	if err := disarmNextFork(bpfObjs); err != nil {
		abortTraceTarget(cmd, bpfObjs, targetPid)
		return nil, 0, fdStateSeed{}, fmt.Errorf("disarm initial fork: %w", err)
	}
	return cmd, targetPid, initialTraceCommandFDSeed(targetPid, initialCwd), nil
}

// armNextFork asks the BPF sched_process_fork program to add the next child of
// this process to the trace filter before that child executes.
func armNextFork(bpfObjs *bpfObjects) error {
	if bpfObjs == nil || bpfObjs.ArmForkMap == nil {
		return fmt.Errorf("BPF arm fork map is unavailable")
	}
	pid := uint32(os.Getpid())
	if err := bpfObjs.ArmForkMap.Update(uint32(0), pid, 0); err != nil {
		return fmt.Errorf("update arm fork map: %w", err)
	}
	return nil
}

// disarmNextFork clears a pending fork arm after Start returns or on failure.
func disarmNextFork(bpfObjs *bpfObjects) error {
	if bpfObjs == nil || bpfObjs.ArmForkMap == nil {
		return fmt.Errorf("BPF arm fork map is unavailable")
	}
	var zero uint32
	if err := bpfObjs.ArmForkMap.Update(uint32(0), zero, 0); err != nil {
		return fmt.Errorf("clear arm fork map: %w", err)
	}
	return nil
}

// IMPACT: attachToPids attaches tracing to running processes. FD state starts
// unknown and is populated only by events observed after the attach point.
func attachToPids(pids []int, bpfObjs *bpfObjects) (int, fdStateSeed, error) {
	var firstPid int
	if bpfObjs == nil || bpfObjs.FilterMap == nil {
		return 0, fdStateSeed{}, fmt.Errorf("BPF filter map is unavailable")
	}
	attached := make([]uint32, 0, len(pids))

	for i, pid := range pids {
		// Send signal 0 to check if PID exists and we have permissions
		if err := syscall.Kill(pid, 0); err != nil {
			clearFilterPids(bpfObjs, attached)
			return 0, fdStateSeed{}, fmt.Errorf("check attach pid %d: %w", pid, err)
		}

		if i == 0 {
			firstPid = pid
		}
		if err := bpfObjs.FilterMap.Update(uint32(pid), uint32(1), 0); err != nil {
			clearFilterPids(bpfObjs, attached)
			return 0, fdStateSeed{}, fmt.Errorf("add attach pid %d to filter: %w", pid, err)
		}
		attached = append(attached, uint32(pid))

	}
	return firstPid, fdStateSeed{}, nil
}

func clearFilterPids(bpfObjs *bpfObjects, pids []uint32) {
	if bpfObjs == nil || bpfObjs.FilterMap == nil {
		return
	}
	for _, pid := range pids {
		_ = bpfObjs.FilterMap.Delete(pid)
	}
}

// IMPACT: setupOutput prepares the owned output resource for saving strace text traces.
func setupOutput(outFileOpt string, appendMode bool) (*TraceOutput, error) {
	if outFileOpt == "" {
		return newTraceOutput(TraceOutputDeps{Writer: os.Stderr})
	}
	if strings.HasPrefix(outFileOpt, "|") || strings.HasPrefix(outFileOpt, "!") {
		cmdStr := outFileOpt[1:]
		cmd := exec.Command("sh", "-c", cmdStr)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("create output pipe: %w", err)
		}
		if err := cmd.Start(); err != nil {
			_ = stdin.Close()
			return nil, fmt.Errorf("start output command: %w", err)
		}
		output, err := newTraceOutput(TraceOutputDeps{
			Writer:  stdin,
			Closer:  stdin,
			Command: execTraceOutputWaiter{command: cmd},
		})
		if err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			return nil, err
		}
		return output, nil
	}

	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if appendMode {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	outFile, err := os.OpenFile(outFileOpt, flags, 0666)
	if err != nil {
		return nil, fmt.Errorf("create output file: %w", err)
	}
	output, err := newTraceOutput(TraceOutputDeps{Writer: outFile, Closer: outFile})
	if err != nil {
		_ = outFile.Close()
		return nil, err
	}
	return output, nil
}
