package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type traceSession struct {
	dependencies traceSessionDeps
	eventPolicy  *cliTraceEventPolicy
	components   *traceSessionComponents
}

// traceCommandSpec is the immutable bootstrap input needed to start a tracee.
// Its slices are copied when the spec is built from CLI options.
type traceCommandSpec struct {
	args       []string
	envActions []string
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

func newTraceCommand(spec traceCommandSpec, inheritedFiles []*os.File) *exec.Cmd {
	cmdArgs := spec.args
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
	for _, action := range spec.envActions {
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
func startTraceCmd(spec traceCommandSpec, bpfRuntime traceBPFTargetPort, inheritedFiles []*os.File) (*exec.Cmd, int, fdStateSeed, error) {
	if len(spec.args) == 0 {
		return nil, 0, fdStateSeed{}, fmt.Errorf("trace command is empty")
	}
	if bpfRuntime == nil {
		return nil, 0, fdStateSeed{}, fmt.Errorf("BPF filter map is unavailable")
	}
	if err := armNextFork(bpfRuntime); err != nil {
		return nil, 0, fdStateSeed{}, fmt.Errorf("arm initial fork: %w", err)
	}
	initialCwd, _ := os.Getwd()
	cmd := newTraceCommand(spec, inheritedFiles)
	if err := cmd.Start(); err != nil {
		_ = disarmNextFork(bpfRuntime)
		return nil, 0, fdStateSeed{}, fmt.Errorf("start command: %w", err)
	}

	targetPid := cmd.Process.Pid
	if err := bpfRuntime.addFilterPID(uint32(targetPid)); err != nil {
		_ = disarmNextFork(bpfRuntime)
		abortTraceTarget(cmd, bpfRuntime, targetPid)
		return nil, 0, fdStateSeed{}, fmt.Errorf("add tracee %d to filter: %w", targetPid, err)
	}
	if armedPID, ok := bpfRuntime.armedForkPID(); ok {
		log.Printf("DEBUG arm after start = %d, tracee = %d", armedPID, targetPid)
	}
	if err := disarmNextFork(bpfRuntime); err != nil {
		abortTraceTarget(cmd, bpfRuntime, targetPid)
		return nil, 0, fdStateSeed{}, fmt.Errorf("disarm initial fork: %w", err)
	}
	return cmd, targetPid, initialTraceCommandFDSeed(targetPid, initialCwd), nil
}

// armNextFork asks the BPF sched_process_fork program to add the next child of
// this process to the trace filter before that child executes.
func armNextFork(bpfRuntime traceBPFTargetPort) error {
	if bpfRuntime == nil {
		return fmt.Errorf("BPF arm fork map is unavailable")
	}
	return bpfRuntime.armNextFork()
}

// disarmNextFork clears a pending fork arm after Start returns or on failure.
func disarmNextFork(bpfRuntime traceBPFTargetPort) error {
	if bpfRuntime == nil {
		return fmt.Errorf("BPF arm fork map is unavailable")
	}
	return bpfRuntime.disarmNextFork()
}

// IMPACT: attachToPids attaches tracing to running processes. FD state starts
// unknown and is populated only by events observed after the attach point.
func attachToPids(pids []int, bpfRuntime traceBPFTargetPort) (int, fdStateSeed, error) {
	var firstPid int
	if bpfRuntime == nil {
		return 0, fdStateSeed{}, fmt.Errorf("BPF filter map is unavailable")
	}
	attached := make([]uint32, 0, len(pids))

	for i, pid := range pids {
		// Send signal 0 to check if PID exists and we have permissions
		if err := syscall.Kill(pid, 0); err != nil {
			clearFilterPids(bpfRuntime, attached)
			return 0, fdStateSeed{}, fmt.Errorf("check attach pid %d: %w", pid, err)
		}

		if i == 0 {
			firstPid = pid
		}
		if err := bpfRuntime.addFilterPID(uint32(pid)); err != nil {
			clearFilterPids(bpfRuntime, attached)
			return 0, fdStateSeed{}, fmt.Errorf("add attach pid %d to filter: %w", pid, err)
		}
		attached = append(attached, uint32(pid))

	}
	return firstPid, fdStateSeed{}, nil
}

func clearFilterPids(bpfRuntime traceBPFTargetPort, pids []uint32) {
	if bpfRuntime == nil {
		return
	}
	for _, pid := range pids {
		bpfRuntime.deleteFilterPID(pid)
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
