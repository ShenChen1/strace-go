package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// traceCommandSpec is the immutable bootstrap input needed to start a tracee.
// Its slices are copied when the spec is built from CLI options.
type traceCommandSpec struct {
	args       []string
	envActions []string
}

// traceTargetBootstrap owns target-start side effects until target ownership is
// transferred to traceTargetHandoff. It also owns duplicated inherited files.
type traceTargetBootstrap struct {
	bpfRuntime     traceBPFTargetPort
	inheritedFiles []*os.File
}

func newTraceTargetBootstrap(bpfRuntime traceBPFTargetPort) (*traceTargetBootstrap, error) {
	if bpfRuntime == nil {
		return nil, fmt.Errorf("BPF target port is unavailable")
	}
	return &traceTargetBootstrap{
		bpfRuntime:     bpfRuntime,
		inheritedFiles: collectInheritedFiles(),
	}, nil
}

func (b *traceTargetBootstrap) Resolve(
	targets traceTargetConfig,
) (*traceTargetRuntime, int, fdStateSeed, error) {
	if b == nil || b.bpfRuntime == nil {
		return nil, 0, fdStateSeed{}, fmt.Errorf("BPF target port is unavailable")
	}

	var targetRuntime *traceTargetRuntime
	var targetPID int
	var fdSeed fdStateSeed
	if len(targets.command.args) > 0 {
		var err error
		targetRuntime, targetPID, fdSeed, err = b.startTraceCmd(targets.command)
		if err != nil {
			return nil, 0, fdStateSeed{}, err
		}
	}
	if len(targets.attachPIDs) == 0 {
		return targetRuntime, targetPID, fdSeed, nil
	}

	firstPID, attachSeed, err := b.attachToPids(targets.attachPIDs)
	if err != nil {
		return nil, 0, fdStateSeed{}, errors.Join(err, b.abortTraceTarget(targetRuntime, targetPID))
	}
	if targetPID == 0 {
		targetPID = firstPID
		fdSeed = attachSeed
	} else {
		fdSeed.merge(attachSeed)
	}
	return targetRuntime, targetPID, fdSeed, nil
}

func (b *traceTargetBootstrap) Close() error {
	if b == nil {
		return nil
	}
	closeErr := closeFiles(b.inheritedFiles)
	b.inheritedFiles = nil
	return closeErr
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

func closeFiles(files []*os.File) error {
	var closeErr error
	for _, file := range files {
		if file != nil {
			if err := file.Close(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("close inherited file %s: %w", file.Name(), err))
			}
		}
	}
	return closeErr
}

func newTraceCommand(spec traceCommandSpec, inheritedFiles []*os.File) *exec.Cmd {
	cmdArgs := spec.args
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	envMap := make(map[string]string)
	for _, entry := range os.Environ() {
		if index := strings.Index(entry, "="); index >= 0 {
			envMap[entry[:index]] = entry[index+1:]
		}
	}
	for _, action := range spec.envActions {
		if index := strings.Index(action, "="); index >= 0 {
			envMap[action[:index]] = action[index+1:]
		} else {
			delete(envMap, action)
		}
	}
	for key, value := range envMap {
		cmd.Env = append(cmd.Env, key+"="+value)
	}

	cmd.ExtraFiles = inheritedFiles
	return cmd
}

// IMPACT: startTraceCmd starts a tracee without ptrace; syscall observation is
// purely eBPF based. The next-fork arm installs the pid filter before the
// tracee's initial execve so the exec syscall is observable like upstream.
func (b *traceTargetBootstrap) startTraceCmd(
	spec traceCommandSpec,
) (*traceTargetRuntime, int, fdStateSeed, error) {
	if len(spec.args) == 0 {
		return nil, 0, fdStateSeed{}, fmt.Errorf("trace command is empty")
	}
	if b == nil || b.bpfRuntime == nil {
		return nil, 0, fdStateSeed{}, fmt.Errorf("BPF filter map is unavailable")
	}
	if err := b.armNextFork(); err != nil {
		return nil, 0, fdStateSeed{}, fmt.Errorf("arm initial fork: %w", err)
	}
	initialCwd, _ := os.Getwd()
	cmd := newTraceCommand(spec, b.inheritedFiles)
	if err := cmd.Start(); err != nil {
		return nil, 0, fdStateSeed{}, fmt.Errorf("start command: %w", errors.Join(err, b.disarmNextFork()))
	}

	targetRuntime := newTraceTargetRuntime(cmd)
	targetPID := cmd.Process.Pid
	if err := b.bpfRuntime.addFilterPID(uint32(targetPID)); err != nil {
		cleanupErr := errors.Join(b.disarmNextFork(), b.abortTraceTarget(targetRuntime, targetPID))
		return nil, 0, fdStateSeed{}, fmt.Errorf("add tracee %d to filter: %w", targetPID, errors.Join(err, cleanupErr))
	}
	if armedPID, ok := b.bpfRuntime.armedForkPID(); ok {
		log.Printf("DEBUG arm after start = %d, tracee = %d", armedPID, targetPID)
	}
	if err := b.disarmNextFork(); err != nil {
		return nil, 0, fdStateSeed{}, fmt.Errorf("disarm initial fork: %w", errors.Join(err, b.abortTraceTarget(targetRuntime, targetPID)))
	}
	return targetRuntime, targetPID, initialTraceCommandFDSeed(targetPID, initialCwd), nil
}

func (b *traceTargetBootstrap) armNextFork() error {
	if b == nil || b.bpfRuntime == nil {
		return fmt.Errorf("BPF arm fork map is unavailable")
	}
	return b.bpfRuntime.armNextFork()
}

func (b *traceTargetBootstrap) disarmNextFork() error {
	if b == nil || b.bpfRuntime == nil {
		return fmt.Errorf("BPF arm fork map is unavailable")
	}
	return b.bpfRuntime.disarmNextFork()
}

// IMPACT: attachToPids attaches tracing to running processes. FD state starts
// unknown and is populated only by events observed after the attach point.
func (b *traceTargetBootstrap) attachToPids(pids []int) (int, fdStateSeed, error) {
	if b == nil || b.bpfRuntime == nil {
		return 0, fdStateSeed{}, fmt.Errorf("BPF filter map is unavailable")
	}

	var firstPID int
	attached := make([]uint32, 0, len(pids))
	for index, pid := range pids {
		if err := syscall.Kill(pid, 0); err != nil {
			return 0, fdStateSeed{}, fmt.Errorf("check attach pid %d: %w", pid, errors.Join(err, clearFilterPids(b.bpfRuntime, attached)))
		}
		if index == 0 {
			firstPID = pid
		}
		if err := b.bpfRuntime.addFilterPID(uint32(pid)); err != nil {
			return 0, fdStateSeed{}, fmt.Errorf("add attach pid %d to filter: %w", pid, errors.Join(err, clearFilterPids(b.bpfRuntime, attached)))
		}
		attached = append(attached, uint32(pid))
	}
	return firstPID, fdStateSeed{}, nil
}

func (b *traceTargetBootstrap) abortTraceTarget(targetRuntime *traceTargetRuntime, targetPID int) error {
	var cleanupErr error
	if b != nil && targetPID > 0 {
		cleanupErr = clearFilterPids(b.bpfRuntime, []uint32{uint32(targetPID)})
	}
	return errors.Join(cleanupErr, terminateTraceTarget(targetRuntime))
}

func clearFilterPids(bpfRuntime traceBPFTargetPort, pids []uint32) error {
	if bpfRuntime == nil {
		return nil
	}
	var cleanupErr error
	for _, pid := range pids {
		if err := bpfRuntime.deleteFilterPID(pid); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("delete filter pid %d: %w", pid, err))
		}
	}
	return cleanupErr
}

func terminateTraceTarget(targetRuntime *traceTargetRuntime) error {
	if targetRuntime != nil {
		return targetRuntime.Abort()
	}
	return nil
}

func traceTargetPIDs(attachPIDs []int, targetPID int) []uint32 {
	pids := make([]uint32, 0, 1+len(attachPIDs))
	appendPID := func(pid int) {
		if pid <= 0 {
			return
		}
		for _, existing := range pids {
			if existing == uint32(pid) {
				return
			}
		}
		pids = append(pids, uint32(pid))
	}
	appendPID(targetPID)
	for _, pid := range attachPIDs {
		appendPID(pid)
	}
	return pids
}
