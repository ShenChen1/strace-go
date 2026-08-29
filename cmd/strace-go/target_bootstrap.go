package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// traceCommandSpec is the immutable bootstrap input needed to start a tracee.
// Its slices are copied when the spec is built from CLI options.
type traceCommandSpec struct {
	args       []string
	envActions []string
	argv0      string
	argv0Set   bool
	killOnExit bool
}

// traceTargetBootstrap owns target-start side effects until target ownership is
// transferred to traceTargetHandoff. It also owns duplicated inherited files.
type traceTargetBootstrap struct {
	bpfRuntime       traceBPFTargetPort
	attachIdentity   traceAttachIdentityOpener
	inheritedFiles   []*os.File
	workingDirectory traceWorkingDirectoryReader
}

type traceWorkingDirectoryReader func() (string, error)

func newTraceTargetBootstrap(bpfRuntime traceBPFTargetPort) (*traceTargetBootstrap, error) {
	if bpfRuntime == nil {
		return nil, fmt.Errorf("BPF target port is unavailable")
	}
	inheritedFiles, err := collectInheritedFiles()
	if err != nil {
		return nil, fmt.Errorf("collect inherited files: %w", err)
	}
	return &traceTargetBootstrap{
		bpfRuntime:       bpfRuntime,
		attachIdentity:   pidfdAttachIdentityOpener{},
		inheritedFiles:   inheritedFiles,
		workingDirectory: os.Getwd,
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

func collectInheritedFiles() ([]*os.File, error) {
	fds, err := openFileDescriptors()
	if err != nil {
		return nil, fmt.Errorf("enumerate open file descriptors: %w", err)
	}
	fds, err = passThroughFDs(fds)
	if err != nil {
		return nil, fmt.Errorf("classify inherited file descriptors: %w", err)
	}
	return collectInheritedFilesFromFDs(fds, duplicateInheritedFile)
}

type inheritedFileDuplicator func(fd int) (*os.File, error)

func collectInheritedFilesFromFDs(fds []int, duplicate inheritedFileDuplicator) ([]*os.File, error) {
	if len(fds) == 0 {
		return nil, nil
	}
	if duplicate == nil {
		return nil, fmt.Errorf("inherited file duplicator is nil")
	}

	maxFD := 0
	for _, fd := range fds {
		if fd < 3 {
			return nil, fmt.Errorf("inherited file descriptor %d is below 3", fd)
		}
		if fd > maxFD {
			maxFD = fd
		}
	}
	files := make([]*os.File, maxFD-2)
	for _, fd := range fds {
		file, err := duplicate(fd)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("duplicate inherited file descriptor %d: %w", fd, err),
				closeFiles(files),
			)
		}
		if file == nil {
			return nil, errors.Join(
				fmt.Errorf("duplicate inherited file descriptor %d returned nil file", fd),
				closeFiles(files),
			)
		}
		files[fd-3] = file
	}
	return files, nil
}

func duplicateInheritedFile(fd int) (*os.File, error) {
	dupFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(dupFD), fmt.Sprintf("fd:%d", fd)), nil
}

const maxInheritedFDScan = 1 << 20

func openFileDescriptors() ([]int, error) {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return nil, fmt.Errorf("get RLIMIT_NOFILE: %w", err)
	}
	if limit.Cur > maxInheritedFDScan {
		limit.Cur = maxInheritedFDScan
	}
	fds := make([]int, 0)
	for fd := 3; uint64(fd) < limit.Cur; fd++ {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			if errors.Is(err, unix.EBADF) {
				continue
			}
			return nil, fmt.Errorf("check inherited file descriptor %d: %w", fd, err)
		}
		fds = append(fds, fd)
	}
	return fds, nil
}

func passThroughFDs(fds []int) ([]int, error) {
	passThrough := make([]int, 0, len(fds))
	for _, fd := range fds {
		pass, err := isPassThroughFD(fd)
		if err != nil {
			return nil, err
		}
		if pass {
			passThrough = append(passThrough, fd)
		}
	}
	return passThrough, nil
}

func isPassThroughFD(fd int) (bool, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		if errors.Is(err, unix.EBADF) {
			return false, nil
		}
		return false, fmt.Errorf("stat inherited file descriptor %d: %w", fd, err)
	}
	return isPassThroughFDMode(uint32(stat.Mode)), nil
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
	if spec.argv0Set {
		cmd.Args[0] = spec.argv0
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if spec.killOnExit {
		cmd.SysProcAttr = &unix.SysProcAttr{Pdeathsig: unix.SIGKILL}
	}

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
	initialCwd, err := b.readWorkingDirectory()
	if err != nil {
		return nil, 0, fdStateSeed{}, err
	}
	if err := b.armNextFork(); err != nil {
		return nil, 0, fdStateSeed{}, fmt.Errorf("arm initial fork: %w", err)
	}
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
	if err := b.disarmNextFork(); err != nil {
		return nil, 0, fdStateSeed{}, fmt.Errorf("disarm initial fork: %w", errors.Join(err, b.abortTraceTarget(targetRuntime, targetPID)))
	}
	return targetRuntime, targetPID, initialTraceCommandFDSeed(targetPID, initialCwd), nil
}

func (b *traceTargetBootstrap) readWorkingDirectory() (string, error) {
	reader := traceWorkingDirectoryReader(os.Getwd)
	if b != nil && b.workingDirectory != nil {
		reader = b.workingDirectory
	}
	return readInitialTraceCwd(reader)
}

func readInitialTraceCwd(reader traceWorkingDirectoryReader) (string, error) {
	if reader == nil {
		return "", fmt.Errorf("working directory reader is nil")
	}
	cwd, err := reader()
	if err != nil {
		return "", fmt.Errorf("get initial working directory: %w", err)
	}
	if cwd == "" {
		return "", fmt.Errorf("get initial working directory: empty path")
	}
	return cwd, nil
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
	opener := b.attachIdentity
	if opener == nil {
		opener = pidfdAttachIdentityOpener{}
	}
	for index, pid := range pids {
		identity, err := opener.open(pid)
		if err != nil {
			return 0, fdStateSeed{}, fmt.Errorf("open attach pid %d identity: %w", pid, errors.Join(err, clearFilterPids(b.bpfRuntime, attached)))
		}
		if identity == nil {
			return 0, fdStateSeed{}, errors.Join(
				fmt.Errorf("open attach pid %d identity returned nil", pid),
				clearFilterPids(b.bpfRuntime, attached),
			)
		}
		if index == 0 {
			firstPID = pid
		}
		attached = append(attached, uint32(pid))
		if err := b.bpfRuntime.addFilterPID(uint32(pid)); err != nil {
			cleanupErr := errors.Join(identity.close(), clearFilterPids(b.bpfRuntime, attached))
			return 0, fdStateSeed{}, fmt.Errorf("add attach pid %d to filter: %w", pid, errors.Join(err, cleanupErr))
		}
		exited, err := identity.exited()
		if err != nil {
			cleanupErr := errors.Join(identity.close(), clearFilterPids(b.bpfRuntime, attached))
			return 0, fdStateSeed{}, fmt.Errorf("check attach pid %d state: %w", pid, errors.Join(err, cleanupErr))
		}
		if exited {
			cleanupErr := errors.Join(identity.close(), clearFilterPids(b.bpfRuntime, attached))
			return 0, fdStateSeed{}, errors.Join(
				fmt.Errorf("attach pid %d exited before tracing started", pid),
				cleanupErr,
			)
		}
		if err := identity.close(); err != nil {
			return 0, fdStateSeed{}, fmt.Errorf("close attach pid %d identity: %w", pid, errors.Join(err, clearFilterPids(b.bpfRuntime, attached)))
		}
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
