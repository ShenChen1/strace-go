package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"strace-go/pkg/cli"

	"github.com/cilium/ebpf/ringbuf"
)

const (
	bpfConfigCaptureStack         = 1 << 0
	bpfConfigFollowForks          = 1 << 1
	bpfConfigEmitEnter            = 1 << 2
	bpfConfigSyscallFilter        = 1 << 3
	bpfConfigSyscallFilterNegated = 1 << 4
	bpfConfigEmitLifecycle        = 1 << 5
	bpfConfigFdState              = 1 << 6
)

//go:generate go run -C ../generate-syscalls .
//go:generate go run ../generate-xlats
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/strace.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

// IMPACT: main is the final process error boundary; resource-owning bootstrap
// work stays in error-returning helpers so deferred cleanup always runs.
func main() {
	if err := runMain(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "strace-go: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string) error {
	opts := cli.ParseArgs(args)
	handlePrelude(opts)
	normalizeTraceTargetOptions(opts)
	opts.TracePaths = expandTracePathSet(opts.TracePaths)
	return runTraceSession(newTraceLaunchConfig(opts), systemTraceClock{})
}

func runTraceSession(config *traceLaunchConfig, clock traceClock) error {
	if config == nil {
		return fmt.Errorf("trace launch config is nil")
	}
	if clock == nil {
		return fmt.Errorf("trace clock is nil")
	}
	inheritedFiles := collectInheritedFiles()
	defer closeFiles(inheritedFiles)

	bpfObjs, tpLinks, err := setupBPF()
	if err != nil {
		return fmt.Errorf("failed to set up BPF runtime: %w", err)
	}
	defer bpfObjs.Close()
	defer closeTracepointLinks(tpLinks)

	events, err := ringbuf.NewReader(bpfObjs.Events)
	if err != nil {
		return fmt.Errorf("failed to create ringbuf reader: %w", err)
	}
	defer events.Close()

	cfgVal, err := buildRuntimeConfig(config.bpfConfig, bpfObjs)
	if err != nil {
		return fmt.Errorf("failed to build runtime config: %w", err)
	}
	if err := bpfObjs.ConfigMap.Update(uint32(0), cfgVal, 0); err != nil {
		return fmt.Errorf("failed to update BPF runtime config: %w", err)
	}

	cmd, targetPid, fdSeed, err := resolveTraceTargets(config.targets, bpfObjs, inheritedFiles)
	if err != nil {
		return fmt.Errorf("failed to resolve trace targets: %w", err)
	}
	cleanupTargets := true
	defer func() {
		if cleanupTargets {
			abortTraceTargets(config.targets, cmd, bpfObjs, targetPid)
		}
	}()

	output, err := setupOutput(config.outputPath, config.outputAppend)
	if err != nil {
		return fmt.Errorf("failed to set up output: %w", err)
	}
	defer func() { _ = output.Close() }()

	session, err := composeTraceSession(config.session, clock, traceSessionBootstrap{
		cmd:       cmd,
		events:    events,
		targetPID: targetPid,
		fdSeed:    fdSeed,
		bpfObjs:   bpfObjs,
	}, output)
	if err != nil {
		return fmt.Errorf("failed to compose trace session: %w", err)
	}
	session.emitDebugReady()
	if err := session.run(); err != nil {
		return fmt.Errorf("failed to finalize trace session: %w", err)
	}
	cleanupTargets = false
	return nil
}

// handlePrelude handles help/version requests and rejects sessions without targets.
func handlePrelude(opts *cli.Options) {
	if opts.HelpRequested {
		fmt.Printf("%s", cli.HelpText)
		os.Exit(0)
	}
	if opts.VersionRequested {
		fmt.Printf("strace -- version 6.19\n")
		fmt.Printf("Copyright (c) 1991-2026 The strace developers <https://strace.io>.\n")
		fmt.Printf("This is free software; see the source for copying conditions.  There is NO\n")
		fmt.Printf("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n")
		fmt.Printf("Optional features enabled: stack-trace=libunwind stack-demangle m32-mpers mx32-mpers\n")
		os.Exit(0)
	}
	if len(opts.CmdArgs) == 0 && len(opts.AttachPids) == 0 {
		fmt.Println("Usage: strace-go [options] <command> [args...]")
		os.Exit(1)
	}
}

// normalizeTraceTargetOptions resolves implicit lifecycle policy before BPF
// configuration and target startup. The parsed options are read-only after
// this bootstrap step.
func normalizeTraceTargetOptions(opts *cli.Options) {
	if opts == nil {
		return
	}
	if len(opts.AttachPids) > 1 || (len(opts.CmdArgs) > 0 && len(opts.AttachPids) > 0) {
		opts.FollowForks = true
	}
}

// resolveTraceTargets starts the traced command and/or attaches to pids, merging
// startup FD state seeds when both targets are requested.
func resolveTraceTargets(targets traceTargetConfig, bpfObjs *bpfObjects, inheritedFiles []*os.File) (*exec.Cmd, int, fdStateSeed, error) {
	var cmd *exec.Cmd
	var targetPid int
	var fdSeed fdStateSeed

	if len(targets.command.args) > 0 {
		var err error
		cmd, targetPid, fdSeed, err = startTraceCmd(targets.command, bpfObjs, inheritedFiles)
		if err != nil {
			return nil, 0, fdStateSeed{}, err
		}
	}
	if len(targets.attachPIDs) > 0 {
		firstPid, attachSeed, err := attachToPids(targets.attachPIDs, bpfObjs)
		if err != nil {
			abortTraceTarget(cmd, bpfObjs, targetPid)
			return nil, 0, fdStateSeed{}, err
		}
		if targetPid == 0 {
			targetPid = firstPid
			fdSeed = attachSeed
		} else {
			fdSeed.merge(attachSeed)
		}
	}
	return cmd, targetPid, fdSeed, nil
}

func terminateTraceCommand(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func abortTraceTarget(cmd *exec.Cmd, bpfObjs *bpfObjects, targetPid int) {
	if targetPid > 0 {
		clearFilterPids(bpfObjs, []uint32{uint32(targetPid)})
	}
	terminateTraceCommand(cmd)
}

func abortTraceTargets(targets traceTargetConfig, cmd *exec.Cmd, bpfObjs *bpfObjects, targetPid int) {
	clearFilterPids(bpfObjs, traceTargetPIDs(targets.attachPIDs, targetPid))
	terminateTraceCommand(cmd)
}

func traceTargetPIDs(attachPIDs []int, targetPid int) []uint32 {
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
	appendPID(targetPid)
	for _, pid := range attachPIDs {
		appendPID(pid)
	}
	return pids
}

// expandTracePathSet mirrors upstream strace's pathtrace_select_set: each -P
// entry is kept as given and also stored as its absolute realpath, so
// event-sourced absolute fd targets can still match a relative -P argument
// such as "-P stat.sample".
func expandTracePathSet(paths map[string]bool) map[string]bool {
	if len(paths) == 0 {
		return paths
	}
	expanded := make(map[string]bool, len(paths)*2)
	for p := range paths {
		expanded[p] = true
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			expanded[resolved] = true
		} else {
			expanded[abs] = true
		}
	}
	return expanded
}

func calculateTimeOffsetWithClock(clock traceClock) int64 {
	if clock == nil {
		return 0
	}
	return clock.Now().UnixNano() - int64(clock.NowMonoNs())
}

func shouldEmitGenericEnter(opts *cli.Options) bool {
	if opts == nil {
		return false
	}
	if opts.EventFormat == cli.EventFormatJSON || len(opts.TracePaths) > 0 {
		return true
	}
	return !opts.SummaryOnly
}
