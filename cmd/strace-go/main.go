package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
	"strace-go/pkg/stacktrace"

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

// IMPACT: main is the bootstrap entry point. It parses arguments, resolves the
// runtime config and trace targets through named helpers, and spawns the session.
func main() {
	opts := cli.ParseArgs(os.Args[1:])

	handlePrelude(opts)
	opts.TracePaths = expandTracePathSet(opts.TracePaths)

	inheritedFiles := collectInheritedFiles()
	defer closeFiles(inheritedFiles)

	bpfObjs, tpLinks, err := setupBPF()
	if err != nil {
		log.Fatalf("failed to set up BPF runtime: %v", err)
	}
	defer bpfObjs.Close()
	for _, l := range tpLinks {
		defer l.Close()
	}

	events, err := ringbuf.NewReader(bpfObjs.Events)
	if err != nil {
		log.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer events.Close()

	cfgVal, err := buildRuntimeConfig(opts, bpfObjs)
	if err != nil {
		log.Fatalf("failed to build runtime config: %v", err)
	}
	if err := bpfObjs.ConfigMap.Update(uint32(0), cfgVal, 0); err != nil {
		log.Fatalf("failed to update BPF runtime config: %v", err)
	}

	cmd, targetPid, fdMap, err := resolveTraceTargets(opts, bpfObjs, inheritedFiles)
	if err != nil {
		log.Fatalf("failed to resolve trace targets: %v", err)
	}

	decoder := event.NewDecoder()
	decoder.HexEscapeMode = opts.HexEscapeMode
	// IMPACT: Initialize decoder.StringLimit from parsed CLI options to respect command-line formatting constraints.
	decoder.StringLimit = opts.StringLimit

	output, err := setupOutput(opts.OutFile, opts.OutAppendMode)
	if err != nil {
		abortTraceTarget(cmd, bpfObjs, targetPid)
		log.Fatalf("failed to set up output: %v", err)
	}

	fdState := newFDStateStore(fdMap)

	var resolver *stacktrace.Resolver
	if opts.StackTrace {
		resolver = stacktrace.NewResolver()
	}

	session := newTraceSession(traceSessionDeps{
		Cmd:           cmd,
		Events:        events,
		TargetPID:     targetPid,
		Opts:          opts,
		Catalog:       metaCatalogForOptions(opts),
		Decoder:       decoder,
		FDState:       fdState,
		OutWriter:     output,
		Output:        output,
		TimeFormatter: newTimeFormatter(calculateTimeOffset()),
		BPFObjects:    bpfObjs,
		Resolver:      resolver,
		State:         newTraceStateWithDeferredExit(shouldEmitGenericEnter(opts)),
	})
	session.emitDebugReady()
	if err := session.run(); err != nil {
		log.Fatalf("failed to finalize trace session: %v", err)
	}
}

func metaCatalogForOptions(opts *cli.Options) *meta.Catalog {
	if opts == nil {
		return meta.NewCatalog("abbrev")
	}
	return meta.NewCatalog(opts.XlatFormat)
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

// buildRuntimeConfig computes the BPF config map value from CLI options and the
// syscall filter, returning an error when the filter cannot be configured.
func buildRuntimeConfig(opts *cli.Options, bpfObjs *bpfObjects) (uint32, error) {
	var cfgVal uint32
	if opts.StackTrace {
		cfgVal |= bpfConfigCaptureStack
	}
	if opts.FollowForks {
		cfgVal |= bpfConfigFollowForks
	}
	if shouldEmitGenericEnter(opts) {
		cfgVal |= bpfConfigEmitEnter
	}
	// IMPACT: lifecycle events always flow so task/fd state and attach exit
	// status work in text mode too; JSON rendering is gated separately.
	cfgVal |= bpfConfigEmitLifecycle
	if len(opts.TracePaths) > 0 || opts.ShowPaths {
		// IMPACT: -P filtering and -y/-yy fd path rendering both need a
		// deterministic fd -> path map; the BPF runtime keeps fd-state
		// syscalls flowing under CONFIG_FD_STATE even when filtered out.
		cfgVal |= bpfConfigFdState
	}
	syscallFilterCfg, err := configureSyscallFilter(opts, bpfObjs)
	if err != nil {
		return 0, err
	}
	return cfgVal | syscallFilterCfg, nil
}

// resolveTraceTargets starts the traced command and/or attaches to pids, merging
// fd maps when both targets are requested.
func resolveTraceTargets(opts *cli.Options, bpfObjs *bpfObjects, inheritedFiles []*os.File) (*exec.Cmd, int, map[string]string, error) {
	if opts == nil {
		return nil, 0, nil, fmt.Errorf("trace options are nil")
	}
	var cmd *exec.Cmd
	var targetPid int
	var fdMap map[string]string

	if len(opts.CmdArgs) > 0 {
		var err error
		cmd, targetPid, fdMap, err = startTraceCmd(opts, bpfObjs, inheritedFiles)
		if err != nil {
			return nil, 0, nil, err
		}
	}
	if len(opts.AttachPids) > 0 {
		firstPid, attachFdMap, err := attachToPids(opts.AttachPids, bpfObjs)
		if err != nil {
			abortTraceTarget(cmd, bpfObjs, targetPid)
			return nil, 0, nil, err
		}
		if targetPid == 0 {
			targetPid = firstPid
			fdMap = attachFdMap
		} else {
			opts.FollowForks = true // Tracing command + attached pids
			for k, v := range attachFdMap {
				fdMap[k] = v
			}
		}
		if len(opts.AttachPids) > 1 {
			opts.FollowForks = true // Tracing multiple attached pids
		}
	}
	return cmd, targetPid, fdMap, nil
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

func calculateTimeOffset() int64 {
	var tsMono, tsReal unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &tsMono)
	unix.ClockGettime(unix.CLOCK_REALTIME, &tsReal)
	monoNs := int64(tsMono.Sec)*1e9 + int64(tsMono.Nsec)
	realNs := int64(tsReal.Sec)*1e9 + int64(tsReal.Nsec)
	return realNs - monoNs
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
