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
	meta.XlatFormat = opts.XlatFormat

	handlePrelude(opts)
	opts.TracePaths = expandTracePathSet(opts.TracePaths)

	inheritedFiles := collectInheritedFiles()
	defer closeFiles(inheritedFiles)

	bpfObjs, tpLinks := setupBPF()
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
	bpfObjs.ConfigMap.Update(uint32(0), cfgVal, 0)

	cmd, targetPid, fdMap := resolveTraceTargets(opts, bpfObjs, inheritedFiles)

	decoder := event.NewDecoder()
	decoder.HexEscapeMode = opts.HexEscapeMode
	// IMPACT: Initialize decoder.StringLimit from parsed CLI options to respect command-line formatting constraints.
	decoder.StringLimit = opts.StringLimit

	outWriter, outFile, outCmd, outPipe := setupOutput(opts.OutFile, opts.OutAppendMode)
	if outFile != nil {
		defer outFile.Close()
	}

	fdState := newFDStateStore(targetPid, fdMap)

	var resolver *stacktrace.Resolver
	if opts.StackTrace {
		resolver = stacktrace.NewResolver(targetPid)
	}

	session := &traceSession{
		cmd:           cmd,
		events:        events,
		targetPid:     targetPid,
		opts:          opts,
		decoder:       decoder,
		fdState:       fdState,
		outWriter:     outWriter,
		outFile:       outFile,
		outCmd:        outCmd,
		outPipe:       outPipe,
		timeFormatter: newTimeFormatter(calculateTimeOffset()),
		bpfObjs:       bpfObjs,
		resolver:      resolver,
		state:         newTraceState(),
	}
	session.run()
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
	if opts.EventFormat == cli.EventFormatJSON {
		cfgVal |= bpfConfigEmitLifecycle
	}
	if len(opts.TracePaths) > 0 {
		// IMPACT: -P filtering needs a deterministic fd -> path map; the BPF
		// runtime keeps fd-state syscalls flowing under CONFIG_FD_STATE.
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
func resolveTraceTargets(opts *cli.Options, bpfObjs *bpfObjects, inheritedFiles []*os.File) (*exec.Cmd, int, map[string]string) {
	var cmd *exec.Cmd
	var targetPid int
	var fdMap map[string]string

	if len(opts.CmdArgs) > 0 {
		cmd, targetPid, fdMap = startTraceCmd(opts, bpfObjs, inheritedFiles)
	}
	if len(opts.AttachPids) > 0 {
		_, firstPid, attachFdMap := attachToPids(opts.AttachPids, bpfObjs)
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
	return cmd, targetPid, fdMap
}

// expandTracePathSet mirrors upstream strace's pathtrace_select_set: each -P
// entry is kept as given and also stored as its absolute realpath, so fd-based
// syscalls whose /proc/<pid>/fd/<n> target is absolute can still match a
// relative -P argument such as "-P stat.sample".
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
	return opts.EventFormat == cli.EventFormatJSON || len(opts.TracePaths) > 0
}
