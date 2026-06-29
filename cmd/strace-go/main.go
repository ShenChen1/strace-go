package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"

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
)

//go:generate go run -C ../generate-syscalls .
//go:generate go run ../generate-xlats
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/strace.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

// IMPACT: The main function acts as the bootstrap entry point. It parses arguments,
// configures fallback execution arguments for thread tracing, and spawns the trace session.
// IMPACT: Main entry bootstrap point.
func main() {
	opts := cli.ParseArgs(os.Args[1:])
	meta.XlatFormat = opts.XlatFormat

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

	var cfgVal uint32 = 0
	if opts.StackTrace {
		cfgVal |= bpfConfigCaptureStack
	}
	if opts.FollowForks {
		cfgVal |= bpfConfigFollowForks
	}
	if opts.EventFormat == cli.EventFormatJSON {
		cfgVal |= bpfConfigEmitEnter
		cfgVal |= bpfConfigEmitLifecycle
	}
	syscallFilterCfg, err := configureSyscallFilter(opts, bpfObjs)
	if err != nil {
		log.Fatalf("failed to configure syscall filter: %v", err)
	}
	cfgVal |= syscallFilterCfg
	bpfObjs.ConfigMap.Update(uint32(0), cfgVal, 0)

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

	decoder := event.NewDecoder()
	decoder.HexEscapeMode = opts.HexEscapeMode
	// IMPACT: Initialize decoder.StringLimit from parsed CLI options to respect command-line formatting constraints.
	decoder.StringLimit = opts.StringLimit

	outWriter, outFile, outCmd, outPipe := setupOutput(opts.OutFile, opts.OutAppendMode)
	if outFile != nil {
		defer outFile.Close()
	}

	fdOffsets, fdFiles := initFDTracking(targetPid, fdMap)

	var resolver *stacktrace.Resolver
	if opts.StackTrace {
		resolver = stacktrace.NewResolver(targetPid)
	}

	session := &traceSession{
		cmd:              cmd,
		events:           events,
		targetPid:        targetPid,
		opts:             opts,
		decoder:          decoder,
		fdMap:            fdMap,
		fdOffsets:        fdOffsets,
		fdFiles:          fdFiles,
		outWriter:        outWriter,
		outFile:          outFile,
		outCmd:           outCmd,
		outPipe:          outPipe,
		bootTimeOffsetNs: calculateTimeOffset(),
		bpfObjs:          bpfObjs,
		resolver:         resolver,
	}
	session.run()
}

func calculateTimeOffset() int64 {
	var tsMono, tsReal unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &tsMono)
	unix.ClockGettime(unix.CLOCK_REALTIME, &tsReal)
	monoNs := int64(tsMono.Sec)*1e9 + int64(tsMono.Nsec)
	realNs := int64(tsReal.Sec)*1e9 + int64(tsReal.Nsec)
	return realNs - monoNs
}

type bpfEvent = bpfBpfEvent
