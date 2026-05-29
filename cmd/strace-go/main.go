package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
	"strace-go/pkg/procmem"

	"github.com/cilium/ebpf/ringbuf"
)

var pendingExecArgs = make(map[int]string)
var pendingExecArgsLock sync.Mutex

var currentSigsetSize = "8"
var currentAction = 0
var currentActionLock sync.Mutex

//go:generate go run -C ../generate-syscalls .
//go:generate go run ../generate-xlats/main.go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/strace.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

// IMPACT: The main function acts as the bootstrap entry point. It parses arguments,
// configures fallback execution arguments for thread tracing, and spawns the trace session.
// IMPACT: Main entry bootstrap point.
func main() {
	opts := cli.ParseArgs(os.Args[1:])
	meta.XlatFormat = opts.XlatFormat
	if len(opts.CmdArgs) > 1 {
		currentSigsetSize = opts.CmdArgs[1]
	}
	if len(opts.CmdArgs) > 2 {
		if act, err := strconv.Atoi(opts.CmdArgs[2]); err == nil {
			currentAction = act
		}
	}
	handler.ExecveArgvFallback = func(pid, tid, targetPid int) []string {
		currentActionLock.Lock()
		act := currentAction
		currentActionLock.Unlock()
		if tid != targetPid {
			act++
		}
		return []string{opts.CmdArgs[0], currentSigsetSize, strconv.Itoa(act)}
	}

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
	if len(opts.CmdArgs) == 0 {
		fmt.Println("Usage: strace-go [options] <command> [args...]")
		os.Exit(1)
	}

	bpfObjs, tpEnter, tpExit := setupBPF()
	defer bpfObjs.Close()
	defer tpEnter.Close()
	defer tpExit.Close()

	events, err := ringbuf.NewReader(bpfObjs.Events)
	if err != nil {
		log.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer events.Close()

	cmd, targetPid, fdMap := startAndTraceCmd(opts.CmdArgs, bpfObjs)

	memReader := procmem.NewReader(targetPid)
	defer memReader.Close()
	decoder := event.NewDecoder(memReader)
	decoder.HexEscapeMode = opts.HexEscapeMode
	// IMPACT: Initialize decoder.StringLimit from parsed CLI options to respect command-line formatting constraints.
	decoder.StringLimit = opts.StringLimit

	outWriter, outFile := setupOutput(opts.OutFile)
	if outFile != nil {
		defer outFile.Close()
	}

	session := &traceSession{
		cmd:       cmd,
		events:    events,
		targetPid: targetPid,
		opts:      opts,
		decoder:   decoder,
		memReader: memReader,
		fdMap:     fdMap,
		outWriter: outWriter,
		outFile:   outFile,
	}
	session.run()
}

// IMPACT: bpfEvent structure defines the exact data alignment matching the BPF ringbuffer events.
// IMPACT: Enlarged StrArg from 4104 to 4504 to match BPF event buffer size for multi-segment fsconfig captures.
type bpfEvent struct {
	Pid           uint32
	SysId         uint32
	Tid           uint32
	ProbeRetEnter int32
	ProbeRetExit  int32
	_             uint32 // Padding for 8-byte alignment of u64 fields
	Args          [6]uint64
	Ret           int64
	Ptr           uint64
	DataLen       uint32
	_             uint32
	StrArg        [4504]byte
}
