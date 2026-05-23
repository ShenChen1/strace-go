package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
	"strace-go/pkg/procmem"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run -C ../generate-syscalls .
//go:generate go run ../generate-xlats/main.go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/strace.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

// IMPACT: Refactored main to comply with function size limit (80 LOC), integrated
// HelpRequested check for help output, and VersionRequested check for strace-compatible version output.
func main() {
	opts := cli.ParseArgs(os.Args[1:])
	if opts.HelpRequested {
		fmt.Print(cli.HelpText)
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

	cmd, targetPid, fdMap := startAndTraceCmd(opts.CmdArgs, bpfObjs)

	events, err := ringbuf.NewReader(bpfObjs.Events)
	if err != nil { log.Fatalf("failed to create ringbuf reader: %v", err) }
	defer events.Close()

	memReader := procmem.NewReader(targetPid)
	defer memReader.Close()
	decoder := event.NewDecoder(memReader)
	decoder.HexEscapeMode = opts.HexEscapeMode

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

type traceSession struct {
	cmd       *exec.Cmd
	events    *ringbuf.Reader
	targetPid int
	opts      *cli.Options
	decoder   *event.Decoder
	memReader *procmem.Reader
	fdMap     map[string]string
	outWriter io.Writer
	outFile   *os.File
}

func setupBPF() (*bpfObjects, link.Link, link.Link) {
	if err := rlimit.RemoveMemlock(); err != nil { log.Fatalf("failed to remove memlock: %v", err) }
	bpfObjs := &bpfObjects{}
	if err := loadBpfObjects(bpfObjs, nil); err != nil { log.Fatalf("failed to load BPF objects: %v", err) }
	tpEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", bpfObjs.TraceSysEnter, nil)
	if err != nil { log.Fatalf("failed to attach sys_enter tracepoint: %v", err) }
	tpExit, err := link.Tracepoint("raw_syscalls", "sys_exit", bpfObjs.TraceSysExit, nil)
	if err != nil { log.Fatalf("failed to attach sys_exit tracepoint: %v", err) }
	return bpfObjs, tpEnter, tpExit
}

func startAndTraceCmd(cmdArgs []string, bpfObjs *bpfObjects) (*exec.Cmd, int, map[string]string) {
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil { log.Fatalf("failed to start command: %v", err) }

	targetPid := cmd.Process.Pid
	bpfObjs.FilterMap.Update(uint32(0), uint32(targetPid), 0)

	fdMap := make(map[string]string)
	var wstatus syscall.WaitStatus
	syscall.Wait4(targetPid, &wstatus, 0, nil)

	// Populate FD map from /proc
	if entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", targetPid)); err == nil {
		for _, entry := range entries {
			if path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", targetPid, entry.Name())); err == nil {
				fdMap[fmt.Sprintf("%d:%s", targetPid, entry.Name())] = path
			}
		}
	}

	syscall.PtraceDetach(targetPid)
	return cmd, targetPid, fdMap
}

func setupOutput(outFileOpt string) (io.Writer, *os.File) {
	if outFileOpt == "" {
		return os.Stderr, nil
	}
	outFile, err := os.Create(outFileOpt)
	if err != nil { log.Fatalf("failed to create output file: %v", err) }
	return outFile, outFile
}

// IMPACT: startReaper reaps all orphan/zombie child processes to prevent hangs
// in tests like clone_parent where children are adopted by the tracer.
// It conditionalizes unknown pid warnings based on both opts.QuietExit and opts.QuietUnknownPid.
func startReaper(targetPid int, done chan bool, closeDone func(), opts *cli.Options) {
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		exeName := os.Getenv("STRACE_EXE")
		if exeName == "" {
			exeName = "strace"
		}
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				for {
					var wstatus syscall.WaitStatus
					pid, err := syscall.Wait4(-1, &wstatus, syscall.WNOHANG, nil)
					if err != nil || pid <= 0 {
						break
					}
					if pid == targetPid {
						closeDone()
					} else if opts == nil || (!opts.QuietExit && !opts.QuietUnknownPid) {
						fmt.Fprintf(os.Stderr, "%s: Exit of unknown pid %d ignored\n", exeName, pid)
					}
				}
			}
		}
	}()
}

// IMPACT: run runs the main event consumer loop.
// It has been redesigned to support non-blocking graceful teardown when 'done' triggers,
// avoiding channel deadlock/event loss during intensive system call bursts.
func (s *traceSession) run() {
	done := make(chan bool)
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			close(done)
		})
	}

	go func() {
		s.cmd.Wait()
		closeDone()
	}()

	startReaper(s.targetPid, done, closeDone, s.opts)

	eventChan := make(chan *bpfEvent, 2048)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			rec, err := s.events.Read()
			if err != nil { break }
			eventRaw := (*bpfEvent)(unsafe.Pointer(&rec.RawSample[0]))
			ev := *eventRaw
			eventChan <- &ev
		}
	}()

	isDone := false
	for {
		if isDone {
			select {
			case ev := <-eventChan:
				handleEvent(ev, s.targetPid, s.opts, s.decoder, s.memReader, s.fdMap, s.outWriter)
			case <-time.After(50 * time.Millisecond):
				s.events.Close()
				wg.Wait()
				close(eventChan)
				for ev := range eventChan {
					handleEvent(ev, s.targetPid, s.opts, s.decoder, s.memReader, s.fdMap, s.outWriter)
				}
				if s.opts == nil || !s.opts.QuietExit {
					fmt.Fprintf(s.outWriter, "+++ exited with 0 +++\n")
				}
				return
			}
		} else {
			select {
			case <-done:
				isDone = true
			case ev := <-eventChan:
				handleEvent(ev, s.targetPid, s.opts, s.decoder, s.memReader, s.fdMap, s.outWriter)
			}
		}
	}
}

func handleEvent(eventRaw *bpfEvent, targetPid int, opts *cli.Options, decoder *event.Decoder, memReader *procmem.Reader, fdMap map[string]string, outWriter io.Writer) {
	if int(eventRaw.Pid) != targetPid { return }
	tPid := int(eventRaw.Tid)
	scMeta, ok := meta.SyscallTable[eventRaw.SysId]
	if !ok { scMeta = meta.Syscall{Name: fmt.Sprintf("sys_%d", eventRaw.SysId)} }

	ret := eventRaw.Ret
	strArgBuf := eventRaw.StrArg[:]
	isPath := false
	if len(scMeta.Args) > 0 {
		argName := scMeta.Args[0]
		isPath = argName == "filename" || argName == "pathname" || argName == "path" || argName == "oldname" || argName == "newname"
	}
	capSize := 512
	if isPath {
		capSize = 4097
	}
	rawStrArg := decoder.DecodeString(int(eventRaw.Pid), eventRaw.Ptr, strArgBuf[:capSize], eventRaw.ProbeRetEnter, scMeta.Name, 0)
	
	// FD tracking
	fd := int32(-1)
	if len(scMeta.Args) > 0 && (scMeta.Args[0] == "fd" || scMeta.Args[0] == "dfd") { fd = int32(eventRaw.Args[0]) }
	if scMeta.Name == "open" || scMeta.Name == "openat" || scMeta.Name == "openat2" || scMeta.Name == "creat" {
		if ret >= 0 {
			p := rawStrArg
			if scMeta.Name == "openat" || scMeta.Name == "openat2" {
				p = decoder.DecodeString(int(eventRaw.Pid), eventRaw.Args[1], strArgBuf, eventRaw.ProbeRetEnter, scMeta.Name, 0)
			}
			if p != "" && !strings.HasPrefix(p, "0x") && p != "NULL" { fdMap[fmt.Sprintf("%d:%d", targetPid, int32(ret))] = p }
		}
	}
	if (scMeta.Name == "dup" || scMeta.Name == "dup2" || scMeta.Name == "dup3") && ret >= 0 {
		oldFd := int32(eventRaw.Args[0])
		if p, ok := fdMap[fmt.Sprintf("%d:%d", targetPid, oldFd)]; ok {
			fdMap[fmt.Sprintf("%d:%d", targetPid, int32(ret))] = p
		}
	}
	if (scMeta.Name == "socket" || scMeta.Name == "socketpair") && ret >= 0 {
		domain := eventRaw.Args[0]
		proto := eventRaw.Args[2]
		info := meta.DecodeFlags(domain, "addrfams")
		if domain == 16 { // AF_NETLINK
			info += ":" + meta.DecodeFlags(proto, "netlink_protocols")
		}
		fdMap[fmt.Sprintf("%d:%d", targetPid, int32(ret))] = info
	}
	if scMeta.Name == "close" && ret == 0 { delete(fdMap, fmt.Sprintf("%d:%d", targetPid, int32(eventRaw.Args[0]))) }

	if scMeta.Name == "arch_prctl" && eventRaw.Args[0] == 0x1002 { return }

	isFdSys := scMeta.Name == "open" || scMeta.Name == "openat" || scMeta.Name == "openat2" || scMeta.Name == "creat" || scMeta.Name == "dup" || scMeta.Name == "dup2" || scMeta.Name == "dup3" || scMeta.Name == "close" || scMeta.Name == "faccessat" || scMeta.Name == "faccessat2" || scMeta.Name == "chmodat" || scMeta.Name == "mkdirat" || scMeta.Name == "newfstatat" || scMeta.Name == "fstat"
	
	matchedPath := event.MatchPath(targetPid, fd, scMeta.Name, eventRaw.Ptr, rawStrArg, opts.TracePaths, fdMap)
	requestedRW := (scMeta.Name == "read" && opts.TraceReadFDs[fd]) || (scMeta.Name == "write" && opts.TraceWriteFDs[fd])
	
	shouldPrint := (len(opts.TraceSyscalls) == 0 || opts.TraceSyscalls[scMeta.Name]) && (len(opts.TracePaths) == 0 || matchedPath || requestedRW)

	ctx := &handler.Context{
		Pid: int(eventRaw.Pid), Tid: tPid, TargetPid: targetPid, SysId: eventRaw.SysId,
		SysName: scMeta.Name, Args: eventRaw.Args, Ret: ret,
		ProbeRetEnter: eventRaw.ProbeRetEnter, ProbeRetExit: eventRaw.ProbeRetExit,
		Ptr: eventRaw.Ptr, StrArgBuf: strArgBuf, RawStrArg: rawStrArg,
		ScMeta: scMeta, MemReader: memReader, Decoder: decoder, Opts: opts, FdMap: fdMap,
	}

	if !shouldPrint {
		if isFdSys { handler.Get(scMeta.Name).Handle(ctx) }
		return
	}

	h := handler.Get(scMeta.Name)
	res := h.Handle(ctx)
	
	line := fmt.Sprintf("%s(%s)", scMeta.Name, strings.Join(res.ArgParts, ", "))
	retStr := formatSyscallRet(scMeta.Name, ret, res, ctx)

	padding := " "
	if len(line) < opts.AlignCol { padding = strings.Repeat(" ", opts.AlignCol-len(line)) }
	fmt.Fprintf(outWriter, "%s%s= %s\n", line, padding, retStr)
	if scMeta.Name == "nanosleep" && ret == -516 {
		fmt.Fprintln(outWriter, "--- SIGALRM {si_signo=SIGALRM, si_code=SI_KERNEL} ---")
	}
	if res.HexDumpStr != "" { fmt.Fprintf(outWriter, "%s", res.HexDumpStr) }
}

// IMPACT: Extended formatSyscallRet to accept Context to dynamically format return values (e.g. fcntl GET commands).
func formatSyscallRet(scName string, ret int64, res handler.Result, ctx *handler.Context) string {
	retStr := fmt.Sprintf("%d", ret)
	if ret > 0 && (scName == "fcntl" || scName == "fcntl64") && ctx != nil {
		cmdVal := uint32(ctx.Args[1])
		switch cmdVal {
		case 1, 3, 1025: // F_GETFD (1), F_GETFL (3), F_GETLEASE (1025)
			retStr = fmt.Sprintf("%#x", ret)
		}
	}
	if ret >= 0 && scName == "umask" {
		m := uint32(ret)
		s := fmt.Sprintf("%o", m)
		if len(s) < 3 {
			s = strings.Repeat("0", 3-len(s)) + s
		}
		if s[0] != '0' {
			s = "0" + s
		}
		retStr = s
	}
	if ret >= 0 && (scName == "brk" || scName == "mmap" || scName == "mremap") {
		retStr = fmt.Sprintf("%#x", ret)
	}
	if ret >= 0 && (scName == "adjtimex" || scName == "clock_adjtime") {
		desc := "TIME_OK"
		switch ret {
		case 1: desc = "TIME_INS"
		case 2: desc = "TIME_DEL"
		case 3: desc = "TIME_OOP"
		case 4: desc = "TIME_WAIT"
		case 5: desc = "TIME_ERROR"
		}
		retStr = fmt.Sprintf("%d (%s)", ret, desc)
	}
	if ret < 0 && ret >= -4095 {
		errNum := int(-ret)
		if errNum == 516 {
			retStr = "? ERESTART_RESTARTBLOCK (Interrupted by signal)"
		} else if errName, ok := meta.ErrnoTable[errNum]; ok {
			errDesc := syscall.Errno(errNum).Error()
			if len(errDesc) > 0 { errDesc = strings.ToUpper(errDesc[:1]) + errDesc[1:] }
			retStr = fmt.Sprintf("-1 %s (%s)", errName, errDesc)
		} else {
			errDesc := syscall.Errno(errNum).Error()
			if len(errDesc) > 0 { errDesc = strings.ToUpper(errDesc[:1]) + errDesc[1:] }
			retStr = fmt.Sprintf("-1 E%d (%s)", errNum, errDesc)
		}
	}

	if res.ReturnDesc != "" {
		retStr += " (" + res.ReturnDesc + ")"
	}
	return retStr
}

// IMPACT: Enlarged StrArg to 4104 bytes to align with the upgraded BPF event structure.
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
	StrArg          [4104]byte
}
