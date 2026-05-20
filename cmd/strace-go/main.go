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

func main() {
	opts := cli.ParseArgs(os.Args[1:])
	if len(opts.CmdArgs) == 0 {
		fmt.Println("Usage: strace-go [options] <command> [args...]")
		os.Exit(1)
	}

	if err := rlimit.RemoveMemlock(); err != nil { log.Fatalf("failed to remove memlock: %v", err) }

	bpfObjs := bpfObjects{}
	if err := loadBpfObjects(&bpfObjs, nil); err != nil { log.Fatalf("failed to load BPF objects: %v", err) }
	defer bpfObjs.Close()

	tpEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", bpfObjs.TraceSysEnter, nil)
	if err != nil { log.Fatalf("failed to attach sys_enter tracepoint: %v", err) }
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("raw_syscalls", "sys_exit", bpfObjs.TraceSysExit, nil)
	if err != nil { log.Fatalf("failed to attach sys_exit tracepoint: %v", err) }
	defer tpExit.Close()

	cmd := exec.Command(opts.CmdArgs[0], opts.CmdArgs[1:]...)
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

	events, err := ringbuf.NewReader(bpfObjs.Events)
	if err != nil { log.Fatalf("failed to create ringbuf reader: %v", err) }
	defer events.Close()

	memReader := procmem.NewReader(targetPid)
	defer memReader.Close()
	decoder := event.NewDecoder(memReader)
	
	var outWriter io.Writer
	var outFile *os.File
	if opts.OutFile != "" {
		var err error
		outFile, err = os.Create(opts.OutFile)
		if err != nil { log.Fatalf("failed to create output file: %v", err) }
		outWriter = outFile
	} else {
		outWriter = os.Stderr
	}

	done := make(chan bool)
	go func() {
		cmd.Wait()
		close(done)
	}()

	eventChan := make(chan *bpfEvent, 2048)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			rec, err := events.Read()
			if err != nil { break }
			eventRaw := (*bpfEvent)(unsafe.Pointer(&rec.RawSample[0]))
			ev := *eventRaw
			eventChan <- &ev
		}
	}()

	for {
		select {
		case <-done:
			time.Sleep(200 * time.Millisecond)
			events.Close()
			wg.Wait()
			close(eventChan)
			for ev := range eventChan {
				handleEvent(ev, targetPid, opts, decoder, memReader, fdMap, outWriter)
			}
			fmt.Fprintf(outWriter, "+++ exited with 0 +++\n")
			if outFile != nil { outFile.Close() }
			return
		case ev := <-eventChan:
			handleEvent(ev, targetPid, opts, decoder, memReader, fdMap, outWriter)
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
	rawStrArg := decoder.DecodeString(int(eventRaw.Pid), eventRaw.Ptr, strArgBuf, eventRaw.ProbeRetEnter, scMeta.Name, 0)
	
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
	retStr := fmt.Sprintf("%d", ret)
	if ret >= 0 && (scMeta.Name == "brk" || scMeta.Name == "mmap" || scMeta.Name == "munmap" || scMeta.Name == "mprotect") {
		retStr = fmt.Sprintf("%#x", ret)
	}
	if ret >= 0 && (scMeta.Name == "adjtimex" || scMeta.Name == "clock_adjtime") {
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
		if errName, ok := meta.ErrnoTable[errNum]; ok {
			errDesc := syscall.Errno(errNum).Error()
			if len(errDesc) > 0 { errDesc = strings.ToUpper(errDesc[:1]) + errDesc[1:] }
			retStr = fmt.Sprintf("-1 %s (%s)", errName, errDesc)
		} else {
			errDesc := syscall.Errno(errNum).Error()
			if len(errDesc) > 0 { errDesc = strings.ToUpper(errDesc[:1]) + errDesc[1:] }
			retStr = fmt.Sprintf("-1 E%d (%s)", errNum, errDesc)
		}
	}

	padding := " "
	if len(line) < opts.AlignCol { padding = strings.Repeat(" ", opts.AlignCol-len(line)) }
	fmt.Fprintf(outWriter, "%s%s= %s\n", line, padding, retStr)
	if res.HexDumpStr != "" { fmt.Fprintf(outWriter, "%s", res.HexDumpStr) }
}

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
	StrArg          [2048]byte
}
