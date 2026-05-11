package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/format"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
	"strace-go/pkg/procmem"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run ../generate-syscalls/main.go
//go:generate go run ../generate-xlats/main.go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/strace.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

func main() {
	opts := cli.ParseArgs(os.Args[1:])
	if len(opts.CmdArgs) == 0 { os.Exit(0) }

	var outWriterRaw *os.File = os.Stderr
	if opts.OutFile != "" { f, err := os.Create(opts.OutFile); if err == nil { defer f.Close(); outWriterRaw = f } }
	outWriter := bufio.NewWriterSize(outWriterRaw, 1024*1024); defer outWriter.Flush()

	if err := rlimit.RemoveMemlock(); err != nil { log.Fatal(err) }
	objs := bpfObjects{}; if err := loadBpfObjects(&objs, nil); err != nil { log.Fatalf("loading objects: %v", err) }
	defer objs.Close()
	enterL, _ := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSysEnter, nil); defer enterL.Close()
	exitL, _ := link.Tracepoint("raw_syscalls", "sys_exit", objs.TraceSysExit, nil); defer exitL.Close()
	rd, _ := ringbuf.NewReader(objs.Events); defer rd.Close()

	cmd := exec.Command(opts.CmdArgs[0], opts.CmdArgs[1:]...); cmd.Stdin = os.Stdin; cmd.Stdout = os.Stdout; cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{ Ptrace: true }
	if err := cmd.Start(); err != nil { log.Fatalf("failed to start cmd: %v", err) }
	targetPid := cmd.Process.Pid
	var ws syscall.WaitStatus; if _, err := syscall.Wait4(targetPid, &ws, 0, nil); err != nil { log.Fatalf("failed to wait for child: %v", err) }
	var key uint32 = 0; targetPidU32 := uint32(targetPid); objs.FilterMap.Update(&key, &targetPidU32, 0)
	
	syscall.PtraceSetOptions(targetPid, 0x1) // PTRACE_O_TRACESYSGOOD
	syscall.PtraceCont(targetPid, 0)

	memReader := procmem.NewReader(targetPid)
	decoder := event.NewDecoder(memReader)

	done := make(chan bool, 1)
	go func() { 
		for {
			var ws syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &ws, 0, nil)
			if err != nil || (pid == targetPid && (ws.Exited() || ws.Signaled())) { break }
			if pid > 0 { syscall.PtraceCont(pid, 0) }
		}
		time.Sleep(1000 * time.Millisecond); rd.Close(); done <- true 
	}()

	fdMap := make(map[string]string)
	for {
		record, err := rd.Read(); if err != nil { break }
		eventRaw := (*bpfBpfEvent)(unsafe.Pointer(&record.RawSample[0]))
		if eventRaw.Pid != uint32(targetPid) { continue }
		scMeta, ok := meta.SyscallTable[eventRaw.SysId]; if !ok { continue }
		ret := int64(eventRaw.Ret); strArgBuf := unsafe.Slice((*byte)(unsafe.Pointer(&eventRaw.StrArg[0])), 2048)
		tPid := int(eventRaw.Tid); if tPid == 0 { tPid = int(eventRaw.Pid) }

		var fd int32 = -1; if strings.Contains(scMeta.Name, "read") || strings.Contains(scMeta.Name, "write") || scMeta.Name == "openat" || scMeta.Name == "fstat" || scMeta.Name == "fchmod" || scMeta.Name == "fchown" || scMeta.Name == "faccessat" || scMeta.Name == "faccessat2" || scMeta.Name == "chmodat" || scMeta.Name == "mkdirat" || scMeta.Name == "newfstatat" || scMeta.Name == "ioctl" { fd = int32(eventRaw.Args[0]) } else if scMeta.Name == "open" || scMeta.Name == "dup" || scMeta.Name == "dup2" || scMeta.Name == "dup3" || scMeta.Name == "close" { fd = int32(eventRaw.Args[0]) }
		
		pRet := eventRaw.ProbeRetEnter; if scMeta.Name == "read" { pRet = eventRaw.ProbeRetExit }
		expectedLen := 0; if scMeta.Name == "write" { expectedLen = int(eventRaw.Args[2]) } else if scMeta.Name == "read" { expectedLen = int(ret) }
		rawStrArg := ""; if eventRaw.Ptr != 0 { bD := strArgBuf; if scMeta.Name == "stat" || scMeta.Name == "lstat" || scMeta.Name == "fstat" || scMeta.Name == "newfstatat" || scMeta.Name == "openat" || scMeta.Name == "faccessat" || scMeta.Name == "faccessat2" || scMeta.Name == "chmodat" || scMeta.Name == "mkdirat" || scMeta.Name == "chdir" || scMeta.Name == "rmdir" || scMeta.Name == "mkdir" || scMeta.Name == "unlink" || scMeta.Name == "chmod" || scMeta.Name == "chown" || scMeta.Name == "lchown" || scMeta.Name == "chroot" || scMeta.Name == "readlink" || scMeta.Name == "write" || scMeta.Name == "read" { bD = strArgBuf[:512] }; rawStrArg = decoder.DecodeString(tPid, eventRaw.Ptr, bD, pRet, scMeta.Name, expectedLen) }
		
		if ret >= 0 {
			if scMeta.Name == "open" || scMeta.Name == "openat" || scMeta.Name == "openat2" || scMeta.Name == "creat" { fdMap[fmt.Sprintf("%d:%d", targetPid, int32(ret))] = rawStrArg
			} else if scMeta.Name == "dup" || scMeta.Name == "dup2" || scMeta.Name == "dup3" { if p, ok := fdMap[fmt.Sprintf("%d:%d", targetPid, int32(eventRaw.Args[0]))]; ok { fdMap[fmt.Sprintf("%d:%d", targetPid, int32(ret))] = p } }
		}
		if scMeta.Name == "close" && ret == 0 { delete(fdMap, fmt.Sprintf("%d:%d", targetPid, int32(eventRaw.Args[0]))) }

		if scMeta.Name == "arch_prctl" && eventRaw.Args[0] == 0x1002 { continue }

		isFdSys := scMeta.Name == "open" || scMeta.Name == "openat" || scMeta.Name == "openat2" || scMeta.Name == "creat" || scMeta.Name == "dup" || scMeta.Name == "dup2" || scMeta.Name == "dup3" || scMeta.Name == "close" || scMeta.Name == "faccessat" || scMeta.Name == "faccessat2" || scMeta.Name == "chmodat" || scMeta.Name == "mkdirat" || scMeta.Name == "newfstatat"
		if len(opts.TraceSyscalls) > 0 && !opts.TraceSyscalls[scMeta.Name] && !isFdSys { continue }
		if !event.MatchPath(targetPid, fd, scMeta.Name, eventRaw.Ptr, rawStrArg, opts.TracePaths, fdMap) {
			if !((scMeta.Name == "read" && opts.TraceReadFDs[fd]) || (scMeta.Name == "write" && opts.TraceWriteFDs[fd])) { continue }
		}
		if len(opts.TraceSyscalls) > 0 && !opts.TraceSyscalls[scMeta.Name] && isFdSys { continue }

		ctx := &handler.Context{
			Pid:           int(eventRaw.Pid),
			Tid:           tPid,
			TargetPid:     targetPid,
			SysId:         eventRaw.SysId,
			SysName:       scMeta.Name,
			Args:          eventRaw.Args,
			Ret:           ret,
			ProbeRetEnter: eventRaw.ProbeRetEnter,
			ProbeRetExit:  eventRaw.ProbeRetExit,
			Ptr:           eventRaw.Ptr,
			StrArgBuf:     strArgBuf,
			RawStrArg:     rawStrArg,
			ScMeta:        scMeta,
			MemReader:     memReader,
			Decoder:       decoder,
			Opts:          opts,
			FdMap:         fdMap,
		}

		res := handler.Get(scMeta.Name).Handle(ctx)
		
		line := fmt.Sprintf("%s(%s)", scMeta.Name, strings.Join(res.ArgParts, ", "))
		var retStr string
		if ret < 0 && ret >= -4095 {
			retStr = fmt.Sprintf("-1 %s", format.Errno(-ret))
		} else {
			if scMeta.Name == "brk" || scMeta.Name == "mmap" || scMeta.Name == "mremap" || scMeta.Name == "shmat" {
				retStr = fmt.Sprintf("%#x", uint64(ret))
			} else {
				retStr = fmt.Sprintf("%d", ret)
				if scMeta.Name == "adjtimex" { retStr += " (TIME_OK)" }
			}
		}
		
		padLen := opts.AlignCol - len(line)
		if padLen < 1 { padLen = 1 }
		padding := strings.Repeat(" ", padLen)
		
		fmt.Fprintf(outWriter, "%s%s= %s\n", line, padding, retStr)
		if res.HexDumpStr != "" { fmt.Fprintf(outWriter, "%s", res.HexDumpStr) }
		outWriter.Flush()
	}
	outWriter.Flush(); fmt.Fprintf(outWriter, "+++ exited with 0 +++\n"); outWriter.Flush(); <-done
}
