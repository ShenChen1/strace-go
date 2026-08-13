package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// tracepointSpec declares one required tracepoint program attachment.
type tracepointSpec struct {
	program  *ebpf.Program
	category string
	name     string
}

// bpfAttacher owns the program attachment policy for the eBPF runtime.
// It keeps runtime loading separate from program-to-tracepoint wiring and
// makes that wiring declarative and unit-testable.
type bpfAttacher struct {
	objs *bpfObjects
}

func newBpfAttacher(objs *bpfObjects) *bpfAttacher {
	return &bpfAttacher{objs: objs}
}

// attachAll attaches every raw syscall, lifecycle and recvmsg kretprobe program.
func (a *bpfAttacher) attachAll() ([]link.Link, error) {
	if a == nil || a.objs == nil {
		return nil, fmt.Errorf("BPF objects are nil")
	}
	if err := a.populateProgArrays(); err != nil {
		return nil, fmt.Errorf("populate tail call prog arrays: %w", err)
	}
	links, err := a.attachTracepoints(rawSyscallTracepointSpecs(a.objs))
	if err != nil {
		return nil, errors.Join(err, closeTracepointLinks(links))
	}
	lifecycleLinks, err := a.attachTracepoints(lifecycleTracepointSpecs(a.objs))
	if err != nil {
		return nil, errors.Join(err, closeTracepointLinks(links), closeTracepointLinks(lifecycleLinks))
	}
	links = append(links, lifecycleLinks...)
	if kp, err := a.attachRecvmsgKretprobe(); err != nil {
		log.Printf("recvmsg kretprobe unavailable; nested OUT payloads may fall back to bounded tracepoint data: %v", err)
	} else if kp != nil {
		links = append(links, kp)
	}
	return links, nil
}

// rawSyscallTracepointSpecs lists the raw_syscalls programs that must attach.
//
// IMPACT: raw syscall programs are required; a failure to attach any of them
// aborts the session because syscall observation would be incomplete. Family
// handlers are not attached here; they live in enter_progs/exit_progs and are
// dispatched via bpf_tail_call (see populateProgArrays).
func rawSyscallTracepointSpecs(objs *bpfObjects) []tracepointSpec {
	return []tracepointSpec{
		{program: objs.TraceSysEnter, category: "raw_syscalls", name: "sys_enter"},
		{program: objs.TraceSysExit, category: "raw_syscalls", name: "sys_exit"},
	}
}

// Tail call prog array indices, kept in sync with bpf/enter_dispatch.h and
// bpf/exit_dispatch.h. The BPF source gate test enforces the mapping.
const (
	enterProgTerminating = 1
	enterProgExec        = 2
	enterProgPathStat    = 3
	enterProgPathOnly    = 4
	enterProgDualPath    = 5
	enterProgOpenat2     = 6
	enterProgReadlink    = 7
	enterProgMiscStruct  = 8
	enterProgSmallStruct = 9
	enterProgItimer      = 10
	enterProgTimeStruct  = 11
	enterProgSignal      = 12
	enterProgFileTime    = 13
	enterProgSleep       = 14
	enterProgFutex       = 15
	enterProgCachestat   = 16
	enterProgCapability  = 17
	enterProgMemfd       = 18
	enterProgPrctl       = 19
	enterProgClone3      = 20
	enterProgBpf         = 21
	enterProgIovec       = 22
	enterProgMsg         = 23
	enterProgMmsg        = 24
	enterProgFcntl       = 25
	enterProgIoctl       = 26
	enterProgNetwork     = 27
	enterProgKey         = 28
	enterProgXattr       = 29
	enterProgFs          = 30
	enterProgAio         = 31
	enterProgPoll        = 32
	enterProgSelect      = 33
	enterProgEpoll       = 34
	enterProgNoPayload   = 35
	enterProgPayload     = 36
	enterProgIovecBase   = 37
	enterProgSendmsgBase = 38
	enterProgMmsgB01     = 39
	enterProgMmsgB2      = 40
	enterProgMmsgB3      = 41
	enterProgAioIovec    = 42
	enterProgAioBuf      = 43
	enterProgQuota       = 44
	enterProgMountPath   = 45
)

const (
	exitProgGeneric        = 0
	exitProgIovecBase      = 1
	exitProgMsg            = 2
	exitProgMmsgFinal      = 3
	exitProgRecvmmsgBase01 = 4
	exitProgRecvmmsgBase23 = 5
	exitProgQuota          = 6
	exitProgMountQuery     = 7
	exitProgPath           = 8
)

const (
	recvmsgProgName    = 0
	recvmsgProgControl = 1
	recvmsgProgFinal   = 2
)

const (
	mmsgBytesProgBase0 = 0
	mmsgBytesProgBase1 = 1
	mmsgBytesProgBase2 = 2
	mmsgBytesProgBase3 = 3
)

type progArrayEntry struct {
	index uint32
	prog  *ebpf.Program
}

// progArrayWriter is the minimal map operation needed to populate a tail-call array.
type progArrayWriter interface {
	Put(key, value interface{}) error
}

func enterProgArrayEntries(objs *bpfObjects) []progArrayEntry {
	return []progArrayEntry{
		{enterProgTerminating, objs.EnterTerminating},
		{enterProgExec, objs.EnterExec},
		{enterProgPathStat, objs.EnterPathStat},
		{enterProgPathOnly, objs.EnterPathOnly},
		{enterProgDualPath, objs.EnterDualPath},
		{enterProgOpenat2, objs.EnterOpenat2},
		{enterProgReadlink, objs.EnterReadlink},
		{enterProgMiscStruct, objs.EnterMiscStruct},
		{enterProgSmallStruct, objs.EnterSmallStruct},
		{enterProgItimer, objs.EnterItimer},
		{enterProgTimeStruct, objs.EnterTimeStruct},
		{enterProgSignal, objs.EnterSignal},
		{enterProgFileTime, objs.EnterFileTime},
		{enterProgSleep, objs.EnterSleep},
		{enterProgFutex, objs.EnterFutex},
		{enterProgCachestat, objs.EnterCachestat},
		{enterProgCapability, objs.EnterCapability},
		{enterProgMemfd, objs.EnterMemfd},
		{enterProgPrctl, objs.EnterPrctl},
		{enterProgClone3, objs.EnterClone3},
		{enterProgBpf, objs.EnterBpf},
		{enterProgIovec, objs.EnterIovec},
		{enterProgMsg, objs.EnterMsg},
		{enterProgMmsg, objs.EnterMmsg},
		{enterProgFcntl, objs.EnterFcntl},
		{enterProgIoctl, objs.EnterIoctl},
		{enterProgNetwork, objs.EnterNetwork},
		{enterProgKey, objs.EnterKey},
		{enterProgXattr, objs.EnterXattr},
		{enterProgFs, objs.EnterFs},
		{enterProgAio, objs.EnterAio},
		{enterProgPoll, objs.EnterPoll},
		{enterProgSelect, objs.EnterSelect},
		{enterProgEpoll, objs.EnterEpoll},
		{enterProgNoPayload, objs.EnterNoPayloadDirect},
		{enterProgPayload, objs.EnterPayloadDirect},
		{enterProgIovecBase, objs.EnterIovecBase},
		{enterProgSendmsgBase, objs.EnterSendmsgBase},
		{enterProgMmsgB01, objs.EnterMmsgBase01},
		{enterProgMmsgB2, objs.EnterMmsgBase2},
		{enterProgMmsgB3, objs.EnterMmsgBase3},
		{enterProgAioIovec, objs.EnterAioIovec},
		{enterProgAioBuf, objs.EnterAioBuf},
		{enterProgQuota, objs.EnterQuota},
		{enterProgMountPath, objs.EnterMountPath},
	}
}

func exitProgArrayEntries(objs *bpfObjects) []progArrayEntry {
	return []progArrayEntry{
		{exitProgGeneric, objs.ExitGeneric},
		{exitProgIovecBase, objs.ExitIovecBase},
		{exitProgMsg, objs.ExitMsg},
		{exitProgMmsgFinal, objs.ExitMmsgFinal},
		{exitProgRecvmmsgBase01, objs.ExitRecvmmsgBase01},
		{exitProgRecvmmsgBase23, objs.ExitRecvmmsgBase23},
		{exitProgQuota, objs.ExitQuota},
		{exitProgMountQuery, objs.ExitMountQuery},
		{exitProgPath, objs.ExitPath},
	}
}

func recvmsgProgArrayEntries(objs *bpfObjects) []progArrayEntry {
	return []progArrayEntry{
		{recvmsgProgName, objs.TraceKretprobeRecvmsgName},
		{recvmsgProgControl, objs.TraceKretprobeRecvmsgControl},
		{recvmsgProgFinal, objs.TraceKretprobeRecvmsgFinal},
	}
}

func mmsgBytesProgArrayEntries(objs *bpfObjects) []progArrayEntry {
	return []progArrayEntry{
		{mmsgBytesProgBase0, objs.EnterMmsgBytes0},
		{mmsgBytesProgBase1, objs.EnterMmsgBytes1},
		{mmsgBytesProgBase2, objs.EnterMmsgBytes2},
		{mmsgBytesProgBase3, objs.EnterMmsgBytes3},
	}
}

// putProgArrayEntries validates and writes one complete tail-call array.
func putProgArrayEntries(name string, writer progArrayWriter, entries []progArrayEntry) error {
	for _, entry := range entries {
		if entry.prog == nil {
			return fmt.Errorf("%s[%d]: nil handler", name, entry.index)
		}
		if err := writer.Put(entry.index, entry.prog); err != nil {
			return fmt.Errorf("%s[%d]: %w", name, entry.index, err)
		}
	}
	return nil
}

// populateProgArrays fills the tail call prog arrays before any raw syscall
// tracepoint is attached; an empty slot would silently drop that family.
func (a *bpfAttacher) populateProgArrays() error {
	if err := putProgArrayEntries("enter_progs", a.objs.EnterProgs, enterProgArrayEntries(a.objs)); err != nil {
		return err
	}
	if err := putProgArrayEntries("mmsg_bytes_progs", a.objs.MmsgBytesProgs, mmsgBytesProgArrayEntries(a.objs)); err != nil {
		return err
	}
	if err := putProgArrayEntries("exit_progs", a.objs.ExitProgs, exitProgArrayEntries(a.objs)); err != nil {
		return err
	}
	return putProgArrayEntries("recvmsg_progs", a.objs.RecvmsgProgs, recvmsgProgArrayEntries(a.objs))
}

// lifecycleTracepointSpecs lists the sched lifecycle programs required by the
// event-sourced task state contract.
func lifecycleTracepointSpecs(objs *bpfObjects) []tracepointSpec {
	return []tracepointSpec{
		{program: objs.TraceSchedProcessFork, category: "sched", name: "sched_process_fork"},
		{program: objs.TraceSchedProcessExec, category: "sched", name: "sched_process_exec"},
		{program: objs.TraceSchedProcessExit, category: "sched", name: "sched_process_exit"},
		{program: objs.TraceSchedProcessFree, category: "sched", name: "sched_process_free"},
	}
}

// attachTracepoints attaches each required spec and aborts on the first
// failure so the session never runs with incomplete event facts.
func (a *bpfAttacher) attachTracepoints(specs []tracepointSpec) ([]link.Link, error) {
	var links []link.Link
	for _, spec := range specs {
		tp, err := link.Tracepoint(spec.category, spec.name, spec.program, nil)
		if err != nil {
			return links, fmt.Errorf("attach %s/%s tracepoint: %w", spec.category, spec.name, err)
		}
		links = append(links, tp)
	}
	return links, nil
}

// attachRecvmsgKretprobe attaches the single recvmsg return dispatcher.
func (a *bpfAttacher) attachRecvmsgKretprobe() (link.Link, error) {
	var lastErr error
	for _, symbol := range []string{"__sys_recvmsg", "__x64_sys_recvmsg"} {
		kp, err := link.Kretprobe(symbol, a.objs.TraceKretprobeRecvmsgDispatch, nil)
		if err == nil {
			return kp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		return nil, fmt.Errorf("no recvmsg kretprobe symbol available")
	}
	return nil, fmt.Errorf("recvmsg symbols: %w", lastErr)
}

func closeTracepointLinks(links []link.Link) error {
	var closeErr error
	for index, l := range links {
		if l != nil {
			if err := l.Close(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("close BPF link %d: %w", index, err))
			}
		}
	}
	return closeErr
}
