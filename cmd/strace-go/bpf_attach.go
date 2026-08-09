package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// tracepointSpec declares one tracepoint program attachment.
//
// optional marks lifecycle tracepoints that older kernels may not expose;
// the attacher skips them instead of failing the whole session.
type tracepointSpec struct {
	program  *ebpf.Program
	category string
	name     string
	label    string
	optional bool
}

// bpfAttacher owns the program attachment policy for the eBPF runtime.
// It keeps session.go focused on session orchestration and makes the
// program-to-tracepoint wiring declarative and unit-testable.
type bpfAttacher struct {
	objs *bpfObjects
}

func newBpfAttacher(objs *bpfObjects) *bpfAttacher {
	return &bpfAttacher{objs: objs}
}

// attachAll attaches every raw syscall, lifecycle and recvmsg kretprobe program.
func (a *bpfAttacher) attachAll() []link.Link {
	if err := a.populateProgArrays(); err != nil {
		log.Fatalf("failed to populate tail call prog arrays: %v", err)
	}
	var links []link.Link
	links = a.attachTracepoints(rawSyscallTracepointSpecs(a.objs))
	links = append(links, a.attachTracepoints(lifecycleTracepointSpecs(a.objs))...)
	if kp := a.attachRecvmsgKretprobe(); kp != nil {
		links = append(links, kp)
	}
	return links
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
	enterProgSendmmsgB0  = 39
	enterProgSendmmsgB1  = 40
	enterProgAioIovec    = 41
	enterProgAioBuf      = 42
	enterProgQuota       = 43
)

const (
	exitProgGeneric       = 0
	exitProgIovecBase     = 1
	exitProgMsg           = 2
	exitProgMmsgFinal     = 3
	exitProgRecvmmsgBase0 = 4
	exitProgRecvmmsgBase1 = 5
	exitProgQuota         = 6
	exitProgMountQuery    = 7
)

const (
	recvmsgProgName    = 0
	recvmsgProgControl = 1
	recvmsgProgFinal   = 2
)

type progArrayEntry struct {
	index uint32
	prog  *ebpf.Program
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
		{enterProgSendmmsgB0, objs.EnterSendmmsgBase0},
		{enterProgSendmmsgB1, objs.EnterSendmmsgBase1},
		{enterProgAioIovec, objs.EnterAioIovec},
		{enterProgAioBuf, objs.EnterAioBuf},
		{enterProgQuota, objs.EnterQuota},
	}
}

func exitProgArrayEntries(objs *bpfObjects) []progArrayEntry {
	return []progArrayEntry{
		{exitProgGeneric, objs.ExitGeneric},
		{exitProgIovecBase, objs.ExitIovecBase},
		{exitProgMsg, objs.ExitMsg},
		{exitProgMmsgFinal, objs.ExitMmsgFinal},
		{exitProgRecvmmsgBase0, objs.ExitRecvmmsgBase0},
		{exitProgRecvmmsgBase1, objs.ExitRecvmmsgBase1},
		{exitProgQuota, objs.ExitQuota},
		{exitProgMountQuery, objs.ExitMountQuery},
	}
}

func recvmsgProgArrayEntries(objs *bpfObjects) []progArrayEntry {
	return []progArrayEntry{
		{recvmsgProgName, objs.TraceKretprobeRecvmsgName},
		{recvmsgProgControl, objs.TraceKretprobeRecvmsgControl},
		{recvmsgProgFinal, objs.TraceKretprobeRecvmsgFinal},
	}
}

// populateProgArrays fills the tail call prog arrays before any raw syscall
// tracepoint is attached; an empty slot would silently drop that family.
func (a *bpfAttacher) populateProgArrays() error {
	for _, entry := range enterProgArrayEntries(a.objs) {
		if entry.prog == nil {
			return fmt.Errorf("nil enter handler for prog array index %d", entry.index)
		}
		if err := a.objs.EnterProgs.Put(entry.index, entry.prog); err != nil {
			return fmt.Errorf("enter_progs[%d]: %w", entry.index, err)
		}
	}
	for _, entry := range exitProgArrayEntries(a.objs) {
		if entry.prog == nil {
			return fmt.Errorf("nil exit handler for prog array index %d", entry.index)
		}
		if err := a.objs.ExitProgs.Put(entry.index, entry.prog); err != nil {
			return fmt.Errorf("exit_progs[%d]: %w", entry.index, err)
		}
	}
	for _, entry := range recvmsgProgArrayEntries(a.objs) {
		if entry.prog == nil {
			return fmt.Errorf("nil recvmsg handler for prog array index %d", entry.index)
		}
		if err := a.objs.RecvmsgProgs.Put(entry.index, entry.prog); err != nil {
			return fmt.Errorf("recvmsg_progs[%d]: %w", entry.index, err)
		}
	}
	return nil
}

// lifecycleTracepointSpecs lists the sched lifecycle programs.
//
// IMPACT: lifecycle tracepoints are best-effort; when unavailable the session
// keeps running and lifecycle state degrades to syscall-driven cleanup only.
func lifecycleTracepointSpecs(objs *bpfObjects) []tracepointSpec {
	return []tracepointSpec{
		{program: objs.TraceSchedProcessFork, category: "sched", name: "sched_process_fork", optional: true},
		{program: objs.TraceSchedProcessExec, category: "sched", name: "sched_process_exec", optional: true},
		{program: objs.TraceSchedProcessExit, category: "sched", name: "sched_process_exit", optional: true},
		{program: objs.TraceSchedProcessFree, category: "sched", name: "sched_process_free", optional: true},
	}
}

// attachTracepoints attaches each spec, skipping optional failures and aborting
// on required failures so the session never runs with missing raw syscall data.
func (a *bpfAttacher) attachTracepoints(specs []tracepointSpec) []link.Link {
	var links []link.Link
	for _, spec := range specs {
		tp, err := link.Tracepoint(spec.category, spec.name, spec.program, nil)
		if err != nil {
			if spec.optional {
				continue
			}
			label := ""
			if spec.label != "" {
				label = spec.label + " "
			}
			log.Fatalf("failed to attach %s%s tracepoint: %v", label, spec.name, err)
		}
		links = append(links, tp)
	}
	return links
}

// attachRecvmsgKretprobe attaches the single recvmsg return dispatcher.
func (a *bpfAttacher) attachRecvmsgKretprobe() link.Link {
	for _, symbol := range []string{"__sys_recvmsg", "__x64_sys_recvmsg"} {
		kp, err := link.Kretprobe(symbol, a.objs.TraceKretprobeRecvmsgDispatch, nil)
		if err == nil {
			return kp
		}
	}
	log.Printf("recvmsg kretprobe unavailable; nested OUT payloads may fall back to bounded tracepoint data")
	return nil
}
