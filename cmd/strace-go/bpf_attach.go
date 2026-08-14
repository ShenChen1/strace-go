package main

import (
	"errors"
	"fmt"
	"io"
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
	objs     *bpfObjects
	programs bpfProgramProvider
}

func newBpfAttacher(objs *bpfObjects) *bpfAttacher {
	return newBpfAttacherWithPrograms(objs, objs)
}

func newBpfAttacherWithPrograms(
	objs *bpfObjects,
	programs bpfProgramProvider,
) *bpfAttacher {
	return &bpfAttacher{objs: objs, programs: programs}
}

// attachAll attaches every raw syscall, lifecycle and recvmsg kretprobe program.
func (a *bpfAttacher) attachAll() ([]link.Link, error) {
	if a == nil || a.objs == nil {
		return nil, fmt.Errorf("BPF objects are nil")
	}
	if err := a.populateProgArrays(); err != nil {
		return nil, fmt.Errorf("populate tail call prog arrays: %w", err)
	}
	links, err := a.attachRequired()
	if err != nil {
		return nil, errors.Join(err, closeTracepointLinks(links))
	}
	if kp, err := a.attachOptionalRecvmsg(); err != nil {
		log.Printf("recvmsg kretprobe unavailable; nested OUT payloads may fall back to bounded tracepoint data: %v", err)
	} else if kp != nil {
		links = append(links, kp)
	}
	return links, nil
}

// attachRequired owns only the raw syscall and lifecycle links. Partial links
// are returned so the caller can roll them back when a later attach fails.
func (a *bpfAttacher) attachRequired() ([]link.Link, error) {
	if a == nil || a.objs == nil {
		return nil, fmt.Errorf("BPF objects are nil")
	}
	links, err := a.attachTracepoints(rawSyscallTracepointSpecs(a.objs))
	if err != nil {
		return links, err
	}
	lifecycleLinks, err := a.attachTracepoints(lifecycleTracepointSpecs(a.objs))
	if err != nil {
		return append(links, lifecycleLinks...), err
	}
	return append(links, lifecycleLinks...), nil
}

func (a *bpfAttacher) attachOptionalRecvmsg() (link.Link, error) {
	return a.attachOptionalRecvmsgFor(true)
}

func (a *bpfAttacher) attachOptionalRecvmsgFor(enabled bool) (link.Link, error) {
	if a == nil || a.objs == nil {
		return nil, fmt.Errorf("BPF objects are nil")
	}
	if !enabled {
		return nil, nil
	}
	return a.attachRecvmsgKretprobe()
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
	enterProgTerminating      = 1
	enterProgExec             = 2
	enterProgPathStat         = 3
	enterProgPathOnly         = 4
	enterProgDualPath         = 5
	enterProgOpenat2          = 6
	enterProgReadlink         = 7
	enterProgMiscStruct       = 8
	enterProgSmallStruct      = 9
	enterProgItimer           = 10
	enterProgTimeStruct       = 11
	enterProgSignal           = 12
	enterProgFileTime         = 13
	enterProgSleep            = 14
	enterProgFutex            = 15
	enterProgCachestat        = 16
	enterProgCapability       = 17
	enterProgMemfd            = 18
	enterProgPrctl            = 19
	enterProgClone3           = 20
	enterProgBpf              = 21
	enterProgIovec            = 22
	enterProgMsg              = 23
	enterProgMmsg             = 24
	enterProgFcntl            = 25
	enterProgIoctl            = 26
	enterProgNetwork          = 27
	enterProgKey              = 28
	enterProgXattr            = 29
	enterProgFs               = 30
	enterProgAio              = 31
	enterProgPoll             = 32
	enterProgSelect           = 33
	enterProgEpoll            = 34
	enterProgNoPayload        = 35
	enterProgPayload          = 36
	enterProgIovecBase        = 37
	enterProgSendmsgBase      = 38
	enterProgMmsgB01          = 39
	enterProgMmsgB2           = 40
	enterProgMmsgB3           = 41
	enterProgAioIovec         = 42
	enterProgAioBuf           = 43
	enterProgQuota            = 44
	enterProgMountPath        = 45
	enterProgNoPayloadGeneric = 46
	enterProgSelectFDPath0    = 47
	enterProgSelectFDPath1    = 48
	enterProgSelectFDPath2    = 49
	enterProgSelectFDPath3    = 50
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
	exitProgFDTime         = 9
	exitProgStruct         = 10
	exitProgAsync          = 11
	exitProgIO             = 12
	exitProgControl        = 13
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

func enterProgArrayEntries(programs bpfProgramProvider) []progArrayEntry {
	return []progArrayEntry{
		{enterProgTerminating, bpfProgram(programs, "enter_terminating")},
		{enterProgExec, bpfProgram(programs, "enter_exec")},
		{enterProgPathStat, bpfProgram(programs, "enter_path_stat")},
		{enterProgPathOnly, bpfProgram(programs, "enter_path_only")},
		{enterProgDualPath, bpfProgram(programs, "enter_dual_path")},
		{enterProgOpenat2, bpfProgram(programs, "enter_openat2")},
		{enterProgReadlink, bpfProgram(programs, "enter_readlink")},
		{enterProgMiscStruct, bpfProgram(programs, "enter_misc_struct")},
		{enterProgSmallStruct, bpfProgram(programs, "enter_small_struct")},
		{enterProgItimer, bpfProgram(programs, "enter_itimer")},
		{enterProgTimeStruct, bpfProgram(programs, "enter_time_struct")},
		{enterProgSignal, bpfProgram(programs, "enter_signal")},
		{enterProgFileTime, bpfProgram(programs, "enter_file_time")},
		{enterProgSleep, bpfProgram(programs, "enter_sleep")},
		{enterProgFutex, bpfProgram(programs, "enter_futex")},
		{enterProgCachestat, bpfProgram(programs, "enter_cachestat")},
		{enterProgCapability, bpfProgram(programs, "enter_capability")},
		{enterProgMemfd, bpfProgram(programs, "enter_memfd")},
		{enterProgPrctl, bpfProgram(programs, "enter_prctl")},
		{enterProgClone3, bpfProgram(programs, "enter_clone3")},
		{enterProgBpf, bpfProgram(programs, "enter_bpf")},
		{enterProgIovec, bpfProgram(programs, "enter_iovec")},
		{enterProgMsg, bpfProgram(programs, "enter_msg")},
		{enterProgMmsg, bpfProgram(programs, "enter_mmsg")},
		{enterProgFcntl, bpfProgram(programs, "enter_fcntl")},
		{enterProgIoctl, bpfProgram(programs, "enter_ioctl")},
		{enterProgNetwork, bpfProgram(programs, "enter_network")},
		{enterProgKey, bpfProgram(programs, "enter_key")},
		{enterProgXattr, bpfProgram(programs, "enter_xattr")},
		{enterProgFs, bpfProgram(programs, "enter_fs")},
		{enterProgAio, bpfProgram(programs, "enter_aio")},
		{enterProgPoll, bpfProgram(programs, "enter_poll")},
		{enterProgSelect, bpfProgram(programs, "enter_select")},
		{enterProgEpoll, bpfProgram(programs, "enter_epoll")},
		{enterProgNoPayload, bpfProgram(programs, "enter_no_payload_direct")},
		{enterProgPayload, bpfProgram(programs, "enter_payload_direct")},
		{enterProgIovecBase, bpfProgram(programs, "enter_iovec_base")},
		{enterProgSendmsgBase, bpfProgram(programs, "enter_sendmsg_base")},
		{enterProgMmsgB01, bpfProgram(programs, "enter_mmsg_base01")},
		{enterProgMmsgB2, bpfProgram(programs, "enter_mmsg_base2")},
		{enterProgMmsgB3, bpfProgram(programs, "enter_mmsg_base3")},
		{enterProgAioIovec, bpfProgram(programs, "enter_aio_iovec")},
		{enterProgAioBuf, bpfProgram(programs, "enter_aio_buf")},
		{enterProgQuota, bpfProgram(programs, "enter_quota")},
		{enterProgMountPath, bpfProgram(programs, "enter_mount_path")},
		{enterProgNoPayloadGeneric, bpfProgram(programs, "enter_no_payload_generic")},
		{enterProgSelectFDPath0, bpfProgram(programs, "enter_select_fd_path0")},
		{enterProgSelectFDPath1, bpfProgram(programs, "enter_select_fd_path1")},
		{enterProgSelectFDPath2, bpfProgram(programs, "enter_select_fd_path2")},
		{enterProgSelectFDPath3, bpfProgram(programs, "enter_select_fd_path3")},
	}
}

func exitProgArrayEntries(programs bpfProgramProvider) []progArrayEntry {
	return []progArrayEntry{
		{exitProgGeneric, bpfProgram(programs, "exit_generic")},
		{exitProgIovecBase, bpfProgram(programs, "exit_iovec_base")},
		{exitProgMsg, bpfProgram(programs, "exit_msg")},
		{exitProgMmsgFinal, bpfProgram(programs, "exit_mmsg_final")},
		{exitProgRecvmmsgBase01, bpfProgram(programs, "exit_recvmmsg_base01")},
		{exitProgRecvmmsgBase23, bpfProgram(programs, "exit_recvmmsg_base23")},
		{exitProgQuota, bpfProgram(programs, "exit_quota")},
		{exitProgMountQuery, bpfProgram(programs, "exit_mount_query")},
		{exitProgPath, bpfProgram(programs, "exit_path")},
		{exitProgFDTime, bpfProgram(programs, "exit_fd_time")},
		{exitProgStruct, bpfProgram(programs, "exit_struct")},
		{exitProgAsync, bpfProgram(programs, "exit_async")},
		{exitProgIO, bpfProgram(programs, "exit_io")},
		{exitProgControl, bpfProgram(programs, "exit_control")},
	}
}

func recvmsgProgArrayEntries(programs bpfProgramProvider) []progArrayEntry {
	return []progArrayEntry{
		{recvmsgProgName, bpfProgram(programs, "trace_kretprobe_recvmsg_name")},
		{recvmsgProgControl, bpfProgram(programs, "trace_kretprobe_recvmsg_control")},
		{recvmsgProgFinal, bpfProgram(programs, "trace_kretprobe_recvmsg_final")},
	}
}

func mmsgBytesProgArrayEntries(programs bpfProgramProvider) []progArrayEntry {
	return []progArrayEntry{
		{mmsgBytesProgBase0, bpfProgram(programs, "enter_mmsg_bytes0")},
		{mmsgBytesProgBase1, bpfProgram(programs, "enter_mmsg_bytes1")},
		{mmsgBytesProgBase2, bpfProgram(programs, "enter_mmsg_bytes2")},
		{mmsgBytesProgBase3, bpfProgram(programs, "enter_mmsg_bytes3")},
	}
}

func bpfProgram(provider bpfProgramProvider, name string) *ebpf.Program {
	if provider == nil {
		return nil
	}
	return provider.program(name)
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
	return a.populateProgArraysFor(bpfProgramSelection{loadAll: true})
}

func (a *bpfAttacher) populateProgArraysFor(selection bpfProgramSelection) error {
	enterEntries := selectedProgArrayEntries(
		enterProgArrayEntries(a.programs),
		selection.enterSlots,
		selection.loadAll,
	)
	if err := putProgArrayEntries("enter_progs", a.objs.EnterProgs, enterEntries); err != nil {
		return err
	}
	mmsgByteEntries := selectedProgArrayEntries(
		mmsgBytesProgArrayEntries(a.programs),
		selection.mmsgByteSlots,
		selection.loadAll,
	)
	if err := putProgArrayEntries("mmsg_bytes_progs", a.objs.MmsgBytesProgs, mmsgByteEntries); err != nil {
		return err
	}
	exitEntries := selectedProgArrayEntries(
		exitProgArrayEntries(a.programs),
		selection.exitSlots,
		selection.loadAll,
	)
	if err := putProgArrayEntries("exit_progs", a.objs.ExitProgs, exitEntries); err != nil {
		return err
	}
	recvmsgEntries := selectedProgArrayEntries(
		recvmsgProgArrayEntries(a.programs),
		selection.recvmsgSlots,
		selection.loadAll,
	)
	return putProgArrayEntries("recvmsg_progs", a.objs.RecvmsgProgs, recvmsgEntries)
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
	program := bpfProgram(a.programs, "trace_kretprobe_recvmsg_dispatch")
	if program == nil {
		return nil, fmt.Errorf("recvmsg kretprobe program is unavailable")
	}
	var lastErr error
	for _, symbol := range []string{"__sys_recvmsg", "__x64_sys_recvmsg"} {
		kp, err := link.Kretprobe(symbol, program, nil)
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
	return closeTracepointLinksWithDiagnostics(links, nil, nil)
}

func closeTracepointLinksWithDiagnostics(
	links []link.Link,
	clock traceClock,
	observer traceCleanupObserver,
) error {
	var closeErr error
	for index, l := range links {
		if l != nil {
			startNS := cleanupClockNowNS(clock)
			if err := l.Close(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("close BPF link %d: %w", index, err))
			}
			recordBPFResourceTiming(observer, fmt.Sprintf("bpf_link_%d", index), startNS, cleanupClockNowNS(clock))
		}
	}
	return closeErr
}

func closeTracepointLinksParallelWithDiagnostics(
	links []link.Link,
	clock traceClock,
	observer traceCleanupObserver,
) error {
	resources := make([]traceBPFResource, 0, len(links))
	for index, current := range links {
		if current == nil {
			continue
		}
		resources = append(resources, traceBPFResource{
			Name:   fmt.Sprintf("bpf_link_%d", index),
			Closer: tracepointLinkCloser{index: index, closer: current},
		})
	}
	return closeNamedBPFResourcesParallel(resources, clock, observer)
}

type tracepointLinkCloser struct {
	index  int
	closer io.Closer
}

func (c tracepointLinkCloser) Close() error {
	if c.closer == nil {
		return nil
	}
	if err := c.closer.Close(); err != nil {
		return fmt.Errorf("close BPF link %d: %w", c.index, err)
	}
	return nil
}
