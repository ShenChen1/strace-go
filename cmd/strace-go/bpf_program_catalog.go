package main

import "github.com/cilium/ebpf"

// bpfProgramProvider exposes only programs needed by attach and ProgArray setup.
type bpfProgramProvider interface {
	program(name string) *ebpf.Program
}

const (
	bpfRawSyscallTracepointCategory = "raw_syscalls"
	bpfLifecycleTracepointCategory  = "sched"
)

// bpfCoreProgramSpec owns the generated core program name and its kernel hook.
type bpfCoreProgramSpec struct {
	name       string
	category   string
	tracepoint string
	lookup     func(*bpfObjects) *ebpf.Program
}

var bpfCoreProgramCatalog = []bpfCoreProgramSpec{
	{
		name:       "trace_sys_enter",
		category:   bpfRawSyscallTracepointCategory,
		tracepoint: "sys_enter",
		lookup:     func(objects *bpfObjects) *ebpf.Program { return objects.TraceSysEnter },
	},
	{
		name:       "trace_sys_exit",
		category:   bpfRawSyscallTracepointCategory,
		tracepoint: "sys_exit",
		lookup:     func(objects *bpfObjects) *ebpf.Program { return objects.TraceSysExit },
	},
	{
		name:       "trace_sched_process_fork",
		category:   bpfLifecycleTracepointCategory,
		tracepoint: "sched_process_fork",
		lookup:     func(objects *bpfObjects) *ebpf.Program { return objects.TraceSchedProcessFork },
	},
	{
		name:       "trace_sched_process_exec",
		category:   bpfLifecycleTracepointCategory,
		tracepoint: "sched_process_exec",
		lookup:     func(objects *bpfObjects) *ebpf.Program { return objects.TraceSchedProcessExec },
	},
	{
		name:       "trace_sched_process_exit",
		category:   bpfLifecycleTracepointCategory,
		tracepoint: "sched_process_exit",
		lookup:     func(objects *bpfObjects) *ebpf.Program { return objects.TraceSchedProcessExit },
	},
	{
		name:       "trace_sched_process_free",
		category:   bpfLifecycleTracepointCategory,
		tracepoint: "sched_process_free",
		lookup:     func(objects *bpfObjects) *ebpf.Program { return objects.TraceSchedProcessFree },
	},
}

func bpfCoreProgramSpecByName(name string) (bpfCoreProgramSpec, bool) {
	for _, program := range bpfCoreProgramCatalog {
		if program.name == name {
			return program, true
		}
	}
	return bpfCoreProgramSpec{}, false
}

// bpfTailCallProgramSpec is the single Go-side description of a handler
// program exposed through a BPF ProgArray.
type bpfTailCallProgramSpec struct {
	slot   uint32
	name   string
	family bpfHandlerFamily
}

// bpfStandaloneProgramSpec describes a handler attached directly to a kernel
// hook instead of being entered through a BPF ProgArray.
type bpfStandaloneProgramSpec struct {
	name   string
	family bpfHandlerFamily
}

var bpfEnterProgramCatalog = []bpfTailCallProgramSpec{
	{enterProgTerminating, "enter_terminating", bpfHandlerEnterGenericFamily},
	{enterProgExec, "enter_exec", bpfHandlerEnterPayloadFamily},
	{enterProgPathStat, "enter_path_stat", bpfHandlerEnterPathFamily},
	{enterProgPathOnly, "enter_path_only", bpfHandlerEnterPathFamily},
	{enterProgDualPath, "enter_dual_path", bpfHandlerEnterPathFamily},
	{enterProgOpenat2, "enter_openat2", bpfHandlerEnterPathFamily},
	{enterProgReadlink, "enter_readlink", bpfHandlerEnterPathFamily},
	{enterProgMiscStruct, "enter_misc_struct", bpfHandlerEnterStructuredFamily},
	{enterProgSmallStruct, "enter_small_struct", bpfHandlerEnterStructuredFamily},
	{enterProgItimer, "enter_itimer", bpfHandlerEnterStructuredFamily},
	{enterProgTimeStruct, "enter_time_struct", bpfHandlerEnterStructuredFamily},
	{enterProgSignal, "enter_signal", bpfHandlerEnterStructuredFamily},
	{enterProgFileTime, "enter_file_time", bpfHandlerEnterStructuredFamily},
	{enterProgSleep, "enter_sleep", bpfHandlerEnterStructuredFamily},
	{enterProgFutex, "enter_futex", bpfHandlerEnterStructuredFamily},
	{enterProgCachestat, "enter_cachestat", bpfHandlerEnterStructuredFamily},
	{enterProgCapability, "enter_capability", bpfHandlerEnterStructuredFamily},
	{enterProgMemfd, "enter_memfd", bpfHandlerEnterStructuredFamily},
	{enterProgPrctl, "enter_prctl", bpfHandlerEnterStructuredFamily},
	{enterProgClone3, "enter_clone3", bpfHandlerEnterStructuredFamily},
	{enterProgBpf, "enter_bpf", bpfHandlerEnterStructuredFamily},
	{enterProgIovec, "enter_iovec", bpfHandlerEnterMemoryFamily},
	{enterProgMsg, "enter_msg", bpfHandlerEnterMemoryFamily},
	{enterProgMmsg, "enter_mmsg", bpfHandlerEnterMemoryFamily},
	{enterProgFcntl, "enter_fcntl", bpfHandlerEnterControlFamily},
	{enterProgIoctl, "enter_ioctl", bpfHandlerEnterControlFamily},
	{enterProgNetwork, "enter_network", bpfHandlerEnterControlFamily},
	{enterProgKey, "enter_key", bpfHandlerEnterControlFamily},
	{enterProgXattr, "enter_xattr", bpfHandlerEnterControlFamily},
	{enterProgFs, "enter_fs", bpfHandlerEnterControlFamily},
	{enterProgAio, "enter_aio", bpfHandlerEnterMemoryFamily},
	{enterProgPoll, "enter_poll", bpfHandlerEnterControlFamily},
	{enterProgSelect, "enter_select", bpfHandlerEnterControlFamily},
	{enterProgEpoll, "enter_epoll", bpfHandlerEnterControlFamily},
	{enterProgNoPayload, "enter_no_payload_direct", bpfHandlerEnterPathFamily},
	{enterProgPayload, "enter_payload_direct", bpfHandlerEnterPayloadFamily},
	{enterProgNoPayloadGeneric, "enter_no_payload_generic", bpfHandlerEnterGenericFamily},
	{enterProgIovecBase, "enter_iovec_base", bpfHandlerEnterMemoryFamily},
	{enterProgSendmsgBase, "enter_sendmsg_base", bpfHandlerEnterMemoryFamily},
	{enterProgMmsgB01, "enter_mmsg_base01", bpfHandlerEnterMemoryFamily},
	{enterProgMmsgB2, "enter_mmsg_base2", bpfHandlerEnterMemoryFamily},
	{enterProgMmsgB3, "enter_mmsg_base3", bpfHandlerEnterMemoryFamily},
	{enterProgAioIovec, "enter_aio_iovec", bpfHandlerEnterMemoryFamily},
	{enterProgAioBuf, "enter_aio_buf", bpfHandlerEnterMemoryFamily},
	{enterProgQuota, "enter_quota", bpfHandlerEnterStructuredFamily},
	{enterProgMountPath, "enter_mount_path", bpfHandlerEnterPathFamily},
	{enterProgNestedFDPath0, "enter_nested_fd_path0", bpfHandlerEnterControlFamily},
	{enterProgNestedFDPath1, "enter_nested_fd_path1", bpfHandlerEnterControlFamily},
	{enterProgNestedFDPath2, "enter_nested_fd_path2", bpfHandlerEnterControlFamily},
	{enterProgNestedFDPath3, "enter_nested_fd_path3", bpfHandlerEnterControlFamily},
}

var bpfExitProgramCatalog = []bpfTailCallProgramSpec{
	{exitProgGeneric, "exit_generic", bpfHandlerExitFamily},
	{exitProgIovecBase, "exit_iovec_base", bpfHandlerExitFamily},
	{exitProgMsg, "exit_msg", bpfHandlerExitFamily},
	{exitProgMmsgFinal, "exit_mmsg_final", bpfHandlerExitFamily},
	{exitProgRecvmmsgBase01, "exit_recvmmsg_base01", bpfHandlerExitFamily},
	{exitProgRecvmmsgBase23, "exit_recvmmsg_base23", bpfHandlerExitFamily},
	{exitProgQuota, "exit_quota", bpfHandlerExitFamily},
	{exitProgMountQuery, "exit_mount_query", bpfHandlerExitFamily},
	{exitProgPath, "exit_path", bpfHandlerExitFamily},
	{exitProgFDTime, "exit_fd_time", bpfHandlerExitFamily},
	{exitProgStruct, "exit_struct", bpfHandlerExitFamily},
	{exitProgAsync, "exit_async", bpfHandlerExitFamily},
	{exitProgIO, "exit_io", bpfHandlerExitFamily},
	{exitProgControl, "exit_control", bpfHandlerExitFamily},
	{exitProgNestedFDPath0, "exit_nested_fd_path0", bpfHandlerExitFamily},
	{exitProgNestedFDPath1, "exit_nested_fd_path1", bpfHandlerExitFamily},
	{exitProgNestedFDPath2, "exit_nested_fd_path2", bpfHandlerExitFamily},
	{exitProgNestedFDPath3, "exit_nested_fd_path3", bpfHandlerExitFamily},
}

var bpfRecvmsgProgramCatalog = []bpfTailCallProgramSpec{
	{recvmsgProgName, "trace_kretprobe_recvmsg_name", bpfHandlerRecvmsgFamily},
	{recvmsgProgControl, "trace_kretprobe_recvmsg_control", bpfHandlerRecvmsgFamily},
	{recvmsgProgFinal, "trace_kretprobe_recvmsg_final", bpfHandlerRecvmsgFamily},
}

var bpfMmsgByteProgramCatalog = []bpfTailCallProgramSpec{
	{mmsgBytesProgBase0, "enter_mmsg_bytes0", bpfHandlerEnterMemoryFamily},
	{mmsgBytesProgBase1, "enter_mmsg_bytes1", bpfHandlerEnterMemoryFamily},
	{mmsgBytesProgBase2, "enter_mmsg_bytes2", bpfHandlerEnterMemoryFamily},
	{mmsgBytesProgBase3, "enter_mmsg_bytes3", bpfHandlerEnterMemoryFamily},
}

const bpfRecvmsgDispatchProgramName = "trace_kretprobe_recvmsg_dispatch"

var bpfStandaloneProgramCatalog = []bpfStandaloneProgramSpec{
	{bpfRecvmsgDispatchProgramName, bpfHandlerRecvmsgFamily},
}

func bpfTailCallProgramBySlot(
	catalog []bpfTailCallProgramSpec,
	slot uint32,
) (bpfTailCallProgramSpec, bool) {
	for _, program := range catalog {
		if program.slot == slot {
			return program, true
		}
	}
	return bpfTailCallProgramSpec{}, false
}

func bpfTailCallProgramEntries(
	provider bpfProgramProvider,
	catalog []bpfTailCallProgramSpec,
) []progArrayEntry {
	entries := make([]progArrayEntry, 0, len(catalog))
	for _, program := range catalog {
		entries = append(entries, progArrayEntry{
			index: program.slot,
			prog:  bpfProgram(provider, program.name),
		})
	}
	return entries
}

func buildBPFHandlerProgramFamilies() map[string]bpfHandlerFamily {
	families := make(map[string]bpfHandlerFamily)
	for _, catalog := range [][]bpfTailCallProgramSpec{
		bpfEnterProgramCatalog,
		bpfExitProgramCatalog,
		bpfRecvmsgProgramCatalog,
		bpfMmsgByteProgramCatalog,
	} {
		for _, program := range catalog {
			families[program.name] = program.family
		}
	}
	for _, program := range bpfStandaloneProgramCatalog {
		families[program.name] = program.family
	}
	return families
}

type bpfProgramCatalog struct {
	core     bpfProgramProvider
	handlers map[string]*ebpf.Program
}

func newBPFProgramCatalog(
	core bpfProgramProvider,
	handlers map[string]*ebpf.Program,
) *bpfProgramCatalog {
	return &bpfProgramCatalog{core: core, handlers: handlers}
}

func (c *bpfProgramCatalog) program(name string) *ebpf.Program {
	if c == nil {
		return nil
	}
	if c.core != nil {
		if coreProgram := c.core.program(name); coreProgram != nil {
			return coreProgram
		}
	}
	return c.handlers[name]
}

func (o *bpfObjects) program(name string) *ebpf.Program {
	if o == nil {
		return nil
	}
	return coreBPFProgram(o, name)
}

func coreBPFProgram(objects *bpfObjects, name string) *ebpf.Program {
	program, ok := bpfCoreProgramSpecByName(name)
	if !ok || objects == nil || program.lookup == nil {
		return nil
	}
	return program.lookup(objects)
}
