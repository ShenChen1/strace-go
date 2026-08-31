package main

import "github.com/cilium/ebpf"

// bpfProgramProvider exposes only programs needed by attach and ProgArray setup.
type bpfProgramProvider interface {
	program(name string) *ebpf.Program
}

const (
	bpfRawSyscallTracepointCategory = "raw_syscalls"
	bpfLifecycleTracepointCategory  = "sched"
	bpfSignalDeliverProgramName     = "trace_signal_deliver"
	bpfSignalGenerateProgramName    = "trace_signal_generate"
)

type bpfProgramAttachKind uint8

const (
	bpfProgramAttachTracepoint bpfProgramAttachKind = iota
	bpfProgramAttachRawTracepoint
)

// bpfCoreProgramSpec owns the generated core program name and its kernel hook.
type bpfCoreProgramSpec struct {
	name       string
	attachKind bpfProgramAttachKind
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
	{
		name:       bpfSignalDeliverProgramName,
		attachKind: bpfProgramAttachRawTracepoint,
		tracepoint: "signal_deliver",
		lookup:     func(objects *bpfObjects) *ebpf.Program { return objects.TraceSignalDeliver },
	},
	{
		name:       bpfSignalGenerateProgramName,
		attachKind: bpfProgramAttachRawTracepoint,
		tracepoint: "signal_generate",
		lookup:     func(objects *bpfObjects) *ebpf.Program { return objects.TraceSignalGenerate },
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

type bpfProgramArray uint8

const (
	bpfProgramArrayEnter bpfProgramArray = iota
	bpfProgramArrayExit
	bpfProgramArrayRecvmsg
	bpfProgramArrayMmsgBytes
)

type bpfProgramRef struct {
	array bpfProgramArray
	slot  uint32
}

// bpfTailCallProgramSpec is the generated Go-side description of a handler
// program exposed through a BPF ProgArray.
type bpfTailCallProgramSpec struct {
	slot         uint32
	name         string
	family       bpfHandlerFamily
	dependencies []bpfProgramRef
}

// bpfStandaloneProgramSpec describes a handler attached directly to a kernel
// hook instead of being entered through a BPF ProgArray.
type bpfStandaloneProgramSpec struct {
	name   string
	family bpfHandlerFamily
}

type bpfProgramRootSpec struct {
	programs         []string
	refs             []bpfProgramRef
	recvmsgKretprobe bool
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
