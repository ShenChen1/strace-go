package main

import "github.com/cilium/ebpf"

// bpfProgramProvider exposes only programs needed by attach and ProgArray setup.
type bpfProgramProvider interface {
	program(name string) *ebpf.Program
}

type bpfProgramCatalog struct {
	core     *bpfObjects
	handlers map[string]*ebpf.Program
}

func newBPFProgramCatalog(
	core *bpfObjects,
	handlers map[string]*ebpf.Program,
) *bpfProgramCatalog {
	return &bpfProgramCatalog{core: core, handlers: handlers}
}

func (c *bpfProgramCatalog) program(name string) *ebpf.Program {
	if c == nil {
		return nil
	}
	if coreProgram := coreBPFProgram(c.core, name); coreProgram != nil {
		return coreProgram
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
	if objects == nil {
		return nil
	}
	switch name {
	case "trace_sys_enter":
		return objects.TraceSysEnter
	case "trace_sys_exit":
		return objects.TraceSysExit
	case "trace_sched_process_fork":
		return objects.TraceSchedProcessFork
	case "trace_sched_process_exec":
		return objects.TraceSchedProcessExec
	case "trace_sched_process_exit":
		return objects.TraceSchedProcessExit
	case "trace_sched_process_free":
		return objects.TraceSchedProcessFree
	default:
		return nil
	}
}
