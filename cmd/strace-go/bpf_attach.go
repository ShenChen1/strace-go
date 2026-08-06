package main

import (
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
	var links []link.Link
	links = a.attachTracepoints(rawSyscallTracepointSpecs(a.objs))
	links = append(links, a.attachTracepoints(lifecycleTracepointSpecs(a.objs))...)
	if kp := a.attachRecvmsgNameKretprobe(); kp != nil {
		links = append(links, kp)
	}
	if kp := a.attachRecvmsgControlKretprobe(); kp != nil {
		links = append(links, kp)
	}
	return links
}

// rawSyscallTracepointSpecs lists the raw_syscalls programs that must attach.
//
// IMPACT: raw syscall programs are required; a failure to attach any of them
// aborts the session because syscall observation would be incomplete.
func rawSyscallTracepointSpecs(objs *bpfObjects) []tracepointSpec {
	return []tracepointSpec{
		{program: objs.TraceSysEnter, category: "raw_syscalls", name: "sys_enter"},
		{program: objs.TraceSysEnterBpf, category: "raw_syscalls", name: "sys_enter", label: "bpf"},
		{program: objs.TraceSysEnterAio, category: "raw_syscalls", name: "sys_enter", label: "aio"},
		{program: objs.TraceSysEnterAioIovec, category: "raw_syscalls", name: "sys_enter", label: "aio iovec"},
		{program: objs.TraceSysEnterAioBuf, category: "raw_syscalls", name: "sys_enter", label: "aio buf"},
		{program: objs.TraceSysEnterIovecBase, category: "raw_syscalls", name: "sys_enter", label: "iovec base"},
		{program: objs.TraceSysEnterMsg, category: "raw_syscalls", name: "sys_enter", label: "msg"},
		{program: objs.TraceSysEnterSendmsgBase, category: "raw_syscalls", name: "sys_enter", label: "sendmsg base"},
		{program: objs.TraceSysEnterMmsg, category: "raw_syscalls", name: "sys_enter", label: "mmsg"},
		{program: objs.TraceSysEnterSendmmsgBase0, category: "raw_syscalls", name: "sys_enter", label: "sendmmsg base0"},
		{program: objs.TraceSysEnterSendmmsgBase1, category: "raw_syscalls", name: "sys_enter", label: "sendmmsg base1"},
		{program: objs.TraceSysExit, category: "raw_syscalls", name: "sys_exit"},
		{program: objs.TraceSysExitIovecBase, category: "raw_syscalls", name: "sys_exit", label: "iovec base"},
		{program: objs.TraceSysExitRecvmmsgBase0, category: "raw_syscalls", name: "sys_exit", label: "recvmmsg base0"},
		{program: objs.TraceSysExitRecvmmsgBase1, category: "raw_syscalls", name: "sys_exit", label: "recvmmsg base1"},
		{program: objs.TraceSysExitMsg, category: "raw_syscalls", name: "sys_exit", label: "msg"},
		{program: objs.TraceSysExitMmsg, category: "raw_syscalls", name: "sys_exit", label: "mmsg"},
	}
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

// attachRecvmsgNameKretprobe attaches the msg_name sockaddr capture fragment.
func (a *bpfAttacher) attachRecvmsgNameKretprobe() link.Link {
	for _, symbol := range []string{"__sys_recvmsg", "__x64_sys_recvmsg"} {
		kp, err := link.Kretprobe(symbol, a.objs.TraceKretprobeRecvmsgName, nil)
		if err == nil {
			return kp
		}
	}
	log.Printf("recvmsg msg_name kretprobe unavailable; msg_name sockaddr payloads may fall back to pointers")
	return nil
}

// attachRecvmsgControlKretprobe attaches the msg_control ancillary capture fragment.
func (a *bpfAttacher) attachRecvmsgControlKretprobe() link.Link {
	for _, symbol := range []string{"__sys_recvmsg", "__x64_sys_recvmsg"} {
		kp, err := link.Kretprobe(symbol, a.objs.TraceKretprobeRecvmsgControl, nil)
		if err == nil {
			return kp
		}
	}
	log.Printf("recvmsg msg_control kretprobe unavailable; ancillary payloads may fall back to pointers")
	return nil
}
