package main

import "github.com/cilium/ebpf"

// bpfMapProvider exposes named core maps without leaking generated bindings.
type bpfMapProvider interface {
	coreMap(name string) *ebpf.Map
}

const (
	bpfMapArmFork            = "arm_fork_map"
	bpfMapAttachExited       = "attach_exited_map"
	bpfMapAttachRoots        = "attach_roots_map"
	bpfMapConfig             = "config_map"
	bpfMapEnterProgs         = "enter_progs"
	bpfMapEnterRoutes        = "enter_routes"
	bpfMapEvents             = "events"
	bpfMapExitProgs          = "exit_progs"
	bpfMapExitRoutes         = "exit_routes"
	bpfMapFDPathScratch      = "fd_path_scratch_map"
	bpfMapFilter             = "filter_map"
	bpfMapMainExited         = "main_exited_map"
	bpfMapMmsgBytesProgs     = "mmsg_bytes_progs"
	bpfMapPendingExec        = "pending_exec_map"
	bpfMapPendingStack       = "pending_stack_map"
	bpfMapPendingTask        = "pending_task_storage"
	bpfMapPIDNamespaceConfig = "pid_namespace_config_map"
	bpfMapPlainEnterElide    = "plain_enter_elide_map"
	bpfMapRecvmsgProgs       = "recvmsg_progs"
	bpfMapRuntimeMeta        = "runtime_meta_map"
	bpfMapStackTraces        = "stack_traces"
	bpfMapStats              = "stats_map"
	bpfMapSyscallFilter      = "syscall_filter_map"
)

// bpfCoreMapSpec owns one generated map binding used by the runtime.
type bpfCoreMapSpec struct {
	name   string
	lookup func(*bpfObjects) *ebpf.Map
}

var bpfCoreMapCatalog = []bpfCoreMapSpec{
	{name: bpfMapArmFork, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.ArmForkMap }},
	{name: bpfMapAttachExited, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.AttachExitedMap }},
	{name: bpfMapAttachRoots, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.AttachRootsMap }},
	{name: bpfMapConfig, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.ConfigMap }},
	{name: bpfMapEnterProgs, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.EnterProgs }},
	{name: bpfMapEnterRoutes, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.EnterRoutes }},
	{name: bpfMapEvents, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.Events }},
	{name: bpfMapExitProgs, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.ExitProgs }},
	{name: bpfMapExitRoutes, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.ExitRoutes }},
	{name: bpfMapFDPathScratch, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.FdPathScratchMap }},
	{name: bpfMapFilter, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.FilterMap }},
	{name: bpfMapMainExited, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.MainExitedMap }},
	{name: bpfMapMmsgBytesProgs, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.MmsgBytesProgs }},
	{name: bpfMapPendingExec, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.PendingExecMap }},
	{name: bpfMapPendingStack, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.PendingStackMap }},
	{name: bpfMapPendingTask, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.PendingTaskStorage }},
	{name: bpfMapPIDNamespaceConfig, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.PidNamespaceConfigMap }},
	{name: bpfMapPlainEnterElide, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.PlainEnterElideMap }},
	{name: bpfMapRecvmsgProgs, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.RecvmsgProgs }},
	{name: bpfMapRuntimeMeta, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.RuntimeMetaMap }},
	{name: bpfMapStackTraces, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.StackTraces }},
	{name: bpfMapStats, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.StatsMap }},
	{name: bpfMapSyscallFilter, lookup: func(objects *bpfObjects) *ebpf.Map { return objects.SyscallFilterMap }},
}

func bpfCoreMapSpecByName(name string) (bpfCoreMapSpec, bool) {
	for _, spec := range bpfCoreMapCatalog {
		if spec.name == name {
			return spec, true
		}
	}
	return bpfCoreMapSpec{}, false
}

func bpfCoreMap(objects *bpfObjects, name string) *ebpf.Map {
	spec, ok := bpfCoreMapSpecByName(name)
	if !ok || objects == nil || spec.lookup == nil {
		return nil
	}
	return spec.lookup(objects)
}

func (o *bpfObjects) coreMap(name string) *ebpf.Map {
	return bpfCoreMap(o, name)
}

var _ bpfMapProvider = (*bpfObjects)(nil)
