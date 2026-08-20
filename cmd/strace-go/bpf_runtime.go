package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"strace-go/pkg/meta"
)

// traceBPFRuntime owns the loaded collection, all attached links, and the
// narrow operations needed by bootstrap. Callers never close its internals.
type traceBPFRuntime struct {
	objects        *bpfObjects
	programs       bpfProgramProvider
	links          []link.Link
	handlerClosers []io.Closer
	extraClosers   []io.Closer
	setupTimings   []traceBPFSetupTiming
}

// traceBPFTargetPort is the smallest BPF capability needed while starting or
// cleaning trace targets. It deliberately does not expose generated maps.
type traceBPFTargetPort interface {
	armNextFork() error
	disarmNextFork() error
	addFilterPID(pid uint32) error
	deleteFilterPID(pid uint32) error
	armedForkPID() (uint32, bool)
}

func (r *traceBPFRuntime) coreMap(name string) *ebpf.Map {
	if r == nil {
		return nil
	}
	return bpfCoreMap(r.objects, name)
}

type traceRingbufResource interface {
	traceRingbufReader
	io.Closer
}

// setSyscallVariables resolves Go-managed BPF syscall ids only from the
// generated SyscallTable. ABI-only constants remain owned by runtime_abi.h.
func setSyscallVariables(spec *ebpf.CollectionSpec) error {
	sysNameToID := make(map[string]uint32)
	for id, sc := range meta.SyscallTable {
		sysNameToID[sc.Name] = id
	}

	setVar := func(name string, val uint32) error {
		if v, ok := spec.Variables[name]; ok {
			if err := v.Set(val); err != nil {
				return fmt.Errorf("set %s: %w", name, err)
			}
			return nil
		}
		return fmt.Errorf("variable %s not found in BPF spec", name)
	}

	syscalls := []struct {
		varName string
		scName  string
	}{
		{"SYS_RT_SIGRETURN", "rt_sigreturn"},
		{"SYS_NANOSLEEP", "nanosleep"},
		{"SYS_EXECVE", "execve"},
		{"SYS_EXIT", "exit"},
		{"SYS_CAPGET", "capget"},
		{"SYS_CAPSET", "capset"},
		{"SYS_RT_SIGSUSPEND", "rt_sigsuspend"},
		{"SYS_EXIT_GROUP", "exit_group"},
		{"SYS_EXECVEAT", "execveat"},
	}
	for _, sc := range syscalls {
		id, ok := sysNameToID[sc.scName]
		if !ok {
			return fmt.Errorf("syscall %q is missing from generated syscall table", sc.scName)
		}
		if err := setVar(sc.varName, id); err != nil {
			return err
		}
	}
	return nil
}

func (r *traceBPFRuntime) newEventReader() (traceRingbufResource, error) {
	events := r.coreMap(bpfMapEvents)
	if events == nil {
		return nil, fmt.Errorf("BPF events map is unavailable")
	}
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return nil, err
	}
	return reader, nil
}

func (r *traceBPFRuntime) configure(config traceBPFConfig) error {
	configMap := r.coreMap(bpfMapConfig)
	if configMap == nil {
		return fmt.Errorf("BPF config map is unavailable")
	}
	cfgVal, err := buildRuntimeConfig(config, r.objects)
	if err != nil {
		return fmt.Errorf("build runtime config: %w", err)
	}
	if err := configMap.Update(uint32(0), cfgVal, 0); err != nil {
		return fmt.Errorf("update BPF runtime config: %w", err)
	}
	return nil
}

func (r *traceBPFRuntime) readPorts() traceBPFReadPorts {
	if r == nil {
		return traceBPFReadPorts{}
	}
	return newTraceBPFReadPorts(r.objects)
}

func (r *traceBPFRuntime) setupStages() []traceBPFSetupTiming {
	if r == nil {
		return nil
	}
	return append([]traceBPFSetupTiming(nil), r.setupTimings...)
}

func (r *traceBPFRuntime) armNextFork() error {
	armFork := r.coreMap(bpfMapArmFork)
	if armFork == nil {
		return fmt.Errorf("BPF arm fork map is unavailable")
	}
	pid := uint32(os.Getpid())
	if err := armFork.Update(uint32(0), pid, 0); err != nil {
		return fmt.Errorf("update arm fork map: %w", err)
	}
	return nil
}

func (r *traceBPFRuntime) disarmNextFork() error {
	armFork := r.coreMap(bpfMapArmFork)
	if armFork == nil {
		return fmt.Errorf("BPF arm fork map is unavailable")
	}
	var zero uint32
	if err := armFork.Update(uint32(0), zero, 0); err != nil {
		return fmt.Errorf("clear arm fork map: %w", err)
	}
	return nil
}

func (r *traceBPFRuntime) addFilterPID(pid uint32) error {
	filterMap := r.coreMap(bpfMapFilter)
	attachExited := r.coreMap(bpfMapAttachExited)
	attachRoots := r.coreMap(bpfMapAttachRoots)
	if filterMap == nil || attachExited == nil || attachRoots == nil {
		return fmt.Errorf("BPF filter map is unavailable")
	}
	if err := attachExited.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("clear attach exit fact for pid %d: %w", pid, err)
	}
	if err := attachRoots.Update(pid, uint32(1), 0); err != nil {
		return fmt.Errorf("register attach root %d: %w", pid, err)
	}
	if err := filterMap.Update(pid, uint32(1), 0); err != nil {
		return errors.Join(
			fmt.Errorf("add filter pid %d: %w", pid, err),
			deleteAttachRoot(attachRoots, pid),
		)
	}
	return nil
}

func (r *traceBPFRuntime) deleteFilterPID(pid uint32) error {
	if r == nil || r.objects == nil {
		return nil
	}
	filterMap := r.coreMap(bpfMapFilter)
	attachRoots := r.coreMap(bpfMapAttachRoots)
	attachExited := r.coreMap(bpfMapAttachExited)
	var filterErr error
	if filterMap != nil {
		if err := filterMap.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			filterErr = fmt.Errorf("delete filter pid %d: %w", pid, err)
		}
	}
	var rootErr error
	if attachRoots != nil {
		if err := attachRoots.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			rootErr = fmt.Errorf("delete attach root %d: %w", pid, err)
		}
	}
	var exitFactErr error
	if attachExited != nil {
		if err := attachExited.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			exitFactErr = fmt.Errorf("delete attach exit fact for pid %d: %w", pid, err)
		}
	}
	return errors.Join(filterErr, rootErr, exitFactErr)
}

func deleteAttachRoot(roots *ebpf.Map, pid uint32) error {
	if roots == nil {
		return nil
	}
	if err := roots.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("rollback attach root %d: %w", pid, err)
	}
	return nil
}

func (r *traceBPFRuntime) armedForkPID() (uint32, bool) {
	armFork := r.coreMap(bpfMapArmFork)
	if armFork == nil {
		return 0, false
	}
	raw, err := armFork.LookupBytes(uint32(0))
	if err != nil || len(raw) != 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(raw), true
}

// Close releases links before maps/programs and is safe to call repeatedly.
func (r *traceBPFRuntime) Close() error {
	return r.closeWithDiagnostics(nil, nil)
}

func (r *traceBPFRuntime) closeWithDiagnostics(
	clock traceClock,
	observer traceCleanupObserver,
) error {
	if r == nil {
		return nil
	}
	links := r.links
	r.links = nil
	linkStartNS := cleanupClockNowNS(clock)
	linkErr := closeTracepointLinksParallelWithDiagnostics(links, clock, observer)
	recordBPFResourceTiming(observer, "bpf_links", linkStartNS, cleanupClockNowNS(clock))
	namedResources := make([]traceBPFResource, 0, len(r.handlerClosers)+len(r.extraClosers)+1)
	for index, closer := range r.handlerClosers {
		namedResources = append(namedResources, traceBPFResource{
			Name:   fmt.Sprintf("bpf_handler_%d", index),
			Closer: closer,
		})
	}
	r.handlerClosers = nil
	if r.objects != nil {
		namedResources = append(namedResources, traceBPFResource{
			Name:   "bpf_core_objects",
			Closer: r.objects,
		})
	}
	for index, closer := range r.extraClosers {
		namedResources = append(namedResources, traceBPFResource{
			Name:   fmt.Sprintf("bpf_extra_%d", index),
			Closer: closer,
		})
	}
	r.extraClosers = nil
	r.objects = nil
	return errors.Join(linkErr, closeNamedBPFResourcesParallel(namedResources, clock, observer))
}

func recordBPFResourceTiming(observer traceCleanupObserver, name string, startNS uint64, endNS uint64) {
	if observer == nil {
		return
	}
	observer.RecordCleanupStep(traceCleanupTiming{Name: name, StartNS: startNS, EndNS: endNS})
}

var _ traceBPFTargetPort = (*traceBPFRuntime)(nil)
