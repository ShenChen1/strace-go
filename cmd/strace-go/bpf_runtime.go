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
	objects      *bpfObjects
	links        []link.Link
	extraClosers []io.Closer
	setupTimings []traceBPFSetupTiming
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
	if r == nil || r.objects == nil || r.objects.Events == nil {
		return nil, fmt.Errorf("BPF events map is unavailable")
	}
	reader, err := ringbuf.NewReader(r.objects.Events)
	if err != nil {
		return nil, err
	}
	return reader, nil
}

func (r *traceBPFRuntime) configure(config traceBPFConfig) error {
	if r == nil || r.objects == nil || r.objects.ConfigMap == nil {
		return fmt.Errorf("BPF config map is unavailable")
	}
	cfgVal, err := buildRuntimeConfig(config, r.objects)
	if err != nil {
		return fmt.Errorf("build runtime config: %w", err)
	}
	if err := r.objects.ConfigMap.Update(uint32(0), cfgVal, 0); err != nil {
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
	if r == nil || r.objects == nil || r.objects.ArmForkMap == nil {
		return fmt.Errorf("BPF arm fork map is unavailable")
	}
	pid := uint32(os.Getpid())
	if err := r.objects.ArmForkMap.Update(uint32(0), pid, 0); err != nil {
		return fmt.Errorf("update arm fork map: %w", err)
	}
	return nil
}

func (r *traceBPFRuntime) disarmNextFork() error {
	if r == nil || r.objects == nil || r.objects.ArmForkMap == nil {
		return fmt.Errorf("BPF arm fork map is unavailable")
	}
	var zero uint32
	if err := r.objects.ArmForkMap.Update(uint32(0), zero, 0); err != nil {
		return fmt.Errorf("clear arm fork map: %w", err)
	}
	return nil
}

func (r *traceBPFRuntime) addFilterPID(pid uint32) error {
	if r == nil || r.objects == nil || r.objects.FilterMap == nil ||
		r.objects.AttachExitedMap == nil || r.objects.AttachRootsMap == nil {
		return fmt.Errorf("BPF filter map is unavailable")
	}
	if err := r.objects.AttachExitedMap.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("clear attach exit fact for pid %d: %w", pid, err)
	}
	if err := r.objects.AttachRootsMap.Update(pid, uint32(1), 0); err != nil {
		return fmt.Errorf("register attach root %d: %w", pid, err)
	}
	if err := r.objects.FilterMap.Update(pid, uint32(1), 0); err != nil {
		return errors.Join(
			fmt.Errorf("add filter pid %d: %w", pid, err),
			deleteAttachRoot(r.objects.AttachRootsMap, pid),
		)
	}
	return nil
}

func (r *traceBPFRuntime) deleteFilterPID(pid uint32) error {
	if r == nil || r.objects == nil {
		return nil
	}
	var filterErr error
	if r.objects.FilterMap != nil {
		if err := r.objects.FilterMap.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			filterErr = fmt.Errorf("delete filter pid %d: %w", pid, err)
		}
	}
	var rootErr error
	if r.objects.AttachRootsMap != nil {
		if err := r.objects.AttachRootsMap.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			rootErr = fmt.Errorf("delete attach root %d: %w", pid, err)
		}
	}
	var exitFactErr error
	if r.objects.AttachExitedMap != nil {
		if err := r.objects.AttachExitedMap.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
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
	if r == nil || r.objects == nil || r.objects.ArmForkMap == nil {
		return 0, false
	}
	raw, err := r.objects.ArmForkMap.LookupBytes(uint32(0))
	if err != nil || len(raw) != 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(raw), true
}

// Close releases links before maps/programs and is safe to call repeatedly.
func (r *traceBPFRuntime) Close() error {
	if r == nil {
		return nil
	}
	links := r.links
	r.links = nil
	linkErr := closeTracepointLinks(links)
	extraClosers := r.extraClosers
	r.extraClosers = nil
	if r.objects == nil {
		return errors.Join(linkErr, closeBPFExtraResources(extraClosers))
	}
	objects := r.objects
	r.objects = nil
	return errors.Join(linkErr, objects.Close(), closeBPFExtraResources(extraClosers))
}

var _ traceBPFTargetPort = (*traceBPFRuntime)(nil)
