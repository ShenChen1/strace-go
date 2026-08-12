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
	"github.com/cilium/ebpf/rlimit"

	"strace-go/pkg/meta"
)

// traceBPFRuntime owns the loaded collection, all attached links, and the
// narrow operations needed by bootstrap. Callers never close its internals.
type traceBPFRuntime struct {
	objects *bpfObjects
	links   []link.Link
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

func setupBPF() (*traceBPFRuntime, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}
	if err := setSyscallVariables(spec); err != nil {
		return nil, fmt.Errorf("resolve BPF syscall variables: %w", err)
	}

	objects := &bpfObjects{}
	if err := spec.LoadAndAssign(objects, nil); err != nil {
		_ = objects.Close()
		return nil, fmt.Errorf("load and assign BPF objects: %w", err)
	}
	runtime := &traceBPFRuntime{objects: objects}
	links, err := newBpfAttacher(objects).attachAll()
	if err != nil {
		// attachAll owns partial-link cleanup on every attach failure.
		_ = objects.Close()
		return nil, fmt.Errorf("attach BPF programs: %w", err)
	}
	runtime.links = links
	return runtime, nil
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
	if r == nil || r.objects == nil || r.objects.FilterMap == nil {
		return fmt.Errorf("BPF filter map is unavailable")
	}
	return r.objects.FilterMap.Update(pid, uint32(1), 0)
}

func (r *traceBPFRuntime) deleteFilterPID(pid uint32) error {
	if r == nil || r.objects == nil || r.objects.FilterMap == nil {
		return nil
	}
	if err := r.objects.FilterMap.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete filter pid %d: %w", pid, err)
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
	closeTracepointLinks(r.links)
	r.links = nil
	if r.objects == nil {
		return nil
	}
	objects := r.objects
	r.objects = nil
	return objects.Close()
}

var _ traceBPFTargetPort = (*traceBPFRuntime)(nil)
