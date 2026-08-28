package main

import (
	"fmt"

	"github.com/cilium/ebpf"

	"strace-go/pkg/meta"
)

type bpfProgramSelection struct {
	loadAll          bool
	programs         map[string]struct{}
	visited          map[bpfProgramRef]struct{}
	enterSlots       map[uint32]struct{}
	exitSlots        map[uint32]struct{}
	recvmsgSlots     map[uint32]struct{}
	mmsgByteSlots    map[uint32]struct{}
	recvmsgKretprobe bool
}

func selectBPFRoutePlan(plan bpfRoutePlan, config traceBPFConfig) bpfRoutePlan {
	selected := copyBPFRoutePlan(plan)
	if !config.syscallFilter.negated && config.syscallFilter.enabled && !config.fdState {
		ids := make(map[uint32]struct{}, len(config.syscallFilter.ids))
		for _, id := range config.syscallFilter.ids {
			ids[id] = struct{}{}
		}
		selected.enter = filterBPFRouteMap(selected.enter, ids)
		selected.exit = filterBPFRouteMap(selected.exit, ids)
	}
	if !config.fdState {
		selected.enter = useGenericNoPayloadEnterSlot(selected.enter)
	}
	return selected
}

func useGenericNoPayloadEnterSlot(routes map[uint32]uint32) map[uint32]uint32 {
	for id, slot := range routes {
		if slot == enterProgNoPayload {
			routes[id] = enterProgNoPayloadGeneric
		}
	}
	return routes
}

func copyBPFRoutePlan(plan bpfRoutePlan) bpfRoutePlan {
	return bpfRoutePlan{
		enter: copyBPFRouteMap(plan.enter),
		exit:  copyBPFRouteMap(plan.exit),
	}
}

func filterBPFRouteMap(routes map[uint32]uint32, selected map[uint32]struct{}) map[uint32]uint32 {
	filtered := make(map[uint32]uint32, len(selected))
	for id, slot := range routes {
		if _, ok := selected[id]; ok {
			filtered[id] = slot
		}
	}
	return filtered
}

func copyBPFRouteMap(routes map[uint32]uint32) map[uint32]uint32 {
	copyOf := make(map[uint32]uint32, len(routes))
	for id, slot := range routes {
		copyOf[id] = slot
	}
	return copyOf
}

func newBPFProgramSelection(
	plan bpfRoutePlan,
	table map[uint32]meta.Syscall,
	config traceBPFConfig,
) (bpfProgramSelection, error) {
	selection := bpfProgramSelection{
		loadAll:       shouldLoadAllBPFPrograms(config),
		programs:      make(map[string]struct{}),
		visited:       make(map[bpfProgramRef]struct{}),
		enterSlots:    make(map[uint32]struct{}),
		exitSlots:     make(map[uint32]struct{}),
		recvmsgSlots:  make(map[uint32]struct{}),
		mmsgByteSlots: make(map[uint32]struct{}),
	}
	if selection.loadAll {
		selection.recvmsgKretprobe = true
		return selection, nil
	}

	if err := selection.addCorePrograms(config.fdState); err != nil {
		return bpfProgramSelection{}, err
	}
	for _, slot := range plan.enter {
		if err := selection.addEnterSlot(slot); err != nil {
			return bpfProgramSelection{}, err
		}
	}
	for _, slot := range plan.exit {
		if err := selection.addExitSlot(slot); err != nil {
			return bpfProgramSelection{}, err
		}
	}
	for syscallName, root := range bpfSyscallProgramRoots {
		if !routePlanHasSyscall(table, plan, syscallName) {
			continue
		}
		if err := selection.addProgramRoot(root); err != nil {
			return bpfProgramSelection{}, err
		}
	}
	return selection, nil
}

func shouldLoadAllBPFPrograms(config traceBPFConfig) bool {
	// Full and negated filters still have a complete route closure, so they can
	// prune unreachable handler programs. FD-state must keep excluded creator and
	// closer syscalls alive to maintain the event-sourced fd state map.
	return config.fdState
}

func (s *bpfProgramSelection) addCorePrograms(fdState bool) error {
	for _, name := range []string{
		"trace_sys_enter",
		"trace_sys_exit",
		"trace_sched_process_fork",
		"trace_sched_process_exec",
		"trace_sched_process_exit",
		"trace_sched_process_free",
		bpfSignalDeliverProgramName,
	} {
		s.addProgram(name)
	}
	noPayloadSlot := uint32(enterProgNoPayloadGeneric)
	if fdState {
		noPayloadSlot = enterProgNoPayload
	}
	if err := s.addEnterSlot(noPayloadSlot); err != nil {
		return err
	}
	return s.addExitSlot(exitProgGeneric)
}

func (s *bpfProgramSelection) addEnterSlot(slot uint32) error {
	return s.addProgramRef(bpfProgramRef{array: bpfProgramArrayEnter, slot: slot})
}

func (s *bpfProgramSelection) addExitSlot(slot uint32) error {
	return s.addProgramRef(bpfProgramRef{array: bpfProgramArrayExit, slot: slot})
}

func (s *bpfProgramSelection) addProgramRoot(root bpfProgramRootSpec) error {
	for _, name := range root.programs {
		s.addProgram(name)
	}
	for _, ref := range root.refs {
		if err := s.addProgramRef(ref); err != nil {
			return err
		}
	}
	if root.recvmsgKretprobe {
		s.recvmsgKretprobe = true
	}
	return nil
}

func (s *bpfProgramSelection) addProgramRef(ref bpfProgramRef) error {
	if s.visited == nil {
		s.visited = make(map[bpfProgramRef]struct{})
	}
	if _, ok := s.visited[ref]; ok {
		return nil
	}
	program, ok := bpfTailCallProgramByRef(ref)
	if !ok {
		return fmt.Errorf("unknown BPF %s program slot %d", bpfProgramArrayName(ref.array), ref.slot)
	}
	s.visited[ref] = struct{}{}
	s.addProgram(program.name)
	switch ref.array {
	case bpfProgramArrayEnter:
		s.enterSlots[ref.slot] = struct{}{}
	case bpfProgramArrayExit:
		s.exitSlots[ref.slot] = struct{}{}
	case bpfProgramArrayRecvmsg:
		s.recvmsgSlots[ref.slot] = struct{}{}
	case bpfProgramArrayMmsgBytes:
		s.mmsgByteSlots[ref.slot] = struct{}{}
	default:
		return fmt.Errorf("unknown BPF program array %d", ref.array)
	}
	for _, dependency := range program.dependencies {
		if err := s.addProgramRef(dependency); err != nil {
			return err
		}
	}
	return nil
}

func bpfTailCallProgramByRef(ref bpfProgramRef) (bpfTailCallProgramSpec, bool) {
	switch ref.array {
	case bpfProgramArrayEnter:
		return bpfTailCallProgramBySlot(bpfEnterProgramCatalog, ref.slot)
	case bpfProgramArrayExit:
		return bpfTailCallProgramBySlot(bpfExitProgramCatalog, ref.slot)
	case bpfProgramArrayRecvmsg:
		return bpfTailCallProgramBySlot(bpfRecvmsgProgramCatalog, ref.slot)
	case bpfProgramArrayMmsgBytes:
		return bpfTailCallProgramBySlot(bpfMmsgByteProgramCatalog, ref.slot)
	default:
		return bpfTailCallProgramSpec{}, false
	}
}

func bpfProgramArrayName(array bpfProgramArray) string {
	switch array {
	case bpfProgramArrayEnter:
		return "enter"
	case bpfProgramArrayExit:
		return "exit"
	case bpfProgramArrayRecvmsg:
		return "recvmsg"
	case bpfProgramArrayMmsgBytes:
		return "mmsg_bytes"
	default:
		return "unknown"
	}
}

func (s *bpfProgramSelection) addProgram(name string) {
	s.programs[name] = struct{}{}
}

func (s bpfProgramSelection) hasProgram(name string) bool {
	return s.loadAll || hasBPFProgram(s.programs, name)
}

func hasBPFProgram(programs map[string]struct{}, name string) bool {
	_, ok := programs[name]
	return ok
}

func routePlanHasSyscall(table map[uint32]meta.Syscall, plan bpfRoutePlan, name string) bool {
	for id := range plan.enter {
		if syscall, ok := table[id]; ok && syscall.Name == name {
			return true
		}
	}
	return false
}

func selectedProgArrayEntries(
	entries []progArrayEntry,
	slots map[uint32]struct{},
	loadAll bool,
) []progArrayEntry {
	if loadAll {
		return entries
	}
	selected := make([]progArrayEntry, 0, len(slots))
	for _, entry := range entries {
		if _, ok := slots[entry.index]; ok {
			selected = append(selected, entry)
		}
	}
	return selected
}

func pruneBPFProgramSpecs(spec *ebpf.CollectionSpec, selection bpfProgramSelection) error {
	if spec == nil {
		return fmt.Errorf("BPF collection spec is nil")
	}
	if selection.loadAll {
		return nil
	}
	for name := range selection.programs {
		if _, ok := spec.Programs[name]; !ok {
			return fmt.Errorf("selected BPF program %q is unavailable", name)
		}
	}
	for name := range spec.Programs {
		if !selection.hasProgram(name) {
			delete(spec.Programs, name)
		}
	}
	return nil
}
