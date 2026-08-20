package main

import (
	"fmt"

	"github.com/cilium/ebpf"

	"strace-go/pkg/meta"
)

type bpfProgramSelection struct {
	loadAll          bool
	programs         map[string]struct{}
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
	if routePlanHasSyscall(table, plan, "recvmsg") {
		selection.addRecvmsgPrograms()
	}
	if routePlanHasSyscall(table, plan, "sendmmsg") {
		selection.addMmsgBytePrograms()
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
	} {
		s.addProgram(name)
	}
	noPayloadSlot := uint32(enterProgNoPayloadGeneric)
	if fdState {
		noPayloadSlot = enterProgNoPayload
	}
	if err := s.addEnterSlotUnchecked(noPayloadSlot); err != nil {
		return err
	}
	return s.addExitSlotUnchecked(exitProgGeneric)
}

func (s *bpfProgramSelection) addEnterSlot(slot uint32) error {
	if err := s.addEnterSlotUnchecked(slot); err != nil {
		return err
	}
	switch slot {
	case enterProgIovec:
		return s.addEnterSlotUnchecked(enterProgIovecBase)
	case enterProgMsg:
		return s.addEnterSlotUnchecked(enterProgSendmsgBase)
	case enterProgMmsg:
		if err := s.addEnterSlotUnchecked(enterProgMmsgB01); err != nil {
			return err
		}
		if err := s.addEnterSlotUnchecked(enterProgMmsgB2); err != nil {
			return err
		}
		return s.addEnterSlotUnchecked(enterProgMmsgB3)
	case enterProgAio:
		return s.addEnterSlot(enterProgAioIovec)
	case enterProgAioIovec:
		return s.addEnterSlotUnchecked(enterProgAioBuf)
	case enterProgMmsgB01:
		return s.addEnterSlotUnchecked(enterProgMmsgB2)
	case enterProgMmsgB2:
		return s.addEnterSlotUnchecked(enterProgMmsgB3)
	}
	return nil
}

func (s *bpfProgramSelection) addEnterSlotUnchecked(slot uint32) error {
	program, ok := bpfTailCallProgramBySlot(bpfEnterProgramCatalog, slot)
	if !ok {
		return fmt.Errorf("unknown BPF enter program slot %d", slot)
	}
	s.enterSlots[slot] = struct{}{}
	s.addProgram(program.name)
	return nil
}

func (s *bpfProgramSelection) addExitSlot(slot uint32) error {
	if err := s.addExitSlotUnchecked(slot); err != nil {
		return err
	}
	switch slot {
	case exitProgRecvmmsgBase01:
		if err := s.addExitSlotUnchecked(exitProgRecvmmsgBase23); err != nil {
			return err
		}
		return s.addExitSlotUnchecked(exitProgMmsgFinal)
	case exitProgRecvmmsgBase23:
		return s.addExitSlotUnchecked(exitProgMmsgFinal)
	}
	return nil
}

func (s *bpfProgramSelection) addExitSlotUnchecked(slot uint32) error {
	program, ok := bpfTailCallProgramBySlot(bpfExitProgramCatalog, slot)
	if !ok {
		return fmt.Errorf("unknown BPF exit program slot %d", slot)
	}
	s.exitSlots[slot] = struct{}{}
	s.addProgram(program.name)
	return nil
}

func (s *bpfProgramSelection) addRecvmsgPrograms() {
	s.recvmsgKretprobe = true
	s.addProgram(bpfRecvmsgDispatchProgramName)
	for _, program := range bpfRecvmsgProgramCatalog {
		s.recvmsgSlots[program.slot] = struct{}{}
		s.addProgram(program.name)
	}
}

func (s *bpfProgramSelection) addMmsgBytePrograms() {
	for _, program := range bpfMmsgByteProgramCatalog {
		s.mmsgByteSlots[program.slot] = struct{}{}
		s.addProgram(program.name)
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
