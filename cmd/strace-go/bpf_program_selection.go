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

var bpfEnterProgramNames = map[uint32]string{
	enterProgTerminating:      "enter_terminating",
	enterProgExec:             "enter_exec",
	enterProgPathStat:         "enter_path_stat",
	enterProgPathOnly:         "enter_path_only",
	enterProgDualPath:         "enter_dual_path",
	enterProgOpenat2:          "enter_openat2",
	enterProgReadlink:         "enter_readlink",
	enterProgMiscStruct:       "enter_misc_struct",
	enterProgSmallStruct:      "enter_small_struct",
	enterProgItimer:           "enter_itimer",
	enterProgTimeStruct:       "enter_time_struct",
	enterProgSignal:           "enter_signal",
	enterProgFileTime:         "enter_file_time",
	enterProgSleep:            "enter_sleep",
	enterProgFutex:            "enter_futex",
	enterProgCachestat:        "enter_cachestat",
	enterProgCapability:       "enter_capability",
	enterProgMemfd:            "enter_memfd",
	enterProgPrctl:            "enter_prctl",
	enterProgClone3:           "enter_clone3",
	enterProgBpf:              "enter_bpf",
	enterProgIovec:            "enter_iovec",
	enterProgMsg:              "enter_msg",
	enterProgMmsg:             "enter_mmsg",
	enterProgFcntl:            "enter_fcntl",
	enterProgIoctl:            "enter_ioctl",
	enterProgNetwork:          "enter_network",
	enterProgKey:              "enter_key",
	enterProgXattr:            "enter_xattr",
	enterProgFs:               "enter_fs",
	enterProgAio:              "enter_aio",
	enterProgPoll:             "enter_poll",
	enterProgSelect:           "enter_select",
	enterProgEpoll:            "enter_epoll",
	enterProgNoPayload:        "enter_no_payload_direct",
	enterProgPayload:          "enter_payload_direct",
	enterProgNoPayloadGeneric: "enter_no_payload_generic",
	enterProgIovecBase:        "enter_iovec_base",
	enterProgSendmsgBase:      "enter_sendmsg_base",
	enterProgMmsgB01:          "enter_mmsg_base01",
	enterProgMmsgB2:           "enter_mmsg_base2",
	enterProgMmsgB3:           "enter_mmsg_base3",
	enterProgAioIovec:         "enter_aio_iovec",
	enterProgAioBuf:           "enter_aio_buf",
	enterProgQuota:            "enter_quota",
	enterProgMountPath:        "enter_mount_path",
	enterProgNestedFDPath0:    "enter_nested_fd_path0",
	enterProgNestedFDPath1:    "enter_nested_fd_path1",
	enterProgNestedFDPath2:    "enter_nested_fd_path2",
	enterProgNestedFDPath3:    "enter_nested_fd_path3",
}

var bpfExitProgramNames = map[uint32]string{
	exitProgGeneric:        "exit_generic",
	exitProgIovecBase:      "exit_iovec_base",
	exitProgMsg:            "exit_msg",
	exitProgMmsgFinal:      "exit_mmsg_final",
	exitProgRecvmmsgBase01: "exit_recvmmsg_base01",
	exitProgRecvmmsgBase23: "exit_recvmmsg_base23",
	exitProgQuota:          "exit_quota",
	exitProgMountQuery:     "exit_mount_query",
	exitProgPath:           "exit_path",
	exitProgFDTime:         "exit_fd_time",
	exitProgStruct:         "exit_struct",
	exitProgAsync:          "exit_async",
	exitProgIO:             "exit_io",
	exitProgControl:        "exit_control",
}

var bpfRecvmsgProgramNames = map[uint32]string{
	recvmsgProgName:    "trace_kretprobe_recvmsg_name",
	recvmsgProgControl: "trace_kretprobe_recvmsg_control",
	recvmsgProgFinal:   "trace_kretprobe_recvmsg_final",
}

var bpfMmsgByteProgramNames = map[uint32]string{
	mmsgBytesProgBase0: "enter_mmsg_bytes0",
	mmsgBytesProgBase1: "enter_mmsg_bytes1",
	mmsgBytesProgBase2: "enter_mmsg_bytes2",
	mmsgBytesProgBase3: "enter_mmsg_bytes3",
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
	name, ok := bpfEnterProgramNames[slot]
	if !ok {
		return fmt.Errorf("unknown BPF enter program slot %d", slot)
	}
	s.enterSlots[slot] = struct{}{}
	s.addProgram(name)
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
	name, ok := bpfExitProgramNames[slot]
	if !ok {
		return fmt.Errorf("unknown BPF exit program slot %d", slot)
	}
	s.exitSlots[slot] = struct{}{}
	s.addProgram(name)
	return nil
}

func (s *bpfProgramSelection) addRecvmsgPrograms() {
	s.recvmsgKretprobe = true
	s.addProgram("trace_kretprobe_recvmsg_dispatch")
	for slot, name := range bpfRecvmsgProgramNames {
		s.recvmsgSlots[slot] = struct{}{}
		s.addProgram(name)
	}
}

func (s *bpfProgramSelection) addMmsgBytePrograms() {
	for slot, name := range bpfMmsgByteProgramNames {
		s.mmsgByteSlots[slot] = struct{}{}
		s.addProgram(name)
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
