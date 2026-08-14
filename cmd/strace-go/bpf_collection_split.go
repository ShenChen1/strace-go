package main

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

type bpfHandlerFamily string

const (
	bpfHandlerEnterGenericFamily    bpfHandlerFamily = "enter_generic"
	bpfHandlerEnterPayloadFamily    bpfHandlerFamily = "enter_payload"
	bpfHandlerEnterPathFamily       bpfHandlerFamily = "enter_path"
	bpfHandlerEnterMemoryFamily     bpfHandlerFamily = "enter_memory"
	bpfHandlerEnterControlFamily    bpfHandlerFamily = "enter_control"
	bpfHandlerEnterStructuredFamily bpfHandlerFamily = "enter_structured"
	bpfHandlerExitFamily            bpfHandlerFamily = "exit"
	bpfHandlerRecvmsgFamily         bpfHandlerFamily = "recvmsg"
)

var bpfHandlerLoadOrder = []bpfHandlerFamily{
	bpfHandlerEnterGenericFamily,
	bpfHandlerEnterPayloadFamily,
	bpfHandlerEnterPathFamily,
	bpfHandlerEnterMemoryFamily,
	bpfHandlerEnterControlFamily,
	bpfHandlerEnterStructuredFamily,
	bpfHandlerExitFamily,
	bpfHandlerRecvmsgFamily,
}

var bpfHandlerProgramFamilies = map[string]bpfHandlerFamily{
	"enter_terminating":                bpfHandlerEnterGenericFamily,
	"enter_no_payload_generic":         bpfHandlerEnterGenericFamily,
	"enter_exec":                       bpfHandlerEnterPayloadFamily,
	"enter_payload_direct":             bpfHandlerEnterPayloadFamily,
	"enter_path_stat":                  bpfHandlerEnterPathFamily,
	"enter_path_only":                  bpfHandlerEnterPathFamily,
	"enter_dual_path":                  bpfHandlerEnterPathFamily,
	"enter_openat2":                    bpfHandlerEnterPathFamily,
	"enter_readlink":                   bpfHandlerEnterPathFamily,
	"enter_no_payload_direct":          bpfHandlerEnterPathFamily,
	"enter_mount_path":                 bpfHandlerEnterPathFamily,
	"enter_iovec":                      bpfHandlerEnterMemoryFamily,
	"enter_msg":                        bpfHandlerEnterMemoryFamily,
	"enter_mmsg":                       bpfHandlerEnterMemoryFamily,
	"enter_iovec_base":                 bpfHandlerEnterMemoryFamily,
	"enter_sendmsg_base":               bpfHandlerEnterMemoryFamily,
	"enter_mmsg_base01":                bpfHandlerEnterMemoryFamily,
	"enter_mmsg_base2":                 bpfHandlerEnterMemoryFamily,
	"enter_mmsg_base3":                 bpfHandlerEnterMemoryFamily,
	"enter_aio":                        bpfHandlerEnterMemoryFamily,
	"enter_aio_iovec":                  bpfHandlerEnterMemoryFamily,
	"enter_aio_buf":                    bpfHandlerEnterMemoryFamily,
	"enter_mmsg_bytes0":                bpfHandlerEnterMemoryFamily,
	"enter_mmsg_bytes1":                bpfHandlerEnterMemoryFamily,
	"enter_mmsg_bytes2":                bpfHandlerEnterMemoryFamily,
	"enter_mmsg_bytes3":                bpfHandlerEnterMemoryFamily,
	"enter_fcntl":                      bpfHandlerEnterControlFamily,
	"enter_ioctl":                      bpfHandlerEnterControlFamily,
	"enter_network":                    bpfHandlerEnterControlFamily,
	"enter_key":                        bpfHandlerEnterControlFamily,
	"enter_xattr":                      bpfHandlerEnterControlFamily,
	"enter_fs":                         bpfHandlerEnterControlFamily,
	"enter_poll":                       bpfHandlerEnterControlFamily,
	"enter_select":                     bpfHandlerEnterControlFamily,
	"enter_nested_fd_path0":            bpfHandlerEnterControlFamily,
	"enter_nested_fd_path1":            bpfHandlerEnterControlFamily,
	"enter_nested_fd_path2":            bpfHandlerEnterControlFamily,
	"enter_nested_fd_path3":            bpfHandlerEnterControlFamily,
	"enter_epoll":                      bpfHandlerEnterControlFamily,
	"enter_misc_struct":                bpfHandlerEnterStructuredFamily,
	"enter_small_struct":               bpfHandlerEnterStructuredFamily,
	"enter_itimer":                     bpfHandlerEnterStructuredFamily,
	"enter_time_struct":                bpfHandlerEnterStructuredFamily,
	"enter_signal":                     bpfHandlerEnterStructuredFamily,
	"enter_file_time":                  bpfHandlerEnterStructuredFamily,
	"enter_sleep":                      bpfHandlerEnterStructuredFamily,
	"enter_futex":                      bpfHandlerEnterStructuredFamily,
	"enter_cachestat":                  bpfHandlerEnterStructuredFamily,
	"enter_capability":                 bpfHandlerEnterStructuredFamily,
	"enter_memfd":                      bpfHandlerEnterStructuredFamily,
	"enter_prctl":                      bpfHandlerEnterStructuredFamily,
	"enter_clone3":                     bpfHandlerEnterStructuredFamily,
	"enter_bpf":                        bpfHandlerEnterStructuredFamily,
	"enter_quota":                      bpfHandlerEnterStructuredFamily,
	"exit_generic":                     bpfHandlerExitFamily,
	"exit_iovec_base":                  bpfHandlerExitFamily,
	"exit_msg":                         bpfHandlerExitFamily,
	"exit_mmsg_final":                  bpfHandlerExitFamily,
	"exit_recvmmsg_base01":             bpfHandlerExitFamily,
	"exit_recvmmsg_base23":             bpfHandlerExitFamily,
	"exit_quota":                       bpfHandlerExitFamily,
	"exit_mount_query":                 bpfHandlerExitFamily,
	"exit_path":                        bpfHandlerExitFamily,
	"exit_fd_time":                     bpfHandlerExitFamily,
	"exit_struct":                      bpfHandlerExitFamily,
	"exit_async":                       bpfHandlerExitFamily,
	"exit_io":                          bpfHandlerExitFamily,
	"exit_control":                     bpfHandlerExitFamily,
	"trace_kretprobe_recvmsg_dispatch": bpfHandlerRecvmsgFamily,
	"trace_kretprobe_recvmsg_name":     bpfHandlerRecvmsgFamily,
	"trace_kretprobe_recvmsg_control":  bpfHandlerRecvmsgFamily,
	"trace_kretprobe_recvmsg_final":    bpfHandlerRecvmsgFamily,
}

func classifyBPFHandlerProgram(name string) (bpfHandlerFamily, bool) {
	family, ok := bpfHandlerProgramFamilies[name]
	return family, ok
}

// bpfMapReplacementPlan describes handler maps that must reuse core state.
// ELF data sections stay private because their global variables are object-local.
type bpfMapReplacementPlan struct {
	replacements map[string]*ebpf.Map
}

func newBPFMapReplacementPlan(
	core *ebpf.Collection,
	handlers *ebpf.CollectionSpec,
) (*bpfMapReplacementPlan, error) {
	if core == nil {
		return nil, fmt.Errorf("core BPF collection is nil")
	}
	if handlers == nil {
		return nil, fmt.Errorf("handler BPF spec is nil")
	}
	replacements := make(map[string]*ebpf.Map)
	for name := range handlers.Maps {
		if isBPFDataSection(name) {
			continue
		}
		resource, ok := core.Maps[name]
		if !ok || resource == nil {
			return nil, fmt.Errorf("core map %q is unavailable", name)
		}
		replacements[name] = resource
	}
	return &bpfMapReplacementPlan{replacements: replacements}, nil
}

func isBPFDataSection(name string) bool {
	return strings.HasPrefix(name, ".")
}

func prepareBPFCollectionPrograms(
	core *ebpf.CollectionSpec,
	handlers map[bpfHandlerFamily]*ebpf.CollectionSpec,
	selection bpfProgramSelection,
) error {
	if core == nil || len(handlers) == 0 {
		return fmt.Errorf("BPF core and handler specs are required")
	}
	for name := range selection.programs {
		if _, ok := core.Programs[name]; ok {
			continue
		}
		family, ok := classifyBPFHandlerProgram(name)
		if !ok {
			return fmt.Errorf("selected BPF program %q is unavailable", name)
		}
		spec, familyOK := handlers[family]
		if familyOK && spec != nil {
			if _, ok := spec.Programs[name]; ok {
				continue
			}
		}
		return fmt.Errorf("selected BPF program %q is unavailable", name)
	}
	if selection.loadAll {
		return nil
	}
	coreSelection := selectionForBPFSpec(selection, core)
	if err := pruneBPFProgramSpecs(core, coreSelection); err != nil {
		return fmt.Errorf("prune core programs: %w", err)
	}
	for family, spec := range handlers {
		if spec == nil {
			return fmt.Errorf("handler spec %q is nil", family)
		}
		handlerSelection := selectionForBPFSpec(selection, spec)
		if err := pruneBPFProgramSpecs(spec, handlerSelection); err != nil {
			return fmt.Errorf("prune %s handler programs: %w", family, err)
		}
	}
	return nil
}

func selectionForBPFSpec(
	selection bpfProgramSelection,
	spec *ebpf.CollectionSpec,
) bpfProgramSelection {
	selected := selection
	selected.loadAll = false
	selected.programs = make(map[string]struct{})
	for name := range selection.programs {
		if _, ok := spec.Programs[name]; ok {
			selected.programs[name] = struct{}{}
		}
	}
	return selected
}
