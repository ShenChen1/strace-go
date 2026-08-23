package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFBpfMapLookupExitProviderUsesKernelValueSizeOutTLV(t *testing.T) {
	root := repoRootForTest(t)
	exit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_exit_direct_event_v2.h"))
	mapExit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_exit_direct_event_v2.h"))
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	common := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_common_direct_event_v2.h"))
	fdState := readTextFile(t, filepath.Join(root, "bpf/syscall_fd_state_direct_event_v2.h"))

	for _, snippet := range []string{
		"BPF_DIRECT_MAP_LOOKUP_ELEM 1",
		"BPF_DIRECT_MAP_LOOKUP_AND_DELETE_ELEM 21",
		"BPF_DIRECT_MAP_VALUE_ARG 117",
		"BPF_DIRECT_MAP_VALUE_MAX 512",
		"BPF_DIRECT_MAP_FD_OFF 0",
		"BPF_DIRECT_MAP_VALUE_OFF 16",
	} {
		if !strings.Contains(nested+exit+common, snippet) {
			t.Fatalf("BPF map lookup exit provider missing %q", snippet)
		}
	}

	for _, snippet := range []string{
		"emit_bpf_map_lookup_exit_event_v2_direct(",
		"read_bpf_map_lookup_output_request_direct(",
		"lookup_current_fd_file(",
		"BPF_CORE_READ(file, private_data)",
		"BPF_CORE_READ(map, value_size)",
		"ret_value != 0",
		"bpf_probe_read_user(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"PAYLOAD_TLV_KIND_BYTES",
		"init_syscall_exit_event_v2_from_pending(",
	} {
		if !strings.Contains(exit+mapExit+fdState+common, snippet) {
			t.Fatalf("BPF map lookup exit provider missing %q", snippet)
		}
	}

	if !strings.Contains(exit+mapExit+common, "emit_bpf_exit_bytes_event_v2_direct(") {
		t.Fatal("BPF map lookup exit provider must reuse the bounded bytes emitter")
	}
}

func TestBPFBpfMapBatchExitProviderUsesBoundedMetadataOutputs(t *testing.T) {
	root := repoRootForTest(t)
	mapExit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_exit_direct_event_v2.h"))
	exit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_exit_direct_event_v2.h"))
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	common := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_common_direct_event_v2.h"))

	for _, snippet := range []string{
		"BPF_DIRECT_MAP_LOOKUP_BATCH 24",
		"BPF_DIRECT_MAP_LOOKUP_AND_DELETE_BATCH 25",
		"BPF_DIRECT_MAP_BATCH_CURSOR_MIN 4",
		"BPF_DIRECT_MAP_TYPE_HASH 1",
		"BPF_DIRECT_MAP_TYPE_PERCPU_HASH 5",
		"BPF_DIRECT_MAP_TYPE_LRU_HASH 9",
		"BPF_DIRECT_MAP_TYPE_LRU_PERCPU_HASH 10",
		"BPF_DIRECT_MAP_BATCH_OUT_BATCH_OFF 8",
		"BPF_DIRECT_MAP_BATCH_KEYS_OFF 16",
		"BPF_DIRECT_MAP_BATCH_VALUES_OFF 24",
		"BPF_DIRECT_MAP_BATCH_COUNT_OFF 32",
		"BPF_DIRECT_MAP_BATCH_FD_OFF 36",
		"BPF_DIRECT_MAP_BATCH_OUT_BATCH_ARG 120",
		"BPF_DIRECT_MAP_BATCH_KEYS_ARG 118",
		"BPF_DIRECT_MAP_BATCH_VALUES_ARG 119",
	} {
		if !strings.Contains(nested+mapExit+common, snippet) {
			t.Fatalf("BPF map batch provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_bpf_map_batch_lookup_exit_event_v2_direct(",
		"read_bpf_map_batch_output_requests_direct(",
		"bpf_map_batch_cursor_len_direct(",
		"BPF_CORE_READ(map, map_type)",
		"BPF_CORE_READ(map, key_size)",
		"BPF_CORE_READ(map, value_size)",
		"ret_value != -ENOENT",
		"count * element_size",
		"bpf_ringbuf_reserve_dynptr(",
		"bpf_probe_read_user(",
		"PAYLOAD_TLV_FLAG_DIRECTION_OUT",
		"BPF_MAP_LOOKUP_BATCH",
		"BPF_MAP_LOOKUP_AND_DELETE_BATCH",
	} {
		if !strings.Contains(exit+mapExit+common, snippet) {
			t.Fatalf("BPF map batch provider missing %q", snippet)
		}
	}
}

func TestBPFBpfMapUpdateBatchEnterProviderUsesBoundedInputPayloads(t *testing.T) {
	root := repoRootForTest(t)
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	provider := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_input_direct_event_v2.h"))
	capture := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_capture_direct_event_v2.h"))
	common := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_common_direct_event_v2.h"))

	for _, snippet := range []string{
		"BPF_DIRECT_MAP_UPDATE_BATCH 26",
		"BPF_DIRECT_MAP_BATCH_KEYS_IN_ARG 121",
		"BPF_DIRECT_MAP_BATCH_VALUES_IN_ARG 122",
		"BPF_DIRECT_MAP_BATCH_KEYS_OFF 16",
		"BPF_DIRECT_MAP_BATCH_VALUES_OFF 24",
		"BPF_DIRECT_MAP_BATCH_COUNT_OFF 32",
		"BPF_DIRECT_MAP_BATCH_FD_OFF 36",
		"capture_bpf_map_batch_inputs_tlv_direct(",
		"BPF_CORE_READ(map, key_size)",
		"BPF_CORE_READ(map, value_size)",
		"BPF_DIRECT_MAP_TYPE_PERCPU_HASH",
		"BPF_DIRECT_MAP_TYPE_PERCPU_ARRAY",
		"capture_bpf_bytes_tlv_direct(",
		"bpf_probe_read_user(",
		"PAYLOAD_TLV_KIND_BYTES",
	} {
		if !strings.Contains(nested+provider+capture+common, snippet) {
			t.Fatalf("BPF map update batch enter provider missing %q", snippet)
		}
	}
}

func TestBPFBpfPerCPUMapProvidersUseRuntimeMetadataAndFlags(t *testing.T) {
	root := repoRootForTest(t)
	runtimeABI := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))
	common := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_common_direct_event_v2.h"))
	nested := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_nested_direct_event_v2.h"))
	mapExit := readTextFile(t, filepath.Join(root, "bpf/syscall_bpf_map_exit_direct_event_v2.h"))
	runtime := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_runtime.go"))
	config := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_config.go"))
	catalog := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_map_catalog.go"))

	for _, snippet := range []string{
		"runtime_meta_map SEC(\".maps\")",
		"BPF_DIRECT_RUNTIME_META_KEY",
		"BPF_DIRECT_MAP_FLAG_CPU",
		"BPF_DIRECT_MAP_FLAG_ALL_CPUS",
		"bpf_map_effective_value_size_direct(",
		"& ~7ULL",
		"bpf_runtime_possible_cpu_count_direct(",
	} {
		if !strings.Contains(runtimeABI+common, snippet) {
			t.Fatalf("per-CPU runtime ABI missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"BPF_DIRECT_MAP_BATCH_ELEM_FLAGS_OFF 40",
		"BPF_DIRECT_MAP_ELEM_FLAGS_OFF 24",
		"bpf_map_effective_value_size_direct(",
		"BPF_DIRECT_MAP_BATCH_VALUES_IN_ARG",
		"BPF_DIRECT_MAP_BATCH_VALUES_ARG",
		"BPF_DIRECT_MAP_VALUE_ARG",
	} {
		if !strings.Contains(nested+mapExit, snippet) {
			t.Fatalf("per-CPU map provider missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"bpfMapRuntimeMeta",
		"ebpf.PossibleCPU()",
		"runtime_meta_map",
		"configureBPFRuntimeMetadata(",
	} {
		if !strings.Contains(runtime+config+catalog, snippet) {
			t.Fatalf("per-CPU runtime configuration missing %q", snippet)
		}
	}
}
