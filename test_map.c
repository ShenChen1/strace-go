#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64[128]); // 128 entries
} stack_traces SEC(".maps");
