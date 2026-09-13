#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} local_sequence SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} global_sequence SEC(".maps");

SEC("socket")
int baseline(struct __sk_buff *skb)
{
    u32 key = 0;
    u64 *value = bpf_map_lookup_elem(&local_sequence, &key);
    return value ? *(volatile u64 *)value : 0;
}

SEC("socket")
int per_cpu(struct __sk_buff *skb)
{
    u32 key = 0;
    u64 *value = bpf_map_lookup_elem(&local_sequence, &key);
    return value ? __sync_fetch_and_add(value, 1) : 0;
}

SEC("socket")
int global_atomic(struct __sk_buff *skb)
{
    u32 key = 0;
    u64 *value = bpf_map_lookup_elem(&global_sequence, &key);
    return value ? __sync_fetch_and_add(value, 1) : 0;
}
