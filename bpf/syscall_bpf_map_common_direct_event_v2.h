#ifndef STRACE_GO_SYSCALL_BPF_MAP_COMMON_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_MAP_COMMON_DIRECT_EVENT_V2_H

#define BPF_DIRECT_MAP_BATCH_CURSOR_MIN 4
#define BPF_DIRECT_MAP_TYPE_HASH 1
#define BPF_DIRECT_MAP_TYPE_PERCPU_HASH 5
#define BPF_DIRECT_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_DIRECT_MAP_TYPE_LRU_HASH 9
#define BPF_DIRECT_MAP_TYPE_LRU_PERCPU_HASH 10
#define BPF_DIRECT_MAP_TYPE_PERCPU_CGROUP_STORAGE 21
#define BPF_DIRECT_RUNTIME_META_KEY 0
#define BPF_DIRECT_MAP_FLAG_CPU 8ULL
#define BPF_DIRECT_MAP_FLAG_ALL_CPUS 16ULL

static __always_inline struct bpf_map *lookup_current_bpf_map_direct(s32 map_fd)
{
    struct file *file = lookup_current_fd_file(map_fd);
    if (!file) {
        return 0;
    }
    return (struct bpf_map *)BPF_CORE_READ(file, private_data);
}

static __always_inline int bpf_map_type_is_percpu_direct(u32 map_type)
{
    return map_type == BPF_DIRECT_MAP_TYPE_PERCPU_HASH ||
        map_type == BPF_DIRECT_MAP_TYPE_PERCPU_ARRAY ||
        map_type == BPF_DIRECT_MAP_TYPE_LRU_PERCPU_HASH ||
        map_type == BPF_DIRECT_MAP_TYPE_PERCPU_CGROUP_STORAGE;
}

static __always_inline u32 bpf_runtime_possible_cpu_count_direct(void)
{
    u32 key = BPF_DIRECT_RUNTIME_META_KEY;
    u32 *count = bpf_map_lookup_elem(&runtime_meta_map, &key);
    if (!count || *count == 0) {
        return 0;
    }
    return *count;
}

static __always_inline u32 bpf_map_effective_value_size_direct(
    struct bpf_map *map,
    u32 value_size,
    u64 flags)
{
    u32 map_type = BPF_CORE_READ(map, map_type);
    if (!bpf_map_type_is_percpu_direct(map_type) ||
        (flags & (BPF_DIRECT_MAP_FLAG_CPU | BPF_DIRECT_MAP_FLAG_ALL_CPUS))) {
        return value_size;
    }

    u32 possible_cpus = bpf_runtime_possible_cpu_count_direct();
    if (!possible_cpus) {
        return 0;
    }
    u64 stride = ((u64)value_size + 7ULL) & ~7ULL;
    u64 total = stride * possible_cpus;
    if (total > 0xffffffffULL) {
        return 0xffffffffU;
    }
    return (u32)total;
}

static __always_inline u32 bpf_map_batch_buffer_len_direct(
    u32 count,
    u32 element_size)
{
    // Keep logical length bounded before it reaches the TLV u32 ABI.
    u64 total = (u64)count * element_size;
    if (total > 0xffffffffULL) {
        return 0xffffffffU;
    }
    return (u32)total;
}

#endif
