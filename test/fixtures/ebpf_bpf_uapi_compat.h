#ifndef STRACE_GO_EBPF_BPF_UAPI_COMPAT_H
#define STRACE_GO_EBPF_BPF_UAPI_COMPAT_H

#include <linux/bpf.h>
#include <stdint.h>
#include <string.h>

/*
 * Distribution linux/bpf.h headers can lag behind the kernel UAPI used by
 * these probes. Keep the command numbers and 64-bit userspace attr layout in
 * one place so old headers do not change the bytes sent to the kernel.
 */
enum {
	STRACE_BPF_ENABLE_STATS = 32,
	STRACE_BPF_ITER_CREATE = 33,
	STRACE_BPF_TOKEN_CREATE = 36,
	STRACE_BPF_PROG_STREAM_READ_BY_FD = 37,
	STRACE_BPF_PROG_ASSOC_STRUCT_OPS = 38,
	STRACE_BPF_STREAM_STDOUT = 1,

	STRACE_BPF_TOKEN_CREATE_FLAGS_OFFSET = 0,
	STRACE_BPF_TOKEN_CREATE_BPFFS_FD_OFFSET = 4,
	STRACE_BPF_PROG_STREAM_READ_STREAM_BUF_OFFSET = 0,
	STRACE_BPF_PROG_STREAM_READ_STREAM_BUF_LEN_OFFSET = 8,
	STRACE_BPF_PROG_STREAM_READ_STREAM_ID_OFFSET = 12,
	STRACE_BPF_PROG_STREAM_READ_PROG_FD_OFFSET = 16,
	STRACE_BPF_PROG_ASSOC_STRUCT_OPS_MAP_FD_OFFSET = 0,
	STRACE_BPF_PROG_ASSOC_STRUCT_OPS_PROG_FD_OFFSET = 4,
	STRACE_BPF_PROG_ASSOC_STRUCT_OPS_FLAGS_OFFSET = 8,
	STRACE_BPF_ATTR_MIN_SIZE = 24,
};

_Static_assert(sizeof(uintptr_t) == sizeof(uint64_t),
	"BPF fixture requires a native 64-bit userspace ABI");
_Static_assert(sizeof(union bpf_attr) >= STRACE_BPF_ATTR_MIN_SIZE,
	"host BPF UAPI attr is smaller than the fixture ABI");

static inline void strace_bpf_attr_set_u32(
	union bpf_attr *attr,
	size_t offset,
	uint32_t value)
{
	memcpy((unsigned char *)attr + offset, &value, sizeof(value));
}

static inline void strace_bpf_attr_set_u64(
	union bpf_attr *attr,
	size_t offset,
	uint64_t value)
{
	memcpy((unsigned char *)attr + offset, &value, sizeof(value));
}

#endif
