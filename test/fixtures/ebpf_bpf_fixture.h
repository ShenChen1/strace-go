#ifndef STRACE_GO_EBPF_BPF_FIXTURE_H
#define STRACE_GO_EBPF_BPF_FIXTURE_H

#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>

long bpf_call(uint32_t command, union bpf_attr *attr, size_t size);
int run_map_elem_ops(uint32_t map_fd);
int run_large_map_value_ops(void);
int run_prog_query(void);
int run_task_fd_query(void);
int run_uprobe_multi(const char *binary_path);

#endif
