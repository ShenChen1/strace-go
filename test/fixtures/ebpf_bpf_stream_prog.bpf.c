#include "../../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef BPF_STDOUT
#define BPF_STDOUT 1
#endif

extern int bpf_stream_vprintk(int stream_id, const char *fmt,
				      const void *args, __u32 len) __weak __ksym;

SEC("syscall")
int stream_syscall(void *ctx)
{
	(void)ctx;
	__u64 args[1] = {};
	if (bpf_stream_vprintk) {
		bpf_stream_vprintk(BPF_STDOUT, "stream-data", args, sizeof(args));
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
