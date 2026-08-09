package main

type semanticOverrideSpec struct {
	Reason       string
	OverrideArgs []string
	OverrideType []string
	BTFArgs      []string
	BTFType      []string
}

// semanticOverrideSpecs documents intentional strace-facing signature overrides.
// Each row matches both sides exactly so new BTF or override drift stays visible.
var semanticOverrideSpecs = map[string]semanticOverrideSpec{
	"adjtimex": {
		Reason:       "strace_timex_struct",
		OverrideArgs: []string{"txc_p"},
		OverrideType: []string{"struct timex *"},
		BTFArgs:      []string{"txc_p"},
		BTFType:      []string{"struct __kernel_timex *"},
	},
	"bpf": {
		Reason:       "strace_bpf_attr_signature",
		OverrideArgs: []string{"cmd", "attr", "size"},
		OverrideType: []string{"int", "void *", "unsigned int"},
		BTFArgs:      []string{"cmd", "uattr", "size"},
		BTFType:      []string{"enum bpf_cmd", "bpfptr_t", "unsigned int"},
	},
	"execveat": {
		Reason:       "strace_execveat_signature",
		OverrideArgs: []string{"dfd", "filename", "argv", "envp", "flags"},
		OverrideType: []string{"int", "const char *", "const char *const *", "const char *const *", "int"},
		BTFArgs:      []string{"fd", "filename", "argv", "envp", "flags"},
		BTFType:      []string{"int", "const char *", "const char *const *", "const char *const *", "int"},
	},
	"fstat": {
		Reason:       "strace_stat_struct",
		OverrideArgs: []string{"fd", "statbuf"},
		OverrideType: []string{"int", "struct stat *"},
		BTFArgs:      []string{"fd", "statbuf"},
		BTFType:      []string{"unsigned int", "struct __old_kernel_stat *"},
	},
	"getsockname": {
		Reason:       "strace_socket_signature",
		OverrideArgs: []string{"fd", "usockaddr", "usockaddr_len"},
		OverrideType: []string{"int", "struct sockaddr *", "int *"},
		BTFArgs:      []string{"fd", "usockaddr", "usockaddr_len", "peer"},
		BTFType:      []string{"int", "struct sockaddr *", "int *", "int"},
	},
	"lstat": {
		Reason:       "strace_stat_struct",
		OverrideArgs: []string{"filename", "statbuf"},
		OverrideType: []string{"const char *", "struct stat *"},
		BTFArgs:      []string{"filename", "statbuf"},
		BTFType:      []string{"const char *", "struct __old_kernel_stat *"},
	},
	"map_shadow_stack": {
		Reason:       "strace_pointer_types",
		OverrideArgs: []string{"addr", "size", "flags"},
		OverrideType: []string{"void *", "size_t", "unsigned int"},
		BTFArgs:      []string{"addr", "size", "flags"},
		BTFType:      []string{"long unsigned int", "long unsigned int", "unsigned int"},
	},
	"mmap": {
		Reason:       "strace_mmap_signature",
		OverrideArgs: []string{"addr", "len", "prot", "flags", "fd", "off"},
		OverrideType: []string{"const void *", "size_t", "unsigned long", "unsigned long", "int", "kernel_off_t"},
		BTFArgs:      []string{"addr", "len", "prot", "flags", "fd", "pgoff"},
		BTFType:      []string{"long unsigned int", "long unsigned int", "long unsigned int", "long unsigned int", "long unsigned int", "long unsigned int"},
	},
	"mremap": {
		Reason:       "strace_pointer_types",
		OverrideArgs: []string{"addr", "old_len", "new_len", "flags", "new_addr"},
		OverrideType: []string{"const void *", "unsigned long", "unsigned long", "unsigned long", "const void *"},
		BTFArgs:      []string{"addr", "old_len", "new_len", "flags", "new_addr"},
		BTFType:      []string{"long unsigned int", "long unsigned int", "long unsigned int", "long unsigned int", "long unsigned int"},
	},
	"mprotect": {
		Reason:       "strace_pointer_types",
		OverrideArgs: []string{"start", "len", "prot"},
		OverrideType: []string{"const void *", "size_t", "unsigned long"},
		BTFArgs:      []string{"start", "len", "prot"},
		BTFType:      []string{"unsigned long", "size_t", "unsigned long"},
	},
	"msync": {
		Reason:       "strace_pointer_types",
		OverrideArgs: []string{"addr", "len", "flags"},
		OverrideType: []string{"const void *", "size_t", "int"},
		BTFArgs:      []string{"start", "len", "flags"},
		BTFType:      []string{"long unsigned int", "size_t", "int"},
	},
	"recvmsg": {
		Reason:       "strace_msghdr_signature",
		OverrideArgs: []string{"fd", "msg", "flags"},
		OverrideType: []string{"int", "struct msghdr *", "unsigned int"},
		BTFArgs:      []string{"fd", "msg", "flags", "forbid_cmsg_compat"},
		BTFType:      []string{"int", "struct user_msghdr *", "unsigned int", "bool"},
	},
	"sendmsg": {
		Reason:       "strace_msghdr_signature",
		OverrideArgs: []string{"fd", "msg", "flags"},
		OverrideType: []string{"int", "struct msghdr *", "unsigned int"},
		BTFArgs:      []string{"fd", "msg", "flags", "forbid_cmsg_compat"},
		BTFType:      []string{"int", "struct user_msghdr *", "unsigned int", "bool"},
	},
	"setsockopt": {
		Reason:       "strace_socket_signature",
		OverrideArgs: []string{"fd", "level", "optname", "optval", "optlen"},
		OverrideType: []string{"int", "int", "int", "char *", "int"},
		BTFArgs:      []string{"fd", "level", "optname", "user_optval", "optlen"},
		BTFType:      []string{"int", "int", "int", "char *", "int"},
	},
	"stat": {
		Reason:       "strace_stat_struct",
		OverrideArgs: []string{"filename", "statbuf"},
		OverrideType: []string{"const char *", "struct stat *"},
		BTFArgs:      []string{"filename", "statbuf"},
		BTFType:      []string{"const char *", "struct __old_kernel_stat *"},
	},
	"uname": {
		Reason:       "strace_utsname_struct",
		OverrideArgs: []string{"name"},
		OverrideType: []string{"struct utsname *"},
		BTFArgs:      []string{"name"},
		BTFType:      []string{"struct old_utsname *"},
	},
	"ustat": {
		Reason:       "strace_dev_t",
		OverrideArgs: []string{"dev", "ubuf"},
		OverrideType: []string{"dev_t", "struct ustat *"},
		BTFArgs:      []string{"dev", "ubuf"},
		BTFType:      []string{"unsigned int", "struct ustat *"},
	},
	"munmap": {
		Reason:       "strace_pointer_types",
		OverrideArgs: []string{"addr", "len"},
		OverrideType: []string{"const void *", "size_t"},
		BTFArgs:      []string{"addr", "len"},
		BTFType:      []string{"unsigned long", "size_t"},
	},
}

var semanticOverrides = buildSemanticOverrides()

func buildSemanticOverrides() map[string]SyscallMeta {
	result := make(map[string]SyscallMeta, len(semanticOverrideSpecs))
	for name, spec := range semanticOverrideSpecs {
		result[name] = SyscallMeta{
			Name:     name,
			Args:     append([]string(nil), spec.OverrideArgs...),
			ArgTypes: append([]string(nil), spec.OverrideType...),
		}
	}
	return result
}
