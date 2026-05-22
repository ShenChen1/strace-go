package meta
type XlatVal struct { Val uint64; Str string }
type XlatTable struct { Prefix string; Entries []XlatVal }
var XlatTables = map[string]XlatTable{
	"access_modes": {
		Prefix: "",
		Entries: []XlatVal{
			{Val: 0, Str: "F_OK"},
			{Val: 4, Str: "R_OK"},
			{Val: 2, Str: "W_OK"},
			{Val: 1, Str: "X_OK"},
		},
	},
	"addrfams": {
		Prefix: "AF_",
		Entries: []XlatVal{
			{Val: 0, Str: "AF_UNSPEC"},
			{Val: 1, Str: "AF_UNIX"},
			{Val: 2, Str: "AF_INET"},
			{Val: 3, Str: "AF_AX25"},
			{Val: 4, Str: "AF_IPX"},
			{Val: 5, Str: "AF_APPLETALK"},
			{Val: 6, Str: "AF_NETROM"},
			{Val: 7, Str: "AF_BRIDGE"},
			{Val: 8, Str: "AF_ATMPVC"},
			{Val: 9, Str: "AF_X25"},
			{Val: 10, Str: "AF_INET6"},
			{Val: 11, Str: "AF_ROSE"},
			{Val: 12, Str: "AF_DECnet"},
			{Val: 13, Str: "AF_NETBEUI"},
			{Val: 14, Str: "AF_SECURITY"},
			{Val: 15, Str: "AF_KEY"},
			{Val: 16, Str: "AF_NETLINK"},
			{Val: 17, Str: "AF_PACKET"},
			{Val: 18, Str: "AF_ASH"},
			{Val: 19, Str: "AF_ECONET"},
			{Val: 20, Str: "AF_ATMSVC"},
			{Val: 21, Str: "AF_RDS"},
			{Val: 22, Str: "AF_SNA"},
			{Val: 23, Str: "AF_IRDA"},
			{Val: 24, Str: "AF_PPPOX"},
			{Val: 25, Str: "AF_WANPIPE"},
			{Val: 26, Str: "AF_LLC"},
			{Val: 27, Str: "AF_IB"},
			{Val: 28, Str: "AF_MPLS"},
			{Val: 29, Str: "AF_CAN"},
			{Val: 30, Str: "AF_TIPC"},
			{Val: 31, Str: "AF_BLUETOOTH"},
			{Val: 32, Str: "AF_IUCV"},
			{Val: 33, Str: "AF_RXRPC"},
			{Val: 34, Str: "AF_ISDN"},
			{Val: 35, Str: "AF_PHONET"},
			{Val: 36, Str: "AF_IEEE802154"},
			{Val: 37, Str: "AF_CAIF"},
			{Val: 38, Str: "AF_ALG"},
			{Val: 39, Str: "AF_NFC"},
			{Val: 40, Str: "AF_VSOCK"},
			{Val: 41, Str: "AF_KCM"},
			{Val: 42, Str: "AF_QIPCRTR"},
			{Val: 43, Str: "AF_SMC"},
			{Val: 44, Str: "AF_XDP"},
			{Val: 45, Str: "AF_MCTP"},
		},
	},
	"adjtimex_status": {
		Prefix: "STA_",
		Entries: []XlatVal{
			{Val: 1, Str: "STA_PLL"},
			{Val: 2, Str: "STA_PPSFREQ"},
			{Val: 4, Str: "STA_PPSTIME"},
			{Val: 8, Str: "STA_FLL"},
			{Val: 16, Str: "STA_INS"},
			{Val: 32, Str: "STA_DEL"},
			{Val: 64, Str: "STA_UNSYNC"},
			{Val: 128, Str: "STA_FREQHOLD"},
			{Val: 256, Str: "STA_PPSSIGNAL"},
			{Val: 512, Str: "STA_PPSJITTER"},
			{Val: 1024, Str: "STA_PPSWANDER"},
			{Val: 2048, Str: "STA_PPSERROR"},
			{Val: 4096, Str: "STA_CLOCKERR"},
			{Val: 8192, Str: "STA_NANO"},
			{Val: 16384, Str: "STA_MODE"},
			{Val: 32768, Str: "STA_CLK"},
		},
	},
	"archvals": {
		Prefix: "ARCH_",
		Entries: []XlatVal{
			{Val: 4097, Str: "ARCH_SET_GS"},
			{Val: 4098, Str: "ARCH_SET_FS"},
			{Val: 4099, Str: "ARCH_GET_FS"},
			{Val: 4100, Str: "ARCH_GET_GS"},
			{Val: 4113, Str: "ARCH_GET_CPUID"},
			{Val: 4114, Str: "ARCH_SET_CPUID"},
			{Val: 4129, Str: "ARCH_GET_XCOMP_SUPP"},
			{Val: 4130, Str: "ARCH_GET_XCOMP_PERM"},
			{Val: 4131, Str: "ARCH_REQ_XCOMP_PERM"},
			{Val: 4132, Str: "ARCH_GET_XCOMP_GUEST_PERM"},
			{Val: 4133, Str: "ARCH_REQ_XCOMP_GUEST_PERM"},
			{Val: 8193, Str: "ARCH_MAP_VDSO_X32"},
			{Val: 8194, Str: "ARCH_MAP_VDSO_32"},
			{Val: 8195, Str: "ARCH_MAP_VDSO_64"},
			{Val: 16385, Str: "ARCH_GET_UNTAG_MASK"},
			{Val: 16386, Str: "ARCH_ENABLE_TAGGED_ADDR"},
			{Val: 16387, Str: "ARCH_GET_MAX_TAG_BITS"},
			{Val: 16388, Str: "ARCH_FORCE_TAGGED_SVA"},
			{Val: 20481, Str: "ARCH_SHSTK_ENABLE"},
			{Val: 20482, Str: "ARCH_SHSTK_DISABLE"},
			{Val: 20483, Str: "ARCH_SHSTK_LOCK"},
			{Val: 20484, Str: "ARCH_SHSTK_UNLOCK"},
			{Val: 20485, Str: "ARCH_SHSTK_STATUS"},
		},
	},
	"at_flags": {
		Prefix: "AT_",
		Entries: []XlatVal{
			{Val: 256, Str: "AT_SYMLINK_NOFOLLOW"},
			{Val: 512, Str: "AT_REMOVEDIR"},
			{Val: 1024, Str: "AT_SYMLINK_FOLLOW"},
			{Val: 2048, Str: "AT_NO_AUTOMOUNT"},
			{Val: 4096, Str: "AT_EMPTY_PATH"},
			{Val: 32768, Str: "AT_RECURSIVE"},
		},
	},
	"bpf_attach_type": {
		Prefix: "BPF_",
		Entries: []XlatVal{
			{Val: 1, Str: "BPF_CGROUP_INET_EGRESS"},
			{Val: 2, Str: "BPF_CGROUP_INET_SOCK_CREATE"},
			{Val: 3, Str: "BPF_CGROUP_SOCK_OPS"},
			{Val: 4, Str: "BPF_SK_SKB_STREAM_PARSER"},
			{Val: 5, Str: "BPF_SK_SKB_STREAM_VERDICT"},
			{Val: 6, Str: "BPF_CGROUP_DEVICE"},
			{Val: 7, Str: "BPF_SK_MSG_VERDICT"},
			{Val: 8, Str: "BPF_CGROUP_INET4_BIND"},
			{Val: 9, Str: "BPF_CGROUP_INET6_BIND"},
			{Val: 10, Str: "BPF_CGROUP_INET4_CONNECT"},
			{Val: 11, Str: "BPF_CGROUP_INET6_CONNECT"},
			{Val: 12, Str: "BPF_CGROUP_INET4_POST_BIND"},
			{Val: 13, Str: "BPF_CGROUP_INET6_POST_BIND"},
			{Val: 14, Str: "BPF_CGROUP_UDP4_SENDMSG"},
			{Val: 15, Str: "BPF_CGROUP_UDP6_SENDMSG"},
			{Val: 16, Str: "BPF_LIRC_MODE2"},
			{Val: 17, Str: "BPF_FLOW_DISSECTOR"},
			{Val: 18, Str: "BPF_CGROUP_SYSCTL"},
			{Val: 19, Str: "BPF_CGROUP_UDP4_RECVMSG"},
			{Val: 20, Str: "BPF_CGROUP_UDP6_RECVMSG"},
			{Val: 21, Str: "BPF_CGROUP_GETSOCKOPT"},
			{Val: 22, Str: "BPF_CGROUP_SETSOCKOPT"},
			{Val: 23, Str: "BPF_TRACE_RAW_TP"},
			{Val: 24, Str: "BPF_TRACE_FENTRY"},
			{Val: 25, Str: "BPF_TRACE_FEXIT"},
			{Val: 26, Str: "BPF_MODIFY_RETURN"},
			{Val: 27, Str: "BPF_LSM_MAC"},
			{Val: 28, Str: "BPF_TRACE_ITER"},
			{Val: 29, Str: "BPF_CGROUP_INET4_GETPEERNAME"},
			{Val: 30, Str: "BPF_CGROUP_INET6_GETPEERNAME"},
			{Val: 31, Str: "BPF_CGROUP_INET4_GETSOCKNAME"},
			{Val: 32, Str: "BPF_CGROUP_INET6_GETSOCKNAME"},
			{Val: 33, Str: "BPF_XDP_DEVMAP"},
			{Val: 34, Str: "BPF_CGROUP_INET_SOCK_RELEASE"},
			{Val: 35, Str: "BPF_XDP_CPUMAP"},
			{Val: 36, Str: "BPF_SK_LOOKUP"},
			{Val: 37, Str: "BPF_XDP"},
			{Val: 38, Str: "BPF_SK_SKB_VERDICT"},
			{Val: 39, Str: "BPF_SK_REUSEPORT_SELECT"},
			{Val: 40, Str: "BPF_SK_REUSEPORT_SELECT_OR_MIGRATE"},
			{Val: 41, Str: "BPF_PERF_EVENT"},
			{Val: 42, Str: "BPF_TRACE_KPROBE_MULTI"},
			{Val: 43, Str: "BPF_LSM_CGROUP"},
			{Val: 44, Str: "BPF_STRUCT_OPS"},
			{Val: 45, Str: "BPF_NETFILTER"},
			{Val: 46, Str: "BPF_TCX_INGRESS"},
			{Val: 47, Str: "BPF_TCX_EGRESS"},
			{Val: 48, Str: "BPF_TRACE_UPROBE_MULTI"},
			{Val: 49, Str: "BPF_CGROUP_UNIX_CONNECT"},
			{Val: 50, Str: "BPF_CGROUP_UNIX_SENDMSG"},
			{Val: 51, Str: "BPF_CGROUP_UNIX_RECVMSG"},
			{Val: 52, Str: "BPF_CGROUP_UNIX_GETPEERNAME"},
			{Val: 53, Str: "BPF_CGROUP_UNIX_GETSOCKNAME"},
			{Val: 54, Str: "BPF_NETKIT_PRIMARY"},
			{Val: 55, Str: "BPF_NETKIT_PEER"},
			{Val: 56, Str: "BPF_TRACE_KPROBE_SESSION"},
			{Val: 57, Str: "BPF_TRACE_UPROBE_SESSION"},
			{Val: 58, Str: "BPF_TRACE_FSESSION"},
		},
	},
	"bpf_commands": {
		Prefix: "BPF_",
		Entries: []XlatVal{
			{Val: 0, Str: "BPF_MAP_CREATE"},
			{Val: 1, Str: "BPF_MAP_LOOKUP_ELEM"},
			{Val: 2, Str: "BPF_MAP_UPDATE_ELEM"},
			{Val: 3, Str: "BPF_MAP_DELETE_ELEM"},
			{Val: 4, Str: "BPF_MAP_GET_NEXT_KEY"},
			{Val: 5, Str: "BPF_PROG_LOAD"},
			{Val: 6, Str: "BPF_OBJ_PIN"},
			{Val: 7, Str: "BPF_OBJ_GET"},
			{Val: 8, Str: "BPF_PROG_ATTACH"},
			{Val: 9, Str: "BPF_PROG_DETACH"},
			{Val: 10, Str: "BPF_PROG_TEST_RUN"},
			{Val: 11, Str: "BPF_PROG_GET_NEXT_ID"},
			{Val: 12, Str: "BPF_MAP_GET_NEXT_ID"},
			{Val: 13, Str: "BPF_PROG_GET_FD_BY_ID"},
			{Val: 14, Str: "BPF_MAP_GET_FD_BY_ID"},
			{Val: 15, Str: "BPF_OBJ_GET_INFO_BY_FD"},
			{Val: 16, Str: "BPF_PROG_QUERY"},
			{Val: 17, Str: "BPF_RAW_TRACEPOINT_OPEN"},
			{Val: 18, Str: "BPF_BTF_LOAD"},
			{Val: 19, Str: "BPF_BTF_GET_FD_BY_ID"},
			{Val: 20, Str: "BPF_TASK_FD_QUERY"},
			{Val: 21, Str: "BPF_MAP_LOOKUP_AND_DELETE_ELEM"},
			{Val: 22, Str: "BPF_MAP_FREEZE"},
			{Val: 23, Str: "BPF_BTF_GET_NEXT_ID"},
			{Val: 24, Str: "BPF_MAP_LOOKUP_BATCH"},
			{Val: 25, Str: "BPF_MAP_LOOKUP_AND_DELETE_BATCH"},
			{Val: 26, Str: "BPF_MAP_UPDATE_BATCH"},
			{Val: 27, Str: "BPF_MAP_DELETE_BATCH"},
			{Val: 28, Str: "BPF_LINK_CREATE"},
			{Val: 29, Str: "BPF_LINK_UPDATE"},
			{Val: 30, Str: "BPF_LINK_GET_FD_BY_ID"},
			{Val: 31, Str: "BPF_LINK_GET_NEXT_ID"},
			{Val: 32, Str: "BPF_ENABLE_STATS"},
			{Val: 33, Str: "BPF_ITER_CREATE"},
			{Val: 34, Str: "BPF_LINK_DETACH"},
			{Val: 35, Str: "BPF_PROG_BIND_MAP"},
			{Val: 36, Str: "BPF_TOKEN_CREATE"},
			{Val: 37, Str: "BPF_PROG_STREAM_READ_BY_FD"},
			{Val: 38, Str: "BPF_PROG_ASSOC_STRUCT_OPS"},
		},
	},
	"bpf_map_flags": {
		Prefix: "BPF_F_",
		Entries: []XlatVal{
			{Val: 1, Str: "BPF_F_NO_PREALLOC"},
			{Val: 2, Str: "BPF_F_NO_COMMON_LRU"},
			{Val: 4, Str: "BPF_F_NUMA_NODE"},
			{Val: 8, Str: "BPF_F_RDONLY"},
			{Val: 16, Str: "BPF_F_WRONLY"},
			{Val: 32, Str: "BPF_F_STACK_BUILD_ID"},
			{Val: 64, Str: "BPF_F_ZERO_SEED"},
			{Val: 128, Str: "BPF_F_RDONLY_PROG"},
			{Val: 256, Str: "BPF_F_WRONLY_PROG"},
			{Val: 512, Str: "BPF_F_CLONE"},
			{Val: 1024, Str: "BPF_F_MMAPABLE"},
			{Val: 2048, Str: "BPF_F_PRESERVE_ELEMS"},
			{Val: 4096, Str: "BPF_F_INNER_MAP"},
			{Val: 8192, Str: "BPF_F_LINK"},
		},
	},
	"bpf_map_types": {
		Prefix: "BPF_MAP_TYPE_",
		Entries: []XlatVal{
			{Val: 0, Str: "BPF_MAP_TYPE_UNSPEC"},
			{Val: 1, Str: "BPF_MAP_TYPE_HASH"},
			{Val: 2, Str: "BPF_MAP_TYPE_ARRAY"},
			{Val: 3, Str: "BPF_MAP_TYPE_PROG_ARRAY"},
			{Val: 4, Str: "BPF_MAP_TYPE_PERF_EVENT_ARRAY"},
			{Val: 5, Str: "BPF_MAP_TYPE_PERCPU_HASH"},
			{Val: 6, Str: "BPF_MAP_TYPE_PERCPU_ARRAY"},
			{Val: 7, Str: "BPF_MAP_TYPE_STACK_TRACE"},
			{Val: 8, Str: "BPF_MAP_TYPE_CGROUP_ARRAY"},
			{Val: 9, Str: "BPF_MAP_TYPE_LRU_HASH"},
			{Val: 10, Str: "BPF_MAP_TYPE_LRU_PERCPU_HASH"},
			{Val: 11, Str: "BPF_MAP_TYPE_LPM_TRIE"},
			{Val: 12, Str: "BPF_MAP_TYPE_ARRAY_OF_MAPS"},
			{Val: 13, Str: "BPF_MAP_TYPE_HASH_OF_MAPS"},
			{Val: 14, Str: "BPF_MAP_TYPE_DEVMAP"},
			{Val: 15, Str: "BPF_MAP_TYPE_SOCKMAP"},
			{Val: 16, Str: "BPF_MAP_TYPE_CPUMAP"},
			{Val: 17, Str: "BPF_MAP_TYPE_XSKMAP"},
			{Val: 18, Str: "BPF_MAP_TYPE_SOCKHASH"},
			{Val: 19, Str: "BPF_MAP_TYPE_CGROUP_STORAGE"},
			{Val: 20, Str: "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY"},
			{Val: 21, Str: "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE"},
			{Val: 22, Str: "BPF_MAP_TYPE_QUEUE"},
			{Val: 23, Str: "BPF_MAP_TYPE_STACK"},
			{Val: 24, Str: "BPF_MAP_TYPE_SK_STORAGE"},
			{Val: 25, Str: "BPF_MAP_TYPE_DEVMAP_HASH"},
			{Val: 26, Str: "BPF_MAP_TYPE_STRUCT_OPS"},
			{Val: 27, Str: "BPF_MAP_TYPE_RINGBUF"},
			{Val: 28, Str: "BPF_MAP_TYPE_INODE_STORAGE"},
			{Val: 29, Str: "BPF_MAP_TYPE_TASK_STORAGE"},
			{Val: 30, Str: "BPF_MAP_TYPE_BLOOM_FILTER"},
			{Val: 31, Str: "BPF_MAP_TYPE_USER_RINGBUF"},
			{Val: 32, Str: "BPF_MAP_TYPE_CGRP_STORAGE"},
			{Val: 33, Str: "BPF_MAP_TYPE_ARENA"},
			{Val: 34, Str: "BPF_MAP_TYPE_INSN_ARRAY"},
		},
	},
	"bpf_prog_flags": {
		Prefix: "BPF_F_",
		Entries: []XlatVal{
			{Val: 1, Str: "BPF_F_STRICT_ALIGNMENT"},
			{Val: 2, Str: "BPF_F_ANY_ALIGNMENT"},
			{Val: 4, Str: "BPF_F_TEST_RND_HI32"},
			{Val: 8, Str: "BPF_F_TEST_STATE_FREQ"},
			{Val: 16, Str: "BPF_F_SLEEPABLE"},
			{Val: 32, Str: "BPF_F_XDP_HAS_FRAGS"},
			{Val: 64, Str: "BPF_F_XDP_DEV_BOUND_ONLY"},
			{Val: 128, Str: "BPF_F_TEST_REG_INVARIANTS"},
		},
	},
	"bpf_prog_types": {
		Prefix: "BPF_PROG_TYPE_",
		Entries: []XlatVal{
			{Val: 1, Str: "BPF_PROG_TYPE_SOCKET_FILTER"},
			{Val: 2, Str: "BPF_PROG_TYPE_KPROBE"},
			{Val: 3, Str: "BPF_PROG_TYPE_SCHED_CLS"},
			{Val: 4, Str: "BPF_PROG_TYPE_SCHED_ACT"},
			{Val: 5, Str: "BPF_PROG_TYPE_TRACEPOINT"},
			{Val: 6, Str: "BPF_PROG_TYPE_XDP"},
			{Val: 7, Str: "BPF_PROG_TYPE_PERF_EVENT"},
			{Val: 8, Str: "BPF_PROG_TYPE_CGROUP_SKB"},
			{Val: 9, Str: "BPF_PROG_TYPE_CGROUP_SOCK"},
			{Val: 10, Str: "BPF_PROG_TYPE_LWT_IN"},
			{Val: 11, Str: "BPF_PROG_TYPE_LWT_OUT"},
			{Val: 12, Str: "BPF_PROG_TYPE_LWT_XMIT"},
			{Val: 13, Str: "BPF_PROG_TYPE_SOCK_OPS"},
			{Val: 14, Str: "BPF_PROG_TYPE_SK_SKB"},
			{Val: 15, Str: "BPF_PROG_TYPE_CGROUP_DEVICE"},
			{Val: 16, Str: "BPF_PROG_TYPE_SK_MSG"},
			{Val: 17, Str: "BPF_PROG_TYPE_RAW_TRACEPOINT"},
			{Val: 18, Str: "BPF_PROG_TYPE_CGROUP_SOCK_ADDR"},
			{Val: 19, Str: "BPF_PROG_TYPE_LWT_SEG6LOCAL"},
			{Val: 20, Str: "BPF_PROG_TYPE_LIRC_MODE2"},
			{Val: 21, Str: "BPF_PROG_TYPE_SK_REUSEPORT"},
			{Val: 22, Str: "BPF_PROG_TYPE_FLOW_DISSECTOR"},
			{Val: 23, Str: "BPF_PROG_TYPE_CGROUP_SYSCTL"},
			{Val: 24, Str: "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE"},
			{Val: 25, Str: "BPF_PROG_TYPE_CGROUP_SOCKOPT"},
			{Val: 26, Str: "BPF_PROG_TYPE_TRACING"},
			{Val: 27, Str: "BPF_PROG_TYPE_STRUCT_OPS"},
			{Val: 28, Str: "BPF_PROG_TYPE_EXT"},
			{Val: 29, Str: "BPF_PROG_TYPE_LSM"},
			{Val: 30, Str: "BPF_PROG_TYPE_SK_LOOKUP"},
			{Val: 31, Str: "BPF_PROG_TYPE_SYSCALL"},
			{Val: 32, Str: "BPF_PROG_TYPE_NETFILTER"},
		},
	},
	"clone_flags": {
		Prefix: "CLONE_",
		Entries: []XlatVal{
			{Val: 256, Str: "CLONE_VM"},
			{Val: 512, Str: "CLONE_FS"},
			{Val: 1024, Str: "CLONE_FILES"},
			{Val: 2048, Str: "CLONE_SIGHAND"},
			{Val: 4096, Str: "CLONE_PIDFD"},
			{Val: 8192, Str: "CLONE_PTRACE"},
			{Val: 16384, Str: "CLONE_VFORK"},
			{Val: 32768, Str: "CLONE_PARENT"},
			{Val: 65536, Str: "CLONE_THREAD"},
			{Val: 131072, Str: "CLONE_NEWNS"},
			{Val: 262144, Str: "CLONE_SYSVSEM"},
			{Val: 524288, Str: "CLONE_SETTLS"},
			{Val: 1048576, Str: "CLONE_PARENT_SETTID"},
			{Val: 2097152, Str: "CLONE_CHILD_CLEARTID"},
			{Val: 8388608, Str: "CLONE_UNTRACED"},
			{Val: 16777216, Str: "CLONE_CHILD_SETTID"},
			{Val: 33554432, Str: "CLONE_NEWCGROUP"},
			{Val: 67108864, Str: "CLONE_NEWUTS"},
			{Val: 134217728, Str: "CLONE_NEWIPC"},
			{Val: 268435456, Str: "CLONE_NEWUSER"},
			{Val: 536870912, Str: "CLONE_NEWPID"},
			{Val: 1073741824, Str: "CLONE_NEWNET"},
			{Val: 2147483648, Str: "CLONE_IO"},
		},
	},
	"dm_flags": {
		Prefix: "DM_",
		Entries: []XlatVal{
			{Val: 1, Str: "DM_READONLY_FLAG"},
			{Val: 2, Str: "DM_SUSPEND_FLAG"},
			{Val: 8, Str: "DM_PERSISTENT_DEV_FLAG"},
			{Val: 16, Str: "DM_STATUS_TABLE_FLAG"},
			{Val: 32, Str: "DM_ACTIVE_PRESENT_FLAG"},
			{Val: 64, Str: "DM_INACTIVE_PRESENT_FLAG"},
			{Val: 256, Str: "DM_BUFFER_FULL_FLAG"},
			{Val: 512, Str: "DM_SKIP_BDGET_FLAG"},
			{Val: 1024, Str: "DM_SKIP_LOCKFS_FLAG"},
			{Val: 2048, Str: "DM_NOFLUSH_FLAG"},
			{Val: 4096, Str: "DM_QUERY_INACTIVE_TABLE_FLAG"},
			{Val: 8192, Str: "DM_UEVENT_GENERATED_FLAG"},
			{Val: 16384, Str: "DM_UUID_FLAG"},
			{Val: 32768, Str: "DM_SECURE_DATA_FLAG"},
			{Val: 65536, Str: "DM_DATA_OUT_FLAG"},
			{Val: 131072, Str: "DM_DEFERRED_REMOVE"},
			{Val: 262144, Str: "DM_INTERNAL_SUSPEND_FLAG"},
			{Val: 524288, Str: "DM_IMA_MEASUREMENT_FLAG"},
		},
	},
	"epollctls": {
		Prefix: "EPOLL_CTL_",
		Entries: []XlatVal{
			{Val: 1, Str: "EPOLL_CTL_ADD"},
			{Val: 2, Str: "EPOLL_CTL_DEL"},
			{Val: 3, Str: "EPOLL_CTL_MOD"},
		},
	},
	"epollevents": {
		Prefix: "EPOLL",
		Entries: []XlatVal{
			{Val: 1, Str: "EPOLLIN"},
			{Val: 2, Str: "EPOLLPRI"},
			{Val: 4, Str: "EPOLLOUT"},
			{Val: 8, Str: "EPOLLERR"},
			{Val: 16, Str: "EPOLLHUP"},
			{Val: 32, Str: "EPOLLNVAL"},
			{Val: 64, Str: "EPOLLRDNORM"},
			{Val: 128, Str: "EPOLLRDBAND"},
			{Val: 256, Str: "EPOLLWRNORM"},
			{Val: 512, Str: "EPOLLWRBAND"},
			{Val: 1024, Str: "EPOLLMSG"},
			{Val: 8192, Str: "EPOLLRDHUP"},
			{Val: 268435456, Str: "EPOLLEXCLUSIVE"},
			{Val: 536870912, Str: "EPOLLWAKEUP"},
			{Val: 1073741824, Str: "EPOLLONESHOT"},
			{Val: 2147483648, Str: "EPOLLET"},
		},
	},
	"epollflags": {
		Prefix: "EPOLL_",
		Entries: []XlatVal{
			{Val: 524288, Str: "EPOLL_CLOEXEC"},
		},
	},
	"futexops": {
		Prefix: "FUTEX_",
		Entries: []XlatVal{
			{Val: 0, Str: "FUTEX_WAIT"},
			{Val: 1, Str: "FUTEX_WAKE"},
			{Val: 2, Str: "FUTEX_FD"},
			{Val: 3, Str: "FUTEX_REQUEUE"},
			{Val: 4, Str: "FUTEX_CMP_REQUEUE"},
			{Val: 5, Str: "FUTEX_WAKE_OP"},
			{Val: 6, Str: "FUTEX_LOCK_PI"},
			{Val: 7, Str: "FUTEX_UNLOCK_PI"},
			{Val: 8, Str: "FUTEX_TRYLOCK_PI"},
			{Val: 9, Str: "FUTEX_WAIT_BITSET"},
			{Val: 10, Str: "FUTEX_WAKE_BITSET"},
			{Val: 11, Str: "FUTEX_WAIT_REQUEUE_PI"},
			{Val: 12, Str: "FUTEX_CMP_REQUEUE_PI"},
			{Val: 13, Str: "FUTEX_LOCK_PI2"},
		},
	},
	"key_spec": {
		Prefix: "KEY_SPEC_",
		Entries: []XlatVal{
			{Val: 18446744073709551615, Str: "KEY_SPEC_THREAD_KEYRING"},
			{Val: 18446744073709551614, Str: "KEY_SPEC_PROCESS_KEYRING"},
			{Val: 18446744073709551613, Str: "KEY_SPEC_SESSION_KEYRING"},
			{Val: 18446744073709551612, Str: "KEY_SPEC_USER_KEYRING"},
			{Val: 18446744073709551611, Str: "KEY_SPEC_USER_SESSION_KEYRING"},
			{Val: 18446744073709551610, Str: "KEY_SPEC_GROUP_KEYRING"},
			{Val: 18446744073709551609, Str: "KEY_SPEC_REQKEY_AUTH_KEY"},
			{Val: 18446744073709551608, Str: "KEY_SPEC_REQUESTOR_KEYRING"},
		},
	},
	"madvise_cmds": {
		Prefix: "MADV_",
		Entries: []XlatVal{
			{Val: 0, Str: "MADV_NORMAL"},
			{Val: 1, Str: "MADV_RANDOM"},
			{Val: 2, Str: "MADV_SEQUENTIAL"},
			{Val: 3, Str: "MADV_WILLNEED"},
			{Val: 4, Str: "MADV_DONTNEED"},
			{Val: 4, Str: "MADV_DONTNEED"},
			{Val: 8, Str: "MADV_FREE"},
			{Val: 9, Str: "MADV_REMOVE"},
			{Val: 10, Str: "MADV_DONTFORK"},
			{Val: 11, Str: "MADV_DOFORK"},
			{Val: 20, Str: "MADV_COLD"},
			{Val: 21, Str: "MADV_PAGEOUT"},
			{Val: 22, Str: "MADV_POPULATE_READ"},
			{Val: 23, Str: "MADV_POPULATE_WRITE"},
			{Val: 24, Str: "MADV_DONTNEED_LOCKED"},
			{Val: 100, Str: "MADV_HWPOISON"},
			{Val: 101, Str: "MADV_SOFT_OFFLINE"},
			{Val: 102, Str: "MADV_GUARD_INSTALL"},
			{Val: 103, Str: "MADV_GUARD_REMOVE"},
		},
	},
	"mmap_flags": {
		Prefix: "",
		Entries: []XlatVal{
			{Val: 1, Str: "MAP_SHARED"},
			{Val: 2, Str: "MAP_PRIVATE"},
			{Val: 3, Str: "MAP_SHARED_VALIDATE"},
			{Val: 8, Str: "MAP_DROPPABLE"},
			{Val: 16, Str: "MAP_FIXED"},
			{Val: 16, Str: "MAP_FIXED"},
			{Val: 16, Str: "MAP_FIXED"},
			{Val: 32, Str: "MAP_ANONYMOUS"},
			{Val: 32, Str: "MAP_ANONYMOUS"},
			{Val: 32, Str: "MAP_ANONYMOUS"},
			{Val: 64, Str: "MAP_32BIT"},
			{Val: 64, Str: "MAP_32BIT"},
			{Val: 128, Str: "MAP_ABOVE4G"},
			{Val: 128, Str: "MAP_ABOVE4G"},
			{Val: 0x20, Str: "MAP_RENAME"},
			{Val: 0x20, Str: "MAP_RENAME"},
			{Val: 16384, Str: "MAP_NORESERVE"},
			{Val: 16384, Str: "MAP_NORESERVE"},
			{Val: 16384, Str: "MAP_NORESERVE"},
			{Val: 16384, Str: "MAP_NORESERVE"},
			{Val: 32768, Str: "MAP_POPULATE"},
			{Val: 32768, Str: "MAP_POPULATE"},
			{Val: 32768, Str: "MAP_POPULATE"},
			{Val: 65536, Str: "MAP_NONBLOCK"},
			{Val: 65536, Str: "MAP_NONBLOCK"},
			{Val: 65536, Str: "MAP_NONBLOCK"},
			{Val: 0x80000000, Str: "_MAP_NEW"},
			{Val: 0x80000000, Str: "_MAP_NEW"},
			{Val: 256, Str: "MAP_GROWSDOWN"},
			{Val: 256, Str: "MAP_GROWSDOWN"},
			{Val: 256, Str: "MAP_GROWSDOWN"},
			{Val: 256, Str: "MAP_GROWSDOWN"},
			{Val: 0x200, Str: "MAP_GROWSUP"},
			{Val: 0x200, Str: "MAP_GROWSUP"},
			{Val: 2048, Str: "MAP_DENYWRITE"},
			{Val: 2048, Str: "MAP_DENYWRITE"},
			{Val: 4096, Str: "MAP_EXECUTABLE"},
			{Val: 4096, Str: "MAP_EXECUTABLE"},
			{Val: 0x80, Str: "MAP_INHERIT"},
			{Val: 0x80, Str: "MAP_INHERIT"},
			{Val: 0x400, Str: "_MAP_INHERIT"},
			{Val: 0x400, Str: "_MAP_INHERIT"},
			{Val: 8192, Str: "MAP_LOCKED"},
			{Val: 8192, Str: "MAP_LOCKED"},
			{Val: 8192, Str: "MAP_LOCKED"},
			{Val: 8192, Str: "MAP_LOCKED"},
			{Val: 0x200, Str: "_MAP_HASSEMAPHORE"},
			{Val: 0x200, Str: "_MAP_HASSEMAPHORE"},
			{Val: 131072, Str: "MAP_STACK"},
			{Val: 131072, Str: "MAP_STACK"},
			{Val: 131072, Str: "MAP_STACK"},
			{Val: 262144, Str: "MAP_HUGETLB"},
			{Val: 262144, Str: "MAP_HUGETLB"},
			{Val: 262144, Str: "MAP_HUGETLB"},
			{Val: 524288, Str: "MAP_SYNC"},
			{Val: 67108864, Str: "MAP_UNINITIALIZED"},
			{Val: 1048576, Str: "MAP_FIXED_NOREPLACE"},
			{Val: 1048576, Str: "MAP_FIXED_NOREPLACE"},
			{Val: 0x40, Str: "MAP_AUTOGROW"},
			{Val: 0x40, Str: "MAP_AUTOGROW"},
			{Val: 0x100, Str: "MAP_AUTORSRV"},
			{Val: 0x100, Str: "MAP_AUTORSRV"},
			{Val: 0x80, Str: "MAP_LOCAL"},
			{Val: 0x80, Str: "MAP_LOCAL"},
			{Val: 0x800, Str: "_MAP_UNALIGNED"},
			{Val: 0x800, Str: "_MAP_UNALIGNED"},
		},
	},
	"mmap_prot": {
		Prefix: "PROT_",
		Entries: []XlatVal{
			{Val: 0, Str: "PROT_NONE"},
			{Val: 1, Str: "PROT_READ"},
			{Val: 2, Str: "PROT_WRITE"},
			{Val: 4, Str: "PROT_EXEC"},
			{Val: 16777216, Str: "PROT_GROWSDOWN"},
			{Val: 33554432, Str: "PROT_GROWSUP"},
		},
	},
	"modetypes": {
		Prefix: "S_",
		Entries: []XlatVal{
			{Val: 32768, Str: "S_IFREG"},
			{Val: 49152, Str: "S_IFSOCK"},
			{Val: 4096, Str: "S_IFIFO"},
			{Val: 40960, Str: "S_IFLNK"},
			{Val: 16384, Str: "S_IFDIR"},
			{Val: 24576, Str: "S_IFBLK"},
			{Val: 8192, Str: "S_IFCHR"},
		},
	},
	"mremap_flags": {
		Prefix: "MREMAP_",
		Entries: []XlatVal{
			{Val: 1, Str: "MREMAP_MAYMOVE"},
			{Val: 2, Str: "MREMAP_FIXED"},
			{Val: 4, Str: "MREMAP_DONTUNMAP"},
		},
	},
	"msg_flags": {
		Prefix: "MSG_",
		Entries: []XlatVal{
			{Val: 0x1, Str: "MSG_OOB"},
			{Val: 0x2, Str: "MSG_PEEK"},
			{Val: 0x4, Str: "MSG_DONTROUTE"},
			{Val: 0x8, Str: "MSG_CTRUNC"},
			{Val: 0x10, Str: "MSG_PROBE"},
			{Val: 0x20, Str: "MSG_TRUNC"},
			{Val: 0x40, Str: "MSG_DONTWAIT"},
			{Val: 0x80, Str: "MSG_EOR"},
			{Val: 0x100, Str: "MSG_WAITALL"},
			{Val: 0x200, Str: "MSG_FIN"},
			{Val: 0x400, Str: "MSG_SYN"},
			{Val: 0x800, Str: "MSG_CONFIRM"},
			{Val: 0x1000, Str: "MSG_RST"},
			{Val: 0x2000, Str: "MSG_ERRQUEUE"},
			{Val: 0x4000, Str: "MSG_NOSIGNAL"},
			{Val: 0x8000, Str: "MSG_MORE"},
			{Val: 0x10000, Str: "MSG_WAITFORONE"},
			{Val: 0x20000, Str: "MSG_SENDPAGE_NOTLAST"},
			{Val: 0x40000, Str: "MSG_BATCH"},
			{Val: 0x80000, Str: "MSG_NO_SHARED_FRAGS"},
			{Val: 0x2000000, Str: "MSG_SOCK_DEVMEM"},
			{Val: 0x4000000, Str: "MSG_ZEROCOPY"},
			{Val: 0x20000000, Str: "MSG_FASTOPEN"},
			{Val: 0x40000000, Str: "MSG_CMSG_CLOEXEC"},
			{Val: 0x80000000, Str: "MSG_CMSG_COMPAT"},
		},
	},
	"netlink_ack_flags": {
		Prefix: "NLM_F_",
		Entries: []XlatVal{
			{Val: 256, Str: "NLM_F_CAPPED"},
			{Val: 512, Str: "NLM_F_ACK_TLVS"},
		},
	},
	"netlink_flags": {
		Prefix: "NLM_F_",
		Entries: []XlatVal{
			{Val: 1, Str: "NLM_F_REQUEST"},
			{Val: 2, Str: "NLM_F_MULTI"},
			{Val: 4, Str: "NLM_F_ACK"},
			{Val: 8, Str: "NLM_F_ECHO"},
			{Val: 16, Str: "NLM_F_DUMP_INTR"},
			{Val: 32, Str: "NLM_F_DUMP_FILTERED"},
		},
	},
	"netlink_get_flags": {
		Prefix: "NLM_F_",
		Entries: []XlatVal{
			{Val: 768, Str: "NLM_F_DUMP"},
			{Val: 256, Str: "NLM_F_ROOT"},
			{Val: 512, Str: "NLM_F_MATCH"},
			{Val: 1024, Str: "NLM_F_ATOMIC"},
		},
	},
	"netlink_new_flags": {
		Prefix: "NLM_F_",
		Entries: []XlatVal{
			{Val: 256, Str: "NLM_F_REPLACE"},
			{Val: 512, Str: "NLM_F_EXCL"},
			{Val: 1024, Str: "NLM_F_CREATE"},
			{Val: 2048, Str: "NLM_F_APPEND"},
		},
	},
	"netlink_protocols": {
		Prefix: "NETLINK_",
		Entries: []XlatVal{
			{Val: 1, Str: "NETLINK_UNUSED"},
			{Val: 2, Str: "NETLINK_USERSOCK"},
			{Val: 3, Str: "NETLINK_FIREWALL"},
			{Val: 4, Str: "NETLINK_SOCK_DIAG"},
			{Val: 5, Str: "NETLINK_NFLOG"},
			{Val: 6, Str: "NETLINK_XFRM"},
			{Val: 7, Str: "NETLINK_SELINUX"},
			{Val: 8, Str: "NETLINK_ISCSI"},
			{Val: 9, Str: "NETLINK_AUDIT"},
			{Val: 10, Str: "NETLINK_FIB_LOOKUP"},
			{Val: 11, Str: "NETLINK_CONNECTOR"},
			{Val: 12, Str: "NETLINK_NETFILTER"},
			{Val: 13, Str: "NETLINK_IP6_FW"},
			{Val: 14, Str: "NETLINK_DNRTMSG"},
			{Val: 15, Str: "NETLINK_KOBJECT_UEVENT"},
			{Val: 16, Str: "NETLINK_GENERIC"},
			{Val: 18, Str: "NETLINK_SCSITRANSPORT"},
			{Val: 19, Str: "NETLINK_ECRYPTFS"},
			{Val: 20, Str: "NETLINK_RDMA"},
			{Val: 21, Str: "NETLINK_CRYPTO"},
			{Val: 22, Str: "NETLINK_SMC"},
		},
	},
	"netlink_types": {
		Prefix: "NLMSG_",
		Entries: []XlatVal{
			{Val: 1, Str: "NLMSG_NOOP"},
			{Val: 2, Str: "NLMSG_ERROR"},
			{Val: 3, Str: "NLMSG_DONE"},
			{Val: 4, Str: "NLMSG_OVERRUN"},
		},
	},
	"open_access_modes": {
		Prefix: "O_",
		Entries: []XlatVal{
			{Val: 0, Str: "O_RDONLY"},
			{Val: 1, Str: "O_WRONLY"},
			{Val: 2, Str: "O_RDWR"},
			{Val: 3, Str: "O_ACCMODE"},
		},
	},
	"open_mode_flags": {
		Prefix: "O_",
		Entries: []XlatVal{
			{Val: 64, Str: "O_CREAT"},
			{Val: 128, Str: "O_EXCL"},
			{Val: 256, Str: "O_NOCTTY"},
			{Val: 512, Str: "O_TRUNC"},
			{Val: 1024, Str: "O_APPEND"},
			{Val: 2048, Str: "O_NONBLOCK"},
			{Val: 1052672, Str: "O_SYNC"},
			{Val: 4096, Str: "O_DSYNC"},
			{Val: 16384, Str: "O_DIRECT"},
			{Val: 131072, Str: "O_NOFOLLOW"},
			{Val: 262144, Str: "O_NOATIME"},
			{Val: 524288, Str: "O_CLOEXEC"},
			{Val: 2097152, Str: "O_PATH"},
			{Val: 4259840, Str: "O_TMPFILE"},
			{Val: 4259840, Str: "__O_TMPFILE"},
			{Val: 65536, Str: "O_DIRECTORY"},
			{Val: 8192, Str: "FASYNC"},
			{Val: 16384, Str: "O_DIRECT"},
			{Val: 4259840, Str: "O_TMPFILE"},
			{Val: 1052672, Str: "O_SYNC"},
			{Val: 4194304, Str: "__O_TMPFILE"},
			{Val: 1048576, Str: "__O_SYNC"},
			{Val: 32768, Str: "O_LARGEFILE"},
		},
	},
	"pollflags": {
		Prefix: "POLL",
		Entries: []XlatVal{
			{Val: 1, Str: "POLLIN"},
			{Val: 2, Str: "POLLPRI"},
			{Val: 4, Str: "POLLOUT"},
			{Val: 8, Str: "POLLERR"},
			{Val: 16, Str: "POLLHUP"},
			{Val: 32, Str: "POLLNVAL"},
			{Val: 64, Str: "POLLRDNORM"},
			{Val: 128, Str: "POLLRDBAND"},
			{Val: 256, Str: "POLLWRNORM"},
			{Val: 512, Str: "POLLWRBAND"},
			{Val: 512, Str: "POLLWRBAND"},
			{Val: 1024, Str: "POLLMSG"},
			{Val: 1024, Str: "POLLMSG"},
			{Val: 4096, Str: "POLLREMOVE"},
			{Val: 4096, Str: "POLLREMOVE"},
			{Val: 4096, Str: "POLLREMOVE"},
			{Val: 8192, Str: "POLLRDHUP"},
			{Val: 8192, Str: "POLLRDHUP"},
			{Val: 32768, Str: "POLL_BUSY_LOOP"},
		},
	},
	"prctl_options": {
		Prefix: "PR_",
		Entries: []XlatVal{
			{Val: 1, Str: "PR_SET_PDEATHSIG"},
			{Val: 2, Str: "PR_GET_PDEATHSIG"},
			{Val: 3, Str: "PR_GET_DUMPABLE"},
			{Val: 4, Str: "PR_SET_DUMPABLE"},
			{Val: 5, Str: "PR_GET_UNALIGN"},
			{Val: 6, Str: "PR_SET_UNALIGN"},
			{Val: 7, Str: "PR_GET_KEEPCAPS"},
			{Val: 8, Str: "PR_SET_KEEPCAPS"},
			{Val: 9, Str: "PR_GET_FPEMU"},
			{Val: 10, Str: "PR_SET_FPEMU"},
			{Val: 11, Str: "PR_GET_FPEXC"},
			{Val: 12, Str: "PR_SET_FPEXC"},
			{Val: 13, Str: "PR_GET_TIMING"},
			{Val: 14, Str: "PR_SET_TIMING"},
			{Val: 15, Str: "PR_SET_NAME"},
			{Val: 16, Str: "PR_GET_NAME"},
			{Val: 19, Str: "PR_GET_ENDIAN"},
			{Val: 20, Str: "PR_SET_ENDIAN"},
			{Val: 21, Str: "PR_GET_SECCOMP"},
			{Val: 22, Str: "PR_SET_SECCOMP"},
			{Val: 23, Str: "PR_CAPBSET_READ"},
			{Val: 24, Str: "PR_CAPBSET_DROP"},
			{Val: 25, Str: "PR_GET_TSC"},
			{Val: 26, Str: "PR_SET_TSC"},
			{Val: 27, Str: "PR_GET_SECUREBITS"},
			{Val: 28, Str: "PR_SET_SECUREBITS"},
			{Val: 29, Str: "PR_SET_TIMERSLACK"},
			{Val: 30, Str: "PR_GET_TIMERSLACK"},
			{Val: 31, Str: "PR_TASK_PERF_EVENTS_DISABLE"},
			{Val: 32, Str: "PR_TASK_PERF_EVENTS_ENABLE"},
			{Val: 33, Str: "PR_MCE_KILL"},
			{Val: 34, Str: "PR_MCE_KILL_GET"},
			{Val: 35, Str: "PR_SET_MM"},
			{Val: 36, Str: "PR_SET_CHILD_SUBREAPER"},
			{Val: 37, Str: "PR_GET_CHILD_SUBREAPER"},
			{Val: 38, Str: "PR_SET_NO_NEW_PRIVS"},
			{Val: 39, Str: "PR_GET_NO_NEW_PRIVS"},
			{Val: 40, Str: "PR_GET_TID_ADDRESS"},
			{Val: 41, Str: "PR_SET_THP_DISABLE"},
			{Val: 42, Str: "PR_GET_THP_DISABLE"},
			{Val: 43, Str: "PR_MPX_ENABLE_MANAGEMENT"},
			{Val: 44, Str: "PR_MPX_DISABLE_MANAGEMENT"},
			{Val: 45, Str: "PR_SET_FP_MODE"},
			{Val: 46, Str: "PR_GET_FP_MODE"},
			{Val: 47, Str: "PR_CAP_AMBIENT"},
			{Val: 50, Str: "PR_SVE_SET_VL"},
			{Val: 51, Str: "PR_SVE_GET_VL"},
			{Val: 52, Str: "PR_GET_SPECULATION_CTRL"},
			{Val: 53, Str: "PR_SET_SPECULATION_CTRL"},
			{Val: 54, Str: "PR_PAC_RESET_KEYS"},
			{Val: 55, Str: "PR_SET_TAGGED_ADDR_CTRL"},
			{Val: 56, Str: "PR_GET_TAGGED_ADDR_CTRL"},
			{Val: 57, Str: "PR_SET_IO_FLUSHER"},
			{Val: 58, Str: "PR_GET_IO_FLUSHER"},
			{Val: 59, Str: "PR_SET_SYSCALL_USER_DISPATCH"},
			{Val: 60, Str: "PR_PAC_SET_ENABLED_KEYS"},
			{Val: 61, Str: "PR_PAC_GET_ENABLED_KEYS"},
			{Val: 62, Str: "PR_SCHED_CORE"},
			{Val: 63, Str: "PR_SME_SET_VL"},
			{Val: 64, Str: "PR_SME_GET_VL"},
			{Val: 65, Str: "PR_SET_MDWE"},
			{Val: 66, Str: "PR_GET_MDWE"},
			{Val: 67, Str: "PR_SET_MEMORY_MERGE"},
			{Val: 68, Str: "PR_GET_MEMORY_MERGE"},
			{Val: 69, Str: "PR_RISCV_V_SET_CONTROL"},
			{Val: 70, Str: "PR_RISCV_V_GET_CONTROL"},
			{Val: 71, Str: "PR_RISCV_SET_ICACHE_FLUSH_CTX"},
			{Val: 72, Str: "PR_PPC_GET_DEXCR"},
			{Val: 73, Str: "PR_PPC_SET_DEXCR"},
			{Val: 74, Str: "PR_GET_SHADOW_STACK_STATUS"},
			{Val: 75, Str: "PR_SET_SHADOW_STACK_STATUS"},
			{Val: 76, Str: "PR_LOCK_SHADOW_STACK_STATUS"},
			{Val: 77, Str: "PR_TIMER_CREATE_RESTORE_IDS"},
			{Val: 78, Str: "PR_FUTEX_HASH"},
			{Val: 79, Str: "PR_RSEQ_SLICE_EXTENSION"},
			{Val: 80, Str: "PR_GET_CFI"},
			{Val: 81, Str: "PR_SET_CFI"},
			{Val: 1096112214, Str: "PR_GET_AUXV"},
			{Val: 1398164801, Str: "PR_SET_VMA"},
			{Val: 1499557217, Str: "PR_SET_PTRACER"},
		},
	},
	"sigprocmaskcmds": {
		Prefix: "SIG_",
		Entries: []XlatVal{
			{Val: 0, Str: "SIG_BLOCK"},
			{Val: 1, Str: "SIG_UNBLOCK"},
			{Val: 2, Str: "SIG_SETMASK"},
		},
	},
	"sock_ip_options": {
		Prefix: "IP_ MCAST_",
		Entries: []XlatVal{
			{Val: 1, Str: "IP_TOS"},
			{Val: 2, Str: "IP_TTL"},
			{Val: 3, Str: "IP_HDRINCL"},
			{Val: 4, Str: "IP_OPTIONS"},
			{Val: 5, Str: "IP_ROUTER_ALERT"},
			{Val: 6, Str: "IP_RECVOPTS"},
			{Val: 7, Str: "IP_RETOPTS"},
			{Val: 8, Str: "IP_PKTINFO"},
			{Val: 9, Str: "IP_PKTOPTIONS"},
			{Val: 10, Str: "IP_MTU_DISCOVER"},
			{Val: 11, Str: "IP_RECVERR"},
			{Val: 12, Str: "IP_RECVTTL"},
			{Val: 13, Str: "IP_RECVTOS"},
			{Val: 14, Str: "IP_MTU"},
			{Val: 15, Str: "IP_FREEBIND"},
			{Val: 16, Str: "IP_IPSEC_POLICY"},
			{Val: 17, Str: "IP_XFRM_POLICY"},
			{Val: 18, Str: "IP_PASSSEC"},
			{Val: 19, Str: "IP_TRANSPARENT"},
			{Val: 20, Str: "IP_ORIGDSTADDR"},
			{Val: 21, Str: "IP_MINTTL"},
			{Val: 22, Str: "IP_NODEFRAG"},
			{Val: 23, Str: "IP_CHECKSUM"},
			{Val: 24, Str: "IP_BIND_ADDRESS_NO_PORT"},
			{Val: 25, Str: "IP_RECVFRAGSIZE"},
			{Val: 26, Str: "IP_RECVERR_RFC4884"},
			{Val: 32, Str: "IP_MULTICAST_IF"},
			{Val: 33, Str: "IP_MULTICAST_TTL"},
			{Val: 34, Str: "IP_MULTICAST_LOOP"},
			{Val: 35, Str: "IP_ADD_MEMBERSHIP"},
			{Val: 36, Str: "IP_DROP_MEMBERSHIP"},
			{Val: 37, Str: "IP_UNBLOCK_SOURCE"},
			{Val: 38, Str: "IP_BLOCK_SOURCE"},
			{Val: 39, Str: "IP_ADD_SOURCE_MEMBERSHIP"},
			{Val: 40, Str: "IP_DROP_SOURCE_MEMBERSHIP"},
			{Val: 41, Str: "IP_MSFILTER"},
			{Val: 42, Str: "MCAST_JOIN_GROUP"},
			{Val: 43, Str: "MCAST_BLOCK_SOURCE"},
			{Val: 44, Str: "MCAST_UNBLOCK_SOURCE"},
			{Val: 45, Str: "MCAST_LEAVE_GROUP"},
			{Val: 46, Str: "MCAST_JOIN_SOURCE_GROUP"},
			{Val: 47, Str: "MCAST_LEAVE_SOURCE_GROUP"},
			{Val: 48, Str: "MCAST_MSFILTER"},
			{Val: 49, Str: "IP_MULTICAST_ALL"},
			{Val: 50, Str: "IP_UNICAST_IF"},
			{Val: 51, Str: "IP_LOCAL_PORT_RANGE"},
			{Val: 52, Str: "IP_PROTOCOL"},
		},
	},
	"sock_options": {
		Prefix: "",
		Entries: []XlatVal{
			{Val: 1, Str: "SO_DEBUG"},
			{Val: 2, Str: "SO_REUSEADDR"},
			{Val: 2, Str: "SO_REUSEADDR"},
			{Val: 3, Str: "SO_TYPE"},
			{Val: 3, Str: "SO_TYPE"},
			{Val: 4, Str: "SO_ERROR"},
			{Val: 4, Str: "SO_ERROR"},
			{Val: 5, Str: "SO_DONTROUTE"},
			{Val: 5, Str: "SO_DONTROUTE"},
			{Val: 6, Str: "SO_BROADCAST"},
			{Val: 6, Str: "SO_BROADCAST"},
			{Val: 7, Str: "SO_SNDBUF"},
			{Val: 7, Str: "SO_SNDBUF"},
			{Val: 8, Str: "SO_RCVBUF"},
			{Val: 8, Str: "SO_RCVBUF"},
			{Val: 9, Str: "SO_KEEPALIVE"},
			{Val: 9, Str: "SO_KEEPALIVE"},
			{Val: 10, Str: "SO_OOBINLINE"},
			{Val: 10, Str: "SO_OOBINLINE"},
			{Val: 11, Str: "SO_NO_CHECK"},
			{Val: 11, Str: "SO_NO_CHECK"},
			{Val: 12, Str: "SO_PRIORITY"},
			{Val: 12, Str: "SO_PRIORITY"},
			{Val: 13, Str: "SO_LINGER"},
			{Val: 13, Str: "SO_LINGER"},
			{Val: 14, Str: "SO_BSDCOMPAT"},
			{Val: 14, Str: "SO_BSDCOMPAT"},
			{Val: 14, Str: "SO_BSDCOMPAT"},
			{Val: 15, Str: "SO_REUSEPORT"},
			{Val: 15, Str: "SO_REUSEPORT"},
			{Val: 16, Str: "SO_PASSCRED"},
			{Val: 16, Str: "SO_PASSCRED"},
			{Val: 16, Str: "SO_PASSCRED"},
			{Val: 16, Str: "SO_PASSCRED"},
			{Val: 16, Str: "SO_PASSCRED"},
			{Val: 17, Str: "SO_PEERCRED"},
			{Val: 17, Str: "SO_PEERCRED"},
			{Val: 17, Str: "SO_PEERCRED"},
			{Val: 17, Str: "SO_PEERCRED"},
			{Val: 17, Str: "SO_PEERCRED"},
			{Val: 18, Str: "SO_RCVLOWAT"},
			{Val: 18, Str: "SO_RCVLOWAT"},
			{Val: 18, Str: "SO_RCVLOWAT"},
			{Val: 18, Str: "SO_RCVLOWAT"},
			{Val: 18, Str: "SO_RCVLOWAT"},
			{Val: 19, Str: "SO_SNDLOWAT"},
			{Val: 19, Str: "SO_SNDLOWAT"},
			{Val: 19, Str: "SO_SNDLOWAT"},
			{Val: 19, Str: "SO_SNDLOWAT"},
			{Val: 19, Str: "SO_SNDLOWAT"},
			{Val: 20, Str: "SO_RCVTIMEO_OLD"},
			{Val: 20, Str: "SO_RCVTIMEO_OLD"},
			{Val: 20, Str: "SO_RCVTIMEO_OLD"},
			{Val: 20, Str: "SO_RCVTIMEO_OLD"},
			{Val: 20, Str: "SO_RCVTIMEO_OLD"},
			{Val: 21, Str: "SO_SNDTIMEO_OLD"},
			{Val: 21, Str: "SO_SNDTIMEO_OLD"},
			{Val: 21, Str: "SO_SNDTIMEO_OLD"},
			{Val: 21, Str: "SO_SNDTIMEO_OLD"},
			{Val: 21, Str: "SO_SNDTIMEO_OLD"},
			{Val: 22, Str: "SO_SECURITY_AUTHENTICATION"},
			{Val: 22, Str: "SO_SECURITY_AUTHENTICATION"},
			{Val: 22, Str: "SO_SECURITY_AUTHENTICATION"},
			{Val: 22, Str: "SO_SECURITY_AUTHENTICATION"},
			{Val: 23, Str: "SO_SECURITY_ENCRYPTION_TRANSPORT"},
			{Val: 23, Str: "SO_SECURITY_ENCRYPTION_TRANSPORT"},
			{Val: 23, Str: "SO_SECURITY_ENCRYPTION_TRANSPORT"},
			{Val: 23, Str: "SO_SECURITY_ENCRYPTION_TRANSPORT"},
			{Val: 24, Str: "SO_SECURITY_ENCRYPTION_NETWORK"},
			{Val: 24, Str: "SO_SECURITY_ENCRYPTION_NETWORK"},
			{Val: 24, Str: "SO_SECURITY_ENCRYPTION_NETWORK"},
			{Val: 24, Str: "SO_SECURITY_ENCRYPTION_NETWORK"},
			{Val: 25, Str: "SO_BINDTODEVICE"},
			{Val: 25, Str: "SO_BINDTODEVICE"},
			{Val: 25, Str: "SO_BINDTODEVICE"},
			{Val: 27, Str: "SO_DETACH_FILTER"},
			{Val: 27, Str: "SO_DETACH_FILTER"},
			{Val: 28, Str: "SO_PEERNAME"},
			{Val: 28, Str: "SO_PEERNAME"},
			{Val: 29, Str: "SO_TIMESTAMP_OLD"},
			{Val: 29, Str: "SO_TIMESTAMP_OLD"},
			{Val: 30, Str: "SO_ACCEPTCONN"},
			{Val: 30, Str: "SO_ACCEPTCONN"},
			{Val: 30, Str: "SO_ACCEPTCONN"},
			{Val: 30, Str: "SO_ACCEPTCONN"},
			{Val: 30, Str: "SO_ACCEPTCONN"},
			{Val: 31, Str: "SO_PEERSEC"},
			{Val: 31, Str: "SO_PEERSEC"},
			{Val: 31, Str: "SO_PEERSEC"},
			{Val: 32, Str: "SO_SNDBUFFORCE"},
			{Val: 32, Str: "SO_SNDBUFFORCE"},
			{Val: 32, Str: "SO_SNDBUFFORCE"},
			{Val: 33, Str: "SO_RCVBUFFORCE"},
			{Val: 33, Str: "SO_RCVBUFFORCE"},
			{Val: 34, Str: "SO_PASSSEC"},
			{Val: 34, Str: "SO_PASSSEC"},
			{Val: 34, Str: "SO_PASSSEC"},
			{Val: 35, Str: "SO_TIMESTAMPNS_OLD"},
			{Val: 35, Str: "SO_TIMESTAMPNS_OLD"},
			{Val: 35, Str: "SO_TIMESTAMPNS_OLD"},
			{Val: 36, Str: "SO_MARK"},
			{Val: 36, Str: "SO_MARK"},
			{Val: 36, Str: "SO_MARK"},
			{Val: 37, Str: "SO_TIMESTAMPING_OLD"},
			{Val: 37, Str: "SO_TIMESTAMPING_OLD"},
			{Val: 37, Str: "SO_TIMESTAMPING_OLD"},
			{Val: 38, Str: "SO_PROTOCOL"},
			{Val: 38, Str: "SO_PROTOCOL"},
			{Val: 39, Str: "SO_DOMAIN"},
			{Val: 39, Str: "SO_DOMAIN"},
			{Val: 40, Str: "SO_RXQ_OVFL"},
			{Val: 40, Str: "SO_RXQ_OVFL"},
			{Val: 40, Str: "SO_RXQ_OVFL"},
			{Val: 41, Str: "SO_WIFI_STATUS"},
			{Val: 41, Str: "SO_WIFI_STATUS"},
			{Val: 41, Str: "SO_WIFI_STATUS"},
			{Val: 42, Str: "SO_PEEK_OFF"},
			{Val: 42, Str: "SO_PEEK_OFF"},
			{Val: 42, Str: "SO_PEEK_OFF"},
			{Val: 43, Str: "SO_NOFCS"},
			{Val: 43, Str: "SO_NOFCS"},
			{Val: 43, Str: "SO_NOFCS"},
			{Val: 44, Str: "SO_LOCK_FILTER"},
			{Val: 44, Str: "SO_LOCK_FILTER"},
			{Val: 44, Str: "SO_LOCK_FILTER"},
			{Val: 45, Str: "SO_SELECT_ERR_QUEUE"},
			{Val: 45, Str: "SO_SELECT_ERR_QUEUE"},
			{Val: 45, Str: "SO_SELECT_ERR_QUEUE"},
			{Val: 46, Str: "SO_BUSY_POLL"},
			{Val: 46, Str: "SO_BUSY_POLL"},
			{Val: 46, Str: "SO_BUSY_POLL"},
			{Val: 47, Str: "SO_MAX_PACING_RATE"},
			{Val: 47, Str: "SO_MAX_PACING_RATE"},
			{Val: 47, Str: "SO_MAX_PACING_RATE"},
			{Val: 48, Str: "SO_BPF_EXTENSIONS"},
			{Val: 48, Str: "SO_BPF_EXTENSIONS"},
			{Val: 48, Str: "SO_BPF_EXTENSIONS"},
			{Val: 49, Str: "SO_INCOMING_CPU"},
			{Val: 49, Str: "SO_INCOMING_CPU"},
			{Val: 49, Str: "SO_INCOMING_CPU"},
			{Val: 50, Str: "SO_ATTACH_BPF"},
			{Val: 50, Str: "SO_ATTACH_BPF"},
			{Val: 50, Str: "SO_ATTACH_BPF"},
			{Val: 51, Str: "SO_ATTACH_REUSEPORT_CBPF"},
			{Val: 51, Str: "SO_ATTACH_REUSEPORT_CBPF"},
			{Val: 51, Str: "SO_ATTACH_REUSEPORT_CBPF"},
			{Val: 52, Str: "SO_ATTACH_REUSEPORT_EBPF"},
			{Val: 52, Str: "SO_ATTACH_REUSEPORT_EBPF"},
			{Val: 52, Str: "SO_ATTACH_REUSEPORT_EBPF"},
			{Val: 53, Str: "SO_CNX_ADVICE"},
			{Val: 53, Str: "SO_CNX_ADVICE"},
			{Val: 53, Str: "SO_CNX_ADVICE"},
			{Val: 55, Str: "SO_MEMINFO"},
			{Val: 55, Str: "SO_MEMINFO"},
			{Val: 55, Str: "SO_MEMINFO"},
			{Val: 56, Str: "SO_INCOMING_NAPI_ID"},
			{Val: 56, Str: "SO_INCOMING_NAPI_ID"},
			{Val: 56, Str: "SO_INCOMING_NAPI_ID"},
			{Val: 57, Str: "SO_COOKIE"},
			{Val: 57, Str: "SO_COOKIE"},
			{Val: 57, Str: "SO_COOKIE"},
			{Val: 59, Str: "SO_PEERGROUPS"},
			{Val: 59, Str: "SO_PEERGROUPS"},
			{Val: 59, Str: "SO_PEERGROUPS"},
			{Val: 60, Str: "SO_ZEROCOPY"},
			{Val: 60, Str: "SO_ZEROCOPY"},
			{Val: 60, Str: "SO_ZEROCOPY"},
			{Val: 61, Str: "SO_TXTIME"},
			{Val: 61, Str: "SO_TXTIME"},
			{Val: 61, Str: "SO_TXTIME"},
			{Val: 62, Str: "SO_BINDTOIFINDEX"},
			{Val: 62, Str: "SO_BINDTOIFINDEX"},
			{Val: 62, Str: "SO_BINDTOIFINDEX"},
			{Val: 63, Str: "SO_TIMESTAMP_NEW"},
			{Val: 63, Str: "SO_TIMESTAMP_NEW"},
			{Val: 63, Str: "SO_TIMESTAMP_NEW"},
			{Val: 64, Str: "SO_TIMESTAMPNS_NEW"},
			{Val: 64, Str: "SO_TIMESTAMPNS_NEW"},
			{Val: 64, Str: "SO_TIMESTAMPNS_NEW"},
			{Val: 65, Str: "SO_TIMESTAMPING_NEW"},
			{Val: 65, Str: "SO_TIMESTAMPING_NEW"},
			{Val: 65, Str: "SO_TIMESTAMPING_NEW"},
			{Val: 66, Str: "SO_RCVTIMEO_NEW"},
			{Val: 66, Str: "SO_RCVTIMEO_NEW"},
			{Val: 66, Str: "SO_RCVTIMEO_NEW"},
			{Val: 67, Str: "SO_SNDTIMEO_NEW"},
			{Val: 67, Str: "SO_SNDTIMEO_NEW"},
			{Val: 67, Str: "SO_SNDTIMEO_NEW"},
			{Val: 68, Str: "SO_DETACH_REUSEPORT_BPF"},
			{Val: 68, Str: "SO_DETACH_REUSEPORT_BPF"},
			{Val: 68, Str: "SO_DETACH_REUSEPORT_BPF"},
			{Val: 69, Str: "SO_PREFER_BUSY_POLL"},
			{Val: 69, Str: "SO_PREFER_BUSY_POLL"},
			{Val: 69, Str: "SO_PREFER_BUSY_POLL"},
			{Val: 70, Str: "SO_BUSY_POLL_BUDGET"},
			{Val: 70, Str: "SO_BUSY_POLL_BUDGET"},
			{Val: 70, Str: "SO_BUSY_POLL_BUDGET"},
			{Val: 71, Str: "SO_NETNS_COOKIE"},
			{Val: 71, Str: "SO_NETNS_COOKIE"},
			{Val: 71, Str: "SO_NETNS_COOKIE"},
			{Val: 72, Str: "SO_BUF_LOCK"},
			{Val: 72, Str: "SO_BUF_LOCK"},
			{Val: 72, Str: "SO_BUF_LOCK"},
			{Val: 73, Str: "SO_RESERVE_MEM"},
			{Val: 73, Str: "SO_RESERVE_MEM"},
			{Val: 73, Str: "SO_RESERVE_MEM"},
			{Val: 74, Str: "SO_TXREHASH"},
			{Val: 74, Str: "SO_TXREHASH"},
			{Val: 74, Str: "SO_TXREHASH"},
			{Val: 75, Str: "SO_RCVMARK"},
			{Val: 75, Str: "SO_RCVMARK"},
			{Val: 75, Str: "SO_RCVMARK"},
			{Val: 76, Str: "SO_PASSPIDFD"},
			{Val: 76, Str: "SO_PASSPIDFD"},
			{Val: 76, Str: "SO_PASSPIDFD"},
			{Val: 77, Str: "SO_PEERPIDFD"},
			{Val: 77, Str: "SO_PEERPIDFD"},
			{Val: 77, Str: "SO_PEERPIDFD"},
			{Val: 82, Str: "SO_RCVPRIORITY"},
			{Val: 82, Str: "SO_RCVPRIORITY"},
			{Val: 82, Str: "SO_RCVPRIORITY"},
			{Val: 83, Str: "SO_PASSRIGHTS"},
			{Val: 83, Str: "SO_PASSRIGHTS"},
			{Val: 83, Str: "SO_PASSRIGHTS"},
			{Val: 84, Str: "SO_INQ"},
			{Val: 84, Str: "SO_INQ"},
			{Val: 84, Str: "SO_INQ"},
		},
	},
	"sock_tcp_options": {
		Prefix: "TCP_",
		Entries: []XlatVal{
			{Val: 1, Str: "TCP_NODELAY"},
			{Val: 2, Str: "TCP_MAXSEG"},
			{Val: 3, Str: "TCP_CORK"},
			{Val: 4, Str: "TCP_KEEPIDLE"},
			{Val: 5, Str: "TCP_KEEPINTVL"},
			{Val: 6, Str: "TCP_KEEPCNT"},
			{Val: 7, Str: "TCP_SYNCNT"},
			{Val: 8, Str: "TCP_LINGER2"},
			{Val: 9, Str: "TCP_DEFER_ACCEPT"},
			{Val: 10, Str: "TCP_WINDOW_CLAMP"},
			{Val: 11, Str: "TCP_INFO"},
			{Val: 12, Str: "TCP_QUICKACK"},
			{Val: 13, Str: "TCP_CONGESTION"},
			{Val: 14, Str: "TCP_MD5SIG"},
			{Val: 15, Str: "TCP_COOKIE_TRANSACTIONS"},
			{Val: 16, Str: "TCP_THIN_LINEAR_TIMEOUTS"},
			{Val: 17, Str: "TCP_THIN_DUPACK"},
			{Val: 18, Str: "TCP_USER_TIMEOUT"},
			{Val: 19, Str: "TCP_REPAIR"},
			{Val: 20, Str: "TCP_REPAIR_QUEUE"},
			{Val: 21, Str: "TCP_QUEUE_SEQ"},
			{Val: 22, Str: "TCP_REPAIR_OPTIONS"},
			{Val: 23, Str: "TCP_FASTOPEN"},
			{Val: 24, Str: "TCP_TIMESTAMP"},
			{Val: 25, Str: "TCP_NOTSENT_LOWAT"},
			{Val: 26, Str: "TCP_CC_INFO"},
			{Val: 27, Str: "TCP_SAVE_SYN"},
			{Val: 28, Str: "TCP_SAVED_SYN"},
			{Val: 29, Str: "TCP_REPAIR_WINDOW"},
			{Val: 30, Str: "TCP_FASTOPEN_CONNECT"},
			{Val: 31, Str: "TCP_ULP"},
			{Val: 32, Str: "TCP_MD5SIG_EXT"},
			{Val: 33, Str: "TCP_FASTOPEN_KEY"},
			{Val: 34, Str: "TCP_FASTOPEN_NO_COOKIE"},
			{Val: 35, Str: "TCP_ZEROCOPY_RECEIVE"},
			{Val: 36, Str: "TCP_INQ"},
			{Val: 37, Str: "TCP_TX_DELAY"},
			{Val: 38, Str: "TCP_AO_ADD_KEY"},
			{Val: 39, Str: "TCP_AO_DEL_KEY"},
			{Val: 40, Str: "TCP_AO_INFO"},
			{Val: 41, Str: "TCP_AO_GET_KEYS"},
			{Val: 42, Str: "TCP_AO_REPAIR"},
			{Val: 43, Str: "TCP_IS_MPTCP"},
			{Val: 44, Str: "TCP_RTO_MAX_MS"},
			{Val: 45, Str: "TCP_RTO_MIN_US"},
			{Val: 46, Str: "TCP_DELACK_MAX_US"},
		},
	},
	"sock_type_flags": {
		Prefix: "SOCK_",
		Entries: []XlatVal{
			{Val: 524288, Str: "SOCK_CLOEXEC"},
			{Val: 2048, Str: "SOCK_NONBLOCK"},
		},
	},
	"socketlayers": {
		Prefix: "AF_ SOL_",
		Entries: []XlatVal{
			{Val: 1, Str: "SOL_SOCKET"},
			{Val: 6, Str: "SOL_TCP"},
			{Val: 17, Str: "SOL_UDP"},
			{Val: 40, Str: "AF_VSOCK"},
			{Val: 41, Str: "SOL_IPV6"},
			{Val: 58, Str: "SOL_ICMPV6"},
			{Val: 100, Str: "SOL_CAN_BASE"},
			{Val: 101, Str: "SOL_CAN_RAW"},
			{Val: 132, Str: "SOL_SCTP"},
			{Val: 136, Str: "SOL_UDPLITE"},
			{Val: 255, Str: "SOL_RAW"},
			{Val: 256, Str: "SOL_IPX"},
			{Val: 257, Str: "SOL_AX25"},
			{Val: 258, Str: "SOL_ATALK"},
			{Val: 259, Str: "SOL_NETROM"},
			{Val: 260, Str: "SOL_ROSE"},
			{Val: 261, Str: "SOL_DECNET"},
			{Val: 262, Str: "SOL_X25"},
			{Val: 263, Str: "SOL_PACKET"},
			{Val: 264, Str: "SOL_ATM"},
			{Val: 265, Str: "SOL_AAL"},
			{Val: 266, Str: "SOL_IRDA"},
			{Val: 267, Str: "SOL_NETBEUI"},
			{Val: 268, Str: "SOL_LLC"},
			{Val: 269, Str: "SOL_DCCP"},
			{Val: 270, Str: "SOL_NETLINK"},
			{Val: 271, Str: "SOL_TIPC"},
			{Val: 272, Str: "SOL_RXRPC"},
			{Val: 273, Str: "SOL_PPPOL2TP"},
			{Val: 274, Str: "SOL_BLUETOOTH"},
			{Val: 275, Str: "SOL_PNPIPE"},
			{Val: 276, Str: "SOL_RDS"},
			{Val: 277, Str: "SOL_IUCV"},
			{Val: 278, Str: "SOL_CAIF"},
			{Val: 279, Str: "SOL_ALG"},
			{Val: 280, Str: "SOL_NFC"},
			{Val: 281, Str: "SOL_KCM"},
			{Val: 282, Str: "SOL_TLS"},
			{Val: 283, Str: "SOL_XDP"},
			{Val: 284, Str: "SOL_MPTCP"},
			{Val: 285, Str: "SOL_MCTP"},
			{Val: 286, Str: "SOL_SMC"},
			{Val: 287, Str: "SOL_VSOCK"},
			{Val: 1, Str: "SOL_SOCKET"},
		},
	},
	"umount_flags": {
		Prefix: "MNT_ UMOUNT_",
		Entries: []XlatVal{
			{Val: 1, Str: "MNT_FORCE"},
			{Val: 2, Str: "MNT_DETACH"},
			{Val: 4, Str: "MNT_EXPIRE"},
			{Val: 8, Str: "UMOUNT_NOFOLLOW"},
		},
	},
	"wait4_options": {
		Prefix: "W __W",
		Entries: []XlatVal{
			{Val: 1, Str: "WNOHANG"},
			{Val: 2, Str: "WUNTRACED"},
			{Val: 4, Str: "WEXITED"},
			{Val: 2, Str: "WSTOPPED"},
			{Val: 8, Str: "WCONTINUED"},
			{Val: 16777216, Str: "WNOWAIT"},
			{Val: 2147483648, Str: "__WCLONE"},
			{Val: 1073741824, Str: "__WALL"},
			{Val: 536870912, Str: "__WNOTHREAD"},
		},
	},
	"whence_codes": {
		Prefix: "SEEK_",
		Entries: []XlatVal{
			{Val: 0, Str: "SEEK_SET"},
			{Val: 1, Str: "SEEK_CUR"},
			{Val: 2, Str: "SEEK_END"},
			{Val: 3, Str: "SEEK_DATA"},
			{Val: 4, Str: "SEEK_HOLE"},
		},
	},
	"x86_xfeature_bits": {
		Prefix: "XFEATURE_",
		Entries: []XlatVal{
			{Val: 0, Str: "XFEATURE_FP"},
			{Val: 1, Str: "XFEATURE_SSE"},
			{Val: 2, Str: "XFEATURE_YMM"},
			{Val: 3, Str: "XFEATURE_BNDREGS"},
			{Val: 4, Str: "XFEATURE_BNDCSR"},
			{Val: 5, Str: "XFEATURE_OPMASK"},
			{Val: 6, Str: "XFEATURE_ZMM_Hi256"},
			{Val: 7, Str: "XFEATURE_Hi16_ZMM"},
			{Val: 8, Str: "XFEATURE_PT_UNIMPLEMENTED_SO_FAR"},
			{Val: 9, Str: "XFEATURE_PKRU"},
			{Val: 10, Str: "XFEATURE_PASID"},
			{Val: 15, Str: "XFEATURE_LBR"},
			{Val: 17, Str: "XFEATURE_XTILE_CFG"},
			{Val: 18, Str: "XFEATURE_XTILE_DATA"},
			{Val: 8, Str: "XFEATURE_PT_UNIMPLEMENTED_SO_FAR"},
			{Val: 15, Str: "XFEATURE_LBR"},
			{Val: 17, Str: "XFEATURE_XTILE_CFG"},
			{Val: 18, Str: "XFEATURE_XTILE_DATA"},
		},
	},
	"ioctl_cmds": {
		Prefix: "",
		Entries: []XlatVal{
			{Val: 1074283777, Str: "APEI_ERST_CLEAR_RECORD"}, // From acpi/apei.h
			{Val: 2147763458, Str: "APEI_ERST_GET_RECORD_COUNT"}, // From acpi/apei.h
			{Val: 21586, Str: "FIOASYNC"}, // From asm-generic/ioctls.h
			{Val: 21585, Str: "FIOCLEX"}, // From asm-generic/ioctls.h
			{Val: 21537, Str: "FIONBIO"}, // From asm-generic/ioctls.h
			{Val: 21584, Str: "FIONCLEX"}, // From asm-generic/ioctls.h
			{Val: 21531, Str: "FIONREAD"}, // From asm-generic/ioctls.h
			{Val: 21600, Str: "FIOQSIZE"}, // From asm-generic/ioctls.h
			{Val: 21515, Str: "TCFLSH"}, // From asm-generic/ioctls.h
			{Val: 21509, Str: "TCGETA"}, // From asm-generic/ioctls.h
			{Val: 21505, Str: "TCGETS"}, // From asm-generic/ioctls.h
			{Val: 2150388778, Str: "TCGETS2"}, // From asm-generic/ioctls.h
			{Val: 21554, Str: "TCGETX"}, // From asm-generic/ioctls.h
			{Val: 21513, Str: "TCSBRK"}, // From asm-generic/ioctls.h
			{Val: 21541, Str: "TCSBRKP"}, // From asm-generic/ioctls.h
			{Val: 21510, Str: "TCSETA"}, // From asm-generic/ioctls.h
			{Val: 21512, Str: "TCSETAF"}, // From asm-generic/ioctls.h
			{Val: 21511, Str: "TCSETAW"}, // From asm-generic/ioctls.h
			{Val: 21506, Str: "TCSETS"}, // From asm-generic/ioctls.h
			{Val: 1076646955, Str: "TCSETS2"}, // From asm-generic/ioctls.h
			{Val: 21508, Str: "TCSETSF"}, // From asm-generic/ioctls.h
			{Val: 1076646957, Str: "TCSETSF2"}, // From asm-generic/ioctls.h
			{Val: 21507, Str: "TCSETSW"}, // From asm-generic/ioctls.h
			{Val: 1076646956, Str: "TCSETSW2"}, // From asm-generic/ioctls.h
			{Val: 21555, Str: "TCSETX"}, // From asm-generic/ioctls.h
			{Val: 21556, Str: "TCSETXF"}, // From asm-generic/ioctls.h
			{Val: 21557, Str: "TCSETXW"}, // From asm-generic/ioctls.h
			{Val: 21514, Str: "TCXONC"}, // From asm-generic/ioctls.h
			{Val: 21544, Str: "TIOCCBRK"}, // From asm-generic/ioctls.h
			{Val: 21533, Str: "TIOCCONS"}, // From asm-generic/ioctls.h
			{Val: 21516, Str: "TIOCEXCL"}, // From asm-generic/ioctls.h
			{Val: 2147767346, Str: "TIOCGDEV"}, // From asm-generic/ioctls.h
			{Val: 21540, Str: "TIOCGETD"}, // From asm-generic/ioctls.h
			{Val: 2147767360, Str: "TIOCGEXCL"}, // From asm-generic/ioctls.h
			{Val: 21597, Str: "TIOCGICOUNT"}, // From asm-generic/ioctls.h
			{Val: 2150126658, Str: "TIOCGISO7816"}, // From asm-generic/ioctls.h
			{Val: 21590, Str: "TIOCGLCKTRMIOS"}, // From asm-generic/ioctls.h
			{Val: 21519, Str: "TIOCGPGRP"}, // From asm-generic/ioctls.h
			{Val: 2147767352, Str: "TIOCGPKT"}, // From asm-generic/ioctls.h
			{Val: 2147767353, Str: "TIOCGPTLCK"}, // From asm-generic/ioctls.h
			{Val: 2147767344, Str: "TIOCGPTN"}, // From asm-generic/ioctls.h
			{Val: 21569, Str: "TIOCGPTPEER"}, // From asm-generic/ioctls.h
			{Val: 21550, Str: "TIOCGRS485"}, // From asm-generic/ioctls.h
			{Val: 21534, Str: "TIOCGSERIAL"}, // From asm-generic/ioctls.h
			{Val: 21545, Str: "TIOCGSID"}, // From asm-generic/ioctls.h
			{Val: 21529, Str: "TIOCGSOFTCAR"}, // From asm-generic/ioctls.h
			{Val: 21523, Str: "TIOCGWINSZ"}, // From asm-generic/ioctls.h
			{Val: 21532, Str: "TIOCLINUX"}, // From asm-generic/ioctls.h
			{Val: 21527, Str: "TIOCMBIC"}, // From asm-generic/ioctls.h
			{Val: 21526, Str: "TIOCMBIS"}, // From asm-generic/ioctls.h
			{Val: 21525, Str: "TIOCMGET"}, // From asm-generic/ioctls.h
			{Val: 21596, Str: "TIOCMIWAIT"}, // From asm-generic/ioctls.h
			{Val: 21528, Str: "TIOCMSET"}, // From asm-generic/ioctls.h
			{Val: 21538, Str: "TIOCNOTTY"}, // From asm-generic/ioctls.h
			{Val: 21517, Str: "TIOCNXCL"}, // From asm-generic/ioctls.h
			{Val: 21521, Str: "TIOCOUTQ"}, // From asm-generic/ioctls.h
			{Val: 21536, Str: "TIOCPKT"}, // From asm-generic/ioctls.h
			{Val: 21543, Str: "TIOCSBRK"}, // From asm-generic/ioctls.h
			{Val: 21518, Str: "TIOCSCTTY"}, // From asm-generic/ioctls.h
			{Val: 21587, Str: "TIOCSERCONFIG"}, // From asm-generic/ioctls.h
			{Val: 21593, Str: "TIOCSERGETLSR"}, // From asm-generic/ioctls.h
			{Val: 21594, Str: "TIOCSERGETMULTI"}, // From asm-generic/ioctls.h
			{Val: 21592, Str: "TIOCSERGSTRUCT"}, // From asm-generic/ioctls.h
			{Val: 21588, Str: "TIOCSERGWILD"}, // From asm-generic/ioctls.h
			{Val: 21595, Str: "TIOCSERSETMULTI"}, // From asm-generic/ioctls.h
			{Val: 21589, Str: "TIOCSERSWILD"}, // From asm-generic/ioctls.h
			{Val: 21539, Str: "TIOCSETD"}, // From asm-generic/ioctls.h
			{Val: 1074025526, Str: "TIOCSIG"}, // From asm-generic/ioctls.h
			{Val: 3223868483, Str: "TIOCSISO7816"}, // From asm-generic/ioctls.h
			{Val: 21591, Str: "TIOCSLCKTRMIOS"}, // From asm-generic/ioctls.h
			{Val: 21520, Str: "TIOCSPGRP"}, // From asm-generic/ioctls.h
			{Val: 1074025521, Str: "TIOCSPTLCK"}, // From asm-generic/ioctls.h
			{Val: 21551, Str: "TIOCSRS485"}, // From asm-generic/ioctls.h
			{Val: 21535, Str: "TIOCSSERIAL"}, // From asm-generic/ioctls.h
			{Val: 21530, Str: "TIOCSSOFTCAR"}, // From asm-generic/ioctls.h
			{Val: 21522, Str: "TIOCSTI"}, // From asm-generic/ioctls.h
			{Val: 21524, Str: "TIOCSWINSZ"}, // From asm-generic/ioctls.h
			{Val: 21559, Str: "TIOCVHANGUP"}, // From asm-generic/ioctls.h
			{Val: 35075, Str: "FIOGETOWN"}, // From asm-generic/sockios.h
			{Val: 35073, Str: "FIOSETOWN"}, // From asm-generic/sockios.h
			{Val: 35077, Str: "SIOCATMARK"}, // From asm-generic/sockios.h
			{Val: 35076, Str: "SIOCGPGRP"}, // From asm-generic/sockios.h
			{Val: 35079, Str: "SIOCGSTAMPNS_OLD"}, // From asm-generic/sockios.h
			{Val: 35078, Str: "SIOCGSTAMP_OLD"}, // From asm-generic/sockios.h
			{Val: 35074, Str: "SIOCSPGRP"}, // From asm-generic/sockios.h
			{Val: 3222824003, Str: "DRM_IOCTL_AMDGPU_BO_LIST"}, // From drm/amdgpu_drm.h
			{Val: 3222824004, Str: "DRM_IOCTL_AMDGPU_CS"}, // From drm/amdgpu_drm.h
			{Val: 3222299714, Str: "DRM_IOCTL_AMDGPU_CTX"}, // From drm/amdgpu_drm.h
			{Val: 3223348308, Str: "DRM_IOCTL_AMDGPU_FENCE_TO_HANDLE"}, // From drm/amdgpu_drm.h
			{Val: 3223348288, Str: "DRM_IOCTL_AMDGPU_GEM_CREATE"}, // From drm/amdgpu_drm.h
			{Val: 3222299737, Str: "DRM_IOCTL_AMDGPU_GEM_LIST_HANDLES"}, // From drm/amdgpu_drm.h
			{Val: 3240125510, Str: "DRM_IOCTL_AMDGPU_GEM_METADATA"}, // From drm/amdgpu_drm.h
			{Val: 3221775425, Str: "DRM_IOCTL_AMDGPU_GEM_MMAP"}, // From drm/amdgpu_drm.h
			{Val: 3222824016, Str: "DRM_IOCTL_AMDGPU_GEM_OP"}, // From drm/amdgpu_drm.h
			{Val: 3222824017, Str: "DRM_IOCTL_AMDGPU_GEM_USERPTR"}, // From drm/amdgpu_drm.h
			{Val: 1077961800, Str: "DRM_IOCTL_AMDGPU_GEM_VA"}, // From drm/amdgpu_drm.h
			{Val: 3222299719, Str: "DRM_IOCTL_AMDGPU_GEM_WAIT_IDLE"}, // From drm/amdgpu_drm.h
			{Val: 1075864645, Str: "DRM_IOCTL_AMDGPU_INFO"}, // From drm/amdgpu_drm.h
			{Val: 1074816085, Str: "DRM_IOCTL_AMDGPU_SCHED"}, // From drm/amdgpu_drm.h
			{Val: 3225969750, Str: "DRM_IOCTL_AMDGPU_USERQ"}, // From drm/amdgpu_drm.h
			{Val: 3224396887, Str: "DRM_IOCTL_AMDGPU_USERQ_SIGNAL"}, // From drm/amdgpu_drm.h
			{Val: 3225969752, Str: "DRM_IOCTL_AMDGPU_USERQ_WAIT"}, // From drm/amdgpu_drm.h
			{Val: 3221775443, Str: "DRM_IOCTL_AMDGPU_VM"}, // From drm/amdgpu_drm.h
			{Val: 3223348297, Str: "DRM_IOCTL_AMDGPU_WAIT_CS"}, // From drm/amdgpu_drm.h
			{Val: 3222824018, Str: "DRM_IOCTL_AMDGPU_WAIT_FENCES"}, // From drm/amdgpu_drm.h
			{Val: 3222824002, Str: "DRM_IOCTL_AMDXDNA_CONFIG_HWCTX"}, // From drm/amdxdna_accel.h
			{Val: 3223348291, Str: "DRM_IOCTL_AMDXDNA_CREATE_BO"}, // From drm/amdxdna_accel.h
			{Val: 3224921152, Str: "DRM_IOCTL_AMDXDNA_CREATE_HWCTX"}, // From drm/amdxdna_accel.h
			{Val: 3221775425, Str: "DRM_IOCTL_AMDXDNA_DESTROY_HWCTX"}, // From drm/amdxdna_accel.h
			{Val: 3224921158, Str: "DRM_IOCTL_AMDXDNA_EXEC_CMD"}, // From drm/amdxdna_accel.h
			{Val: 3222824010, Str: "DRM_IOCTL_AMDXDNA_GET_ARRAY"}, // From drm/amdxdna_accel.h
			{Val: 3224396868, Str: "DRM_IOCTL_AMDXDNA_GET_BO_INFO"}, // From drm/amdxdna_accel.h
			{Val: 3222299719, Str: "DRM_IOCTL_AMDXDNA_GET_INFO"}, // From drm/amdxdna_accel.h
			{Val: 3222299720, Str: "DRM_IOCTL_AMDXDNA_SET_STATE"}, // From drm/amdxdna_accel.h
			{Val: 3222824005, Str: "DRM_IOCTL_AMDXDNA_SYNC_BO"}, // From drm/amdxdna_accel.h
			{Val: 3221775424, Str: "DRM_IOCTL_ARMADA_GEM_CREATE"}, // From drm/armada_drm.h
			{Val: 3223348290, Str: "DRM_IOCTL_ARMADA_GEM_MMAP"}, // From drm/armada_drm.h
			{Val: 1075340355, Str: "DRM_IOCTL_ARMADA_GEM_PWRITE"}, // From drm/armada_drm.h
			{Val: 3223348246, Str: "DRM_IOCTL_ADD_BUFS"}, // From drm/drm.h
			{Val: 3221775392, Str: "DRM_IOCTL_ADD_CTX"}, // From drm/drm.h
			{Val: 3221513255, Str: "DRM_IOCTL_ADD_DRAW"}, // From drm/drm.h
			{Val: 3223872533, Str: "DRM_IOCTL_ADD_MAP"}, // From drm/drm.h
			{Val: 25648, Str: "DRM_IOCTL_AGP_ACQUIRE"}, // From drm/drm.h
			{Val: 3223348276, Str: "DRM_IOCTL_AGP_ALLOC"}, // From drm/drm.h
			{Val: 1074816054, Str: "DRM_IOCTL_AGP_BIND"}, // From drm/drm.h
			{Val: 1074291762, Str: "DRM_IOCTL_AGP_ENABLE"}, // From drm/drm.h
			{Val: 1075864629, Str: "DRM_IOCTL_AGP_FREE"}, // From drm/drm.h
			{Val: 2151179315, Str: "DRM_IOCTL_AGP_INFO"}, // From drm/drm.h
			{Val: 25649, Str: "DRM_IOCTL_AGP_RELEASE"}, // From drm/drm.h
			{Val: 1074816055, Str: "DRM_IOCTL_AGP_UNBIND"}, // From drm/drm.h
			{Val: 1074029585, Str: "DRM_IOCTL_AUTH_MAGIC"}, // From drm/drm.h
			{Val: 3221513234, Str: "DRM_IOCTL_BLOCK"}, // From drm/drm.h
			{Val: 1074291732, Str: "DRM_IOCTL_CONTROL"}, // From drm/drm.h
			{Val: 3222823995, Str: "DRM_IOCTL_CRTC_GET_SEQUENCE"}, // From drm/drm.h
			{Val: 3222823996, Str: "DRM_IOCTL_CRTC_QUEUE_SEQUENCE"}, // From drm/drm.h
			{Val: 3225445417, Str: "DRM_IOCTL_DMA"}, // From drm/drm.h
			{Val: 25631, Str: "DRM_IOCTL_DROP_MASTER"}, // From drm/drm.h
			{Val: 1074291756, Str: "DRM_IOCTL_FINISH"}, // From drm/drm.h
			{Val: 1074816026, Str: "DRM_IOCTL_FREE_BUFS"}, // From drm/drm.h
			{Val: 3221775570, Str: "DRM_IOCTL_GEM_CHANGE_HANDLE"}, // From drm/drm.h
			{Val: 1074291721, Str: "DRM_IOCTL_GEM_CLOSE"}, // From drm/drm.h
			{Val: 3221775370, Str: "DRM_IOCTL_GEM_FLINK"}, // From drm/drm.h
			{Val: 3222299659, Str: "DRM_IOCTL_GEM_OPEN"}, // From drm/drm.h
			{Val: 3222299660, Str: "DRM_IOCTL_GET_CAP"}, // From drm/drm.h
			{Val: 3223872517, Str: "DRM_IOCTL_GET_CLIENT"}, // From drm/drm.h
			{Val: 3221775395, Str: "DRM_IOCTL_GET_CTX"}, // From drm/drm.h
			{Val: 2147771394, Str: "DRM_IOCTL_GET_MAGIC"}, // From drm/drm.h
			{Val: 3223872516, Str: "DRM_IOCTL_GET_MAP"}, // From drm/drm.h
			{Val: 3222299677, Str: "DRM_IOCTL_GET_SAREA_CTX"}, // From drm/drm.h
			{Val: 2163762182, Str: "DRM_IOCTL_GET_STATS"}, // From drm/drm.h
			{Val: 3222299649, Str: "DRM_IOCTL_GET_UNIQUE"}, // From drm/drm.h
			{Val: 3222299672, Str: "DRM_IOCTL_INFO_BUFS"}, // From drm/drm.h
			{Val: 3222299651, Str: "DRM_IOCTL_IRQ_BUSID"}, // From drm/drm.h
			{Val: 1074291754, Str: "DRM_IOCTL_LOCK"}, // From drm/drm.h
			{Val: 3222823961, Str: "DRM_IOCTL_MAP_BUFS"}, // From drm/drm.h
			{Val: 1075864599, Str: "DRM_IOCTL_MARK_BUFS"}, // From drm/drm.h
			{Val: 1074291720, Str: "DRM_IOCTL_MODESET_CTL"}, // From drm/drm.h
			{Val: 3223086254, Str: "DRM_IOCTL_MODE_ADDFB"}, // From drm/drm.h
			{Val: 3228067000, Str: "DRM_IOCTL_MODE_ADDFB2"}, // From drm/drm.h
			{Val: 3224921276, Str: "DRM_IOCTL_MODE_ATOMIC"}, // From drm/drm.h
			{Val: 3225969832, Str: "DRM_IOCTL_MODE_ATTACHMODE"}, // From drm/drm.h
			{Val: 3221775568, Str: "DRM_IOCTL_MODE_CLOSEFB"}, // From drm/drm.h
			{Val: 3222299837, Str: "DRM_IOCTL_MODE_CREATEPROPBLOB"}, // From drm/drm.h
			{Val: 3223348402, Str: "DRM_IOCTL_MODE_CREATE_DUMB"}, // From drm/drm.h
			{Val: 3222824134, Str: "DRM_IOCTL_MODE_CREATE_LEASE"}, // From drm/drm.h
			{Val: 3223086243, Str: "DRM_IOCTL_MODE_CURSOR"}, // From drm/drm.h
			{Val: 3223610555, Str: "DRM_IOCTL_MODE_CURSOR2"}, // From drm/drm.h
			{Val: 3221513406, Str: "DRM_IOCTL_MODE_DESTROYPROPBLOB"}, // From drm/drm.h
			{Val: 3221513396, Str: "DRM_IOCTL_MODE_DESTROY_DUMB"}, // From drm/drm.h
			{Val: 3225969833, Str: "DRM_IOCTL_MODE_DETACHMODE"}, // From drm/drm.h
			{Val: 3222824113, Str: "DRM_IOCTL_MODE_DIRTYFB"}, // From drm/drm.h
			{Val: 3226494119, Str: "DRM_IOCTL_MODE_GETCONNECTOR"}, // From drm/drm.h
			{Val: 3228066977, Str: "DRM_IOCTL_MODE_GETCRTC"}, // From drm/drm.h
			{Val: 3222561958, Str: "DRM_IOCTL_MODE_GETENCODER"}, // From drm/drm.h
			{Val: 3223086253, Str: "DRM_IOCTL_MODE_GETFB"}, // From drm/drm.h
			{Val: 3228067022, Str: "DRM_IOCTL_MODE_GETFB2"}, // From drm/drm.h
			{Val: 3223348388, Str: "DRM_IOCTL_MODE_GETGAMMA"}, // From drm/drm.h
			{Val: 3223348406, Str: "DRM_IOCTL_MODE_GETPLANE"}, // From drm/drm.h
			{Val: 3222299829, Str: "DRM_IOCTL_MODE_GETPLANERESOURCES"}, // From drm/drm.h
			{Val: 3222299820, Str: "DRM_IOCTL_MODE_GETPROPBLOB"}, // From drm/drm.h
			{Val: 3225445546, Str: "DRM_IOCTL_MODE_GETPROPERTY"}, // From drm/drm.h
			{Val: 3225445536, Str: "DRM_IOCTL_MODE_GETRESOURCES"}, // From drm/drm.h
			{Val: 3222299848, Str: "DRM_IOCTL_MODE_GET_LEASE"}, // From drm/drm.h
			{Val: 3222299847, Str: "DRM_IOCTL_MODE_LIST_LESSEES"}, // From drm/drm.h
			{Val: 3222299827, Str: "DRM_IOCTL_MODE_MAP_DUMB"}, // From drm/drm.h
			{Val: 3223348409, Str: "DRM_IOCTL_MODE_OBJ_GETPROPERTIES"}, // From drm/drm.h
			{Val: 3222824122, Str: "DRM_IOCTL_MODE_OBJ_SETPROPERTY"}, // From drm/drm.h
			{Val: 3222824112, Str: "DRM_IOCTL_MODE_PAGE_FLIP"}, // From drm/drm.h
			{Val: 3221513417, Str: "DRM_IOCTL_MODE_REVOKE_LEASE"}, // From drm/drm.h
			{Val: 3221513391, Str: "DRM_IOCTL_MODE_RMFB"}, // From drm/drm.h
			{Val: 3228066978, Str: "DRM_IOCTL_MODE_SETCRTC"}, // From drm/drm.h
			{Val: 3223348389, Str: "DRM_IOCTL_MODE_SETGAMMA"}, // From drm/drm.h
			{Val: 3224396983, Str: "DRM_IOCTL_MODE_SETPLANE"}, // From drm/drm.h
			{Val: 3222299819, Str: "DRM_IOCTL_MODE_SETPROPERTY"}, // From drm/drm.h
			{Val: 1074291746, Str: "DRM_IOCTL_MOD_CTX"}, // From drm/drm.h
			{Val: 1074291749, Str: "DRM_IOCTL_NEW_CTX"}, // From drm/drm.h
			{Val: 3222037550, Str: "DRM_IOCTL_PRIME_FD_TO_HANDLE"}, // From drm/drm.h
			{Val: 3222037549, Str: "DRM_IOCTL_PRIME_HANDLE_TO_FD"}, // From drm/drm.h
			{Val: 3222299686, Str: "DRM_IOCTL_RES_CTX"}, // From drm/drm.h
			{Val: 3221775393, Str: "DRM_IOCTL_RM_CTX"}, // From drm/drm.h
			{Val: 3221513256, Str: "DRM_IOCTL_RM_DRAW"}, // From drm/drm.h
			{Val: 1076388891, Str: "DRM_IOCTL_RM_MAP"}, // From drm/drm.h
			{Val: 1074816013, Str: "DRM_IOCTL_SET_CLIENT_CAP"}, // From drm/drm.h
			{Val: 3222299857, Str: "DRM_IOCTL_SET_CLIENT_NAME"}, // From drm/drm.h
			{Val: 25630, Str: "DRM_IOCTL_SET_MASTER"}, // From drm/drm.h
			{Val: 1074816028, Str: "DRM_IOCTL_SET_SAREA_CTX"}, // From drm/drm.h
			{Val: 1074816016, Str: "DRM_IOCTL_SET_UNIQUE"}, // From drm/drm.h
			{Val: 3222299655, Str: "DRM_IOCTL_SET_VERSION"}, // From drm/drm.h
			{Val: 3222299704, Str: "DRM_IOCTL_SG_ALLOC"}, // From drm/drm.h
			{Val: 1074816057, Str: "DRM_IOCTL_SG_FREE"}, // From drm/drm.h
			{Val: 1074291748, Str: "DRM_IOCTL_SWITCH_CTX"}, // From drm/drm.h
			{Val: 3221775551, Str: "DRM_IOCTL_SYNCOBJ_CREATE"}, // From drm/drm.h
			{Val: 3221775552, Str: "DRM_IOCTL_SYNCOBJ_DESTROY"}, // From drm/drm.h
			{Val: 3222824143, Str: "DRM_IOCTL_SYNCOBJ_EVENTFD"}, // From drm/drm.h
			{Val: 3222824130, Str: "DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE"}, // From drm/drm.h
			{Val: 3222824129, Str: "DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD"}, // From drm/drm.h
			{Val: 3222824139, Str: "DRM_IOCTL_SYNCOBJ_QUERY"}, // From drm/drm.h
			{Val: 3222299844, Str: "DRM_IOCTL_SYNCOBJ_RESET"}, // From drm/drm.h
			{Val: 3222299845, Str: "DRM_IOCTL_SYNCOBJ_SIGNAL"}, // From drm/drm.h
			{Val: 3222824141, Str: "DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL"}, // From drm/drm.h
			{Val: 3224397002, Str: "DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT"}, // From drm/drm.h
			{Val: 3223348428, Str: "DRM_IOCTL_SYNCOBJ_TRANSFER"}, // From drm/drm.h
			{Val: 3223872707, Str: "DRM_IOCTL_SYNCOBJ_WAIT"}, // From drm/drm.h
			{Val: 3221513235, Str: "DRM_IOCTL_UNBLOCK"}, // From drm/drm.h
			{Val: 1074291755, Str: "DRM_IOCTL_UNLOCK"}, // From drm/drm.h
			{Val: 1075340351, Str: "DRM_IOCTL_UPDATE_DRAW"}, // From drm/drm.h
			{Val: 3225445376, Str: "DRM_IOCTL_VERSION"}, // From drm/drm.h
			{Val: 3222823994, Str: "DRM_IOCTL_WAIT_VBLANK"}, // From drm/drm.h
			{Val: 1074291781, Str: "DRM_IOCTL_ETNAVIV_GEM_CPU_FINI"}, // From drm/etnaviv_drm.h
			{Val: 1075340356, Str: "DRM_IOCTL_ETNAVIV_GEM_CPU_PREP"}, // From drm/etnaviv_drm.h
			{Val: 3222299715, Str: "DRM_IOCTL_ETNAVIV_GEM_INFO"}, // From drm/etnaviv_drm.h
			{Val: 3222299714, Str: "DRM_IOCTL_ETNAVIV_GEM_NEW"}, // From drm/etnaviv_drm.h
			{Val: 3225969734, Str: "DRM_IOCTL_ETNAVIV_GEM_SUBMIT"}, // From drm/etnaviv_drm.h
			{Val: 3222824008, Str: "DRM_IOCTL_ETNAVIV_GEM_USERPTR"}, // From drm/etnaviv_drm.h
			{Val: 1075864649, Str: "DRM_IOCTL_ETNAVIV_GEM_WAIT"}, // From drm/etnaviv_drm.h
			{Val: 3222299712, Str: "DRM_IOCTL_ETNAVIV_GET_PARAM"}, // From drm/etnaviv_drm.h
			{Val: 3225969738, Str: "DRM_IOCTL_ETNAVIV_PM_QUERY_DOM"}, // From drm/etnaviv_drm.h
			{Val: 3226231883, Str: "DRM_IOCTL_ETNAVIV_PM_QUERY_SIG"}, // From drm/etnaviv_drm.h
			{Val: 1075864647, Str: "DRM_IOCTL_ETNAVIV_WAIT_FENCE"}, // From drm/etnaviv_drm.h
			{Val: 3221775458, Str: "DRM_IOCTL_EXYNOS_G2D_EXEC"}, // From drm/exynos_drm.h
			{Val: 3221775456, Str: "DRM_IOCTL_EXYNOS_G2D_GET_VER"}, // From drm/exynos_drm.h
			{Val: 3223872609, Str: "DRM_IOCTL_EXYNOS_G2D_SET_CMDLIST"}, // From drm/exynos_drm.h
			{Val: 3222299712, Str: "DRM_IOCTL_EXYNOS_GEM_CREATE"}, // From drm/exynos_drm.h
			{Val: 3222299716, Str: "DRM_IOCTL_EXYNOS_GEM_GET"}, // From drm/exynos_drm.h
			{Val: 3222299713, Str: "DRM_IOCTL_EXYNOS_GEM_MAP"}, // From drm/exynos_drm.h
			{Val: 3223348355, Str: "DRM_IOCTL_EXYNOS_IPP_COMMIT"}, // From drm/exynos_drm.h
			{Val: 3222824065, Str: "DRM_IOCTL_EXYNOS_IPP_GET_CAPS"}, // From drm/exynos_drm.h
			{Val: 3223348354, Str: "DRM_IOCTL_EXYNOS_IPP_GET_LIMITS"}, // From drm/exynos_drm.h
			{Val: 3222299776, Str: "DRM_IOCTL_EXYNOS_IPP_GET_RESOURCES"}, // From drm/exynos_drm.h
			{Val: 3222299719, Str: "DRM_IOCTL_EXYNOS_VIDI_CONNECTION"}, // From drm/exynos_drm.h
			{Val: 3222824001, Str: "DRM_IOCTL_HL_CB"}, // From drm/habanalabs_accel.h
			{Val: 3224396866, Str: "DRM_IOCTL_HL_CS"}, // From drm/habanalabs_accel.h
			{Val: 3223872581, Str: "DRM_IOCTL_HL_DEBUG"}, // From drm/habanalabs_accel.h
			{Val: 3222824000, Str: "DRM_IOCTL_HL_INFO"}, // From drm/habanalabs_accel.h
			{Val: 3223872580, Str: "DRM_IOCTL_HL_MEMORY"}, // From drm/habanalabs_accel.h
			{Val: 3224921155, Str: "DRM_IOCTL_HL_WAIT_CS"}, // From drm/habanalabs_accel.h
			{Val: 3222824008, Str: "DRM_IOCTL_I915_ALLOC"}, // From drm/i915_drm.h
			{Val: 1075864643, Str: "DRM_IOCTL_I915_BATCHBUFFER"}, // From drm/i915_drm.h
			{Val: 1075864651, Str: "DRM_IOCTL_I915_CMDBUFFER"}, // From drm/i915_drm.h
			{Val: 1074029644, Str: "DRM_IOCTL_I915_DESTROY_HEAP"}, // From drm/i915_drm.h
			{Val: 25666, Str: "DRM_IOCTL_I915_FLIP"}, // From drm/i915_drm.h
			{Val: 25665, Str: "DRM_IOCTL_I915_FLUSH"}, // From drm/i915_drm.h
			{Val: 1074291785, Str: "DRM_IOCTL_I915_FREE"}, // From drm/i915_drm.h
			{Val: 3221775447, Str: "DRM_IOCTL_I915_GEM_BUSY"}, // From drm/i915_drm.h
			{Val: 3221775469, Str: "DRM_IOCTL_I915_GEM_CONTEXT_CREATE"}, // From drm/i915_drm.h
			{Val: 3222299757, Str: "DRM_IOCTL_I915_GEM_CONTEXT_CREATE_EXT"}, // From drm/i915_drm.h
			{Val: 1074291822, Str: "DRM_IOCTL_I915_GEM_CONTEXT_DESTROY"}, // From drm/i915_drm.h
			{Val: 3222824052, Str: "DRM_IOCTL_I915_GEM_CONTEXT_GETPARAM"}, // From drm/i915_drm.h
			{Val: 3222824053, Str: "DRM_IOCTL_I915_GEM_CONTEXT_SETPARAM"}, // From drm/i915_drm.h
			{Val: 3222299739, Str: "DRM_IOCTL_I915_GEM_CREATE"}, // From drm/i915_drm.h
			{Val: 3222824060, Str: "DRM_IOCTL_I915_GEM_CREATE_EXT"}, // From drm/i915_drm.h
			{Val: 25689, Str: "DRM_IOCTL_I915_GEM_ENTERVT"}, // From drm/i915_drm.h
			{Val: 1076388948, Str: "DRM_IOCTL_I915_GEM_EXECBUFFER"}, // From drm/i915_drm.h
			{Val: 1077961833, Str: "DRM_IOCTL_I915_GEM_EXECBUFFER2"}, // From drm/i915_drm.h
			{Val: 3225445481, Str: "DRM_IOCTL_I915_GEM_EXECBUFFER2_WR"}, // From drm/i915_drm.h
			{Val: 2148557923, Str: "DRM_IOCTL_I915_GEM_GET_APERTURE"}, // From drm/i915_drm.h
			{Val: 3221775472, Str: "DRM_IOCTL_I915_GEM_GET_CACHING"}, // From drm/i915_drm.h
			{Val: 3222299746, Str: "DRM_IOCTL_I915_GEM_GET_TILING"}, // From drm/i915_drm.h
			{Val: 1074816083, Str: "DRM_IOCTL_I915_GEM_INIT"}, // From drm/i915_drm.h
			{Val: 25690, Str: "DRM_IOCTL_I915_GEM_LEAVEVT"}, // From drm/i915_drm.h
			{Val: 3222037606, Str: "DRM_IOCTL_I915_GEM_MADVISE"}, // From drm/i915_drm.h
			{Val: 3223872606, Str: "DRM_IOCTL_I915_GEM_MMAP"}, // From drm/i915_drm.h
			{Val: 3222299748, Str: "DRM_IOCTL_I915_GEM_MMAP_GTT"}, // From drm/i915_drm.h
			{Val: 3223348324, Str: "DRM_IOCTL_I915_GEM_MMAP_OFFSET"}, // From drm/i915_drm.h
			{Val: 3222824021, Str: "DRM_IOCTL_I915_GEM_PIN"}, // From drm/i915_drm.h
			{Val: 1075864668, Str: "DRM_IOCTL_I915_GEM_PREAD"}, // From drm/i915_drm.h
			{Val: 1075864669, Str: "DRM_IOCTL_I915_GEM_PWRITE"}, // From drm/i915_drm.h
			{Val: 1074291823, Str: "DRM_IOCTL_I915_GEM_SET_CACHING"}, // From drm/i915_drm.h
			{Val: 1074553951, Str: "DRM_IOCTL_I915_GEM_SET_DOMAIN"}, // From drm/i915_drm.h
			{Val: 3222299745, Str: "DRM_IOCTL_I915_GEM_SET_TILING"}, // From drm/i915_drm.h
			{Val: 1074029664, Str: "DRM_IOCTL_I915_GEM_SW_FINISH"}, // From drm/i915_drm.h
			{Val: 25688, Str: "DRM_IOCTL_I915_GEM_THROTTLE"}, // From drm/i915_drm.h
			{Val: 1074291798, Str: "DRM_IOCTL_I915_GEM_UNPIN"}, // From drm/i915_drm.h
			{Val: 3222824051, Str: "DRM_IOCTL_I915_GEM_USERPTR"}, // From drm/i915_drm.h
			{Val: 3222299770, Str: "DRM_IOCTL_I915_GEM_VM_CREATE"}, // From drm/i915_drm.h
			{Val: 1074816123, Str: "DRM_IOCTL_I915_GEM_VM_DESTROY"}, // From drm/i915_drm.h
			{Val: 3222299756, Str: "DRM_IOCTL_I915_GEM_WAIT"}, // From drm/i915_drm.h
			{Val: 3222299718, Str: "DRM_IOCTL_I915_GETPARAM"}, // From drm/i915_drm.h
			{Val: 3221775461, Str: "DRM_IOCTL_I915_GET_PIPE_FROM_CRTC_ID"}, // From drm/i915_drm.h
			{Val: 3222824050, Str: "DRM_IOCTL_I915_GET_RESET_STATS"}, // From drm/i915_drm.h
			{Val: 3222561898, Str: "DRM_IOCTL_I915_GET_SPRITE_COLORKEY"}, // From drm/i915_drm.h
			{Val: 2147771470, Str: "DRM_IOCTL_I915_GET_VBLANK_PIPE"}, // From drm/i915_drm.h
			{Val: 1074816081, Str: "DRM_IOCTL_I915_HWS_ADDR"}, // From drm/i915_drm.h
			{Val: 1078223936, Str: "DRM_IOCTL_I915_INIT"}, // From drm/i915_drm.h
			{Val: 1074553930, Str: "DRM_IOCTL_I915_INIT_HEAP"}, // From drm/i915_drm.h
			{Val: 3221775428, Str: "DRM_IOCTL_I915_IRQ_EMIT"}, // From drm/i915_drm.h
			{Val: 1074029637, Str: "DRM_IOCTL_I915_IRQ_WAIT"}, // From drm/i915_drm.h
			{Val: 3224134760, Str: "DRM_IOCTL_I915_OVERLAY_ATTRS"}, // From drm/i915_drm.h
			{Val: 1076651111, Str: "DRM_IOCTL_I915_OVERLAY_PUT_IMAGE"}, // From drm/i915_drm.h
			{Val: 1078486135, Str: "DRM_IOCTL_I915_PERF_ADD_CONFIG"}, // From drm/i915_drm.h
			{Val: 1074816118, Str: "DRM_IOCTL_I915_PERF_OPEN"}, // From drm/i915_drm.h
			{Val: 1074291832, Str: "DRM_IOCTL_I915_PERF_REMOVE_CONFIG"}, // From drm/i915_drm.h
			{Val: 3222299769, Str: "DRM_IOCTL_I915_QUERY"}, // From drm/i915_drm.h
			{Val: 3222299761, Str: "DRM_IOCTL_I915_REG_READ"}, // From drm/i915_drm.h
			{Val: 1074291783, Str: "DRM_IOCTL_I915_SETPARAM"}, // From drm/i915_drm.h
			{Val: 3222561899, Str: "DRM_IOCTL_I915_SET_SPRITE_COLORKEY"}, // From drm/i915_drm.h
			{Val: 1074029645, Str: "DRM_IOCTL_I915_SET_VBLANK_PIPE"}, // From drm/i915_drm.h
			{Val: 3222037583, Str: "DRM_IOCTL_I915_VBLANK_SWAP"}, // From drm/i915_drm.h
			{Val: 26882, Str: "I915_PERF_IOCTL_CONFIG"}, // From drm/i915_drm.h
			{Val: 26881, Str: "I915_PERF_IOCTL_DISABLE"}, // From drm/i915_drm.h
			{Val: 26880, Str: "I915_PERF_IOCTL_ENABLE"}, // From drm/i915_drm.h
			{Val: 3222824002, Str: "DRM_IOCTL_IVPU_BO_CREATE"}, // From drm/ivpu_accel.h
			{Val: 3223348302, Str: "DRM_IOCTL_IVPU_BO_CREATE_FROM_USERPTR"}, // From drm/ivpu_accel.h
			{Val: 3223348291, Str: "DRM_IOCTL_IVPU_BO_INFO"}, // From drm/ivpu_accel.h
			{Val: 3222824006, Str: "DRM_IOCTL_IVPU_BO_WAIT"}, // From drm/ivpu_accel.h
			{Val: 3222037579, Str: "DRM_IOCTL_IVPU_CMDQ_CREATE"}, // From drm/ivpu_accel.h
			{Val: 1074029644, Str: "DRM_IOCTL_IVPU_CMDQ_DESTROY"}, // From drm/ivpu_accel.h
			{Val: 1075864653, Str: "DRM_IOCTL_IVPU_CMDQ_SUBMIT"}, // From drm/ivpu_accel.h
			{Val: 3222299712, Str: "DRM_IOCTL_IVPU_GET_PARAM"}, // From drm/ivpu_accel.h
			{Val: 3223348297, Str: "DRM_IOCTL_IVPU_METRIC_STREAMER_GET_DATA"}, // From drm/ivpu_accel.h
			{Val: 3223348298, Str: "DRM_IOCTL_IVPU_METRIC_STREAMER_GET_INFO"}, // From drm/ivpu_accel.h
			{Val: 3223348295, Str: "DRM_IOCTL_IVPU_METRIC_STREAMER_START"}, // From drm/ivpu_accel.h
			{Val: 1074291784, Str: "DRM_IOCTL_IVPU_METRIC_STREAMER_STOP"}, // From drm/ivpu_accel.h
			{Val: 1074816065, Str: "DRM_IOCTL_IVPU_SET_PARAM"}, // From drm/ivpu_accel.h
			{Val: 1075864645, Str: "DRM_IOCTL_IVPU_SUBMIT"}, // From drm/ivpu_accel.h
			{Val: 2148033605, Str: "DRM_IOCTL_LIMA_CTX_CREATE"}, // From drm/lima_drm.h
			{Val: 1074291782, Str: "DRM_IOCTL_LIMA_CTX_FREE"}, // From drm/lima_drm.h
			{Val: 3222299713, Str: "DRM_IOCTL_LIMA_GEM_CREATE"}, // From drm/lima_drm.h
			{Val: 3222299714, Str: "DRM_IOCTL_LIMA_GEM_INFO"}, // From drm/lima_drm.h
			{Val: 1076913219, Str: "DRM_IOCTL_LIMA_GEM_SUBMIT"}, // From drm/lima_drm.h
			{Val: 1074816068, Str: "DRM_IOCTL_LIMA_GEM_WAIT"}, // From drm/lima_drm.h
			{Val: 3222299712, Str: "DRM_IOCTL_LIMA_GET_PARAM"}, // From drm/lima_drm.h
			{Val: 1074029637, Str: "DRM_IOCTL_MSM_GEM_CPU_FINI"}, // From drm/msm_drm.h
			{Val: 1075340356, Str: "DRM_IOCTL_MSM_GEM_CPU_PREP"}, // From drm/msm_drm.h
			{Val: 3222824003, Str: "DRM_IOCTL_MSM_GEM_INFO"}, // From drm/msm_drm.h
			{Val: 3222037576, Str: "DRM_IOCTL_MSM_GEM_MADVISE"}, // From drm/msm_drm.h
			{Val: 3222299714, Str: "DRM_IOCTL_MSM_GEM_NEW"}, // From drm/msm_drm.h
			{Val: 3225969734, Str: "DRM_IOCTL_MSM_GEM_SUBMIT"}, // From drm/msm_drm.h
			{Val: 3222824000, Str: "DRM_IOCTL_MSM_GET_PARAM"}, // From drm/msm_drm.h
			{Val: 1075340353, Str: "DRM_IOCTL_MSM_SET_PARAM"}, // From drm/msm_drm.h
			{Val: 1074029643, Str: "DRM_IOCTL_MSM_SUBMITQUEUE_CLOSE"}, // From drm/msm_drm.h
			{Val: 3222037578, Str: "DRM_IOCTL_MSM_SUBMITQUEUE_NEW"}, // From drm/msm_drm.h
			{Val: 1075340364, Str: "DRM_IOCTL_MSM_SUBMITQUEUE_QUERY"}, // From drm/msm_drm.h
			{Val: 3227018317, Str: "DRM_IOCTL_MSM_VM_BIND"}, // From drm/msm_drm.h
			{Val: 1075864647, Str: "DRM_IOCTL_MSM_WAIT_FENCE"}, // From drm/msm_drm.h
			{Val: 3227018306, Str: "DRM_IOCTL_NOUVEAU_CHANNEL_ALLOC"}, // From drm/nouveau_drm.h
			{Val: 1074029635, Str: "DRM_IOCTL_NOUVEAU_CHANNEL_FREE"}, // From drm/nouveau_drm.h
			{Val: 3223872594, Str: "DRM_IOCTL_NOUVEAU_EXEC"}, // From drm/nouveau_drm.h
			{Val: 1074029699, Str: "DRM_IOCTL_NOUVEAU_GEM_CPU_FINI"}, // From drm/nouveau_drm.h
			{Val: 1074291842, Str: "DRM_IOCTL_NOUVEAU_GEM_CPU_PREP"}, // From drm/nouveau_drm.h
			{Val: 3223872644, Str: "DRM_IOCTL_NOUVEAU_GEM_INFO"}, // From drm/nouveau_drm.h
			{Val: 3224396928, Str: "DRM_IOCTL_NOUVEAU_GEM_NEW"}, // From drm/nouveau_drm.h
			{Val: 3225445505, Str: "DRM_IOCTL_NOUVEAU_GEM_PUSHBUF"}, // From drm/nouveau_drm.h
			{Val: 3222299712, Str: "DRM_IOCTL_NOUVEAU_GETPARAM"}, // From drm/nouveau_drm.h
			{Val: 3225445449, Str: "DRM_IOCTL_NOUVEAU_SVM_BIND"}, // From drm/nouveau_drm.h
			{Val: 3222299720, Str: "DRM_IOCTL_NOUVEAU_SVM_INIT"}, // From drm/nouveau_drm.h
			{Val: 3223872593, Str: "DRM_IOCTL_NOUVEAU_VM_BIND"}, // From drm/nouveau_drm.h
			{Val: 3222299728, Str: "DRM_IOCTL_NOUVEAU_VM_INIT"}, // From drm/nouveau_drm.h
			{Val: 3222299713, Str: "DRM_IOCTL_NOVA_GEM_CREATE"}, // From drm/nova_drm.h
			{Val: 3222299714, Str: "DRM_IOCTL_NOVA_GEM_INFO"}, // From drm/nova_drm.h
			{Val: 3222299712, Str: "DRM_IOCTL_NOVA_GETPARAM"}, // From drm/nova_drm.h
			{Val: 1074816069, Str: "DRM_IOCTL_OMAP_GEM_CPU_FINI"}, // From drm/omap_drm.h
			{Val: 1074291780, Str: "DRM_IOCTL_OMAP_GEM_CPU_PREP"}, // From drm/omap_drm.h
			{Val: 3222824006, Str: "DRM_IOCTL_OMAP_GEM_INFO"}, // From drm/omap_drm.h
			{Val: 3222299715, Str: "DRM_IOCTL_OMAP_GEM_NEW"}, // From drm/omap_drm.h
			{Val: 3222299712, Str: "DRM_IOCTL_OMAP_GET_PARAM"}, // From drm/omap_drm.h
			{Val: 1074816065, Str: "DRM_IOCTL_OMAP_SET_PARAM"}, // From drm/omap_drm.h
			{Val: 3222824002, Str: "DRM_IOCTL_PANFROST_CREATE_BO"}, // From drm/panfrost_drm.h
			{Val: 3222299717, Str: "DRM_IOCTL_PANFROST_GET_BO_OFFSET"}, // From drm/panfrost_drm.h
			{Val: 3222299716, Str: "DRM_IOCTL_PANFROST_GET_PARAM"}, // From drm/panfrost_drm.h
			{Val: 3221775434, Str: "DRM_IOCTL_PANFROST_JM_CTX_CREATE"}, // From drm/panfrost_drm.h
			{Val: 3221775435, Str: "DRM_IOCTL_PANFROST_JM_CTX_DESTROY"}, // From drm/panfrost_drm.h
			{Val: 3222037576, Str: "DRM_IOCTL_PANFROST_MADVISE"}, // From drm/panfrost_drm.h
			{Val: 3222299715, Str: "DRM_IOCTL_PANFROST_MMAP_BO"}, // From drm/panfrost_drm.h
			{Val: 1074291783, Str: "DRM_IOCTL_PANFROST_PERFCNT_DUMP"}, // From drm/panfrost_drm.h
			{Val: 1074291782, Str: "DRM_IOCTL_PANFROST_PERFCNT_ENABLE"}, // From drm/panfrost_drm.h
			{Val: 3222299725, Str: "DRM_IOCTL_PANFROST_QUERY_BO_INFO"}, // From drm/panfrost_drm.h
			{Val: 3222299721, Str: "DRM_IOCTL_PANFROST_SET_LABEL_BO"}, // From drm/panfrost_drm.h
			{Val: 1076913216, Str: "DRM_IOCTL_PANFROST_SUBMIT"}, // From drm/panfrost_drm.h
			{Val: 3222299724, Str: "DRM_IOCTL_PANFROST_SYNC_BO"}, // From drm/panfrost_drm.h
			{Val: 1074816065, Str: "DRM_IOCTL_PANFROST_WAIT_BO"}, // From drm/panfrost_drm.h
			{Val: 3222824001, Str: "DRM_IOCTL_PVR_CREATE_BO"}, // From drm/pvr_drm.h
			{Val: 3223872583, Str: "DRM_IOCTL_PVR_CREATE_CONTEXT"}, // From drm/pvr_drm.h
			{Val: 3223348297, Str: "DRM_IOCTL_PVR_CREATE_FREE_LIST"}, // From drm/pvr_drm.h
			{Val: 3230164043, Str: "DRM_IOCTL_PVR_CREATE_HWRT_DATASET"}, // From drm/pvr_drm.h
			{Val: 3221775427, Str: "DRM_IOCTL_PVR_CREATE_VM_CONTEXT"}, // From drm/pvr_drm.h
			{Val: 1074291784, Str: "DRM_IOCTL_PVR_DESTROY_CONTEXT"}, // From drm/pvr_drm.h
			{Val: 1074291786, Str: "DRM_IOCTL_PVR_DESTROY_FREE_LIST"}, // From drm/pvr_drm.h
			{Val: 1074291788, Str: "DRM_IOCTL_PVR_DESTROY_HWRT_DATASET"}, // From drm/pvr_drm.h
			{Val: 1074291780, Str: "DRM_IOCTL_PVR_DESTROY_VM_CONTEXT"}, // From drm/pvr_drm.h
			{Val: 3222299712, Str: "DRM_IOCTL_PVR_DEV_QUERY"}, // From drm/pvr_drm.h
			{Val: 3222299714, Str: "DRM_IOCTL_PVR_GET_BO_MMAP_OFFSET"}, // From drm/pvr_drm.h
			{Val: 1074816077, Str: "DRM_IOCTL_PVR_SUBMIT_JOBS"}, // From drm/pvr_drm.h
			{Val: 1076388933, Str: "DRM_IOCTL_PVR_VM_MAP"}, // From drm/pvr_drm.h
			{Val: 1075340358, Str: "DRM_IOCTL_PVR_VM_UNMAP"}, // From drm/pvr_drm.h
			{Val: 1075864643, Str: "DRM_IOCTL_QAIC_ATTACH_SLICE_BO"}, // From drm/qaic_accel.h
			{Val: 3222299713, Str: "DRM_IOCTL_QAIC_CREATE_BO"}, // From drm/qaic_accel.h
			{Val: 1074291784, Str: "DRM_IOCTL_QAIC_DETACH_SLICE_BO"}, // From drm/qaic_accel.h
			{Val: 1074816068, Str: "DRM_IOCTL_QAIC_EXECUTE_BO"}, // From drm/qaic_accel.h
			{Val: 3222299712, Str: "DRM_IOCTL_QAIC_MANAGE"}, // From drm/qaic_accel.h
			{Val: 3222299714, Str: "DRM_IOCTL_QAIC_MMAP_BO"}, // From drm/qaic_accel.h
			{Val: 1074816069, Str: "DRM_IOCTL_QAIC_PARTIAL_EXECUTE_BO"}, // From drm/qaic_accel.h
			{Val: 3222299719, Str: "DRM_IOCTL_QAIC_PERF_STATS_BO"}, // From drm/qaic_accel.h
			{Val: 1074816070, Str: "DRM_IOCTL_QAIC_WAIT_BO"}, // From drm/qaic_accel.h
			{Val: 3221775424, Str: "DRM_IOCTL_QXL_ALLOC"}, // From drm/qxl_drm.h
			{Val: 3222824006, Str: "DRM_IOCTL_QXL_ALLOC_SURF"}, // From drm/qxl_drm.h
			{Val: 1074291781, Str: "DRM_IOCTL_QXL_CLIENTCAP"}, // From drm/qxl_drm.h
			{Val: 1074816066, Str: "DRM_IOCTL_QXL_EXECBUFFER"}, // From drm/qxl_drm.h
			{Val: 3222299716, Str: "DRM_IOCTL_QXL_GETPARAM"}, // From drm/qxl_drm.h
			{Val: 3222299713, Str: "DRM_IOCTL_QXL_MAP"}, // From drm/qxl_drm.h
			{Val: 1075340355, Str: "DRM_IOCTL_QXL_UPDATE_AREA"}, // From drm/qxl_drm.h
			{Val: 3222824019, Str: "DRM_IOCTL_RADEON_ALLOC"}, // From drm/radeon_drm.h
			{Val: 1075864648, Str: "DRM_IOCTL_RADEON_CLEAR"}, // From drm/radeon_drm.h
			{Val: 1075864656, Str: "DRM_IOCTL_RADEON_CMDBUF"}, // From drm/radeon_drm.h
			{Val: 25668, Str: "DRM_IOCTL_RADEON_CP_IDLE"}, // From drm/radeon_drm.h
			{Val: 1081631808, Str: "DRM_IOCTL_RADEON_CP_INIT"}, // From drm/radeon_drm.h
			{Val: 25667, Str: "DRM_IOCTL_RADEON_CP_RESET"}, // From drm/radeon_drm.h
			{Val: 25688, Str: "DRM_IOCTL_RADEON_CP_RESUME"}, // From drm/radeon_drm.h
			{Val: 25665, Str: "DRM_IOCTL_RADEON_CP_START"}, // From drm/radeon_drm.h
			{Val: 1074291778, Str: "DRM_IOCTL_RADEON_CP_STOP"}, // From drm/radeon_drm.h
			{Val: 3223348326, Str: "DRM_IOCTL_RADEON_CS"}, // From drm/radeon_drm.h
			{Val: 25682, Str: "DRM_IOCTL_RADEON_FLIP"}, // From drm/radeon_drm.h
			{Val: 1074291796, Str: "DRM_IOCTL_RADEON_FREE"}, // From drm/radeon_drm.h
			{Val: 1074029638, Str: "DRM_IOCTL_RADEON_FULLSCREEN"}, // From drm/radeon_drm.h
			{Val: 3221775466, Str: "DRM_IOCTL_RADEON_GEM_BUSY"}, // From drm/radeon_drm.h
			{Val: 3223348317, Str: "DRM_IOCTL_RADEON_GEM_CREATE"}, // From drm/radeon_drm.h
			{Val: 3222037609, Str: "DRM_IOCTL_RADEON_GEM_GET_TILING"}, // From drm/radeon_drm.h
			{Val: 3222824028, Str: "DRM_IOCTL_RADEON_GEM_INFO"}, // From drm/radeon_drm.h
			{Val: 3223348318, Str: "DRM_IOCTL_RADEON_GEM_MMAP"}, // From drm/radeon_drm.h
			{Val: 3222299756, Str: "DRM_IOCTL_RADEON_GEM_OP"}, // From drm/radeon_drm.h
			{Val: 3223348321, Str: "DRM_IOCTL_RADEON_GEM_PREAD"}, // From drm/radeon_drm.h
			{Val: 3223348322, Str: "DRM_IOCTL_RADEON_GEM_PWRITE"}, // From drm/radeon_drm.h
			{Val: 3222037603, Str: "DRM_IOCTL_RADEON_GEM_SET_DOMAIN"}, // From drm/radeon_drm.h
			{Val: 3222037608, Str: "DRM_IOCTL_RADEON_GEM_SET_TILING"}, // From drm/radeon_drm.h
			{Val: 3222824045, Str: "DRM_IOCTL_RADEON_GEM_USERPTR"}, // From drm/radeon_drm.h
			{Val: 3222824043, Str: "DRM_IOCTL_RADEON_GEM_VA"}, // From drm/radeon_drm.h
			{Val: 1074291812, Str: "DRM_IOCTL_RADEON_GEM_WAIT_IDLE"}, // From drm/radeon_drm.h
			{Val: 3222299729, Str: "DRM_IOCTL_RADEON_GETPARAM"}, // From drm/radeon_drm.h
			{Val: 1075078218, Str: "DRM_IOCTL_RADEON_INDICES"}, // From drm/radeon_drm.h
			{Val: 3222299725, Str: "DRM_IOCTL_RADEON_INDIRECT"}, // From drm/radeon_drm.h
			{Val: 3222299751, Str: "DRM_IOCTL_RADEON_INFO"}, // From drm/radeon_drm.h
			{Val: 1074553941, Str: "DRM_IOCTL_RADEON_INIT_HEAP"}, // From drm/radeon_drm.h
			{Val: 3221775446, Str: "DRM_IOCTL_RADEON_IRQ_EMIT"}, // From drm/radeon_drm.h
			{Val: 1074029655, Str: "DRM_IOCTL_RADEON_IRQ_WAIT"}, // From drm/radeon_drm.h
			{Val: 25669, Str: "DRM_IOCTL_RADEON_RESET"}, // From drm/radeon_drm.h
			{Val: 1074816089, Str: "DRM_IOCTL_RADEON_SETPARAM"}, // From drm/radeon_drm.h
			{Val: 1074291788, Str: "DRM_IOCTL_RADEON_STIPPLE"}, // From drm/radeon_drm.h
			{Val: 1074553946, Str: "DRM_IOCTL_RADEON_SURF_ALLOC"}, // From drm/radeon_drm.h
			{Val: 1074029659, Str: "DRM_IOCTL_RADEON_SURF_FREE"}, // From drm/radeon_drm.h
			{Val: 25671, Str: "DRM_IOCTL_RADEON_SWAP"}, // From drm/radeon_drm.h
			{Val: 3223348302, Str: "DRM_IOCTL_RADEON_TEXTURE"}, // From drm/radeon_drm.h
			{Val: 1074816073, Str: "DRM_IOCTL_RADEON_VERTEX"}, // From drm/radeon_drm.h
			{Val: 1076388943, Str: "DRM_IOCTL_RADEON_VERTEX2"}, // From drm/radeon_drm.h
			{Val: 3222824000, Str: "DRM_IOCTL_ROCKET_CREATE_BO"}, // From drm/rocket_accel.h
			{Val: 1074291779, Str: "DRM_IOCTL_ROCKET_FINI_BO"}, // From drm/rocket_accel.h
			{Val: 1074816066, Str: "DRM_IOCTL_ROCKET_PREP_BO"}, // From drm/rocket_accel.h
			{Val: 1075340353, Str: "DRM_IOCTL_ROCKET_SUBMIT"}, // From drm/rocket_accel.h
			{Val: 3221775441, Str: "DRM_IOCTL_TEGRA_CHANNEL_CLOSE"}, // From drm/tegra_drm.h
			{Val: 3222299730, Str: "DRM_IOCTL_TEGRA_CHANNEL_MAP"}, // From drm/tegra_drm.h
			{Val: 3222824016, Str: "DRM_IOCTL_TEGRA_CHANNEL_OPEN"}, // From drm/tegra_drm.h
			{Val: 3225445460, Str: "DRM_IOCTL_TEGRA_CHANNEL_SUBMIT"}, // From drm/tegra_drm.h
			{Val: 3221775443, Str: "DRM_IOCTL_TEGRA_CHANNEL_UNMAP"}, // From drm/tegra_drm.h
			{Val: 3221775430, Str: "DRM_IOCTL_TEGRA_CLOSE_CHANNEL"}, // From drm/tegra_drm.h
			{Val: 3222299712, Str: "DRM_IOCTL_TEGRA_GEM_CREATE"}, // From drm/tegra_drm.h
			{Val: 3221775437, Str: "DRM_IOCTL_TEGRA_GEM_GET_FLAGS"}, // From drm/tegra_drm.h
			{Val: 3222299723, Str: "DRM_IOCTL_TEGRA_GEM_GET_TILING"}, // From drm/tegra_drm.h
			{Val: 3222299713, Str: "DRM_IOCTL_TEGRA_GEM_MMAP"}, // From drm/tegra_drm.h
			{Val: 3221775436, Str: "DRM_IOCTL_TEGRA_GEM_SET_FLAGS"}, // From drm/tegra_drm.h
			{Val: 3222299722, Str: "DRM_IOCTL_TEGRA_GEM_SET_TILING"}, // From drm/tegra_drm.h
			{Val: 3222299719, Str: "DRM_IOCTL_TEGRA_GET_SYNCPT"}, // From drm/tegra_drm.h
			{Val: 3222299721, Str: "DRM_IOCTL_TEGRA_GET_SYNCPT_BASE"}, // From drm/tegra_drm.h
			{Val: 3222299717, Str: "DRM_IOCTL_TEGRA_OPEN_CHANNEL"}, // From drm/tegra_drm.h
			{Val: 3227018312, Str: "DRM_IOCTL_TEGRA_SUBMIT"}, // From drm/tegra_drm.h
			{Val: 3221775456, Str: "DRM_IOCTL_TEGRA_SYNCPOINT_ALLOCATE"}, // From drm/tegra_drm.h
			{Val: 3221775457, Str: "DRM_IOCTL_TEGRA_SYNCPOINT_FREE"}, // From drm/tegra_drm.h
			{Val: 3222824034, Str: "DRM_IOCTL_TEGRA_SYNCPOINT_WAIT"}, // From drm/tegra_drm.h
			{Val: 3221775427, Str: "DRM_IOCTL_TEGRA_SYNCPT_INCR"}, // From drm/tegra_drm.h
			{Val: 3221775426, Str: "DRM_IOCTL_TEGRA_SYNCPT_READ"}, // From drm/tegra_drm.h
			{Val: 3222299716, Str: "DRM_IOCTL_TEGRA_SYNCPT_WAIT"}, // From drm/tegra_drm.h
			{Val: 3222299714, Str: "DRM_IOCTL_V3D_CREATE_BO"}, // From drm/v3d_drm.h
			{Val: 3221775429, Str: "DRM_IOCTL_V3D_GET_BO_OFFSET"}, // From drm/v3d_drm.h
			{Val: 3222299716, Str: "DRM_IOCTL_V3D_GET_PARAM"}, // From drm/v3d_drm.h
			{Val: 3222299715, Str: "DRM_IOCTL_V3D_MMAP_BO"}, // From drm/v3d_drm.h
			{Val: 3223872584, Str: "DRM_IOCTL_V3D_PERFMON_CREATE"}, // From drm/v3d_drm.h
			{Val: 3221513289, Str: "DRM_IOCTL_V3D_PERFMON_DESTROY"}, // From drm/v3d_drm.h
			{Val: 3244844108, Str: "DRM_IOCTL_V3D_PERFMON_GET_COUNTER"}, // From drm/v3d_drm.h
			{Val: 3222299722, Str: "DRM_IOCTL_V3D_PERFMON_GET_VALUES"}, // From drm/v3d_drm.h
			{Val: 1074291789, Str: "DRM_IOCTL_V3D_PERFMON_SET_GLOBAL"}, // From drm/v3d_drm.h
			{Val: 3225969728, Str: "DRM_IOCTL_V3D_SUBMIT_CL"}, // From drm/v3d_drm.h
			{Val: 1075340363, Str: "DRM_IOCTL_V3D_SUBMIT_CPU"}, // From drm/v3d_drm.h
			{Val: 1079534663, Str: "DRM_IOCTL_V3D_SUBMIT_CSD"}, // From drm/v3d_drm.h
			{Val: 1079534662, Str: "DRM_IOCTL_V3D_SUBMIT_TFU"}, // From drm/v3d_drm.h
			{Val: 3222299713, Str: "DRM_IOCTL_V3D_WAIT_BO"}, // From drm/v3d_drm.h
			{Val: 3222299715, Str: "DRM_IOCTL_VC4_CREATE_BO"}, // From drm/vc4_drm.h
			{Val: 3222824005, Str: "DRM_IOCTL_VC4_CREATE_SHADER_BO"}, // From drm/vc4_drm.h
			{Val: 3222299723, Str: "DRM_IOCTL_VC4_GEM_MADVISE"}, // From drm/vc4_drm.h
			{Val: 3231736902, Str: "DRM_IOCTL_VC4_GET_HANG_STATE"}, // From drm/vc4_drm.h
			{Val: 3222299719, Str: "DRM_IOCTL_VC4_GET_PARAM"}, // From drm/vc4_drm.h
			{Val: 3222299721, Str: "DRM_IOCTL_VC4_GET_TILING"}, // From drm/vc4_drm.h
			{Val: 3222299722, Str: "DRM_IOCTL_VC4_LABEL_BO"}, // From drm/vc4_drm.h
			{Val: 3222299716, Str: "DRM_IOCTL_VC4_MMAP_BO"}, // From drm/vc4_drm.h
			{Val: 3222824012, Str: "DRM_IOCTL_VC4_PERFMON_CREATE"}, // From drm/vc4_drm.h
			{Val: 3221513293, Str: "DRM_IOCTL_VC4_PERFMON_DESTROY"}, // From drm/vc4_drm.h
			{Val: 3222299726, Str: "DRM_IOCTL_VC4_PERFMON_GET_VALUES"}, // From drm/vc4_drm.h
			{Val: 3222299720, Str: "DRM_IOCTL_VC4_SET_TILING"}, // From drm/vc4_drm.h
			{Val: 3232785472, Str: "DRM_IOCTL_VC4_SUBMIT_CL"}, // From drm/vc4_drm.h
			{Val: 3222299714, Str: "DRM_IOCTL_VC4_WAIT_BO"}, // From drm/vc4_drm.h
			{Val: 3222299713, Str: "DRM_IOCTL_VC4_WAIT_SEQNO"}, // From drm/vc4_drm.h
			{Val: 3222299713, Str: "DRM_IOCTL_VGEM_FENCE_ATTACH"}, // From drm/vgem_drm.h
			{Val: 1074291778, Str: "DRM_IOCTL_VGEM_FENCE_SIGNAL"}, // From drm/vgem_drm.h
			{Val: 3222299723, Str: "DRM_IOCTL_VIRTGPU_CONTEXT_INIT"}, // From drm/virtgpu_drm.h
			{Val: 3225445442, Str: "DRM_IOCTL_VIRTGPU_EXECBUFFER"}, // From drm/virtgpu_drm.h
			{Val: 3222299715, Str: "DRM_IOCTL_VIRTGPU_GETPARAM"}, // From drm/virtgpu_drm.h
			{Val: 3222824009, Str: "DRM_IOCTL_VIRTGPU_GET_CAPS"}, // From drm/virtgpu_drm.h
			{Val: 3222299713, Str: "DRM_IOCTL_VIRTGPU_MAP"}, // From drm/virtgpu_drm.h
			{Val: 3224921156, Str: "DRM_IOCTL_VIRTGPU_RESOURCE_CREATE"}, // From drm/virtgpu_drm.h
			{Val: 3224396874, Str: "DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB"}, // From drm/virtgpu_drm.h
			{Val: 3222299717, Str: "DRM_IOCTL_VIRTGPU_RESOURCE_INFO"}, // From drm/virtgpu_drm.h
			{Val: 3224134726, Str: "DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST"}, // From drm/virtgpu_drm.h
			{Val: 3224134727, Str: "DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST"}, // From drm/virtgpu_drm.h
			{Val: 3221775432, Str: "DRM_IOCTL_VIRTGPU_WAIT"}, // From drm/virtgpu_drm.h
			{Val: 3223872576, Str: "DRM_IOCTL_XE_DEVICE_QUERY"}, // From drm/xe_drm.h
			{Val: 1077437513, Str: "DRM_IOCTL_XE_EXEC"}, // From drm/xe_drm.h
			{Val: 3224396870, Str: "DRM_IOCTL_XE_EXEC_QUEUE_CREATE"}, // From drm/xe_drm.h
			{Val: 1075340359, Str: "DRM_IOCTL_XE_EXEC_QUEUE_DESTROY"}, // From drm/xe_drm.h
			{Val: 3223872584, Str: "DRM_IOCTL_XE_EXEC_QUEUE_GET_PROPERTY"}, // From drm/xe_drm.h
			{Val: 1076388942, Str: "DRM_IOCTL_XE_EXEC_QUEUE_SET_PROPERTY"}, // From drm/xe_drm.h
			{Val: 3224921153, Str: "DRM_IOCTL_XE_GEM_CREATE"}, // From drm/xe_drm.h
			{Val: 3223872578, Str: "DRM_IOCTL_XE_GEM_MMAP_OFFSET"}, // From drm/xe_drm.h
			{Val: 1077961804, Str: "DRM_IOCTL_XE_MADVISE"}, // From drm/xe_drm.h
			{Val: 1075864651, Str: "DRM_IOCTL_XE_OBSERVATION"}, // From drm/xe_drm.h
			{Val: 1082680389, Str: "DRM_IOCTL_XE_VM_BIND"}, // From drm/xe_drm.h
			{Val: 3223348291, Str: "DRM_IOCTL_XE_VM_CREATE"}, // From drm/xe_drm.h
			{Val: 1075340356, Str: "DRM_IOCTL_XE_VM_DESTROY"}, // From drm/xe_drm.h
			{Val: 3225445453, Str: "DRM_IOCTL_XE_VM_QUERY_MEM_RANGE_ATTRS"}, // From drm/xe_drm.h
			{Val: 3225969738, Str: "DRM_IOCTL_XE_WAIT_USER_FENCE"}, // From drm/xe_drm.h
			{Val: 26882, Str: "DRM_XE_OBSERVATION_IOCTL_CONFIG"}, // From drm/xe_drm.h
			{Val: 26881, Str: "DRM_XE_OBSERVATION_IOCTL_DISABLE"}, // From drm/xe_drm.h
			{Val: 26880, Str: "DRM_XE_OBSERVATION_IOCTL_ENABLE"}, // From drm/xe_drm.h
			{Val: 26884, Str: "DRM_XE_OBSERVATION_IOCTL_INFO"}, // From drm/xe_drm.h
			{Val: 26883, Str: "DRM_XE_OBSERVATION_IOCTL_STATUS"}, // From drm/xe_drm.h
			{Val: 39424, Str: "FWCTL_INFO"}, // From fwctl/fwctl.h
			{Val: 39425, Str: "FWCTL_RPC"}, // From fwctl/fwctl.h
			{Val: 1080599127, Str: "ACRN_IOCTL_ASSIGN_MMIODEV"}, // From linux/acrn.h
			{Val: 1076142677, Str: "ACRN_IOCTL_ASSIGN_PCIDEV"}, // From linux/acrn.h
			{Val: 41523, Str: "ACRN_IOCTL_ATTACH_IOREQ_CLIENT"}, // From linux/acrn.h
			{Val: 41525, Str: "ACRN_IOCTL_CLEAR_VM_IOREQ"}, // From linux/acrn.h
			{Val: 41522, Str: "ACRN_IOCTL_CREATE_IOREQ_CLIENT"}, // From linux/acrn.h
			{Val: 1086366297, Str: "ACRN_IOCTL_CREATE_VDEV"}, // From linux/acrn.h
			{Val: 3224412688, Str: "ACRN_IOCTL_CREATE_VM"}, // From linux/acrn.h
			{Val: 1080599128, Str: "ACRN_IOCTL_DEASSIGN_MMIODEV"}, // From linux/acrn.h
			{Val: 1076142678, Str: "ACRN_IOCTL_DEASSIGN_PCIDEV"}, // From linux/acrn.h
			{Val: 41524, Str: "ACRN_IOCTL_DESTROY_IOREQ_CLIENT"}, // From linux/acrn.h
			{Val: 1086366298, Str: "ACRN_IOCTL_DESTROY_VDEV"}, // From linux/acrn.h
			{Val: 41489, Str: "ACRN_IOCTL_DESTROY_VM"}, // From linux/acrn.h
			{Val: 1074831907, Str: "ACRN_IOCTL_INJECT_MSI"}, // From linux/acrn.h
			{Val: 1075880560, Str: "ACRN_IOCTL_IOEVENTFD"}, // From linux/acrn.h
			{Val: 1075356273, Str: "ACRN_IOCTL_IRQFD"}, // From linux/acrn.h
			{Val: 1074307633, Str: "ACRN_IOCTL_NOTIFY_REQUEST_FINISH"}, // From linux/acrn.h
			{Val: 41491, Str: "ACRN_IOCTL_PAUSE_VM"}, // From linux/acrn.h
			{Val: 3221791328, Str: "ACRN_IOCTL_PM_GET_CPU_STATE"}, // From linux/acrn.h
			{Val: 1075094100, Str: "ACRN_IOCTL_RESET_PTDEV_INTR"}, // From linux/acrn.h
			{Val: 41493, Str: "ACRN_IOCTL_RESET_VM"}, // From linux/acrn.h
			{Val: 1074307621, Str: "ACRN_IOCTL_SET_IRQLINE"}, // From linux/acrn.h
			{Val: 1075880513, Str: "ACRN_IOCTL_SET_MEMSEG"}, // From linux/acrn.h
			{Val: 1075094099, Str: "ACRN_IOCTL_SET_PTDEV_INTR"}, // From linux/acrn.h
			{Val: 1093181974, Str: "ACRN_IOCTL_SET_VCPU_REGS"}, // From linux/acrn.h
			{Val: 41490, Str: "ACRN_IOCTL_START_VM"}, // From linux/acrn.h
			{Val: 1075880514, Str: "ACRN_IOCTL_UNSET_MEMSEG"}, // From linux/acrn.h
			{Val: 1074307620, Str: "ACRN_IOCTL_VM_INTR_MONITOR"}, // From linux/acrn.h
			{Val: 16641, Str: "AGPIOC_ACQUIRE"}, // From linux/agpgart.h
			{Val: 3221766406, Str: "AGPIOC_ALLOCATE"}, // From linux/agpgart.h
			{Val: 1074282760, Str: "AGPIOC_BIND"}, // From linux/agpgart.h
			{Val: 16650, Str: "AGPIOC_CHIPSET_FLUSH"}, // From linux/agpgart.h
			{Val: 1074020615, Str: "AGPIOC_DEALLOCATE"}, // From linux/agpgart.h
			{Val: 2148024576, Str: "AGPIOC_INFO"}, // From linux/agpgart.h
			{Val: 1074282757, Str: "AGPIOC_PROTECT"}, // From linux/agpgart.h
			{Val: 16642, Str: "AGPIOC_RELEASE"}, // From linux/agpgart.h
			{Val: 1074282756, Str: "AGPIOC_RESERVE"}, // From linux/agpgart.h
			{Val: 1074282755, Str: "AGPIOC_SETUP"}, // From linux/agpgart.h
			{Val: 1074282761, Str: "AGPIOC_UNBIND"}, // From linux/agpgart.h
			{Val: 1074288321, Str: "VIDIOC_AM437X_CCDC_CFG"}, // From linux/am437x-vpfe.h
			{Val: 1074029317, Str: "BC_ACQUIRE"}, // From linux/android/binder.h
			{Val: 1074815753, Str: "BC_ACQUIRE_DONE"}, // From linux/android/binder.h
			{Val: 1074029314, Str: "BC_ACQUIRE_RESULT"}, // From linux/android/binder.h
			{Val: 1074291466, Str: "BC_ATTEMPT_ACQUIRE"}, // From linux/android/binder.h
			{Val: 1074553615, Str: "BC_CLEAR_DEATH_NOTIFICATION"}, // From linux/android/binder.h
			{Val: 1074553620, Str: "BC_CLEAR_FREEZE_NOTIFICATION"}, // From linux/android/binder.h
			{Val: 1074291472, Str: "BC_DEAD_BINDER_DONE"}, // From linux/android/binder.h
			{Val: 1074029319, Str: "BC_DECREFS"}, // From linux/android/binder.h
			{Val: 25356, Str: "BC_ENTER_LOOPER"}, // From linux/android/binder.h
			{Val: 25357, Str: "BC_EXIT_LOOPER"}, // From linux/android/binder.h
			{Val: 1074291477, Str: "BC_FREEZE_NOTIFICATION_DONE"}, // From linux/android/binder.h
			{Val: 1074291459, Str: "BC_FREE_BUFFER"}, // From linux/android/binder.h
			{Val: 1074029316, Str: "BC_INCREFS"}, // From linux/android/binder.h
			{Val: 1074815752, Str: "BC_INCREFS_DONE"}, // From linux/android/binder.h
			{Val: 25355, Str: "BC_REGISTER_LOOPER"}, // From linux/android/binder.h
			{Val: 1074029318, Str: "BC_RELEASE"}, // From linux/android/binder.h
			{Val: 1077961473, Str: "BC_REPLY"}, // From linux/android/binder.h
			{Val: 1078485778, Str: "BC_REPLY_SG"}, // From linux/android/binder.h
			{Val: 1074553614, Str: "BC_REQUEST_DEATH_NOTIFICATION"}, // From linux/android/binder.h
			{Val: 1077961472, Str: "BC_TRANSACTION"}, // From linux/android/binder.h
			{Val: 1078485777, Str: "BC_TRANSACTION_SG"}, // From linux/android/binder.h
			{Val: 1074029072, Str: "BINDER_ENABLE_ONEWAY_SPAM_DETECTION"}, // From linux/android/binder.h
			{Val: 1074553358, Str: "BINDER_FREEZE"}, // From linux/android/binder.h
			{Val: 3222037009, Str: "BINDER_GET_EXTENDED_ERROR"}, // From linux/android/binder.h
			{Val: 3222037007, Str: "BINDER_GET_FROZEN_INFO"}, // From linux/android/binder.h
			{Val: 3222823435, Str: "BINDER_GET_NODE_DEBUG_INFO"}, // From linux/android/binder.h
			{Val: 3222823436, Str: "BINDER_GET_NODE_INFO_FOR_REF"}, // From linux/android/binder.h
			{Val: 1074029063, Str: "BINDER_SET_CONTEXT_MGR"}, // From linux/android/binder.h
			{Val: 1075339789, Str: "BINDER_SET_CONTEXT_MGR_EXT"}, // From linux/android/binder.h
			{Val: 1074029062, Str: "BINDER_SET_IDLE_PRIORITY"}, // From linux/android/binder.h
			{Val: 1074291203, Str: "BINDER_SET_IDLE_TIMEOUT"}, // From linux/android/binder.h
			{Val: 1074029061, Str: "BINDER_SET_MAX_THREADS"}, // From linux/android/binder.h
			{Val: 1074029064, Str: "BINDER_THREAD_EXIT"}, // From linux/android/binder.h
			{Val: 3221512713, Str: "BINDER_VERSION"}, // From linux/android/binder.h
			{Val: 3224396289, Str: "BINDER_WRITE_READ"}, // From linux/android/binder.h
			{Val: 2148561416, Str: "BR_ACQUIRE"}, // From linux/android/binder.h
			{Val: 2147774980, Str: "BR_ACQUIRE_RESULT"}, // From linux/android/binder.h
			{Val: 2149085707, Str: "BR_ATTEMPT_ACQUIRE"}, // From linux/android/binder.h
			{Val: 2148037136, Str: "BR_CLEAR_DEATH_NOTIFICATION_DONE"}, // From linux/android/binder.h
			{Val: 2148037142, Str: "BR_CLEAR_FREEZE_NOTIFICATION_DONE"}, // From linux/android/binder.h
			{Val: 2148037135, Str: "BR_DEAD_BINDER"}, // From linux/android/binder.h
			{Val: 29189, Str: "BR_DEAD_REPLY"}, // From linux/android/binder.h
			{Val: 2148561418, Str: "BR_DECREFS"}, // From linux/android/binder.h
			{Val: 2147774976, Str: "BR_ERROR"}, // From linux/android/binder.h
			{Val: 29201, Str: "BR_FAILED_REPLY"}, // From linux/android/binder.h
			{Val: 29198, Str: "BR_FINISHED"}, // From linux/android/binder.h
			{Val: 2148561429, Str: "BR_FROZEN_BINDER"}, // From linux/android/binder.h
			{Val: 29202, Str: "BR_FROZEN_REPLY"}, // From linux/android/binder.h
			{Val: 2148561415, Str: "BR_INCREFS"}, // From linux/android/binder.h
			{Val: 29196, Str: "BR_NOOP"}, // From linux/android/binder.h
			{Val: 29185, Str: "BR_OK"}, // From linux/android/binder.h
			{Val: 29203, Str: "BR_ONEWAY_SPAM_SUSPECT"}, // From linux/android/binder.h
			{Val: 2148561417, Str: "BR_RELEASE"}, // From linux/android/binder.h
			{Val: 2151707139, Str: "BR_REPLY"}, // From linux/android/binder.h
			{Val: 29197, Str: "BR_SPAWN_LOOPER"}, // From linux/android/binder.h
			{Val: 2151707138, Str: "BR_TRANSACTION"}, // From linux/android/binder.h
			{Val: 29190, Str: "BR_TRANSACTION_COMPLETE"}, // From linux/android/binder.h
			{Val: 29204, Str: "BR_TRANSACTION_PENDING_FROZEN"}, // From linux/android/binder.h
			{Val: 2152231426, Str: "BR_TRANSACTION_SEC_CTX"}, // From linux/android/binder.h
			{Val: 3238552065, Str: "BINDER_CTL_ADD"}, // From linux/android/binderfs.h
			{Val: 16641, Str: "APM_IOC_STANDBY"}, // From linux/apm_bios.h
			{Val: 16642, Str: "APM_IOC_SUSPEND"}, // From linux/apm_bios.h
			{Val: 2148025993, Str: "FBIO_GETCONTROL2"}, // From linux/arcfb.h
			{Val: 18056, Str: "FBIO_WAITEVENT"}, // From linux/arcfb.h
			{Val: 3222319616, Str: "ASPEED_LPC_CTRL_IOCTL_GET_SIZE"}, // From linux/aspeed-lpc-ctrl.h
			{Val: 1074835969, Str: "ASPEED_LPC_CTRL_IOCTL_MAP"}, // From linux/aspeed-lpc-ctrl.h
			{Val: 3222319873, Str: "ASPEED_P2A_CTRL_IOCTL_GET_MEMORY_CONFIG"}, // From linux/aspeed-p2a-ctrl.h
			{Val: 1074836224, Str: "ASPEED_P2A_CTRL_IOCTL_SET_WINDOW"}, // From linux/aspeed-p2a-ctrl.h
			{Val: 1074815328, Str: "ENI_MEMDUMP"}, // From linux/atm_eni.h
			{Val: 1074815335, Str: "ENI_SETMULT"}, // From linux/atm_eni.h
			{Val: 1074815328, Str: "HE_GET_REG"}, // From linux/atm_he.h
			{Val: 1074815282, Str: "IDT77105_GETSTAT"}, // From linux/atm_idt77105.h
			{Val: 1074815283, Str: "IDT77105_GETSTATZ"}, // From linux/atm_idt77105.h
			{Val: 24931, Str: "NS_ADJBUFLEV"}, // From linux/atm_nicstar.h
			{Val: 3222298977, Str: "NS_GETPSTAT"}, // From linux/atm_nicstar.h
			{Val: 1074815330, Str: "NS_SETBUFLEV"}, // From linux/atm_nicstar.h
			{Val: 24974, Str: "ATMTCP_CREATE"}, // From linux/atm_tcp.h
			{Val: 24975, Str: "ATMTCP_REMOVE"}, // From linux/atm_tcp.h
			{Val: 24960, Str: "SIOCSIFATMTCP"}, // From linux/atm_tcp.h
			{Val: 1074815329, Str: "ZATM_GETPOOL"}, // From linux/atm_zatm.h
			{Val: 1074815330, Str: "ZATM_GETPOOLZ"}, // From linux/atm_zatm.h
			{Val: 1074815331, Str: "ZATM_SETPOOL"}, // From linux/atm_zatm.h
			{Val: 25057, Str: "ATMARPD_CTRL"}, // From linux/atmarp.h
			{Val: 25061, Str: "ATMARP_ENCAP"}, // From linux/atmarp.h
			{Val: 25058, Str: "ATMARP_MKIP"}, // From linux/atmarp.h
			{Val: 25059, Str: "ATMARP_SETENTRY"}, // From linux/atmarp.h
			{Val: 1075601808, Str: "BR2684_SETFILT"}, // From linux/atmbr2684.h
			{Val: 25056, Str: "SIOCMKCLIP"}, // From linux/atmclip.h
			{Val: 1074815368, Str: "ATM_ADDADDR"}, // From linux/atmdev.h
			{Val: 1074815374, Str: "ATM_ADDLECSADDR"}, // From linux/atmdev.h
			{Val: 1074815476, Str: "ATM_ADDPARTY"}, // From linux/atmdev.h
			{Val: 1074815369, Str: "ATM_DELADDR"}, // From linux/atmdev.h
			{Val: 1074815375, Str: "ATM_DELLECSADDR"}, // From linux/atmdev.h
			{Val: 1074029045, Str: "ATM_DROPPARTY"}, // From linux/atmdev.h
			{Val: 1074815366, Str: "ATM_GETADDR"}, // From linux/atmdev.h
			{Val: 1074815370, Str: "ATM_GETCIRANGE"}, // From linux/atmdev.h
			{Val: 1074815365, Str: "ATM_GETESI"}, // From linux/atmdev.h
			{Val: 1074815376, Str: "ATM_GETLECSADDR"}, // From linux/atmdev.h
			{Val: 1074815361, Str: "ATM_GETLINKRATE"}, // From linux/atmdev.h
			{Val: 1074815314, Str: "ATM_GETLOOP"}, // From linux/atmdev.h
			{Val: 1074815363, Str: "ATM_GETNAMES"}, // From linux/atmdev.h
			{Val: 1074815312, Str: "ATM_GETSTAT"}, // From linux/atmdev.h
			{Val: 1074815313, Str: "ATM_GETSTATZ"}, // From linux/atmdev.h
			{Val: 1074815364, Str: "ATM_GETTYPE"}, // From linux/atmdev.h
			{Val: 1073897971, Str: "ATM_NEWBACKENDIF"}, // From linux/atmdev.h
			{Val: 1074815316, Str: "ATM_QUERYLOOP"}, // From linux/atmdev.h
			{Val: 1074815367, Str: "ATM_RSTADDR"}, // From linux/atmdev.h
			{Val: 1073897970, Str: "ATM_SETBACKEND"}, // From linux/atmdev.h
			{Val: 1074815371, Str: "ATM_SETCIRANGE"}, // From linux/atmdev.h
			{Val: 1074815372, Str: "ATM_SETESI"}, // From linux/atmdev.h
			{Val: 1074815373, Str: "ATM_SETESIF"}, // From linux/atmdev.h
			{Val: 1074815315, Str: "ATM_SETLOOP"}, // From linux/atmdev.h
			{Val: 1074029041, Str: "ATM_SETSC"}, // From linux/atmdev.h
			{Val: 25040, Str: "ATMLEC_CTRL"}, // From linux/atmlec.h
			{Val: 25041, Str: "ATMLEC_DATA"}, // From linux/atmlec.h
			{Val: 25042, Str: "ATMLEC_MCAST"}, // From linux/atmlec.h
			{Val: 25048, Str: "ATMMPC_CTRL"}, // From linux/atmmpc.h
			{Val: 25049, Str: "ATMMPC_DATA"}, // From linux/atmmpc.h
			{Val: 25072, Str: "ATMSIGD_CTRL"}, // From linux/atmsvc.h
			{Val: 3222836093, Str: "AUTOFS_DEV_IOCTL_ASKUMOUNT"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836089, Str: "AUTOFS_DEV_IOCTL_CATATONIC"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836085, Str: "AUTOFS_DEV_IOCTL_CLOSEMOUNT"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836092, Str: "AUTOFS_DEV_IOCTL_EXPIRE"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836087, Str: "AUTOFS_DEV_IOCTL_FAIL"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836094, Str: "AUTOFS_DEV_IOCTL_ISMOUNTPOINT"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836084, Str: "AUTOFS_DEV_IOCTL_OPENMOUNT"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836083, Str: "AUTOFS_DEV_IOCTL_PROTOSUBVER"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836082, Str: "AUTOFS_DEV_IOCTL_PROTOVER"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836086, Str: "AUTOFS_DEV_IOCTL_READY"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836091, Str: "AUTOFS_DEV_IOCTL_REQUESTER"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836088, Str: "AUTOFS_DEV_IOCTL_SETPIPEFD"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836090, Str: "AUTOFS_DEV_IOCTL_TIMEOUT"}, // From linux/auto_dev-ioctl.h
			{Val: 3222836081, Str: "AUTOFS_DEV_IOCTL_VERSION"}, // From linux/auto_dev-ioctl.h
			{Val: 2147783536, Str: "AUTOFS_IOC_ASKUMOUNT"}, // From linux/auto_fs.h
			{Val: 37730, Str: "AUTOFS_IOC_CATATONIC"}, // From linux/auto_fs.h
			{Val: 2165085029, Str: "AUTOFS_IOC_EXPIRE"}, // From linux/auto_fs.h
			{Val: 1074041702, Str: "AUTOFS_IOC_EXPIRE_MULTI"}, // From linux/auto_fs.h
			{Val: 37729, Str: "AUTOFS_IOC_FAIL"}, // From linux/auto_fs.h
			{Val: 2147783527, Str: "AUTOFS_IOC_PROTOSUBVER"}, // From linux/auto_fs.h
			{Val: 2147783523, Str: "AUTOFS_IOC_PROTOVER"}, // From linux/auto_fs.h
			{Val: 37728, Str: "AUTOFS_IOC_READY"}, // From linux/auto_fs.h
			{Val: 3221787492, Str: "AUTOFS_IOC_SETTIMEOUT"}, // From linux/auto_fs.h
			{Val: 3221525348, Str: "AUTOFS_IOC_SETTIMEOUT32"}, // From linux/auto_fs.h
			{Val: 3224375946, Str: "BLKCRYPTOGENERATEKEY"}, // From linux/blk-crypto.h
			{Val: 3225424521, Str: "BLKCRYPTOIMPORTKEY"}, // From linux/blk-crypto.h
			{Val: 3225424523, Str: "BLKCRYPTOPREPAREKEY"}, // From linux/blk-crypto.h
			{Val: 4608, Str: "BLOCK_URING_CMD_DISCARD"}, // From linux/blkdev.h
			{Val: 4713, Str: "BLKPG"}, // From linux/blkpg.h
			{Val: 1074795143, Str: "BLKCLOSEZONE"}, // From linux/blkzoned.h
			{Val: 1074795144, Str: "BLKFINISHZONE"}, // From linux/blkzoned.h
			{Val: 2147750533, Str: "BLKGETNRZONES"}, // From linux/blkzoned.h
			{Val: 2147750532, Str: "BLKGETZONESZ"}, // From linux/blkzoned.h
			{Val: 1074795142, Str: "BLKOPENZONE"}, // From linux/blkzoned.h
			{Val: 3222278786, Str: "BLKREPORTZONE"}, // From linux/blkzoned.h
			{Val: 3222278798, Str: "BLKREPORTZONEV2"}, // From linux/blkzoned.h
			{Val: 1074795139, Str: "BLKRESETZONE"}, // From linux/blkzoned.h
			{Val: 45312, Str: "BT_BMC_IOCTL_SMS_ATN"}, // From linux/bt-bmc.h
			{Val: 1342215178, Str: "BTRFS_IOC_ADD_DEV"}, // From linux/btrfs.h
			{Val: 1342215180, Str: "BTRFS_IOC_BALANCE"}, // From linux/btrfs.h
			{Val: 1074041889, Str: "BTRFS_IOC_BALANCE_CTL"}, // From linux/btrfs.h
			{Val: 2214630434, Str: "BTRFS_IOC_BALANCE_PROGRESS"}, // From linux/btrfs.h
			{Val: 3288372256, Str: "BTRFS_IOC_BALANCE_V2"}, // From linux/btrfs.h
			{Val: 1074041865, Str: "BTRFS_IOC_CLONE"}, // From linux/btrfs.h
			{Val: 1075876877, Str: "BTRFS_IOC_CLONE_RANGE"}, // From linux/btrfs.h
			{Val: 1074304019, Str: "BTRFS_IOC_DEFAULT_SUBVOL"}, // From linux/btrfs.h
			{Val: 1342215170, Str: "BTRFS_IOC_DEFRAG"}, // From linux/btrfs.h
			{Val: 1076925456, Str: "BTRFS_IOC_DEFRAG_RANGE"}, // From linux/btrfs.h
			{Val: 2415957031, Str: "BTRFS_IOC_DEVICES_READY"}, // From linux/btrfs.h
			{Val: 3489698846, Str: "BTRFS_IOC_DEV_INFO"}, // From linux/btrfs.h
			{Val: 3391657013, Str: "BTRFS_IOC_DEV_REPLACE"}, // From linux/btrfs.h
			{Val: 2155910208, Str: "BTRFS_IOC_ENCODED_READ"}, // From linux/btrfs.h
			{Val: 1082168384, Str: "BTRFS_IOC_ENCODED_WRITE"}, // From linux/btrfs.h
			{Val: 3222836278, Str: "BTRFS_IOC_FILE_EXTENT_SAME"}, // From linux/btrfs.h
			{Val: 1342215173, Str: "BTRFS_IOC_FORGET_DEV"}, // From linux/btrfs.h
			{Val: 2214630431, Str: "BTRFS_IOC_FS_INFO"}, // From linux/btrfs.h
			{Val: 3288896564, Str: "BTRFS_IOC_GET_DEV_STATS"}, // From linux/btrfs.h
			{Val: 2149094457, Str: "BTRFS_IOC_GET_FEATURES"}, // From linux/btrfs.h
			{Val: 2180551740, Str: "BTRFS_IOC_GET_SUBVOL_INFO"}, // From linux/btrfs.h
			{Val: 3489698877, Str: "BTRFS_IOC_GET_SUBVOL_ROOTREF"}, // From linux/btrfs.h
			{Val: 2152240185, Str: "BTRFS_IOC_GET_SUPPORTED_FEATURES"}, // From linux/btrfs.h
			{Val: 3489698834, Str: "BTRFS_IOC_INO_LOOKUP"}, // From linux/btrfs.h
			{Val: 3489698878, Str: "BTRFS_IOC_INO_LOOKUP_USER"}, // From linux/btrfs.h
			{Val: 3224933411, Str: "BTRFS_IOC_INO_PATHS"}, // From linux/btrfs.h
			{Val: 3224933412, Str: "BTRFS_IOC_LOGICAL_INO"}, // From linux/btrfs.h
			{Val: 3224933435, Str: "BTRFS_IOC_LOGICAL_INO_V2"}, // From linux/btrfs.h
			{Val: 1075352617, Str: "BTRFS_IOC_QGROUP_ASSIGN"}, // From linux/btrfs.h
			{Val: 1074828330, Str: "BTRFS_IOC_QGROUP_CREATE"}, // From linux/btrfs.h
			{Val: 2150667307, Str: "BTRFS_IOC_QGROUP_LIMIT"}, // From linux/btrfs.h
			{Val: 3222311976, Str: "BTRFS_IOC_QUOTA_CTL"}, // From linux/btrfs.h
			{Val: 1077974060, Str: "BTRFS_IOC_QUOTA_RESCAN"}, // From linux/btrfs.h
			{Val: 2151715885, Str: "BTRFS_IOC_QUOTA_RESCAN_STATUS"}, // From linux/btrfs.h
			{Val: 37934, Str: "BTRFS_IOC_QUOTA_RESCAN_WAIT"}, // From linux/btrfs.h
			{Val: 1342215171, Str: "BTRFS_IOC_RESIZE"}, // From linux/btrfs.h
			{Val: 1342215179, Str: "BTRFS_IOC_RM_DEV"}, // From linux/btrfs.h
			{Val: 1342215226, Str: "BTRFS_IOC_RM_DEV_V2"}, // From linux/btrfs.h
			{Val: 1342215172, Str: "BTRFS_IOC_SCAN_DEV"}, // From linux/btrfs.h
			{Val: 3288372251, Str: "BTRFS_IOC_SCRUB"}, // From linux/btrfs.h
			{Val: 37916, Str: "BTRFS_IOC_SCRUB_CANCEL"}, // From linux/btrfs.h
			{Val: 3288372253, Str: "BTRFS_IOC_SCRUB_PROGRESS"}, // From linux/btrfs.h
			{Val: 1078498342, Str: "BTRFS_IOC_SEND"}, // From linux/btrfs.h
			{Val: 1076925497, Str: "BTRFS_IOC_SET_FEATURES"}, // From linux/btrfs.h
			{Val: 3234370597, Str: "BTRFS_IOC_SET_RECEIVED_SUBVOL"}, // From linux/btrfs.h
			{Val: 1342215169, Str: "BTRFS_IOC_SNAP_CREATE"}, // From linux/btrfs.h
			{Val: 1342215191, Str: "BTRFS_IOC_SNAP_CREATE_V2"}, // From linux/btrfs.h
			{Val: 1342215183, Str: "BTRFS_IOC_SNAP_DESTROY"}, // From linux/btrfs.h
			{Val: 1342215231, Str: "BTRFS_IOC_SNAP_DESTROY_V2"}, // From linux/btrfs.h
			{Val: 3222311956, Str: "BTRFS_IOC_SPACE_INFO"}, // From linux/btrfs.h
			{Val: 2148045848, Str: "BTRFS_IOC_START_SYNC"}, // From linux/btrfs.h
			{Val: 1342215182, Str: "BTRFS_IOC_SUBVOL_CREATE"}, // From linux/btrfs.h
			{Val: 1342215192, Str: "BTRFS_IOC_SUBVOL_CREATE_V2"}, // From linux/btrfs.h
			{Val: 2148045849, Str: "BTRFS_IOC_SUBVOL_GETFLAGS"}, // From linux/btrfs.h
			{Val: 1074304026, Str: "BTRFS_IOC_SUBVOL_SETFLAGS"}, // From linux/btrfs.h
			{Val: 1074828353, Str: "BTRFS_IOC_SUBVOL_SYNC_WAIT"}, // From linux/btrfs.h
			{Val: 37896, Str: "BTRFS_IOC_SYNC"}, // From linux/btrfs.h
			{Val: 37895, Str: "BTRFS_IOC_TRANS_END"}, // From linux/btrfs.h
			{Val: 37894, Str: "BTRFS_IOC_TRANS_START"}, // From linux/btrfs.h
			{Val: 3489698833, Str: "BTRFS_IOC_TREE_SEARCH"}, // From linux/btrfs.h
			{Val: 3228603409, Str: "BTRFS_IOC_TREE_SEARCH_V2"}, // From linux/btrfs.h
			{Val: 1074304022, Str: "BTRFS_IOC_WAIT_SYNC"}, // From linux/btrfs.h
			{Val: 1074042881, Str: "CACHEFILES_IOC_READ_COMPLETE"}, // From linux/cachefiles.h
			{Val: 2147762981, Str: "CAPI_CLR_FLAGS"}, // From linux/capi.h
			{Val: 2147631905, Str: "CAPI_GET_ERRCODE"}, // From linux/capi.h
			{Val: 2147762979, Str: "CAPI_GET_FLAGS"}, // From linux/capi.h
			{Val: 3221504774, Str: "CAPI_GET_MANUFACTURER"}, // From linux/capi.h
			{Val: 3225436937, Str: "CAPI_GET_PROFILE"}, // From linux/capi.h
			{Val: 3221504776, Str: "CAPI_GET_SERIAL"}, // From linux/capi.h
			{Val: 3222291207, Str: "CAPI_GET_VERSION"}, // From linux/capi.h
			{Val: 2147631906, Str: "CAPI_INSTALLED"}, // From linux/capi.h
			{Val: 3222291232, Str: "CAPI_MANUFACTURER_CMD"}, // From linux/capi.h
			{Val: 2147762983, Str: "CAPI_NCCI_GETUNIT"}, // From linux/capi.h
			{Val: 2147762982, Str: "CAPI_NCCI_OPENCOUNT"}, // From linux/capi.h
			{Val: 1074545409, Str: "CAPI_REGISTER"}, // From linux/capi.h
			{Val: 2147762980, Str: "CAPI_SET_FLAGS"}, // From linux/capi.h
			{Val: 3227533842, Str: "CCISS_BIG_PASSTHRU"}, // From linux/cciss_ioctl.h
			{Val: 16908, Str: "CCISS_DEREGDISK"}, // From linux/cciss_ioctl.h
			{Val: 2147762695, Str: "CCISS_GETBUSTYPES"}, // From linux/cciss_ioctl.h
			{Val: 2147762697, Str: "CCISS_GETDRIVVER"}, // From linux/cciss_ioctl.h
			{Val: 2147762696, Str: "CCISS_GETFIRMVER"}, // From linux/cciss_ioctl.h
			{Val: 2147762694, Str: "CCISS_GETHEARTBEAT"}, // From linux/cciss_ioctl.h
			{Val: 2148024834, Str: "CCISS_GETINTINFO"}, // From linux/cciss_ioctl.h
			{Val: 2148286993, Str: "CCISS_GETLUNINFO"}, // From linux/cciss_ioctl.h
			{Val: 2148549124, Str: "CCISS_GETNODENAME"}, // From linux/cciss_ioctl.h
			{Val: 2148024833, Str: "CCISS_GETPCIINFO"}, // From linux/cciss_ioctl.h
			{Val: 3227009547, Str: "CCISS_PASSTHRU"}, // From linux/cciss_ioctl.h
			{Val: 16910, Str: "CCISS_REGNEWD"}, // From linux/cciss_ioctl.h
			{Val: 1074020877, Str: "CCISS_REGNEWDISK"}, // From linux/cciss_ioctl.h
			{Val: 16912, Str: "CCISS_RESCANDISK"}, // From linux/cciss_ioctl.h
			{Val: 16906, Str: "CCISS_REVALIDVOLS"}, // From linux/cciss_ioctl.h
			{Val: 1074283011, Str: "CCISS_SETINTINFO"}, // From linux/cciss_ioctl.h
			{Val: 1074807301, Str: "CCISS_SETNODENAME"}, // From linux/cciss_ioctl.h
			{Val: 21378, Str: "CDROMAUDIOBUFSIZ"}, // From linux/cdrom.h
			{Val: 21273, Str: "CDROMCLOSETRAY"}, // From linux/cdrom.h
			{Val: 21257, Str: "CDROMEJECT"}, // From linux/cdrom.h
			{Val: 21263, Str: "CDROMEJECT_SW"}, // From linux/cdrom.h
			{Val: 21277, Str: "CDROMGETSPINDOWN"}, // From linux/cdrom.h
			{Val: 21264, Str: "CDROMMULTISESSION"}, // From linux/cdrom.h
			{Val: 21249, Str: "CDROMPAUSE"}, // From linux/cdrom.h
			{Val: 21271, Str: "CDROMPLAYBLK"}, // From linux/cdrom.h
			{Val: 21251, Str: "CDROMPLAYMSF"}, // From linux/cdrom.h
			{Val: 21252, Str: "CDROMPLAYTRKIND"}, // From linux/cdrom.h
			{Val: 21272, Str: "CDROMREADALL"}, // From linux/cdrom.h
			{Val: 21262, Str: "CDROMREADAUDIO"}, // From linux/cdrom.h
			{Val: 21269, Str: "CDROMREADCOOKED"}, // From linux/cdrom.h
			{Val: 21261, Str: "CDROMREADMODE1"}, // From linux/cdrom.h
			{Val: 21260, Str: "CDROMREADMODE2"}, // From linux/cdrom.h
			{Val: 21268, Str: "CDROMREADRAW"}, // From linux/cdrom.h
			{Val: 21254, Str: "CDROMREADTOCENTRY"}, // From linux/cdrom.h
			{Val: 21253, Str: "CDROMREADTOCHDR"}, // From linux/cdrom.h
			{Val: 21266, Str: "CDROMRESET"}, // From linux/cdrom.h
			{Val: 21250, Str: "CDROMRESUME"}, // From linux/cdrom.h
			{Val: 21270, Str: "CDROMSEEK"}, // From linux/cdrom.h
			{Val: 21278, Str: "CDROMSETSPINDOWN"}, // From linux/cdrom.h
			{Val: 21256, Str: "CDROMSTART"}, // From linux/cdrom.h
			{Val: 21255, Str: "CDROMSTOP"}, // From linux/cdrom.h
			{Val: 21259, Str: "CDROMSUBCHNL"}, // From linux/cdrom.h
			{Val: 21258, Str: "CDROMVOLCTRL"}, // From linux/cdrom.h
			{Val: 21267, Str: "CDROMVOLREAD"}, // From linux/cdrom.h
			{Val: 21288, Str: "CDROM_CHANGER_NSLOTS"}, // From linux/cdrom.h
			{Val: 21281, Str: "CDROM_CLEAR_OPTIONS"}, // From linux/cdrom.h
			{Val: 21296, Str: "CDROM_DEBUG"}, // From linux/cdrom.h
			{Val: 21287, Str: "CDROM_DISC_STATUS"}, // From linux/cdrom.h
			{Val: 21286, Str: "CDROM_DRIVE_STATUS"}, // From linux/cdrom.h
			{Val: 21297, Str: "CDROM_GET_CAPABILITY"}, // From linux/cdrom.h
			{Val: 21265, Str: "CDROM_GET_MCN"}, // From linux/cdrom.h
			{Val: 21397, Str: "CDROM_LAST_WRITTEN"}, // From linux/cdrom.h
			{Val: 21289, Str: "CDROM_LOCKDOOR"}, // From linux/cdrom.h
			{Val: 21285, Str: "CDROM_MEDIA_CHANGED"}, // From linux/cdrom.h
			{Val: 21396, Str: "CDROM_NEXT_WRITABLE"}, // From linux/cdrom.h
			{Val: 21283, Str: "CDROM_SELECT_DISC"}, // From linux/cdrom.h
			{Val: 21282, Str: "CDROM_SELECT_SPEED"}, // From linux/cdrom.h
			{Val: 21395, Str: "CDROM_SEND_PACKET"}, // From linux/cdrom.h
			{Val: 21280, Str: "CDROM_SET_OPTIONS"}, // From linux/cdrom.h
			{Val: 21398, Str: "CDROM_TIMED_MEDIA_CHANGE"}, // From linux/cdrom.h
			{Val: 21394, Str: "DVD_AUTH"}, // From linux/cdrom.h
			{Val: 21392, Str: "DVD_READ_STRUCT"}, // From linux/cdrom.h
			{Val: 21393, Str: "DVD_WRITE_STRUCT"}, // From linux/cdrom.h
			{Val: 3226231040, Str: "CEC_ADAP_G_CAPS"}, // From linux/cec.h
			{Val: 2151964938, Str: "CEC_ADAP_G_CONNECTOR_INFO"}, // From linux/cec.h
			{Val: 2153537795, Str: "CEC_ADAP_G_LOG_ADDRS"}, // From linux/cec.h
			{Val: 2147639553, Str: "CEC_ADAP_G_PHYS_ADDR"}, // From linux/cec.h
			{Val: 3227279620, Str: "CEC_ADAP_S_LOG_ADDRS"}, // From linux/cec.h
			{Val: 1073897730, Str: "CEC_ADAP_S_PHYS_ADDR"}, // From linux/cec.h
			{Val: 3226493191, Str: "CEC_DQEVENT"}, // From linux/cec.h
			{Val: 2147770632, Str: "CEC_G_MODE"}, // From linux/cec.h
			{Val: 3224920326, Str: "CEC_RECEIVE"}, // From linux/cec.h
			{Val: 1074028809, Str: "CEC_S_MODE"}, // From linux/cec.h
			{Val: 3224920325, Str: "CEC_TRANSMIT"}, // From linux/cec.h
			{Val: 1075602178, Str: "CHIOEXCHANGE"}, // From linux/chio.h
			{Val: 1080845072, Str: "CHIOGELEM"}, // From linux/chio.h
			{Val: 2148819718, Str: "CHIOGPARAMS"}, // From linux/chio.h
			{Val: 2147771140, Str: "CHIOGPICKER"}, // From linux/chio.h
			{Val: 1074815752, Str: "CHIOGSTATUS"}, // From linux/chio.h
			{Val: 2154849043, Str: "CHIOGVPARAMS"}, // From linux/chio.h
			{Val: 25361, Str: "CHIOINITELEM"}, // From linux/chio.h
			{Val: 1075077889, Str: "CHIOMOVE"}, // From linux/chio.h
			{Val: 1074553603, Str: "CHIOPOSITION"}, // From linux/chio.h
			{Val: 1074029317, Str: "CHIOSPICKER"}, // From linux/chio.h
			{Val: 1076912914, Str: "CHIOSVOLTAG"}, // From linux/chio.h
			{Val: 3221775114, Str: "CIOC_KERNEL_VERSION"}, // From linux/coda.h
			{Val: 2149606413, Str: "COMEDI_BUFCONFIG"}, // From linux/comedi.h
			{Val: 3224134670, Str: "COMEDI_BUFINFO"}, // From linux/comedi.h
			{Val: 25607, Str: "COMEDI_CANCEL"}, // From linux/comedi.h
			{Val: 2150654979, Str: "COMEDI_CHANINFO"}, // From linux/comedi.h
			{Val: 2152752137, Str: "COMEDI_CMD"}, // From linux/comedi.h
			{Val: 2152752138, Str: "COMEDI_CMDTEST"}, // From linux/comedi.h
			{Val: 1083466752, Str: "COMEDI_DEVCONFIG"}, // From linux/comedi.h
			{Val: 2159043585, Str: "COMEDI_DEVINFO"}, // From linux/comedi.h
			{Val: 2150130700, Str: "COMEDI_INSN"}, // From linux/comedi.h
			{Val: 2148557835, Str: "COMEDI_INSNLIST"}, // From linux/comedi.h
			{Val: 25605, Str: "COMEDI_LOCK"}, // From linux/comedi.h
			{Val: 25615, Str: "COMEDI_POLL"}, // From linux/comedi.h
			{Val: 2148557832, Str: "COMEDI_RANGEINFO"}, // From linux/comedi.h
			{Val: 25616, Str: "COMEDI_SETRSUBD"}, // From linux/comedi.h
			{Val: 25617, Str: "COMEDI_SETWSUBD"}, // From linux/comedi.h
			{Val: 2152227842, Str: "COMEDI_SUBDINFO"}, // From linux/comedi.h
			{Val: 25606, Str: "COMEDI_UNLOCK"}, // From linux/comedi.h
			{Val: 1074150912, Str: "COUNTER_ADD_WATCH_IOCTL"}, // From linux/counter.h
			{Val: 15874, Str: "COUNTER_DISABLE_EVENTS_IOCTL"}, // From linux/counter.h
			{Val: 15873, Str: "COUNTER_ENABLE_EVENTS_IOCTL"}, // From linux/counter.h
			{Val: 2148060673, Str: "CXL_MEM_QUERY_COMMANDS"}, // From linux/cxl_mem.h
			{Val: 3224423938, Str: "CXL_MEM_SEND_COMMAND"}, // From linux/cxl_mem.h
			{Val: 3241737488, Str: "DM_DEV_ARM_POLL"}, // From linux/dm-ioctl.h
			{Val: 3241737475, Str: "DM_DEV_CREATE"}, // From linux/dm-ioctl.h
			{Val: 3241737476, Str: "DM_DEV_REMOVE"}, // From linux/dm-ioctl.h
			{Val: 3241737477, Str: "DM_DEV_RENAME"}, // From linux/dm-ioctl.h
			{Val: 3241737487, Str: "DM_DEV_SET_GEOMETRY"}, // From linux/dm-ioctl.h
			{Val: 3241737479, Str: "DM_DEV_STATUS"}, // From linux/dm-ioctl.h
			{Val: 3241737478, Str: "DM_DEV_SUSPEND"}, // From linux/dm-ioctl.h
			{Val: 3241737480, Str: "DM_DEV_WAIT"}, // From linux/dm-ioctl.h
			{Val: 3241737489, Str: "DM_GET_TARGET_VERSION"}, // From linux/dm-ioctl.h
			{Val: 3241737474, Str: "DM_LIST_DEVICES"}, // From linux/dm-ioctl.h
			{Val: 3241737485, Str: "DM_LIST_VERSIONS"}, // From linux/dm-ioctl.h
			{Val: 64786, Str: "DM_MPATH_PROBE_PATHS"}, // From linux/dm-ioctl.h
			{Val: 3241737473, Str: "DM_REMOVE_ALL"}, // From linux/dm-ioctl.h
			{Val: 3241737482, Str: "DM_TABLE_CLEAR"}, // From linux/dm-ioctl.h
			{Val: 3241737483, Str: "DM_TABLE_DEPS"}, // From linux/dm-ioctl.h
			{Val: 3241737481, Str: "DM_TABLE_LOAD"}, // From linux/dm-ioctl.h
			{Val: 3241737484, Str: "DM_TABLE_STATUS"}, // From linux/dm-ioctl.h
			{Val: 3241737486, Str: "DM_TARGET_MSG"}, // From linux/dm-ioctl.h
			{Val: 3241737472, Str: "DM_VERSION"}, // From linux/dm-ioctl.h
			{Val: 3221774850, Str: "DMA_BUF_IOCTL_EXPORT_SYNC_FILE"}, // From linux/dma-buf.h
			{Val: 1074291203, Str: "DMA_BUF_IOCTL_IMPORT_SYNC_FILE"}, // From linux/dma-buf.h
			{Val: 1074291200, Str: "DMA_BUF_IOCTL_SYNC"}, // From linux/dma-buf.h
			{Val: 1074029057, Str: "DMA_BUF_SET_NAME_A"}, // From linux/dma-buf.h
			{Val: 1074291201, Str: "DMA_BUF_SET_NAME_B"}, // From linux/dma-buf.h
			{Val: 3222816768, Str: "DMA_HEAP_IOCTL_ALLOC"}, // From linux/dma-heap.h
			{Val: 28436, Str: "AUDIO_BILINGUAL_CHANNEL_SELECT"}, // From linux/dvb/audio.h
			{Val: 28425, Str: "AUDIO_CHANNEL_SELECT"}, // From linux/dvb/audio.h
			{Val: 28428, Str: "AUDIO_CLEAR_BUFFER"}, // From linux/dvb/audio.h
			{Val: 28420, Str: "AUDIO_CONTINUE"}, // From linux/dvb/audio.h
			{Val: 2147774219, Str: "AUDIO_GET_CAPABILITIES"}, // From linux/dvb/audio.h
			{Val: 2149609226, Str: "AUDIO_GET_STATUS"}, // From linux/dvb/audio.h
			{Val: 28419, Str: "AUDIO_PAUSE"}, // From linux/dvb/audio.h
			{Val: 28418, Str: "AUDIO_PLAY"}, // From linux/dvb/audio.h
			{Val: 28421, Str: "AUDIO_SELECT_SOURCE"}, // From linux/dvb/audio.h
			{Val: 28423, Str: "AUDIO_SET_AV_SYNC"}, // From linux/dvb/audio.h
			{Val: 28424, Str: "AUDIO_SET_BYPASS_MODE"}, // From linux/dvb/audio.h
			{Val: 28429, Str: "AUDIO_SET_ID"}, // From linux/dvb/audio.h
			{Val: 1074294542, Str: "AUDIO_SET_MIXER"}, // From linux/dvb/audio.h
			{Val: 28422, Str: "AUDIO_SET_MUTE"}, // From linux/dvb/audio.h
			{Val: 28431, Str: "AUDIO_SET_STREAMTYPE"}, // From linux/dvb/audio.h
			{Val: 28417, Str: "AUDIO_STOP"}, // From linux/dvb/audio.h
			{Val: 2148560769, Str: "CA_GET_CAP"}, // From linux/dvb/ca.h
			{Val: 2148036483, Str: "CA_GET_DESCR_INFO"}, // From linux/dvb/ca.h
			{Val: 2165075844, Str: "CA_GET_MSG"}, // From linux/dvb/ca.h
			{Val: 2148298626, Str: "CA_GET_SLOT_INFO"}, // From linux/dvb/ca.h
			{Val: 28544, Str: "CA_RESET"}, // From linux/dvb/ca.h
			{Val: 1091334021, Str: "CA_SEND_MSG"}, // From linux/dvb/ca.h
			{Val: 1074818950, Str: "CA_SET_DESCR"}, // From linux/dvb/ca.h
			{Val: 1073901363, Str: "DMX_ADD_PID"}, // From linux/dvb/dmx.h
			{Val: 3222826816, Str: "DMX_DQBUF"}, // From linux/dvb/dmx.h
			{Val: 3222040382, Str: "DMX_EXPBUF"}, // From linux/dvb/dmx.h
			{Val: 2148167471, Str: "DMX_GET_PES_PIDS"}, // From linux/dvb/dmx.h
			{Val: 3222302514, Str: "DMX_GET_STC"}, // From linux/dvb/dmx.h
			{Val: 3222826815, Str: "DMX_QBUF"}, // From linux/dvb/dmx.h
			{Val: 3222826813, Str: "DMX_QUERYBUF"}, // From linux/dvb/dmx.h
			{Val: 1073901364, Str: "DMX_REMOVE_PID"}, // From linux/dvb/dmx.h
			{Val: 3221778236, Str: "DMX_REQBUFS"}, // From linux/dvb/dmx.h
			{Val: 28461, Str: "DMX_SET_BUFFER_SIZE"}, // From linux/dvb/dmx.h
			{Val: 1077702443, Str: "DMX_SET_FILTER"}, // From linux/dvb/dmx.h
			{Val: 1075081004, Str: "DMX_SET_PES_FILTER"}, // From linux/dvb/dmx.h
			{Val: 28457, Str: "DMX_START"}, // From linux/dvb/dmx.h
			{Val: 28458, Str: "DMX_STOP"}, // From linux/dvb/dmx.h
			{Val: 2148298560, Str: "FE_DISEQC_RECV_SLAVE_REPLY"}, // From linux/dvb/frontend.h
			{Val: 28478, Str: "FE_DISEQC_RESET_OVERLOAD"}, // From linux/dvb/frontend.h
			{Val: 28481, Str: "FE_DISEQC_SEND_BURST"}, // From linux/dvb/frontend.h
			{Val: 1074229055, Str: "FE_DISEQC_SEND_MASTER_CMD"}, // From linux/dvb/frontend.h
			{Val: 28496, Str: "FE_DISHNETWORK_SEND_LEGACY_CMD"}, // From linux/dvb/frontend.h
			{Val: 28484, Str: "FE_ENABLE_HIGH_LNB_VOLTAGE"}, // From linux/dvb/frontend.h
			{Val: 2150133582, Str: "FE_GET_EVENT"}, // From linux/dvb/frontend.h
			{Val: 2149871437, Str: "FE_GET_FRONTEND"}, // From linux/dvb/frontend.h
			{Val: 2158522173, Str: "FE_GET_INFO"}, // From linux/dvb/frontend.h
			{Val: 2148560723, Str: "FE_GET_PROPERTY"}, // From linux/dvb/frontend.h
			{Val: 2147774278, Str: "FE_READ_BER"}, // From linux/dvb/frontend.h
			{Val: 2147643207, Str: "FE_READ_SIGNAL_STRENGTH"}, // From linux/dvb/frontend.h
			{Val: 2147643208, Str: "FE_READ_SNR"}, // From linux/dvb/frontend.h
			{Val: 2147774277, Str: "FE_READ_STATUS"}, // From linux/dvb/frontend.h
			{Val: 2147774281, Str: "FE_READ_UNCORRECTED_BLOCKS"}, // From linux/dvb/frontend.h
			{Val: 1076129612, Str: "FE_SET_FRONTEND"}, // From linux/dvb/frontend.h
			{Val: 28497, Str: "FE_SET_FRONTEND_TUNE_MODE"}, // From linux/dvb/frontend.h
			{Val: 1074818898, Str: "FE_SET_PROPERTY"}, // From linux/dvb/frontend.h
			{Val: 28482, Str: "FE_SET_TONE"}, // From linux/dvb/frontend.h
			{Val: 28483, Str: "FE_SET_VOLTAGE"}, // From linux/dvb/frontend.h
			{Val: 3221647156, Str: "NET_ADD_IF"}, // From linux/dvb/net.h
			{Val: 3221647158, Str: "NET_GET_IF"}, // From linux/dvb/net.h
			{Val: 28469, Str: "NET_REMOVE_IF"}, // From linux/dvb/net.h
			{Val: 2148560801, Str: "OSD_GET_CAPABILITY"}, // From linux/dvb/osd.h
			{Val: 1075867552, Str: "OSD_SEND_CMD"}, // From linux/dvb/osd.h
			{Val: 28450, Str: "VIDEO_CLEAR_BUFFER"}, // From linux/dvb/video.h
			{Val: 3225972539, Str: "VIDEO_COMMAND"}, // From linux/dvb/video.h
			{Val: 28440, Str: "VIDEO_CONTINUE"}, // From linux/dvb/video.h
			{Val: 28447, Str: "VIDEO_FAST_FORWARD"}, // From linux/dvb/video.h
			{Val: 28439, Str: "VIDEO_FREEZE"}, // From linux/dvb/video.h
			{Val: 2147774241, Str: "VIDEO_GET_CAPABILITIES"}, // From linux/dvb/video.h
			{Val: 2149609244, Str: "VIDEO_GET_EVENT"}, // From linux/dvb/video.h
			{Val: 2148036410, Str: "VIDEO_GET_FRAME_COUNT"}, // From linux/dvb/video.h
			{Val: 2148036409, Str: "VIDEO_GET_PTS"}, // From linux/dvb/video.h
			{Val: 2148298551, Str: "VIDEO_GET_SIZE"}, // From linux/dvb/video.h
			{Val: 2148822811, Str: "VIDEO_GET_STATUS"}, // From linux/dvb/video.h
			{Val: 28438, Str: "VIDEO_PLAY"}, // From linux/dvb/video.h
			{Val: 28441, Str: "VIDEO_SELECT_SOURCE"}, // From linux/dvb/video.h
			{Val: 28442, Str: "VIDEO_SET_BLANK"}, // From linux/dvb/video.h
			{Val: 28445, Str: "VIDEO_SET_DISPLAY_FORMAT"}, // From linux/dvb/video.h
			{Val: 28453, Str: "VIDEO_SET_FORMAT"}, // From linux/dvb/video.h
			{Val: 28452, Str: "VIDEO_SET_STREAMTYPE"}, // From linux/dvb/video.h
			{Val: 28448, Str: "VIDEO_SLOWMOTION"}, // From linux/dvb/video.h
			{Val: 1074818846, Str: "VIDEO_STILLPICTURE"}, // From linux/dvb/video.h
			{Val: 28437, Str: "VIDEO_STOP"}, // From linux/dvb/video.h
			{Val: 3225972540, Str: "VIDEO_TRY_COMMAND"}, // From linux/dvb/video.h
			{Val: 2148043266, Str: "EPIOCGPARAMS"}, // From linux/eventpoll.h
			{Val: 1074301441, Str: "EPIOCSPARAMS"}, // From linux/eventpoll.h
			{Val: 2147771909, Str: "EXT4_IOC32_GETRSVSZ"}, // From linux/ext4.h
			{Val: 2147771907, Str: "EXT4_IOC32_GETVERSION"}, // From linux/ext4.h
			{Val: 1074030087, Str: "EXT4_IOC32_GROUP_EXTEND"}, // From linux/ext4.h
			{Val: 1074030086, Str: "EXT4_IOC32_SETRSVSZ"}, // From linux/ext4.h
			{Val: 1074030084, Str: "EXT4_IOC32_SETVERSION"}, // From linux/ext4.h
			{Val: 26124, Str: "EXT4_IOC_ALLOC_DA_BLKS"}, // From linux/ext4.h
			{Val: 1074030123, Str: "EXT4_IOC_CHECKPOINT"}, // From linux/ext4.h
			{Val: 26152, Str: "EXT4_IOC_CLEAR_ES_CACHE"}, // From linux/ext4.h
			{Val: 2148034092, Str: "EXT4_IOC_GETFSUUID"}, // From linux/ext4.h
			{Val: 2148034053, Str: "EXT4_IOC_GETRSVSZ"}, // From linux/ext4.h
			{Val: 1074030121, Str: "EXT4_IOC_GETSTATE"}, // From linux/ext4.h
			{Val: 2148034051, Str: "EXT4_IOC_GETVERSION"}, // From linux/ext4.h
			{Val: 3223348778, Str: "EXT4_IOC_GET_ES_CACHE"}, // From linux/ext4.h
			{Val: 2162714157, Str: "EXT4_IOC_GET_TUNE_SB_PARAM"}, // From linux/ext4.h
			{Val: 1076389384, Str: "EXT4_IOC_GROUP_ADD"}, // From linux/ext4.h
			{Val: 1074292231, Str: "EXT4_IOC_GROUP_EXTEND"}, // From linux/ext4.h
			{Val: 26121, Str: "EXT4_IOC_MIGRATE"}, // From linux/ext4.h
			{Val: 3223873039, Str: "EXT4_IOC_MOVE_EXT"}, // From linux/ext4.h
			{Val: 26130, Str: "EXT4_IOC_PRECACHE_EXTENTS"}, // From linux/ext4.h
			{Val: 1074292240, Str: "EXT4_IOC_RESIZE_FS"}, // From linux/ext4.h
			{Val: 1074292268, Str: "EXT4_IOC_SETFSUUID"}, // From linux/ext4.h
			{Val: 1074292230, Str: "EXT4_IOC_SETRSVSZ"}, // From linux/ext4.h
			{Val: 1074292228, Str: "EXT4_IOC_SETVERSION"}, // From linux/ext4.h
			{Val: 1088972334, Str: "EXT4_IOC_SET_TUNE_SB_PARAM"}, // From linux/ext4.h
			{Val: 26129, Str: "EXT4_IOC_SWAP_BOOT"}, // From linux/ext4.h
			{Val: 62725, Str: "F2FS_IOC_ABORT_ATOMIC_WRITE"}, // From linux/f2fs.h
			{Val: 62722, Str: "F2FS_IOC_COMMIT_ATOMIC_WRITE"}, // From linux/f2fs.h
			{Val: 62744, Str: "F2FS_IOC_COMPRESS_FILE"}, // From linux/f2fs.h
			{Val: 62743, Str: "F2FS_IOC_DECOMPRESS_FILE"}, // From linux/f2fs.h
			{Val: 3222336776, Str: "F2FS_IOC_DEFRAGMENT"}, // From linux/f2fs.h
			{Val: 1074328842, Str: "F2FS_IOC_FLUSH_DEVICE"}, // From linux/f2fs.h
			{Val: 1074066694, Str: "F2FS_IOC_GARBAGE_COLLECT"}, // From linux/f2fs.h
			{Val: 1075377419, Str: "F2FS_IOC_GARBAGE_COLLECT_RANGE"}, // From linux/f2fs.h
			{Val: 2148070673, Str: "F2FS_IOC_GET_COMPRESS_BLOCKS"}, // From linux/f2fs.h
			{Val: 2147677461, Str: "F2FS_IOC_GET_COMPRESS_OPTION"}, // From linux/f2fs.h
			{Val: 2147808538, Str: "F2FS_IOC_GET_DEV_ALIAS_FILE"}, // From linux/f2fs.h
			{Val: 2147808524, Str: "F2FS_IOC_GET_FEATURES"}, // From linux/f2fs.h
			{Val: 2147808526, Str: "F2FS_IOC_GET_PIN_FILE"}, // From linux/f2fs.h
			{Val: 1074066715, Str: "F2FS_IOC_IO_PRIO"}, // From linux/f2fs.h
			{Val: 3223385353, Str: "F2FS_IOC_MOVE_RANGE"}, // From linux/f2fs.h
			{Val: 62735, Str: "F2FS_IOC_PRECACHE_EXTENTS"}, // From linux/f2fs.h
			{Val: 2148070674, Str: "F2FS_IOC_RELEASE_COMPRESS_BLOCKS"}, // From linux/f2fs.h
			{Val: 62724, Str: "F2FS_IOC_RELEASE_VOLATILE_WRITE"}, // From linux/f2fs.h
			{Val: 2148070675, Str: "F2FS_IOC_RESERVE_COMPRESS_BLOCKS"}, // From linux/f2fs.h
			{Val: 1074328848, Str: "F2FS_IOC_RESIZE_FS"}, // From linux/f2fs.h
			{Val: 1075377428, Str: "F2FS_IOC_SEC_TRIM_FILE"}, // From linux/f2fs.h
			{Val: 1073935638, Str: "F2FS_IOC_SET_COMPRESS_OPTION"}, // From linux/f2fs.h
			{Val: 1074066701, Str: "F2FS_IOC_SET_PIN_FILE"}, // From linux/f2fs.h
			{Val: 62745, Str: "F2FS_IOC_START_ATOMIC_REPLACE"}, // From linux/f2fs.h
			{Val: 62721, Str: "F2FS_IOC_START_ATOMIC_WRITE"}, // From linux/f2fs.h
			{Val: 62723, Str: "F2FS_IOC_START_VOLATILE_WRITE"}, // From linux/f2fs.h
			{Val: 62727, Str: "F2FS_IOC_WRITE_CHECKPOINT"}, // From linux/f2fs.h
			{Val: 17937, Str: "FBIOBLANK"}, // From linux/fb.h
			{Val: 17924, Str: "FBIOGETCMAP"}, // From linux/fb.h
			{Val: 17935, Str: "FBIOGET_CON2FBMAP"}, // From linux/fb.h
			{Val: 17944, Str: "FBIOGET_DISPINFO"}, // From linux/fb.h
			{Val: 17922, Str: "FBIOGET_FSCREENINFO"}, // From linux/fb.h
			{Val: 17941, Str: "FBIOGET_GLYPH"}, // From linux/fb.h
			{Val: 17942, Str: "FBIOGET_HWCINFO"}, // From linux/fb.h
			{Val: 2149598738, Str: "FBIOGET_VBLANK"}, // From linux/fb.h
			{Val: 17920, Str: "FBIOGET_VSCREENINFO"}, // From linux/fb.h
			{Val: 17926, Str: "FBIOPAN_DISPLAY"}, // From linux/fb.h
			{Val: 17925, Str: "FBIOPUTCMAP"}, // From linux/fb.h
			{Val: 17936, Str: "FBIOPUT_CON2FBMAP"}, // From linux/fb.h
			{Val: 17943, Str: "FBIOPUT_MODEINFO"}, // From linux/fb.h
			{Val: 17921, Str: "FBIOPUT_VSCREENINFO"}, // From linux/fb.h
			{Val: 17939, Str: "FBIO_ALLOC"}, // From linux/fb.h
			{Val: 3228059144, Str: "FBIO_CURSOR"}, // From linux/fb.h
			{Val: 17940, Str: "FBIO_FREE"}, // From linux/fb.h
			{Val: 1074021920, Str: "FBIO_WAITFORVSYNC"}, // From linux/fb.h
			{Val: 577, Str: "FDCLRPRM"}, // From linux/fd.h
			{Val: 1075839555, Str: "FDDEFPRM"}, // From linux/fd.h
			{Val: 602, Str: "FDEJECT"}, // From linux/fd.h
			{Val: 587, Str: "FDFLUSH"}, // From linux/fd.h
			{Val: 583, Str: "FDFMTBEG"}, // From linux/fd.h
			{Val: 585, Str: "FDFMTEND"}, // From linux/fd.h
			{Val: 1074528840, Str: "FDFMTTRK"}, // From linux/fd.h
			{Val: 2155872785, Str: "FDGETDRVPRM"}, // From linux/fd.h
			{Val: 2152727058, Str: "FDGETDRVSTAT"}, // From linux/fd.h
			{Val: 2148532751, Str: "FDGETDRVTYP"}, // From linux/fd.h
			{Val: 2150105621, Str: "FDGETFDCSTAT"}, // From linux/fd.h
			{Val: 2148794894, Str: "FDGETMAXERRS"}, // From linux/fd.h
			{Val: 2149581316, Str: "FDGETPRM"}, // From linux/fd.h
			{Val: 582, Str: "FDMSGOFF"}, // From linux/fd.h
			{Val: 581, Str: "FDMSGON"}, // From linux/fd.h
			{Val: 2152727059, Str: "FDPOLLDRVSTAT"}, // From linux/fd.h
			{Val: 600, Str: "FDRAWCMD"}, // From linux/fd.h
			{Val: 596, Str: "FDRESET"}, // From linux/fd.h
			{Val: 1082131088, Str: "FDSETDRVPRM"}, // From linux/fd.h
			{Val: 586, Str: "FDSETEMSGTRESH"}, // From linux/fd.h
			{Val: 1075053132, Str: "FDSETMAXERRS"}, // From linux/fd.h
			{Val: 1075839554, Str: "FDSETPRM"}, // From linux/fd.h
			{Val: 601, Str: "FDTWADDLE"}, // From linux/fd.h
			{Val: 598, Str: "FDWERRORCLR"}, // From linux/fd.h
			{Val: 2150105623, Str: "FDWERRORGET"}, // From linux/fd.h
			{Val: 3222807302, Str: "FW_CDEV_IOC_ADD_DESCRIPTOR"}, // From linux/firewire-cdev.h
			{Val: 3223331586, Str: "FW_CDEV_IOC_ALLOCATE"}, // From linux/firewire-cdev.h
			{Val: 3222807309, Str: "FW_CDEV_IOC_ALLOCATE_ISO_RESOURCE"}, // From linux/firewire-cdev.h
			{Val: 1075323663, Str: "FW_CDEV_IOC_ALLOCATE_ISO_RESOURCE_ONCE"}, // From linux/firewire-cdev.h
			{Val: 3223331592, Str: "FW_CDEV_IOC_CREATE_ISO_CONTEXT"}, // From linux/firewire-cdev.h
			{Val: 1074012931, Str: "FW_CDEV_IOC_DEALLOCATE"}, // From linux/firewire-cdev.h
			{Val: 1074012942, Str: "FW_CDEV_IOC_DEALLOCATE_ISO_RESOURCE"}, // From linux/firewire-cdev.h
			{Val: 1075323664, Str: "FW_CDEV_IOC_DEALLOCATE_ISO_RESOURCE_ONCE"}, // From linux/firewire-cdev.h
			{Val: 1074012952, Str: "FW_CDEV_IOC_FLUSH_ISO"}, // From linux/firewire-cdev.h
			{Val: 2148541196, Str: "FW_CDEV_IOC_GET_CYCLE_TIMER"}, // From linux/firewire-cdev.h
			{Val: 3222807316, Str: "FW_CDEV_IOC_GET_CYCLE_TIMER2"}, // From linux/firewire-cdev.h
			{Val: 3223855872, Str: "FW_CDEV_IOC_GET_INFO"}, // From linux/firewire-cdev.h
			{Val: 8977, Str: "FW_CDEV_IOC_GET_SPEED"}, // From linux/firewire-cdev.h
			{Val: 1074012933, Str: "FW_CDEV_IOC_INITIATE_BUS_RESET"}, // From linux/firewire-cdev.h
			{Val: 3222807305, Str: "FW_CDEV_IOC_QUEUE_ISO"}, // From linux/firewire-cdev.h
			{Val: 1074275094, Str: "FW_CDEV_IOC_RECEIVE_PHY_PACKETS"}, // From linux/firewire-cdev.h
			{Val: 1074012935, Str: "FW_CDEV_IOC_REMOVE_DESCRIPTOR"}, // From linux/firewire-cdev.h
			{Val: 1076372242, Str: "FW_CDEV_IOC_SEND_BROADCAST_REQUEST"}, // From linux/firewire-cdev.h
			{Val: 3222807317, Str: "FW_CDEV_IOC_SEND_PHY_PACKET"}, // From linux/firewire-cdev.h
			{Val: 1076372225, Str: "FW_CDEV_IOC_SEND_REQUEST"}, // From linux/firewire-cdev.h
			{Val: 1075323652, Str: "FW_CDEV_IOC_SEND_RESPONSE"}, // From linux/firewire-cdev.h
			{Val: 1076372243, Str: "FW_CDEV_IOC_SEND_STREAM_PACKET"}, // From linux/firewire-cdev.h
			{Val: 1074799383, Str: "FW_CDEV_IOC_SET_ISO_CHANNELS"}, // From linux/firewire-cdev.h
			{Val: 1074799370, Str: "FW_CDEV_IOC_START_ISO"}, // From linux/firewire-cdev.h
			{Val: 1074012939, Str: "FW_CDEV_IOC_STOP_ISO"}, // From linux/firewire-cdev.h
			{Val: 46593, Str: "DFL_FPGA_CHECK_EXTENSION"}, // From linux/fpga-dfl.h
			{Val: 2147792515, Str: "DFL_FPGA_FME_ERR_GET_IRQ_NUM"}, // From linux/fpga-dfl.h
			{Val: 1074312836, Str: "DFL_FPGA_FME_ERR_SET_IRQ"}, // From linux/fpga-dfl.h
			{Val: 1074050690, Str: "DFL_FPGA_FME_PORT_ASSIGN"}, // From linux/fpga-dfl.h
			{Val: 46720, Str: "DFL_FPGA_FME_PORT_PR"}, // From linux/fpga-dfl.h
			{Val: 1074050689, Str: "DFL_FPGA_FME_PORT_RELEASE"}, // From linux/fpga-dfl.h
			{Val: 46592, Str: "DFL_FPGA_GET_API_VERSION"}, // From linux/fpga-dfl.h
			{Val: 46659, Str: "DFL_FPGA_PORT_DMA_MAP"}, // From linux/fpga-dfl.h
			{Val: 46660, Str: "DFL_FPGA_PORT_DMA_UNMAP"}, // From linux/fpga-dfl.h
			{Val: 2147792453, Str: "DFL_FPGA_PORT_ERR_GET_IRQ_NUM"}, // From linux/fpga-dfl.h
			{Val: 1074312774, Str: "DFL_FPGA_PORT_ERR_SET_IRQ"}, // From linux/fpga-dfl.h
			{Val: 46657, Str: "DFL_FPGA_PORT_GET_INFO"}, // From linux/fpga-dfl.h
			{Val: 46658, Str: "DFL_FPGA_PORT_GET_REGION_INFO"}, // From linux/fpga-dfl.h
			{Val: 46656, Str: "DFL_FPGA_PORT_RESET"}, // From linux/fpga-dfl.h
			{Val: 2147792455, Str: "DFL_FPGA_PORT_UINT_GET_IRQ_NUM"}, // From linux/fpga-dfl.h
			{Val: 1074312776, Str: "DFL_FPGA_PORT_UINT_SET_IRQ"}, // From linux/fpga-dfl.h
			{Val: 4730, Str: "BLKALIGNOFF"}, // From linux/fs.h
			{Val: 2148012656, Str: "BLKBSZGET"}, // From linux/fs.h
			{Val: 1074270833, Str: "BLKBSZSET"}, // From linux/fs.h
			{Val: 4727, Str: "BLKDISCARD"}, // From linux/fs.h
			{Val: 4732, Str: "BLKDISCARDZEROES"}, // From linux/fs.h
			{Val: 4705, Str: "BLKFLSBUF"}, // From linux/fs.h
			{Val: 4709, Str: "BLKFRAGET"}, // From linux/fs.h
			{Val: 4708, Str: "BLKFRASET"}, // From linux/fs.h
			{Val: 2148012672, Str: "BLKGETDISKSEQ"}, // From linux/fs.h
			{Val: 4704, Str: "BLKGETSIZE"}, // From linux/fs.h
			{Val: 2148012658, Str: "BLKGETSIZE64"}, // From linux/fs.h
			{Val: 4728, Str: "BLKIOMIN"}, // From linux/fs.h
			{Val: 4729, Str: "BLKIOOPT"}, // From linux/fs.h
			{Val: 4731, Str: "BLKPBSZGET"}, // From linux/fs.h
			{Val: 4707, Str: "BLKRAGET"}, // From linux/fs.h
			{Val: 4706, Str: "BLKRASET"}, // From linux/fs.h
			{Val: 4702, Str: "BLKROGET"}, // From linux/fs.h
			{Val: 4701, Str: "BLKROSET"}, // From linux/fs.h
			{Val: 4734, Str: "BLKROTATIONAL"}, // From linux/fs.h
			{Val: 4703, Str: "BLKRRPART"}, // From linux/fs.h
			{Val: 4733, Str: "BLKSECDISCARD"}, // From linux/fs.h
			{Val: 4711, Str: "BLKSECTGET"}, // From linux/fs.h
			{Val: 4710, Str: "BLKSECTSET"}, // From linux/fs.h
			{Val: 4712, Str: "BLKSSZGET"}, // From linux/fs.h
			{Val: 3225948787, Str: "BLKTRACESETUP"}, // From linux/fs.h
			{Val: 3233813134, Str: "BLKTRACESETUP2"}, // From linux/fs.h
			{Val: 4724, Str: "BLKTRACESTART"}, // From linux/fs.h
			{Val: 4725, Str: "BLKTRACESTOP"}, // From linux/fs.h
			{Val: 4726, Str: "BLKTRACETEARDOWN"}, // From linux/fs.h
			{Val: 4735, Str: "BLKZEROOUT"}, // From linux/fs.h
			{Val: 1, Str: "FIBMAP"}, // From linux/fs.h
			{Val: 1074041865, Str: "FICLONE"}, // From linux/fs.h
			{Val: 1075876877, Str: "FICLONERANGE"}, // From linux/fs.h
			{Val: 3222836278, Str: "FIDEDUPERANGE"}, // From linux/fs.h
			{Val: 3221510263, Str: "FIFREEZE"}, // From linux/fs.h
			{Val: 2, Str: "FIGETBSZ"}, // From linux/fs.h
			{Val: 3221510264, Str: "FITHAW"}, // From linux/fs.h
			{Val: 3222820985, Str: "FITRIM"}, // From linux/fs.h
			{Val: 2147771905, Str: "FS_IOC32_GETFLAGS"}, // From linux/fs.h
			{Val: 2147776001, Str: "FS_IOC32_GETVERSION"}, // From linux/fs.h
			{Val: 1074030082, Str: "FS_IOC32_SETFLAGS"}, // From linux/fs.h
			{Val: 1074034178, Str: "FS_IOC32_SETVERSION"}, // From linux/fs.h
			{Val: 3223348747, Str: "FS_IOC_FIEMAP"}, // From linux/fs.h
			{Val: 2149341215, Str: "FS_IOC_FSGETXATTR"}, // From linux/fs.h
			{Val: 1075599392, Str: "FS_IOC_FSSETXATTR"}, // From linux/fs.h
			{Val: 2148034049, Str: "FS_IOC_GETFLAGS"}, // From linux/fs.h
			{Val: 2164298801, Str: "FS_IOC_GETFSLABEL"}, // From linux/fs.h
			{Val: 2155943169, Str: "FS_IOC_GETFSSYSFSPATH"}, // From linux/fs.h
			{Val: 2148603136, Str: "FS_IOC_GETFSUUID"}, // From linux/fs.h
			{Val: 3222279426, Str: "FS_IOC_GETLBMD_CAP"}, // From linux/fs.h
			{Val: 2148038145, Str: "FS_IOC_GETVERSION"}, // From linux/fs.h
			{Val: 1074292226, Str: "FS_IOC_SETFLAGS"}, // From linux/fs.h
			{Val: 1090556978, Str: "FS_IOC_SETFSLABEL"}, // From linux/fs.h
			{Val: 1074296322, Str: "FS_IOC_SETVERSION"}, // From linux/fs.h
			{Val: 2147768445, Str: "FS_IOC_SHUTDOWN"}, // From linux/fs.h
			{Val: 3227543056, Str: "PAGEMAP_SCAN"}, // From linux/fs.h
			{Val: 3228067345, Str: "PROCMAP_QUERY"}, // From linux/fs.h
			{Val: 3226494487, Str: "FS_IOC_ADD_ENCRYPTION_KEY"}, // From linux/fscrypt.h
			{Val: 3229640218, Str: "FS_IOC_GET_ENCRYPTION_KEY_STATUS"}, // From linux/fscrypt.h
			{Val: 2148558363, Str: "FS_IOC_GET_ENCRYPTION_NONCE"}, // From linux/fscrypt.h
			{Val: 1074554389, Str: "FS_IOC_GET_ENCRYPTION_POLICY"}, // From linux/fscrypt.h
			{Val: 3221841430, Str: "FS_IOC_GET_ENCRYPTION_POLICY_EX"}, // From linux/fscrypt.h
			{Val: 1074816532, Str: "FS_IOC_GET_ENCRYPTION_PWSALT"}, // From linux/fscrypt.h
			{Val: 3225445912, Str: "FS_IOC_REMOVE_ENCRYPTION_KEY"}, // From linux/fscrypt.h
			{Val: 3225445913, Str: "FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS"}, // From linux/fscrypt.h
			{Val: 2148296211, Str: "FS_IOC_SET_ENCRYPTION_POLICY"}, // From linux/fscrypt.h
			{Val: 1074033409, Str: "FSI_SBEFIFO_CMD_TIMEOUT_SECONDS"}, // From linux/fsi.h
			{Val: 1074033408, Str: "FSI_SBEFIFO_READ_TIMEOUT_SECONDS"}, // From linux/fsi.h
			{Val: 2147775232, Str: "FSI_SCOM_CHECK"}, // From linux/fsi.h
			{Val: 3223352065, Str: "FSI_SCOM_READ"}, // From linux/fsi.h
			{Val: 1074033411, Str: "FSI_SCOM_RESET"}, // From linux/fsi.h
			{Val: 3223352066, Str: "FSI_SCOM_WRITE"}, // From linux/fsi.h
			{Val: 2147568896, Str: "MFB_GET_ALPHA"}, // From linux/fsl-diu-fb.h
			{Val: 2148027652, Str: "MFB_GET_AOID"}, // From linux/fsl-diu-fb.h
			{Val: 2147568897, Str: "MFB_GET_GAMMA"}, // From linux/fsl-diu-fb.h
			{Val: 2147765512, Str: "MFB_GET_PIXFMT"}, // From linux/fsl-diu-fb.h
			{Val: 1073827072, Str: "MFB_SET_ALPHA"}, // From linux/fsl-diu-fb.h
			{Val: 1074285828, Str: "MFB_SET_AOID"}, // From linux/fsl-diu-fb.h
			{Val: 1073827075, Str: "MFB_SET_BRIGHTNESS"}, // From linux/fsl-diu-fb.h
			{Val: 1074547969, Str: "MFB_SET_CHROMA_KEY"}, // From linux/fsl-diu-fb.h
			{Val: 1073827073, Str: "MFB_SET_GAMMA"}, // From linux/fsl-diu-fb.h
			{Val: 1074023688, Str: "MFB_SET_PIXFMT"}, // From linux/fsl-diu-fb.h
			{Val: 3221794566, Str: "FSL_HV_IOCTL_DOORBELL"}, // From linux/fsl_hypervisor.h
			{Val: 3223891719, Str: "FSL_HV_IOCTL_GETPROP"}, // From linux/fsl_hypervisor.h
			{Val: 3223891717, Str: "FSL_HV_IOCTL_MEMCPY"}, // From linux/fsl_hypervisor.h
			{Val: 3222056706, Str: "FSL_HV_IOCTL_PARTITION_GET_STATUS"}, // From linux/fsl_hypervisor.h
			{Val: 3221794561, Str: "FSL_HV_IOCTL_PARTITION_RESTART"}, // From linux/fsl_hypervisor.h
			{Val: 3222318851, Str: "FSL_HV_IOCTL_PARTITION_START"}, // From linux/fsl_hypervisor.h
			{Val: 3221794564, Str: "FSL_HV_IOCTL_PARTITION_STOP"}, // From linux/fsl_hypervisor.h
			{Val: 3223891720, Str: "FSL_HV_IOCTL_SETPROP"}, // From linux/fsl_hypervisor.h
			{Val: 3225440992, Str: "FSL_MC_SEND_MC_COMMAND"}, // From linux/fsl_mc.h
			{Val: 3233830971, Str: "FS_IOC_GETFSMAP"}, // From linux/fsmap.h
			{Val: 1082156677, Str: "FS_IOC_ENABLE_VERITY"}, // From linux/fsverity.h
			{Val: 3221513862, Str: "FS_IOC_MEASURE_VERITY"}, // From linux/fsverity.h
			{Val: 3223873159, Str: "FS_IOC_READ_VERITY_METADATA"}, // From linux/fsverity.h
			{Val: 1074062594, Str: "FUSE_DEV_IOC_BACKING_CLOSE"}, // From linux/fuse.h
			{Val: 1074849025, Str: "FUSE_DEV_IOC_BACKING_OPEN"}, // From linux/fuse.h
			{Val: 2147804416, Str: "FUSE_DEV_IOC_CLONE"}, // From linux/fuse.h
			{Val: 58627, Str: "FUSE_DEV_IOC_SYNC_INIT"}, // From linux/fuse.h
			{Val: 3236472114, Str: "GENWQE_EXECUTE_DDCB"}, // From linux/genwqe/genwqe_card.h
			{Val: 3236472115, Str: "GENWQE_EXECUTE_RAW_DDCB"}, // From linux/genwqe/genwqe_card.h
			{Val: 2147788068, Str: "GENWQE_GET_CARD_STATE"}, // From linux/genwqe/genwqe_card.h
			{Val: 3223364904, Str: "GENWQE_PIN_MEM"}, // From linux/genwqe/genwqe_card.h
			{Val: 2148574498, Str: "GENWQE_READ_REG16"}, // From linux/genwqe/genwqe_card.h
			{Val: 2148574496, Str: "GENWQE_READ_REG32"}, // From linux/genwqe/genwqe_card.h
			{Val: 2148574494, Str: "GENWQE_READ_REG64"}, // From linux/genwqe/genwqe_card.h
			{Val: 3224937809, Str: "GENWQE_SLU_READ"}, // From linux/genwqe/genwqe_card.h
			{Val: 3224937808, Str: "GENWQE_SLU_UPDATE"}, // From linux/genwqe/genwqe_card.h
			{Val: 3223364905, Str: "GENWQE_UNPIN_MEM"}, // From linux/genwqe/genwqe_card.h
			{Val: 1074832675, Str: "GENWQE_WRITE_REG16"}, // From linux/genwqe/genwqe_card.h
			{Val: 1074832673, Str: "GENWQE_WRITE_REG32"}, // From linux/genwqe/genwqe_card.h
			{Val: 1074832671, Str: "GENWQE_WRITE_REG64"}, // From linux/genwqe/genwqe_card.h
			{Val: 1074307093, Str: "CFCBASE"}, // From linux/gpib_ioctl.h
			{Val: 1080336408, Str: "CFCBOARDTYPE"}, // From linux/gpib_ioctl.h
			{Val: 1074044951, Str: "CFCDMA"}, // From linux/gpib_ioctl.h
			{Val: 1074044950, Str: "CFCIRQ"}, // From linux/gpib_ioctl.h
			{Val: 1073913894, Str: "IBAUTOSPOLL"}, // From linux/gpib_ioctl.h
			{Val: 2149359645, Str: "IBBOARD_INFO"}, // From linux/gpib_ioctl.h
			{Val: 1074044940, Str: "IBCAC"}, // From linux/gpib_ioctl.h
			{Val: 1074044932, Str: "IBCLOSEDEV"}, // From linux/gpib_ioctl.h
			{Val: 3222839398, Str: "IBCMD"}, // From linux/gpib_ioctl.h
			{Val: 1074307091, Str: "IBEOS"}, // From linux/gpib_ioctl.h
			{Val: 2147655713, Str: "IBEVENT"}, // From linux/gpib_ioctl.h
			{Val: 40971, Str: "IBGTS"}, // From linux/gpib_ioctl.h
			{Val: 2147655694, Str: "IBLINES"}, // From linux/gpib_ioctl.h
			{Val: 40996, Str: "IBLOC"}, // From linux/gpib_ioctl.h
			{Val: 1074044954, Str: "IBMUTEX"}, // From linux/gpib_ioctl.h
			{Val: 1074831399, Str: "IBONL"}, // From linux/gpib_ioctl.h
			{Val: 3222315011, Str: "IBOPENDEV"}, // From linux/gpib_ioctl.h
			{Val: 1074307087, Str: "IBPAD"}, // From linux/gpib_ioctl.h
			{Val: 2147655721, Str: "IBPP2_GET"}, // From linux/gpib_ioctl.h
			{Val: 1073913896, Str: "IBPP2_SET"}, // From linux/gpib_ioctl.h
			{Val: 1074044956, Str: "IBPPC"}, // From linux/gpib_ioctl.h
			{Val: 2147786783, Str: "IBQUERY_BOARD_RSV"}, // From linux/gpib_ioctl.h
			{Val: 3222839396, Str: "IBRD"}, // From linux/gpib_ioctl.h
			{Val: 3221331974, Str: "IBRPP"}, // From linux/gpib_ioctl.h
			{Val: 1074044962, Str: "IBRSC"}, // From linux/gpib_ioctl.h
			{Val: 3222052882, Str: "IBRSP"}, // From linux/gpib_ioctl.h
			{Val: 1073848340, Str: "IBRSV"}, // From linux/gpib_ioctl.h
			{Val: 1074307088, Str: "IBSAD"}, // From linux/gpib_ioctl.h
			{Val: 1342218283, Str: "IBSELECT_DEVICE_PATH"}, // From linux/gpib_ioctl.h
			{Val: 3221790752, Str: "IBSELECT_PCI"}, // From linux/gpib_ioctl.h
			{Val: 1074044937, Str: "IBSIC"}, // From linux/gpib_ioctl.h
			{Val: 3222052891, Str: "IBSPOLL_BYTES"}, // From linux/gpib_ioctl.h
			{Val: 1074044938, Str: "IBSRE"}, // From linux/gpib_ioctl.h
			{Val: 1074044945, Str: "IBTMO"}, // From linux/gpib_ioctl.h
			{Val: 3223363589, Str: "IBWAIT"}, // From linux/gpib_ioctl.h
			{Val: 3222839397, Str: "IBWRT"}, // From linux/gpib_ioctl.h
			{Val: 1074044963, Str: "IB_T1_DELAY"}, // From linux/gpib_ioctl.h
			{Val: 3225465864, Str: "GPIOHANDLE_GET_LINE_VALUES_IOCTL"}, // From linux/gpio.h
			{Val: 3226776586, Str: "GPIOHANDLE_SET_CONFIG_IOCTL"}, // From linux/gpio.h
			{Val: 3225465865, Str: "GPIOHANDLE_SET_LINE_VALUES_IOCTL"}, // From linux/gpio.h
			{Val: 2151986177, Str: "GPIO_GET_CHIPINFO_IOCTL"}, // From linux/gpio.h
			{Val: 3224417284, Str: "GPIO_GET_LINEEVENT_IOCTL"}, // From linux/gpio.h
			{Val: 3245126659, Str: "GPIO_GET_LINEHANDLE_IOCTL"}, // From linux/gpio.h
			{Val: 3225990146, Str: "GPIO_GET_LINEINFO_IOCTL"}, // From linux/gpio.h
			{Val: 3221533708, Str: "GPIO_GET_LINEINFO_UNWATCH_IOCTL"}, // From linux/gpio.h
			{Val: 3225990155, Str: "GPIO_GET_LINEINFO_WATCH_IOCTL"}, // From linux/gpio.h
			{Val: 3238048773, Str: "GPIO_V2_GET_LINEINFO_IOCTL"}, // From linux/gpio.h
			{Val: 3238048774, Str: "GPIO_V2_GET_LINEINFO_WATCH_IOCTL"}, // From linux/gpio.h
			{Val: 3260068871, Str: "GPIO_V2_GET_LINE_IOCTL"}, // From linux/gpio.h
			{Val: 3222320142, Str: "GPIO_V2_LINE_GET_VALUES_IOCTL"}, // From linux/gpio.h
			{Val: 3239097357, Str: "GPIO_V2_LINE_SET_CONFIG_IOCTL"}, // From linux/gpio.h
			{Val: 3222320143, Str: "GPIO_V2_LINE_SET_VALUES_IOCTL"}, // From linux/gpio.h
			{Val: 18179, Str: "GSMIOC_DISABLE_NET"}, // From linux/gsmmux.h
			{Val: 1077167874, Str: "GSMIOC_ENABLE_NET"}, // From linux/gsmmux.h
			{Val: 2152482560, Str: "GSMIOC_GETCONF"}, // From linux/gsmmux.h
			{Val: 3224913671, Str: "GSMIOC_GETCONF_DLCI"}, // From linux/gsmmux.h
			{Val: 2149598981, Str: "GSMIOC_GETCONF_EXT"}, // From linux/gsmmux.h
			{Val: 2147763972, Str: "GSMIOC_GETFIRST"}, // From linux/gsmmux.h
			{Val: 1078740737, Str: "GSMIOC_SETCONF"}, // From linux/gsmmux.h
			{Val: 1077430024, Str: "GSMIOC_SETCONF_DLCI"}, // From linux/gsmmux.h
			{Val: 1075857158, Str: "GSMIOC_SETCONF_EXT"}, // From linux/gsmmux.h
			{Val: 799, Str: "HDIO_DRIVE_CMD"}, // From linux/hdreg.h
			{Val: 796, Str: "HDIO_DRIVE_RESET"}, // From linux/hdreg.h
			{Val: 798, Str: "HDIO_DRIVE_TASK"}, // From linux/hdreg.h
			{Val: 797, Str: "HDIO_DRIVE_TASKFILE"}, // From linux/hdreg.h
			{Val: 769, Str: "HDIO_GETGEO"}, // From linux/hdreg.h
			{Val: 777, Str: "HDIO_GET_32BIT"}, // From linux/hdreg.h
			{Val: 783, Str: "HDIO_GET_ACOUSTIC"}, // From linux/hdreg.h
			{Val: 784, Str: "HDIO_GET_ADDRESS"}, // From linux/hdreg.h
			{Val: 794, Str: "HDIO_GET_BUSSTATE"}, // From linux/hdreg.h
			{Val: 779, Str: "HDIO_GET_DMA"}, // From linux/hdreg.h
			{Val: 781, Str: "HDIO_GET_IDENTITY"}, // From linux/hdreg.h
			{Val: 776, Str: "HDIO_GET_KEEPSETTINGS"}, // From linux/hdreg.h
			{Val: 772, Str: "HDIO_GET_MULTCOUNT"}, // From linux/hdreg.h
			{Val: 780, Str: "HDIO_GET_NICE"}, // From linux/hdreg.h
			{Val: 778, Str: "HDIO_GET_NOWERR"}, // From linux/hdreg.h
			{Val: 773, Str: "HDIO_GET_QDMA"}, // From linux/hdreg.h
			{Val: 770, Str: "HDIO_GET_UNMASKINTR"}, // From linux/hdreg.h
			{Val: 782, Str: "HDIO_GET_WCACHE"}, // From linux/hdreg.h
			{Val: 775, Str: "HDIO_OBSOLETE_IDENTITY"}, // From linux/hdreg.h
			{Val: 808, Str: "HDIO_SCAN_HWIF"}, // From linux/hdreg.h
			{Val: 804, Str: "HDIO_SET_32BIT"}, // From linux/hdreg.h
			{Val: 812, Str: "HDIO_SET_ACOUSTIC"}, // From linux/hdreg.h
			{Val: 815, Str: "HDIO_SET_ADDRESS"}, // From linux/hdreg.h
			{Val: 813, Str: "HDIO_SET_BUSSTATE"}, // From linux/hdreg.h
			{Val: 806, Str: "HDIO_SET_DMA"}, // From linux/hdreg.h
			{Val: 803, Str: "HDIO_SET_KEEPSETTINGS"}, // From linux/hdreg.h
			{Val: 801, Str: "HDIO_SET_MULTCOUNT"}, // From linux/hdreg.h
			{Val: 809, Str: "HDIO_SET_NICE"}, // From linux/hdreg.h
			{Val: 805, Str: "HDIO_SET_NOWERR"}, // From linux/hdreg.h
			{Val: 807, Str: "HDIO_SET_PIO_MODE"}, // From linux/hdreg.h
			{Val: 814, Str: "HDIO_SET_QDMA"}, // From linux/hdreg.h
			{Val: 802, Str: "HDIO_SET_UNMASKINTR"}, // From linux/hdreg.h
			{Val: 811, Str: "HDIO_SET_WCACHE"}, // From linux/hdreg.h
			{Val: 774, Str: "HDIO_SET_XFER"}, // From linux/hdreg.h
			{Val: 795, Str: "HDIO_TRISTATE_HWIF"}, // From linux/hdreg.h
			{Val: 810, Str: "HDIO_UNREGISTER_HWIF"}, // From linux/hdreg.h
			{Val: 2147764465, Str: "ROCCATIOCGREPSIZE"}, // From linux/hid-roccat.h
			{Val: 18434, Str: "HIDIOCAPPLICATION"}, // From linux/hiddev.h
			{Val: 1075333136, Str: "HIDIOCGCOLLECTIONINDEX"}, // From linux/hiddev.h
			{Val: 3222292497, Str: "HIDIOCGCOLLECTIONINFO"}, // From linux/hiddev.h
			{Val: 2149337091, Str: "HIDIOCGDEVINFO"}, // From linux/hiddev.h
			{Val: 3224913930, Str: "HIDIOCGFIELDINFO"}, // From linux/hiddev.h
			{Val: 2147764238, Str: "HIDIOCGFLAG"}, // From linux/hiddev.h
			{Val: 1074546695, Str: "HIDIOCGREPORT"}, // From linux/hiddev.h
			{Val: 3222030345, Str: "HIDIOCGREPORTINFO"}, // From linux/hiddev.h
			{Val: 2164541444, Str: "HIDIOCGSTRING"}, // From linux/hiddev.h
			{Val: 3222816781, Str: "HIDIOCGUCODE"}, // From linux/hiddev.h
			{Val: 3222816779, Str: "HIDIOCGUSAGE"}, // From linux/hiddev.h
			{Val: 3491514387, Str: "HIDIOCGUSAGES"}, // From linux/hiddev.h
			{Val: 2147764225, Str: "HIDIOCGVERSION"}, // From linux/hiddev.h
			{Val: 18437, Str: "HIDIOCINITREPORT"}, // From linux/hiddev.h
			{Val: 1074022415, Str: "HIDIOCSFLAG"}, // From linux/hiddev.h
			{Val: 1074546696, Str: "HIDIOCSREPORT"}, // From linux/hiddev.h
			{Val: 1075333132, Str: "HIDIOCSUSAGE"}, // From linux/hiddev.h
			{Val: 1344030740, Str: "HIDIOCSUSAGES"}, // From linux/hiddev.h
			{Val: 2148026371, Str: "HIDIOCGRAWINFO"}, // From linux/hidraw.h
			{Val: 2416199682, Str: "HIDIOCGRDESC"}, // From linux/hidraw.h
			{Val: 2147764225, Str: "HIDIOCGRDESCSIZE"}, // From linux/hidraw.h
			{Val: 1074022413, Str: "HIDIOCREVOKE"}, // From linux/hidraw.h
			{Val: 26629, Str: "HPET_DPI"}, // From linux/hpet.h
			{Val: 26628, Str: "HPET_EPI"}, // From linux/hpet.h
			{Val: 26626, Str: "HPET_IE_OFF"}, // From linux/hpet.h
			{Val: 26625, Str: "HPET_IE_ON"}, // From linux/hpet.h
			{Val: 2149083139, Str: "HPET_INFO"}, // From linux/hpet.h
			{Val: 1074292742, Str: "HPET_IRQFREQ"}, // From linux/hpet.h
			{Val: 1075856159, Str: "CS_CONFIG_BUFS"}, // From linux/hsi/cs-protocol.h
			{Val: 2147762974, Str: "CS_GET_IF_VERSION"}, // From linux/hsi/cs-protocol.h
			{Val: 2147762965, Str: "CS_GET_STATE"}, // From linux/hsi/cs-protocol.h
			{Val: 1074021143, Str: "CS_SET_WAKELINE"}, // From linux/hsi/cs-protocol.h
			{Val: 1074555668, Str: "HSC_GET_RX"}, // From linux/hsi/hsi_char.h
			{Val: 1074817814, Str: "HSC_GET_TX"}, // From linux/hsi/hsi_char.h
			{Val: 27408, Str: "HSC_RESET"}, // From linux/hsi/hsi_char.h
			{Val: 27410, Str: "HSC_SEND_BREAK"}, // From linux/hsi/hsi_char.h
			{Val: 27409, Str: "HSC_SET_PM"}, // From linux/hsi/hsi_char.h
			{Val: 1074555667, Str: "HSC_SET_RX"}, // From linux/hsi/hsi_char.h
			{Val: 1074817813, Str: "HSC_SET_TX"}, // From linux/hsi/hsi_char.h
			{Val: 2154326283, Str: "I2OEVTGET"}, // From linux/i2o-dev.h
			{Val: 1074555146, Str: "I2OEVTREG"}, // From linux/i2o-dev.h
			{Val: 2149607680, Str: "I2OGETIOPS"}, // From linux/i2o-dev.h
			{Val: 3222825217, Str: "I2OHRTGET"}, // From linux/i2o-dev.h
			{Val: 3224398089, Str: "I2OHTML"}, // From linux/i2o-dev.h
			{Val: 3222825218, Str: "I2OLCTGET"}, // From linux/i2o-dev.h
			{Val: 3223873796, Str: "I2OPARMGET"}, // From linux/i2o-dev.h
			{Val: 3223873795, Str: "I2OPARMSET"}, // From linux/i2o-dev.h
			{Val: 2148559116, Str: "I2OPASSTHRU"}, // From linux/i2o-dev.h
			{Val: 2148034828, Str: "I2OPASSTHRU32"}, // From linux/i2o-dev.h
			{Val: 3224398087, Str: "I2OSWDEL"}, // From linux/i2o-dev.h
			{Val: 3224398085, Str: "I2OSWDL"}, // From linux/i2o-dev.h
			{Val: 3224398086, Str: "I2OSWUL"}, // From linux/i2o-dev.h
			{Val: 2147772680, Str: "I2OVALIDATE"}, // From linux/i2o-dev.h
			{Val: 2147772800, Str: "I8K_BIOS_VERSION"}, // From linux/i8k.h
			{Val: 2148034947, Str: "I8K_FN_STATUS"}, // From linux/i8k.h
			{Val: 3221776774, Str: "I8K_GET_FAN"}, // From linux/i8k.h
			{Val: 3221776773, Str: "I8K_GET_SPEED"}, // From linux/i8k.h
			{Val: 2148034948, Str: "I8K_GET_TEMP"}, // From linux/i8k.h
			{Val: 2147772801, Str: "I8K_MACHINE_ID"}, // From linux/i8k.h
			{Val: 2148034946, Str: "I8K_POWER_STATUS"}, // From linux/i8k.h
			{Val: 3221776775, Str: "I8K_SET_FAN"}, // From linux/i8k.h
			{Val: 45313, Str: "PPPOEIOCDFWD"}, // From linux/if_pppox.h
			{Val: 1074311424, Str: "PPPOEIOCSFWD"}, // From linux/if_pppox.h
			{Val: 1074812117, Str: "TUNATTACHFILTER"}, // From linux/if_tun.h
			{Val: 1074812118, Str: "TUNDETACHFILTER"}, // From linux/if_tun.h
			{Val: 21731, Str: "TUNGETDEVNETNS"}, // From linux/if_tun.h
			{Val: 2147767503, Str: "TUNGETFEATURES"}, // From linux/if_tun.h
			{Val: 2148553947, Str: "TUNGETFILTER"}, // From linux/if_tun.h
			{Val: 2147767506, Str: "TUNGETIFF"}, // From linux/if_tun.h
			{Val: 2147767507, Str: "TUNGETSNDBUF"}, // From linux/if_tun.h
			{Val: 2147767519, Str: "TUNGETVNETBE"}, // From linux/if_tun.h
			{Val: 2147767511, Str: "TUNGETVNETHDRSZ"}, // From linux/if_tun.h
			{Val: 2147767517, Str: "TUNGETVNETLE"}, // From linux/if_tun.h
			{Val: 1074025698, Str: "TUNSETCARRIER"}, // From linux/if_tun.h
			{Val: 1074025673, Str: "TUNSETDEBUG"}, // From linux/if_tun.h
			{Val: 2147767521, Str: "TUNSETFILTEREBPF"}, // From linux/if_tun.h
			{Val: 1074025678, Str: "TUNSETGROUP"}, // From linux/if_tun.h
			{Val: 1074025674, Str: "TUNSETIFF"}, // From linux/if_tun.h
			{Val: 1074025690, Str: "TUNSETIFINDEX"}, // From linux/if_tun.h
			{Val: 1074025677, Str: "TUNSETLINK"}, // From linux/if_tun.h
			{Val: 1074025672, Str: "TUNSETNOCSUM"}, // From linux/if_tun.h
			{Val: 1074025680, Str: "TUNSETOFFLOAD"}, // From linux/if_tun.h
			{Val: 1074025676, Str: "TUNSETOWNER"}, // From linux/if_tun.h
			{Val: 1074025675, Str: "TUNSETPERSIST"}, // From linux/if_tun.h
			{Val: 1074025689, Str: "TUNSETQUEUE"}, // From linux/if_tun.h
			{Val: 1074025684, Str: "TUNSETSNDBUF"}, // From linux/if_tun.h
			{Val: 2147767520, Str: "TUNSETSTEERINGEBPF"}, // From linux/if_tun.h
			{Val: 1074025681, Str: "TUNSETTXFILTER"}, // From linux/if_tun.h
			{Val: 1074025694, Str: "TUNSETVNETBE"}, // From linux/if_tun.h
			{Val: 1074025688, Str: "TUNSETVNETHDRSZ"}, // From linux/if_tun.h
			{Val: 1074025692, Str: "TUNSETVNETLE"}, // From linux/if_tun.h
			{Val: 1074030994, Str: "IIO_BUFFER_DMABUF_ATTACH_IOCTL"}, // From linux/iio/buffer.h
			{Val: 1074030995, Str: "IIO_BUFFER_DMABUF_DETACH_IOCTL"}, // From linux/iio/buffer.h
			{Val: 1074817428, Str: "IIO_BUFFER_DMABUF_ENQUEUE_IOCTL"}, // From linux/iio/buffer.h
			{Val: 3221514641, Str: "IIO_BUFFER_GET_FD_IOCTL"}, // From linux/iio/buffer.h
			{Val: 2147772816, Str: "IIO_GET_EVENT_FD_IOCTL"}, // From linux/iio/events.h
			{Val: 1074022656, Str: "INOTIFY_IOC_SETNEXTWD"}, // From linux/inotify.h
			{Val: 2147763588, Str: "EVIOCGEFFECTS"}, // From linux/input.h
			{Val: 2148025602, Str: "EVIOCGID"}, // From linux/input.h
			{Val: 2148025604, Str: "EVIOCGKEYCODE"}, // From linux/input.h
			{Val: 2150122756, Str: "EVIOCGKEYCODE_V2"}, // From linux/input.h
			{Val: 2148550034, Str: "EVIOCGMASK"}, // From linux/input.h
			{Val: 1074021776, Str: "EVIOCGRAB"}, // From linux/input.h
			{Val: 2148025603, Str: "EVIOCGREP"}, // From linux/input.h
			{Val: 2147763457, Str: "EVIOCGVERSION"}, // From linux/input.h
			{Val: 1074021777, Str: "EVIOCREVOKE"}, // From linux/input.h
			{Val: 1074021761, Str: "EVIOCRMFF"}, // From linux/input.h
			{Val: 1074021792, Str: "EVIOCSCLOCKID"}, // From linux/input.h
			{Val: 1076905344, Str: "EVIOCSFF"}, // From linux/input.h
			{Val: 1074283780, Str: "EVIOCSKEYCODE"}, // From linux/input.h
			{Val: 1076380932, Str: "EVIOCSKEYCODE_V2"}, // From linux/input.h
			{Val: 1074808211, Str: "EVIOCSMASK"}, // From linux/input.h
			{Val: 1074283779, Str: "EVIOCSREP"}, // From linux/input.h
			{Val: 15232, Str: "IOMMU_DESTROY"}, // From linux/iommufd.h
			{Val: 15246, Str: "IOMMU_FAULT_QUEUE_ALLOC"}, // From linux/iommufd.h
			{Val: 15242, Str: "IOMMU_GET_HW_INFO"}, // From linux/iommufd.h
			{Val: 15241, Str: "IOMMU_HWPT_ALLOC"}, // From linux/iommufd.h
			{Val: 15244, Str: "IOMMU_HWPT_GET_DIRTY_BITMAP"}, // From linux/iommufd.h
			{Val: 15245, Str: "IOMMU_HWPT_INVALIDATE"}, // From linux/iommufd.h
			{Val: 15243, Str: "IOMMU_HWPT_SET_DIRTY_TRACKING"}, // From linux/iommufd.h
			{Val: 15252, Str: "IOMMU_HW_QUEUE_ALLOC"}, // From linux/iommufd.h
			{Val: 15233, Str: "IOMMU_IOAS_ALLOC"}, // From linux/iommufd.h
			{Val: 15234, Str: "IOMMU_IOAS_ALLOW_IOVAS"}, // From linux/iommufd.h
			{Val: 15250, Str: "IOMMU_IOAS_CHANGE_PROCESS"}, // From linux/iommufd.h
			{Val: 15235, Str: "IOMMU_IOAS_COPY"}, // From linux/iommufd.h
			{Val: 15236, Str: "IOMMU_IOAS_IOVA_RANGES"}, // From linux/iommufd.h
			{Val: 15237, Str: "IOMMU_IOAS_MAP"}, // From linux/iommufd.h
			{Val: 15247, Str: "IOMMU_IOAS_MAP_FILE"}, // From linux/iommufd.h
			{Val: 15238, Str: "IOMMU_IOAS_UNMAP"}, // From linux/iommufd.h
			{Val: 15239, Str: "IOMMU_OPTION"}, // From linux/iommufd.h
			{Val: 15249, Str: "IOMMU_VDEVICE_ALLOC"}, // From linux/iommufd.h
			{Val: 15251, Str: "IOMMU_VEVENTQ_ALLOC"}, // From linux/iommufd.h
			{Val: 15240, Str: "IOMMU_VFIO_IOAS"}, // From linux/iommufd.h
			{Val: 15248, Str: "IOMMU_VIOMMU_ALLOC"}, // From linux/iommufd.h
			{Val: 2147772702, Str: "IPMICTL_GET_MAINTENANCE_MODE_CMD"}, // From linux/ipmi.h
			{Val: 2147772690, Str: "IPMICTL_GET_MY_ADDRESS_CMD"}, // From linux/ipmi.h
			{Val: 2147772697, Str: "IPMICTL_GET_MY_CHANNEL_ADDRESS_CMD"}, // From linux/ipmi.h
			{Val: 2147772699, Str: "IPMICTL_GET_MY_CHANNEL_LUN_CMD"}, // From linux/ipmi.h
			{Val: 2147772692, Str: "IPMICTL_GET_MY_LUN_CMD"}, // From linux/ipmi.h
			{Val: 2148034839, Str: "IPMICTL_GET_TIMING_PARMS_CMD"}, // From linux/ipmi.h
			{Val: 3224398092, Str: "IPMICTL_RECEIVE_MSG"}, // From linux/ipmi.h
			{Val: 3224398091, Str: "IPMICTL_RECEIVE_MSG_TRUNC"}, // From linux/ipmi.h
			{Val: 2147641614, Str: "IPMICTL_REGISTER_FOR_CMD"}, // From linux/ipmi.h
			{Val: 2148296988, Str: "IPMICTL_REGISTER_FOR_CMD_CHANS"}, // From linux/ipmi.h
			{Val: 2150131981, Str: "IPMICTL_SEND_COMMAND"}, // From linux/ipmi.h
			{Val: 2150656277, Str: "IPMICTL_SEND_COMMAND_SETTIME"}, // From linux/ipmi.h
			{Val: 2147772688, Str: "IPMICTL_SET_GETS_EVENTS_CMD"}, // From linux/ipmi.h
			{Val: 1074030879, Str: "IPMICTL_SET_MAINTENANCE_MODE_CMD"}, // From linux/ipmi.h
			{Val: 2147772689, Str: "IPMICTL_SET_MY_ADDRESS_CMD"}, // From linux/ipmi.h
			{Val: 2147772696, Str: "IPMICTL_SET_MY_CHANNEL_ADDRESS_CMD"}, // From linux/ipmi.h
			{Val: 2147772698, Str: "IPMICTL_SET_MY_CHANNEL_LUN_CMD"}, // From linux/ipmi.h
			{Val: 2147772691, Str: "IPMICTL_SET_MY_LUN_CMD"}, // From linux/ipmi.h
			{Val: 2148034838, Str: "IPMICTL_SET_TIMING_PARMS_CMD"}, // From linux/ipmi.h
			{Val: 2147641615, Str: "IPMICTL_UNREGISTER_FOR_CMD"}, // From linux/ipmi.h
			{Val: 2148296989, Str: "IPMICTL_UNREGISTER_FOR_CMD_CHANS"}, // From linux/ipmi.h
			{Val: 45313, Str: "IPMI_BMC_IOCTL_CLEAR_SMS_ATN"}, // From linux/ipmi_bmc.h
			{Val: 45314, Str: "IPMI_BMC_IOCTL_FORCE_ABORT"}, // From linux/ipmi_bmc.h
			{Val: 45312, Str: "IPMI_BMC_IOCTL_SET_SMS_ATN"}, // From linux/ipmi_bmc.h
			{Val: 3221814792, Str: "ISST_IF_CLOS_ASSOC"}, // From linux/isst_if.h
			{Val: 3221814791, Str: "ISST_IF_CLOS_PARAM"}, // From linux/isst_if.h
			{Val: 3221814790, Str: "ISST_IF_CORE_POWER_STATE"}, // From linux/isst_if.h
			{Val: 2148072965, Str: "ISST_IF_COUNT_TPMI_INSTANCES"}, // From linux/isst_if.h
			{Val: 2148072975, Str: "ISST_IF_GET_BASE_FREQ_CPU_MASK"}, // From linux/isst_if.h
			{Val: 2148072974, Str: "ISST_IF_GET_BASE_FREQ_INFO"}, // From linux/isst_if.h
			{Val: 2148072973, Str: "ISST_IF_GET_PERF_LEVEL_CPU_MASK"}, // From linux/isst_if.h
			{Val: 2148072977, Str: "ISST_IF_GET_PERF_LEVEL_FABRIC_INFO"}, // From linux/isst_if.h
			{Val: 2148072972, Str: "ISST_IF_GET_PERF_LEVEL_INFO"}, // From linux/isst_if.h
			{Val: 3221814785, Str: "ISST_IF_GET_PHY_ID"}, // From linux/isst_if.h
			{Val: 2148072960, Str: "ISST_IF_GET_PLATFORM_INFO"}, // From linux/isst_if.h
			{Val: 2148072976, Str: "ISST_IF_GET_TURBO_FREQ_INFO"}, // From linux/isst_if.h
			{Val: 1074331138, Str: "ISST_IF_IO_CMD"}, // From linux/isst_if.h
			{Val: 3221814787, Str: "ISST_IF_MBOX_COMMAND"}, // From linux/isst_if.h
			{Val: 3221814788, Str: "ISST_IF_MSR_COMMAND"}, // From linux/isst_if.h
			{Val: 3221814793, Str: "ISST_IF_PERF_LEVELS"}, // From linux/isst_if.h
			{Val: 1074331147, Str: "ISST_IF_PERF_SET_FEATURE"}, // From linux/isst_if.h
			{Val: 1074331146, Str: "ISST_IF_PERF_SET_LEVEL"}, // From linux/isst_if.h
			{Val: 1077958336, Str: "IVTV_IOC_DMA_FRAME"}, // From linux/ivtv.h
			{Val: 1074026177, Str: "IVTV_IOC_PASSTHROUGH_MODE"}, // From linux/ivtv.h
			{Val: 1075336896, Str: "IVTVFB_IOC_DMA_FRAME"}, // From linux/ivtvfb.h
			{Val: 2147576337, Str: "JSIOCGAXES"}, // From linux/joystick.h
			{Val: 2151705138, Str: "JSIOCGAXMAP"}, // From linux/joystick.h
			{Val: 2214619700, Str: "JSIOCGBTNMAP"}, // From linux/joystick.h
			{Val: 2147576338, Str: "JSIOCGBUTTONS"}, // From linux/joystick.h
			{Val: 2149870114, Str: "JSIOCGCORR"}, // From linux/joystick.h
			{Val: 2147772929, Str: "JSIOCGVERSION"}, // From linux/joystick.h
			{Val: 1077963313, Str: "JSIOCSAXMAP"}, // From linux/joystick.h
			{Val: 1140877875, Str: "JSIOCSBTNMAP"}, // From linux/joystick.h
			{Val: 1076128289, Str: "JSIOCSCORR"}, // From linux/joystick.h
			{Val: 25445, Str: "KCOV_DISABLE"}, // From linux/kcov.h
			{Val: 25444, Str: "KCOV_ENABLE"}, // From linux/kcov.h
			{Val: 2148033281, Str: "KCOV_INIT_TRACE"}, // From linux/kcov.h
			{Val: 1075340134, Str: "KCOV_REMOTE_ENABLE"}, // From linux/kcov.h
			{Val: 19312, Str: "GIO_CMAP"}, // From linux/kd.h
			{Val: 19296, Str: "GIO_FONT"}, // From linux/kd.h
			{Val: 19307, Str: "GIO_FONTX"}, // From linux/kd.h
			{Val: 19264, Str: "GIO_SCRNMAP"}, // From linux/kd.h
			{Val: 19302, Str: "GIO_UNIMAP"}, // From linux/kd.h
			{Val: 19305, Str: "GIO_UNISCRNMAP"}, // From linux/kd.h
			{Val: 19252, Str: "KDADDIO"}, // From linux/kd.h
			{Val: 19253, Str: "KDDELIO"}, // From linux/kd.h
			{Val: 19255, Str: "KDDISABIO"}, // From linux/kd.h
			{Val: 19254, Str: "KDENABIO"}, // From linux/kd.h
			{Val: 19314, Str: "KDFONTOP"}, // From linux/kd.h
			{Val: 19276, Str: "KDGETKEYCODE"}, // From linux/kd.h
			{Val: 19249, Str: "KDGETLED"}, // From linux/kd.h
			{Val: 19259, Str: "KDGETMODE"}, // From linux/kd.h
			{Val: 19274, Str: "KDGKBDIACR"}, // From linux/kd.h
			{Val: 19450, Str: "KDGKBDIACRUC"}, // From linux/kd.h
			{Val: 19270, Str: "KDGKBENT"}, // From linux/kd.h
			{Val: 19300, Str: "KDGKBLED"}, // From linux/kd.h
			{Val: 19298, Str: "KDGKBMETA"}, // From linux/kd.h
			{Val: 19268, Str: "KDGKBMODE"}, // From linux/kd.h
			{Val: 19272, Str: "KDGKBSENT"}, // From linux/kd.h
			{Val: 19251, Str: "KDGKBTYPE"}, // From linux/kd.h
			{Val: 19282, Str: "KDKBDREP"}, // From linux/kd.h
			{Val: 19260, Str: "KDMAPDISP"}, // From linux/kd.h
			{Val: 19248, Str: "KDMKTONE"}, // From linux/kd.h
			{Val: 19277, Str: "KDSETKEYCODE"}, // From linux/kd.h
			{Val: 19250, Str: "KDSETLED"}, // From linux/kd.h
			{Val: 19258, Str: "KDSETMODE"}, // From linux/kd.h
			{Val: 19278, Str: "KDSIGACCEPT"}, // From linux/kd.h
			{Val: 19275, Str: "KDSKBDIACR"}, // From linux/kd.h
			{Val: 19451, Str: "KDSKBDIACRUC"}, // From linux/kd.h
			{Val: 19271, Str: "KDSKBENT"}, // From linux/kd.h
			{Val: 19301, Str: "KDSKBLED"}, // From linux/kd.h
			{Val: 19299, Str: "KDSKBMETA"}, // From linux/kd.h
			{Val: 19269, Str: "KDSKBMODE"}, // From linux/kd.h
			{Val: 19273, Str: "KDSKBSENT"}, // From linux/kd.h
			{Val: 19261, Str: "KDUNMAPDISP"}, // From linux/kd.h
			{Val: 19247, Str: "KIOCSOUND"}, // From linux/kd.h
			{Val: 19313, Str: "PIO_CMAP"}, // From linux/kd.h
			{Val: 19297, Str: "PIO_FONT"}, // From linux/kd.h
			{Val: 19309, Str: "PIO_FONTRESET"}, // From linux/kd.h
			{Val: 19308, Str: "PIO_FONTX"}, // From linux/kd.h
			{Val: 19265, Str: "PIO_SCRNMAP"}, // From linux/kd.h
			{Val: 19303, Str: "PIO_UNIMAP"}, // From linux/kd.h
			{Val: 19304, Str: "PIO_UNIMAPCLR"}, // From linux/kd.h
			{Val: 19306, Str: "PIO_UNISCRNMAP"}, // From linux/kd.h
			{Val: 1074285333, Str: "AMDKFD_IOC_ACQUIRE_VM"}, // From linux/kfd_ioctl.h
			{Val: 3223866134, Str: "AMDKFD_IOC_ALLOC_MEMORY_OF_GPU"}, // From linux/kfd_ioctl.h
			{Val: 3222293278, Str: "AMDKFD_IOC_ALLOC_QUEUE_GWS"}, // From linux/kfd_ioctl.h
			{Val: 3222293283, Str: "AMDKFD_IOC_AVAILABLE_MEMORY"}, // From linux/kfd_ioctl.h
			{Val: 3223341832, Str: "AMDKFD_IOC_CREATE_EVENT"}, // From linux/kfd_ioctl.h
			{Val: 19239, Str: "AMDKFD_IOC_CREATE_PROCESS"}, // From linux/kfd_ioctl.h
			{Val: 3227536130, Str: "AMDKFD_IOC_CREATE_QUEUE"}, // From linux/kfd_ioctl.h
			{Val: 3224914722, Str: "AMDKFD_IOC_CRIU_OP"}, // From linux/kfd_ioctl.h
			{Val: 1074809615, Str: "AMDKFD_IOC_DBG_ADDRESS_WATCH_DEPRECATED"}, // From linux/kfd_ioctl.h
			{Val: 1074285325, Str: "AMDKFD_IOC_DBG_REGISTER_DEPRECATED"}, // From linux/kfd_ioctl.h
			{Val: 3223341862, Str: "AMDKFD_IOC_DBG_TRAP"}, // From linux/kfd_ioctl.h
			{Val: 1074285326, Str: "AMDKFD_IOC_DBG_UNREGISTER_DEPRECATED"}, // From linux/kfd_ioctl.h
			{Val: 1074809616, Str: "AMDKFD_IOC_DBG_WAVE_CONTROL_DEPRECATED"}, // From linux/kfd_ioctl.h
			{Val: 1074285321, Str: "AMDKFD_IOC_DESTROY_EVENT"}, // From linux/kfd_ioctl.h
			{Val: 3221768963, Str: "AMDKFD_IOC_DESTROY_QUEUE"}, // From linux/kfd_ioctl.h
			{Val: 3222293284, Str: "AMDKFD_IOC_EXPORT_DMABUF"}, // From linux/kfd_ioctl.h
			{Val: 1074285335, Str: "AMDKFD_IOC_FREE_MEMORY_OF_GPU"}, // From linux/kfd_ioctl.h
			{Val: 3223866117, Str: "AMDKFD_IOC_GET_CLOCK_COUNTERS"}, // From linux/kfd_ioctl.h
			{Val: 3223341852, Str: "AMDKFD_IOC_GET_DMABUF_INFO"}, // From linux/kfd_ioctl.h
			{Val: 2173717254, Str: "AMDKFD_IOC_GET_PROCESS_APERTURES"}, // From linux/kfd_ioctl.h
			{Val: 3222293268, Str: "AMDKFD_IOC_GET_PROCESS_APERTURES_NEW"}, // From linux/kfd_ioctl.h
			{Val: 3222817563, Str: "AMDKFD_IOC_GET_QUEUE_WAVE_STATE"}, // From linux/kfd_ioctl.h
			{Val: 3223866130, Str: "AMDKFD_IOC_GET_TILE_CONFIG"}, // From linux/kfd_ioctl.h
			{Val: 2148027137, Str: "AMDKFD_IOC_GET_VERSION"}, // From linux/kfd_ioctl.h
			{Val: 3222817565, Str: "AMDKFD_IOC_IMPORT_DMABUF"}, // From linux/kfd_ioctl.h
			{Val: 3222817560, Str: "AMDKFD_IOC_MAP_MEMORY_TO_GPU"}, // From linux/kfd_ioctl.h
			{Val: 1074285323, Str: "AMDKFD_IOC_RESET_EVENT"}, // From linux/kfd_ioctl.h
			{Val: 3222293285, Str: "AMDKFD_IOC_RUNTIME_ENABLE"}, // From linux/kfd_ioctl.h
			{Val: 1074809626, Str: "AMDKFD_IOC_SET_CU_MASK"}, // From linux/kfd_ioctl.h
			{Val: 1074285322, Str: "AMDKFD_IOC_SET_EVENT"}, // From linux/kfd_ioctl.h
			{Val: 1075858180, Str: "AMDKFD_IOC_SET_MEMORY_POLICY"}, // From linux/kfd_ioctl.h
			{Val: 3222293265, Str: "AMDKFD_IOC_SET_SCRATCH_BACKING_VA"}, // From linux/kfd_ioctl.h
			{Val: 1075333907, Str: "AMDKFD_IOC_SET_TRAP_HANDLER"}, // From linux/kfd_ioctl.h
			{Val: 3221506849, Str: "AMDKFD_IOC_SET_XNACK_MODE"}, // From linux/kfd_ioctl.h
			{Val: 3221768991, Str: "AMDKFD_IOC_SMI_EVENTS"}, // From linux/kfd_ioctl.h
			{Val: 3222817568, Str: "AMDKFD_IOC_SVM"}, // From linux/kfd_ioctl.h
			{Val: 3222817561, Str: "AMDKFD_IOC_UNMAP_MEMORY_FROM_GPU"}, // From linux/kfd_ioctl.h
			{Val: 1075333895, Str: "AMDKFD_IOC_UPDATE_QUEUE"}, // From linux/kfd_ioctl.h
			{Val: 3222817548, Str: "AMDKFD_IOC_WAIT_EVENTS"}, // From linux/kfd_ioctl.h
			{Val: 2147772672, Str: "LIRC_GET_FEATURES"}, // From linux/lirc.h
			{Val: 2147772687, Str: "LIRC_GET_LENGTH"}, // From linux/lirc.h
			{Val: 2147772681, Str: "LIRC_GET_MAX_TIMEOUT"}, // From linux/lirc.h
			{Val: 2147772680, Str: "LIRC_GET_MIN_TIMEOUT"}, // From linux/lirc.h
			{Val: 2147772674, Str: "LIRC_GET_REC_MODE"}, // From linux/lirc.h
			{Val: 2147772679, Str: "LIRC_GET_REC_RESOLUTION"}, // From linux/lirc.h
			{Val: 2147772708, Str: "LIRC_GET_REC_TIMEOUT"}, // From linux/lirc.h
			{Val: 2147772673, Str: "LIRC_GET_SEND_MODE"}, // From linux/lirc.h
			{Val: 1074030877, Str: "LIRC_SET_MEASURE_CARRIER_MODE"}, // From linux/lirc.h
			{Val: 1074030868, Str: "LIRC_SET_REC_CARRIER"}, // From linux/lirc.h
			{Val: 1074030879, Str: "LIRC_SET_REC_CARRIER_RANGE"}, // From linux/lirc.h
			{Val: 1074030866, Str: "LIRC_SET_REC_MODE"}, // From linux/lirc.h
			{Val: 1074030872, Str: "LIRC_SET_REC_TIMEOUT"}, // From linux/lirc.h
			{Val: 1074030873, Str: "LIRC_SET_REC_TIMEOUT_REPORTS"}, // From linux/lirc.h
			{Val: 1074030867, Str: "LIRC_SET_SEND_CARRIER"}, // From linux/lirc.h
			{Val: 1074030869, Str: "LIRC_SET_SEND_DUTY_CYCLE"}, // From linux/lirc.h
			{Val: 1074030865, Str: "LIRC_SET_SEND_MODE"}, // From linux/lirc.h
			{Val: 1074030871, Str: "LIRC_SET_TRANSMITTER_MASK"}, // From linux/lirc.h
			{Val: 1074030883, Str: "LIRC_SET_WIDEBAND_RECEIVER"}, // From linux/lirc.h
			{Val: 47616, Str: "LIVEUPDATE_IOCTL_CREATE_SESSION"}, // From linux/liveupdate.h
			{Val: 47617, Str: "LIVEUPDATE_IOCTL_RETRIEVE_SESSION"}, // From linux/liveupdate.h
			{Val: 47682, Str: "LIVEUPDATE_SESSION_FINISH"}, // From linux/liveupdate.h
			{Val: 47680, Str: "LIVEUPDATE_SESSION_PRESERVE_FD"}, // From linux/liveupdate.h
			{Val: 47681, Str: "LIVEUPDATE_SESSION_RETRIEVE_FD"}, // From linux/liveupdate.h
			{Val: 1074023424, Str: "LOADPIN_IOC_SET_TRUSTED_VERITY_DIGESTS"}, // From linux/loadpin.h
			{Val: 19462, Str: "LOOP_CHANGE_FD"}, // From linux/loop.h
			{Val: 19457, Str: "LOOP_CLR_FD"}, // From linux/loop.h
			{Val: 19466, Str: "LOOP_CONFIGURE"}, // From linux/loop.h
			{Val: 19584, Str: "LOOP_CTL_ADD"}, // From linux/loop.h
			{Val: 19586, Str: "LOOP_CTL_GET_FREE"}, // From linux/loop.h
			{Val: 19585, Str: "LOOP_CTL_REMOVE"}, // From linux/loop.h
			{Val: 19459, Str: "LOOP_GET_STATUS"}, // From linux/loop.h
			{Val: 19461, Str: "LOOP_GET_STATUS64"}, // From linux/loop.h
			{Val: 19465, Str: "LOOP_SET_BLOCK_SIZE"}, // From linux/loop.h
			{Val: 19463, Str: "LOOP_SET_CAPACITY"}, // From linux/loop.h
			{Val: 19464, Str: "LOOP_SET_DIRECT_IO"}, // From linux/loop.h
			{Val: 19456, Str: "LOOP_SET_FD"}, // From linux/loop.h
			{Val: 19458, Str: "LOOP_SET_STATUS"}, // From linux/loop.h
			{Val: 19460, Str: "LOOP_SET_STATUS64"}, // From linux/loop.h
			{Val: 1074791951, Str: "LPSETTIMEOUT_NEW"}, // From linux/lp.h
			{Val: 2147764544, Str: "IMADDTIMER"}, // From linux/mISDNif.h
			{Val: 2147764550, Str: "IMCLEAR_L2"}, // From linux/mISDNif.h
			{Val: 2147764549, Str: "IMCTRLREQ"}, // From linux/mISDNif.h
			{Val: 2147764545, Str: "IMDELTIMER"}, // From linux/mISDNif.h
			{Val: 2147764547, Str: "IMGETCOUNT"}, // From linux/mISDNif.h
			{Val: 2147764548, Str: "IMGETDEVINFO"}, // From linux/mISDNif.h
			{Val: 2147764546, Str: "IMGETVERSION"}, // From linux/mISDNif.h
			{Val: 2147764552, Str: "IMHOLD_L1"}, // From linux/mISDNif.h
			{Val: 2149075271, Str: "IMSETDEVNAME"}, // From linux/mISDNif.h
			{Val: 3230163969, Str: "DMA_MAP_BENCHMARK"}, // From linux/map_benchmark.h
			{Val: 2148036347, Str: "MATROXFB_GET_ALL_OUTPUTS"}, // From linux/matroxfb.h
			{Val: 2148036345, Str: "MATROXFB_GET_AVAILABLE_OUTPUTS"}, // From linux/matroxfb.h
			{Val: 2148036344, Str: "MATROXFB_GET_OUTPUT_CONNECTION"}, // From linux/matroxfb.h
			{Val: 3221778170, Str: "MATROXFB_GET_OUTPUT_MODE"}, // From linux/matroxfb.h
			{Val: 1074294520, Str: "MATROXFB_SET_OUTPUT_CONNECTION"}, // From linux/matroxfb.h
			{Val: 1074294522, Str: "MATROXFB_SET_OUTPUT_MODE"}, // From linux/matroxfb.h
			{Val: 3238034432, Str: "MEDIA_IOC_DEVICE_INFO"}, // From linux/media.h
			{Val: 3238034433, Str: "MEDIA_IOC_ENUM_ENTITIES"}, // From linux/media.h
			{Val: 3223878658, Str: "MEDIA_IOC_ENUM_LINKS"}, // From linux/media.h
			{Val: 3225975812, Str: "MEDIA_IOC_G_TOPOLOGY"}, // From linux/media.h
			{Val: 2147777541, Str: "MEDIA_IOC_REQUEST_ALLOC"}, // From linux/media.h
			{Val: 3224665091, Str: "MEDIA_IOC_SETUP_LINK"}, // From linux/media.h
			{Val: 31872, Str: "MEDIA_REQUEST_IOC_QUEUE"}, // From linux/media.h
			{Val: 31873, Str: "MEDIA_REQUEST_IOC_REINIT"}, // From linux/media.h
			{Val: 3222292481, Str: "IOCTL_MEI_CONNECT_CLIENT"}, // From linux/mei.h
			{Val: 3222554628, Str: "IOCTL_MEI_CONNECT_CLIENT_VTAG"}, // From linux/mei.h
			{Val: 2147764227, Str: "IOCTL_MEI_NOTIFY_GET"}, // From linux/mei.h
			{Val: 1074022402, Str: "IOCTL_MEI_NOTIFY_SET"}, // From linux/mei.h
			{Val: 1078222338, Str: "VK_IOCTL_LOAD_IMAGE"}, // From linux/misc/bcm_vk.h
			{Val: 1074290180, Str: "VK_IOCTL_RESET"}, // From linux/misc/bcm_vk.h
			{Val: 3225989888, Str: "MMC_IOC_CMD"}, // From linux/mmc/ioctl.h
			{Val: 3221795585, Str: "MMC_IOC_MULTI_CMD"}, // From linux/mmc/ioctl.h
			{Val: 27908, Str: "MMTIMER_GETBITS"}, // From linux/mmtimer.h
			{Val: 2148035849, Str: "MMTIMER_GETCOUNTER"}, // From linux/mmtimer.h
			{Val: 2148035842, Str: "MMTIMER_GETFREQ"}, // From linux/mmtimer.h
			{Val: 27904, Str: "MMTIMER_GETOFFSET"}, // From linux/mmtimer.h
			{Val: 2148035841, Str: "MMTIMER_GETRES"}, // From linux/mmtimer.h
			{Val: 27910, Str: "MMTIMER_MMAPAVAIL"}, // From linux/mmtimer.h
			{Val: 2147774992, Str: "FAT_IOCTL_GET_ATTRIBUTES"}, // From linux/msdos_fs.h
			{Val: 2147774995, Str: "FAT_IOCTL_GET_VOLUME_ID"}, // From linux/msdos_fs.h
			{Val: 1074033169, Str: "FAT_IOCTL_SET_ATTRIBUTES"}, // From linux/msdos_fs.h
			{Val: 2184212993, Str: "VFAT_IOCTL_READDIR_BOTH"}, // From linux/msdos_fs.h
			{Val: 2184212994, Str: "VFAT_IOCTL_READDIR_SHORT"}, // From linux/msdos_fs.h
			{Val: 1074837537, Str: "MSHV_ADD_VTL0_MEMORY"}, // From linux/mshv.h
			{Val: 1074051072, Str: "MSHV_CHECK_EXTENSION"}, // From linux/mshv.h
			{Val: 1074837504, Str: "MSHV_CREATE_PARTITION"}, // From linux/mshv.h
			{Val: 1074051073, Str: "MSHV_CREATE_VP"}, // From linux/mshv.h
			{Val: 2147596317, Str: "MSHV_CREATE_VTL"}, // From linux/mshv.h
			{Val: 3223369734, Str: "MSHV_GET_GPAP_ACCESS_BITMAP"}, // From linux/mshv.h
			{Val: 3222321157, Str: "MSHV_GET_VP_REGISTERS"}, // From linux/mshv.h
			{Val: 3222321153, Str: "MSHV_GET_VP_STATE"}, // From linux/mshv.h
			{Val: 3224418335, Str: "MSHV_HVCALL"}, // From linux/mshv.h
			{Val: 1074837534, Str: "MSHV_HVCALL_SETUP"}, // From linux/mshv.h
			{Val: 47104, Str: "MSHV_INITIALIZE_PARTITION"}, // From linux/mshv.h
			{Val: 1075886084, Str: "MSHV_IOEVENTFD"}, // From linux/mshv.h
			{Val: 1074837507, Str: "MSHV_IRQFD"}, // From linux/mshv.h
			{Val: 47143, Str: "MSHV_RETURN_TO_LOWER_VTL"}, // From linux/mshv.h
			{Val: 3223369735, Str: "MSHV_ROOT_HVCALL"}, // From linux/mshv.h
			{Val: 2164307968, Str: "MSHV_RUN_VP"}, // From linux/mshv.h
			{Val: 1075886082, Str: "MSHV_SET_GUEST_MEMORY"}, // From linux/mshv.h
			{Val: 1074313221, Str: "MSHV_SET_MSI_ROUTING"}, // From linux/mshv.h
			{Val: 1074313253, Str: "MSHV_SET_POLL_FILE"}, // From linux/mshv.h
			{Val: 1074837510, Str: "MSHV_SET_VP_REGISTERS"}, // From linux/mshv.h
			{Val: 3222321154, Str: "MSHV_SET_VP_STATE"}, // From linux/mshv.h
			{Val: 1074313253, Str: "MSHV_SINT_PAUSE_MESSAGE_STREAM"}, // From linux/mshv.h
			{Val: 1075361827, Str: "MSHV_SINT_POST_MESSAGE"}, // From linux/mshv.h
			{Val: 1074313252, Str: "MSHV_SINT_SET_EVENTFD"}, // From linux/mshv.h
			{Val: 1074313250, Str: "MSHV_SINT_SIGNAL_EVENT"}, // From linux/mshv.h
			{Val: 2150657282, Str: "MTIOCGET"}, // From linux/mtio.h
			{Val: 2148035843, Str: "MTIOCPOS"}, // From linux/mtio.h
			{Val: 1074294017, Str: "MTIOCTOP"}, // From linux/mtio.h
			{Val: 43781, Str: "NBD_CLEAR_QUE"}, // From linux/nbd.h
			{Val: 43780, Str: "NBD_CLEAR_SOCK"}, // From linux/nbd.h
			{Val: 43784, Str: "NBD_DISCONNECT"}, // From linux/nbd.h
			{Val: 43779, Str: "NBD_DO_IT"}, // From linux/nbd.h
			{Val: 43782, Str: "NBD_PRINT_DEBUG"}, // From linux/nbd.h
			{Val: 43777, Str: "NBD_SET_BLKSIZE"}, // From linux/nbd.h
			{Val: 43786, Str: "NBD_SET_FLAGS"}, // From linux/nbd.h
			{Val: 43778, Str: "NBD_SET_SIZE"}, // From linux/nbd.h
			{Val: 43783, Str: "NBD_SET_SIZE_BLOCKS"}, // From linux/nbd.h
			{Val: 43776, Str: "NBD_SET_SOCK"}, // From linux/nbd.h
			{Val: 43785, Str: "NBD_SET_TIMEOUT"}, // From linux/nbd.h
			{Val: 3223342593, Str: "ND_IOCTL_ARS_CAP"}, // From linux/ndctl.h
			{Val: 3223342594, Str: "ND_IOCTL_ARS_START"}, // From linux/ndctl.h
			{Val: 3224391171, Str: "ND_IOCTL_ARS_STATUS"}, // From linux/ndctl.h
			{Val: 3225439754, Str: "ND_IOCTL_CALL"}, // From linux/ndctl.h
			{Val: 3223342596, Str: "ND_IOCTL_CLEAR_ERROR"}, // From linux/ndctl.h
			{Val: 3221769731, Str: "ND_IOCTL_DIMM_FLAGS"}, // From linux/ndctl.h
			{Val: 3222031877, Str: "ND_IOCTL_GET_CONFIG_DATA"}, // From linux/ndctl.h
			{Val: 3222031876, Str: "ND_IOCTL_GET_CONFIG_SIZE"}, // From linux/ndctl.h
			{Val: 3221769734, Str: "ND_IOCTL_SET_CONFIG_DATA"}, // From linux/ndctl.h
			{Val: 3221769737, Str: "ND_IOCTL_VENDOR"}, // From linux/ndctl.h
			{Val: 1074818688, Str: "NILFS_IOCTL_CHANGE_CPMODE"}, // From linux/nilfs2_api.h
			{Val: 1081634440, Str: "NILFS_IOCTL_CLEAN_SEGMENTS"}, // From linux/nilfs2_api.h
			{Val: 1074294401, Str: "NILFS_IOCTL_DELETE_CHECKPOINT"}, // From linux/nilfs2_api.h
			{Val: 3222826631, Str: "NILFS_IOCTL_GET_BDESCS"}, // From linux/nilfs2_api.h
			{Val: 2149084802, Str: "NILFS_IOCTL_GET_CPINFO"}, // From linux/nilfs2_api.h
			{Val: 2149084803, Str: "NILFS_IOCTL_GET_CPSTAT"}, // From linux/nilfs2_api.h
			{Val: 2149084804, Str: "NILFS_IOCTL_GET_SUINFO"}, // From linux/nilfs2_api.h
			{Val: 2150657669, Str: "NILFS_IOCTL_GET_SUSTAT"}, // From linux/nilfs2_api.h
			{Val: 3222826630, Str: "NILFS_IOCTL_GET_VINFO"}, // From linux/nilfs2_api.h
			{Val: 1074294411, Str: "NILFS_IOCTL_RESIZE"}, // From linux/nilfs2_api.h
			{Val: 1074818700, Str: "NILFS_IOCTL_SET_ALLOC_RANGE"}, // From linux/nilfs2_api.h
			{Val: 1075342989, Str: "NILFS_IOCTL_SET_SUINFO"}, // From linux/nilfs2_api.h
			{Val: 2148036234, Str: "NILFS_IOCTL_SYNC"}, // From linux/nilfs2_api.h
			{Val: 3221532193, Str: "NE_ADD_VCPU"}, // From linux/nitro_enclaves.h
			{Val: 2148052512, Str: "NE_CREATE_VM"}, // From linux/nitro_enclaves.h
			{Val: 3222318626, Str: "NE_GET_IMAGE_LOAD_INFO"}, // From linux/nitro_enclaves.h
			{Val: 1075359267, Str: "NE_SET_USER_MEMORY_REGION"}, // From linux/nitro_enclaves.h
			{Val: 3222318628, Str: "NE_START_ENCLAVE"}, // From linux/nitro_enclaves.h
			{Val: 2148054797, Str: "NS_GET_ID"}, // From linux/nsfs.h
			{Val: 2148054789, Str: "NS_GET_MNTNS_ID"}, // From linux/nsfs.h
			{Val: 46851, Str: "NS_GET_NSTYPE"}, // From linux/nsfs.h
			{Val: 46852, Str: "NS_GET_OWNER_UID"}, // From linux/nsfs.h
			{Val: 46850, Str: "NS_GET_PARENT"}, // From linux/nsfs.h
			{Val: 2147792646, Str: "NS_GET_PID_FROM_PIDNS"}, // From linux/nsfs.h
			{Val: 2147792648, Str: "NS_GET_PID_IN_PIDNS"}, // From linux/nsfs.h
			{Val: 2147792647, Str: "NS_GET_TGID_FROM_PIDNS"}, // From linux/nsfs.h
			{Val: 2147792649, Str: "NS_GET_TGID_IN_PIDNS"}, // From linux/nsfs.h
			{Val: 46849, Str: "NS_GET_USERNS"}, // From linux/nsfs.h
			{Val: 2148579082, Str: "NS_MNT_GET_INFO"}, // From linux/nsfs.h
			{Val: 2148579083, Str: "NS_MNT_GET_NEXT"}, // From linux/nsfs.h
			{Val: 2148579084, Str: "NS_MNT_GET_PREV"}, // From linux/nsfs.h
			{Val: 3223325184, Str: "NSM_IOCTL_RAW"}, // From linux/nsm.h
			{Val: 1074286215, Str: "NTSYNC_IOC_CREATE_EVENT"}, // From linux/ntsync.h
			{Val: 1074286212, Str: "NTSYNC_IOC_CREATE_MUTEX"}, // From linux/ntsync.h
			{Val: 1074286208, Str: "NTSYNC_IOC_CREATE_SEM"}, // From linux/ntsync.h
			{Val: 2147765898, Str: "NTSYNC_IOC_EVENT_PULSE"}, // From linux/ntsync.h
			{Val: 2148028045, Str: "NTSYNC_IOC_EVENT_READ"}, // From linux/ntsync.h
			{Val: 2147765897, Str: "NTSYNC_IOC_EVENT_RESET"}, // From linux/ntsync.h
			{Val: 2147765896, Str: "NTSYNC_IOC_EVENT_SET"}, // From linux/ntsync.h
			{Val: 1074024070, Str: "NTSYNC_IOC_MUTEX_KILL"}, // From linux/ntsync.h
			{Val: 2148028044, Str: "NTSYNC_IOC_MUTEX_READ"}, // From linux/ntsync.h
			{Val: 3221769861, Str: "NTSYNC_IOC_MUTEX_UNLOCK"}, // From linux/ntsync.h
			{Val: 2148028043, Str: "NTSYNC_IOC_SEM_READ"}, // From linux/ntsync.h
			{Val: 3221507713, Str: "NTSYNC_IOC_SEM_RELEASE"}, // From linux/ntsync.h
			{Val: 3223867011, Str: "NTSYNC_IOC_WAIT_ALL"}, // From linux/ntsync.h
			{Val: 3223867010, Str: "NTSYNC_IOC_WAIT_ANY"}, // From linux/ntsync.h
			{Val: 3226488391, Str: "NVME_IOCTL_ADMIN64_CMD"}, // From linux/nvme_ioctl.h
			{Val: 3225964097, Str: "NVME_IOCTL_ADMIN_CMD"}, // From linux/nvme_ioctl.h
			{Val: 20032, Str: "NVME_IOCTL_ID"}, // From linux/nvme_ioctl.h
			{Val: 3226488392, Str: "NVME_IOCTL_IO64_CMD"}, // From linux/nvme_ioctl.h
			{Val: 3226488393, Str: "NVME_IOCTL_IO64_CMD_VEC"}, // From linux/nvme_ioctl.h
			{Val: 3225964099, Str: "NVME_IOCTL_IO_CMD"}, // From linux/nvme_ioctl.h
			{Val: 20038, Str: "NVME_IOCTL_RESCAN"}, // From linux/nvme_ioctl.h
			{Val: 20036, Str: "NVME_IOCTL_RESET"}, // From linux/nvme_ioctl.h
			{Val: 1076907586, Str: "NVME_IOCTL_SUBMIT_IO"}, // From linux/nvme_ioctl.h
			{Val: 20037, Str: "NVME_IOCTL_SUBSYS_RESET"}, // From linux/nvme_ioctl.h
			{Val: 3225964162, Str: "NVME_URING_CMD_ADMIN"}, // From linux/nvme_ioctl.h
			{Val: 3225964163, Str: "NVME_URING_CMD_ADMIN_VEC"}, // From linux/nvme_ioctl.h
			{Val: 3225964160, Str: "NVME_URING_CMD_IO"}, // From linux/nvme_ioctl.h
			{Val: 3225964161, Str: "NVME_URING_CMD_IO_VEC"}, // From linux/nvme_ioctl.h
			{Val: 28736, Str: "NVRAM_INIT"}, // From linux/nvram.h
			{Val: 28737, Str: "NVRAM_SETCKS"}, // From linux/nvram.h
			{Val: 3223344835, Str: "VIDIOC_OMAP3ISP_AEWB_CFG"}, // From linux/omap3isp.h
			{Val: 3226228421, Str: "VIDIOC_OMAP3ISP_AF_CFG"}, // From linux/omap3isp.h
			{Val: 3224917697, Str: "VIDIOC_OMAP3ISP_CCDC_CFG"}, // From linux/omap3isp.h
			{Val: 3224393412, Str: "VIDIOC_OMAP3ISP_HIST_CFG"}, // From linux/omap3isp.h
			{Val: 3228587714, Str: "VIDIOC_OMAP3ISP_PRV_CFG"}, // From linux/omap3isp.h
			{Val: 3221771975, Str: "VIDIOC_OMAP3ISP_STAT_EN"}, // From linux/omap3isp.h
			{Val: 3223869126, Str: "VIDIOC_OMAP3ISP_STAT_REQ"}, // From linux/omap3isp.h
			{Val: 3222820550, Str: "VIDIOC_OMAP3ISP_STAT_REQ_TIME32"}, // From linux/omap3isp.h
			{Val: 1074024238, Str: "OMAPFB_CTRL_TEST"}, // From linux/omapfb.h
			{Val: 2148290346, Str: "OMAPFB_GET_CAPS"}, // From linux/omapfb.h
			{Val: 1074810675, Str: "OMAPFB_GET_COLOR_KEY"}, // From linux/omapfb.h
			{Val: 2149601087, Str: "OMAPFB_GET_DISPLAY_INFO"}, // From linux/omapfb.h
			{Val: 2151436091, Str: "OMAPFB_GET_OVERLAY_COLORMODE"}, // From linux/omapfb.h
			{Val: 1074024235, Str: "OMAPFB_GET_UPDATE_MODE"}, // From linux/omapfb.h
			{Val: 2149601085, Str: "OMAPFB_GET_VRAM_INFO"}, // From linux/omapfb.h
			{Val: 1074024237, Str: "OMAPFB_LCD_TEST"}, // From linux/omapfb.h
			{Val: 2149076794, Str: "OMAPFB_MEMORY_READ"}, // From linux/omapfb.h
			{Val: 1074024223, Str: "OMAPFB_MIRROR"}, // From linux/omapfb.h
			{Val: 1074286392, Str: "OMAPFB_QUERY_MEM"}, // From linux/omapfb.h
			{Val: 1078218549, Str: "OMAPFB_QUERY_PLANE"}, // From linux/omapfb.h
			{Val: 1074286391, Str: "OMAPFB_SETUP_MEM"}, // From linux/omapfb.h
			{Val: 1078218548, Str: "OMAPFB_SETUP_PLANE"}, // From linux/omapfb.h
			{Val: 1074810674, Str: "OMAPFB_SET_COLOR_KEY"}, // From linux/omapfb.h
			{Val: 1074286398, Str: "OMAPFB_SET_TEARSYNC"}, // From linux/omapfb.h
			{Val: 1074024232, Str: "OMAPFB_SET_UPDATE_MODE"}, // From linux/omapfb.h
			{Val: 20261, Str: "OMAPFB_SYNC_GFX"}, // From linux/omapfb.h
			{Val: 1078218550, Str: "OMAPFB_UPDATE_WINDOW"}, // From linux/omapfb.h
			{Val: 1075072815, Str: "OMAPFB_UPDATE_WINDOW_OLD"}, // From linux/omapfb.h
			{Val: 20262, Str: "OMAPFB_VSYNC"}, // From linux/omapfb.h
			{Val: 20284, Str: "OMAPFB_WAITFORGO"}, // From linux/omapfb.h
			{Val: 20281, Str: "OMAPFB_WAITFORVSYNC"}, // From linux/omapfb.h
			{Val: 20481, Str: "PCITEST_BAR"}, // From linux/pcitest.h
			{Val: 20490, Str: "PCITEST_BARS"}, // From linux/pcitest.h
			{Val: 20492, Str: "PCITEST_BAR_SUBRANGE"}, // From linux/pcitest.h
			{Val: 20496, Str: "PCITEST_CLEAR_IRQ"}, // From linux/pcitest.h
			{Val: 1074286598, Str: "PCITEST_COPY"}, // From linux/pcitest.h
			{Val: 20491, Str: "PCITEST_DOORBELL"}, // From linux/pcitest.h
			{Val: 20489, Str: "PCITEST_GET_IRQTYPE"}, // From linux/pcitest.h
			{Val: 20482, Str: "PCITEST_INTX_IRQ"}, // From linux/pcitest.h
			{Val: 1074024451, Str: "PCITEST_MSI"}, // From linux/pcitest.h
			{Val: 1074024455, Str: "PCITEST_MSIX"}, // From linux/pcitest.h
			{Val: 1074286597, Str: "PCITEST_READ"}, // From linux/pcitest.h
			{Val: 1074024456, Str: "PCITEST_SET_IRQTYPE"}, // From linux/pcitest.h
			{Val: 1074286596, Str: "PCITEST_WRITE"}, // From linux/pcitest.h
			{Val: 9217, Str: "PERF_EVENT_IOC_DISABLE"}, // From linux/perf_event.h
			{Val: 9216, Str: "PERF_EVENT_IOC_ENABLE"}, // From linux/perf_event.h
			{Val: 2148017159, Str: "PERF_EVENT_IOC_ID"}, // From linux/perf_event.h
			{Val: 1074275339, Str: "PERF_EVENT_IOC_MODIFY_ATTRIBUTES"}, // From linux/perf_event.h
			{Val: 1074013193, Str: "PERF_EVENT_IOC_PAUSE_OUTPUT"}, // From linux/perf_event.h
			{Val: 1074275332, Str: "PERF_EVENT_IOC_PERIOD"}, // From linux/perf_event.h
			{Val: 3221758986, Str: "PERF_EVENT_IOC_QUERY_BPF"}, // From linux/perf_event.h
			{Val: 9218, Str: "PERF_EVENT_IOC_REFRESH"}, // From linux/perf_event.h
			{Val: 9219, Str: "PERF_EVENT_IOC_RESET"}, // From linux/perf_event.h
			{Val: 1074013192, Str: "PERF_EVENT_IOC_SET_BPF"}, // From linux/perf_event.h
			{Val: 1074275334, Str: "PERF_EVENT_IOC_SET_FILTER"}, // From linux/perf_event.h
			{Val: 9221, Str: "PERF_EVENT_IOC_SET_OUTPUT"}, // From linux/perf_event.h
			{Val: 2151738888, Str: "PFRT_LOG_IOC_GET_DATA_INFO"}, // From linux/pfrut.h
			{Val: 2148331015, Str: "PFRT_LOG_IOC_GET_INFO"}, // From linux/pfrut.h
			{Val: 1074589190, Str: "PFRT_LOG_IOC_SET_INFO"}, // From linux/pfrut.h
			{Val: 1074064899, Str: "PFRU_IOC_ACTIVATE"}, // From linux/pfrut.h
			{Val: 2153573893, Str: "PFRU_IOC_QUERY_CAP"}, // From linux/pfrut.h
			{Val: 1074064897, Str: "PFRU_IOC_SET_REV"}, // From linux/pfrut.h
			{Val: 1074064898, Str: "PFRU_IOC_STAGE"}, // From linux/pfrut.h
			{Val: 1074064900, Str: "PFRU_IOC_STAGE_ACTIVATE"}, // From linux/pfrut.h
			{Val: 3221778437, Str: "PHN_GETREG"}, // From linux/phantom.h
			{Val: 3223875591, Str: "PHN_GETREGS"}, // From linux/phantom.h
			{Val: 3221778432, Str: "PHN_GET_REG"}, // From linux/phantom.h
			{Val: 3221778434, Str: "PHN_GET_REGS"}, // From linux/phantom.h
			{Val: 28676, Str: "PHN_NOT_OH"}, // From linux/phantom.h
			{Val: 1074294790, Str: "PHN_SETREG"}, // From linux/phantom.h
			{Val: 1076391944, Str: "PHN_SETREGS"}, // From linux/phantom.h
			{Val: 1074294785, Str: "PHN_SET_REG"}, // From linux/phantom.h
			{Val: 1074294787, Str: "PHN_SET_REGS"}, // From linux/phantom.h
			{Val: 65281, Str: "PIDFD_GET_CGROUP_NAMESPACE"}, // From linux/pidfd.h
			{Val: 3227057931, Str: "PIDFD_GET_INFO"}, // From linux/pidfd.h
			{Val: 65282, Str: "PIDFD_GET_IPC_NAMESPACE"}, // From linux/pidfd.h
			{Val: 65283, Str: "PIDFD_GET_MNT_NAMESPACE"}, // From linux/pidfd.h
			{Val: 65284, Str: "PIDFD_GET_NET_NAMESPACE"}, // From linux/pidfd.h
			{Val: 65286, Str: "PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE"}, // From linux/pidfd.h
			{Val: 65285, Str: "PIDFD_GET_PID_NAMESPACE"}, // From linux/pidfd.h
			{Val: 65288, Str: "PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE"}, // From linux/pidfd.h
			{Val: 65287, Str: "PIDFD_GET_TIME_NAMESPACE"}, // From linux/pidfd.h
			{Val: 65289, Str: "PIDFD_GET_USER_NAMESPACE"}, // From linux/pidfd.h
			{Val: 65290, Str: "PIDFD_GET_UTS_NAMESPACE"}, // From linux/pidfd.h
			{Val: 3222820865, Str: "PACKET_CTRL_CMD"}, // From linux/pktcdvd.h
			{Val: 60418, Str: "CROS_EC_DEV_IOCEVENTMASK"}, // From linux/platform_data/cros_ec_chardev.h
			{Val: 3238587393, Str: "CROS_EC_DEV_IOCRDMEM"}, // From linux/platform_data/cros_ec_chardev.h
			{Val: 3222596608, Str: "CROS_EC_DEV_IOCXCMD"}, // From linux/platform_data/cros_ec_chardev.h
			{Val: 3223082688, Str: "SI4713_IOC_MEASURE_RNL"}, // From linux/platform_data/media/si4713.h
			{Val: 2148024837, Str: "PMU_IOC_CAN_SLEEP"}, // From linux/pmu.h
			{Val: 2148024833, Str: "PMU_IOC_GET_BACKLIGHT"}, // From linux/pmu.h
			{Val: 2148024835, Str: "PMU_IOC_GET_MODEL"}, // From linux/pmu.h
			{Val: 2148024838, Str: "PMU_IOC_GRAB_BACKLIGHT"}, // From linux/pmu.h
			{Val: 2148024836, Str: "PMU_IOC_HAS_ADB"}, // From linux/pmu.h
			{Val: 1074283010, Str: "PMU_IOC_SET_BACKLIGHT"}, // From linux/pmu.h
			{Val: 16896, Str: "PMU_IOC_SLEEP"}, // From linux/pmu.h
			{Val: 28811, Str: "PPCLAIM"}, // From linux/ppdev.h
			{Val: 2147774611, Str: "PPCLRIRQ"}, // From linux/ppdev.h
			{Val: 1074032784, Str: "PPDATADIR"}, // From linux/ppdev.h
			{Val: 28815, Str: "PPEXCL"}, // From linux/ppdev.h
			{Val: 1073901710, Str: "PPFCONTROL"}, // From linux/ppdev.h
			{Val: 2147774618, Str: "PPGETFLAGS"}, // From linux/ppdev.h
			{Val: 2147774616, Str: "PPGETMODE"}, // From linux/ppdev.h
			{Val: 2147774615, Str: "PPGETMODES"}, // From linux/ppdev.h
			{Val: 2147774617, Str: "PPGETPHASE"}, // From linux/ppdev.h
			{Val: 2148561045, Str: "PPGETTIME"}, // From linux/ppdev.h
			{Val: 1074032785, Str: "PPNEGOT"}, // From linux/ppdev.h
			{Val: 2147577987, Str: "PPRCONTROL"}, // From linux/ppdev.h
			{Val: 2147577989, Str: "PPRDATA"}, // From linux/ppdev.h
			{Val: 28812, Str: "PPRELEASE"}, // From linux/ppdev.h
			{Val: 2147577985, Str: "PPRSTATUS"}, // From linux/ppdev.h
			{Val: 1074032795, Str: "PPSETFLAGS"}, // From linux/ppdev.h
			{Val: 1074032768, Str: "PPSETMODE"}, // From linux/ppdev.h
			{Val: 1074032788, Str: "PPSETPHASE"}, // From linux/ppdev.h
			{Val: 1074819222, Str: "PPSETTIME"}, // From linux/ppdev.h
			{Val: 1073836164, Str: "PPWCONTROL"}, // From linux/ppdev.h
			{Val: 1073836178, Str: "PPWCTLONIRQ"}, // From linux/ppdev.h
			{Val: 1073836166, Str: "PPWDATA"}, // From linux/ppdev.h
			{Val: 28813, Str: "PPYIELD"}, // From linux/ppdev.h
			{Val: 1074033725, Str: "PPPIOCATTACH"}, // From linux/ppp-ioctl.h
			{Val: 1074033720, Str: "PPPIOCATTCHAN"}, // From linux/ppp-ioctl.h
			{Val: 1074033717, Str: "PPPIOCBRIDGECHAN"}, // From linux/ppp-ioctl.h
			{Val: 1074033722, Str: "PPPIOCCONNECT"}, // From linux/ppp-ioctl.h
			{Val: 1074033724, Str: "PPPIOCDETACH"}, // From linux/ppp-ioctl.h
			{Val: 29753, Str: "PPPIOCDISCONN"}, // From linux/ppp-ioctl.h
			{Val: 2147775576, Str: "PPPIOCGASYNCMAP"}, // From linux/ppp-ioctl.h
			{Val: 2147775543, Str: "PPPIOCGCHAN"}, // From linux/ppp-ioctl.h
			{Val: 2147775553, Str: "PPPIOCGDEBUG"}, // From linux/ppp-ioctl.h
			{Val: 2147775578, Str: "PPPIOCGFLAGS"}, // From linux/ppp-ioctl.h
			{Val: 2148037695, Str: "PPPIOCGIDLE32"}, // From linux/ppp-ioctl.h
			{Val: 2148561983, Str: "PPPIOCGIDLE64"}, // From linux/ppp-ioctl.h
			{Val: 2152231990, Str: "PPPIOCGL2TPSTATS"}, // From linux/ppp-ioctl.h
			{Val: 2147775571, Str: "PPPIOCGMRU"}, // From linux/ppp-ioctl.h
			{Val: 3221779532, Str: "PPPIOCGNPMODE"}, // From linux/ppp-ioctl.h
			{Val: 2147775573, Str: "PPPIOCGRASYNCMAP"}, // From linux/ppp-ioctl.h
			{Val: 2147775574, Str: "PPPIOCGUNIT"}, // From linux/ppp-ioctl.h
			{Val: 2149610576, Str: "PPPIOCGXASYNCMAP"}, // From linux/ppp-ioctl.h
			{Val: 3221517374, Str: "PPPIOCNEWUNIT"}, // From linux/ppp-ioctl.h
			{Val: 1074820166, Str: "PPPIOCSACTIVE"}, // From linux/ppp-ioctl.h
			{Val: 1074033751, Str: "PPPIOCSASYNCMAP"}, // From linux/ppp-ioctl.h
			{Val: 1074820173, Str: "PPPIOCSCOMPRESS"}, // From linux/ppp-ioctl.h
			{Val: 1074033728, Str: "PPPIOCSDEBUG"}, // From linux/ppp-ioctl.h
			{Val: 1074033753, Str: "PPPIOCSFLAGS"}, // From linux/ppp-ioctl.h
			{Val: 1074033745, Str: "PPPIOCSMAXCID"}, // From linux/ppp-ioctl.h
			{Val: 1074033723, Str: "PPPIOCSMRRU"}, // From linux/ppp-ioctl.h
			{Val: 1074033746, Str: "PPPIOCSMRU"}, // From linux/ppp-ioctl.h
			{Val: 1074295883, Str: "PPPIOCSNPMODE"}, // From linux/ppp-ioctl.h
			{Val: 1074820167, Str: "PPPIOCSPASS"}, // From linux/ppp-ioctl.h
			{Val: 1074033748, Str: "PPPIOCSRASYNCMAP"}, // From linux/ppp-ioctl.h
			{Val: 1075868751, Str: "PPPIOCSXASYNCMAP"}, // From linux/ppp-ioctl.h
			{Val: 29748, Str: "PPPIOCUNBRIDGECHAN"}, // From linux/ppp-ioctl.h
			{Val: 29774, Str: "PPPIOCXFERUNIT"}, // From linux/ppp-ioctl.h
			{Val: 3221778596, Str: "PPS_FETCH"}, // From linux/pps.h
			{Val: 2148036771, Str: "PPS_GETCAP"}, // From linux/pps.h
			{Val: 2148036769, Str: "PPS_GETPARAMS"}, // From linux/pps.h
			{Val: 1074294949, Str: "PPS_KC_BIND"}, // From linux/pps.h
			{Val: 1074294946, Str: "PPS_SETPARAMS"}, // From linux/pps.h
			{Val: 2148036787, Str: "PPS_GEN_FETCHEVENT"}, // From linux/pps_gen.h
			{Val: 1074294961, Str: "PPS_GEN_SETENABLE"}, // From linux/pps_gen.h
			{Val: 2148036786, Str: "PPS_GEN_USESYSTEMCLOCK"}, // From linux/pps_gen.h
			{Val: 1074819277, Str: "IOC_PR_CLEAR"}, // From linux/pr.h
			{Val: 1075343563, Str: "IOC_PR_PREEMPT"}, // From linux/pr.h
			{Val: 1075343564, Str: "IOC_PR_PREEMPT_ABORT"}, // From linux/pr.h
			{Val: 3222302926, Str: "IOC_PR_READ_KEYS"}, // From linux/pr.h
			{Val: 2148561103, Str: "IOC_PR_READ_RESERVATION"}, // From linux/pr.h
			{Val: 1075343560, Str: "IOC_PR_REGISTER"}, // From linux/pr.h
			{Val: 1074819274, Str: "IOC_PR_RELEASE"}, // From linux/pr.h
			{Val: 1074819273, Str: "IOC_PR_RESERVE"}, // From linux/pr.h
			{Val: 3224650753, Str: "DBCIOCNONCE"}, // From linux/psp-dbc.h
			{Val: 3223864323, Str: "DBCIOCPARAM"}, // From linux/psp-dbc.h
			{Val: 1076904962, Str: "DBCIOCUID"}, // From linux/psp-dbc.h
			{Val: 3222295296, Str: "SEV_ISSUE_CMD"}, // From linux/psp-sev.h
			{Val: 3490206465, Str: "SFSIOCFWVERS"}, // From linux/psp-sfs.h
			{Val: 3225965314, Str: "SFSIOCUPDATEPKG"}, // From linux/psp-sfs.h
			{Val: 2152742145, Str: "PTP_CLOCK_GETCAPS"}, // From linux/ptp_clock.h
			{Val: 2152742154, Str: "PTP_CLOCK_GETCAPS2"}, // From linux/ptp_clock.h
			{Val: 1074019588, Str: "PTP_ENABLE_PPS"}, // From linux/ptp_clock.h
			{Val: 1074019597, Str: "PTP_ENABLE_PPS2"}, // From linux/ptp_clock.h
			{Val: 1074806018, Str: "PTP_EXTTS_REQUEST"}, // From linux/ptp_clock.h
			{Val: 1074806027, Str: "PTP_EXTTS_REQUEST2"}, // From linux/ptp_clock.h
			{Val: 15635, Str: "PTP_MASK_CLEAR_ALL"}, // From linux/ptp_clock.h
			{Val: 1074019604, Str: "PTP_MASK_EN_SINGLE"}, // From linux/ptp_clock.h
			{Val: 1077427459, Str: "PTP_PEROUT_REQUEST"}, // From linux/ptp_clock.h
			{Val: 1077427468, Str: "PTP_PEROUT_REQUEST2"}, // From linux/ptp_clock.h
			{Val: 3227532550, Str: "PTP_PIN_GETFUNC"}, // From linux/ptp_clock.h
			{Val: 3227532559, Str: "PTP_PIN_GETFUNC2"}, // From linux/ptp_clock.h
			{Val: 1080048903, Str: "PTP_PIN_SETFUNC"}, // From linux/ptp_clock.h
			{Val: 1080048912, Str: "PTP_PIN_SETFUNC2"}, // From linux/ptp_clock.h
			{Val: 1128283397, Str: "PTP_SYS_OFFSET"}, // From linux/ptp_clock.h
			{Val: 1128283406, Str: "PTP_SYS_OFFSET2"}, // From linux/ptp_clock.h
			{Val: 3300932873, Str: "PTP_SYS_OFFSET_EXTENDED"}, // From linux/ptp_clock.h
			{Val: 3300932882, Str: "PTP_SYS_OFFSET_EXTENDED2"}, // From linux/ptp_clock.h
			{Val: 3300932886, Str: "PTP_SYS_OFFSET_EXTENDED_CYCLES"}, // From linux/ptp_clock.h
			{Val: 3225435400, Str: "PTP_SYS_OFFSET_PRECISE"}, // From linux/ptp_clock.h
			{Val: 3225435409, Str: "PTP_SYS_OFFSET_PRECISE2"}, // From linux/ptp_clock.h
			{Val: 3225435413, Str: "PTP_SYS_OFFSET_PRECISE_CYCLES"}, // From linux/ptp_clock.h
			{Val: 29954, Str: "PWM_IOCTL_FREE"}, // From linux/pwm.h
			{Val: 3223352580, Str: "PWM_IOCTL_GETWF"}, // From linux/pwm.h
			{Val: 29953, Str: "PWM_IOCTL_REQUEST"}, // From linux/pwm.h
			{Val: 3223352579, Str: "PWM_IOCTL_ROUNDWF"}, // From linux/pwm.h
			{Val: 1075868934, Str: "PWM_IOCTL_SETEXACTWF"}, // From linux/pwm.h
			{Val: 1075868933, Str: "PWM_IOCTL_SETROUNDEDWF"}, // From linux/pwm.h
			{Val: 2148024323, Str: "FBIO_RADEON_GET_MIRROR"}, // From linux/radeonfb.h
			{Val: 1074282500, Str: "FBIO_RADEON_SET_MIRROR"}, // From linux/radeonfb.h
			{Val: 1075054881, Str: "ADD_NEW_DISK"}, // From linux/raid/md_u.h
			{Val: 2336, Str: "CLEAR_ARRAY"}, // From linux/raid/md_u.h
			{Val: 2357, Str: "CLUSTERED_DISK_NACK"}, // From linux/raid/md_u.h
			{Val: 2152204561, Str: "GET_ARRAY_INFO"}, // From linux/raid/md_u.h
			{Val: 2415921429, Str: "GET_BITMAP_FILE"}, // From linux/raid/md_u.h
			{Val: 2148796690, Str: "GET_DISK_INFO"}, // From linux/raid/md_u.h
			{Val: 2344, Str: "HOT_ADD_DISK"}, // From linux/raid/md_u.h
			{Val: 2346, Str: "HOT_GENERATE_ERROR"}, // From linux/raid/md_u.h
			{Val: 2338, Str: "HOT_REMOVE_DISK"}, // From linux/raid/md_u.h
			{Val: 2343, Str: "PROTECT_ARRAY"}, // From linux/raid/md_u.h
			{Val: 2324, Str: "RAID_AUTORUN"}, // From linux/raid/md_u.h
			{Val: 2148272400, Str: "RAID_VERSION"}, // From linux/raid/md_u.h
			{Val: 2356, Str: "RESTART_ARRAY_RW"}, // From linux/raid/md_u.h
			{Val: 1074530608, Str: "RUN_ARRAY"}, // From linux/raid/md_u.h
			{Val: 1078462755, Str: "SET_ARRAY_INFO"}, // From linux/raid/md_u.h
			{Val: 1074006315, Str: "SET_BITMAP_FILE"}, // From linux/raid/md_u.h
			{Val: 2345, Str: "SET_DISK_FAULTY"}, // From linux/raid/md_u.h
			{Val: 2340, Str: "SET_DISK_INFO"}, // From linux/raid/md_u.h
			{Val: 2354, Str: "STOP_ARRAY"}, // From linux/raid/md_u.h
			{Val: 2355, Str: "STOP_ARRAY_RO"}, // From linux/raid/md_u.h
			{Val: 2342, Str: "UNPROTECT_ARRAY"}, // From linux/raid/md_u.h
			{Val: 2341, Str: "WRITE_RAID_INFO"}, // From linux/raid/md_u.h
			{Val: 1074287107, Str: "RNDADDENTROPY"}, // From linux/random.h
			{Val: 1074024961, Str: "RNDADDTOENTCNT"}, // From linux/random.h
			{Val: 20998, Str: "RNDCLEARPOOL"}, // From linux/random.h
			{Val: 2147766784, Str: "RNDGETENTCNT"}, // From linux/random.h
			{Val: 2148028930, Str: "RNDGETPOOL"}, // From linux/random.h
			{Val: 20999, Str: "RNDRESEEDCRNG"}, // From linux/random.h
			{Val: 20996, Str: "RNDZAPENTCNT"}, // From linux/random.h
			{Val: 2147792642, Str: "RPROC_GET_SHUTDOWN_ON_RELEASE"}, // From linux/remoteproc_cdev.h
			{Val: 1074050817, Str: "RPROC_SET_SHUTDOWN_ON_RELEASE"}, // From linux/remoteproc_cdev.h
			{Val: 1074024962, Str: "RFKILL_IOCTL_MAX_SIZE"}, // From linux/rfkill.h
			{Val: 20993, Str: "RFKILL_IOCTL_NOINPUT"}, // From linux/rfkill.h
			{Val: 3221775111, Str: "RIO_CM_CHAN_ACCEPT"}, // From linux/rio_cm_cdev.h
			{Val: 1074291461, Str: "RIO_CM_CHAN_BIND"}, // From linux/rio_cm_cdev.h
			{Val: 1073898244, Str: "RIO_CM_CHAN_CLOSE"}, // From linux/rio_cm_cdev.h
			{Val: 1074291464, Str: "RIO_CM_CHAN_CONNECT"}, // From linux/rio_cm_cdev.h
			{Val: 3221381891, Str: "RIO_CM_CHAN_CREATE"}, // From linux/rio_cm_cdev.h
			{Val: 1073898246, Str: "RIO_CM_CHAN_LISTEN"}, // From linux/rio_cm_cdev.h
			{Val: 3222299402, Str: "RIO_CM_CHAN_RECEIVE"}, // From linux/rio_cm_cdev.h
			{Val: 1074815753, Str: "RIO_CM_CHAN_SEND"}, // From linux/rio_cm_cdev.h
			{Val: 3221512962, Str: "RIO_CM_EP_GET_LIST"}, // From linux/rio_cm_cdev.h
			{Val: 3221512961, Str: "RIO_CM_EP_GET_LIST_SIZE"}, // From linux/rio_cm_cdev.h
			{Val: 3221512971, Str: "RIO_CM_MPORT_GET_LIST"}, // From linux/rio_cm_cdev.h
			{Val: 3222826259, Str: "RIO_ALLOC_DMA"}, // From linux/rio_mport_cdev.h
			{Val: 1075866903, Str: "RIO_DEV_ADD"}, // From linux/rio_mport_cdev.h
			{Val: 1075866904, Str: "RIO_DEV_DEL"}, // From linux/rio_mport_cdev.h
			{Val: 1074294026, Str: "RIO_DISABLE_DOORBELL_RANGE"}, // From linux/rio_mport_cdev.h
			{Val: 1074818316, Str: "RIO_DISABLE_PORTWRITE_RANGE"}, // From linux/rio_mport_cdev.h
			{Val: 1074294025, Str: "RIO_ENABLE_DOORBELL_RANGE"}, // From linux/rio_mport_cdev.h
			{Val: 1074818315, Str: "RIO_ENABLE_PORTWRITE_RANGE"}, // From linux/rio_mport_cdev.h
			{Val: 1074294036, Str: "RIO_FREE_DMA"}, // From linux/rio_mport_cdev.h
			{Val: 2147773710, Str: "RIO_GET_EVENT_MASK"}, // From linux/rio_mport_cdev.h
			{Val: 3223874833, Str: "RIO_MAP_INBOUND"}, // From linux/rio_mport_cdev.h
			{Val: 3223874831, Str: "RIO_MAP_OUTBOUND"}, // From linux/rio_mport_cdev.h
			{Val: 2150657284, Str: "RIO_MPORT_GET_PROPERTIES"}, // From linux/rio_mport_cdev.h
			{Val: 1074031874, Str: "RIO_MPORT_MAINT_COMPTAG_SET"}, // From linux/rio_mport_cdev.h
			{Val: 1073900801, Str: "RIO_MPORT_MAINT_HDID_SET"}, // From linux/rio_mport_cdev.h
			{Val: 2147773699, Str: "RIO_MPORT_MAINT_PORT_IDX_GET"}, // From linux/rio_mport_cdev.h
			{Val: 2149084421, Str: "RIO_MPORT_MAINT_READ_LOCAL"}, // From linux/rio_mport_cdev.h
			{Val: 2149084423, Str: "RIO_MPORT_MAINT_READ_REMOTE"}, // From linux/rio_mport_cdev.h
			{Val: 1075342598, Str: "RIO_MPORT_MAINT_WRITE_LOCAL"}, // From linux/rio_mport_cdev.h
			{Val: 1075342600, Str: "RIO_MPORT_MAINT_WRITE_REMOTE"}, // From linux/rio_mport_cdev.h
			{Val: 1074031885, Str: "RIO_SET_EVENT_MASK"}, // From linux/rio_mport_cdev.h
			{Val: 3222826261, Str: "RIO_TRANSFER"}, // From linux/rio_mport_cdev.h
			{Val: 1074294034, Str: "RIO_UNMAP_INBOUND"}, // From linux/rio_mport_cdev.h
			{Val: 1076391184, Str: "RIO_UNMAP_OUTBOUND"}, // From linux/rio_mport_cdev.h
			{Val: 1074294038, Str: "RIO_WAIT_FOR_ASYNC"}, // From linux/rio_mport_cdev.h
			{Val: 1076409603, Str: "RPMSG_CREATE_DEV_IOCTL"}, // From linux/rpmsg.h
			{Val: 1076409601, Str: "RPMSG_CREATE_EPT_IOCTL"}, // From linux/rpmsg.h
			{Val: 46338, Str: "RPMSG_DESTROY_EPT_IOCTL"}, // From linux/rpmsg.h
			{Val: 2147792133, Str: "RPMSG_GET_OUTGOING_FLOWCONTROL"}, // From linux/rpmsg.h
			{Val: 1076409604, Str: "RPMSG_RELEASE_DEV_IOCTL"}, // From linux/rpmsg.h
			{Val: 2147792134, Str: "RPMSG_SET_INCOMING_FLOWCONTROL"}, // From linux/rpmsg.h
			{Val: 28674, Str: "RTC_AIE_OFF"}, // From linux/rtc.h
			{Val: 28673, Str: "RTC_AIE_ON"}, // From linux/rtc.h
			{Val: 2149871624, Str: "RTC_ALM_READ"}, // From linux/rtc.h
			{Val: 1076129799, Str: "RTC_ALM_SET"}, // From linux/rtc.h
			{Val: 2148036621, Str: "RTC_EPOCH_READ"}, // From linux/rtc.h
			{Val: 1074294798, Str: "RTC_EPOCH_SET"}, // From linux/rtc.h
			{Val: 2148036619, Str: "RTC_IRQP_READ"}, // From linux/rtc.h
			{Val: 1074294796, Str: "RTC_IRQP_SET"}, // From linux/rtc.h
			{Val: 1075343379, Str: "RTC_PARAM_GET"}, // From linux/rtc.h
			{Val: 1075343380, Str: "RTC_PARAM_SET"}, // From linux/rtc.h
			{Val: 28678, Str: "RTC_PIE_OFF"}, // From linux/rtc.h
			{Val: 28677, Str: "RTC_PIE_ON"}, // From linux/rtc.h
			{Val: 2149609489, Str: "RTC_PLL_GET"}, // From linux/rtc.h
			{Val: 1075867666, Str: "RTC_PLL_SET"}, // From linux/rtc.h
			{Val: 2149871625, Str: "RTC_RD_TIME"}, // From linux/rtc.h
			{Val: 1076129802, Str: "RTC_SET_TIME"}, // From linux/rtc.h
			{Val: 28676, Str: "RTC_UIE_OFF"}, // From linux/rtc.h
			{Val: 28675, Str: "RTC_UIE_ON"}, // From linux/rtc.h
			{Val: 28692, Str: "RTC_VL_CLR"}, // From linux/rtc.h
			{Val: 2147774483, Str: "RTC_VL_READ"}, // From linux/rtc.h
			{Val: 28688, Str: "RTC_WIE_OFF"}, // From linux/rtc.h
			{Val: 28687, Str: "RTC_WIE_ON"}, // From linux/rtc.h
			{Val: 2150133776, Str: "RTC_WKALM_RD"}, // From linux/rtc.h
			{Val: 1076391951, Str: "RTC_WKALM_SET"}, // From linux/rtc.h
			{Val: 3221779205, Str: "SCIF_ACCEPTREG"}, // From linux/scif_ioctl.h
			{Val: 3222303492, Str: "SCIF_ACCEPTREQ"}, // From linux/scif_ioctl.h
			{Val: 3221779201, Str: "SCIF_BIND"}, // From linux/scif_ioctl.h
			{Val: 3221779203, Str: "SCIF_CONNECT"}, // From linux/scif_ioctl.h
			{Val: 3222303503, Str: "SCIF_FENCE_MARK"}, // From linux/scif_ioctl.h
			{Val: 3223876369, Str: "SCIF_FENCE_SIGNAL"}, // From linux/scif_ioctl.h
			{Val: 3221517072, Str: "SCIF_FENCE_WAIT"}, // From linux/scif_ioctl.h
			{Val: 3222827790, Str: "SCIF_GET_NODEIDS"}, // From linux/scif_ioctl.h
			{Val: 1074033410, Str: "SCIF_LISTEN"}, // From linux/scif_ioctl.h
			{Val: 3223876362, Str: "SCIF_READFROM"}, // From linux/scif_ioctl.h
			{Val: 3222827783, Str: "SCIF_RECV"}, // From linux/scif_ioctl.h
			{Val: 3223876360, Str: "SCIF_REG"}, // From linux/scif_ioctl.h
			{Val: 3222827782, Str: "SCIF_SEND"}, // From linux/scif_ioctl.h
			{Val: 3222303497, Str: "SCIF_UNREG"}, // From linux/scif_ioctl.h
			{Val: 3223876364, Str: "SCIF_VREADFROM"}, // From linux/scif_ioctl.h
			{Val: 3223876365, Str: "SCIF_VWRITETO"}, // From linux/scif_ioctl.h
			{Val: 3223876363, Str: "SCIF_WRITETO"}, // From linux/scif_ioctl.h
			{Val: 1075323139, Str: "SECCOMP_IOCTL_NOTIF_ADDFD"}, // From linux/seccomp.h
			{Val: 1074274562, Str: "SECCOMP_IOCTL_NOTIF_ID_VALID"}, // From linux/seccomp.h
			{Val: 3226476800, Str: "SECCOMP_IOCTL_NOTIF_RECV"}, // From linux/seccomp.h
			{Val: 3222806785, Str: "SECCOMP_IOCTL_NOTIF_SEND"}, // From linux/seccomp.h
			{Val: 1074274564, Str: "SECCOMP_IOCTL_NOTIF_SET_FLAGS"}, // From linux/seccomp.h
			{Val: 1092120799, Str: "IOC_OPAL_ACTIVATE_LSP"}, // From linux/sed-opal.h
			{Val: 1091596513, Str: "IOC_OPAL_ACTIVATE_USR"}, // From linux/sed-opal.h
			{Val: 1092120804, Str: "IOC_OPAL_ADD_USR_TO_LR"}, // From linux/sed-opal.h
			{Val: 1074819311, Str: "IOC_OPAL_DISCOVERY"}, // From linux/sed-opal.h
			{Val: 1091596517, Str: "IOC_OPAL_ENABLE_DISABLE_MBR"}, // From linux/sed-opal.h
			{Val: 1091596518, Str: "IOC_OPAL_ERASE_LR"}, // From linux/sed-opal.h
			{Val: 1094217963, Str: "IOC_OPAL_GENERIC_TABLE_RW"}, // From linux/sed-opal.h
			{Val: 2149609710, Str: "IOC_OPAL_GET_GEOMETRY"}, // From linux/sed-opal.h
			{Val: 1093693677, Str: "IOC_OPAL_GET_LR_STATUS"}, // From linux/sed-opal.h
			{Val: 2148036844, Str: "IOC_OPAL_GET_STATUS"}, // From linux/sed-opal.h
			{Val: 1092120797, Str: "IOC_OPAL_LOCK_UNLOCK"}, // From linux/sed-opal.h
			{Val: 1093169379, Str: "IOC_OPAL_LR_SETUP"}, // From linux/sed-opal.h
			{Val: 1091596521, Str: "IOC_OPAL_MBR_DONE"}, // From linux/sed-opal.h
			{Val: 1091072232, Str: "IOC_OPAL_PSID_REVERT_TPR"}, // From linux/sed-opal.h
			{Val: 1091596528, Str: "IOC_OPAL_REVERT_LSP"}, // From linux/sed-opal.h
			{Val: 1091072226, Str: "IOC_OPAL_REVERT_TPR"}, // From linux/sed-opal.h
			{Val: 1092120796, Str: "IOC_OPAL_SAVE"}, // From linux/sed-opal.h
			{Val: 1091596519, Str: "IOC_OPAL_SECURE_ERASE_LR"}, // From linux/sed-opal.h
			{Val: 1109422304, Str: "IOC_OPAL_SET_PW"}, // From linux/sed-opal.h
			{Val: 1109422321, Str: "IOC_OPAL_SET_SID_PW"}, // From linux/sed-opal.h
			{Val: 1091072222, Str: "IOC_OPAL_TAKE_OWNERSHIP"}, // From linux/sed-opal.h
			{Val: 1092645098, Str: "IOC_OPAL_WRITE_SHADOW_MBR"}, // From linux/sed-opal.h
			{Val: 1074295041, Str: "SPIOCSTYPE"}, // From linux/serio.h
			{Val: 3223343873, Str: "SNP_GET_DERIVED_KEY"}, // From linux/sev-guest.h
			{Val: 3223343874, Str: "SNP_GET_EXT_REPORT"}, // From linux/sev-guest.h
			{Val: 3223343872, Str: "SNP_GET_REPORT"}, // From linux/sev-guest.h
			{Val: 35200, Str: "SIOCADDDLCI"}, // From linux/sockios.h
			{Val: 35121, Str: "SIOCADDMULTI"}, // From linux/sockios.h
			{Val: 35083, Str: "SIOCADDRT"}, // From linux/sockios.h
			{Val: 35221, Str: "SIOCBONDCHANGEACTIVE"}, // From linux/sockios.h
			{Val: 35216, Str: "SIOCBONDENSLAVE"}, // From linux/sockios.h
			{Val: 35220, Str: "SIOCBONDINFOQUERY"}, // From linux/sockios.h
			{Val: 35217, Str: "SIOCBONDRELEASE"}, // From linux/sockios.h
			{Val: 35218, Str: "SIOCBONDSETHWADDR"}, // From linux/sockios.h
			{Val: 35219, Str: "SIOCBONDSLAVEINFOQUERY"}, // From linux/sockios.h
			{Val: 35232, Str: "SIOCBRADDBR"}, // From linux/sockios.h
			{Val: 35234, Str: "SIOCBRADDIF"}, // From linux/sockios.h
			{Val: 35233, Str: "SIOCBRDELBR"}, // From linux/sockios.h
			{Val: 35235, Str: "SIOCBRDELIF"}, // From linux/sockios.h
			{Val: 35155, Str: "SIOCDARP"}, // From linux/sockios.h
			{Val: 35201, Str: "SIOCDELDLCI"}, // From linux/sockios.h
			{Val: 35122, Str: "SIOCDELMULTI"}, // From linux/sockios.h
			{Val: 35084, Str: "SIOCDELRT"}, // From linux/sockios.h
			{Val: 35312, Str: "SIOCDEVPRIVATE"}, // From linux/sockios.h
			{Val: 35126, Str: "SIOCDIFADDR"}, // From linux/sockios.h
			{Val: 35168, Str: "SIOCDRARP"}, // From linux/sockios.h
			{Val: 35142, Str: "SIOCETHTOOL"}, // From linux/sockios.h
			{Val: 35156, Str: "SIOCGARP"}, // From linux/sockios.h
			{Val: 35249, Str: "SIOCGHWTSTAMP"}, // From linux/sockios.h
			{Val: 35093, Str: "SIOCGIFADDR"}, // From linux/sockios.h
			{Val: 35136, Str: "SIOCGIFBR"}, // From linux/sockios.h
			{Val: 35097, Str: "SIOCGIFBRDADDR"}, // From linux/sockios.h
			{Val: 35090, Str: "SIOCGIFCONF"}, // From linux/sockios.h
			{Val: 35128, Str: "SIOCGIFCOUNT"}, // From linux/sockios.h
			{Val: 35095, Str: "SIOCGIFDSTADDR"}, // From linux/sockios.h
			{Val: 35109, Str: "SIOCGIFENCAP"}, // From linux/sockios.h
			{Val: 35091, Str: "SIOCGIFFLAGS"}, // From linux/sockios.h
			{Val: 35111, Str: "SIOCGIFHWADDR"}, // From linux/sockios.h
			{Val: 35123, Str: "SIOCGIFINDEX"}, // From linux/sockios.h
			{Val: 35184, Str: "SIOCGIFMAP"}, // From linux/sockios.h
			{Val: 35103, Str: "SIOCGIFMEM"}, // From linux/sockios.h
			{Val: 35101, Str: "SIOCGIFMETRIC"}, // From linux/sockios.h
			{Val: 35105, Str: "SIOCGIFMTU"}, // From linux/sockios.h
			{Val: 35088, Str: "SIOCGIFNAME"}, // From linux/sockios.h
			{Val: 35099, Str: "SIOCGIFNETMASK"}, // From linux/sockios.h
			{Val: 35125, Str: "SIOCGIFPFLAGS"}, // From linux/sockios.h
			{Val: 35113, Str: "SIOCGIFSLAVE"}, // From linux/sockios.h
			{Val: 35138, Str: "SIOCGIFTXQLEN"}, // From linux/sockios.h
			{Val: 35202, Str: "SIOCGIFVLAN"}, // From linux/sockios.h
			{Val: 35143, Str: "SIOCGMIIPHY"}, // From linux/sockios.h
			{Val: 35144, Str: "SIOCGMIIREG"}, // From linux/sockios.h
			{Val: 35169, Str: "SIOCGRARP"}, // From linux/sockios.h
			{Val: 35148, Str: "SIOCGSKNS"}, // From linux/sockios.h
			{Val: 2148567303, Str: "SIOCGSTAMPNS_NEW"}, // From linux/sockios.h
			{Val: 2148567302, Str: "SIOCGSTAMP_NEW"}, // From linux/sockios.h
			{Val: 35147, Str: "SIOCOUTQNSD"}, // From linux/sockios.h
			{Val: 35296, Str: "SIOCPROTOPRIVATE"}, // From linux/sockios.h
			{Val: 35085, Str: "SIOCRTMSG"}, // From linux/sockios.h
			{Val: 35157, Str: "SIOCSARP"}, // From linux/sockios.h
			{Val: 35248, Str: "SIOCSHWTSTAMP"}, // From linux/sockios.h
			{Val: 35094, Str: "SIOCSIFADDR"}, // From linux/sockios.h
			{Val: 35137, Str: "SIOCSIFBR"}, // From linux/sockios.h
			{Val: 35098, Str: "SIOCSIFBRDADDR"}, // From linux/sockios.h
			{Val: 35096, Str: "SIOCSIFDSTADDR"}, // From linux/sockios.h
			{Val: 35110, Str: "SIOCSIFENCAP"}, // From linux/sockios.h
			{Val: 35092, Str: "SIOCSIFFLAGS"}, // From linux/sockios.h
			{Val: 35108, Str: "SIOCSIFHWADDR"}, // From linux/sockios.h
			{Val: 35127, Str: "SIOCSIFHWBROADCAST"}, // From linux/sockios.h
			{Val: 35089, Str: "SIOCSIFLINK"}, // From linux/sockios.h
			{Val: 35185, Str: "SIOCSIFMAP"}, // From linux/sockios.h
			{Val: 35104, Str: "SIOCSIFMEM"}, // From linux/sockios.h
			{Val: 35102, Str: "SIOCSIFMETRIC"}, // From linux/sockios.h
			{Val: 35106, Str: "SIOCSIFMTU"}, // From linux/sockios.h
			{Val: 35107, Str: "SIOCSIFNAME"}, // From linux/sockios.h
			{Val: 35100, Str: "SIOCSIFNETMASK"}, // From linux/sockios.h
			{Val: 35124, Str: "SIOCSIFPFLAGS"}, // From linux/sockios.h
			{Val: 35120, Str: "SIOCSIFSLAVE"}, // From linux/sockios.h
			{Val: 35139, Str: "SIOCSIFTXQLEN"}, // From linux/sockios.h
			{Val: 35203, Str: "SIOCSIFVLAN"}, // From linux/sockios.h
			{Val: 35145, Str: "SIOCSMIIREG"}, // From linux/sockios.h
			{Val: 35170, Str: "SIOCSRARP"}, // From linux/sockios.h
			{Val: 35146, Str: "SIOCWANDEV"}, // From linux/sockios.h
			{Val: 3221512467, Str: "SONET_CLRDIAG"}, // From linux/sonet.h
			{Val: 2147770644, Str: "SONET_GETDIAG"}, // From linux/sonet.h
			{Val: 2147770646, Str: "SONET_GETFRAMING"}, // From linux/sonet.h
			{Val: 2147901719, Str: "SONET_GETFRSENSE"}, // From linux/sonet.h
			{Val: 2149867792, Str: "SONET_GETSTAT"}, // From linux/sonet.h
			{Val: 2149867793, Str: "SONET_GETSTATZ"}, // From linux/sonet.h
			{Val: 3221512466, Str: "SONET_SETDIAG"}, // From linux/sonet.h
			{Val: 1074028821, Str: "SONET_SETFRAMING"}, // From linux/sonet.h
			{Val: 2147644930, Str: "SONYPI_IOCGBAT1CAP"}, // From linux/sonypi.h
			{Val: 2147644931, Str: "SONYPI_IOCGBAT1REM"}, // From linux/sonypi.h
			{Val: 2147644932, Str: "SONYPI_IOCGBAT2CAP"}, // From linux/sonypi.h
			{Val: 2147644933, Str: "SONYPI_IOCGBAT2REM"}, // From linux/sonypi.h
			{Val: 2147579399, Str: "SONYPI_IOCGBATFLAGS"}, // From linux/sonypi.h
			{Val: 2147579400, Str: "SONYPI_IOCGBLUE"}, // From linux/sonypi.h
			{Val: 2147579392, Str: "SONYPI_IOCGBRT"}, // From linux/sonypi.h
			{Val: 2147579402, Str: "SONYPI_IOCGFAN"}, // From linux/sonypi.h
			{Val: 2147579404, Str: "SONYPI_IOCGTEMP"}, // From linux/sonypi.h
			{Val: 1073837577, Str: "SONYPI_IOCSBLUE"}, // From linux/sonypi.h
			{Val: 1073837568, Str: "SONYPI_IOCSBRT"}, // From linux/sonypi.h
			{Val: 1073837579, Str: "SONYPI_IOCSFAN"}, // From linux/sonypi.h
			{Val: 2147765622, Str: "OSS_GETVERSION"}, // From linux/soundcard.h
			{Val: 3222553351, Str: "SNDCTL_COPR_HALT"}, // From linux/soundcard.h
			{Val: 3484435201, Str: "SNDCTL_COPR_LOAD"}, // From linux/soundcard.h
			{Val: 3222553347, Str: "SNDCTL_COPR_RCODE"}, // From linux/soundcard.h
			{Val: 2409906953, Str: "SNDCTL_COPR_RCVMSG"}, // From linux/soundcard.h
			{Val: 3222553346, Str: "SNDCTL_COPR_RDATA"}, // From linux/soundcard.h
			{Val: 17152, Str: "SNDCTL_COPR_RESET"}, // From linux/soundcard.h
			{Val: 3222553350, Str: "SNDCTL_COPR_RUN"}, // From linux/soundcard.h
			{Val: 3483648776, Str: "SNDCTL_COPR_SENDMSG"}, // From linux/soundcard.h
			{Val: 1075069701, Str: "SNDCTL_COPR_WCODE"}, // From linux/soundcard.h
			{Val: 1075069700, Str: "SNDCTL_COPR_WDATA"}, // From linux/soundcard.h
			{Val: 3221508161, Str: "SNDCTL_DSP_BIND_CHANNEL"}, // From linux/soundcard.h
			{Val: 3221508102, Str: "SNDCTL_DSP_CHANNELS"}, // From linux/soundcard.h
			{Val: 3221508100, Str: "SNDCTL_DSP_GETBLKSIZE"}, // From linux/soundcard.h
			{Val: 2147766287, Str: "SNDCTL_DSP_GETCAPS"}, // From linux/soundcard.h
			{Val: 3221508160, Str: "SNDCTL_DSP_GETCHANNELMASK"}, // From linux/soundcard.h
			{Val: 2147766283, Str: "SNDCTL_DSP_GETFMTS"}, // From linux/soundcard.h
			{Val: 2148290577, Str: "SNDCTL_DSP_GETIPTR"}, // From linux/soundcard.h
			{Val: 2148552717, Str: "SNDCTL_DSP_GETISPACE"}, // From linux/soundcard.h
			{Val: 2147766295, Str: "SNDCTL_DSP_GETODELAY"}, // From linux/soundcard.h
			{Val: 2148290578, Str: "SNDCTL_DSP_GETOPTR"}, // From linux/soundcard.h
			{Val: 2148552716, Str: "SNDCTL_DSP_GETOSPACE"}, // From linux/soundcard.h
			{Val: 2147766339, Str: "SNDCTL_DSP_GETSPDIF"}, // From linux/soundcard.h
			{Val: 2147766288, Str: "SNDCTL_DSP_GETTRIGGER"}, // From linux/soundcard.h
			{Val: 2148552723, Str: "SNDCTL_DSP_MAPINBUF"}, // From linux/soundcard.h
			{Val: 2148552724, Str: "SNDCTL_DSP_MAPOUTBUF"}, // From linux/soundcard.h
			{Val: 20494, Str: "SNDCTL_DSP_NONBLOCK"}, // From linux/soundcard.h
			{Val: 20488, Str: "SNDCTL_DSP_POST"}, // From linux/soundcard.h
			{Val: 1074024471, Str: "SNDCTL_DSP_PROFILE"}, // From linux/soundcard.h
			{Val: 20480, Str: "SNDCTL_DSP_RESET"}, // From linux/soundcard.h
			{Val: 20502, Str: "SNDCTL_DSP_SETDUPLEX"}, // From linux/soundcard.h
			{Val: 3221508101, Str: "SNDCTL_DSP_SETFMT"}, // From linux/soundcard.h
			{Val: 3221508106, Str: "SNDCTL_DSP_SETFRAGMENT"}, // From linux/soundcard.h
			{Val: 1074024514, Str: "SNDCTL_DSP_SETSPDIF"}, // From linux/soundcard.h
			{Val: 20501, Str: "SNDCTL_DSP_SETSYNCRO"}, // From linux/soundcard.h
			{Val: 1074024464, Str: "SNDCTL_DSP_SETTRIGGER"}, // From linux/soundcard.h
			{Val: 3221508098, Str: "SNDCTL_DSP_SPEED"}, // From linux/soundcard.h
			{Val: 3221508099, Str: "SNDCTL_DSP_STEREO"}, // From linux/soundcard.h
			{Val: 3221508105, Str: "SNDCTL_DSP_SUBDIVIDE"}, // From linux/soundcard.h
			{Val: 20481, Str: "SNDCTL_DSP_SYNC"}, // From linux/soundcard.h
			{Val: 1074024719, Str: "SNDCTL_FM_4OP_ENABLE"}, // From linux/soundcard.h
			{Val: 1076384007, Str: "SNDCTL_FM_LOAD_INSTR"}, // From linux/soundcard.h
			{Val: 3228848396, Str: "SNDCTL_MIDI_INFO"}, // From linux/soundcard.h
			{Val: 3223416066, Str: "SNDCTL_MIDI_MPUCMD"}, // From linux/soundcard.h
			{Val: 3221515521, Str: "SNDCTL_MIDI_MPUMODE"}, // From linux/soundcard.h
			{Val: 3221515520, Str: "SNDCTL_MIDI_PRETIME"}, // From linux/soundcard.h
			{Val: 3221508355, Str: "SNDCTL_SEQ_CTRLRATE"}, // From linux/soundcard.h
			{Val: 2147766533, Str: "SNDCTL_SEQ_GETINCOUNT"}, // From linux/soundcard.h
			{Val: 2147766532, Str: "SNDCTL_SEQ_GETOUTCOUNT"}, // From linux/soundcard.h
			{Val: 2147766547, Str: "SNDCTL_SEQ_GETTIME"}, // From linux/soundcard.h
			{Val: 2147766539, Str: "SNDCTL_SEQ_NRMIDIS"}, // From linux/soundcard.h
			{Val: 2147766538, Str: "SNDCTL_SEQ_NRSYNTHS"}, // From linux/soundcard.h
			{Val: 1074286866, Str: "SNDCTL_SEQ_OUTOFBAND"}, // From linux/soundcard.h
			{Val: 20753, Str: "SNDCTL_SEQ_PANIC"}, // From linux/soundcard.h
			{Val: 1074024710, Str: "SNDCTL_SEQ_PERCMODE"}, // From linux/soundcard.h
			{Val: 20736, Str: "SNDCTL_SEQ_RESET"}, // From linux/soundcard.h
			{Val: 1074024713, Str: "SNDCTL_SEQ_RESETSAMPLES"}, // From linux/soundcard.h
			{Val: 20737, Str: "SNDCTL_SEQ_SYNC"}, // From linux/soundcard.h
			{Val: 1074024712, Str: "SNDCTL_SEQ_TESTMIDI"}, // From linux/soundcard.h
			{Val: 1074024717, Str: "SNDCTL_SEQ_THRESHOLD"}, // From linux/soundcard.h
			{Val: 3483652373, Str: "SNDCTL_SYNTH_CONTROL"}, // From linux/soundcard.h
			{Val: 3230421268, Str: "SNDCTL_SYNTH_ID"}, // From linux/soundcard.h
			{Val: 3230421250, Str: "SNDCTL_SYNTH_INFO"}, // From linux/soundcard.h
			{Val: 3221508366, Str: "SNDCTL_SYNTH_MEMAVL"}, // From linux/soundcard.h
			{Val: 3222032662, Str: "SNDCTL_SYNTH_REMOVESAMPLE"}, // From linux/soundcard.h
			{Val: 21508, Str: "SNDCTL_TMR_CONTINUE"}, // From linux/soundcard.h
			{Val: 1074025479, Str: "SNDCTL_TMR_METRONOME"}, // From linux/soundcard.h
			{Val: 1074025480, Str: "SNDCTL_TMR_SELECT"}, // From linux/soundcard.h
			{Val: 3221509126, Str: "SNDCTL_TMR_SOURCE"}, // From linux/soundcard.h
			{Val: 21506, Str: "SNDCTL_TMR_START"}, // From linux/soundcard.h
			{Val: 21507, Str: "SNDCTL_TMR_STOP"}, // From linux/soundcard.h
			{Val: 3221509125, Str: "SNDCTL_TMR_TEMPO"}, // From linux/soundcard.h
			{Val: 3221509121, Str: "SNDCTL_TMR_TIMEBASE"}, // From linux/soundcard.h
			{Val: 3221507432, Str: "SOUND_MIXER_3DSE"}, // From linux/soundcard.h
			{Val: 3229633894, Str: "SOUND_MIXER_ACCESS"}, // From linux/soundcard.h
			{Val: 3221507431, Str: "SOUND_MIXER_AGC"}, // From linux/soundcard.h
			{Val: 3231993204, Str: "SOUND_MIXER_GETLEVELS"}, // From linux/soundcard.h
			{Val: 2153532773, Str: "SOUND_MIXER_INFO"}, // From linux/soundcard.h
			{Val: 3221507439, Str: "SOUND_MIXER_PRIVATE1"}, // From linux/soundcard.h
			{Val: 3221507440, Str: "SOUND_MIXER_PRIVATE2"}, // From linux/soundcard.h
			{Val: 3221507441, Str: "SOUND_MIXER_PRIVATE3"}, // From linux/soundcard.h
			{Val: 3221507442, Str: "SOUND_MIXER_PRIVATE4"}, // From linux/soundcard.h
			{Val: 3221507443, Str: "SOUND_MIXER_PRIVATE5"}, // From linux/soundcard.h
			{Val: 3231993205, Str: "SOUND_MIXER_SETLEVELS"}, // From linux/soundcard.h
			{Val: 2150649189, Str: "SOUND_OLD_MIXER_INFO"}, // From linux/soundcard.h
			{Val: 2147766277, Str: "SOUND_PCM_READ_BITS"}, // From linux/soundcard.h
			{Val: 2147766278, Str: "SOUND_PCM_READ_CHANNELS"}, // From linux/soundcard.h
			{Val: 2147766279, Str: "SOUND_PCM_READ_FILTER"}, // From linux/soundcard.h
			{Val: 2147766274, Str: "SOUND_PCM_READ_RATE"}, // From linux/soundcard.h
			{Val: 3221508103, Str: "SOUND_PCM_WRITE_FILTER"}, // From linux/soundcard.h
			{Val: 2147576579, Str: "SPI_IOC_RD_BITS_PER_WORD"}, // From linux/spi/spidev.h
			{Val: 2147576578, Str: "SPI_IOC_RD_LSB_FIRST"}, // From linux/spi/spidev.h
			{Val: 2147773188, Str: "SPI_IOC_RD_MAX_SPEED_HZ"}, // From linux/spi/spidev.h
			{Val: 2147576577, Str: "SPI_IOC_RD_MODE"}, // From linux/spi/spidev.h
			{Val: 2147773189, Str: "SPI_IOC_RD_MODE32"}, // From linux/spi/spidev.h
			{Val: 1073834755, Str: "SPI_IOC_WR_BITS_PER_WORD"}, // From linux/spi/spidev.h
			{Val: 1073834754, Str: "SPI_IOC_WR_LSB_FIRST"}, // From linux/spi/spidev.h
			{Val: 1074031364, Str: "SPI_IOC_WR_MAX_SPEED_HZ"}, // From linux/spi/spidev.h
			{Val: 1073834753, Str: "SPI_IOC_WR_MODE"}, // From linux/spi/spidev.h
			{Val: 1074031365, Str: "SPI_IOC_WR_MODE32"}, // From linux/spi/spidev.h
			{Val: 2148541697, Str: "STP_POLICY_ID_GET"}, // From linux/stm.h
			{Val: 3222283520, Str: "STP_POLICY_ID_SET"}, // From linux/stm.h
			{Val: 1074275586, Str: "STP_SET_OPTIONS"}, // From linux/stm.h
			{Val: 1074242821, Str: "SSAM_CDEV_EVENT_DISABLE"}, // From linux/surface_aggregator/cdev.h
			{Val: 1074242820, Str: "SSAM_CDEV_EVENT_ENABLE"}, // From linux/surface_aggregator/cdev.h
			{Val: 1074111746, Str: "SSAM_CDEV_NOTIF_REGISTER"}, // From linux/surface_aggregator/cdev.h
			{Val: 1074111747, Str: "SSAM_CDEV_NOTIF_UNREGISTER"}, // From linux/surface_aggregator/cdev.h
			{Val: 3223889153, Str: "SSAM_CDEV_REQUEST"}, // From linux/surface_aggregator/cdev.h
			{Val: 42274, Str: "SDTX_IOCTL_EVENTS_DISABLE"}, // From linux/surface_aggregator/dtx.h
			{Val: 42273, Str: "SDTX_IOCTL_EVENTS_ENABLE"}, // From linux/surface_aggregator/dtx.h
			{Val: 2147788073, Str: "SDTX_IOCTL_GET_BASE_INFO"}, // From linux/surface_aggregator/dtx.h
			{Val: 2147657002, Str: "SDTX_IOCTL_GET_DEVICE_MODE"}, // From linux/surface_aggregator/dtx.h
			{Val: 2147657003, Str: "SDTX_IOCTL_GET_LATCH_STATUS"}, // From linux/surface_aggregator/dtx.h
			{Val: 42280, Str: "SDTX_IOCTL_LATCH_CANCEL"}, // From linux/surface_aggregator/dtx.h
			{Val: 42278, Str: "SDTX_IOCTL_LATCH_CONFIRM"}, // From linux/surface_aggregator/dtx.h
			{Val: 42279, Str: "SDTX_IOCTL_LATCH_HEARTBEAT"}, // From linux/surface_aggregator/dtx.h
			{Val: 42275, Str: "SDTX_IOCTL_LATCH_LOCK"}, // From linux/surface_aggregator/dtx.h
			{Val: 42277, Str: "SDTX_IOCTL_LATCH_REQUEST"}, // From linux/surface_aggregator/dtx.h
			{Val: 42276, Str: "SDTX_IOCTL_LATCH_UNLOCK"}, // From linux/surface_aggregator/dtx.h
			{Val: 2148021012, Str: "SNAPSHOT_ALLOC_SWAP_PAGE"}, // From linux/suspend_ioctls.h
			{Val: 13060, Str: "SNAPSHOT_ATOMIC_RESTORE"}, // From linux/suspend_ioctls.h
			{Val: 2148021011, Str: "SNAPSHOT_AVAIL_SWAP_SIZE"}, // From linux/suspend_ioctls.h
			{Val: 1074017041, Str: "SNAPSHOT_CREATE_IMAGE"}, // From linux/suspend_ioctls.h
			{Val: 13061, Str: "SNAPSHOT_FREE"}, // From linux/suspend_ioctls.h
			{Val: 13057, Str: "SNAPSHOT_FREEZE"}, // From linux/suspend_ioctls.h
			{Val: 13065, Str: "SNAPSHOT_FREE_SWAP_PAGES"}, // From linux/suspend_ioctls.h
			{Val: 2148021006, Str: "SNAPSHOT_GET_IMAGE_SIZE"}, // From linux/suspend_ioctls.h
			{Val: 13071, Str: "SNAPSHOT_PLATFORM_SUPPORT"}, // From linux/suspend_ioctls.h
			{Val: 13072, Str: "SNAPSHOT_POWER_OFF"}, // From linux/suspend_ioctls.h
			{Val: 13074, Str: "SNAPSHOT_PREF_IMAGE_SIZE"}, // From linux/suspend_ioctls.h
			{Val: 13067, Str: "SNAPSHOT_S2RAM"}, // From linux/suspend_ioctls.h
			{Val: 1074541325, Str: "SNAPSHOT_SET_SWAP_AREA"}, // From linux/suspend_ioctls.h
			{Val: 13058, Str: "SNAPSHOT_UNFREEZE"}, // From linux/suspend_ioctls.h
			{Val: 3223869251, Str: "SWITCHTEC_IOCTL_EVENT_CTL"}, // From linux/switchtec_ioctl.h
			{Val: 2228770626, Str: "SWITCHTEC_IOCTL_EVENT_SUMMARY"}, // From linux/switchtec_ioctl.h
			{Val: 2174244674, Str: "SWITCHTEC_IOCTL_EVENT_SUMMARY_LEGACY"}, // From linux/switchtec_ioctl.h
			{Val: 2148554560, Str: "SWITCHTEC_IOCTL_FLASH_INFO"}, // From linux/switchtec_ioctl.h
			{Val: 3222296385, Str: "SWITCHTEC_IOCTL_FLASH_PART_INFO"}, // From linux/switchtec_ioctl.h
			{Val: 3222034244, Str: "SWITCHTEC_IOCTL_PFF_TO_PORT"}, // From linux/switchtec_ioctl.h
			{Val: 3222034245, Str: "SWITCHTEC_IOCTL_PORT_TO_PFF"}, // From linux/switchtec_ioctl.h
			{Val: 3224911364, Str: "SYNC_IOC_FILE_INFO"}, // From linux/sync_file.h
			{Val: 3224387075, Str: "SYNC_IOC_MERGE"}, // From linux/sync_file.h
			{Val: 1074806277, Str: "SYNC_IOC_SET_DEADLINE"}, // From linux/sync_file.h
			{Val: 27919, Str: "MGSL_IOCCLRMODCOUNT"}, // From linux/synclink.h
			{Val: 2148560145, Str: "MGSL_IOCGGPIO"}, // From linux/synclink.h
			{Val: 27915, Str: "MGSL_IOCGIF"}, // From linux/synclink.h
			{Val: 2150657281, Str: "MGSL_IOCGPARAMS"}, // From linux/synclink.h
			{Val: 27911, Str: "MGSL_IOCGSTATS"}, // From linux/synclink.h
			{Val: 27907, Str: "MGSL_IOCGTXIDLE"}, // From linux/synclink.h
			{Val: 27926, Str: "MGSL_IOCGXCTRL"}, // From linux/synclink.h
			{Val: 27924, Str: "MGSL_IOCGXSYNC"}, // From linux/synclink.h
			{Val: 27913, Str: "MGSL_IOCLOOPTXDONE"}, // From linux/synclink.h
			{Val: 27909, Str: "MGSL_IOCRXENABLE"}, // From linux/synclink.h
			{Val: 1074818320, Str: "MGSL_IOCSGPIO"}, // From linux/synclink.h
			{Val: 27914, Str: "MGSL_IOCSIF"}, // From linux/synclink.h
			{Val: 1076915456, Str: "MGSL_IOCSPARAMS"}, // From linux/synclink.h
			{Val: 27906, Str: "MGSL_IOCSTXIDLE"}, // From linux/synclink.h
			{Val: 27925, Str: "MGSL_IOCSXCTRL"}, // From linux/synclink.h
			{Val: 27923, Str: "MGSL_IOCSXSYNC"}, // From linux/synclink.h
			{Val: 27910, Str: "MGSL_IOCTXABORT"}, // From linux/synclink.h
			{Val: 27908, Str: "MGSL_IOCTXENABLE"}, // From linux/synclink.h
			{Val: 3221515528, Str: "MGSL_IOCWAITEVENT"}, // From linux/synclink.h
			{Val: 3222301970, Str: "MGSL_IOCWAITGPIO"}, // From linux/synclink.h
			{Val: 3292550145, Str: "TDX_CMD_GET_REPORT0"}, // From linux/tdx-guest.h
			{Val: 2148049924, Str: "TEE_IOC_CANCEL"}, // From linux/tee.h
			{Val: 2147787781, Str: "TEE_IOC_CLOSE_SESSION"}, // From linux/tee.h
			{Val: 2148574211, Str: "TEE_IOC_INVOKE"}, // From linux/tee.h
			{Val: 2148574218, Str: "TEE_IOC_OBJECT_INVOKE"}, // From linux/tee.h
			{Val: 2148574210, Str: "TEE_IOC_OPEN_SESSION"}, // From linux/tee.h
			{Val: 3222316033, Str: "TEE_IOC_SHM_ALLOC"}, // From linux/tee.h
			{Val: 3222840329, Str: "TEE_IOC_SHM_REGISTER"}, // From linux/tee.h
			{Val: 3222840328, Str: "TEE_IOC_SHM_REGISTER_FD"}, // From linux/tee.h
			{Val: 2148574214, Str: "TEE_IOC_SUPPL_RECV"}, // From linux/tee.h
			{Val: 2148574215, Str: "TEE_IOC_SUPPL_SEND"}, // From linux/tee.h
			{Val: 2148312064, Str: "TEE_IOC_VERSION"}, // From linux/tee.h
			{Val: 1074287616, Str: "TFD_IOC_SET_TICKS"}, // From linux/timerfd.h
			{Val: 3222828177, Str: "TOSHIBA_ACPI_SCI"}, // From linux/toshiba.h
			{Val: 3222828176, Str: "TOSH_SMM"}, // From linux/toshiba.h
			{Val: 20481, Str: "PMIC_GOTO_LP_STANDBY"}, // From linux/tps6594_pfsm.h
			{Val: 20480, Str: "PMIC_GOTO_STANDBY"}, // From linux/tps6594_pfsm.h
			{Val: 20483, Str: "PMIC_SET_ACTIVE_STATE"}, // From linux/tps6594_pfsm.h
			{Val: 1073958916, Str: "PMIC_SET_MCU_ONLY_STATE"}, // From linux/tps6594_pfsm.h
			{Val: 1073958917, Str: "PMIC_SET_RETENTION_STATE"}, // From linux/tps6594_pfsm.h
			{Val: 20482, Str: "PMIC_UPDATE_PGM"}, // From linux/tps6594_pfsm.h
			{Val: 21024, Str: "TRACE_MMAP_IOCTL_GET_READER"}, // From linux/trace_mmap.h
			{Val: 3223352580, Str: "UBLK_U_CMD_ADD_DEV"}, // From linux/ublk_cmd.h
			{Val: 3223352581, Str: "UBLK_U_CMD_DEL_DEV"}, // From linux/ublk_cmd.h
			{Val: 2149610772, Str: "UBLK_U_CMD_DEL_DEV_ASYNC"}, // From linux/ublk_cmd.h
			{Val: 3223352593, Str: "UBLK_U_CMD_END_USER_RECOVERY"}, // From linux/ublk_cmd.h
			{Val: 2149610754, Str: "UBLK_U_CMD_GET_DEV_INFO"}, // From linux/ublk_cmd.h
			{Val: 2149610770, Str: "UBLK_U_CMD_GET_DEV_INFO2"}, // From linux/ublk_cmd.h
			{Val: 2149610771, Str: "UBLK_U_CMD_GET_FEATURES"}, // From linux/ublk_cmd.h
			{Val: 2149610761, Str: "UBLK_U_CMD_GET_PARAMS"}, // From linux/ublk_cmd.h
			{Val: 2149610753, Str: "UBLK_U_CMD_GET_QUEUE_AFFINITY"}, // From linux/ublk_cmd.h
			{Val: 3223352598, Str: "UBLK_U_CMD_QUIESCE_DEV"}, // From linux/ublk_cmd.h
			{Val: 3223352584, Str: "UBLK_U_CMD_SET_PARAMS"}, // From linux/ublk_cmd.h
			{Val: 3223352582, Str: "UBLK_U_CMD_START_DEV"}, // From linux/ublk_cmd.h
			{Val: 3223352592, Str: "UBLK_U_CMD_START_USER_RECOVERY"}, // From linux/ublk_cmd.h
			{Val: 3223352583, Str: "UBLK_U_CMD_STOP_DEV"}, // From linux/ublk_cmd.h
			{Val: 3223352599, Str: "UBLK_U_CMD_TRY_STOP_DEV"}, // From linux/ublk_cmd.h
			{Val: 3223352597, Str: "UBLK_U_CMD_UPDATE_SIZE"}, // From linux/ublk_cmd.h
			{Val: 3222304033, Str: "UBLK_U_IO_COMMIT_AND_FETCH_REQ"}, // From linux/ublk_cmd.h
			{Val: 3222304038, Str: "UBLK_U_IO_COMMIT_IO_CMDS"}, // From linux/ublk_cmd.h
			{Val: 3222304039, Str: "UBLK_U_IO_FETCH_IO_CMDS"}, // From linux/ublk_cmd.h
			{Val: 3222304032, Str: "UBLK_U_IO_FETCH_REQ"}, // From linux/ublk_cmd.h
			{Val: 3222304034, Str: "UBLK_U_IO_NEED_GET_DATA"}, // From linux/ublk_cmd.h
			{Val: 3222304037, Str: "UBLK_U_IO_PREP_IO_CMDS"}, // From linux/ublk_cmd.h
			{Val: 3222304035, Str: "UBLK_U_IO_REGISTER_IO_BUF"}, // From linux/ublk_cmd.h
			{Val: 3222304036, Str: "UBLK_U_IO_UNREGISTER_IO_BUF"}, // From linux/ublk_cmd.h
			{Val: 2148035649, Str: "UDF_GETEABLOCK"}, // From linux/udf_fs_i.h
			{Val: 2147773504, Str: "UDF_GETEASIZE"}, // From linux/udf_fs_i.h
			{Val: 2148035650, Str: "UDF_GETVOLIDENT"}, // From linux/udf_fs_i.h
			{Val: 3221777475, Str: "UDF_RELOCATE_BLOCKS"}, // From linux/udf_fs_i.h
			{Val: 1075344706, Str: "UDMABUF_CREATE"}, // From linux/udmabuf.h
			{Val: 1074296131, Str: "UDMABUF_CREATE_LIST"}, // From linux/udmabuf.h
			{Val: 1075598596, Str: "UI_ABS_SETUP"}, // From linux/uinput.h
			{Val: 3222033866, Str: "UI_BEGIN_FF_ERASE"}, // From linux/uinput.h
			{Val: 3228063176, Str: "UI_BEGIN_FF_UPLOAD"}, // From linux/uinput.h
			{Val: 21761, Str: "UI_DEV_CREATE"}, // From linux/uinput.h
			{Val: 21762, Str: "UI_DEV_DESTROY"}, // From linux/uinput.h
			{Val: 1079792899, Str: "UI_DEV_SETUP"}, // From linux/uinput.h
			{Val: 1074550219, Str: "UI_END_FF_ERASE"}, // From linux/uinput.h
			{Val: 1080579529, Str: "UI_END_FF_UPLOAD"}, // From linux/uinput.h
			{Val: 2147767597, Str: "UI_GET_VERSION"}, // From linux/uinput.h
			{Val: 1074025831, Str: "UI_SET_ABSBIT"}, // From linux/uinput.h
			{Val: 1074025828, Str: "UI_SET_EVBIT"}, // From linux/uinput.h
			{Val: 1074025835, Str: "UI_SET_FFBIT"}, // From linux/uinput.h
			{Val: 1074025829, Str: "UI_SET_KEYBIT"}, // From linux/uinput.h
			{Val: 1074025833, Str: "UI_SET_LEDBIT"}, // From linux/uinput.h
			{Val: 1074025832, Str: "UI_SET_MSCBIT"}, // From linux/uinput.h
			{Val: 1074287980, Str: "UI_SET_PHYS"}, // From linux/uinput.h
			{Val: 1074025838, Str: "UI_SET_PROPBIT"}, // From linux/uinput.h
			{Val: 1074025830, Str: "UI_SET_RELBIT"}, // From linux/uinput.h
			{Val: 1074025834, Str: "UI_SET_SNDBIT"}, // From linux/uinput.h
			{Val: 1074025837, Str: "UI_SET_SWBIT"}, // From linux/uinput.h
			{Val: 2147633312, Str: "IOCTL_WDM_MAX_COMMAND"}, // From linux/usb/cdc-wdm.h
			{Val: 26371, Str: "FUNCTIONFS_CLEAR_HALT"}, // From linux/usb/functionfs.h
			{Val: 1074030467, Str: "FUNCTIONFS_DMABUF_ATTACH"}, // From linux/usb/functionfs.h
			{Val: 1074030468, Str: "FUNCTIONFS_DMABUF_DETACH"}, // From linux/usb/functionfs.h
			{Val: 1074816901, Str: "FUNCTIONFS_DMABUF_TRANSFER"}, // From linux/usb/functionfs.h
			{Val: 2148099970, Str: "FUNCTIONFS_ENDPOINT_DESC"}, // From linux/usb/functionfs.h
			{Val: 26497, Str: "FUNCTIONFS_ENDPOINT_REVMAP"}, // From linux/usb/functionfs.h
			{Val: 26370, Str: "FUNCTIONFS_FIFO_FLUSH"}, // From linux/usb/functionfs.h
			{Val: 26369, Str: "FUNCTIONFS_FIFO_STATUS"}, // From linux/usb/functionfs.h
			{Val: 26496, Str: "FUNCTIONFS_INTERFACE_REVMAP"}, // From linux/usb/functionfs.h
			{Val: 2147575617, Str: "GADGET_HID_READ_GET_REPORT_ID"}, // From linux/usb/g_hid.h
			{Val: 1078486850, Str: "GADGET_HID_WRITE_GET_REPORT"}, // From linux/usb/g_hid.h
			{Val: 2147575585, Str: "GADGET_GET_PRINTER_STATUS"}, // From linux/usb/g_printer.h
			{Val: 3221317410, Str: "GADGET_SET_PRINTER_STATUS"}, // From linux/usb/g_printer.h
			{Val: 1077957889, Str: "UVCIOC_SEND_RESPONSE"}, // From linux/usb/g_uvc.h
			{Val: 26371, Str: "GADGETFS_CLEAR_HALT"}, // From linux/usb/gadgetfs.h
			{Val: 26370, Str: "GADGETFS_FIFO_FLUSH"}, // From linux/usb/gadgetfs.h
			{Val: 26369, Str: "GADGETFS_FIFO_STATUS"}, // From linux/usb/gadgetfs.h
			{Val: 2150154243, Str: "IOW_GETINFO"}, // From linux/usb/iowarrior.h
			{Val: 1074315266, Str: "IOW_READ"}, // From linux/usb/iowarrior.h
			{Val: 1074315265, Str: "IOW_WRITE"}, // From linux/usb/iowarrior.h
			{Val: 21769, Str: "USB_RAW_IOCTL_CONFIGURE"}, // From linux/usb/raw_gadget.h
			{Val: 3221771524, Str: "USB_RAW_IOCTL_EP0_READ"}, // From linux/usb/raw_gadget.h
			{Val: 21772, Str: "USB_RAW_IOCTL_EP0_STALL"}, // From linux/usb/raw_gadget.h
			{Val: 1074287875, Str: "USB_RAW_IOCTL_EP0_WRITE"}, // From linux/usb/raw_gadget.h
			{Val: 2210419979, Str: "USB_RAW_IOCTL_EPS_INFO"}, // From linux/usb/raw_gadget.h
			{Val: 1074025742, Str: "USB_RAW_IOCTL_EP_CLEAR_HALT"}, // From linux/usb/raw_gadget.h
			{Val: 1074025734, Str: "USB_RAW_IOCTL_EP_DISABLE"}, // From linux/usb/raw_gadget.h
			{Val: 1074353413, Str: "USB_RAW_IOCTL_EP_ENABLE"}, // From linux/usb/raw_gadget.h
			{Val: 3221771528, Str: "USB_RAW_IOCTL_EP_READ"}, // From linux/usb/raw_gadget.h
			{Val: 1074025741, Str: "USB_RAW_IOCTL_EP_SET_HALT"}, // From linux/usb/raw_gadget.h
			{Val: 1074025743, Str: "USB_RAW_IOCTL_EP_SET_WEDGE"}, // From linux/usb/raw_gadget.h
			{Val: 1074287879, Str: "USB_RAW_IOCTL_EP_WRITE"}, // From linux/usb/raw_gadget.h
			{Val: 2148029698, Str: "USB_RAW_IOCTL_EVENT_FETCH"}, // From linux/usb/raw_gadget.h
			{Val: 1090606336, Str: "USB_RAW_IOCTL_INIT"}, // From linux/usb/raw_gadget.h
			{Val: 21761, Str: "USB_RAW_IOCTL_RUN"}, // From linux/usb/raw_gadget.h
			{Val: 1074025738, Str: "USB_RAW_IOCTL_VBUS_DRAW"}, // From linux/usb/raw_gadget.h
			{Val: 2147572497, Str: "USBTMC488_IOCTL_GET_CAPS"}, // From linux/usb/tmc.h
			{Val: 23316, Str: "USBTMC488_IOCTL_GOTO_LOCAL"}, // From linux/usb/tmc.h
			{Val: 23317, Str: "USBTMC488_IOCTL_LOCAL_LOCKOUT"}, // From linux/usb/tmc.h
			{Val: 2147572498, Str: "USBTMC488_IOCTL_READ_STB"}, // From linux/usb/tmc.h
			{Val: 1073830675, Str: "USBTMC488_IOCTL_REN_CONTROL"}, // From linux/usb/tmc.h
			{Val: 23318, Str: "USBTMC488_IOCTL_TRIGGER"}, // From linux/usb/tmc.h
			{Val: 1074027287, Str: "USBTMC488_IOCTL_WAIT_SRQ"}, // From linux/usb/tmc.h
			{Val: 23300, Str: "USBTMC_IOCTL_ABORT_BULK_IN"}, // From linux/usb/tmc.h
			{Val: 23299, Str: "USBTMC_IOCTL_ABORT_BULK_OUT"}, // From linux/usb/tmc.h
			{Val: 2147769104, Str: "USBTMC_IOCTL_API_VERSION"}, // From linux/usb/tmc.h
			{Val: 1073830681, Str: "USBTMC_IOCTL_AUTO_ABORT"}, // From linux/usb/tmc.h
			{Val: 23331, Str: "USBTMC_IOCTL_CANCEL_IO"}, // From linux/usb/tmc.h
			{Val: 23332, Str: "USBTMC_IOCTL_CLEANUP_IO"}, // From linux/usb/tmc.h
			{Val: 23298, Str: "USBTMC_IOCTL_CLEAR"}, // From linux/usb/tmc.h
			{Val: 23303, Str: "USBTMC_IOCTL_CLEAR_IN_HALT"}, // From linux/usb/tmc.h
			{Val: 23302, Str: "USBTMC_IOCTL_CLEAR_OUT_HALT"}, // From linux/usb/tmc.h
			{Val: 1073896204, Str: "USBTMC_IOCTL_CONFIG_TERMCHAR"}, // From linux/usb/tmc.h
			{Val: 3222297352, Str: "USBTMC_IOCTL_CTRL_REQUEST"}, // From linux/usb/tmc.h
			{Val: 1073830667, Str: "USBTMC_IOCTL_EOM_ENABLE"}, // From linux/usb/tmc.h
			{Val: 2147572507, Str: "USBTMC_IOCTL_GET_SRQ_STB"}, // From linux/usb/tmc.h
			{Val: 2147572506, Str: "USBTMC_IOCTL_GET_STB"}, // From linux/usb/tmc.h
			{Val: 2147769097, Str: "USBTMC_IOCTL_GET_TIMEOUT"}, // From linux/usb/tmc.h
			{Val: 23297, Str: "USBTMC_IOCTL_INDICATOR_PULSE"}, // From linux/usb/tmc.h
			{Val: 2147572504, Str: "USBTMC_IOCTL_MSG_IN_ATTR"}, // From linux/usb/tmc.h
			{Val: 3222559502, Str: "USBTMC_IOCTL_READ"}, // From linux/usb/tmc.h
			{Val: 1074027274, Str: "USBTMC_IOCTL_SET_TIMEOUT"}, // From linux/usb/tmc.h
			{Val: 3222559501, Str: "USBTMC_IOCTL_WRITE"}, // From linux/usb/tmc.h
			{Val: 3221510927, Str: "USBTMC_IOCTL_WRITE_RESULT"}, // From linux/usb/tmc.h
			{Val: 2148029724, Str: "USBDEVFS_ALLOC_STREAMS"}, // From linux/usbdevice_fs.h
			{Val: 21794, Str: "USBDEVFS_ALLOW_SUSPEND"}, // From linux/usbdevice_fs.h
			{Val: 3222820098, Str: "USBDEVFS_BULK"}, // From linux/usbdevice_fs.h
			{Val: 3222295810, Str: "USBDEVFS_BULK32"}, // From linux/usbdevice_fs.h
			{Val: 2147767567, Str: "USBDEVFS_CLAIMINTERFACE"}, // From linux/usbdevice_fs.h
			{Val: 2147767576, Str: "USBDEVFS_CLAIM_PORT"}, // From linux/usbdevice_fs.h
			{Val: 2147767573, Str: "USBDEVFS_CLEAR_HALT"}, // From linux/usbdevice_fs.h
			{Val: 21783, Str: "USBDEVFS_CONNECT"}, // From linux/usbdevice_fs.h
			{Val: 1074287889, Str: "USBDEVFS_CONNECTINFO"}, // From linux/usbdevice_fs.h
			{Val: 3222820096, Str: "USBDEVFS_CONTROL"}, // From linux/usbdevice_fs.h
			{Val: 3222295808, Str: "USBDEVFS_CONTROL32"}, // From linux/usbdevice_fs.h
			{Val: 21771, Str: "USBDEVFS_DISCARDURB"}, // From linux/usbdevice_fs.h
			{Val: 21782, Str: "USBDEVFS_DISCONNECT"}, // From linux/usbdevice_fs.h
			{Val: 2164806939, Str: "USBDEVFS_DISCONNECT_CLAIM"}, // From linux/usbdevice_fs.h
			{Val: 2148553998, Str: "USBDEVFS_DISCSIGNAL"}, // From linux/usbdevice_fs.h
			{Val: 2148029710, Str: "USBDEVFS_DISCSIGNAL32"}, // From linux/usbdevice_fs.h
			{Val: 1074025758, Str: "USBDEVFS_DROP_PRIVILEGES"}, // From linux/usbdevice_fs.h
			{Val: 21793, Str: "USBDEVFS_FORBID_SUSPEND"}, // From linux/usbdevice_fs.h
			{Val: 2148029725, Str: "USBDEVFS_FREE_STREAMS"}, // From linux/usbdevice_fs.h
			{Val: 1090802952, Str: "USBDEVFS_GETDRIVER"}, // From linux/usbdevice_fs.h
			{Val: 2147767578, Str: "USBDEVFS_GET_CAPABILITIES"}, // From linux/usbdevice_fs.h
			{Val: 21791, Str: "USBDEVFS_GET_SPEED"}, // From linux/usbdevice_fs.h
			{Val: 2155894035, Str: "USBDEVFS_HUB_PORTINFO"}, // From linux/usbdevice_fs.h
			{Val: 3222295826, Str: "USBDEVFS_IOCTL"}, // From linux/usbdevice_fs.h
			{Val: 3222033682, Str: "USBDEVFS_IOCTL32"}, // From linux/usbdevice_fs.h
			{Val: 1074287884, Str: "USBDEVFS_REAPURB"}, // From linux/usbdevice_fs.h
			{Val: 1074025740, Str: "USBDEVFS_REAPURB32"}, // From linux/usbdevice_fs.h
			{Val: 1074287885, Str: "USBDEVFS_REAPURBNDELAY"}, // From linux/usbdevice_fs.h
			{Val: 1074025741, Str: "USBDEVFS_REAPURBNDELAY32"}, // From linux/usbdevice_fs.h
			{Val: 2147767568, Str: "USBDEVFS_RELEASEINTERFACE"}, // From linux/usbdevice_fs.h
			{Val: 2147767577, Str: "USBDEVFS_RELEASE_PORT"}, // From linux/usbdevice_fs.h
			{Val: 21780, Str: "USBDEVFS_RESET"}, // From linux/usbdevice_fs.h
			{Val: 2147767555, Str: "USBDEVFS_RESETEP"}, // From linux/usbdevice_fs.h
			{Val: 2147767557, Str: "USBDEVFS_SETCONFIGURATION"}, // From linux/usbdevice_fs.h
			{Val: 2148029700, Str: "USBDEVFS_SETINTERFACE"}, // From linux/usbdevice_fs.h
			{Val: 2151175434, Str: "USBDEVFS_SUBMITURB"}, // From linux/usbdevice_fs.h
			{Val: 2150257930, Str: "USBDEVFS_SUBMITURB32"}, // From linux/usbdevice_fs.h
			{Val: 21795, Str: "USBDEVFS_WAIT_FOR_RESUME"}, // From linux/usbdevice_fs.h
			{Val: 1074276865, Str: "DIAG_IOCSDEL"}, // From linux/user_events.h
			{Val: 3221760512, Str: "DIAG_IOCSREG"}, // From linux/user_events.h
			{Val: 1074276866, Str: "DIAG_IOCSUNREG"}, // From linux/user_events.h
			{Val: 3222841919, Str: "UFFDIO_API"}, // From linux/userfaultfd.h
			{Val: 3223366151, Str: "UFFDIO_CONTINUE"}, // From linux/userfaultfd.h
			{Val: 3223890435, Str: "UFFDIO_COPY"}, // From linux/userfaultfd.h
			{Val: 3223890437, Str: "UFFDIO_MOVE"}, // From linux/userfaultfd.h
			{Val: 3223366152, Str: "UFFDIO_POISON"}, // From linux/userfaultfd.h
			{Val: 3223366144, Str: "UFFDIO_REGISTER"}, // From linux/userfaultfd.h
			{Val: 2148575745, Str: "UFFDIO_UNREGISTER"}, // From linux/userfaultfd.h
			{Val: 2148575746, Str: "UFFDIO_WAKE"}, // From linux/userfaultfd.h
			{Val: 3222841862, Str: "UFFDIO_WRITEPROTECT"}, // From linux/userfaultfd.h
			{Val: 3223366148, Str: "UFFDIO_ZEROPAGE"}, // From linux/userfaultfd.h
			{Val: 43520, Str: "USERFAULTFD_IOC_NEW"}, // From linux/userfaultfd.h
			{Val: 3227546912, Str: "UVCIOC_CTRL_MAP"}, // From linux/uvcvideo.h
			{Val: 3222304033, Str: "UVCIOC_CTRL_QUERY"}, // From linux/uvcvideo.h
			{Val: 3225441867, Str: "VIDIOC_SUBDEV_ENUM_FRAME_INTERVAL"}, // From linux/v4l2-subdev.h
			{Val: 3225441866, Str: "VIDIOC_SUBDEV_ENUM_FRAME_SIZE"}, // From linux/v4l2-subdev.h
			{Val: 3224393218, Str: "VIDIOC_SUBDEV_ENUM_MBUS_CODE"}, // From linux/v4l2-subdev.h
			{Val: 2148030053, Str: "VIDIOC_SUBDEV_G_CLIENT_CAP"}, // From linux/v4l2-subdev.h
			{Val: 3224917563, Str: "VIDIOC_SUBDEV_G_CROP"}, // From linux/v4l2-subdev.h
			{Val: 3227014660, Str: "VIDIOC_SUBDEV_G_FMT"}, // From linux/v4l2-subdev.h
			{Val: 3224393237, Str: "VIDIOC_SUBDEV_G_FRAME_INTERVAL"}, // From linux/v4l2-subdev.h
			{Val: 3225441830, Str: "VIDIOC_SUBDEV_G_ROUTING"}, // From linux/v4l2-subdev.h
			{Val: 3225441853, Str: "VIDIOC_SUBDEV_G_SELECTION"}, // From linux/v4l2-subdev.h
			{Val: 2151699968, Str: "VIDIOC_SUBDEV_QUERYCAP"}, // From linux/v4l2-subdev.h
			{Val: 3221771878, Str: "VIDIOC_SUBDEV_S_CLIENT_CAP"}, // From linux/v4l2-subdev.h
			{Val: 3224917564, Str: "VIDIOC_SUBDEV_S_CROP"}, // From linux/v4l2-subdev.h
			{Val: 3227014661, Str: "VIDIOC_SUBDEV_S_FMT"}, // From linux/v4l2-subdev.h
			{Val: 3224393238, Str: "VIDIOC_SUBDEV_S_FRAME_INTERVAL"}, // From linux/v4l2-subdev.h
			{Val: 3225441831, Str: "VIDIOC_SUBDEV_S_ROUTING"}, // From linux/v4l2-subdev.h
			{Val: 3225441854, Str: "VIDIOC_SUBDEV_S_SELECTION"}, // From linux/v4l2-subdev.h
			{Val: 3223606797, Str: "VBG_IOCTL_ACQUIRE_GUEST_CAPABILITIES"}, // From linux/vboxguest.h
			{Val: 3223344652, Str: "VBG_IOCTL_CHANGE_FILTER_MASK"}, // From linux/vboxguest.h
			{Val: 3223344654, Str: "VBG_IOCTL_CHANGE_GUEST_CAPABILITIES"}, // From linux/vboxguest.h
			{Val: 3223344657, Str: "VBG_IOCTL_CHECK_BALLOON"}, // From linux/vboxguest.h
			{Val: 3224131072, Str: "VBG_IOCTL_DRIVER_VERSION_INFO"}, // From linux/vboxguest.h
			{Val: 3231471108, Str: "VBG_IOCTL_HGCM_CONNECT"}, // From linux/vboxguest.h
			{Val: 3223082501, Str: "VBG_IOCTL_HGCM_DISCONNECT"}, // From linux/vboxguest.h
			{Val: 3222820363, Str: "VBG_IOCTL_INTERRUPT_ALL_WAIT_FOR_EVENTS"}, // From linux/vboxguest.h
			{Val: 22019, Str: "VBG_IOCTL_VMMDEV_REQUEST_BIG"}, // From linux/vboxguest.h
			{Val: 3223344650, Str: "VBG_IOCTL_WAIT_FOR_EVENTS"}, // From linux/vboxguest.h
			{Val: 3223082515, Str: "VBG_IOCTL_WRITE_CORE_DUMP"}, // From linux/vboxguest.h
			{Val: 1095794946, Str: "VDUSE_CREATE_DEV"}, // From linux/vduse.h
			{Val: 1090552067, Str: "VDUSE_DESTROY_DEV"}, // From linux/vduse.h
			{Val: 2148040977, Str: "VDUSE_DEV_GET_FEATURES"}, // From linux/vduse.h
			{Val: 33043, Str: "VDUSE_DEV_INJECT_CONFIG_IRQ"}, // From linux/vduse.h
			{Val: 1074299154, Str: "VDUSE_DEV_SET_CONFIG"}, // From linux/vduse.h
			{Val: 2148040960, Str: "VDUSE_GET_API_VERSION"}, // From linux/vduse.h
			{Val: 1076920601, Str: "VDUSE_IOTLB_DEREG_UMEM"}, // From linux/vduse.h
			{Val: 3223355664, Str: "VDUSE_IOTLB_GET_FD"}, // From linux/vduse.h
			{Val: 3226501403, Str: "VDUSE_IOTLB_GET_FD2"}, // From linux/vduse.h
			{Val: 3224404250, Str: "VDUSE_IOTLB_GET_INFO"}, // From linux/vduse.h
			{Val: 1076920600, Str: "VDUSE_IOTLB_REG_UMEM"}, // From linux/vduse.h
			{Val: 1074299137, Str: "VDUSE_SET_API_VERSION"}, // From linux/vduse.h
			{Val: 3224404245, Str: "VDUSE_VQ_GET_INFO"}, // From linux/vduse.h
			{Val: 1074037015, Str: "VDUSE_VQ_INJECT_IRQ"}, // From linux/vduse.h
			{Val: 1075872020, Str: "VDUSE_VQ_SETUP"}, // From linux/vduse.h
			{Val: 1074299158, Str: "VDUSE_VQ_SETUP_KICKFD"}, // From linux/vduse.h
			{Val: 15205, Str: "VFIO_CHECK_EXTENSION"}, // From linux/vfio.h
			{Val: 15223, Str: "VFIO_DEVICE_ATTACH_IOMMUFD_PT"}, // From linux/vfio.h
			{Val: 15222, Str: "VFIO_DEVICE_BIND_IOMMUFD"}, // From linux/vfio.h
			{Val: 15224, Str: "VFIO_DEVICE_DETACH_IOMMUFD_PT"}, // From linux/vfio.h
			{Val: 15221, Str: "VFIO_DEVICE_FEATURE"}, // From linux/vfio.h
			{Val: 15219, Str: "VFIO_DEVICE_GET_GFX_DMABUF"}, // From linux/vfio.h
			{Val: 15211, Str: "VFIO_DEVICE_GET_INFO"}, // From linux/vfio.h
			{Val: 15213, Str: "VFIO_DEVICE_GET_IRQ_INFO"}, // From linux/vfio.h
			{Val: 15216, Str: "VFIO_DEVICE_GET_PCI_HOT_RESET_INFO"}, // From linux/vfio.h
			{Val: 15212, Str: "VFIO_DEVICE_GET_REGION_INFO"}, // From linux/vfio.h
			{Val: 15220, Str: "VFIO_DEVICE_IOEVENTFD"}, // From linux/vfio.h
			{Val: 15217, Str: "VFIO_DEVICE_PCI_HOT_RESET"}, // From linux/vfio.h
			{Val: 15218, Str: "VFIO_DEVICE_QUERY_GFX_PLANE"}, // From linux/vfio.h
			{Val: 15215, Str: "VFIO_DEVICE_RESET"}, // From linux/vfio.h
			{Val: 15214, Str: "VFIO_DEVICE_SET_IRQS"}, // From linux/vfio.h
			{Val: 15225, Str: "VFIO_EEH_PE_OP"}, // From linux/vfio.h
			{Val: 15204, Str: "VFIO_GET_API_VERSION"}, // From linux/vfio.h
			{Val: 15210, Str: "VFIO_GROUP_GET_DEVICE_FD"}, // From linux/vfio.h
			{Val: 15207, Str: "VFIO_GROUP_GET_STATUS"}, // From linux/vfio.h
			{Val: 15208, Str: "VFIO_GROUP_SET_CONTAINER"}, // From linux/vfio.h
			{Val: 15209, Str: "VFIO_GROUP_UNSET_CONTAINER"}, // From linux/vfio.h
			{Val: 15221, Str: "VFIO_IOMMU_DIRTY_PAGES"}, // From linux/vfio.h
			{Val: 15220, Str: "VFIO_IOMMU_DISABLE"}, // From linux/vfio.h
			{Val: 15219, Str: "VFIO_IOMMU_ENABLE"}, // From linux/vfio.h
			{Val: 15216, Str: "VFIO_IOMMU_GET_INFO"}, // From linux/vfio.h
			{Val: 15217, Str: "VFIO_IOMMU_MAP_DMA"}, // From linux/vfio.h
			{Val: 15221, Str: "VFIO_IOMMU_SPAPR_REGISTER_MEMORY"}, // From linux/vfio.h
			{Val: 15223, Str: "VFIO_IOMMU_SPAPR_TCE_CREATE"}, // From linux/vfio.h
			{Val: 15216, Str: "VFIO_IOMMU_SPAPR_TCE_GET_INFO"}, // From linux/vfio.h
			{Val: 15224, Str: "VFIO_IOMMU_SPAPR_TCE_REMOVE"}, // From linux/vfio.h
			{Val: 15222, Str: "VFIO_IOMMU_SPAPR_UNREGISTER_MEMORY"}, // From linux/vfio.h
			{Val: 15218, Str: "VFIO_IOMMU_UNMAP_DMA"}, // From linux/vfio.h
			{Val: 15225, Str: "VFIO_MIG_GET_PRECOPY_INFO"}, // From linux/vfio.h
			{Val: 15206, Str: "VFIO_SET_IOMMU"}, // From linux/vfio.h
			{Val: 1074310933, Str: "VHOST_ATTACH_VRING_WORKER"}, // From linux/vhost.h
			{Val: 1074048777, Str: "VHOST_FREE_WORKER"}, // From linux/vhost.h
			{Val: 2148052774, Str: "VHOST_GET_BACKEND_FEATURES"}, // From linux/vhost.h
			{Val: 2148052736, Str: "VHOST_GET_FEATURES"}, // From linux/vhost.h
			{Val: 2148052867, Str: "VHOST_GET_FEATURES_ARRAY"}, // From linux/vhost.h
			{Val: 2147594117, Str: "VHOST_GET_FORK_FROM_OWNER"}, // From linux/vhost.h
			{Val: 3221794578, Str: "VHOST_GET_VRING_BASE"}, // From linux/vhost.h
			{Val: 1074310948, Str: "VHOST_GET_VRING_BUSYLOOP_TIMEOUT"}, // From linux/vhost.h
			{Val: 1074310932, Str: "VHOST_GET_VRING_ENDIAN"}, // From linux/vhost.h
			{Val: 3221794582, Str: "VHOST_GET_VRING_WORKER"}, // From linux/vhost.h
			{Val: 1074310960, Str: "VHOST_NET_SET_BACKEND"}, // From linux/vhost.h
			{Val: 2147790600, Str: "VHOST_NEW_WORKER"}, // From linux/vhost.h
			{Val: 44802, Str: "VHOST_RESET_OWNER"}, // From linux/vhost.h
			{Val: 1088991041, Str: "VHOST_SCSI_CLEAR_ENDPOINT"}, // From linux/vhost.h
			{Val: 1074048834, Str: "VHOST_SCSI_GET_ABI_VERSION"}, // From linux/vhost.h
			{Val: 1074048836, Str: "VHOST_SCSI_GET_EVENTS_MISSED"}, // From linux/vhost.h
			{Val: 1088991040, Str: "VHOST_SCSI_SET_ENDPOINT"}, // From linux/vhost.h
			{Val: 1074048835, Str: "VHOST_SCSI_SET_EVENTS_MISSED"}, // From linux/vhost.h
			{Val: 1074310949, Str: "VHOST_SET_BACKEND_FEATURES"}, // From linux/vhost.h
			{Val: 1074310912, Str: "VHOST_SET_FEATURES"}, // From linux/vhost.h
			{Val: 1074311043, Str: "VHOST_SET_FEATURES_ARRAY"}, // From linux/vhost.h
			{Val: 1073852292, Str: "VHOST_SET_FORK_FROM_OWNER"}, // From linux/vhost.h
			{Val: 1074310916, Str: "VHOST_SET_LOG_BASE"}, // From linux/vhost.h
			{Val: 1074048775, Str: "VHOST_SET_LOG_FD"}, // From linux/vhost.h
			{Val: 1074310915, Str: "VHOST_SET_MEM_TABLE"}, // From linux/vhost.h
			{Val: 44801, Str: "VHOST_SET_OWNER"}, // From linux/vhost.h
			{Val: 1076408081, Str: "VHOST_SET_VRING_ADDR"}, // From linux/vhost.h
			{Val: 1074310930, Str: "VHOST_SET_VRING_BASE"}, // From linux/vhost.h
			{Val: 1074310947, Str: "VHOST_SET_VRING_BUSYLOOP_TIMEOUT"}, // From linux/vhost.h
			{Val: 1074310945, Str: "VHOST_SET_VRING_CALL"}, // From linux/vhost.h
			{Val: 1074310931, Str: "VHOST_SET_VRING_ENDIAN"}, // From linux/vhost.h
			{Val: 1074310946, Str: "VHOST_SET_VRING_ERR"}, // From linux/vhost.h
			{Val: 1074310944, Str: "VHOST_SET_VRING_KICK"}, // From linux/vhost.h
			{Val: 1074310928, Str: "VHOST_SET_VRING_NUM"}, // From linux/vhost.h
			{Val: 2147790714, Str: "VHOST_VDPA_GET_AS_NUM"}, // From linux/vhost.h
			{Val: 2148052851, Str: "VHOST_VDPA_GET_CONFIG"}, // From linux/vhost.h
			{Val: 2147790713, Str: "VHOST_VDPA_GET_CONFIG_SIZE"}, // From linux/vhost.h
			{Val: 2147790704, Str: "VHOST_VDPA_GET_DEVICE_ID"}, // From linux/vhost.h
			{Val: 2147790721, Str: "VHOST_VDPA_GET_GROUP_NUM"}, // From linux/vhost.h
			{Val: 2148577144, Str: "VHOST_VDPA_GET_IOVA_RANGE"}, // From linux/vhost.h
			{Val: 2147594097, Str: "VHOST_VDPA_GET_STATUS"}, // From linux/vhost.h
			{Val: 2147790720, Str: "VHOST_VDPA_GET_VQS_COUNT"}, // From linux/vhost.h
			{Val: 3221794687, Str: "VHOST_VDPA_GET_VRING_DESC_GROUP"}, // From linux/vhost.h
			{Val: 3221794683, Str: "VHOST_VDPA_GET_VRING_GROUP"}, // From linux/vhost.h
			{Val: 2147659638, Str: "VHOST_VDPA_GET_VRING_NUM"}, // From linux/vhost.h
			{Val: 3221794690, Str: "VHOST_VDPA_GET_VRING_SIZE"}, // From linux/vhost.h
			{Val: 44926, Str: "VHOST_VDPA_RESUME"}, // From linux/vhost.h
			{Val: 1074311028, Str: "VHOST_VDPA_SET_CONFIG"}, // From linux/vhost.h
			{Val: 1074048887, Str: "VHOST_VDPA_SET_CONFIG_CALL"}, // From linux/vhost.h
			{Val: 1074311036, Str: "VHOST_VDPA_SET_GROUP_ASID"}, // From linux/vhost.h
			{Val: 1073852274, Str: "VHOST_VDPA_SET_STATUS"}, // From linux/vhost.h
			{Val: 1074311029, Str: "VHOST_VDPA_SET_VRING_ENABLE"}, // From linux/vhost.h
			{Val: 44925, Str: "VHOST_VDPA_SUSPEND"}, // From linux/vhost.h
			{Val: 1074311008, Str: "VHOST_VSOCK_SET_GUEST_CID"}, // From linux/vhost.h
			{Val: 1074048865, Str: "VHOST_VSOCK_SET_RUNNING"}, // From linux/vhost.h
			{Val: 3238024796, Str: "VIDIOC_CREATE_BUFS"}, // From linux/videodev2.h
			{Val: 3224131130, Str: "VIDIOC_CROPCAP"}, // From linux/videodev2.h
			{Val: 3234354790, Str: "VIDIOC_DBG_G_CHIP_INFO"}, // From linux/videodev2.h
			{Val: 3224917584, Str: "VIDIOC_DBG_G_REGISTER"}, // From linux/videodev2.h
			{Val: 1077433935, Str: "VIDIOC_DBG_S_REGISTER"}, // From linux/videodev2.h
			{Val: 3225966176, Str: "VIDIOC_DECODER_CMD"}, // From linux/videodev2.h
			{Val: 3227014673, Str: "VIDIOC_DQBUF"}, // From linux/videodev2.h
			{Val: 2156418649, Str: "VIDIOC_DQEVENT"}, // From linux/videodev2.h
			{Val: 3230684772, Str: "VIDIOC_DV_TIMINGS_CAP"}, // From linux/videodev2.h
			{Val: 3223869005, Str: "VIDIOC_ENCODER_CMD"}, // From linux/videodev2.h
			{Val: 3224655425, Str: "VIDIOC_ENUMAUDIO"}, // From linux/videodev2.h
			{Val: 3224655426, Str: "VIDIOC_ENUMAUDOUT"}, // From linux/videodev2.h
			{Val: 3226490394, Str: "VIDIOC_ENUMINPUT"}, // From linux/videodev2.h
			{Val: 3225966128, Str: "VIDIOC_ENUMOUTPUT"}, // From linux/videodev2.h
			{Val: 3225966105, Str: "VIDIOC_ENUMSTD"}, // From linux/videodev2.h
			{Val: 3230946914, Str: "VIDIOC_ENUM_DV_TIMINGS"}, // From linux/videodev2.h
			{Val: 3225441794, Str: "VIDIOC_ENUM_FMT"}, // From linux/videodev2.h
			{Val: 3224655435, Str: "VIDIOC_ENUM_FRAMEINTERVALS"}, // From linux/videodev2.h
			{Val: 3224131146, Str: "VIDIOC_ENUM_FRAMESIZES"}, // From linux/videodev2.h
			{Val: 3225441893, Str: "VIDIOC_ENUM_FREQ_BANDS"}, // From linux/videodev2.h
			{Val: 3225441808, Str: "VIDIOC_EXPBUF"}, // From linux/videodev2.h
			{Val: 2150913569, Str: "VIDIOC_G_AUDIO"}, // From linux/videodev2.h
			{Val: 2150913585, Str: "VIDIOC_G_AUDOUT"}, // From linux/videodev2.h
			{Val: 3222558267, Str: "VIDIOC_G_CROP"}, // From linux/videodev2.h
			{Val: 3221771803, Str: "VIDIOC_G_CTRL"}, // From linux/videodev2.h
			{Val: 3229898328, Str: "VIDIOC_G_DV_TIMINGS"}, // From linux/videodev2.h
			{Val: 3223868968, Str: "VIDIOC_G_EDID"}, // From linux/videodev2.h
			{Val: 2283296332, Str: "VIDIOC_G_ENC_INDEX"}, // From linux/videodev2.h
			{Val: 3223344711, Str: "VIDIOC_G_EXT_CTRLS"}, // From linux/videodev2.h
			{Val: 2150651402, Str: "VIDIOC_G_FBUF"}, // From linux/videodev2.h
			{Val: 3234878980, Str: "VIDIOC_G_FMT"}, // From linux/videodev2.h
			{Val: 3224131128, Str: "VIDIOC_G_FREQUENCY"}, // From linux/videodev2.h
			{Val: 2147767846, Str: "VIDIOC_G_INPUT"}, // From linux/videodev2.h
			{Val: 2156680765, Str: "VIDIOC_G_JPEGCOMP"}, // From linux/videodev2.h
			{Val: 3225703990, Str: "VIDIOC_G_MODULATOR"}, // From linux/videodev2.h
			{Val: 2147767854, Str: "VIDIOC_G_OUTPUT"}, // From linux/videodev2.h
			{Val: 3234616853, Str: "VIDIOC_G_PARM"}, // From linux/videodev2.h
			{Val: 2147767875, Str: "VIDIOC_G_PRIORITY"}, // From linux/videodev2.h
			{Val: 3225441886, Str: "VIDIOC_G_SELECTION"}, // From linux/videodev2.h
			{Val: 3228849733, Str: "VIDIOC_G_SLICED_VBI_CAP"}, // From linux/videodev2.h
			{Val: 2148029975, Str: "VIDIOC_G_STD"}, // From linux/videodev2.h
			{Val: 3226752541, Str: "VIDIOC_G_TUNER"}, // From linux/videodev2.h
			{Val: 22086, Str: "VIDIOC_LOG_STATUS"}, // From linux/videodev2.h
			{Val: 1074025998, Str: "VIDIOC_OVERLAY"}, // From linux/videodev2.h
			{Val: 3227014749, Str: "VIDIOC_PREPARE_BUF"}, // From linux/videodev2.h
			{Val: 3227014671, Str: "VIDIOC_QBUF"}, // From linux/videodev2.h
			{Val: 3227014665, Str: "VIDIOC_QUERYBUF"}, // From linux/videodev2.h
			{Val: 2154321408, Str: "VIDIOC_QUERYCAP"}, // From linux/videodev2.h
			{Val: 3225703972, Str: "VIDIOC_QUERYCTRL"}, // From linux/videodev2.h
			{Val: 3224131109, Str: "VIDIOC_QUERYMENU"}, // From linux/videodev2.h
			{Val: 2148030015, Str: "VIDIOC_QUERYSTD"}, // From linux/videodev2.h
			{Val: 2156156515, Str: "VIDIOC_QUERY_DV_TIMINGS"}, // From linux/videodev2.h
			{Val: 3236451943, Str: "VIDIOC_QUERY_EXT_CTRL"}, // From linux/videodev2.h
			{Val: 3225441896, Str: "VIDIOC_REMOVE_BUFS"}, // From linux/videodev2.h
			{Val: 3222558216, Str: "VIDIOC_REQBUFS"}, // From linux/videodev2.h
			{Val: 1074026003, Str: "VIDIOC_STREAMOFF"}, // From linux/videodev2.h
			{Val: 1074026002, Str: "VIDIOC_STREAMON"}, // From linux/videodev2.h
			{Val: 1075861082, Str: "VIDIOC_SUBSCRIBE_EVENT"}, // From linux/videodev2.h
			{Val: 1077171746, Str: "VIDIOC_S_AUDIO"}, // From linux/videodev2.h
			{Val: 1077171762, Str: "VIDIOC_S_AUDOUT"}, // From linux/videodev2.h
			{Val: 1075074620, Str: "VIDIOC_S_CROP"}, // From linux/videodev2.h
			{Val: 3221771804, Str: "VIDIOC_S_CTRL"}, // From linux/videodev2.h
			{Val: 3229898327, Str: "VIDIOC_S_DV_TIMINGS"}, // From linux/videodev2.h
			{Val: 3223868969, Str: "VIDIOC_S_EDID"}, // From linux/videodev2.h
			{Val: 3223344712, Str: "VIDIOC_S_EXT_CTRLS"}, // From linux/videodev2.h
			{Val: 1076909579, Str: "VIDIOC_S_FBUF"}, // From linux/videodev2.h
			{Val: 3234878981, Str: "VIDIOC_S_FMT"}, // From linux/videodev2.h
			{Val: 1076647481, Str: "VIDIOC_S_FREQUENCY"}, // From linux/videodev2.h
			{Val: 1076909650, Str: "VIDIOC_S_HW_FREQ_SEEK"}, // From linux/videodev2.h
			{Val: 3221509671, Str: "VIDIOC_S_INPUT"}, // From linux/videodev2.h
			{Val: 1082938942, Str: "VIDIOC_S_JPEGCOMP"}, // From linux/videodev2.h
			{Val: 1078220343, Str: "VIDIOC_S_MODULATOR"}, // From linux/videodev2.h
			{Val: 3221509679, Str: "VIDIOC_S_OUTPUT"}, // From linux/videodev2.h
			{Val: 3234616854, Str: "VIDIOC_S_PARM"}, // From linux/videodev2.h
			{Val: 1074026052, Str: "VIDIOC_S_PRIORITY"}, // From linux/videodev2.h
			{Val: 3225441887, Str: "VIDIOC_S_SELECTION"}, // From linux/videodev2.h
			{Val: 1074288152, Str: "VIDIOC_S_STD"}, // From linux/videodev2.h
			{Val: 1079268894, Str: "VIDIOC_S_TUNER"}, // From linux/videodev2.h
			{Val: 3225966177, Str: "VIDIOC_TRY_DECODER_CMD"}, // From linux/videodev2.h
			{Val: 3223869006, Str: "VIDIOC_TRY_ENCODER_CMD"}, // From linux/videodev2.h
			{Val: 3223344713, Str: "VIDIOC_TRY_EXT_CTRLS"}, // From linux/videodev2.h
			{Val: 3234879040, Str: "VIDIOC_TRY_FMT"}, // From linux/videodev2.h
			{Val: 1075861083, Str: "VIDIOC_UNSUBSCRIBE_EVENT"}, // From linux/videodev2.h
			{Val: 1977, Str: "IOCTL_VM_SOCKETS_GET_LOCAL_CID"}, // From linux/vm_sockets.h
			{Val: 1967, Str: "IOCTL_VMCI_CTX_ADD_NOTIFICATION"}, // From linux/vmw_vmci_defs.h
			{Val: 1969, Str: "IOCTL_VMCI_CTX_GET_CPT_STATE"}, // From linux/vmw_vmci_defs.h
			{Val: 1968, Str: "IOCTL_VMCI_CTX_REMOVE_NOTIFICATION"}, // From linux/vmw_vmci_defs.h
			{Val: 1970, Str: "IOCTL_VMCI_CTX_SET_CPT_STATE"}, // From linux/vmw_vmci_defs.h
			{Val: 1964, Str: "IOCTL_VMCI_DATAGRAM_RECEIVE"}, // From linux/vmw_vmci_defs.h
			{Val: 1963, Str: "IOCTL_VMCI_DATAGRAM_SEND"}, // From linux/vmw_vmci_defs.h
			{Val: 1971, Str: "IOCTL_VMCI_GET_CONTEXT_ID"}, // From linux/vmw_vmci_defs.h
			{Val: 1952, Str: "IOCTL_VMCI_INIT_CONTEXT"}, // From linux/vmw_vmci_defs.h
			{Val: 1958, Str: "IOCTL_VMCI_NOTIFICATIONS_RECEIVE"}, // From linux/vmw_vmci_defs.h
			{Val: 1957, Str: "IOCTL_VMCI_NOTIFY_RESOURCE"}, // From linux/vmw_vmci_defs.h
			{Val: 1960, Str: "IOCTL_VMCI_QUEUEPAIR_ALLOC"}, // From linux/vmw_vmci_defs.h
			{Val: 1962, Str: "IOCTL_VMCI_QUEUEPAIR_DETACH"}, // From linux/vmw_vmci_defs.h
			{Val: 1961, Str: "IOCTL_VMCI_QUEUEPAIR_SETPAGEFILE"}, // From linux/vmw_vmci_defs.h
			{Val: 1956, Str: "IOCTL_VMCI_QUEUEPAIR_SETVA"}, // From linux/vmw_vmci_defs.h
			{Val: 1995, Str: "IOCTL_VMCI_SET_NOTIFY"}, // From linux/vmw_vmci_defs.h
			{Val: 1951, Str: "IOCTL_VMCI_VERSION"}, // From linux/vmw_vmci_defs.h
			{Val: 1959, Str: "IOCTL_VMCI_VERSION2"}, // From linux/vmw_vmci_defs.h
			{Val: 22022, Str: "VT_ACTIVATE"}, // From linux/vt.h
			{Val: 22024, Str: "VT_DISALLOCATE"}, // From linux/vt.h
			{Val: 2148029968, Str: "VT_GETCONSIZECSRPOS"}, // From linux/vt.h
			{Val: 22029, Str: "VT_GETHIFONTMASK"}, // From linux/vt.h
			{Val: 22017, Str: "VT_GETMODE"}, // From linux/vt.h
			{Val: 22019, Str: "VT_GETSTATE"}, // From linux/vt.h
			{Val: 22027, Str: "VT_LOCKSWITCH"}, // From linux/vt.h
			{Val: 22016, Str: "VT_OPENQRY"}, // From linux/vt.h
			{Val: 22021, Str: "VT_RELDISP"}, // From linux/vt.h
			{Val: 22025, Str: "VT_RESIZE"}, // From linux/vt.h
			{Val: 22026, Str: "VT_RESIZEX"}, // From linux/vt.h
			{Val: 22020, Str: "VT_SENDSIG"}, // From linux/vt.h
			{Val: 22031, Str: "VT_SETACTIVATE"}, // From linux/vt.h
			{Val: 22018, Str: "VT_SETMODE"}, // From linux/vt.h
			{Val: 22028, Str: "VT_UNLOCKSWITCH"}, // From linux/vt.h
			{Val: 22023, Str: "VT_WAITACTIVE"}, // From linux/vt.h
			{Val: 22030, Str: "VT_WAITEVENT"}, // From linux/vt.h
			{Val: 3222577408, Str: "VTPM_PROXY_IOC_NEW_DEV"}, // From linux/vtpm_proxy.h
			{Val: 22369, Str: "IOC_WATCH_QUEUE_SET_FILTER"}, // From linux/watch_queue.h
			{Val: 22368, Str: "IOC_WATCH_QUEUE_SET_SIZE"}, // From linux/watch_queue.h
			{Val: 2147768066, Str: "WDIOC_GETBOOTSTATUS"}, // From linux/watchdog.h
			{Val: 2147768073, Str: "WDIOC_GETPRETIMEOUT"}, // From linux/watchdog.h
			{Val: 2147768065, Str: "WDIOC_GETSTATUS"}, // From linux/watchdog.h
			{Val: 2150127360, Str: "WDIOC_GETSUPPORT"}, // From linux/watchdog.h
			{Val: 2147768067, Str: "WDIOC_GETTEMP"}, // From linux/watchdog.h
			{Val: 2147768074, Str: "WDIOC_GETTIMELEFT"}, // From linux/watchdog.h
			{Val: 2147768071, Str: "WDIOC_GETTIMEOUT"}, // From linux/watchdog.h
			{Val: 2147768069, Str: "WDIOC_KEEPALIVE"}, // From linux/watchdog.h
			{Val: 2147768068, Str: "WDIOC_SETOPTIONS"}, // From linux/watchdog.h
			{Val: 3221509896, Str: "WDIOC_SETPRETIMEOUT"}, // From linux/watchdog.h
			{Val: 3221509894, Str: "WDIOC_SETTIMEOUT"}, // From linux/watchdog.h
			{Val: 35605, Str: "SIOCGIWAP"}, // From linux/wireless.h
			{Val: 35607, Str: "SIOCGIWAPLIST"}, // From linux/wireless.h
			{Val: 35635, Str: "SIOCGIWAUTH"}, // From linux/wireless.h
			{Val: 35627, Str: "SIOCGIWENCODE"}, // From linux/wireless.h
			{Val: 35637, Str: "SIOCGIWENCODEEXT"}, // From linux/wireless.h
			{Val: 35611, Str: "SIOCGIWESSID"}, // From linux/wireless.h
			{Val: 35621, Str: "SIOCGIWFRAG"}, // From linux/wireless.h
			{Val: 35589, Str: "SIOCGIWFREQ"}, // From linux/wireless.h
			{Val: 35633, Str: "SIOCGIWGENIE"}, // From linux/wireless.h
			{Val: 35591, Str: "SIOCGIWMODE"}, // From linux/wireless.h
			{Val: 35585, Str: "SIOCGIWNAME"}, // From linux/wireless.h
			{Val: 35613, Str: "SIOCGIWNICKN"}, // From linux/wireless.h
			{Val: 35587, Str: "SIOCGIWNWID"}, // From linux/wireless.h
			{Val: 35629, Str: "SIOCGIWPOWER"}, // From linux/wireless.h
			{Val: 35597, Str: "SIOCGIWPRIV"}, // From linux/wireless.h
			{Val: 35595, Str: "SIOCGIWRANGE"}, // From linux/wireless.h
			{Val: 35617, Str: "SIOCGIWRATE"}, // From linux/wireless.h
			{Val: 35625, Str: "SIOCGIWRETRY"}, // From linux/wireless.h
			{Val: 35619, Str: "SIOCGIWRTS"}, // From linux/wireless.h
			{Val: 35609, Str: "SIOCGIWSCAN"}, // From linux/wireless.h
			{Val: 35593, Str: "SIOCGIWSENS"}, // From linux/wireless.h
			{Val: 35601, Str: "SIOCGIWSPY"}, // From linux/wireless.h
			{Val: 35599, Str: "SIOCGIWSTATS"}, // From linux/wireless.h
			{Val: 35603, Str: "SIOCGIWTHRSPY"}, // From linux/wireless.h
			{Val: 35623, Str: "SIOCGIWTXPOW"}, // From linux/wireless.h
			{Val: 35584, Str: "SIOCIWFIRST"}, // From linux/wireless.h
			{Val: 35808, Str: "SIOCIWFIRSTPRIV"}, // From linux/wireless.h
			{Val: 35839, Str: "SIOCIWLASTPRIV"}, // From linux/wireless.h
			{Val: 35604, Str: "SIOCSIWAP"}, // From linux/wireless.h
			{Val: 35634, Str: "SIOCSIWAUTH"}, // From linux/wireless.h
			{Val: 35584, Str: "SIOCSIWCOMMIT"}, // From linux/wireless.h
			{Val: 35626, Str: "SIOCSIWENCODE"}, // From linux/wireless.h
			{Val: 35636, Str: "SIOCSIWENCODEEXT"}, // From linux/wireless.h
			{Val: 35610, Str: "SIOCSIWESSID"}, // From linux/wireless.h
			{Val: 35620, Str: "SIOCSIWFRAG"}, // From linux/wireless.h
			{Val: 35588, Str: "SIOCSIWFREQ"}, // From linux/wireless.h
			{Val: 35632, Str: "SIOCSIWGENIE"}, // From linux/wireless.h
			{Val: 35606, Str: "SIOCSIWMLME"}, // From linux/wireless.h
			{Val: 35590, Str: "SIOCSIWMODE"}, // From linux/wireless.h
			{Val: 35612, Str: "SIOCSIWNICKN"}, // From linux/wireless.h
			{Val: 35586, Str: "SIOCSIWNWID"}, // From linux/wireless.h
			{Val: 35638, Str: "SIOCSIWPMKSA"}, // From linux/wireless.h
			{Val: 35628, Str: "SIOCSIWPOWER"}, // From linux/wireless.h
			{Val: 35596, Str: "SIOCSIWPRIV"}, // From linux/wireless.h
			{Val: 35594, Str: "SIOCSIWRANGE"}, // From linux/wireless.h
			{Val: 35616, Str: "SIOCSIWRATE"}, // From linux/wireless.h
			{Val: 35624, Str: "SIOCSIWRETRY"}, // From linux/wireless.h
			{Val: 35618, Str: "SIOCSIWRTS"}, // From linux/wireless.h
			{Val: 35608, Str: "SIOCSIWSCAN"}, // From linux/wireless.h
			{Val: 35592, Str: "SIOCSIWSENS"}, // From linux/wireless.h
			{Val: 35600, Str: "SIOCSIWSPY"}, // From linux/wireless.h
			{Val: 35598, Str: "SIOCSIWSTATS"}, // From linux/wireless.h
			{Val: 35602, Str: "SIOCSIWTHRSPY"}, // From linux/wireless.h
			{Val: 35622, Str: "SIOCSIWTXPOW"}, // From linux/wireless.h
			{Val: 3224655616, Str: "DELL_WMI_SMBIOS_CMD"}, // From linux/wmi.h
			{Val: 25856, Str: "S5P_FIMC_TX_END_NOTIFY"}, // From media/drv-intf/exynos-fimc.h
			{Val: 22208, Str: "ADV7842_CMD_RAM_TEST"}, // From media/i2c/adv7842.h
			{Val: 25089, Str: "BT819_FIFO_RESET_HIGH"}, // From media/i2c/bt819.h
			{Val: 25088, Str: "BT819_FIFO_RESET_LOW"}, // From media/i2c/bt819.h
			{Val: 1074024962, Str: "SAA6588_CMD_CLOSE"}, // From media/i2c/saa6588.h
			{Val: 2147766788, Str: "SAA6588_CMD_POLL"}, // From media/i2c/saa6588.h
			{Val: 2147766787, Str: "SAA6588_CMD_READ"}, // From media/i2c/saa6588.h
			{Val: 1074816092, Str: "TUNER_SET_CONFIG"}, // From media/v4l2-common.h
			{Val: 1074029670, Str: "VIDIOC_INT_RESET"}, // From media/v4l2-common.h
			{Val: 3226490385, Str: "VIDIOC_DQBUF_TIME32"}, // From media/v4l2-ioctl.h
			{Val: 2155894361, Str: "VIDIOC_DQEVENT_TIME32"}, // From media/v4l2-ioctl.h
			{Val: 3226490461, Str: "VIDIOC_PREPARE_BUF_TIME32"}, // From media/v4l2-ioctl.h
			{Val: 3226490383, Str: "VIDIOC_QBUF_TIME32"}, // From media/v4l2-ioctl.h
			{Val: 3226490377, Str: "VIDIOC_QUERYBUF_TIME32"}, // From media/v4l2-ioctl.h
			{Val: 1082684930, Str: "V4L2_DEVICE_NOTIFY_EVENT"}, // From media/v4l2-subdev.h
			{Val: 1074034176, Str: "V4L2_SUBDEV_IR_RX_NOTIFY"}, // From media/v4l2-subdev.h
			{Val: 1074034177, Str: "V4L2_SUBDEV_IR_TX_NOTIFY"}, // From media/v4l2-subdev.h
			{Val: 3222337793, Str: "SBRMI_IOCTL_CPUID_CMD"}, // From misc/amd-apml.h
			{Val: 3222075648, Str: "SBRMI_IOCTL_MBOX_CMD"}, // From misc/amd-apml.h
			{Val: 3222337794, Str: "SBRMI_IOCTL_MCAMSR_CMD"}, // From misc/amd-apml.h
			{Val: 3221551363, Str: "SBRMI_IOCTL_REG_XFER_CMD"}, // From misc/amd-apml.h
			{Val: 3222295041, Str: "FASTRPC_IOCTL_ALLOC_DMA_BUFF"}, // From misc/fastrpc.h
			{Val: 3221508610, Str: "FASTRPC_IOCTL_FREE_DMA_BUFF"}, // From misc/fastrpc.h
			{Val: 3223081485, Str: "FASTRPC_IOCTL_GET_DSP_INFO"}, // From misc/fastrpc.h
			{Val: 20996, Str: "FASTRPC_IOCTL_INIT_ATTACH"}, // From misc/fastrpc.h
			{Val: 21000, Str: "FASTRPC_IOCTL_INIT_ATTACH_SNS"}, // From misc/fastrpc.h
			{Val: 3222819333, Str: "FASTRPC_IOCTL_INIT_CREATE"}, // From misc/fastrpc.h
			{Val: 3222295049, Str: "FASTRPC_IOCTL_INIT_CREATE_STATIC"}, // From misc/fastrpc.h
			{Val: 3222295043, Str: "FASTRPC_IOCTL_INVOKE"}, // From misc/fastrpc.h
			{Val: 3225440778, Str: "FASTRPC_IOCTL_MEM_MAP"}, // From misc/fastrpc.h
			{Val: 3224392203, Str: "FASTRPC_IOCTL_MEM_UNMAP"}, // From misc/fastrpc.h
			{Val: 3223343622, Str: "FASTRPC_IOCTL_MMAP"}, // From misc/fastrpc.h
			{Val: 3222295047, Str: "FASTRPC_IOCTL_MUNMAP"}, // From misc/fastrpc.h
			{Val: 1075361794, Str: "DPI_ENGINE_CFG"}, // From misc/mrvl_cn10k_dpi.h
			{Val: 1074313217, Str: "DPI_MPS_MRRS_CFG"}, // From misc/mrvl_cn10k_dpi.h
			{Val: 1075890704, Str: "OCXL_IOCTL_ATTACH"}, // From misc/ocxl.h
			{Val: 2149632533, Str: "OCXL_IOCTL_ENABLE_P9_WAIT"}, // From misc/ocxl.h
			{Val: 2149632534, Str: "OCXL_IOCTL_GET_FEATURES"}, // From misc/ocxl.h
			{Val: 2155923988, Str: "OCXL_IOCTL_GET_METADATA"}, // From misc/ocxl.h
			{Val: 2148059665, Str: "OCXL_IOCTL_IRQ_ALLOC"}, // From misc/ocxl.h
			{Val: 1074317842, Str: "OCXL_IOCTL_IRQ_FREE"}, // From misc/ocxl.h
			{Val: 1074842131, Str: "OCXL_IOCTL_IRQ_SET_FD"}, // From misc/ocxl.h
			{Val: 3221506058, Str: "UACCE_CMD_QM_SET_QP_CTX"}, // From misc/uacce/hisi_qm.h
			{Val: 3222292491, Str: "UACCE_CMD_QM_SET_QP_INFO"}, // From misc/uacce/hisi_qm.h
			{Val: 22273, Str: "UACCE_CMD_PUT_Q"}, // From misc/uacce/uacce.h
			{Val: 22272, Str: "UACCE_CMD_START_Q"}, // From misc/uacce/uacce.h
			{Val: 1080059397, Str: "XSDFEC_ADD_LDPC_CODE_PARAMS"}, // From misc/xilinx_sdfec.h
			{Val: 26123, Str: "XSDFEC_CLEAR_STATS"}, // From misc/xilinx_sdfec.h
			{Val: 2149344774, Str: "XSDFEC_GET_CONFIG"}, // From misc/xilinx_sdfec.h
			{Val: 2148296204, Str: "XSDFEC_GET_STATS"}, // From misc/xilinx_sdfec.h
			{Val: 2148034050, Str: "XSDFEC_GET_STATUS"}, // From misc/xilinx_sdfec.h
			{Val: 2148034055, Str: "XSDFEC_GET_TURBO"}, // From misc/xilinx_sdfec.h
			{Val: 2147575306, Str: "XSDFEC_IS_ACTIVE"}, // From misc/xilinx_sdfec.h
			{Val: 1073833481, Str: "XSDFEC_SET_BYPASS"}, // From misc/xilinx_sdfec.h
			{Val: 26125, Str: "XSDFEC_SET_DEFAULT_CONFIG"}, // From misc/xilinx_sdfec.h
			{Val: 1073899011, Str: "XSDFEC_SET_IRQ"}, // From misc/xilinx_sdfec.h
			{Val: 1074292232, Str: "XSDFEC_SET_ORDER"}, // From misc/xilinx_sdfec.h
			{Val: 1074292228, Str: "XSDFEC_SET_TURBO"}, // From misc/xilinx_sdfec.h
			{Val: 26112, Str: "XSDFEC_START_DEV"}, // From misc/xilinx_sdfec.h
			{Val: 26113, Str: "XSDFEC_STOP_DEV"}, // From misc/xilinx_sdfec.h
			{Val: 2168999185, Str: "ECCGETLAYOUT"}, // From mtd/mtd-abi.h
			{Val: 2148551954, Str: "ECCGETSTATS"}, // From mtd/mtd-abi.h
			{Val: 1074285826, Str: "MEMERASE"}, // From mtd/mtd-abi.h
			{Val: 1074810132, Str: "MEMERASE64"}, // From mtd/mtd-abi.h
			{Val: 1074285835, Str: "MEMGETBADBLOCK"}, // From mtd/mtd-abi.h
			{Val: 2149600513, Str: "MEMGETINFO"}, // From mtd/mtd-abi.h
			{Val: 2160610570, Str: "MEMGETOOBSEL"}, // From mtd/mtd-abi.h
			{Val: 2147765511, Str: "MEMGETREGIONCOUNT"}, // From mtd/mtd-abi.h
			{Val: 3222293768, Str: "MEMGETREGIONINFO"}, // From mtd/mtd-abi.h
			{Val: 2148027671, Str: "MEMISLOCKED"}, // From mtd/mtd-abi.h
			{Val: 1074285829, Str: "MEMLOCK"}, // From mtd/mtd-abi.h
			{Val: 3225439514, Str: "MEMREAD"}, // From mtd/mtd-abi.h
			{Val: 3222293764, Str: "MEMREADOOB"}, // From mtd/mtd-abi.h
			{Val: 3222818070, Str: "MEMREADOOB64"}, // From mtd/mtd-abi.h
			{Val: 1074285836, Str: "MEMSETBADBLOCK"}, // From mtd/mtd-abi.h
			{Val: 1074285830, Str: "MEMUNLOCK"}, // From mtd/mtd-abi.h
			{Val: 3224390936, Str: "MEMWRITE"}, // From mtd/mtd-abi.h
			{Val: 3222293763, Str: "MEMWRITEOOB"}, // From mtd/mtd-abi.h
			{Val: 3222818069, Str: "MEMWRITEOOB64"}, // From mtd/mtd-abi.h
			{Val: 19731, Str: "MTDFILEMODE"}, // From mtd/mtd-abi.h
			{Val: 1074547993, Str: "OTPERASE"}, // From mtd/mtd-abi.h
			{Val: 1074023694, Str: "OTPGETREGIONCOUNT"}, // From mtd/mtd-abi.h
			{Val: 1074547983, Str: "OTPGETREGIONINFO"}, // From mtd/mtd-abi.h
			{Val: 2148289808, Str: "OTPLOCK"}, // From mtd/mtd-abi.h
			{Val: 2147765517, Str: "OTPSELECT"}, // From mtd/mtd-abi.h
			{Val: 1075343168, Str: "UBI_IOCATT"}, // From mtd/ubi-user.h
			{Val: 1074032449, Str: "UBI_IOCDET"}, // From mtd/ubi-user.h
			{Val: 1074024194, Str: "UBI_IOCEBCH"}, // From mtd/ubi-user.h
			{Val: 1074024193, Str: "UBI_IOCEBER"}, // From mtd/ubi-user.h
			{Val: 2147766021, Str: "UBI_IOCEBISMAP"}, // From mtd/ubi-user.h
			{Val: 1074286339, Str: "UBI_IOCEBMAP"}, // From mtd/ubi-user.h
			{Val: 1074024196, Str: "UBI_IOCEBUNMAP"}, // From mtd/ubi-user.h
			{Val: 3223088902, Str: "UBI_IOCECNFO"}, // From mtd/ubi-user.h
			{Val: 1083731712, Str: "UBI_IOCMKVOL"}, // From mtd/ubi-user.h
			{Val: 1074032385, Str: "UBI_IOCRMVOL"}, // From mtd/ubi-user.h
			{Val: 1360031491, Str: "UBI_IOCRNVOL"}, // From mtd/ubi-user.h
			{Val: 1074032388, Str: "UBI_IOCRPEB"}, // From mtd/ubi-user.h
			{Val: 1074556674, Str: "UBI_IOCRSVOL"}, // From mtd/ubi-user.h
			{Val: 1074810630, Str: "UBI_IOCSETVOLPROP"}, // From mtd/ubi-user.h
			{Val: 1074032389, Str: "UBI_IOCSPEB"}, // From mtd/ubi-user.h
			{Val: 1082150663, Str: "UBI_IOCVOLCRBLK"}, // From mtd/ubi-user.h
			{Val: 20232, Str: "UBI_IOCVOLRMBLK"}, // From mtd/ubi-user.h
			{Val: 1074286336, Str: "UBI_IOCVOLUP"}, // From mtd/ubi-user.h
			{Val: 1074022630, Str: "HCIBLOCKADDR"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022602, Str: "HCIDEVDOWN"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022603, Str: "HCIDEVRESET"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022604, Str: "HCIDEVRESTAT"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022601, Str: "HCIDEVUP"}, // From net/bluetooth/hci_sock.h
			{Val: 2147764439, Str: "HCIGETAUTHINFO"}, // From net/bluetooth/hci_sock.h
			{Val: 2147764437, Str: "HCIGETCONNINFO"}, // From net/bluetooth/hci_sock.h
			{Val: 2147764436, Str: "HCIGETCONNLIST"}, // From net/bluetooth/hci_sock.h
			{Val: 2147764435, Str: "HCIGETDEVINFO"}, // From net/bluetooth/hci_sock.h
			{Val: 2147764434, Str: "HCIGETDEVLIST"}, // From net/bluetooth/hci_sock.h
			{Val: 2147764464, Str: "HCIINQUIRY"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022627, Str: "HCISETACLMTU"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022622, Str: "HCISETAUTH"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022623, Str: "HCISETENCRYPT"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022626, Str: "HCISETLINKMODE"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022625, Str: "HCISETLINKPOL"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022624, Str: "HCISETPTYPE"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022620, Str: "HCISETRAW"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022621, Str: "HCISETSCAN"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022628, Str: "HCISETSCOMTU"}, // From net/bluetooth/hci_sock.h
			{Val: 1074022631, Str: "HCIUNBLOCKADDR"}, // From net/bluetooth/hci_sock.h
			{Val: 1074025160, Str: "RFCOMMCREATEDEV"}, // From net/bluetooth/rfcomm.h
			{Val: 2147766995, Str: "RFCOMMGETDEVINFO"}, // From net/bluetooth/rfcomm.h
			{Val: 2147766994, Str: "RFCOMMGETDEVLIST"}, // From net/bluetooth/rfcomm.h
			{Val: 1074025161, Str: "RFCOMMRELEASEDEV"}, // From net/bluetooth/rfcomm.h
			{Val: 1074025180, Str: "RFCOMMSTEALDLC"}, // From net/bluetooth/rfcomm.h
			{Val: 1074287872, Str: "NCIUARTSETDRIVER"}, // From net/nfc/nci_core.h
			{Val: 1074273258, Str: "HFI1_IOCTL_ACK_EVENT"}, // From rdma/rdma_user_ioctl.h
			{Val: 3223067617, Str: "HFI1_IOCTL_ASSIGN_CTXT"}, // From rdma/rdma_user_ioctl.h
			{Val: 7142, Str: "HFI1_IOCTL_CREDIT_UPD"}, // From rdma/rdma_user_ioctl.h
			{Val: 1076370402, Str: "HFI1_IOCTL_CTXT_INFO"}, // From rdma/rdma_user_ioctl.h
			{Val: 7148, Str: "HFI1_IOCTL_CTXT_RESET"}, // From rdma/rdma_user_ioctl.h
			{Val: 2147752942, Str: "HFI1_IOCTL_GET_VERS"}, // From rdma/rdma_user_ioctl.h
			{Val: 1074011113, Str: "HFI1_IOCTL_POLL_TYPE"}, // From rdma/rdma_user_ioctl.h
			{Val: 1074011112, Str: "HFI1_IOCTL_RECV_CTRL"}, // From rdma/rdma_user_ioctl.h
			{Val: 1073880043, Str: "HFI1_IOCTL_SET_PKEY"}, // From rdma/rdma_user_ioctl.h
			{Val: 3222805477, Str: "HFI1_IOCTL_TID_FREE"}, // From rdma/rdma_user_ioctl.h
			{Val: 3222805485, Str: "HFI1_IOCTL_TID_INVAL_READ"}, // From rdma/rdma_user_ioctl.h
			{Val: 3222805476, Str: "HFI1_IOCTL_TID_UPDATE"}, // From rdma/rdma_user_ioctl.h
			{Val: 1081613283, Str: "HFI1_IOCTL_USER_INFO"}, // From rdma/rdma_user_ioctl.h
			{Val: 6915, Str: "IB_USER_MAD_ENABLE_PKEY"}, // From rdma/rdma_user_ioctl.h
			{Val: 3223067393, Str: "IB_USER_MAD_REGISTER_AGENT"}, // From rdma/rdma_user_ioctl.h
			{Val: 3223853828, Str: "IB_USER_MAD_REGISTER_AGENT2"}, // From rdma/rdma_user_ioctl.h
			{Val: 1074010882, Str: "IB_USER_MAD_UNREGISTER_AGENT"}, // From rdma/rdma_user_ioctl.h
			{Val: 3222805249, Str: "RDMA_VERBS_IOCTL"}, // From rdma/rdma_user_ioctl_cmds.h
			{Val: 21382, Str: "SCSI_IOCTL_GET_BUS_NUMBER"}, // From scsi/scsi.h
			{Val: 21378, Str: "SCSI_IOCTL_GET_IDLUN"}, // From scsi/scsi.h
			{Val: 21383, Str: "SCSI_IOCTL_GET_PCI"}, // From scsi/scsi.h
			{Val: 21381, Str: "SCSI_IOCTL_PROBE_HOST"}, // From scsi/scsi.h
			{Val: 21376, Str: "SCSI_IOCTL_DOORLOCK"}, // From scsi/scsi_ioctl.h
			{Val: 21377, Str: "SCSI_IOCTL_DOORUNLOCK"}, // From scsi/scsi_ioctl.h
			{Val: 8707, Str: "SG_EMULATED_HOST"}, // From scsi/sg.h
			{Val: 8841, Str: "SG_GET_ACCESS_COUNT"}, // From scsi/sg.h
			{Val: 8816, Str: "SG_GET_COMMAND_Q"}, // From scsi/sg.h
			{Val: 8840, Str: "SG_GET_KEEP_ORPHAN"}, // From scsi/sg.h
			{Val: 8826, Str: "SG_GET_LOW_DMA"}, // From scsi/sg.h
			{Val: 8829, Str: "SG_GET_NUM_WAITING"}, // From scsi/sg.h
			{Val: 8828, Str: "SG_GET_PACK_ID"}, // From scsi/sg.h
			{Val: 8838, Str: "SG_GET_REQUEST_TABLE"}, // From scsi/sg.h
			{Val: 8818, Str: "SG_GET_RESERVED_SIZE"}, // From scsi/sg.h
			{Val: 8822, Str: "SG_GET_SCSI_ID"}, // From scsi/sg.h
			{Val: 8831, Str: "SG_GET_SG_TABLESIZE"}, // From scsi/sg.h
			{Val: 8706, Str: "SG_GET_TIMEOUT"}, // From scsi/sg.h
			{Val: 8709, Str: "SG_GET_TRANSFORM"}, // From scsi/sg.h
			{Val: 8834, Str: "SG_GET_VERSION_NUM"}, // From scsi/sg.h
			{Val: 8837, Str: "SG_IO"}, // From scsi/sg.h
			{Val: 8835, Str: "SG_NEXT_CMD_LEN"}, // From scsi/sg.h
			{Val: 8836, Str: "SG_SCSI_RESET"}, // From scsi/sg.h
			{Val: 8817, Str: "SG_SET_COMMAND_Q"}, // From scsi/sg.h
			{Val: 8830, Str: "SG_SET_DEBUG"}, // From scsi/sg.h
			{Val: 8825, Str: "SG_SET_FORCE_LOW_DMA"}, // From scsi/sg.h
			{Val: 8827, Str: "SG_SET_FORCE_PACK_ID"}, // From scsi/sg.h
			{Val: 8839, Str: "SG_SET_KEEP_ORPHAN"}, // From scsi/sg.h
			{Val: 8821, Str: "SG_SET_RESERVED_SIZE"}, // From scsi/sg.h
			{Val: 8705, Str: "SG_SET_TIMEOUT"}, // From scsi/sg.h
			{Val: 8708, Str: "SG_SET_TRANSFORM"}, // From scsi/sg.h
			{Val: 2147767041, Str: "SNDRV_SEQ_IOCTL_CLIENT_ID"}, // From sound/asequencer.h
			{Val: 3232256800, Str: "SNDRV_SEQ_IOCTL_CREATE_PORT"}, // From sound/asequencer.h
			{Val: 3230421810, Str: "SNDRV_SEQ_IOCTL_CREATE_QUEUE"}, // From sound/asequencer.h
			{Val: 1084773153, Str: "SNDRV_SEQ_IOCTL_DELETE_PORT"}, // From sound/asequencer.h
			{Val: 1082938163, Str: "SNDRV_SEQ_IOCTL_DELETE_QUEUE"}, // From sound/asequencer.h
			{Val: 3233567504, Str: "SNDRV_SEQ_IOCTL_GET_CLIENT_INFO"}, // From sound/asequencer.h
			{Val: 3227013963, Str: "SNDRV_SEQ_IOCTL_GET_CLIENT_POOL"}, // From sound/asequencer.h
			{Val: 3255325458, Str: "SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO"}, // From sound/asequencer.h
			{Val: 3230421814, Str: "SNDRV_SEQ_IOCTL_GET_NAMED_QUEUE"}, // From sound/asequencer.h
			{Val: 3232256802, Str: "SNDRV_SEQ_IOCTL_GET_PORT_INFO"}, // From sound/asequencer.h
			{Val: 3226227529, Str: "SNDRV_SEQ_IOCTL_GET_QUEUE_CLIENT"}, // From sound/asequencer.h
			{Val: 3230421812, Str: "SNDRV_SEQ_IOCTL_GET_QUEUE_INFO"}, // From sound/asequencer.h
			{Val: 3227276096, Str: "SNDRV_SEQ_IOCTL_GET_QUEUE_STATUS"}, // From sound/asequencer.h
			{Val: 3224130369, Str: "SNDRV_SEQ_IOCTL_GET_QUEUE_TEMPO"}, // From sound/asequencer.h
			{Val: 3227538245, Str: "SNDRV_SEQ_IOCTL_GET_QUEUE_TIMER"}, // From sound/asequencer.h
			{Val: 3226489680, Str: "SNDRV_SEQ_IOCTL_GET_SUBSCRIPTION"}, // From sound/asequencer.h
			{Val: 2147767040, Str: "SNDRV_SEQ_IOCTL_PVERSION"}, // From sound/asequencer.h
			{Val: 3233567569, Str: "SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT"}, // From sound/asequencer.h
			{Val: 3232256850, Str: "SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT"}, // From sound/asequencer.h
			{Val: 3227013967, Str: "SNDRV_SEQ_IOCTL_QUERY_SUBS"}, // From sound/asequencer.h
			{Val: 1077957454, Str: "SNDRV_SEQ_IOCTL_REMOVE_EVENTS"}, // From sound/asequencer.h
			{Val: 3222295299, Str: "SNDRV_SEQ_IOCTL_RUNNING_MODE"}, // From sound/asequencer.h
			{Val: 1086083857, Str: "SNDRV_SEQ_IOCTL_SET_CLIENT_INFO"}, // From sound/asequencer.h
			{Val: 1079530316, Str: "SNDRV_SEQ_IOCTL_SET_CLIENT_POOL"}, // From sound/asequencer.h
			{Val: 3255325459, Str: "SNDRV_SEQ_IOCTL_SET_CLIENT_UMP_INFO"}, // From sound/asequencer.h
			{Val: 1084773155, Str: "SNDRV_SEQ_IOCTL_SET_PORT_INFO"}, // From sound/asequencer.h
			{Val: 1078743882, Str: "SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT"}, // From sound/asequencer.h
			{Val: 3230421813, Str: "SNDRV_SEQ_IOCTL_SET_QUEUE_INFO"}, // From sound/asequencer.h
			{Val: 1076646722, Str: "SNDRV_SEQ_IOCTL_SET_QUEUE_TEMPO"}, // From sound/asequencer.h
			{Val: 1080054598, Str: "SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER"}, // From sound/asequencer.h
			{Val: 1079006000, Str: "SNDRV_SEQ_IOCTL_SUBSCRIBE_PORT"}, // From sound/asequencer.h
			{Val: 3224392450, Str: "SNDRV_SEQ_IOCTL_SYSTEM_INFO"}, // From sound/asequencer.h
			{Val: 1079006001, Str: "SNDRV_SEQ_IOCTL_UNSUBSCRIBE_PORT"}, // From sound/asequencer.h
			{Val: 1074025220, Str: "SNDRV_SEQ_IOCTL_USER_PVERSION"}, // From sound/asequencer.h
			{Val: 2172146945, Str: "SNDRV_CTL_IOCTL_CARD_INFO"}, // From sound/asound.h
			{Val: 3239073047, Str: "SNDRV_CTL_IOCTL_ELEM_ADD"}, // From sound/asound.h
			{Val: 3239073041, Str: "SNDRV_CTL_IOCTL_ELEM_INFO"}, // From sound/asound.h
			{Val: 3226490128, Str: "SNDRV_CTL_IOCTL_ELEM_LIST"}, // From sound/asound.h
			{Val: 1077957908, Str: "SNDRV_CTL_IOCTL_ELEM_LOCK"}, // From sound/asound.h
			{Val: 3301463314, Str: "SNDRV_CTL_IOCTL_ELEM_READ"}, // From sound/asound.h
			{Val: 3225441561, Str: "SNDRV_CTL_IOCTL_ELEM_REMOVE"}, // From sound/asound.h
			{Val: 3239073048, Str: "SNDRV_CTL_IOCTL_ELEM_REPLACE"}, // From sound/asound.h
			{Val: 1077957909, Str: "SNDRV_CTL_IOCTL_ELEM_UNLOCK"}, // From sound/asound.h
			{Val: 3301463315, Str: "SNDRV_CTL_IOCTL_ELEM_WRITE"}, // From sound/asound.h
			{Val: 2161923361, Str: "SNDRV_CTL_IOCTL_HWDEP_INFO"}, // From sound/asound.h
			{Val: 3221509408, Str: "SNDRV_CTL_IOCTL_HWDEP_NEXT_DEVICE"}, // From sound/asound.h
			{Val: 3240121649, Str: "SNDRV_CTL_IOCTL_PCM_INFO"}, // From sound/asound.h
			{Val: 2147767600, Str: "SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE"}, // From sound/asound.h
			{Val: 1074025778, Str: "SNDRV_CTL_IOCTL_PCM_PREFER_SUBDEVICE"}, // From sound/asound.h
			{Val: 3221509584, Str: "SNDRV_CTL_IOCTL_POWER"}, // From sound/asound.h
			{Val: 2147767761, Str: "SNDRV_CTL_IOCTL_POWER_STATE"}, // From sound/asound.h
			{Val: 2147767552, Str: "SNDRV_CTL_IOCTL_PVERSION"}, // From sound/asound.h
			{Val: 3238810945, Str: "SNDRV_CTL_IOCTL_RAWMIDI_INFO"}, // From sound/asound.h
			{Val: 3221509440, Str: "SNDRV_CTL_IOCTL_RAWMIDI_NEXT_DEVICE"}, // From sound/asound.h
			{Val: 1074025794, Str: "SNDRV_CTL_IOCTL_RAWMIDI_PREFER_SUBDEVICE"}, // From sound/asound.h
			{Val: 3221509398, Str: "SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS"}, // From sound/asound.h
			{Val: 3221771548, Str: "SNDRV_CTL_IOCTL_TLV_COMMAND"}, // From sound/asound.h
			{Val: 3221771546, Str: "SNDRV_CTL_IOCTL_TLV_READ"}, // From sound/asound.h
			{Val: 3221771547, Str: "SNDRV_CTL_IOCTL_TLV_WRITE"}, // From sound/asound.h
			{Val: 3233043781, Str: "SNDRV_CTL_IOCTL_UMP_BLOCK_INFO"}, // From sound/asound.h
			{Val: 3242743108, Str: "SNDRV_CTL_IOCTL_UMP_ENDPOINT_INFO"}, // From sound/asound.h
			{Val: 3221509443, Str: "SNDRV_CTL_IOCTL_UMP_NEXT_DEVICE"}, // From sound/asound.h
			{Val: 1080051715, Str: "SNDRV_HWDEP_IOCTL_DSP_LOAD"}, // From sound/asound.h
			{Val: 2151696386, Str: "SNDRV_HWDEP_IOCTL_DSP_STATUS"}, // From sound/asound.h
			{Val: 2161920001, Str: "SNDRV_HWDEP_IOCTL_INFO"}, // From sound/asound.h
			{Val: 2147764224, Str: "SNDRV_HWDEP_IOCTL_PVERSION"}, // From sound/asound.h
			{Val: 2149073202, Str: "SNDRV_PCM_IOCTL_CHANNEL_INFO"}, // From sound/asound.h
			{Val: 2148024609, Str: "SNDRV_PCM_IOCTL_DELAY"}, // From sound/asound.h
			{Val: 16708, Str: "SNDRV_PCM_IOCTL_DRAIN"}, // From sound/asound.h
			{Val: 16707, Str: "SNDRV_PCM_IOCTL_DROP"}, // From sound/asound.h
			{Val: 1074282825, Str: "SNDRV_PCM_IOCTL_FORWARD"}, // From sound/asound.h
			{Val: 16674, Str: "SNDRV_PCM_IOCTL_HWSYNC"}, // From sound/asound.h
			{Val: 16658, Str: "SNDRV_PCM_IOCTL_HW_FREE"}, // From sound/asound.h
			{Val: 3261088017, Str: "SNDRV_PCM_IOCTL_HW_PARAMS"}, // From sound/asound.h
			{Val: 3261088016, Str: "SNDRV_PCM_IOCTL_HW_REFINE"}, // From sound/asound.h
			{Val: 2166374657, Str: "SNDRV_PCM_IOCTL_INFO"}, // From sound/asound.h
			{Val: 1074020704, Str: "SNDRV_PCM_IOCTL_LINK"}, // From sound/asound.h
			{Val: 1074020677, Str: "SNDRV_PCM_IOCTL_PAUSE"}, // From sound/asound.h
			{Val: 16704, Str: "SNDRV_PCM_IOCTL_PREPARE"}, // From sound/asound.h
			{Val: 2147762432, Str: "SNDRV_PCM_IOCTL_PVERSION"}, // From sound/asound.h
			{Val: 2149073233, Str: "SNDRV_PCM_IOCTL_READI_FRAMES"}, // From sound/asound.h
			{Val: 2149073235, Str: "SNDRV_PCM_IOCTL_READN_FRAMES"}, // From sound/asound.h
			{Val: 16705, Str: "SNDRV_PCM_IOCTL_RESET"}, // From sound/asound.h
			{Val: 16711, Str: "SNDRV_PCM_IOCTL_RESUME"}, // From sound/asound.h
			{Val: 1074282822, Str: "SNDRV_PCM_IOCTL_REWIND"}, // From sound/asound.h
			{Val: 16706, Str: "SNDRV_PCM_IOCTL_START"}, // From sound/asound.h
			{Val: 2157461792, Str: "SNDRV_PCM_IOCTL_STATUS"}, // From sound/asound.h
			{Val: 3231203620, Str: "SNDRV_PCM_IOCTL_STATUS_EXT"}, // From sound/asound.h
			{Val: 3230155027, Str: "SNDRV_PCM_IOCTL_SW_PARAMS"}, // From sound/asound.h
			{Val: 3230155043, Str: "SNDRV_PCM_IOCTL_SYNC_PTR"}, // From sound/asound.h
			{Val: 1074020610, Str: "SNDRV_PCM_IOCTL_TSTAMP"}, // From sound/asound.h
			{Val: 1074020611, Str: "SNDRV_PCM_IOCTL_TTSTAMP"}, // From sound/asound.h
			{Val: 16737, Str: "SNDRV_PCM_IOCTL_UNLINK"}, // From sound/asound.h
			{Val: 1074020612, Str: "SNDRV_PCM_IOCTL_USER_PVERSION"}, // From sound/asound.h
			{Val: 1075331408, Str: "SNDRV_PCM_IOCTL_WRITEI_FRAMES"}, // From sound/asound.h
			{Val: 1075331410, Str: "SNDRV_PCM_IOCTL_WRITEN_FRAMES"}, // From sound/asound.h
			{Val: 16712, Str: "SNDRV_PCM_IOCTL_XRUN"}, // From sound/asound.h
			{Val: 1074026289, Str: "SNDRV_RAWMIDI_IOCTL_DRAIN"}, // From sound/asound.h
			{Val: 1074026288, Str: "SNDRV_RAWMIDI_IOCTL_DROP"}, // From sound/asound.h
			{Val: 2165069569, Str: "SNDRV_RAWMIDI_IOCTL_INFO"}, // From sound/asound.h
			{Val: 3224393488, Str: "SNDRV_RAWMIDI_IOCTL_PARAMS"}, // From sound/asound.h
			{Val: 2147768064, Str: "SNDRV_RAWMIDI_IOCTL_PVERSION"}, // From sound/asound.h
			{Val: 3224917792, Str: "SNDRV_RAWMIDI_IOCTL_STATUS"}, // From sound/asound.h
			{Val: 1074026242, Str: "SNDRV_RAWMIDI_IOCTL_USER_PVERSION"}, // From sound/asound.h
			{Val: 21666, Str: "SNDRV_TIMER_IOCTL_CONTINUE"}, // From sound/asound.h
			{Val: 3223344293, Str: "SNDRV_TIMER_IOCTL_CREATE"}, // From sound/asound.h
			{Val: 3237499907, Str: "SNDRV_TIMER_IOCTL_GINFO"}, // From sound/asound.h
			{Val: 1078481924, Str: "SNDRV_TIMER_IOCTL_GPARAMS"}, // From sound/asound.h
			{Val: 3226489861, Str: "SNDRV_TIMER_IOCTL_GSTATUS"}, // From sound/asound.h
			{Val: 2162709521, Str: "SNDRV_TIMER_IOCTL_INFO"}, // From sound/asound.h
			{Val: 3222557697, Str: "SNDRV_TIMER_IOCTL_NEXT_DEVICE"}, // From sound/asound.h
			{Val: 1079006226, Str: "SNDRV_TIMER_IOCTL_PARAMS"}, // From sound/asound.h
			{Val: 21667, Str: "SNDRV_TIMER_IOCTL_PAUSE"}, // From sound/asound.h
			{Val: 2147767296, Str: "SNDRV_TIMER_IOCTL_PVERSION"}, // From sound/asound.h
			{Val: 1077171216, Str: "SNDRV_TIMER_IOCTL_SELECT"}, // From sound/asound.h
			{Val: 21664, Str: "SNDRV_TIMER_IOCTL_START"}, // From sound/asound.h
			{Val: 2153796628, Str: "SNDRV_TIMER_IOCTL_STATUS"}, // From sound/asound.h
			{Val: 21665, Str: "SNDRV_TIMER_IOCTL_STOP"}, // From sound/asound.h
			{Val: 1074025636, Str: "SNDRV_TIMER_IOCTL_TREAD64"}, // From sound/asound.h
			{Val: 1074025474, Str: "SNDRV_TIMER_IOCTL_TREAD_OLD"}, // From sound/asound.h
			{Val: 21670, Str: "SNDRV_TIMER_IOCTL_TRIGGER"}, // From sound/asound.h
			{Val: 2159302465, Str: "SNDRV_UMP_IOCTL_BLOCK_INFO"}, // From sound/asound.h
			{Val: 2169001792, Str: "SNDRV_UMP_IOCTL_ENDPOINT_INFO"}, // From sound/asound.h
			{Val: 18496, Str: "SNDRV_DM_FM_IOCTL_CLEAR_PATCHES"}, // From sound/asound_fm.h
			{Val: 2147633184, Str: "SNDRV_DM_FM_IOCTL_INFO"}, // From sound/asound_fm.h
			{Val: 1074546722, Str: "SNDRV_DM_FM_IOCTL_PLAY_NOTE"}, // From sound/asound_fm.h
			{Val: 18465, Str: "SNDRV_DM_FM_IOCTL_RESET"}, // From sound/asound_fm.h
			{Val: 1074022438, Str: "SNDRV_DM_FM_IOCTL_SET_CONNECTION"}, // From sound/asound_fm.h
			{Val: 1074022437, Str: "SNDRV_DM_FM_IOCTL_SET_MODE"}, // From sound/asound_fm.h
			{Val: 1074350116, Str: "SNDRV_DM_FM_IOCTL_SET_PARAMS"}, // From sound/asound_fm.h
			{Val: 1074939939, Str: "SNDRV_DM_FM_IOCTL_SET_VOICE"}, // From sound/asound_fm.h
			{Val: 2149335841, Str: "SNDRV_COMPRESS_AVAIL"}, // From sound/compress_offload.h
			{Val: 2150122275, Str: "SNDRV_COMPRESS_AVAIL64"}, // From sound/compress_offload.h
			{Val: 17204, Str: "SNDRV_COMPRESS_DRAIN"}, // From sound/compress_offload.h
			{Val: 3234087696, Str: "SNDRV_COMPRESS_GET_CAPS"}, // From sound/compress_offload.h
			{Val: 3951575825, Str: "SNDRV_COMPRESS_GET_CODEC_CAPS"}, // From sound/compress_offload.h
			{Val: 3223601941, Str: "SNDRV_COMPRESS_GET_METADATA"}, // From sound/compress_offload.h
			{Val: 2155365139, Str: "SNDRV_COMPRESS_GET_PARAMS"}, // From sound/compress_offload.h
			{Val: 2147762944, Str: "SNDRV_COMPRESS_IOCTL_VERSION"}, // From sound/compress_offload.h
			{Val: 17205, Str: "SNDRV_COMPRESS_NEXT_TRACK"}, // From sound/compress_offload.h
			{Val: 17206, Str: "SNDRV_COMPRESS_PARTIAL_DRAIN"}, // From sound/compress_offload.h
			{Val: 17200, Str: "SNDRV_COMPRESS_PAUSE"}, // From sound/compress_offload.h
			{Val: 17201, Str: "SNDRV_COMPRESS_RESUME"}, // From sound/compress_offload.h
			{Val: 1076118292, Str: "SNDRV_COMPRESS_SET_METADATA"}, // From sound/compress_offload.h
			{Val: 1082409746, Str: "SNDRV_COMPRESS_SET_PARAMS"}, // From sound/compress_offload.h
			{Val: 17202, Str: "SNDRV_COMPRESS_START"}, // From sound/compress_offload.h
			{Val: 17203, Str: "SNDRV_COMPRESS_STOP"}, // From sound/compress_offload.h
			{Val: 3224650592, Str: "SNDRV_COMPRESS_TASK_CREATE"}, // From sound/compress_offload.h
			{Val: 1074283361, Str: "SNDRV_COMPRESS_TASK_FREE"}, // From sound/compress_offload.h
			{Val: 3224650594, Str: "SNDRV_COMPRESS_TASK_START"}, // From sound/compress_offload.h
			{Val: 3224126312, Str: "SNDRV_COMPRESS_TASK_STATUS"}, // From sound/compress_offload.h
			{Val: 1074283363, Str: "SNDRV_COMPRESS_TASK_STOP"}, // From sound/compress_offload.h
			{Val: 2148811552, Str: "SNDRV_COMPRESS_TSTAMP"}, // From sound/compress_offload.h
			{Val: 2149597986, Str: "SNDRV_COMPRESS_TSTAMP64"}, // From sound/compress_offload.h
			{Val: 3249555474, Str: "SNDRV_EMU10K1_IOCTL_CODE_PEEK"}, // From sound/emu10k1.h
			{Val: 1102071825, Str: "SNDRV_EMU10K1_IOCTL_CODE_POKE"}, // From sound/emu10k1.h
			{Val: 18561, Str: "SNDRV_EMU10K1_IOCTL_CONTINUE"}, // From sound/emu10k1.h
			{Val: 2147764356, Str: "SNDRV_EMU10K1_IOCTL_DBG_READ"}, // From sound/emu10k1.h
			{Val: 2282506256, Str: "SNDRV_EMU10K1_IOCTL_INFO"}, // From sound/emu10k1.h
			{Val: 3225962545, Str: "SNDRV_EMU10K1_IOCTL_PCM_PEEK"}, // From sound/emu10k1.h
			{Val: 1078478896, Str: "SNDRV_EMU10K1_IOCTL_PCM_POKE"}, // From sound/emu10k1.h
			{Val: 2147764288, Str: "SNDRV_EMU10K1_IOCTL_PVERSION"}, // From sound/emu10k1.h
			{Val: 1074022531, Str: "SNDRV_EMU10K1_IOCTL_SINGLE_STEP"}, // From sound/emu10k1.h
			{Val: 18560, Str: "SNDRV_EMU10K1_IOCTL_STOP"}, // From sound/emu10k1.h
			{Val: 3222292514, Str: "SNDRV_EMU10K1_IOCTL_TRAM_PEEK"}, // From sound/emu10k1.h
			{Val: 1074808865, Str: "SNDRV_EMU10K1_IOCTL_TRAM_POKE"}, // From sound/emu10k1.h
			{Val: 1074022432, Str: "SNDRV_EMU10K1_IOCTL_TRAM_SETUP"}, // From sound/emu10k1.h
			{Val: 18562, Str: "SNDRV_EMU10K1_IOCTL_ZERO_TRAM_COUNTER"}, // From sound/emu10k1.h
			{Val: 3221771109, Str: "FCP_IOCTL_CMD"}, // From sound/fcp.h
			{Val: 3222033252, Str: "FCP_IOCTL_INIT"}, // From sound/fcp.h
			{Val: 2147767136, Str: "FCP_IOCTL_PVERSION"}, // From sound/fcp.h
			{Val: 1073894247, Str: "FCP_IOCTL_SET_METER_LABELS"}, // From sound/fcp.h
			{Val: 1074025318, Str: "FCP_IOCTL_SET_METER_MAP"}, // From sound/fcp.h
			{Val: 2149599480, Str: "SNDRV_FIREWIRE_IOCTL_GET_INFO"}, // From sound/firewire.h
			{Val: 18681, Str: "SNDRV_FIREWIRE_IOCTL_LOCK"}, // From sound/firewire.h
			{Val: 2252359933, Str: "SNDRV_FIREWIRE_IOCTL_MOTU_COMMAND_DSP_METER"}, // From sound/firewire.h
			{Val: 2150648060, Str: "SNDRV_FIREWIRE_IOCTL_MOTU_REGISTER_DSP_METER"}, // From sound/firewire.h
			{Val: 2181056766, Str: "SNDRV_FIREWIRE_IOCTL_MOTU_REGISTER_DSP_PARAMETER"}, // From sound/firewire.h
			{Val: 2164279547, Str: "SNDRV_FIREWIRE_IOCTL_TASCAM_STATE"}, // From sound/firewire.h
			{Val: 18682, Str: "SNDRV_FIREWIRE_IOCTL_UNLOCK"}, // From sound/firewire.h
			{Val: 3221768210, Str: "HDA_IOCTL_GET_WCAP"}, // From sound/hda_hwdep.h
			{Val: 2147764240, Str: "HDA_IOCTL_PVERSION"}, // From sound/hda_hwdep.h
			{Val: 3221768209, Str: "HDA_IOCTL_VERB_WRITE"}, // From sound/hda_hwdep.h
			{Val: 2148026437, Str: "SNDRV_HDSP_IOCTL_GET_9632_AEB"}, // From sound/hdsp.h
			{Val: 2149861441, Str: "SNDRV_HDSP_IOCTL_GET_CONFIG_INFO"}, // From sound/hdsp.h
			{Val: 2415937604, Str: "SNDRV_HDSP_IOCTL_GET_MIXER"}, // From sound/hdsp.h
			{Val: 2209368128, Str: "SNDRV_HDSP_IOCTL_GET_PEAK_RMS"}, // From sound/hdsp.h
			{Val: 2148026435, Str: "SNDRV_HDSP_IOCTL_GET_VERSION"}, // From sound/hdsp.h
			{Val: 1074284610, Str: "SNDRV_HDSP_IOCTL_UPLOAD_FIRMWARE"}, // From sound/hdsp.h
			{Val: 2149075009, Str: "SNDRV_HDSPM_IOCTL_GET_CONFIG"}, // From sound/hdspm.h
			{Val: 2148550726, Str: "SNDRV_HDSPM_IOCTL_GET_LTC"}, // From sound/hdspm.h
			{Val: 2148026436, Str: "SNDRV_HDSPM_IOCTL_GET_MIXER"}, // From sound/hdspm.h
			{Val: 2299021378, Str: "SNDRV_HDSPM_IOCTL_GET_PEAK_RMS"}, // From sound/hdspm.h
			{Val: 2149599303, Str: "SNDRV_HDSPM_IOCTL_GET_STATUS"}, // From sound/hdspm.h
			{Val: 2149861448, Str: "SNDRV_HDSPM_IOCTL_GET_VERSION"}, // From sound/hdspm.h
			{Val: 2154578208, Str: "SNDRV_PCM_IOCTL_STATUS32"}, // From sound/pcm.h
			{Val: 2157461792, Str: "SNDRV_PCM_IOCTL_STATUS64"}, // From sound/pcm.h
			{Val: 3228320036, Str: "SNDRV_PCM_IOCTL_STATUS_EXT32"}, // From sound/pcm.h
			{Val: 3231203620, Str: "SNDRV_PCM_IOCTL_STATUS_EXT64"}, // From sound/pcm.h
			{Val: 2150123536, Str: "SNDRV_SB_CSP_IOCTL_INFO"}, // From sound/sb16_csp.h
			{Val: 1880246289, Str: "SNDRV_SB_CSP_IOCTL_LOAD_CODE"}, // From sound/sb16_csp.h
			{Val: 18453, Str: "SNDRV_SB_CSP_IOCTL_PAUSE"}, // From sound/sb16_csp.h
			{Val: 18454, Str: "SNDRV_SB_CSP_IOCTL_RESTART"}, // From sound/sb16_csp.h
			{Val: 1074284563, Str: "SNDRV_SB_CSP_IOCTL_START"}, // From sound/sb16_csp.h
			{Val: 18452, Str: "SNDRV_SB_CSP_IOCTL_STOP"}, // From sound/sb16_csp.h
			{Val: 18450, Str: "SNDRV_SB_CSP_IOCTL_UNLOAD_CODE"}, // From sound/sb16_csp.h
			{Val: 21347, Str: "SCARLETT2_IOCTL_ERASE_FLASH_SEGMENT"}, // From sound/scarlett2.h
			{Val: 2147636068, Str: "SCARLETT2_IOCTL_GET_ERASE_PROGRESS"}, // From sound/scarlett2.h
			{Val: 2147767136, Str: "SCARLETT2_IOCTL_PVERSION"}, // From sound/scarlett2.h
			{Val: 21345, Str: "SCARLETT2_IOCTL_REBOOT"}, // From sound/scarlett2.h
			{Val: 1074025314, Str: "SCARLETT2_IOCTL_SELECT_FLASH_SEGMENT"}, // From sound/scarlett2.h
			{Val: 3222292609, Str: "SNDRV_EMUX_IOCTL_LOAD_PATCH"}, // From sound/sfnt_info.h
			{Val: 1074022532, Str: "SNDRV_EMUX_IOCTL_MEM_AVAIL"}, // From sound/sfnt_info.h
			{Val: 3222292612, Str: "SNDRV_EMUX_IOCTL_MISC_MODE"}, // From sound/sfnt_info.h
			{Val: 18563, Str: "SNDRV_EMUX_IOCTL_REMOVE_LAST_SAMPLES"}, // From sound/sfnt_info.h
			{Val: 18562, Str: "SNDRV_EMUX_IOCTL_RESET_SAMPLES"}, // From sound/sfnt_info.h
			{Val: 2147764352, Str: "SNDRV_EMUX_IOCTL_VERSION"}, // From sound/sfnt_info.h
			{Val: 1074808976, Str: "SNDRV_USB_STREAM_IOCTL_SET_PARAMS"}, // From sound/usb_stream.h
			{Val: 27392, Str: "KYRO_IOCTL_OVERLAY_CREATE"}, // From video/kyro.h
			{Val: 27396, Str: "KYRO_IOCTL_OVERLAY_OFFSET"}, // From video/kyro.h
			{Val: 27393, Str: "KYRO_IOCTL_OVERLAY_VIEWPORT_SET"}, // From video/kyro.h
			{Val: 27394, Str: "KYRO_IOCTL_SET_VIDEO_MODE"}, // From video/kyro.h
			{Val: 27397, Str: "KYRO_IOCTL_STRIDE"}, // From video/kyro.h
			{Val: 27395, Str: "KYRO_IOCTL_UVSTRIDE"}, // From video/kyro.h
			{Val: 3226792709, Str: "SISFB_COMMAND"}, // From video/sisfb.h
			{Val: 2147808003, Str: "SISFB_GET_AUTOMAXIMIZE"}, // From video/sisfb.h
			{Val: 2147774202, Str: "SISFB_GET_AUTOMAXIMIZE_OLD"}, // From video/sisfb.h
			{Val: 2166158081, Str: "SISFB_GET_INFO"}, // From video/sisfb.h
			{Val: 2147774200, Str: "SISFB_GET_INFO_OLD"}, // From video/sisfb.h
			{Val: 2147808000, Str: "SISFB_GET_INFO_SIZE"}, // From video/sisfb.h
			{Val: 2147808004, Str: "SISFB_GET_TVPOSOFFSET"}, // From video/sisfb.h
			{Val: 2147808002, Str: "SISFB_GET_VBRSTATUS"}, // From video/sisfb.h
			{Val: 2147774201, Str: "SISFB_GET_VBRSTATUS_OLD"}, // From video/sisfb.h
			{Val: 1074066179, Str: "SISFB_SET_AUTOMAXIMIZE"}, // From video/sisfb.h
			{Val: 1074032378, Str: "SISFB_SET_AUTOMAXIMIZE_OLD"}, // From video/sisfb.h
			{Val: 1074066182, Str: "SISFB_SET_LOCK"}, // From video/sisfb.h
			{Val: 1074066180, Str: "SISFB_SET_TVPOSOFFSET"}, // From video/sisfb.h
			{Val: 2147763933, Str: "SSTFB_GET_VGAPASS"}, // From video/sstfb.h
			{Val: 1074022109, Str: "SSTFB_SET_VGAPASS"}, // From video/sstfb.h
			{Val: 541953, Str: "IOCTL_EVTCHN_BIND_INTERDOMAIN"}, // From xen/evtchn.h
			{Val: 279815, Str: "IOCTL_EVTCHN_BIND_STATIC"}, // From xen/evtchn.h
			{Val: 279810, Str: "IOCTL_EVTCHN_BIND_UNBOUND_PORT"}, // From xen/evtchn.h
			{Val: 279808, Str: "IOCTL_EVTCHN_BIND_VIRQ"}, // From xen/evtchn.h
			{Val: 279812, Str: "IOCTL_EVTCHN_NOTIFY"}, // From xen/evtchn.h
			{Val: 17669, Str: "IOCTL_EVTCHN_RESET"}, // From xen/evtchn.h
			{Val: 148742, Str: "IOCTL_EVTCHN_RESTRICT_DOMID"}, // From xen/evtchn.h
			{Val: 279811, Str: "IOCTL_EVTCHN_UNBIND"}, // From xen/evtchn.h
			{Val: 1328905, Str: "IOCTL_GNTDEV_DMABUF_EXP_FROM_REFS"}, // From xen/gntdev.h
			{Val: 542474, Str: "IOCTL_GNTDEV_DMABUF_EXP_WAIT_RELEASED"}, // From xen/gntdev.h
			{Val: 542476, Str: "IOCTL_GNTDEV_DMABUF_IMP_RELEASE"}, // From xen/gntdev.h
			{Val: 1328907, Str: "IOCTL_GNTDEV_DMABUF_IMP_TO_REFS"}, // From xen/gntdev.h
			{Val: 1591042, Str: "IOCTL_GNTDEV_GET_OFFSET_FOR_VADDR"}, // From xen/gntdev.h
			{Val: 1066760, Str: "IOCTL_GNTDEV_GRANT_COPY"}, // From xen/gntdev.h
			{Val: 1591040, Str: "IOCTL_GNTDEV_MAP_GRANT_REF"}, // From xen/gntdev.h
			{Val: 280323, Str: "IOCTL_GNTDEV_SET_MAX_GRANTS"}, // From xen/gntdev.h
			{Val: 1066759, Str: "IOCTL_GNTDEV_SET_UNMAP_NOTIFY"}, // From xen/gntdev.h
			{Val: 1066753, Str: "IOCTL_GNTDEV_UNMAP_GRANT_REF"}, // From xen/gntdev.h
			{Val: 16896, Str: "IOCTL_XENBUS_BACKEND_EVTCHN"}, // From xen/xenbus_dev.h
			{Val: 16897, Str: "IOCTL_XENBUS_BACKEND_SETUP"}, // From xen/xenbus_dev.h
		},
	},
	"clocknames": {
		Prefix: "CLOCK_",
		Entries: []XlatVal{
			{Val: 3, Str: "CLOCK_THREAD_CPUTIME_ID"},
			{Val: 0, Str: "CLOCK_REALTIME"},
			{Val: 1, Str: "CLOCK_MONOTONIC"},
			{Val: 2, Str: "CLOCK_PROCESS_CPUTIME_ID"},
			{Val: 4, Str: "CLOCK_MONOTONIC_RAW"},
			{Val: 5, Str: "CLOCK_REALTIME_COARSE"},
			{Val: 6, Str: "CLOCK_MONOTONIC_COARSE"},
			{Val: 7, Str: "CLOCK_BOOTTIME"},
			{Val: 8, Str: "CLOCK_REALTIME_ALARM"},
			{Val: 9, Str: "CLOCK_BOOTTIME_ALARM"},
			{Val: 11, Str: "CLOCK_TAI"},
		},
	},
	"sigact_flags": {
		Prefix: "SA_",
		Entries: []XlatVal{
			{Val: 0x04000000, Str: "SA_RESTORER"},
			{Val: 1, Str: "SA_NOCLDSTOP"},
			{Val: 2, Str: "SA_NOCLDWAIT"},
			{Val: 4, Str: "SA_SIGINFO"},
			{Val: 0x08000000, Str: "SA_ONSTACK"},
			{Val: 0x10000000, Str: "SA_RESTART"},
			{Val: 0x20000000, Str: "SA_NODEFER"},
			{Val: 0x40000000, Str: "SA_RESETHAND"},
		},
	},
	"mount_flags": {
		Prefix: "MS_",
		Entries: []XlatVal{
			{Val: 0xc0ed0000, Str: "MS_MGC_VAL"},
			{Val: 1, Str: "MS_RDONLY"},
			{Val: 2, Str: "MS_NOSUID"},
			{Val: 4, Str: "MS_NODEV"},
			{Val: 8, Str: "MS_NOEXEC"},
			{Val: 16, Str: "MS_SYNCHRONOUS"},
			{Val: 32, Str: "MS_REMOUNT"},
			{Val: 64, Str: "MS_MANDLOCK"},
			{Val: 128, Str: "MS_DIRSYNC"},
			{Val: 256, Str: "MS_NOSYMFOLLOW"},
			{Val: 1024, Str: "MS_NOATIME"},
			{Val: 2048, Str: "MS_NODIRATIME"},
			{Val: 4096, Str: "MS_BIND"},
			{Val: 8192, Str: "MS_MOVE"},
			{Val: 16384, Str: "MS_REC"},
			{Val: 32768, Str: "MS_SILENT"},
			{Val: 65536, Str: "MS_POSIXACL"},
			{Val: 131072, Str: "MS_UNBINDABLE"},
			{Val: 262144, Str: "MS_PRIVATE"},
			{Val: 524288, Str: "MS_SLAVE"},
			{Val: 1048576, Str: "MS_SHARED"},
			{Val: 2097152, Str: "MS_RELATIME"},
			{Val: 4194304, Str: "MS_KERNMOUNT"},
			{Val: 8388608, Str: "MS_I_VERSION"},
			{Val: 16777216, Str: "MS_STRICTATIME"},
			{Val: 33554432, Str: "MS_LAZYTIME"},
			{Val: 0x10000000, Str: "MS_NOREMOTELOCK"},
			{Val: 0x20000000, Str: "MS_NOSEC"},
			{Val: 0x40000000, Str: "MS_BORN"},
			{Val: 0x80000000, Str: "MS_ACTIVE"},
			{Val: 0x4000000, Str: "MS_SUBMOUNT"},
			{Val: 0x2000000, Str: "MS_NOUSER"},
		},
	},
	"protocols": {
		Prefix: "IPPROTO_",
		Entries: []XlatVal{
			{Val: 0, Str: "IPPROTO_IP"},
			{Val: 1, Str: "IPPROTO_ICMP"},
			{Val: 2, Str: "IPPROTO_IGMP"},
			{Val: 6, Str: "IPPROTO_TCP"},
			{Val: 17, Str: "IPPROTO_UDP"},
			{Val: 41, Str: "IPPROTO_IPV6"},
			{Val: 58, Str: "IPPROTO_ICMPV6"},
			{Val: 255, Str: "IPPROTO_RAW"},
		},
	},
	"signalnames": {
		Prefix: "SIG",
		Entries: []XlatVal{
			{Val: 1, Str: "SIGHUP"},
			{Val: 2, Str: "SIGINT"},
			{Val: 3, Str: "SIGQUIT"},
			{Val: 4, Str: "SIGILL"},
			{Val: 5, Str: "SIGTRAP"},
			{Val: 6, Str: "SIGABRT"},
			{Val: 7, Str: "SIGBUS"},
			{Val: 8, Str: "SIGFPE"},
			{Val: 9, Str: "SIGKILL"},
			{Val: 10, Str: "SIGUSR1"},
			{Val: 11, Str: "SIGSEGV"},
			{Val: 12, Str: "SIGUSR2"},
			{Val: 13, Str: "SIGPIPE"},
			{Val: 14, Str: "SIGALRM"},
			{Val: 15, Str: "SIGTERM"},
			{Val: 16, Str: "SIGSTKFLT"},
			{Val: 17, Str: "SIGCHLD"},
			{Val: 18, Str: "SIGCONT"},
			{Val: 19, Str: "SIGSTOP"},
			{Val: 20, Str: "SIGTSTP"},
			{Val: 21, Str: "SIGTTIN"},
			{Val: 22, Str: "SIGTTOU"},
			{Val: 23, Str: "SIGURG"},
			{Val: 24, Str: "SIGXCPU"},
			{Val: 25, Str: "SIGXFSZ"},
			{Val: 26, Str: "SIGVTALRM"},
			{Val: 27, Str: "SIGPROF"},
			{Val: 28, Str: "SIGWINCH"},
			{Val: 29, Str: "SIGIO"},
			{Val: 30, Str: "SIGPWR"},
			{Val: 31, Str: "SIGSYS"},
		},
	},
	"clone3_flags": {
		Prefix: "CLONE_",
		Entries: []XlatVal{
			{Val: 0x00000100, Str: "CLONE_VM"},
			{Val: 0x00000200, Str: "CLONE_FS"},
			{Val: 0x00000400, Str: "CLONE_FILES"},
			{Val: 0x00000800, Str: "CLONE_SIGHAND"},
			{Val: 0x00001000, Str: "CLONE_PIDFD"},
			{Val: 0x00002000, Str: "CLONE_PTRACE"},
			{Val: 0x00004000, Str: "CLONE_VFORK"},
			{Val: 0x00008000, Str: "CLONE_PARENT"},
			{Val: 0x00010000, Str: "CLONE_THREAD"},
			{Val: 0x00020000, Str: "CLONE_NEWNS"},
			{Val: 0x00040000, Str: "CLONE_SYSVSEM"},
			{Val: 0x00080000, Str: "CLONE_SETTLS"},
			{Val: 0x00100000, Str: "CLONE_PARENT_SETTID"},
			{Val: 0x00200000, Str: "CLONE_CHILD_CLEARTID"},
			{Val: 0x00800000, Str: "CLONE_UNTRACED"},
			{Val: 0x01000000, Str: "CLONE_CHILD_SETTID"},
			{Val: 0x02000000, Str: "CLONE_NEWCGROUP"},
			{Val: 0x04000000, Str: "CLONE_NEWUTS"},
			{Val: 0x08000000, Str: "CLONE_NEWIPC"},
			{Val: 0x10000000, Str: "CLONE_NEWUSER"},
			{Val: 0x20000000, Str: "CLONE_NEWPID"},
			{Val: 0x40000000, Str: "CLONE_NEWNET"},
			{Val: 0x80000000, Str: "CLONE_IO"},
			{Val: 128, Str: "CLONE_NEWTIME"},
			{Val: 4294967296, Str: "CLONE_CLEAR_SIGHAND"},
			{Val: 8589934592, Str: "CLONE_INTO_CGROUP"},
			{Val: 17179869184, Str: "CLONE_AUTOREAP"},
			{Val: 34359738368, Str: "CLONE_NNP"},
			{Val: 68719476736, Str: "CLONE_PIDFD_AUTOKILL"},
			{Val: 137438953472, Str: "CLONE_EMPTY_MNTNS"},
		},
	},
	"x86_xfeatures": {
		Prefix: "XFEATURE_MASK_",
		Entries: []XlatVal{
			{Val: 0x3, Str: "XFEATURE_MASK_FPSSE"},
			{Val: 0xe0, Str: "XFEATURE_MASK_AVX512"},
			{Val: 0x60000, Str: "XFEATURE_MASK_XTILE"},
			{Val: 0x1, Str: "XFEATURE_MASK_FP"},
			{Val: 0x2, Str: "XFEATURE_MASK_SSE"},
			{Val: 0x4, Str: "XFEATURE_MASK_YMM"},
			{Val: 0x8, Str: "XFEATURE_MASK_BNDREGS"},
			{Val: 0x10, Str: "XFEATURE_MASK_BNDCSR"},
			{Val: 0x20, Str: "XFEATURE_MASK_OPMASK"},
			{Val: 0x40, Str: "XFEATURE_MASK_ZMM_Hi256"},
			{Val: 0x80, Str: "XFEATURE_MASK_Hi16_ZMM"},
			{Val: 0x100, Str: "XFEATURE_MASK_PT"},
			{Val: 0x200, Str: "XFEATURE_MASK_PKRU"},
			{Val: 0x400, Str: "XFEATURE_MASK_PASID"},
			{Val: 0x8000, Str: "XFEATURE_MASK_LBR"},
			{Val: 0x20000, Str: "XFEATURE_MASK_XTILE_CFG"},
			{Val: 0x40000, Str: "XFEATURE_MASK_XTILE_DATA"},
		},
	},
}
var SyscallArgXlatMap = map[string]map[string]string{
	"clock_nanosleep": {
		"which_clock": "clocknames",
	},
	"epoll_create1": {
		"flags": "epollflags",
	},
	"ioctl": {
		"cmd": "ioctl_cmds",
	},
	"faccessat2": {
		"mode": "access_modes",
	},
	"request_key": {
		"destringid": "key_spec",
	},
	"clock_settime": {
		"which_clock": "clocknames",
	},
	"getsockname": {
		"addr": "sockaddr",
	},
	"openat": {
		"flags": "open_mode_flags",
	},
	"arch_prctl": {
		"option": "archvals",
	},
	"accept4": {
		"flags": "sock_type_flags",
	},
	"setsockopt": {
		"level": "socketlayers",
	},
	"bind": {
		"addr": "sockaddr",
	},
	"mprotect": {
		"prot": "mmap_prot",
	},
	"ppoll": {
		"events": "pollflags",
		"revents": "pollflags",
	},
	"wait4": {
		"options": "wait4_options",
	},
	"umount2": {
		"flags": "umount_flags",
	},
	"mount": {
		"flags": "mount_flags",
	},
	"unlinkat": {
		"flag": "at_flags",
	},
	"add_key": {
		"ringid": "key_spec",
	},
	"sendto": {
		"flags": "msg_flags",
		"addr": "sockaddr",
	},
	"mremap": {
		"flags": "mremap_flags",
	},
	"clone": {
		"clone_flags": "clone_flags",
	},
	"futex": {
		"op": "futexops",
	},
	"getpeername": {
		"addr": "sockaddr",
	},
	"bpf": {
		"arg0": "bpf_commands",
	},
	"mmap": {
		"prot": "mmap_prot",
		"flags": "mmap_flags",
	},
	"clone3": {
		"flags": "clone3_flags",
	},
	"prctl": {
		"option": "prctl_options",
	},
	"madvise": {
		"behavior": "madvise_cmds",
	},
	"rt_sigprocmask": {
		"how": "sigprocmaskcmds",
	},
	"socket": {
		"domain": "addrfams",
		"type": "sock_type_flags",
	},
	"getsockopt": {
		"level": "socketlayers",
	},
	"lseek": {
		"whence": "whence_codes",
	},
	"access": {
		"mode": "access_modes",
	},
	"faccessat": {
		"mode": "access_modes",
	},
	"open": {
		"flags": "open_mode_flags",
	},
	"recvfrom": {
		"flags": "msg_flags",
		"addr": "sockaddr",
	},
	"poll": {
		"events": "pollflags",
		"revents": "pollflags",
	},
	"clock_adjtime": {
		"which_clock": "clocknames",
	},
	"epoll_ctl": {
		"op": "epollctls",
	},
	"connect": {
		"addr": "sockaddr",
	},
}
