package meta

import "sync"

var bpfXlatOnce sync.Once

func checkRegisterBpfXlats() {
	bpfXlatOnce.Do(func() {
		if XlatTables == nil {
			XlatTables = make(map[string]XlatTable)
		}
		for name, table := range bpfRuntimeXlatTables {
			if _, ok := XlatTables[name]; !ok {
				XlatTables[name] = table
			}
		}
	})
}

var bpfRuntimeXlatTables = map[string]XlatTable{
	"bpf_map_lookup_flags": {
		Prefix: "BPF_",
		Entries: []XlatVal{
			{Val: 16, Str: "BPF_F_ALL_CPUS"},
			{Val: 8, Str: "BPF_F_CPU"},
			{Val: 4, Str: "BPF_F_LOCK"},
			{Val: 0, Str: "BPF_ANY"},
		},
	},
	"bpf_map_update_flags": {
		Prefix: "BPF_",
		Entries: []XlatVal{
			{Val: 16, Str: "BPF_F_ALL_CPUS"},
			{Val: 8, Str: "BPF_F_CPU"},
			{Val: 4, Str: "BPF_F_LOCK"},
			{Val: 2, Str: "BPF_EXIST"},
			{Val: 1, Str: "BPF_NOEXIST"},
			{Val: 0, Str: "BPF_ANY"},
		},
	},
	"bpf_file_flags": {
		Prefix: "BPF_",
		Entries: []XlatVal{
			{Val: 8, Str: "BPF_F_RDONLY"},
			{Val: 0x10, Str: "BPF_F_WRONLY"},
			{Val: 0x4000, Str: "BPF_F_PATH_FD"},
		},
	},
	"bpf_test_run_flags": {
		Prefix: "BPF_F_TEST_",
		Entries: []XlatVal{
			{Val: 1, Str: "BPF_F_TEST_RUN_ON_CPU"},
			{Val: 2, Str: "BPF_F_TEST_XDP_LIVE_FRAMES"},
		},
	},
	"bpf_query_flags": {
		Prefix: "BPF_F_QUERY_",
		Entries: []XlatVal{
			{Val: 1, Str: "BPF_F_QUERY_EFFECTIVE"},
		},
	},
	"bpf_btf_flags": {
		Prefix: "BPF_F_",
		Entries: []XlatVal{
			{Val: 1 << 16, Str: "BPF_F_TOKEN_FD"},
		},
	},
	"bpf_fd_type": {
		Prefix: "BPF_FD_TYPE_",
		Entries: []XlatVal{
			{Val: 0, Str: "BPF_FD_TYPE_RAW_TRACEPOINT"},
			{Val: 1, Str: "BPF_FD_TYPE_TRACEPOINT"},
			{Val: 2, Str: "BPF_FD_TYPE_KPROBE"},
			{Val: 3, Str: "BPF_FD_TYPE_KRETPROBE"},
			{Val: 4, Str: "BPF_FD_TYPE_UPROBE"},
			{Val: 5, Str: "BPF_FD_TYPE_URETPROBE"},
		},
	},
	"bpf_kprobe_multi_flags": {
		Prefix: "BPF_F_KPROBE_MULTI_",
		Entries: []XlatVal{
			{Val: 1, Str: "BPF_F_KPROBE_MULTI_RETURN"},
		},
	},
	"bpf_netfilter_ip_flags": {
		Prefix: "BPF_F_NETFILTER_",
		Entries: []XlatVal{
			{Val: 1, Str: "BPF_F_NETFILTER_IP_DEFRAG"},
		},
	},
	"bpf_uprobe_multi_flags": {
		Prefix: "BPF_F_UPROBE_MULTI_",
		Entries: []XlatVal{
			{Val: 1, Str: "BPF_F_UPROBE_MULTI_RETURN"},
		},
	},
	"bpf_stats_type": {
		Prefix: "BPF_STATS_",
		Entries: []XlatVal{
			{Val: 0, Str: "BPF_STATS_RUN_TIME"},
		},
	},
}
