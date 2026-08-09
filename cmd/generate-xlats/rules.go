package main

import (
	"fmt"
	"io"
	"strings"
)

const xlatCIncludes = "#define _GNU_SOURCE\n#include <stdio.h>\n#include <fcntl.h>\n#include <sys/types.h>\n#include <sys/time.h>\n#include <sys/socket.h>\n#include <sys/un.h>\n#include <linux/prctl.h>\n#include <asm/prctl.h>\n#include <linux/stat.h>\n#include <linux/fs.h>\n#include <linux/timex.h>\n#include <poll.h>\n#include <sys/epoll.h>\n#include <linux/bpf.h>\n#include <time.h>\n#include <asm/termios.h>\n#include <sys/mman.h>\n#include <linux/sched.h>\n#include <linux/futex.h>\n#include <linux/memfd.h>\n#include <linux/xattr.h>\n#include <sys/wait.h>\n#include <sys/mount.h>\n#include <linux/keyctl.h>\n#include <linux/dm-ioctl.h>\n#include <linux/netlink.h>\n#include <linux/rtnetlink.h>\n#include <linux/openat2.h>\n"

const xlatCCompatDefines = "#ifndef ARCH_GET_CPUID\n#define ARCH_GET_CPUID 0x1011\n#endif\n#ifndef ARCH_SET_CPUID\n#define ARCH_SET_CPUID 0x1012\n#endif\n"

const quotaXlatCDefinitions = "#include <stdint.h>\n#include <linux/quota.h>\n#include <linux/dqblk_xfs.h>\n#ifndef OLD_CMD\n#define OLD_CMD(cmd) ((uint32_t) (cmd) << 8)\n#endif\n#ifndef NEW_CMD\n#define NEW_CMD(cmd) ((uint32_t) (cmd) | 0x800000)\n#endif\n"

var alwaysAllowedXlats = []string{
	"fcntlcmds",
	"notifyflags",
	"lockfcmds",
	"fdflags",
	"open_access_modes",
	"open_resolve_flags",
	"addrfams",
	"whence",
	"at_flags",
	"at_statx_sync_types",
	"adjtimex_status",
	"x86_xfeature_bits",
	"bpf_commands",
	"bpf_map_types",
	"bpf_map_flags",
	"clocknames",
	"clone3_flags",
	"pollflags",
	"signalnames",
	"socketlayers",
	"sock_type_flags",
	"sock_options",
	"prctl_options",
	"futexops",
	"protocols",
	"sigact_flags",
	"dm_flags",
	"netlink_protocols",
	"netlink_types",
	"netlink_flags",
	"netlink_get_flags",
	"netlink_new_flags",
	"netlink_ack_flags",
	"msg_flags",
	"sock_ip_options",
	"sock_tcp_options",
	"fsmagic",
	"statfs_flags",
	"statx_attrs",
	"statx_masks",
	"mount_attr_attr",
	"mount_attr_propagation",
	"mount_setattr_flags",
	"open_tree_flags",
	"move_mount_flags",
	"statmount_flags",
	"statmount_mask",
	"statmount_sb_flags",
	"statmount_mnt_propagation",
	"listmount_flags",
	"listmount_mnt_id",
	"waitid_options",
	"waitid_types",
	"itimer_which",
	"priorities",
	"xattrflags",
	"bpf_attach_flags",
	"quotacmds",
	"quotatypes",
	"quota_formats",
	"if_dqblk_valid",
	"if_dqinfo_flags",
	"if_dqinfo_valid",
	"xfs_dqblk_flags",
	"xfs_quota_flags",
}

var staticOnlyXlats = []string{
	"x86_xfeatures",
	"clocknames",
	"clone3_flags",
	"signalnames",
	"mount_flags",
	"protocols",
	"sigact_flags",
}

var zeroValueXlatNames = map[string]bool{
	"O_RDONLY":                true,
	"F_OK":                    true,
	"AF_UNSPEC":               true,
	"SEEK_SET":                true,
	"XFEATURE_FP":             true,
	"BPF_MAP_CREATE":          true,
	"CLOCK_REALTIME":          true,
	"PROT_NONE":               true,
	"FUTEX_WAIT":              true,
	"FUTEX2_SIZE_U8":          true,
	"MADV_NORMAL":             true,
	"SIG_BLOCK":               true,
	"CLONE_VM":                true,
	"BPF_MAP_TYPE_UNSPEC":     true,
	"BPF_PROG_TYPE_UNSPEC":    true,
	"BPF_CGROUP_INET_INGRESS": true,
	"MAP_FILE":                true,
	"RLIMIT_CPU":              true,
	"F_DUPFD":                 true,
	"F_RDLCK":                 true,
	"PRIO_PROCESS":            true,
	"ITIMER_REAL":             true,
	"USRQUOTA":                true,
	"AT_STATX_SYNC_AS_STAT":   true,
}

func stripIntegerSuffixes(value string) string {
	for _, suffix := range []string{"ULL", "UL", "U", "ull", "ul", "u", "LL", "L", "ll", "l"} {
		value = strings.TrimSuffix(value, suffix)
	}
	return value
}

func keepZeroXlatValue(name string) bool {
	return zeroValueXlatNames[name]
}

func writeOpenModeFlagFallbacks(out io.Writer) {
	for _, entry := range []stableXlatEntry{
		{"O_DIRECT", "16384"},
		{"O_TMPFILE", "4259840"},
		{"O_SYNC", "1052672"},
		{"__O_TMPFILE", "4194304"},
		{"__O_SYNC", "1048576"},
		{"O_LARGEFILE", "32768"},
	} {
		fmt.Fprintf(out, "\t\t\t{Val: %s, Str: %q},\n", entry.value, entry.name)
	}
}
