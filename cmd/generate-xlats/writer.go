package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const ioctlIncludePath = "../../strace-upstream/src/linux/64/ioctls_inc.h"

type staticXlatTable struct {
	name    string
	prefix  string
	entries []stableXlatEntry
}

func writeGeneratedStaticXlatTables(out io.Writer, emitted map[string]bool, ioctlIncPath string) {
	writeAliasXlatTables(out, emitted)
	writeIoctlXlatTable(out, ioctlIncPath)
	for _, table := range generatedStaticXlatTables {
		writeStaticXlatTable(out, table.name, table.prefix, table.entries)
	}
}

var generatedStaticXlatTables = []staticXlatTable{
	{
		name:   "clocknames",
		prefix: "CLOCK_",
		entries: []stableXlatEntry{
			{"CLOCK_THREAD_CPUTIME_ID", "3"},
			{"CLOCK_REALTIME", "0"},
			{"CLOCK_MONOTONIC", "1"},
			{"CLOCK_PROCESS_CPUTIME_ID", "2"},
			{"CLOCK_MONOTONIC_RAW", "4"},
			{"CLOCK_REALTIME_COARSE", "5"},
			{"CLOCK_MONOTONIC_COARSE", "6"},
			{"CLOCK_BOOTTIME", "7"},
			{"CLOCK_REALTIME_ALARM", "8"},
			{"CLOCK_BOOTTIME_ALARM", "9"},
			{"CLOCK_TAI", "11"},
		},
	},
	{
		name:   "sigact_flags",
		prefix: "SA_",
		entries: []stableXlatEntry{
			{"SA_RESTORER", "0x04000000"},
			{"SA_NOCLDSTOP", "1"},
			{"SA_NOCLDWAIT", "2"},
			{"SA_SIGINFO", "4"},
			{"SA_ONSTACK", "0x08000000"},
			{"SA_RESTART", "0x10000000"},
			{"SA_NODEFER", "0x20000000"},
			{"SA_RESETHAND", "0x40000000"},
		},
	},
	{
		name:   "mount_flags",
		prefix: "MS_",
		entries: []stableXlatEntry{
			{"MS_MGC_VAL", "0xc0ed0000"},
			{"MS_RDONLY", "1"},
			{"MS_NOSUID", "2"},
			{"MS_NODEV", "4"},
			{"MS_NOEXEC", "8"},
			{"MS_SYNCHRONOUS", "16"},
			{"MS_REMOUNT", "32"},
			{"MS_MANDLOCK", "64"},
			{"MS_DIRSYNC", "128"},
			{"MS_NOSYMFOLLOW", "256"},
			{"MS_NOATIME", "1024"},
			{"MS_NODIRATIME", "2048"},
			{"MS_BIND", "4096"},
			{"MS_MOVE", "8192"},
			{"MS_REC", "16384"},
			{"MS_SILENT", "32768"},
			{"MS_POSIXACL", "65536"},
			{"MS_UNBINDABLE", "131072"},
			{"MS_PRIVATE", "262144"},
			{"MS_SLAVE", "524288"},
			{"MS_SHARED", "1048576"},
			{"MS_RELATIME", "2097152"},
			{"MS_KERNMOUNT", "4194304"},
			{"MS_I_VERSION", "8388608"},
			{"MS_STRICTATIME", "16777216"},
			{"MS_LAZYTIME", "33554432"},
			{"MS_NOREMOTELOCK", "0x10000000"},
			{"MS_NOSEC", "0x20000000"},
			{"MS_BORN", "0x40000000"},
			{"MS_ACTIVE", "0x80000000"},
			{"MS_SUBMOUNT", "0x4000000"},
			{"MS_NOUSER", "0x2000000"},
		},
	},
	{
		name:   "protocols",
		prefix: "IPPROTO_",
		entries: []stableXlatEntry{
			{"IPPROTO_IP", "0"},
			{"IPPROTO_ICMP", "1"},
			{"IPPROTO_IGMP", "2"},
			{"IPPROTO_TCP", "6"},
			{"IPPROTO_UDP", "17"},
			{"IPPROTO_IPV6", "41"},
			{"IPPROTO_ICMPV6", "58"},
			{"IPPROTO_RAW", "255"},
		},
	},
	{
		name:   "signalnames",
		prefix: "SIG",
		entries: []stableXlatEntry{
			{"SIGHUP", "1"},
			{"SIGINT", "2"},
			{"SIGQUIT", "3"},
			{"SIGILL", "4"},
			{"SIGTRAP", "5"},
			{"SIGABRT", "6"},
			{"SIGBUS", "7"},
			{"SIGFPE", "8"},
			{"SIGKILL", "9"},
			{"SIGUSR1", "10"},
			{"SIGSEGV", "11"},
			{"SIGUSR2", "12"},
			{"SIGPIPE", "13"},
			{"SIGALRM", "14"},
			{"SIGTERM", "15"},
			{"SIGSTKFLT", "16"},
			{"SIGCHLD", "17"},
			{"SIGCONT", "18"},
			{"SIGSTOP", "19"},
			{"SIGTSTP", "20"},
			{"SIGTTIN", "21"},
			{"SIGTTOU", "22"},
			{"SIGURG", "23"},
			{"SIGXCPU", "24"},
			{"SIGXFSZ", "25"},
			{"SIGVTALRM", "26"},
			{"SIGPROF", "27"},
			{"SIGWINCH", "28"},
			{"SIGIO", "29"},
			{"SIGPWR", "30"},
			{"SIGSYS", "31"},
		},
	},
	{
		name:   "clone3_flags",
		prefix: "CLONE_",
		entries: []stableXlatEntry{
			{"CLONE_VM", "0x00000100"},
			{"CLONE_FS", "0x00000200"},
			{"CLONE_FILES", "0x00000400"},
			{"CLONE_SIGHAND", "0x00000800"},
			{"CLONE_PIDFD", "0x00001000"},
			{"CLONE_PTRACE", "0x00002000"},
			{"CLONE_VFORK", "0x00004000"},
			{"CLONE_PARENT", "0x00008000"},
			{"CLONE_THREAD", "0x00010000"},
			{"CLONE_NEWNS", "0x00020000"},
			{"CLONE_SYSVSEM", "0x00040000"},
			{"CLONE_SETTLS", "0x00080000"},
			{"CLONE_PARENT_SETTID", "0x00100000"},
			{"CLONE_CHILD_CLEARTID", "0x00200000"},
			{"CLONE_UNTRACED", "0x00800000"},
			{"CLONE_CHILD_SETTID", "0x01000000"},
			{"CLONE_NEWCGROUP", "0x02000000"},
			{"CLONE_NEWUTS", "0x04000000"},
			{"CLONE_NEWIPC", "0x08000000"},
			{"CLONE_NEWUSER", "0x10000000"},
			{"CLONE_NEWPID", "0x20000000"},
			{"CLONE_NEWNET", "0x40000000"},
			{"CLONE_IO", "0x80000000"},
			{"CLONE_NEWTIME", "128"},
			{"CLONE_CLEAR_SIGHAND", "4294967296"},
			{"CLONE_INTO_CGROUP", "8589934592"},
			{"CLONE_AUTOREAP", "17179869184"},
			{"CLONE_NNP", "34359738368"},
			{"CLONE_PIDFD_AUTOKILL", "68719476736"},
			{"CLONE_EMPTY_MNTNS", "137438953472"},
		},
	},
	{
		name:   "x86_xfeatures",
		prefix: "XFEATURE_MASK_",
		entries: []stableXlatEntry{
			{"XFEATURE_MASK_FPSSE", "0x3"},
			{"XFEATURE_MASK_AVX512", "0xe0"},
			{"XFEATURE_MASK_XTILE", "0x60000"},
			{"XFEATURE_MASK_FP", "0x1"},
			{"XFEATURE_MASK_SSE", "0x2"},
			{"XFEATURE_MASK_YMM", "0x4"},
			{"XFEATURE_MASK_BNDREGS", "0x8"},
			{"XFEATURE_MASK_BNDCSR", "0x10"},
			{"XFEATURE_MASK_OPMASK", "0x20"},
			{"XFEATURE_MASK_ZMM_Hi256", "0x40"},
			{"XFEATURE_MASK_Hi16_ZMM", "0x80"},
			{"XFEATURE_MASK_PT", "0x100"},
			{"XFEATURE_MASK_PKRU", "0x200"},
			{"XFEATURE_MASK_PASID", "0x400"},
			{"XFEATURE_MASK_LBR", "0x8000"},
			{"XFEATURE_MASK_XTILE_CFG", "0x20000"},
			{"XFEATURE_MASK_XTILE_DATA", "0x40000"},
		},
	},
}

func writeIoctlXlatTable(out io.Writer, ioctlIncPath string) {
	fmt.Printf("Generating ioctl_cmds...\n")
	ioctlInc, err := os.ReadFile(ioctlIncPath)
	if err != nil {
		return
	}
	fmt.Fprintf(out, "\t%q: {\n\t\tPrefix: %q,\n\t\tEntries: []XlatVal{\n", "ioctl_cmds", "")
	for _, line := range strings.Split(string(ioctlInc), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		line = strings.Trim(line, "{} ")
		parts := strings.Split(line, ",")
		if len(parts) < 5 {
			continue
		}
		name := strings.Trim(parts[1], " \"")
		dirStr := strings.TrimSpace(parts[2])
		typNrStr := strings.TrimSpace(parts[3])
		sizeStr := strings.TrimSpace(parts[4])

		var dir, typNr, size uint64
		switch {
		case strings.Contains(dirStr, "READ") && strings.Contains(dirStr, "WRITE"):
			dir = 3
		case strings.Contains(dirStr, "READ"):
			dir = 2
		case strings.Contains(dirStr, "WRITE"):
			dir = 1
		default:
			dir = 0
		}

		fmt.Sscanf(typNrStr, "%v", &typNr)
		fmt.Sscanf(sizeStr, "%v", &size)

		val := (dir << 30) | (size << 16) | typNr
		fmt.Fprintf(out, "\t\t\t{Val: %d, Str: %q}, // From %s\n", val, name, strings.Trim(parts[0], " \""))
	}
	fmt.Fprintf(out, "\t\t},\n\t},\n")
}

func writeSyscallArgXlatMap(out io.Writer, syscalls map[string]map[string]string) {
	fmt.Fprintln(out, "var SyscallArgXlatMap = map[string]map[string]string{")
	for _, sc := range sortedKeys(syscalls) {
		if strings.HasSuffix(sc, "_table") {
			continue
		}
		m := syscalls[sc]
		fmt.Fprintf(out, "\t%q: {\n", sc)
		for _, arg := range sortedKeys(m) {
			xlat := m[arg]
			fmt.Fprintf(out, "\t\t%q: %q,\n", arg, xlat)
		}
		fmt.Fprintln(out, "\t},")
	}
	fmt.Fprintln(out, "}")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
