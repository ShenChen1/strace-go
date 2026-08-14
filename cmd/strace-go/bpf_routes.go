package main

import (
	"fmt"
	"sort"

	"github.com/cilium/ebpf"

	"strace-go/pkg/meta"
)

const bpfRouteMapMaxEntries = 512

type bpfRoutePlan struct {
	enter map[uint32]uint32
	exit  map[uint32]uint32
}

type bpfRouteRule struct {
	slot  uint32
	names []string
}

var bpfEnterRouteRules = []bpfRouteRule{
	{enterProgTerminating, []string{"exit", "exit_group"}},
	{enterProgExec, []string{"execve", "execveat"}},
	{enterProgPathStat, []string{"stat", "lstat", "statfs", "newfstatat", "statx"}},
	{enterProgPathOnly, []string{
		"access", "chdir", "chroot", "chmod", "chown", "lchown", "mkdir", "mknod", "rmdir", "unlink",
		"swapon", "swapoff", "acct", "truncate", "fsopen", "mkdirat", "mknodat", "fchownat",
		"unlinkat", "fchmodat", "faccessat", "faccessat2", "fspick", "open_tree",
	}},
	{enterProgDualPath, []string{
		"rename", "link", "symlink", "symlinkat", "renameat", "renameat2", "linkat",
	}},
	{enterProgOpenat2, []string{"openat2"}},
	{enterProgReadlink, []string{"readlink", "readlinkat"}},
	{enterProgMiscStruct, []string{"setrlimit", "prlimit64"}},
	{enterProgSmallStruct, []string{"sendfile", "copy_file_range"}},
	{enterProgItimer, []string{"setitimer"}},
	{enterProgTimeStruct, []string{"clock_settime", "settimeofday"}},
	{enterProgSignal, []string{"rt_sigaction", "rt_sigprocmask", "rt_sigsuspend", "signalfd", "signalfd4"}},
	{enterProgFileTime, []string{"utime", "utimes", "futimesat", "utimensat"}},
	{enterProgSleep, []string{"nanosleep", "clock_nanosleep"}},
	{enterProgFutex, []string{"futex", "futex_wait", "futex_waitv", "futex_requeue"}},
	{enterProgCachestat, []string{"cachestat"}},
	{enterProgCapability, []string{"capget", "capset"}},
	{enterProgMemfd, []string{"memfd_create"}},
	{enterProgPrctl, []string{"prctl"}},
	{enterProgClone3, []string{"clone3"}},
	{enterProgBpf, []string{"bpf"}},
	{enterProgIovec, []string{
		"readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2", "vmsplice",
		"process_vm_readv", "process_vm_writev", "process_madvise",
	}},
	{enterProgMsg, []string{"sendmsg", "recvmsg"}},
	{enterProgMmsg, []string{"sendmmsg", "recvmmsg"}},
	{enterProgFcntl, []string{"fcntl"}},
	{enterProgIoctl, []string{"ioctl"}},
	{enterProgNetwork, []string{
		"connect", "bind", "sendto", "recvfrom", "accept", "accept4", "getsockname", "getpeername",
		"setsockopt", "getsockopt",
	}},
	{enterProgKey, []string{"add_key", "request_key"}},
	{enterProgXattr, []string{
		"setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr",
		"listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr",
	}},
	{enterProgFs, []string{"mount", "umount2", "fsconfig", "mount_setattr", "statmount", "listmount"}},
	{enterProgAio, []string{"io_setup", "io_getevents", "io_pgetevents", "io_submit", "io_cancel"}},
	{enterProgPoll, []string{"poll", "ppoll"}},
	{enterProgSelect, []string{"select"}},
	{enterProgEpoll, []string{"epoll_ctl", "epoll_pwait2"}},
	{enterProgQuota, []string{"quotactl", "quotactl_fd"}},
	{enterProgMountPath, []string{"move_mount"}},
	{enterProgPayload, []string{"open", "creat", "openat", "write", "pwrite64"}},
}

var bpfExitRouteRules = []bpfRouteRule{
	{exitProgFDTime, []string{
		"read", "pread64", "gettimeofday", "clock_gettime", "clock_getres",
		"getitimer", "setitimer", "adjtimex", "clock_adjtime", "nanosleep",
		"clock_nanosleep", "open", "openat", "openat2", "open_tree", "creat",
		"dup", "dup2", "dup3", "epoll_create", "timerfd_create", "eventfd",
		"eventfd2", "epoll_create1", "inotify_init", "inotify_init1", "signalfd",
		"signalfd4",
	}},
	{exitProgStruct, []string{
		"stat", "lstat", "fstat", "newfstatat", "statx", "statfs", "fstatfs",
		"waitid", "rt_sigaction", "rt_sigprocmask", "rt_sigsuspend", "getcwd",
		"readlink", "readlinkat", "pipe", "pipe2", "socketpair", "uname",
		"sysinfo", "getrlimit", "prlimit64",
	}},
	{exitProgAsync, []string{
		"sendfile", "arch_prctl", "get_robust_list", "cachestat", "capget", "capset",
		"prctl", "io_getevents", "io_pgetevents", "io_setup", "poll", "ppoll",
	}},
	{exitProgIO, []string{
		"select", "epoll_wait", "epoll_pwait", "epoll_pwait2", "getdents", "getdents64",
		"execve", "execveat", "getxattr", "lgetxattr", "fgetxattr", "listxattr",
		"llistxattr", "flistxattr",
	}},
	{exitProgControl, []string{
		"fcntl", "ioctl", "connect", "bind", "sendto", "recvfrom", "accept", "accept4",
		"getsockname", "getpeername", "setsockopt", "getsockopt",
	}},
	{exitProgPath, []string{
		"access", "chdir", "chroot", "chmod", "chown", "lchown", "mkdir", "mknod", "rmdir", "unlink",
		"swapon", "swapoff", "acct", "truncate", "fsopen", "mkdirat", "mknodat", "fchownat",
		"unlinkat", "fchmodat", "faccessat", "faccessat2", "fspick", "open_tree", "rename", "link",
		"symlink", "symlinkat", "renameat", "renameat2", "linkat", "open", "creat", "openat", "openat2",
	}},
	{exitProgQuota, []string{"quotactl", "quotactl_fd"}},
	{exitProgMountQuery, []string{"statmount", "listmount"}},
	{exitProgIovecBase, []string{"readv", "preadv", "preadv2", "process_vm_readv"}},
	{exitProgMsg, []string{"sendmsg", "recvmsg"}},
	{exitProgRecvmmsgBase01, []string{"recvmmsg"}},
	{exitProgMmsgFinal, []string{"sendmmsg"}},
}

func newBPFRoutePlan(table map[uint32]meta.Syscall) (bpfRoutePlan, error) {
	ids := make(map[string]uint32, len(table))
	plan := bpfRoutePlan{
		enter: make(map[uint32]uint32, len(table)),
		exit:  make(map[uint32]uint32, len(table)),
	}
	for id, syscall := range table {
		if id >= bpfRouteMapMaxEntries {
			return bpfRoutePlan{}, fmt.Errorf("syscall id %d exceeds BPF route map capacity %d", id, bpfRouteMapMaxEntries)
		}
		if previous, exists := ids[syscall.Name]; exists && previous != id {
			return bpfRoutePlan{}, fmt.Errorf("syscall name %q has ids %d and %d", syscall.Name, previous, id)
		}
		ids[syscall.Name] = id
		plan.enter[id] = enterProgNoPayload
		plan.exit[id] = exitProgGeneric
	}
	applyBPFRouteRules(plan.enter, ids, bpfEnterRouteRules)
	applyBPFRouteRules(plan.exit, ids, bpfExitRouteRules)
	return plan, nil
}

func applyBPFRouteRules(routes map[uint32]uint32, ids map[string]uint32, rules []bpfRouteRule) {
	for _, rule := range rules {
		for _, name := range rule.names {
			if id, ok := ids[name]; ok {
				routes[id] = rule.slot
			}
		}
	}
}

func configureBPFRouteMaps(
	objs *bpfObjects,
	programs bpfProgramProvider,
	plan bpfRoutePlan,
) error {
	if objs == nil || objs.EnterRoutes == nil || objs.ExitRoutes == nil {
		return fmt.Errorf("BPF route maps are unavailable")
	}
	enterPrograms := routePrograms(enterProgArrayEntries(programs))
	if err := putBPFRouteEntries("enter_routes", objs.EnterRoutes, plan.enter, enterPrograms); err != nil {
		return err
	}
	exitPrograms := routePrograms(exitProgArrayEntries(programs))
	return putBPFRouteEntries("exit_routes", objs.ExitRoutes, plan.exit, exitPrograms)
}

func routePrograms(entries []progArrayEntry) map[uint32]*ebpf.Program {
	programs := make(map[uint32]*ebpf.Program, len(entries))
	for _, entry := range entries {
		programs[entry.index] = entry.prog
	}
	return programs
}

func putBPFRouteEntries(name string, writer progArrayWriter, routes map[uint32]uint32, programs map[uint32]*ebpf.Program) error {
	ids := make([]uint32, 0, len(routes))
	for id := range routes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		slot := routes[id]
		program := programs[slot]
		if program == nil {
			return fmt.Errorf("%s[%d]: nil handler for slot %d", name, id, slot)
		}
		if err := writer.Put(id, program); err != nil {
			return fmt.Errorf("%s[%d]: %w", name, id, err)
		}
	}
	return nil
}
