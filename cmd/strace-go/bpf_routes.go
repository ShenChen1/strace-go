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

// bpfRouteCapability is the final capture policy for one syscall. A zero slot
// means that the generic handler owns that direction.
type bpfRouteCapability struct {
	enterSlot uint32
	exitSlot  uint32
}

func isGenericEnterRoute(sysID uint32) bool {
	syscall, ok := meta.SyscallTable[sysID]
	if !ok {
		return true
	}
	capability, ok := bpfRouteCapabilities[syscall.Name]
	return !ok || capability.enterSlot == 0
}

func isPlainGenericEnterExitRoute(sysID uint32) bool {
	// Elision is safe only when both directions use the generic event; specialized exits may carry OUT payload.
	syscall, ok := meta.SyscallTable[sysID]
	if !ok {
		return true
	}
	capability, ok := bpfRouteCapabilities[syscall.Name]
	return !ok || (capability.enterSlot == 0 && capability.exitSlot == 0)
}

// Only these direct exits carry all args and their bounded OUT snapshot in one
// event, so text can synthesize their missing generic enter safely.
func isStandaloneExitElisionRoute(sysID uint32) bool {
	syscall, ok := meta.SyscallTable[sysID]
	if !ok || !isGenericEnterRoute(sysID) {
		return false
	}
	capability, ok := bpfRouteCapabilities[syscall.Name]
	if !ok || capability.exitSlot == 0 {
		return false
	}
	switch syscall.Name {
	case "clock_gettime", "clock_getres", "gettimeofday", "arch_prctl", "get_robust_list":
		return true
	default:
		return false
	}
}

// BTF describes syscall arguments, but not which bounded capture handler owns
// their lifetime and payload semantics. Keep that product policy explicit and
// give each syscall one record so enter/exit choices cannot be overwritten by
// rule ordering.
var bpfRouteCapabilities = map[string]bpfRouteCapability{
	"exit": {enterSlot: enterProgTerminating}, "exit_group": {enterSlot: enterProgTerminating},
	"execve": {enterSlot: enterProgExec, exitSlot: exitProgIO}, "execveat": {enterSlot: enterProgExec, exitSlot: exitProgIO},
	"stat": {enterSlot: enterProgPathStat, exitSlot: exitProgStruct}, "lstat": {enterSlot: enterProgPathStat, exitSlot: exitProgStruct},
	"statfs": {enterSlot: enterProgPathStat, exitSlot: exitProgStruct}, "newfstatat": {enterSlot: enterProgPathStat, exitSlot: exitProgStruct},
	"statx":  {enterSlot: enterProgPathStat, exitSlot: exitProgStruct},
	"access": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath}, "chdir": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath},
	"chroot": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath}, "chmod": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath},
	"chown": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath}, "lchown": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath},
	"mkdir": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath}, "mknod": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath},
	"rmdir": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath}, "unlink": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath},
	"swapon": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath}, "swapoff": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath},
	"acct": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath}, "truncate": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath},
	"fsopen": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath}, "mkdirat": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath},
	"mknodat": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath}, "fchownat": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath},
	"unlinkat": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath}, "fchmodat": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath},
	"faccessat": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath}, "faccessat2": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath},
	"fspick": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath}, "open_tree": {enterSlot: enterProgPathOnly, exitSlot: exitProgPath},
	"rename": {enterSlot: enterProgDualPath, exitSlot: exitProgPath}, "link": {enterSlot: enterProgDualPath, exitSlot: exitProgPath},
	"symlink": {enterSlot: enterProgDualPath, exitSlot: exitProgPath}, "symlinkat": {enterSlot: enterProgDualPath, exitSlot: exitProgPath},
	"renameat": {enterSlot: enterProgDualPath, exitSlot: exitProgPath}, "renameat2": {enterSlot: enterProgDualPath, exitSlot: exitProgPath},
	"linkat": {enterSlot: enterProgDualPath, exitSlot: exitProgPath}, "openat2": {enterSlot: enterProgOpenat2, exitSlot: exitProgPath},
	"readlink": {enterSlot: enterProgReadlink, exitSlot: exitProgStruct}, "readlinkat": {enterSlot: enterProgReadlink, exitSlot: exitProgStruct},
	"setrlimit": {enterSlot: enterProgMiscStruct, exitSlot: exitProgStruct}, "prlimit64": {enterSlot: enterProgMiscStruct, exitSlot: exitProgStruct},
	"sendfile": {enterSlot: enterProgSmallStruct, exitSlot: exitProgAsync}, "copy_file_range": {enterSlot: enterProgSmallStruct},
	"setitimer": {enterSlot: enterProgItimer, exitSlot: exitProgFDTime}, "clock_settime": {enterSlot: enterProgTimeStruct},
	"settimeofday": {enterSlot: enterProgTimeStruct}, "rt_sigaction": {enterSlot: enterProgSignal, exitSlot: exitProgStruct},
	"rt_sigprocmask": {enterSlot: enterProgSignal, exitSlot: exitProgStruct}, "rt_sigsuspend": {enterSlot: enterProgSignal, exitSlot: exitProgStruct},
	"signalfd": {enterSlot: enterProgSignal, exitSlot: exitProgFDTime}, "signalfd4": {enterSlot: enterProgSignal, exitSlot: exitProgFDTime},
	"utime": {enterSlot: enterProgFileTime}, "utimes": {enterSlot: enterProgFileTime}, "futimesat": {enterSlot: enterProgFileTime},
	"utimensat": {enterSlot: enterProgFileTime}, "nanosleep": {enterSlot: enterProgSleep, exitSlot: exitProgFDTime},
	"clock_nanosleep": {enterSlot: enterProgSleep, exitSlot: exitProgFDTime}, "futex": {enterSlot: enterProgFutex},
	"futex_wait": {enterSlot: enterProgFutex}, "futex_waitv": {enterSlot: enterProgFutex}, "futex_requeue": {enterSlot: enterProgFutex},
	"cachestat": {enterSlot: enterProgCachestat, exitSlot: exitProgAsync}, "capget": {enterSlot: enterProgCapability, exitSlot: exitProgAsync},
	"capset": {enterSlot: enterProgCapability, exitSlot: exitProgAsync}, "memfd_create": {enterSlot: enterProgMemfd},
	"prctl": {enterSlot: enterProgPrctl, exitSlot: exitProgAsync}, "clone3": {enterSlot: enterProgClone3}, "bpf": {enterSlot: enterProgBpf, exitSlot: exitProgIO},
	"readv": {enterSlot: enterProgIovec, exitSlot: exitProgIovecBase}, "writev": {enterSlot: enterProgIovec},
	"preadv": {enterSlot: enterProgIovec, exitSlot: exitProgIovecBase}, "pwritev": {enterSlot: enterProgIovec},
	"preadv2": {enterSlot: enterProgIovec, exitSlot: exitProgIovecBase}, "pwritev2": {enterSlot: enterProgIovec},
	"vmsplice": {enterSlot: enterProgIovec}, "process_vm_readv": {enterSlot: enterProgIovec, exitSlot: exitProgIovecBase},
	"process_vm_writev": {enterSlot: enterProgIovec}, "process_madvise": {enterSlot: enterProgIovec},
	"sendmsg": {enterSlot: enterProgMsg, exitSlot: exitProgMsg}, "recvmsg": {enterSlot: enterProgMsg, exitSlot: exitProgMsg},
	"sendmmsg": {enterSlot: enterProgMmsg, exitSlot: exitProgMmsgFinal}, "recvmmsg": {enterSlot: enterProgMmsg, exitSlot: exitProgRecvmmsgBase01},
	"fcntl": {enterSlot: enterProgFcntl, exitSlot: exitProgControl}, "ioctl": {enterSlot: enterProgIoctl, exitSlot: exitProgControl},
	"connect": {enterSlot: enterProgNetwork, exitSlot: exitProgControl}, "bind": {enterSlot: enterProgNetwork, exitSlot: exitProgControl},
	"sendto": {enterSlot: enterProgNetwork, exitSlot: exitProgControl}, "recvfrom": {enterSlot: enterProgNetwork, exitSlot: exitProgControl},
	"accept": {enterSlot: enterProgNetwork, exitSlot: exitProgControl}, "accept4": {enterSlot: enterProgNetwork, exitSlot: exitProgControl},
	"getsockname": {enterSlot: enterProgNetwork, exitSlot: exitProgControl}, "getpeername": {enterSlot: enterProgNetwork, exitSlot: exitProgControl},
	"setsockopt": {enterSlot: enterProgNetwork, exitSlot: exitProgControl}, "getsockopt": {enterSlot: enterProgNetwork, exitSlot: exitProgControl},
	"add_key": {enterSlot: enterProgKey}, "request_key": {enterSlot: enterProgKey},
	"keyctl":   {enterSlot: enterProgKey, exitSlot: exitProgIO},
	"setxattr": {enterSlot: enterProgXattr}, "lsetxattr": {enterSlot: enterProgXattr}, "fsetxattr": {enterSlot: enterProgXattr},
	"getxattr": {enterSlot: enterProgXattr, exitSlot: exitProgIO}, "lgetxattr": {enterSlot: enterProgXattr, exitSlot: exitProgIO},
	"fgetxattr": {enterSlot: enterProgXattr, exitSlot: exitProgIO}, "listxattr": {enterSlot: enterProgXattr, exitSlot: exitProgIO},
	"llistxattr": {enterSlot: enterProgXattr, exitSlot: exitProgIO}, "flistxattr": {enterSlot: enterProgXattr, exitSlot: exitProgIO},
	"removexattr": {enterSlot: enterProgXattr}, "lremovexattr": {enterSlot: enterProgXattr}, "fremovexattr": {enterSlot: enterProgXattr},
	"mount": {enterSlot: enterProgFs}, "umount2": {enterSlot: enterProgFs}, "fsconfig": {enterSlot: enterProgFs},
	"mount_setattr": {enterSlot: enterProgFs}, "statmount": {enterSlot: enterProgFs, exitSlot: exitProgMountQuery},
	"listmount": {enterSlot: enterProgFs, exitSlot: exitProgMountQuery}, "io_setup": {enterSlot: enterProgAio, exitSlot: exitProgAsync},
	"io_getevents": {enterSlot: enterProgAio, exitSlot: exitProgAsync}, "io_pgetevents": {enterSlot: enterProgAio, exitSlot: exitProgAsync},
	"io_submit": {enterSlot: enterProgAio}, "io_cancel": {enterSlot: enterProgAio}, "poll": {enterSlot: enterProgPoll, exitSlot: exitProgAsync},
	"ppoll": {enterSlot: enterProgPoll, exitSlot: exitProgAsync}, "select": {enterSlot: enterProgSelect, exitSlot: exitProgIO},
	"pselect6":  {enterSlot: enterProgSelect, exitSlot: exitProgIO},
	"epoll_ctl": {enterSlot: enterProgEpoll}, "epoll_pwait2": {enterSlot: enterProgEpoll, exitSlot: exitProgIO},
	"epoll_wait": {exitSlot: exitProgIO}, "epoll_pwait": {exitSlot: exitProgIO}, "getdents": {exitSlot: exitProgIO},
	"getdents64": {exitSlot: exitProgIO}, "quotactl": {enterSlot: enterProgQuota, exitSlot: exitProgQuota},
	"quotactl_fd": {enterSlot: enterProgQuota, exitSlot: exitProgQuota}, "move_mount": {enterSlot: enterProgMountPath},
	"open": {enterSlot: enterProgPayload, exitSlot: exitProgPath}, "creat": {enterSlot: enterProgPayload, exitSlot: exitProgPath},
	"openat": {enterSlot: enterProgPayload, exitSlot: exitProgPath}, "write": {enterSlot: enterProgPayload}, "pwrite64": {enterSlot: enterProgPayload},
	"read": {exitSlot: exitProgFDTime}, "pread64": {exitSlot: exitProgFDTime}, "gettimeofday": {exitSlot: exitProgFDTime},
	"clock_gettime": {exitSlot: exitProgFDTime}, "clock_getres": {exitSlot: exitProgFDTime}, "getitimer": {exitSlot: exitProgFDTime},
	"adjtimex": {exitSlot: exitProgFDTime}, "clock_adjtime": {exitSlot: exitProgFDTime}, "dup": {exitSlot: exitProgFDTime},
	"dup2": {exitSlot: exitProgFDTime}, "dup3": {exitSlot: exitProgFDTime}, "epoll_create": {exitSlot: exitProgFDTime},
	"timerfd_create": {exitSlot: exitProgFDTime}, "eventfd": {exitSlot: exitProgFDTime}, "eventfd2": {exitSlot: exitProgFDTime},
	"epoll_create1": {exitSlot: exitProgFDTime}, "inotify_init": {exitSlot: exitProgFDTime}, "inotify_init1": {exitSlot: exitProgFDTime},
	"fstat": {exitSlot: exitProgStruct}, "fstatfs": {exitSlot: exitProgStruct}, "waitid": {exitSlot: exitProgStruct},
	"getcwd": {exitSlot: exitProgStruct}, "getrlimit": {exitSlot: exitProgStruct}, "pipe": {exitSlot: exitProgStruct}, "pipe2": {exitSlot: exitProgStruct},
	"socketpair": {exitSlot: exitProgStruct}, "uname": {exitSlot: exitProgStruct}, "sysinfo": {exitSlot: exitProgStruct},
	"arch_prctl": {exitSlot: exitProgAsync}, "get_robust_list": {exitSlot: exitProgAsync},
}

func newBPFRoutePlan(table map[uint32]meta.Syscall) (bpfRoutePlan, error) {
	return newBPFRoutePlanWithCapabilities(table, bpfRouteCapabilities)
}

func newBPFRoutePlanWithCapabilities(
	table map[uint32]meta.Syscall,
	capabilities map[string]bpfRouteCapability,
) (bpfRoutePlan, error) {
	ids := make(map[string]uint32, len(table))
	plan := bpfRoutePlan{
		enter: make(map[uint32]uint32, len(table)),
		exit:  make(map[uint32]uint32, len(table)),
	}
	if err := validateBPFRouteCapabilities(capabilities); err != nil {
		return bpfRoutePlan{}, err
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
		capability, ok := capabilities[syscall.Name]
		if !ok {
			continue
		}
		if capability.enterSlot != 0 {
			plan.enter[id] = capability.enterSlot
		}
		if capability.exitSlot != 0 {
			plan.exit[id] = capability.exitSlot
		}
	}
	return plan, nil
}

func validateBPFRouteCapabilities(capabilities map[string]bpfRouteCapability) error {
	for name, capability := range capabilities {
		if name == "" {
			return fmt.Errorf("BPF route capability has empty syscall name")
		}
		if capability.enterSlot != 0 {
			if _, ok := bpfTailCallProgramBySlot(bpfEnterProgramCatalog, capability.enterSlot); !ok {
				return fmt.Errorf("unknown BPF enter route slot %d for syscall %q", capability.enterSlot, name)
			}
		}
		if capability.exitSlot != 0 {
			if _, ok := bpfTailCallProgramBySlot(bpfExitProgramCatalog, capability.exitSlot); !ok {
				return fmt.Errorf("unknown BPF exit route slot %d for syscall %q", capability.exitSlot, name)
			}
		}
	}
	return nil
}

func configureBPFRouteMaps(
	maps bpfMapProvider,
	programs bpfProgramProvider,
	plan bpfRoutePlan,
) error {
	if maps == nil {
		return fmt.Errorf("BPF route maps are unavailable")
	}
	enterRoutes := maps.coreMap(bpfMapEnterRoutes)
	exitRoutes := maps.coreMap(bpfMapExitRoutes)
	if enterRoutes == nil || exitRoutes == nil {
		return fmt.Errorf("BPF route maps are unavailable")
	}
	enterPrograms := routePrograms(enterProgArrayEntries(programs))
	if err := putBPFRouteEntries(bpfMapEnterRoutes, enterRoutes, plan.enter, enterPrograms); err != nil {
		return err
	}
	exitPrograms := routePrograms(exitProgArrayEntries(programs))
	return putBPFRouteEntries(bpfMapExitRoutes, exitRoutes, plan.exit, exitPrograms)
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
