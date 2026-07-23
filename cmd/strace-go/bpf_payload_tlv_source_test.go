package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestBPFBasicPayloadsUseTLVFlag(t *testing.T) {
	root := repoRootForTest(t)
	straceSource := readTextFile(t, filepath.Join(root, "bpf/strace.c"))
	tlvHeader := readTextFile(t, filepath.Join(root, "bpf/payload_tlv.h"))
	directHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_direct_event_v2.h"))
	fdArrayDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_fd_array_direct_event_v2.h"))
	getcwdDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_getcwd_direct_event_v2.h"))
	miscDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_misc_struct_direct_event_v2.h"))
	statDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_stat_direct_event_v2.h"))
	waitidDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_waitid_direct_event_v2.h"))
	signalDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_signal_direct_event_v2.h"))
	pathStatDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_path_stat_direct_event_v2.h"))
	readlinkDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_readlink_direct_event_v2.h"))
	timeDirectHeader := readTextFile(t, filepath.Join(root, "bpf/syscall_time_direct_event_v2.h"))
	capturePolicy := readTextFile(t, filepath.Join(root, "cmd/generate-syscalls/capture_rules.yaml"))
	generatedCapture := readTextFile(t, filepath.Join(root, "bpf/syscall_capture.h"))

	if !strings.Contains(straceSource, `#include "payload_tlv.h"`) {
		t.Fatal("strace.c does not include payload_tlv.h")
	}
	if !strings.Contains(straceSource, "#define SYS_READ 0") {
		t.Fatal("strace.c missing SYS_READ constant for read TLV capture")
	}
	if !strings.Contains(straceSource, "#define SYS_PIPE 22") {
		t.Fatal("strace.c missing SYS_PIPE constant for fd-array direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_CLOSE 3") {
		t.Fatal("strace.c missing SYS_CLOSE constant for scalar direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_SOCKETPAIR 53") {
		t.Fatal("strace.c missing SYS_SOCKETPAIR constant for fd-array direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_UNAME 63") {
		t.Fatal("strace.c missing SYS_UNAME constant for misc struct direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_STAT 4") {
		t.Fatal("strace.c missing SYS_STAT constant for stat direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_FSTAT 5") {
		t.Fatal("strace.c missing SYS_FSTAT constant for fstat direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_LSTAT 6") {
		t.Fatal("strace.c missing SYS_LSTAT constant for lstat direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_STATFS 137") {
		t.Fatal("strace.c missing SYS_STATFS constant for statfs direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_FSTATFS 138") {
		t.Fatal("strace.c missing SYS_FSTATFS constant for fstatfs direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_PREAD64 17") {
		t.Fatal("strace.c missing SYS_PREAD64 constant for pread64 TLV capture")
	}
	if !strings.Contains(straceSource, "#define SYS_PWRITE64 18") {
		t.Fatal("strace.c missing SYS_PWRITE64 constant for pwrite64 TLV capture")
	}
	if !strings.Contains(straceSource, "#define SYS_GETPID 39") {
		t.Fatal("strace.c missing SYS_GETPID constant for scalar direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_GETCWD 79") {
		t.Fatal("strace.c missing SYS_GETCWD constant for getcwd direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_READLINK 89") {
		t.Fatal("strace.c missing SYS_READLINK constant for readlink direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_GETTIMEOFDAY 96") {
		t.Fatal("strace.c missing SYS_GETTIMEOFDAY constant for gettimeofday direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_GETRLIMIT 97") ||
		!strings.Contains(straceSource, "#define SYS_SYSINFO 99") ||
		!strings.Contains(straceSource, "#define SYS_SETRLIMIT 160") ||
		!strings.Contains(straceSource, "#define SYS_PRLIMIT64 302") {
		t.Fatal("strace.c missing misc struct direct event v2 constants")
	}
	if !strings.Contains(straceSource, "#define SYS_CLOCK_GETTIME 228") ||
		!strings.Contains(straceSource, "#define SYS_CLOCK_GETRES 229") {
		t.Fatal("strace.c missing clock direct event v2 constants")
	}
	if !strings.Contains(straceSource, "#define SYS_WAITID 247") {
		t.Fatal("strace.c missing SYS_WAITID constant for waitid direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_RT_SIGACTION 13") ||
		!strings.Contains(straceSource, "#define SYS_RT_SIGPROCMASK 14") ||
		!strings.Contains(straceSource, "volatile const u32 SYS_RT_SIGSUSPEND = 130;") {
		t.Fatal("strace.c missing signal direct event v2 constants")
	}
	if !strings.Contains(straceSource, "#define SYS_OPENAT 257") {
		t.Fatal("strace.c missing SYS_OPENAT constant for openat TLV capture")
	}
	if !strings.Contains(straceSource, "#define SYS_NEWFSTATAT 262") {
		t.Fatal("strace.c missing SYS_NEWFSTATAT constant for newfstatat direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_READLINKAT 267") {
		t.Fatal("strace.c missing SYS_READLINKAT constant for readlinkat direct event v2 path")
	}
	if !strings.Contains(straceSource, "#define SYS_PIPE2 293") {
		t.Fatal("strace.c missing SYS_PIPE2 constant for fd-array direct event v2 path")
	}
	if !strings.Contains(straceSource, `#include "syscall_direct_event_v2.h"`) {
		t.Fatal("strace.c should include scalar direct event v2 helpers")
	}
	if !strings.Contains(straceSource, "#define EVENT_V2_ENTER_BODY_LEN 72") ||
		!strings.Contains(straceSource, "s64 ret;") ||
		!strings.Contains(straceSource, "s32 probe_ret_enter;") ||
		!strings.Contains(directHeader, "body->ret = ret_value;") ||
		!strings.Contains(directHeader, "body->probe_ret_enter = probe_ret_enter;") {
		t.Fatal("event v2 enter body should carry ret and probe status for exec-style enter states")
	}
	if strings.Contains(straceSource, "capture_openat_tlv(e);") || strings.Contains(tlvHeader, "capture_openat_tlv") {
		t.Fatal("openat TLV capture should not use the bpf_event fixed-window helper")
	}
	if strings.Contains(straceSource, "capture_write_tlv(e);") || strings.Contains(tlvHeader, "capture_write_tlv") {
		t.Fatal("write TLV capture should not use the bpf_event fixed-window helper")
	}
	if strings.Contains(straceSource, "capture_read_tlv(e);") || strings.Contains(tlvHeader, "capture_read_tlv") {
		t.Fatal("read TLV capture should not use the bpf_event fixed-window helper")
	}
	if strings.Contains(straceSource, "capture_exec_tlv(") ||
		strings.Contains(straceSource, "capture_exec_path_tlv(") {
		t.Fatal("exec TLV capture should not use the bpf_event fixed-window helper")
	}
	if !strings.Contains(directHeader, "capture_exec_tlv_direct(") ||
		!strings.Contains(directHeader, "emit_exec_enter_event_v2_direct(") ||
		!strings.Contains(directHeader, "emit_exec_exit_event_v2_direct(") ||
		!strings.Contains(straceSource, "is_exec_payload_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "emit_exec_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time, probe_ret_enter);") ||
		!strings.Contains(straceSource, "emit_exec_exit_event_v2_direct(p, ret_value, duration);") {
		t.Fatal("execve/execveat should use direct event v2 TLV helpers instead of the bpf_event carrier")
	}
	if !strings.Contains(directHeader, "capture_exec_env_records_direct(") ||
		!strings.Contains(directHeader, "snapshot_offset + sizeof(header) + EXEC_ARG_MAX * sizeof(struct exec_arg_snapshot)") ||
		!strings.Contains(directHeader, "&header.env_count") ||
		!strings.Contains(directHeader, "&header.env_status") ||
		!strings.Contains(directHeader, "&header.env_next") {
		t.Fatal("execve/execveat direct snapshot should deep-copy envp records into the fixed env snapshot area")
	}
	for _, legacyRule := range []string{
		"syscalls: [getcwd]",
		"syscalls: [clock_gettime, clock_getres]",
		"syscalls: [gettimeofday]",
		"syscalls: [getrlimit]",
		"syscalls: [stat, lstat]",
		"syscalls: [fstat]",
		"syscalls: [newfstatat]",
		"syscalls: [pipe, pipe2]",
		"syscalls: [prlimit64]",
		"syscalls: [readlink]",
		"syscalls: [readlinkat]",
		"syscalls: [setrlimit]",
		"syscalls: [socketpair]",
		"syscalls: [statfs]",
		"syscalls: [fstatfs]",
		"syscalls: [sysinfo]",
		"syscalls: [uname]",
		"syscalls: [read, pread64]",
		"syscalls: [write, pwrite64]",
		"syscalls: [waitid]",
		"syscalls: [rt_sigaction]",
		"syscalls: [rt_sigprocmask]",
		"syscalls: [rt_sigsuspend]",
		"syscalls: [chdir, execve]",
		"syscalls: [openat, execveat]",
		"case 0: /* read */",
		"case 1: /* write */",
		"case 4: /* stat */",
		"case 5: /* fstat */",
		"case 6: /* lstat */",
		"case 13: /* rt_sigaction */",
		"case 14: /* rt_sigprocmask */",
		"case 17: /* pread64 */",
		"case 18: /* pwrite64 */",
		"case 22: /* pipe */",
		"case 59: /* execve */",
		"case 53: /* socketpair */",
		"case 63: /* uname */",
		"case 79: /* getcwd */",
		"case 89: /* readlink */",
		"case 96: /* gettimeofday */",
		"case 97: /* getrlimit */",
		"case 99: /* sysinfo */",
		"case 130: /* rt_sigsuspend */",
		"case 137: /* statfs */",
		"case 138: /* fstatfs */",
		"case 160: /* setrlimit */",
		"case 228: /* clock_gettime */",
		"case 229: /* clock_getres */",
		"case 247: /* waitid */",
		"case 257: /* openat */",
		"case 262: /* newfstatat */",
		"case 267: /* readlinkat */",
		"case 293: /* pipe2 */",
		"case 302: /* prlimit64 */",
		"case 322: /* execveat */",
	} {
		if strings.Contains(capturePolicy, legacyRule) || strings.Contains(generatedCapture, legacyRule) {
			t.Fatalf("direct path/exec syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
	if !strings.Contains(directHeader, "flags |= EVENT_FLAG_PAYLOAD_TLV") ||
		!strings.Contains(directHeader, "u16 flags = EVENT_FLAG_GENERIC_ENTER") {
		t.Fatal("direct enter helpers should preserve generic enter and payload TLV flags")
	}
	if !strings.Contains(straceSource, "header->event_type = EVENT_TYPE_LIFECYCLE;") ||
		!strings.Contains(straceSource, "body->action = kind;") {
		t.Fatal("lifecycle events should build event v2 fields without the bpf_event carrier")
	}
	if strings.Contains(straceSource, "lifecycle_action") {
		t.Fatal("bpf_event carrier should not retain lifecycle_action")
	}
	if strings.Contains(straceSource, "e->ptr") {
		t.Fatal("bpf_event carrier should not retain raw pointer field")
	}
	for _, legacyCarrier := range []string{
		`#include "syscall_capture.h"`,
		"struct bpf_event",
		"} heap SEC(\".maps\")",
		"emit_syscall_event_v2(",
		"emit_event(",
		"CAPTURE_ARGS_ENTER(",
		"CAPTURE_ARGS_EXIT(",
	} {
		if strings.Contains(straceSource, legacyCarrier) {
			t.Fatalf("BPF runtime should not retain fixed-window carrier artifact %q", legacyCarrier)
		}
	}
	if !strings.Contains(directHeader, "emit_syscall_enter_event_v2_direct(") ||
		!strings.Contains(straceSource, "emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);") ||
		!strings.Contains(straceSource, "emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);") ||
		!strings.Contains(straceSource, "save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);") ||
		!strings.Contains(straceSource, "is_scalar_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_sys_exit_direct_syscall(p->sys_id)") {
		t.Fatal("scalar syscalls should use direct event v2 helpers instead of the bpf_event carrier")
	}
	if !strings.Contains(directHeader, "return sys_id == SYS_GETPID || sys_id == SYS_CLOSE;") {
		t.Fatal("scalar direct syscall policy should include getpid and close")
	}
	if !strings.Contains(directHeader, "is_terminating_direct_syscall(") ||
		!strings.Contains(directHeader, "return sys_id == SYS_EXIT || sys_id == SYS_EXIT_GROUP;") ||
		!strings.Contains(directHeader, "emit_terminating_exit_event_v2_direct(") ||
		!strings.Contains(straceSource, "is_terminating_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "emit_terminating_exit_event_v2_direct(pid, tid, sys_id, ctx, enter_time);") {
		t.Fatal("exit/exit_group should synthesize direct event v2 exit events without the bpf_event carrier")
	}
	if strings.Contains(straceSource, "if (sys_id == SYS_EXIT || sys_id == SYS_EXIT_GROUP)") {
		t.Fatal("exit/exit_group should not retain the legacy bpf_event enter special case")
	}
	if !strings.Contains(directHeader, "sys_id == SYS_OPENAT") ||
		!strings.Contains(directHeader, "sys_id == SYS_WRITE") ||
		!strings.Contains(directHeader, "sys_id == SYS_PWRITE64") ||
		!strings.Contains(straceSource, "is_payload_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_sys_exit_direct_syscall(p->sys_id)") ||
		!strings.Contains(directHeader, "emit_payload_enter_event_v2_direct(") ||
		!strings.Contains(directHeader, "capture_openat_path_tlv_direct(") {
		t.Fatal("payload syscalls should use direct event v2 TLV helpers instead of the bpf_event carrier")
	}
	if !strings.Contains(directHeader, "PAYLOAD_TLV_HEADER_SIZE + PAYLOAD_TLV_OPENAT_MAX") ||
		!strings.Contains(directHeader, "bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_OPENAT_MAX)") {
		t.Fatal("openat direct helper should reserve TLV payload capacity and copy path into dynptr data")
	}
	if !strings.Contains(directHeader, "return sys_id == SYS_WRITE || sys_id == SYS_PWRITE64;") ||
		!strings.Contains(directHeader, "capture_write_bytes_tlv_direct(") ||
		!strings.Contains(directHeader, "PAYLOAD_TLV_HEADER_SIZE + PAYLOAD_TLV_WRITE_MAX") ||
		!strings.Contains(directHeader, "bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_WRITE_MAX)") ||
		!strings.Contains(directHeader, "record_payload_truncated_event();") {
		t.Fatal("write direct helper should reserve TLV payload capacity, copy bytes, and record truncation")
	}
	if !strings.Contains(directHeader, "return sys_id == SYS_READ || sys_id == SYS_PREAD64;") ||
		!strings.Contains(straceSource, "is_exit_payload_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_exit_payload_direct_syscall(p->sys_id)") ||
		!strings.Contains(straceSource, "ret_value > 0") ||
		!strings.Contains(directHeader, "capture_read_bytes_tlv_direct(") ||
		!strings.Contains(directHeader, "emit_payload_exit_event_v2_direct(") ||
		!strings.Contains(directHeader, "PAYLOAD_TLV_HEADER_SIZE + PAYLOAD_TLV_READ_MAX") ||
		!strings.Contains(directHeader, "PAYLOAD_TLV_FLAG_DIRECTION_OUT") {
		t.Fatal("read direct helper should reserve exit TLV payload capacity and copy bytes with out direction")
	}
	if !strings.Contains(straceSource, `#include "syscall_time_direct_event_v2.h"`) ||
		!strings.Contains(timeDirectHeader, "is_time_struct_direct_syscall(") ||
		!strings.Contains(timeDirectHeader, "return sys_id == SYS_CLOCK_GETTIME || sys_id == SYS_CLOCK_GETRES;") ||
		!strings.Contains(timeDirectHeader, "return sys_id == SYS_GETTIMEOFDAY;") ||
		!strings.Contains(timeDirectHeader, "PAYLOAD_TLV_KIND_STRUCT") ||
		!strings.Contains(timeDirectHeader, "emit_time_struct_exit_event_v2_direct(") ||
		!strings.Contains(timeDirectHeader, "emit_gettimeofday_exit_event_v2_direct(") ||
		!strings.Contains(timeDirectHeader, "TIME_DIRECT_TIMEZONE_SIZE") ||
		!strings.Contains(straceSource, "is_time_struct_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_sys_exit_direct_syscall(p->sys_id)") ||
		!strings.Contains(straceSource, "emit_time_struct_exit_event_v2_direct(p, ret_value, duration);") ||
		!strings.Contains(straceSource, "emit_gettimeofday_exit_event_v2_direct(p, ret_value, duration);") {
		t.Fatal("clock/gettimeofday syscalls should emit direct struct TLV exit events without the bpf_event carrier")
	}
	if !strings.Contains(straceSource, `#include "syscall_stat_direct_event_v2.h"`) ||
		!strings.Contains(straceSource, `#include "syscall_path_stat_direct_event_v2.h"`) ||
		!strings.Contains(statDirectHeader, "is_stat_struct_direct_syscall(") ||
		!strings.Contains(statDirectHeader, "sys_id == SYS_STAT || sys_id == SYS_LSTAT || sys_id == SYS_FSTAT") ||
		!strings.Contains(statDirectHeader, "sys_id == SYS_NEWFSTATAT || sys_id == SYS_STATFS || sys_id == SYS_FSTATFS;") ||
		!strings.Contains(statDirectHeader, "stat_direct_struct_arg_index(") ||
		!strings.Contains(statDirectHeader, "if (sys_id == SYS_NEWFSTATAT)") ||
		!strings.Contains(statDirectHeader, "return p->args[2];") ||
		!strings.Contains(statDirectHeader, "STAT_DIRECT_STRUCT_SIZE 144") ||
		!strings.Contains(statDirectHeader, "STATFS_DIRECT_STRUCT_SIZE 120") ||
		!strings.Contains(pathStatDirectHeader, "return sys_id == SYS_STAT || sys_id == SYS_LSTAT || sys_id == SYS_STATFS || sys_id == SYS_NEWFSTATAT;") ||
		!strings.Contains(pathStatDirectHeader, "emit_path_stat_enter_event_v2_direct_with_path(") ||
		!strings.Contains(pathStatDirectHeader, "ctx, ts_ns, 1, ctx->args[1]") ||
		!strings.Contains(pathStatDirectHeader, "ctx, ts_ns, 0, ctx->args[0]") ||
		!strings.Contains(pathStatDirectHeader, "emit_path_stat_enter_event_v2_direct(") ||
		!strings.Contains(pathStatDirectHeader, "PATH_STAT_DIRECT_PATH_MAX 512") ||
		!strings.Contains(statDirectHeader, "emit_stat_struct_exit_event_v2_direct(") ||
		!strings.Contains(timeDirectHeader, "is_stat_struct_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_path_stat_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "emit_path_stat_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);") ||
		!strings.Contains(straceSource, "is_stat_struct_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "emit_stat_struct_exit_event_v2_direct(p, ret_value, duration);") {
		t.Fatal("stat/lstat/newfstatat/statfs/fstat/fstatfs should emit direct TLV events without the bpf_event carrier")
	}
	if strings.Contains(straceSource, `#include "syscall_statfs_direct_event_v2.h"`) ||
		strings.Contains(straceSource, "is_path_statfs_direct_syscall(") {
		t.Fatal("path stat direct capture should not keep the statfs-only helper")
	}
	if !strings.Contains(straceSource, `#include "syscall_waitid_direct_event_v2.h"`) ||
		!strings.Contains(waitidDirectHeader, "WAITID_DIRECT_SIGINFO_SIZE 128") ||
		!strings.Contains(waitidDirectHeader, "WAITID_DIRECT_RUSAGE_SIZE 144") ||
		!strings.Contains(waitidDirectHeader, "is_waitid_direct_syscall(") ||
		!strings.Contains(waitidDirectHeader, "return sys_id == SYS_WAITID;") ||
		!strings.Contains(waitidDirectHeader, "capture_waitid_struct_tlv_direct(") ||
		!strings.Contains(waitidDirectHeader, "PAYLOAD_TLV_KIND_STRUCT") ||
		!strings.Contains(waitidDirectHeader, "PAYLOAD_TLV_FLAG_DIRECTION_OUT") ||
		!strings.Contains(waitidDirectHeader, "emit_waitid_exit_event_v2_direct(") ||
		!strings.Contains(waitidDirectHeader, "payload_size += capture_waitid_struct_tlv_direct(") ||
		!strings.Contains(timeDirectHeader, "is_waitid_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_waitid_direct_syscall(p->sys_id) && ret_value >= 0") ||
		!strings.Contains(straceSource, "emit_waitid_exit_event_v2_direct(p, ret_value, duration);") {
		t.Fatal("waitid should emit direct siginfo/rusage TLV exit events without the bpf_event carrier")
	}
	if !strings.Contains(straceSource, `#include "syscall_signal_direct_event_v2.h"`) ||
		!strings.Contains(signalDirectHeader, "SIGNAL_DIRECT_SIGSET_SIZE 8") ||
		!strings.Contains(signalDirectHeader, "SIGNAL_DIRECT_SIGACTION_SIZE 32") ||
		!strings.Contains(signalDirectHeader, "is_signal_direct_syscall(") ||
		!strings.Contains(signalDirectHeader, "is_signal_enter_direct_syscall(") ||
		!strings.Contains(signalDirectHeader, "emit_signal_enter_event_v2_direct(") ||
		!strings.Contains(signalDirectHeader, "emit_signal_exit_event_v2_direct(") ||
		!strings.Contains(signalDirectHeader, "emit_signal_sigsuspend_marker_event_v2_direct(") ||
		!strings.Contains(signalDirectHeader, "capture_signal_struct_tlv_direct(") ||
		!strings.Contains(signalDirectHeader, "PAYLOAD_TLV_KIND_STRUCT") ||
		!strings.Contains(signalDirectHeader, "PAYLOAD_TLV_FLAG_DIRECTION_OUT") ||
		!strings.Contains(signalDirectHeader, "init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, probe_ret_enter, -1);") ||
		!strings.Contains(timeDirectHeader, "is_signal_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_signal_enter_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "emit_signal_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time, -1);") ||
		!strings.Contains(straceSource, "should_emit_signal_sigsuspend_marker(tid, pid)") ||
		!strings.Contains(straceSource, "emit_signal_sigsuspend_marker_event_v2_direct(pid, tid, sys_id, ctx, enter_time);") ||
		!strings.Contains(straceSource, "is_signal_direct_syscall(p->sys_id) && ret_value >= 0") ||
		!strings.Contains(straceSource, "emit_signal_exit_event_v2_direct(p, ret_value, duration);") {
		t.Fatal("rt_sigaction/rt_sigprocmask/rt_sigsuspend should emit direct signal TLV events without the bpf_event carrier")
	}
	if !strings.Contains(straceSource, `#include "syscall_getcwd_direct_event_v2.h"`) ||
		!strings.Contains(getcwdDirectHeader, "is_getcwd_direct_syscall(") ||
		!strings.Contains(getcwdDirectHeader, "return sys_id == SYS_GETCWD;") ||
		!strings.Contains(getcwdDirectHeader, "GETCWD_DIRECT_BYTES_MAX 512") ||
		!strings.Contains(getcwdDirectHeader, "emit_getcwd_exit_event_v2_direct(") ||
		!strings.Contains(getcwdDirectHeader, "PAYLOAD_TLV_KIND_BYTES") ||
		!strings.Contains(getcwdDirectHeader, "PAYLOAD_TLV_FLAG_DIRECTION_OUT") ||
		!strings.Contains(straceSource, "is_getcwd_direct_syscall(sys_id)") ||
		!strings.Contains(timeDirectHeader, "is_getcwd_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "emit_getcwd_exit_event_v2_direct(p, ret_value, duration);") {
		t.Fatal("getcwd should emit direct TLV events without the bpf_event carrier")
	}
	if !strings.Contains(straceSource, `#include "syscall_readlink_direct_event_v2.h"`) ||
		!strings.Contains(readlinkDirectHeader, "is_readlink_direct_syscall(") ||
		!strings.Contains(readlinkDirectHeader, "return sys_id == SYS_READLINK || sys_id == SYS_READLINKAT;") ||
		!strings.Contains(readlinkDirectHeader, "READLINK_DIRECT_PATH_MAX 512") ||
		!strings.Contains(readlinkDirectHeader, "READLINK_DIRECT_BYTES_MAX 512") ||
		!strings.Contains(readlinkDirectHeader, "emit_readlink_enter_event_v2_direct(") ||
		!strings.Contains(readlinkDirectHeader, "emit_readlink_exit_event_v2_direct(") ||
		!strings.Contains(readlinkDirectHeader, "ctx, ts_ns, 1, ctx->args[1]") ||
		!strings.Contains(readlinkDirectHeader, "ctx, ts_ns, 0, ctx->args[0]") ||
		!strings.Contains(readlinkDirectHeader, "return p->args[2];") ||
		!strings.Contains(readlinkDirectHeader, "PAYLOAD_TLV_KIND_BYTES") ||
		!strings.Contains(readlinkDirectHeader, "PAYLOAD_TLV_FLAG_DIRECTION_OUT") ||
		!strings.Contains(timeDirectHeader, "is_readlink_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_readlink_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "emit_readlink_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);") ||
		!strings.Contains(straceSource, "emit_readlink_exit_event_v2_direct(p, ret_value, duration);") {
		t.Fatal("readlink/readlinkat should emit direct TLV events without the bpf_event carrier")
	}
	if !strings.Contains(straceSource, `#include "syscall_fd_array_direct_event_v2.h"`) ||
		!strings.Contains(fdArrayDirectHeader, "FD_ARRAY_DIRECT_SIZE 8") ||
		!strings.Contains(fdArrayDirectHeader, "is_fd_array_direct_syscall(") ||
		!strings.Contains(fdArrayDirectHeader, "return sys_id == SYS_PIPE || sys_id == SYS_PIPE2 || sys_id == SYS_SOCKETPAIR;") ||
		!strings.Contains(fdArrayDirectHeader, "fd_array_direct_arg_index(") ||
		!strings.Contains(fdArrayDirectHeader, "return 3;") ||
		!strings.Contains(fdArrayDirectHeader, "return p->args[3];") ||
		!strings.Contains(fdArrayDirectHeader, "PAYLOAD_TLV_KIND_STRUCT") ||
		!strings.Contains(fdArrayDirectHeader, "PAYLOAD_TLV_FLAG_DIRECTION_OUT") ||
		!strings.Contains(fdArrayDirectHeader, "emit_fd_array_exit_event_v2_direct(") ||
		!strings.Contains(timeDirectHeader, "is_fd_array_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_fd_array_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_fd_array_direct_syscall(p->sys_id) && ret_value == 0") ||
		!strings.Contains(straceSource, "emit_fd_array_exit_event_v2_direct(p, ret_value, duration);") {
		t.Fatal("pipe/pipe2/socketpair should emit direct fd-array struct TLV exit events without the bpf_event carrier")
	}
	if !strings.Contains(straceSource, `#include "syscall_misc_struct_direct_event_v2.h"`) ||
		!strings.Contains(miscDirectHeader, "MISC_DIRECT_RLIMIT_SIZE 16") ||
		!strings.Contains(miscDirectHeader, "MISC_DIRECT_SYSINFO_SIZE 112") ||
		!strings.Contains(miscDirectHeader, "MISC_DIRECT_UTSNAME_SIZE 390") ||
		!strings.Contains(miscDirectHeader, "is_misc_struct_direct_syscall(") ||
		!strings.Contains(miscDirectHeader, "sys_id == SYS_UNAME || sys_id == SYS_SYSINFO ||") ||
		!strings.Contains(miscDirectHeader, "sys_id == SYS_GETRLIMIT || sys_id == SYS_SETRLIMIT || sys_id == SYS_PRLIMIT64;") ||
		!strings.Contains(miscDirectHeader, "is_misc_struct_enter_direct_syscall(") ||
		!strings.Contains(miscDirectHeader, "return sys_id == SYS_SETRLIMIT || sys_id == SYS_PRLIMIT64;") ||
		!strings.Contains(miscDirectHeader, "is_misc_struct_exit_direct_syscall(") ||
		!strings.Contains(miscDirectHeader, "PAYLOAD_TLV_KIND_STRUCT") ||
		!strings.Contains(miscDirectHeader, "PAYLOAD_TLV_FLAG_DIRECTION_OUT") ||
		!strings.Contains(miscDirectHeader, "ctx, ts_ns, 2, ctx->args[2]") ||
		!strings.Contains(miscDirectHeader, "ctx, ts_ns, 1, ctx->args[1]") ||
		!strings.Contains(miscDirectHeader, "emit_misc_struct_enter_event_v2_direct(") ||
		!strings.Contains(miscDirectHeader, "emit_misc_struct_exit_event_v2_direct(") ||
		!strings.Contains(miscDirectHeader, "return p->args[3];") ||
		!strings.Contains(miscDirectHeader, "return p->args[1];") ||
		!strings.Contains(timeDirectHeader, "is_misc_struct_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "is_misc_struct_enter_direct_syscall(sys_id)") ||
		!strings.Contains(straceSource, "emit_misc_struct_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);") ||
		!strings.Contains(straceSource, "is_misc_struct_exit_direct_syscall(p->sys_id) && ret_value >= 0") ||
		!strings.Contains(straceSource, "emit_misc_struct_exit_event_v2_direct(p, ret_value, duration);") {
		t.Fatal("uname/sysinfo/getrlimit/setrlimit/prlimit64 should emit direct misc struct TLV events without the bpf_event carrier")
	}
	if !strings.Contains(straceSource, "emit_lifecycle_event_v2_direct(kind, pid, tid, arg0, arg1, snapshot_str);") {
		t.Fatal("lifecycle events should be emitted directly as event v2")
	}
	if strings.Contains(straceSource, "emit_lifecycle_event_v2(e);") {
		t.Fatal("lifecycle events should not use the bpf_event carrier")
	}
	if strings.Contains(straceSource, "emit_legacy_event") {
		t.Fatal("BPF runtime should not retain legacy fixed-window event output")
	}
	if !strings.Contains(straceSource, "EVENT_V2_HEADER_LEN + EVENT_V2_LIFECYCLE_BODY_LEN + payload_capacity") ||
		!strings.Contains(straceSource, "bpf_dynptr_data(&ptr, payload_offset, LIFECYCLE_SNAPSHOT_MAX)") {
		t.Fatal("lifecycle event v2 direct helper should reserve room for direct snapshot payload")
	}
	if !strings.Contains(directHeader, "u32 out_size = payload_offset + payload_capacity") {
		t.Fatal("direct event v2 output size should reserve header plus syscall body plus TLV payload capacity")
	}
	wantFlag := "#define EVENT_FLAG_PAYLOAD_TLV " + strconv.Itoa(int(bpfEventFlagPayloadTLV))
	if !strings.Contains(tlvHeader, wantFlag) {
		t.Fatalf("payload TLV header missing %q", wantFlag)
	}
	wantTruncatedFlag := "#define EVENT_FLAG_TRUNCATED " + strconv.Itoa(int(bpfEventFlagTruncated))
	if !strings.Contains(tlvHeader, wantTruncatedFlag) {
		t.Fatalf("payload TLV header missing %q", wantTruncatedFlag)
	}
	if !strings.Contains(tlvHeader, "PAYLOAD_TLV_KIND_STRING") ||
		!strings.Contains(tlvHeader, "PAYLOAD_TLV_KIND_BYTES") ||
		!strings.Contains(tlvHeader, "PAYLOAD_TLV_KIND_STRUCT") {
		t.Fatal("payload TLV header missing string/bytes/struct section kinds")
	}
	if !strings.Contains(tlvHeader, "PAYLOAD_TLV_KIND_EXEC_ARGS") {
		t.Fatal("payload TLV header missing exec args section kind")
	}
	if !strings.Contains(tlvHeader, "PAYLOAD_TLV_FLAG_DIRECTION_OUT") {
		t.Fatal("payload TLV header missing out direction flag")
	}
}

func repoRootForTest(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
