package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

type SyscallMeta struct {
	Name     string
	Args     []string
	ArgTypes []string
}

func formatStringSlice(s []string) string {
	res := []string{}
	for _, x := range s {
		res = append(res, fmt.Sprintf("%q", x))
	}
	return strings.Join(res, ", ")
}

func main() {
	scTable := make(map[int]SyscallMeta)
	scTable[0] = SyscallMeta{Name: "read", Args: []string{"fd", "buf", "count"}, ArgTypes: []string{"int", "char *", "size_t"}}
	scTable[1] = SyscallMeta{Name: "write", Args: []string{"fd", "buf", "count"}, ArgTypes: []string{"int", "const char *", "size_t"}}
	scTable[2] = SyscallMeta{Name: "open", Args: []string{"filename", "flags", "mode"}, ArgTypes: []string{"const char *", "int", "umode_t"}}
	scTable[3] = SyscallMeta{Name: "close", Args: []string{"fd"}, ArgTypes: []string{"int"}}
	scTable[4] = SyscallMeta{Name: "stat", Args: []string{"filename", "statbuf"}, ArgTypes: []string{"const char *", "struct stat *"}}
	scTable[5] = SyscallMeta{Name: "fstat", Args: []string{"fd", "statbuf"}, ArgTypes: []string{"int", "struct stat *"}}
	scTable[6] = SyscallMeta{Name: "lstat", Args: []string{"filename", "statbuf"}, ArgTypes: []string{"const char *", "struct stat *"}}
	scTable[7] = SyscallMeta{Name: "poll", Args: []string{"ufds", "nfds", "timeout"}, ArgTypes: []string{"struct pollfd *", "unsigned int", "int"}}
	scTable[9] = SyscallMeta{Name: "mmap", Args: []string{"addr", "len", "prot", "flags", "fd", "off"}, ArgTypes: []string{"unsigned long", "unsigned long", "unsigned long", "unsigned long", "unsigned long", "unsigned long"}}
	scTable[10] = SyscallMeta{Name: "mprotect", Args: []string{"start", "len", "prot"}, ArgTypes: []string{"unsigned long", "size_t", "unsigned long"}}
	scTable[11] = SyscallMeta{Name: "munmap", Args: []string{"addr", "len"}, ArgTypes: []string{"unsigned long", "size_t"}}
	scTable[12] = SyscallMeta{Name: "brk", Args: []string{"brk"}, ArgTypes: []string{"unsigned long"}}
	scTable[16] = SyscallMeta{Name: "ioctl", Args: []string{"fd", "cmd", "arg"}, ArgTypes: []string{"int", "unsigned long", "unsigned long"}}
	scTable[21] = SyscallMeta{Name: "access", Args: []string{"filename", "mode"}, ArgTypes: []string{"const char *", "int"}}
	scTable[23] = SyscallMeta{Name: "select", Args: []string{"n", "inp", "outp", "exp", "tvp"}, ArgTypes: []string{"int", "fd_set *", "fd_set *", "fd_set *", "struct timeval *"}}
	scTable[39] = SyscallMeta{Name: "getpid", Args: []string{}, ArgTypes: []string{}}
	scTable[42] = SyscallMeta{Name: "connect", Args: []string{"fd", "uservaddr", "addrlen"}, ArgTypes: []string{"int", "struct sockaddr *", "int"}}
	scTable[43] = SyscallMeta{Name: "accept", Args: []string{"fd", "upeer_sockaddr", "upeer_addrlen"}, ArgTypes: []string{"int", "struct sockaddr *", "int *"}}
	scTable[44] = SyscallMeta{Name: "sendto", Args: []string{"fd", "buff", "len", "flags", "addr", "addr_len"}, ArgTypes: []string{"int", "void *", "size_t", "unsigned int", "struct sockaddr *", "int"}}
	scTable[45] = SyscallMeta{Name: "recvfrom", Args: []string{"fd", "ubuf", "size", "flags", "addr", "addr_len"}, ArgTypes: []string{"int", "void *", "size_t", "unsigned int", "struct sockaddr *", "int *"}}
	scTable[49] = SyscallMeta{Name: "bind", Args: []string{"fd", "umyaddr", "addrlen"}, ArgTypes: []string{"int", "struct sockaddr *", "int"}}
	scTable[51] = SyscallMeta{Name: "getsockname", Args: []string{"fd", "usockaddr", "usockaddr_len"}, ArgTypes: []string{"int", "struct sockaddr *", "int *"}}
	scTable[52] = SyscallMeta{Name: "getpeername", Args: []string{"fd", "usockaddr", "usockaddr_len"}, ArgTypes: []string{"int", "struct sockaddr *", "int *"}}
	scTable[79] = SyscallMeta{Name: "rmdir", Args: []string{"pathname"}, ArgTypes: []string{"const char *"}}
	scTable[80] = SyscallMeta{Name: "chdir", Args: []string{"filename"}, ArgTypes: []string{"const char *"}}
	scTable[81] = SyscallMeta{Name: "fchdir", Args: []string{"fd"}, ArgTypes: []string{"int"}}
	scTable[82] = SyscallMeta{Name: "rename", Args: []string{"oldname", "newname"}, ArgTypes: []string{"const char *", "const char *"}}
	scTable[83] = SyscallMeta{Name: "mkdir", Args: []string{"pathname", "mode"}, ArgTypes: []string{"const char *", "umode_t"}}
	scTable[87] = SyscallMeta{Name: "unlink", Args: []string{"pathname"}, ArgTypes: []string{"const char *"}}
	scTable[89] = SyscallMeta{Name: "readlink", Args: []string{"path", "buf", "bufsiz"}, ArgTypes: []string{"const char *", "char *", "int"}}
	scTable[90] = SyscallMeta{Name: "chmod", Args: []string{"filename", "mode"}, ArgTypes: []string{"const char *", "umode_t"}}
	scTable[92] = SyscallMeta{Name: "chown", Args: []string{"filename", "user", "group"}, ArgTypes: []string{"const char *", "uid_t", "gid_t"}}
	scTable[93] = SyscallMeta{Name: "fchown", Args: []string{"fd", "user", "group"}, ArgTypes: []string{"int", "uid_t", "gid_t"}}
	scTable[94] = SyscallMeta{Name: "lchown", Args: []string{"filename", "user", "group"}, ArgTypes: []string{"const char *", "uid_t", "gid_t"}}
	scTable[158] = SyscallMeta{Name: "arch_prctl", Args: []string{"option", "arg2"}, ArgTypes: []string{"int", "unsigned long"}}
	scTable[159] = SyscallMeta{Name: "adjtimex", Args: []string{"txc_p"}, ArgTypes: []string{"struct timex *"}}
	scTable[161] = SyscallMeta{Name: "chroot", Args: []string{"filename"}, ArgTypes: []string{"const char *"}}
	scTable[232] = SyscallMeta{Name: "epoll_wait", Args: []string{"epfd", "events", "maxevents", "timeout"}, ArgTypes: []string{"int", "struct epoll_event *", "int", "int"}}
	scTable[233] = SyscallMeta{Name: "epoll_ctl", Args: []string{"epfd", "op", "fd", "event"}, ArgTypes: []string{"int", "int", "int", "struct epoll_event *"}}
	scTable[257] = SyscallMeta{Name: "openat", Args: []string{"dfd", "filename", "flags", "mode"}, ArgTypes: []string{"int", "const char *", "int", "umode_t"}}
	scTable[258] = SyscallMeta{Name: "mkdirat", Args: []string{"dfd", "pathname", "mode"}, ArgTypes: []string{"int", "const char *", "umode_t"}}
	scTable[260] = SyscallMeta{Name: "fchownat", Args: []string{"dfd", "filename", "user", "group", "flag"}, ArgTypes: []string{"int", "const char *", "uid_t", "gid_t", "int"}}
	scTable[262] = SyscallMeta{Name: "newfstatat", Args: []string{"dfd", "filename", "statbuf", "flag"}, ArgTypes: []string{"int", "const char *", "struct stat *", "int"}}
	scTable[263] = SyscallMeta{Name: "unlinkat", Args: []string{"dfd", "pathname", "flag"}, ArgTypes: []string{"int", "const char *", "int"}}
	scTable[264] = SyscallMeta{Name: "renameat", Args: []string{"olddfd", "oldname", "newdfd", "newname"}, ArgTypes: []string{"int", "const char *", "int", "const char *"}}
	scTable[266] = SyscallMeta{Name: "readlinkat", Args: []string{"dfd", "pathname", "buf", "bufsiz"}, ArgTypes: []string{"int", "const char *", "char *", "int"}}
	scTable[267] = SyscallMeta{Name: "chmodat", Args: []string{"dfd", "filename", "mode"}, ArgTypes: []string{"int", "const char *", "umode_t"}}
	scTable[269] = SyscallMeta{Name: "faccessat", Args: []string{"dfd", "filename", "mode"}, ArgTypes: []string{"int", "const char *", "int"}}
	scTable[270] = SyscallMeta{Name: "pselect6", Args: []string{"n", "inp", "outp", "exp", "tsp", "sig"}, ArgTypes: []string{"int", "fd_set *", "fd_set *", "fd_set *", "struct timespec *", "void *"}}
	scTable[271] = SyscallMeta{Name: "ppoll", Args: []string{"ufds", "nfds", "tsp", "sigmask", "sigsetsize"}, ArgTypes: []string{"struct pollfd *", "unsigned int", "struct timespec *", "const sigset_t *", "size_t"}}
	scTable[281] = SyscallMeta{Name: "epoll_pwait", Args: []string{"epfd", "events", "maxevents", "timeout", "sigmask", "sigsetsize"}, ArgTypes: []string{"int", "struct epoll_event *", "int", "int", "const sigset_t *", "size_t"}}
	scTable[288] = SyscallMeta{Name: "accept4", Args: []string{"fd", "upeer_sockaddr", "upeer_addrlen", "flags"}, ArgTypes: []string{"int", "struct sockaddr *", "int *", "int"}}
	scTable[291] = SyscallMeta{Name: "epoll_create1", Args: []string{"flags"}, ArgTypes: []string{"int"}}
	scTable[316] = SyscallMeta{Name: "renameat2", Args: []string{"olddfd", "oldname", "newdfd", "newname", "flags"}, ArgTypes: []string{"int", "const char *", "int", "const char *", "unsigned int"}}
	scTable[439] = SyscallMeta{Name: "faccessat2", Args: []string{"dfd", "filename", "mode", "flags"}, ArgTypes: []string{"int", "const char *", "int", "int"}}
	scTable[441] = SyscallMeta{Name: "epoll_pwait2", Args: []string{"epfd", "events", "maxevents", "timeout", "sigmask", "sigsetsize"}, ArgTypes: []string{"int", "struct epoll_event *", "int", "struct timespec *", "const sigset_t *", "size_t"}}

	f, _ := os.Create("../../pkg/meta/syscall_table.go")
	fmt.Fprintln(f, "package meta")
	fmt.Fprintln(f, "type Syscall struct { Name string; Args []string; ArgTypes []string }")
	fmt.Fprintln(f, "var SyscallTable = map[uint32]Syscall{")
	ids := make([]int, 0, len(scTable))
	for id := range scTable {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		m := scTable[id]
		fmt.Fprintf(f, "\t%d: {Name: %q, Args: []string{%s}, ArgTypes: []string{%s}},\n", id, m.Name, formatStringSlice(m.Args), formatStringSlice(m.ArgTypes))
	}
	fmt.Fprintln(f, "}")
	f.Close()

	c, _ := os.Create("../../bpf/syscall_capture.h")
	fmt.Fprintln(c, "#define CAPTURE_ARGS_ENTER(id, e) switch(id) { \\")
	for _, id := range ids {
		m := scTable[id]
		n := m.Name
		pIdx := []int{}
		for i, t := range m.ArgTypes {
			if strings.Contains(t, "*") {
				pIdx = append(pIdx, i)
			}
		}
		if len(pIdx) > 0 || n == "ioctl" {
			fmt.Fprintf(c, "\t\tcase %d: /* %s */ \\\n", id, n)
			if n == "rename" {
				fmt.Fprintf(c, "\t\t\te->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \\\n")
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user_str((e)->str_arg + 1024, 512, (void *)(e)->args[1]); \\\n")
			} else if n == "renameat" || n == "renameat2" {
				fmt.Fprintf(c, "\t\t\te->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \\\n")
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user_str((e)->str_arg + 1024, 512, (void *)(e)->args[3]); \\\n")
			} else if n == "stat" || n == "lstat" || n == "open" || n == "mkdir" || n == "chmod" || n == "access" || n == "rmdir" || n == "chdir" || n == "unlink" || n == "chown" || n == "lchown" || n == "chroot" || n == "readlink" {
				fmt.Fprintf(c, "\t\t\t(e)->ptr = (e)->args[0]; \\\n")
				fmt.Fprintf(c, "\t\t\te->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \\\n")
			} else if n == "newfstatat" || n == "openat" || n == "mkdirat" || n == "chmodat" || n == "faccessat" || n == "faccessat2" || n == "unlinkat" || n == "fchownat" || n == "readlinkat" {
				fmt.Fprintf(c, "\t\t\t(e)->ptr = (e)->args[1]; \\\n")
				fmt.Fprintf(c, "\t\t\te->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \\\n")
			} else if n == "connect" || n == "bind" {
				fmt.Fprintf(c, "\t\t\t(e)->ptr = (e)->args[1]; \\\n")
				fmt.Fprintf(c, "\t\t\te->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \\\n")
			} else if n == "accept" || n == "accept4" {
				fmt.Fprintf(c, "\t\t\t(e)->ptr = (e)->args[1]; \\\n")
				fmt.Fprintf(c, "\t\t\te->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 768, 4, (void *)(e)->args[2]); \\\n")
			} else if n == "adjtimex" {
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[0]); \\\n")
			} else if n == "write" || n == "sendto" {
				fmt.Fprintf(c, "\t\t\t(e)->ptr = (e)->args[1]; \\\n")
				fmt.Fprintf(c, "\t\t\te->probe_ret_enter = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \\\n")
			} else if n == "read" {
				fmt.Fprintf(c, "\t\t\t(e)->ptr = (e)->args[1]; \\\n")
			} else if n == "poll" || n == "ppoll" {
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[0]); \\\n")
			} else if n == "select" || n == "pselect6" {
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg, 128, (void *)(e)->args[1]); \\\n")
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg + 128, 128, (void *)(e)->args[2]); \\\n")
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg + 256, 128, (void *)(e)->args[3]); \\\n")
			} else if n == "epoll_ctl" {
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg, 12, (void *)(e)->args[3]); \\\n")
			} else if n == "ioctl" {
				fmt.Fprintf(c, "\t\t\te->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 512, 128, (void *)(e)->args[2]); \\\n")
			} else {
				fmt.Fprintf(c, "\t\t\t(e)->ptr = (e)->args[%d]; \\\n", pIdx[0])
				fmt.Fprintf(c, "\t\t\te->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[%d]); \\\n", pIdx[0])
			}
			fmt.Fprintln(c, "\t\t\tbreak; \\")
		}
	}
	fmt.Fprintln(c, "\t}")

	fmt.Fprintln(c, "#define CAPTURE_ARGS_EXIT(id, e) switch(id) { \\")
	for _, id := range ids {
		m := scTable[id]
		n := m.Name
		if n == "stat" || n == "lstat" || n == "fstat" || n == "newfstatat" || n == "accept" || n == "accept4" || n == "adjtimex" || n == "getsockname" || n == "getpeername" || n == "read" || n == "recvfrom" || n == "poll" || n == "ppoll" || n == "select" || n == "pselect6" || n == "epoll_wait" || n == "epoll_pwait" || n == "ioctl" {
			fmt.Fprintf(c, "\t\tcase %d: /* %s */ \\\n", id, n)
			if n == "stat" || n == "lstat" || n == "fstat" {
				fmt.Fprintf(c, "\t\t\te->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \\\n")
			} else if n == "newfstatat" {
				fmt.Fprintf(c, "\t\t\te->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[2]); \\\n")
			} else if n == "accept" || n == "accept4" || n == "getsockname" || n == "getpeername" {
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \\\n")
				fmt.Fprintf(c, "\t\t\te->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 772, 4, (void *)(e)->args[2]); \\\n")
			} else if n == "adjtimex" {
				fmt.Fprintf(c, "\t\t\te->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[0]); \\\n")
			} else if n == "read" {
				fmt.Fprintf(c, "\t\t\te->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \\\n")
			} else if n == "recvfrom" {
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \\\n")
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[4]); \\\n")
				fmt.Fprintf(c, "\t\t\te->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 772, 4, (void *)(e)->args[5]); \\\n")
			} else if n == "poll" || n == "ppoll" {
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[0]); \\\n")
			} else if n == "select" || n == "pselect6" {
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg, 128, (void *)(e)->args[1]); \\\n")
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg + 128, 128, (void *)(e)->args[2]); \\\n")
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg + 256, 128, (void *)(e)->args[3]); \\\n")
			} else if n == "epoll_wait" || n == "epoll_pwait" {
				fmt.Fprintf(c, "\t\t\tbpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \\\n")
			} else if n == "ioctl" {
				fmt.Fprintf(c, "\t\t\te->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 512, 128, (void *)(e)->args[2]); \\\n")
			}
			fmt.Fprintln(c, "\t\t\tbreak; \\")
		}
	}
	fmt.Fprintln(c, "\t}")
	c.Close()
}
