package main

// BTF uses different function names for some syscalls.
// This maps BTF name → syscallent.h name.
var btfNameToSyscallent = map[string]string{
	"newstat":    "stat",
	"newlstat":   "lstat",
	"newfstat":   "fstat",
	"newuname":   "uname",
	"mmap_pgoff": "mmap",
}

// manualOverrides provides hand-curated syscall metadata for syscalls
// where BTF data is missing or inaccurate. These take highest priority.
var manualOverrides = map[string]SyscallMeta{
	// Core I/O — BTF ksys_ uses unsigned int for fd, we want int
	"read":  {Name: "read", Args: []string{"fd", "buf", "count"}, ArgTypes: []string{"int", "char *", "size_t"}},
	"write": {Name: "write", Args: []string{"fd", "buf", "count"}, ArgTypes: []string{"int", "const char *", "size_t"}},
	"open":  {Name: "open", Args: []string{"filename", "flags", "mode"}, ArgTypes: []string{"const char *", "int", "umode_t"}},
	"close": {Name: "close", Args: []string{"fd"}, ArgTypes: []string{"int"}},

	// stat family — BTF has __old_kernel_stat, we need struct stat
	"stat":  {Name: "stat", Args: []string{"filename", "statbuf"}, ArgTypes: []string{"const char *", "struct stat *"}},
	"fstat": {Name: "fstat", Args: []string{"fd", "statbuf"}, ArgTypes: []string{"int", "struct stat *"}},
	"lstat": {Name: "lstat", Args: []string{"filename", "statbuf"}, ArgTypes: []string{"const char *", "struct stat *"}},

	// mmap — BTF ksys_mmap_pgoff uses unsigned long for everything
	"mmap": {Name: "mmap", Args: []string{"addr", "len", "prot", "flags", "fd", "off"}, ArgTypes: []string{"unsigned long", "unsigned long", "unsigned long", "unsigned long", "unsigned long", "unsigned long"}},

	// Network — not in __do_sys_ or ksys_
	"connect":     {Name: "connect", Args: []string{"fd", "uservaddr", "addrlen"}, ArgTypes: []string{"int", "struct sockaddr *", "int"}},
	"accept":      {Name: "accept", Args: []string{"fd", "upeer_sockaddr", "upeer_addrlen"}, ArgTypes: []string{"int", "struct sockaddr *", "int *"}},
	"accept4":     {Name: "accept4", Args: []string{"fd", "upeer_sockaddr", "upeer_addrlen", "flags"}, ArgTypes: []string{"int", "struct sockaddr *", "int *", "int"}},
	"bind":        {Name: "bind", Args: []string{"fd", "umyaddr", "addrlen"}, ArgTypes: []string{"int", "struct sockaddr *", "int"}},
	"listen":      {Name: "listen", Args: []string{"fd", "backlog"}, ArgTypes: []string{"int", "int"}},
	"getsockname": {Name: "getsockname", Args: []string{"fd", "usockaddr", "usockaddr_len"}, ArgTypes: []string{"int", "struct sockaddr *", "int *"}},
	"getpeername": {Name: "getpeername", Args: []string{"fd", "usockaddr", "usockaddr_len"}, ArgTypes: []string{"int", "struct sockaddr *", "int *"}},
	"sendto":      {Name: "sendto", Args: []string{"fd", "buff", "len", "flags", "addr", "addr_len"}, ArgTypes: []string{"int", "void *", "size_t", "unsigned int", "struct sockaddr *", "int"}},
	"recvfrom":    {Name: "recvfrom", Args: []string{"fd", "ubuf", "size", "flags", "addr", "addr_len"}, ArgTypes: []string{"int", "void *", "size_t", "unsigned int", "struct sockaddr *", "int *"}},
	"sendmsg":     {Name: "sendmsg", Args: []string{"fd", "msg", "flags"}, ArgTypes: []string{"int", "struct msghdr *", "unsigned int"}},
	"recvmsg":     {Name: "recvmsg", Args: []string{"fd", "msg", "flags"}, ArgTypes: []string{"int", "struct msghdr *", "unsigned int"}},
	"socket":      {Name: "socket", Args: []string{"family", "type", "protocol"}, ArgTypes: []string{"int", "int", "int"}},
	"socketpair":  {Name: "socketpair", Args: []string{"family", "type", "protocol", "usockvec"}, ArgTypes: []string{"int", "int", "int", "int *"}},
	"shutdown":    {Name: "shutdown", Args: []string{"fd", "how"}, ArgTypes: []string{"int", "int"}},
	"setsockopt":  {Name: "setsockopt", Args: []string{"fd", "level", "optname", "optval", "optlen"}, ArgTypes: []string{"int", "int", "int", "char *", "int"}},
	"getsockopt":  {Name: "getsockopt", Args: []string{"fd", "level", "optname", "optval", "optlen"}, ArgTypes: []string{"int", "int", "int", "char *", "int *"}},

	// Process
	"execve":   {Name: "execve", Args: []string{"filename", "argv", "envp"}, ArgTypes: []string{"const char *", "const char *const *", "const char *const *"}},
	"execveat": {Name: "execveat", Args: []string{"dfd", "filename", "argv", "envp", "flags"}, ArgTypes: []string{"int", "const char *", "const char *const *", "const char *const *", "int"}},
	"exit":     {Name: "exit", Args: []string{"error_code"}, ArgTypes: []string{"int"}},

	// Signals — not in __do_sys_
	"rt_sigaction":   {Name: "rt_sigaction", Args: []string{"sig", "act", "oact", "sigsetsize"}, ArgTypes: []string{"int", "const struct sigaction *", "struct sigaction *", "size_t"}},
	"rt_sigprocmask": {Name: "rt_sigprocmask", Args: []string{"how", "nset", "oset", "sigsetsize"}, ArgTypes: []string{"int", "sigset_t *", "sigset_t *", "size_t"}},
	"kill":           {Name: "kill", Args: []string{"pid", "sig"}, ArgTypes: []string{"pid_t", "int"}},
	"tgkill":         {Name: "tgkill", Args: []string{"tgid", "pid", "sig"}, ArgTypes: []string{"pid_t", "pid_t", "int"}},

	// File ops not in BTF
	"dup":     {Name: "dup", Args: []string{"fildes"}, ArgTypes: []string{"unsigned int"}},
	"dup2":    {Name: "dup2", Args: []string{"oldfd", "newfd"}, ArgTypes: []string{"unsigned int", "unsigned int"}},
	"pipe":    {Name: "pipe", Args: []string{"fildes"}, ArgTypes: []string{"int *"}},
	"pipe2":   {Name: "pipe2", Args: []string{"fildes", "flags"}, ArgTypes: []string{"int *", "int"}},
	"fcntl":   {Name: "fcntl", Args: []string{"fd", "cmd", "arg"}, ArgTypes: []string{"unsigned int", "unsigned int", "unsigned long"}},
	"ioctl":   {Name: "ioctl", Args: []string{"fd", "cmd", "arg"}, ArgTypes: []string{"int", "unsigned long", "unsigned long"}},
	"access":  {Name: "access", Args: []string{"filename", "mode"}, ArgTypes: []string{"const char *", "int"}},
	"creat":   {Name: "creat", Args: []string{"pathname", "mode"}, ArgTypes: []string{"const char *", "umode_t"}},
	"truncate": {Name: "truncate", Args: []string{"path", "length"}, ArgTypes: []string{"const char *", "long"}},

	// Memory management
	"mprotect": {Name: "mprotect", Args: []string{"start", "len", "prot"}, ArgTypes: []string{"unsigned long", "size_t", "unsigned long"}},
	"munmap":   {Name: "munmap", Args: []string{"addr", "len"}, ArgTypes: []string{"unsigned long", "size_t"}},
	"brk":      {Name: "brk", Args: []string{"brk"}, ArgTypes: []string{"unsigned long"}},
	"madvise":  {Name: "madvise", Args: []string{"start", "len", "behavior"}, ArgTypes: []string{"unsigned long", "size_t", "int"}},
	"mremap":   {Name: "mremap", Args: []string{"addr", "old_len", "new_len", "flags", "new_addr"}, ArgTypes: []string{"unsigned long", "unsigned long", "unsigned long", "unsigned long", "unsigned long"}},

	// Time
	"nanosleep":      {Name: "nanosleep", Args: []string{"rqtp", "rmtp"}, ArgTypes: []string{"struct timespec *", "struct timespec *"}},
	"alarm":          {Name: "alarm", Args: []string{"seconds"}, ArgTypes: []string{"unsigned int"}},
	"clock_gettime":  {Name: "clock_gettime", Args: []string{"which_clock", "tp"}, ArgTypes: []string{"clockid_t", "struct timespec *"}},
	"clock_settime":  {Name: "clock_settime", Args: []string{"which_clock", "tp"}, ArgTypes: []string{"const clockid_t", "const struct timespec *"}},
	"clock_getres":   {Name: "clock_getres", Args: []string{"which_clock", "tp"}, ArgTypes: []string{"clockid_t", "struct timespec *"}},
	"clock_nanosleep": {Name: "clock_nanosleep", Args: []string{"which_clock", "flags", "rqtp", "rmtp"}, ArgTypes: []string{"clockid_t", "int", "const struct timespec *", "struct timespec *"}},
	"gettimeofday":   {Name: "gettimeofday", Args: []string{"tv", "tz"}, ArgTypes: []string{"struct timeval *", "struct timezone *"}},

	// FS ops
	"select":  {Name: "select", Args: []string{"n", "inp", "outp", "exp", "tvp"}, ArgTypes: []string{"int", "fd_set *", "fd_set *", "fd_set *", "struct timeval *"}},
	"poll":    {Name: "poll", Args: []string{"ufds", "nfds", "timeout"}, ArgTypes: []string{"struct pollfd *", "unsigned int", "int"}},
	"epoll_create":  {Name: "epoll_create", Args: []string{"size"}, ArgTypes: []string{"int"}},
	"epoll_create1": {Name: "epoll_create1", Args: []string{"flags"}, ArgTypes: []string{"int"}},
	"epoll_ctl":     {Name: "epoll_ctl", Args: []string{"epfd", "op", "fd", "event"}, ArgTypes: []string{"int", "int", "int", "struct epoll_event *"}},
	"epoll_wait":    {Name: "epoll_wait", Args: []string{"epfd", "events", "maxevents", "timeout"}, ArgTypes: []string{"int", "struct epoll_event *", "int", "int"}},
	"epoll_pwait":   {Name: "epoll_pwait", Args: []string{"epfd", "events", "maxevents", "timeout", "sigmask", "sigsetsize"}, ArgTypes: []string{"int", "struct epoll_event *", "int", "int", "const sigset_t *", "size_t"}},
	"epoll_pwait2":  {Name: "epoll_pwait2", Args: []string{"epfd", "events", "maxevents", "timeout", "sigmask", "sigsetsize"}, ArgTypes: []string{"int", "struct epoll_event *", "int", "struct timespec *", "const sigset_t *", "size_t"}},

	// dirs
	"getdents64": {Name: "getdents64", Args: []string{"fd", "dirent", "count"}, ArgTypes: []string{"unsigned int", "struct linux_dirent64 *", "unsigned int"}},
	"getcwd":     {Name: "getcwd", Args: []string{"buf", "size"}, ArgTypes: []string{"char *", "unsigned long"}},
	"chdir":      {Name: "chdir", Args: []string{"filename"}, ArgTypes: []string{"const char *"}},
	"fchdir":     {Name: "fchdir", Args: []string{"fd"}, ArgTypes: []string{"int"}},
	"mkdir":      {Name: "mkdir", Args: []string{"pathname", "mode"}, ArgTypes: []string{"const char *", "umode_t"}},
	"mknod":      {Name: "mknod", Args: []string{"filename", "mode", "dev"}, ArgTypes: []string{"const char *", "umode_t", "dev_t"}},
	"rmdir":      {Name: "rmdir", Args: []string{"pathname"}, ArgTypes: []string{"const char *"}},
	"unlink":     {Name: "unlink", Args: []string{"pathname"}, ArgTypes: []string{"const char *"}},
	"rename":     {Name: "rename", Args: []string{"oldname", "newname"}, ArgTypes: []string{"const char *", "const char *"}},
	"chmod":      {Name: "chmod", Args: []string{"filename", "mode"}, ArgTypes: []string{"const char *", "umode_t"}},
	"chown":      {Name: "chown", Args: []string{"filename", "user", "group"}, ArgTypes: []string{"const char *", "uid_t", "gid_t"}},
	"lchown":     {Name: "lchown", Args: []string{"filename", "user", "group"}, ArgTypes: []string{"const char *", "uid_t", "gid_t"}},
	"chroot":     {Name: "chroot", Args: []string{"filename"}, ArgTypes: []string{"const char *"}},
	"readlink":   {Name: "readlink", Args: []string{"path", "buf", "bufsiz"}, ArgTypes: []string{"const char *", "char *", "int"}},
	"acct":       {Name: "acct", Args: []string{"filename"}, ArgTypes: []string{"const char *"}},
	"mount":      {Name: "mount", Args: []string{"dev_name", "dir_name", "type", "flags", "data"}, ArgTypes: []string{"const char *", "const char *", "const char *", "unsigned long", "void *"}},
	"umount2":    {Name: "umount2", Args: []string{"target", "flags"}, ArgTypes: []string{"const char *", "int"}},
	"swapon":     {Name: "swapon", Args: []string{"specialfile", "swap_flags"}, ArgTypes: []string{"const char *", "int"}},
	"swapoff":    {Name: "swapoff", Args: []string{"specialfile"}, ArgTypes: []string{"const char *"}},
	"quotactl":   {Name: "quotactl", Args: []string{"cmd", "special", "id", "addr"}, ArgTypes: []string{"int", "const char *", "int", "void *"}},

	// *at variants
	"openat":     {Name: "openat", Args: []string{"dfd", "filename", "flags", "mode"}, ArgTypes: []string{"int", "const char *", "int", "umode_t"}},
	"mkdirat":    {Name: "mkdirat", Args: []string{"dfd", "pathname", "mode"}, ArgTypes: []string{"int", "const char *", "umode_t"}},
	"mknodat":    {Name: "mknodat", Args: []string{"dfd", "filename", "mode", "dev"}, ArgTypes: []string{"int", "const char *", "umode_t", "dev_t"}},
	"unlinkat":   {Name: "unlinkat", Args: []string{"dfd", "pathname", "flag"}, ArgTypes: []string{"int", "const char *", "int"}},
	"renameat":   {Name: "renameat", Args: []string{"olddfd", "oldname", "newdfd", "newname"}, ArgTypes: []string{"int", "const char *", "int", "const char *"}},
	"renameat2":  {Name: "renameat2", Args: []string{"olddfd", "oldname", "newdfd", "newname", "flags"}, ArgTypes: []string{"int", "const char *", "int", "const char *", "unsigned int"}},
	"readlinkat": {Name: "readlinkat", Args: []string{"dfd", "pathname", "buf", "bufsiz"}, ArgTypes: []string{"int", "const char *", "char *", "int"}},
	"faccessat":  {Name: "faccessat", Args: []string{"dfd", "filename", "mode"}, ArgTypes: []string{"int", "const char *", "int"}},
	"faccessat2": {Name: "faccessat2", Args: []string{"dfd", "filename", "mode", "flags"}, ArgTypes: []string{"int", "const char *", "int", "int"}},
	"fchownat":   {Name: "fchownat", Args: []string{"dfd", "filename", "user", "group", "flag"}, ArgTypes: []string{"int", "const char *", "uid_t", "gid_t", "int"}},
	"utimensat":  {Name: "utimensat", Args: []string{"dfd", "filename", "utimes", "flags"}, ArgTypes: []string{"int", "const char *", "const struct timespec *", "int"}},
	"fchmodat":   {Name: "fchmodat", Args: []string{"dfd", "filename", "mode"}, ArgTypes: []string{"int", "const char *", "umode_t"}},
	"newfstatat": {Name: "newfstatat", Args: []string{"dfd", "filename", "statbuf", "flag"}, ArgTypes: []string{"int", "const char *", "struct stat *", "int"}},
	"linkat":     {Name: "linkat", Args: []string{"olddfd", "oldname", "newdfd", "newname", "flags"}, ArgTypes: []string{"int", "const char *", "int", "const char *", "int"}},
	"link":       {Name: "link", Args: []string{"oldpath", "newpath"}, ArgTypes: []string{"const char *", "const char *"}},
	"symlink":    {Name: "symlink", Args: []string{"oldname", "newname"}, ArgTypes: []string{"const char *", "const char *"}},
	"symlinkat":  {Name: "symlinkat", Args: []string{"oldname", "newdfd", "newname"}, ArgTypes: []string{"const char *", "int", "const char *"}},

	// AIO
	"io_setup":     {Name: "io_setup", Args: []string{"nr_events", "ctxp"}, ArgTypes: []string{"unsigned int", "aio_context_t *"}},
	"io_destroy":   {Name: "io_destroy", Args: []string{"ctx"}, ArgTypes: []string{"aio_context_t"}},
	"io_submit":    {Name: "io_submit", Args: []string{"ctx_id", "nr", "iocbpp"}, ArgTypes: []string{"aio_context_t", "long", "struct iocb **"}},
	"io_getevents": {Name: "io_getevents", Args: []string{"ctx_id", "min_nr", "nr", "events", "timeout"}, ArgTypes: []string{"aio_context_t", "long", "long", "struct io_event *", "struct timespec *"}},
	"io_cancel":    {Name: "io_cancel", Args: []string{"ctx_id", "iocb", "result"}, ArgTypes: []string{"aio_context_t", "struct iocb *", "struct io_event *"}},

	// Keys
	"add_key":      {Name: "add_key", Args: []string{"type", "description", "payload", "plen", "ringid"}, ArgTypes: []string{"const char *", "const char *", "const void *", "size_t", "key_serial_t"}},
	"request_key":  {Name: "request_key", Args: []string{"type", "description", "callout_info", "destringid"}, ArgTypes: []string{"const char *", "const char *", "const char *", "key_serial_t"}},
	"keyctl":       {Name: "keyctl", Args: []string{"option", "arg2", "arg3", "arg4", "arg5"}, ArgTypes: []string{"int", "unsigned long", "unsigned long", "unsigned long", "unsigned long"}},

	// IPC
	"futex": {Name: "futex", Args: []string{"uaddr", "op", "val", "utime", "uaddr2", "val3"}, ArgTypes: []string{"u32 *", "int", "u32", "const struct timespec *", "u32 *", "u32"}},

	// Misc
	"bpf":           {Name: "bpf", Args: []string{"cmd", "attr", "size"}, ArgTypes: []string{"int", "void *", "unsigned int"}},
	"arch_prctl":    {Name: "arch_prctl", Args: []string{"option", "arg2"}, ArgTypes: []string{"int", "unsigned long"}},

	"adjtimex":    {Name: "adjtimex", Args: []string{"txc_p"}, ArgTypes: []string{"struct timex *"}},
	"pselect6":    {Name: "pselect6", Args: []string{"n", "inp", "outp", "exp", "tsp", "sig"}, ArgTypes: []string{"int", "fd_set *", "fd_set *", "fd_set *", "struct timespec *", "void *"}},
	"ppoll":       {Name: "ppoll", Args: []string{"ufds", "nfds", "tsp", "sigmask", "sigsetsize"}, ArgTypes: []string{"struct pollfd *", "unsigned int", "struct timespec *", "const sigset_t *", "size_t"}},
	"sendfile":    {Name: "sendfile", Args: []string{"out_fd", "in_fd", "offset", "count"}, ArgTypes: []string{"int", "int", "off_t *", "size_t"}},
	"fchown":      {Name: "fchown", Args: []string{"fd", "user", "group"}, ArgTypes: []string{"int", "uid_t", "gid_t"}},
	"fchmod":      {Name: "fchmod", Args: []string{"fd", "mode"}, ArgTypes: []string{"unsigned int", "umode_t"}},
	"uname":       {Name: "uname", Args: []string{"name"}, ArgTypes: []string{"struct utsname *"}},
	"exit_group":  {Name: "exit_group", Args: []string{"error_code"}, ArgTypes: []string{"int"}},
	"getdents":    {Name: "getdents", Args: []string{"fd", "dirent", "count"}, ArgTypes: []string{"unsigned int", "struct linux_dirent *", "unsigned int"}},
	"eventfd2":    {Name: "eventfd2", Args: []string{"count", "flags"}, ArgTypes: []string{"unsigned int", "int"}},
	"inotify_add_watch": {Name: "inotify_add_watch", Args: []string{"fd", "pathname", "mask"}, ArgTypes: []string{"int", "const char *", "u32"}},
	"inotify_rm_watch":  {Name: "inotify_rm_watch", Args: []string{"fd", "wd"}, ArgTypes: []string{"int", "int"}},
	"inotify_init1":     {Name: "inotify_init1", Args: []string{"flags"}, ArgTypes: []string{"int"}},
}
