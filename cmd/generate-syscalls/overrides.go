package main

// BTF uses different function names for some syscalls.
// This maps BTF name → syscallent.h name.
var btfNameToSyscallent = map[string]string{
	"newstat":    "stat",
	"newlstat":   "lstat",
	"newfstat":   "fstat",
	"newuname":   "uname",
	"mmap_pgoff": "mmap",
	"sendfile64": "sendfile",
	"umount":     "umount2",
}

// fallbackOverrides provides metadata only for kernels that do not expose a
// usable BTF or tracepoint signature. Strace-facing semantic overrides live in
// override_semantics.go and are resolved separately.
var fallbackOverrides = map[string]SyscallMeta{
	// Core I/O
	"close":             {Name: "close", Args: []string{"fd"}, ArgTypes: []string{"int"}},
	"readv":             {Name: "readv", Args: []string{"fd", "vec", "vlen"}, ArgTypes: []string{"int", "const struct iovec *", "unsigned long"}},
	"writev":            {Name: "writev", Args: []string{"fd", "vec", "vlen"}, ArgTypes: []string{"int", "const struct iovec *", "unsigned long"}},
	"preadv":            {Name: "preadv", Args: []string{"fd", "vec", "vlen", "pos_l", "pos_h"}, ArgTypes: []string{"int", "const struct iovec *", "unsigned long", "unsigned long", "unsigned long"}},
	"pwritev":           {Name: "pwritev", Args: []string{"fd", "vec", "vlen", "pos_l", "pos_h"}, ArgTypes: []string{"int", "const struct iovec *", "unsigned long", "unsigned long", "unsigned long"}},
	"preadv2":           {Name: "preadv2", Args: []string{"fd", "vec", "vlen", "pos_l", "pos_h", "flags"}, ArgTypes: []string{"int", "const struct iovec *", "unsigned long", "unsigned long", "unsigned long", "int"}},
	"pwritev2":          {Name: "pwritev2", Args: []string{"fd", "vec", "vlen", "pos_l", "pos_h", "flags"}, ArgTypes: []string{"int", "const struct iovec *", "unsigned long", "unsigned long", "unsigned long", "int"}},
	"process_vm_readv":  {Name: "process_vm_readv", Args: []string{"pid", "local_iov", "liovcnt", "remote_iov", "riovcnt", "flags"}, ArgTypes: []string{"pid_t", "const struct iovec *", "unsigned long", "const struct iovec *", "unsigned long", "unsigned long"}},
	"process_vm_writev": {Name: "process_vm_writev", Args: []string{"pid", "local_iov", "liovcnt", "remote_iov", "riovcnt", "flags"}, ArgTypes: []string{"pid_t", "const struct iovec *", "unsigned long", "const struct iovec *", "unsigned long", "unsigned long"}},

	// Signals — retain strace-facing names and types where needed.

	// File operations with strace-facing metadata requirements.
	"ioctl": {Name: "ioctl", Args: []string{"fd", "cmd", "arg"}, ArgTypes: []string{"int", "unsigned long", "unsigned long"}},

	// Memory management
	"madvise": {Name: "madvise", Args: []string{"start", "len", "behavior"}, ArgTypes: []string{"const void *", "size_t", "int"}},
	"mlock":   {Name: "mlock", Args: []string{"addr", "len"}, ArgTypes: []string{"const void *", "size_t"}},
	"munlock": {Name: "munlock", Args: []string{"addr", "len"}, ArgTypes: []string{"const void *", "size_t"}},
	"mlock2":  {Name: "mlock2", Args: []string{"addr", "len", "flags"}, ArgTypes: []string{"const void *", "size_t", "int"}},

	// Time
	"nanosleep":       {Name: "nanosleep", Args: []string{"rqtp", "rmtp"}, ArgTypes: []string{"struct timespec *", "struct timespec *"}},
	"clock_gettime":   {Name: "clock_gettime", Args: []string{"which_clock", "tp"}, ArgTypes: []string{"clockid_t", "struct timespec *"}},
	"clock_settime":   {Name: "clock_settime", Args: []string{"which_clock", "tp"}, ArgTypes: []string{"const clockid_t", "const struct timespec *"}},
	"clock_getres":    {Name: "clock_getres", Args: []string{"which_clock", "tp"}, ArgTypes: []string{"clockid_t", "struct timespec *"}},
	"clock_nanosleep": {Name: "clock_nanosleep", Args: []string{"which_clock", "flags", "rqtp", "rmtp"}, ArgTypes: []string{"clockid_t", "int", "const struct timespec *", "struct timespec *"}},
	"gettimeofday":    {Name: "gettimeofday", Args: []string{"tv", "tz"}, ArgTypes: []string{"struct timeval *", "struct timezone *"}},
	"utime":           {Name: "utime", Args: []string{"filename", "times"}, ArgTypes: []string{"const char *", "struct utimbuf *"}},
	"utimes":          {Name: "utimes", Args: []string{"filename", "times"}, ArgTypes: []string{"const char *", "struct timeval *"}},
	"futimesat":       {Name: "futimesat", Args: []string{"dfd", "filename", "times"}, ArgTypes: []string{"int", "const char *", "struct timeval *"}},

	// FS ops
	"fsopen": {Name: "fsopen", Args: []string{"fs_name", "flags"}, ArgTypes: []string{"const char *", "unsigned int"}},
	"select": {Name: "select", Args: []string{"n", "inp", "outp", "exp", "tvp"}, ArgTypes: []string{"int", "fd_set *", "fd_set *", "fd_set *", "struct timeval *"}},
	"poll":   {Name: "poll", Args: []string{"ufds", "nfds", "timeout"}, ArgTypes: []string{"struct pollfd *", "unsigned int", "int"}},

	// Manual syscall types for extended attributes and process control
	"setxattr":        {Name: "setxattr", Args: []string{"path", "name", "value", "size", "flags"}, ArgTypes: []string{"const char *", "const char *", "const void *", "size_t", "int"}},
	"lsetxattr":       {Name: "lsetxattr", Args: []string{"path", "name", "value", "size", "flags"}, ArgTypes: []string{"const char *", "const char *", "const void *", "size_t", "int"}},
	"getxattr":        {Name: "getxattr", Args: []string{"path", "name", "value", "size"}, ArgTypes: []string{"const char *", "const char *", "void *", "size_t"}},
	"lgetxattr":       {Name: "lgetxattr", Args: []string{"path", "name", "value", "size"}, ArgTypes: []string{"const char *", "const char *", "void *", "size_t"}},
	"listxattr":       {Name: "listxattr", Args: []string{"path", "list", "size"}, ArgTypes: []string{"const char *", "char *", "size_t"}},
	"llistxattr":      {Name: "llistxattr", Args: []string{"path", "list", "size"}, ArgTypes: []string{"const char *", "char *", "size_t"}},
	"removexattr":     {Name: "removexattr", Args: []string{"path", "name"}, ArgTypes: []string{"const char *", "const char *"}},
	"lremovexattr":    {Name: "lremovexattr", Args: []string{"path", "name"}, ArgTypes: []string{"const char *", "const char *"}},
	"get_robust_list": {Name: "get_robust_list", Args: []string{"pid", "head_ptr", "len_ptr"}, ArgTypes: []string{"int", "struct robust_list_head **", "size_t *"}},
	"getitimer":       {Name: "getitimer", Args: []string{"which", "value"}, ArgTypes: []string{"int", "struct itimerval *"}},
	"setitimer":       {Name: "setitimer", Args: []string{"which", "value", "ovalue"}, ArgTypes: []string{"int", "const struct itimerval *", "struct itimerval *"}},
	"settimeofday":    {Name: "settimeofday", Args: []string{"tv", "tz"}, ArgTypes: []string{"const struct timeval *", "const struct timezone *"}},

	"epoll_pwait2": {Name: "epoll_pwait2", Args: []string{"epfd", "events", "maxevents", "timeout", "sigmask", "sigsetsize"}, ArgTypes: []string{"int", "struct epoll_event *", "int", "struct timespec *", "const sigset_t *", "size_t"}},

	// dirs
	"fchdir":   {Name: "fchdir", Args: []string{"fd"}, ArgTypes: []string{"int"}},
	"mknod":    {Name: "mknod", Args: []string{"filename", "mode", "dev"}, ArgTypes: []string{"const char *", "umode_t", "dev_t"}},
	"acct":     {Name: "acct", Args: []string{"filename"}, ArgTypes: []string{"const char *"}},
	"mount":    {Name: "mount", Args: []string{"dev_name", "dir_name", "type", "flags", "data"}, ArgTypes: []string{"const char *", "const char *", "const char *", "unsigned long", "void *"}},
	"umount2":  {Name: "umount2", Args: []string{"target", "flags"}, ArgTypes: []string{"const char *", "int"}},
	"quotactl": {Name: "quotactl", Args: []string{"cmd", "special", "id", "addr"}, ArgTypes: []string{"int", "const char *", "int", "void *"}},

	// *at variants
	"openat2":   {Name: "openat2", Args: []string{"dfd", "filename", "how", "size"}, ArgTypes: []string{"int", "const char *", "struct open_how *", "size_t"}},
	"mknodat":   {Name: "mknodat", Args: []string{"dfd", "filename", "mode", "dev"}, ArgTypes: []string{"int", "const char *", "umode_t", "dev_t"}},
	"utimensat": {Name: "utimensat", Args: []string{"dfd", "filename", "utimes", "flags"}, ArgTypes: []string{"int", "const char *", "const struct timespec *", "int"}},
	"link":      {Name: "link", Args: []string{"oldpath", "newpath"}, ArgTypes: []string{"const char *", "const char *"}},

	// AIO
	"io_setup":     {Name: "io_setup", Args: []string{"nr_events", "ctxp"}, ArgTypes: []string{"unsigned int", "aio_context_t *"}},
	"io_submit":    {Name: "io_submit", Args: []string{"ctx_id", "nr", "iocbpp"}, ArgTypes: []string{"aio_context_t", "long", "struct iocb **"}},
	"io_getevents": {Name: "io_getevents", Args: []string{"ctx_id", "min_nr", "nr", "events", "timeout"}, ArgTypes: []string{"aio_context_t", "long", "long", "struct io_event *", "struct timespec *"}},

	// IPC
	"futex": {Name: "futex", Args: []string{"uaddr", "op", "val", "utime", "uaddr2", "val3"}, ArgTypes: []string{"u32 *", "int", "u32", "const struct timespec *", "u32 *", "u32"}},

	// Misc
	"pselect6":         {Name: "pselect6", Args: []string{"n", "inp", "outp", "exp", "tsp", "sig"}, ArgTypes: []string{"int", "fd_set *", "fd_set *", "fd_set *", "struct timespec *", "void *"}},
	"ppoll":            {Name: "ppoll", Args: []string{"ufds", "nfds", "tsp", "sigmask", "sigsetsize"}, ArgTypes: []string{"struct pollfd *", "unsigned int", "struct timespec *", "const sigset_t *", "size_t"}},
	"sendfile":         {Name: "sendfile", Args: []string{"out_fd", "in_fd", "offset", "count"}, ArgTypes: []string{"int", "int", "off_t *", "size_t"}},
	"close_range":      {Name: "close_range", Args: []string{"first", "last", "flags"}, ArgTypes: []string{"unsigned int", "unsigned int", "unsigned int"}},
	"inotify_rm_watch": {Name: "inotify_rm_watch", Args: []string{"fd", "wd"}, ArgTypes: []string{"int", "int"}},
	"userfaultfd":      {Name: "userfaultfd", Args: []string{"flags"}, ArgTypes: []string{"unsigned int"}},
	"pidfd_getfd":      {Name: "pidfd_getfd", Args: []string{"pidfd", "targetfd", "flags"}, ArgTypes: []string{"int", "int", "unsigned int"}},
	"pkey_mprotect":    {Name: "pkey_mprotect", Args: []string{"addr", "len", "prot", "pkey"}, ArgTypes: []string{"void *", "size_t", "long unsigned int", "int"}},
	"mseal":            {Name: "mseal", Args: []string{"addr", "len", "flags"}, ArgTypes: []string{"void *", "size_t", "long unsigned int"}},
	"umask":            {Name: "umask", Args: []string{"mask"}, ArgTypes: []string{"umode_t"}},
	"setrlimit":        {Name: "setrlimit", Args: []string{"resource", "rlim"}, ArgTypes: []string{"unsigned int", "const struct rlimit *"}},
	"ftruncate":        {Name: "ftruncate", Args: []string{"fd", "length"}, ArgTypes: []string{"int", "long"}},
}

func allSyscallOverrides() map[string]SyscallMeta {
	result := make(map[string]SyscallMeta, len(fallbackOverrides)+len(semanticOverrides))
	for name, meta := range fallbackOverrides {
		result[name] = meta
	}
	for name, meta := range semanticOverrides {
		result[name] = meta
	}
	return result
}
