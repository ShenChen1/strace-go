package handler

import (
	"fmt"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestFormatFdWithPathPrefersTrackedFDMap(t *testing.T) {
	ctx := &Context{
		Pid:       202,
		TargetPid: 101,
		Opts: &cli.Options{
			ShowPaths:     true,
			ShowPathsMode: 1,
		},
		FdMap: map[string]string{
			"101:4": "/dev/full",
		},
	}

	if got := FormatFdWithPath(ctx, 4); got != "4</dev/full>" {
		t.Fatalf("FormatFdWithPath = %q, want %q", got, "4</dev/full>")
	}
}

func TestFormatFdWithPathTreatsMissingTrackedFDAsClosed(t *testing.T) {
	ctx := &Context{
		Pid:       202,
		TargetPid: 0,
		Opts: &cli.Options{
			ShowPaths:     true,
			ShowPathsMode: 1,
		},
		FdMap: map[string]string{},
	}

	if got := FormatFdWithPath(ctx, 4); got != "4" {
		t.Fatalf("FormatFdWithPath = %q, want %q", got, "4")
	}
}

func TestFormatFdWithPathDoesNotReadLiveMetadataOnTrackedMapMiss(t *testing.T) {
	pid := 101
	fd := int32(4)
	ctx := &Context{
		Pid:       pid,
		TargetPid: pid,
		Opts: &cli.Options{
			ShowPaths:     true,
			ShowPathsMode: 1,
		},
		FdMap: map[string]string{},
	}

	if got := FormatFdWithPath(ctx, fd); got != fmt.Sprintf("%d", fd) {
		t.Fatalf("FormatFdWithPath = %q, want unknown fd", got)
	}
	if len(ctx.FdMap) != 0 {
		t.Fatalf("fd map changed after unknown fd lookup: %#v", ctx.FdMap)
	}
}

func TestFormatFdWithPathDetailsTrackedTarget(t *testing.T) {
	ctx := &Context{
		Pid:       202,
		TargetPid: 101,
		Opts: &cli.Options{
			ShowPaths:     true,
			ShowPathsMode: 2,
		},
		FdMap: map[string]string{
			"101:0": "/dev/null",
		},
	}

	if got := FormatFdWithPath(ctx, 0); got != "0</dev/null>" {
		t.Fatalf("FormatFdWithPath = %q, want %q", got, "0</dev/null>")
	}
}

func TestDefaultHandlerDecodesSyncFileRangeFlags(t *testing.T) {
	ctx := &Context{
		Args: [6]uint64{
			0xffffffffffffffff,
			0xdeadbeefbadc0ded,
			0xfacefeedcafef00d,
			0xffffffff,
		},
		ScMeta: meta.Syscall{
			Name:     "sync_file_range",
			Args:     []string{"fd", "offset", "nbytes", "flags"},
			ArgTypes: []string{"int", "loff_t", "loff_t", "unsigned int"},
		},
		Opts: &cli.Options{},
	}

	got := (&DefaultHandler{}).Handle(ctx).ArgParts
	want := "SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE|SYNC_FILE_RANGE_WAIT_AFTER|0xfffffff8"
	if got[3] != want {
		t.Fatalf("sync_file_range flags = %q, want %q", got[3], want)
	}
}

func TestDefaultHandlerDecodesFallocateMode(t *testing.T) {
	ctx := &Context{
		Args: [6]uint64{
			0xffffffffbeefface,
			0xffffffffdeadca75,
			0xbadc0dedda7a1057,
			0xbadfaceca7b0d1e5,
		},
		ScMeta: meta.Syscall{
			Name:     "fallocate",
			Args:     []string{"fd", "mode", "offset", "len"},
			ArgTypes: []string{"int", "int", "loff_t", "loff_t"},
		},
		Opts: &cli.Options{},
	}

	got := (&DefaultHandler{}).Handle(ctx).ArgParts
	want := "FALLOC_FL_KEEP_SIZE|FALLOC_FL_NO_HIDE_STALE|FALLOC_FL_ZERO_RANGE|FALLOC_FL_INSERT_RANGE|FALLOC_FL_UNSHARE_RANGE|0xdeadca00"
	if got[1] != want {
		t.Fatalf("fallocate mode = %q, want %q", got[1], want)
	}
}

func TestDefaultHandlerDecodesSpecialFlagXlats(t *testing.T) {
	tests := []struct {
		name     string
		val      uint64
		argNames []string
		argTypes []string
		want     string
	}{
		{
			name:     "pipe2",
			val:      0x80000 | 2048 | 16384,
			argNames: []string{"pipefd", "flags"},
			argTypes: []string{"int *", "int"},
			want:     "O_CLOEXEC|O_NONBLOCK|O_DIRECT",
		},
		{
			name:     "eventfd2",
			val:      1 | 0x80000 | 2048,
			argNames: []string{"initval", "flags"},
			argTypes: []string{"unsigned int", "int"},
			want:     "EFD_SEMAPHORE|EFD_CLOEXEC|EFD_NONBLOCK",
		},
		{
			name:     "pipe2",
			val:      0x40000000,
			argNames: []string{"pipefd", "flags"},
			argTypes: []string{"int *", "int"},
			want:     "0x40000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &Context{
				Args: [6]uint64{0, tt.val},
				ScMeta: meta.Syscall{
					Name:     tt.name,
					Args:     tt.argNames,
					ArgTypes: tt.argTypes,
				},
				Opts: &cli.Options{},
			}

			got := (&DefaultHandler{}).Handle(ctx).ArgParts
			if got[1] != tt.want {
				t.Fatalf("%s flags = %q, want %q (all args %#v)", tt.name, got[1], tt.want, got)
			}
		})
	}
}

func TestDefaultHandlerDoesNotTreatUnsignedFDAsXlatInRawMode(t *testing.T) {
	ctx := &Context{
		Args: [6]uint64{0xffffffff},
		ScMeta: meta.Syscall{
			Name:     "read",
			Args:     []string{"fd"},
			ArgTypes: []string{"unsigned int"},
		},
		Opts: &cli.Options{XlatFormat: "raw"},
	}

	got := (&DefaultHandler{}).Handle(ctx).ArgParts
	if got[0] != "-1" {
		t.Fatalf("unsigned fd in raw xlat mode = %q, want -1", got[0])
	}
}

func TestDefaultHandlerFormatsCloseRangeBoundsAsUnsigned(t *testing.T) {
	ctx := &Context{
		Args:   [6]uint64{0xdefaced0fffffffe, 0xdefaced0ffffffff, 0xdefaced000000006},
		ScMeta: meta.SyscallTable[436],
		Opts:   &cli.Options{},
	}

	got := (&DefaultHandler{}).Handle(ctx).ArgParts
	want := []string{"4294967294", "4294967295", "CLOSE_RANGE_UNSHARE|CLOSE_RANGE_CLOEXEC"}
	if len(got) != len(want) {
		t.Fatalf("close_range args = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("close_range arg %d = %q, want %q (all args %#v)", i, got[i], want[i], got)
		}
	}
}

func TestDefaultHandlerDecodesBasicFlagXlats(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		argNames []string
		argTypes []string
		want     []string
	}{
		{
			name:     "renameat2",
			args:     [6]uint64{0, 0, 0, 0, 1},
			argNames: []string{"olddfd", "oldname", "newdfd", "newname", "flags"},
			argTypes: []string{"int", "const char *", "int", "const char *", "unsigned int"},
			want:     []string{"0", "NULL", "0", "NULL", "RENAME_NOREPLACE"},
		},
		{
			name:     "inotify_init1",
			args:     [6]uint64{0xfacefeed00080800},
			argNames: []string{"flags"},
			argTypes: []string{"int"},
			want:     []string{"IN_NONBLOCK|IN_CLOEXEC"},
		},
		{
			name:     "userfaultfd",
			args:     [6]uint64{0xdefaced000080801},
			argNames: []string{"flags"},
			argTypes: []string{"unsigned int"},
			want:     []string{"UFFD_USER_MODE_ONLY|O_NONBLOCK|O_CLOEXEC"},
		},
		{
			name:     "unshare",
			args:     [6]uint64{0xbadc0ded0000000f},
			argNames: []string{"unshare_flags"},
			argTypes: []string{"long unsigned int"},
			want:     []string{"0xbadc0ded0000000f /* CLONE_??? */"},
		},
		{
			name:     "close_range",
			args:     [6]uint64{0xdefaced0fffffffe, 0xdefaced0ffffffff, 0xdefaced000000006},
			argNames: []string{"first", "last", "flags"},
			argTypes: []string{"unsigned int", "unsigned int", "unsigned int"},
			want:     []string{"4294967294", "4294967295", "CLOSE_RANGE_UNSHARE|CLOSE_RANGE_CLOEXEC"},
		},
		{
			name:     "pidfd_open",
			args:     [6]uint64{0xdefaced0ffffffff, 0xdefaced000000a80},
			argNames: []string{"pid", "flags"},
			argTypes: []string{"pid_t", "unsigned int"},
			want:     []string{"-1", "PIDFD_NONBLOCK|PIDFD_THREAD|PIDFD_AUTOKILL"},
		},
		{
			name:     "pidfd_getfd",
			args:     [6]uint64{0xdefaced0ffffffff, 0xdefaced0ffffffff, 0xdefaced0badc0ded},
			argNames: []string{"pidfd", "targetfd", "flags"},
			argTypes: []string{"int", "int", "unsigned int"},
			want:     []string{"-1", "-1", "0xbadc0ded"},
		},
		{
			name:     "setns",
			args:     [6]uint64{0xdefaced0deadc0de, 0xdefaced081fdff7f},
			argNames: []string{"fd", "flags"},
			argTypes: []string{"int", "int"},
			want:     []string{"-559038242", "0x81fdff7f /* CLONE_NEW??? */"},
		},
		{
			name:     "process_mrelease",
			args:     [6]uint64{0xbadc0ded00000000, 0xbadc0dedfacefeed},
			argNames: []string{"pidfd", "flags"},
			argTypes: []string{"int", "unsigned int"},
			want:     []string{"0", "0xfacefeed"},
		},
		{
			name:     "pkey_alloc",
			args:     [6]uint64{0xbadc0ded00000000, 0xbadc0ded00000002},
			argNames: []string{"flags", "init_val"},
			argTypes: []string{"long unsigned int", "long unsigned int"},
			want:     []string{"0xbadc0ded00000000", "PKEY_DISABLE_WRITE|0xbadc0ded00000000"},
		},
		{
			name:     "pkey_mprotect",
			args:     [6]uint64{0, 0, 0xdeadfeed00ca7500, 0xbadc0ded00000001},
			argNames: []string{"addr", "len", "prot", "pkey"},
			argTypes: []string{"void *", "size_t", "long unsigned int", "int"},
			want:     []string{"NULL", "0", "0xdeadfeed00ca7500 /* PROT_??? */", "1"},
		},
		{
			name:     "pkey_free",
			args:     [6]uint64{0xbadc0ded00000000},
			argNames: []string{"pkey"},
			argTypes: []string{"int"},
			want:     []string{"0"},
		},
		{
			name:     "fanotify_init",
			args:     [6]uint64{0xffffffffffffffff, 0xdeadbeef80000001},
			argNames: []string{"flags", "event_f_flags"},
			argTypes: []string{"unsigned int", "unsigned int"},
			want:     []string{"0xc /* FAN_CLASS_??? */|FAN_CLOEXEC|FAN_NONBLOCK|FAN_UNLIMITED_QUEUE|FAN_UNLIMITED_MARKS|FAN_ENABLE_AUDIT|FAN_REPORT_PIDFD|FAN_REPORT_TID|FAN_REPORT_FID|FAN_REPORT_DIR_FID|FAN_REPORT_NAME|FAN_REPORT_TARGET_FID|FAN_REPORT_FD_ERROR|FAN_REPORT_MNT|0xffff8000", "O_WRONLY|0x80000000"},
		},
		{
			name:     "fsmount",
			args:     [6]uint64{3, 0xdefaced0ffffffff, 0xdefaced0ffffffff},
			argNames: []string{"fs_fd", "flags", "attr_flags"},
			argTypes: []string{"int", "unsigned int", "unsigned int"},
			want:     []string{"3", "FSMOUNT_CLOEXEC|FSMOUNT_NAMESPACE|0xfffffffc", "MOUNT_ATTR_RDONLY|MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV|MOUNT_ATTR_NOEXEC|MOUNT_ATTR__ATIME|MOUNT_ATTR_NODIRATIME|MOUNT_ATTR_NOSYMFOLLOW|0xffdfff00"},
		},
		{
			name:     "fchmodat2",
			args:     [6]uint64{0xbadc0dedffffff9c, 0, 0xbadc0deddead01a4, 0xbadc0ded00001100},
			argNames: []string{"dfd", "filename", "mode", "flags"},
			argTypes: []string{"int", "const char *", "umode_t", "unsigned int"},
			want:     []string{"AT_FDCWD", "NULL", "0644", "AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH"},
		},
		{
			name:     "map_shadow_stack",
			args:     [6]uint64{0, 0, 0xdefaced0ffffffff},
			argNames: []string{"addr", "size", "flags"},
			argTypes: []string{"void *", "size_t", "unsigned int"},
			want:     []string{"NULL", "0", "SHADOW_STACK_SET_TOKEN|0xfffffffe"},
		},
		{
			name:     "mseal",
			args:     [6]uint64{0xfacefeeddeadbeef, 0xcafef00dbadc0ded, 0xffffffffffffffff},
			argNames: []string{"addr", "len", "flags"},
			argTypes: []string{"void *", "size_t", "long unsigned int"},
			want:     []string{"0xfacefeeddeadbeef", "14627392581506174445", "0xffffffffffffffff"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &Context{
				Args: tt.args,
				ScMeta: meta.Syscall{
					Name:     tt.name,
					Args:     tt.argNames,
					ArgTypes: tt.argTypes,
				},
				Opts: &cli.Options{},
			}
			got := (&DefaultHandler{}).Handle(ctx).ArgParts
			if len(got) != len(tt.want) {
				t.Fatalf("%s args length = %d, want %d: %#v", tt.name, len(got), len(tt.want), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("%s arg %d = %q, want %q (all args %#v)", tt.name, i, got[i], tt.want[i], got)
				}
			}
		})
	}
}
