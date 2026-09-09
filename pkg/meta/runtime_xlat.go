package meta

var supplementalXlatTables = map[string]XlatTable{
	"fsconfig_cmds": {
		Prefix: "FSCONFIG_",
		Entries: []XlatVal{
			{Val: 0, Str: "FSCONFIG_SET_FLAG"},
			{Val: 1, Str: "FSCONFIG_SET_STRING"},
			{Val: 2, Str: "FSCONFIG_SET_BINARY"},
			{Val: 3, Str: "FSCONFIG_SET_PATH"},
			{Val: 4, Str: "FSCONFIG_SET_PATH_EMPTY"},
			{Val: 5, Str: "FSCONFIG_SET_FD"},
			{Val: 6, Str: "FSCONFIG_CMD_CREATE"},
			{Val: 7, Str: "FSCONFIG_CMD_RECONFIGURE"},
			{Val: 8, Str: "FSCONFIG_CMD_CREATE_EXCL"},
		},
	},
	"fsopen_flags": {
		Prefix:  "FSOPEN_",
		Entries: []XlatVal{{Val: 1, Str: "FSOPEN_CLOEXEC"}},
	},
	"fspick_flags": {
		Prefix: "FSPICK_",
		Entries: []XlatVal{
			{Val: 1, Str: "FSPICK_CLOEXEC"},
			{Val: 2, Str: "FSPICK_SYMLINK_NOFOLLOW"},
			{Val: 4, Str: "FSPICK_NO_AUTOMOUNT"},
			{Val: 8, Str: "FSPICK_EMPTY_PATH"},
		},
	},
	"fiemap_flags": {
		Prefix: "FIEMAP_FLAG_",
		Entries: []XlatVal{
			{Val: 1, Str: "FIEMAP_FLAG_SYNC"},
			{Val: 2, Str: "FIEMAP_FLAG_XATTR"},
			{Val: 4, Str: "FIEMAP_FLAG_CACHE"},
		},
	},
	"fiemap_extent_flags": {
		Prefix: "FIEMAP_EXTENT_",
		Entries: []XlatVal{
			{Val: 0x00000001, Str: "FIEMAP_EXTENT_LAST"},
			{Val: 0x00000002, Str: "FIEMAP_EXTENT_UNKNOWN"},
			{Val: 0x00000004, Str: "FIEMAP_EXTENT_DELALLOC"},
			{Val: 0x00000008, Str: "FIEMAP_EXTENT_ENCODED"},
			{Val: 0x00000080, Str: "FIEMAP_EXTENT_DATA_ENCRYPTED"},
			{Val: 0x00000100, Str: "FIEMAP_EXTENT_NOT_ALIGNED"},
			{Val: 0x00000200, Str: "FIEMAP_EXTENT_DATA_INLINE"},
			{Val: 0x00000400, Str: "FIEMAP_EXTENT_DATA_TAIL"},
			{Val: 0x00000800, Str: "FIEMAP_EXTENT_UNWRITTEN"},
			{Val: 0x00001000, Str: "FIEMAP_EXTENT_MERGED"},
			{Val: 0x00002000, Str: "FIEMAP_EXTENT_SHARED"},
		},
	},
	"file_attr_at_flags": {
		Prefix: "AT_",
		Entries: []XlatVal{
			{Val: 0, Str: "0"},
			{Val: 0x100, Str: "AT_SYMLINK_NOFOLLOW"},
			{Val: 0x1000, Str: "AT_EMPTY_PATH"},
			{Val: 0x1100, Str: "AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH"},
		},
	},
	"fs_xflags": {
		Prefix: "FS_XFLAG_",
		Entries: []XlatVal{
			{Val: 0x00000001, Str: "FS_XFLAG_REALTIME"},
			{Val: 0x00000002, Str: "FS_XFLAG_PREALLOC"},
			{Val: 0x00000008, Str: "FS_XFLAG_IMMUTABLE"},
			{Val: 0x00000010, Str: "FS_XFLAG_APPEND"},
			{Val: 0x00000020, Str: "FS_XFLAG_SYNC"},
			{Val: 0x00000040, Str: "FS_XFLAG_NOATIME"},
			{Val: 0x00000080, Str: "FS_XFLAG_NODUMP"},
			{Val: 0x00000100, Str: "FS_XFLAG_RTINHERIT"},
			{Val: 0x00000200, Str: "FS_XFLAG_PROJINHERIT"},
			{Val: 0x00000400, Str: "FS_XFLAG_NOSYMLINKS"},
			{Val: 0x00000800, Str: "FS_XFLAG_EXTSIZE"},
			{Val: 0x00001000, Str: "FS_XFLAG_EXTSZINHERIT"},
			{Val: 0x00002000, Str: "FS_XFLAG_NODEFRAG"},
			{Val: 0x00004000, Str: "FS_XFLAG_FILESTREAM"},
			{Val: 0x00008000, Str: "FS_XFLAG_DAX"},
			{Val: 0x00010000, Str: "FS_XFLAG_COWEXTSIZE"},
			{Val: 0x00020000, Str: "FS_XFLAG_VERITY"},
			{Val: 0x80000000, Str: "FS_XFLAG_HASATTR"},
			{Val: 0x00040000, Str: "FS_XFLAG_CASEFOLD"},
			{Val: 0x00080000, Str: "FS_XFLAG_CASENONPRESERVING"},
		},
	},
}

var supplementalSyscallArgXlatMap = map[string]map[string]string{
	"file_getattr": {"at_flags": "file_attr_at_flags"},
	"file_setattr": {"at_flags": "file_attr_at_flags"},
	"fsconfig":     {"cmd": "fsconfig_cmds"},
	"fsopen":       {"flags": "fsopen_flags"},
	"fspick":       {"flags": "fspick_flags"},
}
