package handler

import (
	"fmt"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	h := &FsHandler{}
	Register("getdents", h)
	Register("getdents64", h)
	Register("mount", h)
	Register("umount2", h)
	Register("fsconfig", h)

	// 动态注册字典
	meta.XlatTables["fsconfig_cmds"] = meta.XlatTable{
		Prefix: "FSCONFIG_",
		Entries: []meta.XlatVal{
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
	}
	meta.XlatTables["fsopen_flags"] = meta.XlatTable{
		Prefix: "FSOPEN_",
		Entries: []meta.XlatVal{
			{Val: 1, Str: "FSOPEN_CLOEXEC"},
		},
	}
	// IMPACT: Corrected FSPICK_NO_AUTOMOUNT (4) and FSPICK_EMPTY_PATH (8) values.
	meta.XlatTables["fspick_flags"] = meta.XlatTable{
		Prefix: "FSPICK_",
		Entries: []meta.XlatVal{
			{Val: 1, Str: "FSPICK_CLOEXEC"},
			{Val: 2, Str: "FSPICK_SYMLINK_NOFOLLOW"},
			{Val: 4, Str: "FSPICK_NO_AUTOMOUNT"},
			{Val: 8, Str: "FSPICK_EMPTY_PATH"},
		},
	}

	// 动态注册参数映射关系
	if meta.SyscallArgXlatMap == nil {
		meta.SyscallArgXlatMap = make(map[string]map[string]string)
	}
	meta.SyscallArgXlatMap["fsopen"] = map[string]string{"flags": "fsopen_flags"}
	meta.SyscallArgXlatMap["fspick"] = map[string]string{"flags": "fspick_flags"}
	meta.SyscallArgXlatMap["fsconfig"] = map[string]string{"cmd": "fsconfig_cmds"}
}

type FsHandler struct {
	DefaultHandler
}

const (
	mountFlagRemount uint64 = 0x20
	mountFlagBind    uint64 = 0x1000
)

func (h *FsHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "fsconfig":
		res.ArgParts = h.decodeFsconfig(ctx)
	case "mount":
		res.ArgParts = h.decodeMount(ctx)
	case "umount2":
		res.ArgParts = append(res.ArgParts, fsStringArg(ctx, 0, 0))
		res.ArgParts = append(res.ArgParts, meta.DecodeFlags(ctx.Args[1], "umount_flags"))

	case "getdents", "getdents64":
		res.ArgParts = decodeGetdentsArgs(ctx)
	}
	return res
}

func (h *FsHandler) decodeMount(ctx *Context) []string {
	flags := ctx.Args[3]
	return []string{
		fsStringArg(ctx, 0, 0),
		fsStringArg(ctx, 1, 0),
		mountTypeArg(ctx, flags),
		decodeMountFlags(flags),
		mountDataArg(ctx, flags),
	}
}

func mountTypeArg(ctx *Context, flags uint64) string {
	if ctx.Args[2] == 0 {
		return "NULL"
	}
	if flags&(mountFlagRemount|mountFlagBind) != 0 {
		return formatPointer(ctx.Args[2])
	}
	return fsStringArg(ctx, 2, 0)
}

func mountDataArg(ctx *Context, flags uint64) string {
	if ctx.Args[4] == 0 {
		return "NULL"
	}
	if flags&mountFlagBind != 0 {
		return formatPointer(ctx.Args[4])
	}
	return fsStringArg(ctx, 4, 0)
}

func decodeMountFlags(flags uint64) string {
	if (flags & 0xffff0000) != 0xc0ed0000 {
		return meta.DecodeFlags(flags, "mount_flags")
	}
	if (flags & 0x0000ffff) == 0 {
		return "MS_MGC_VAL"
	}
	return "MS_MGC_VAL|" + meta.DecodeFlags(flags&0xffff, "mount_flags")
}

// decodeFsconfig decodes the arguments of fsconfig based on the command.
// IMPACT: Extracted to keep function size under 80 LOC. Use ctx.Tid instead of ctx.Pid to read memory robustly under exit race conditions.
func (h *FsHandler) decodeFsconfig(ctx *Context) []string {
	fd := ctx.Args[0]
	// IMPACT: Mask cmd to uint32 to strip any upper fill bits added by test programs.
	cmd := uint64(uint32(ctx.Args[1]))
	key := ctx.Args[2]
	value := ctx.Args[3]
	aux := ctx.Args[4]

	parts := []string{
		h.decodeScalar(ctx, "int", "fd", fd),
		meta.DecodeFlags(cmd, "fsconfig_cmds"),
	}

	// IMPACT: Format key and value arguments as pointers when cmd > 5 (create, reconfigure, or invalid commands) matching upstream strace behavior.
	if cmd > 5 {
		parts = append(parts, formatPointer(key), formatPointer(value), fmt.Sprintf("%d", int32(aux)))
		return parts
	}

	// IMPACT: Decode key/value only from semantic payload sections; missing sections fall back to pointers.
	keyStr := fsStringArg(ctx, 2, 256)
	parts = append(parts, keyStr)

	switch cmd {
	case 0: // FSCONFIG_SET_FLAG
		parts = append(parts, formatPointer(value), fmt.Sprintf("%d", int32(aux)))
	case 1: // FSCONFIG_SET_STRING
		valStr := fsStringArg(ctx, 3, 256)
		parts = append(parts, valStr, fmt.Sprintf("%d", int32(aux)))
	case 2: // FSCONFIG_SET_BINARY
		limit := ctx.Opts.StringLimit
		if limit <= 0 {
			limit = 32
		}
		valLen := int(int32(aux))
		if valLen < 0 || valLen > 1024*1024 {
			parts = append(parts, formatPointer(value), fmt.Sprintf("%d", int32(aux)))
		} else if valLen == 0 {
			parts = append(parts, format.BufferEscape(nil, limit, 0, 2), fmt.Sprintf("%d", int32(aux)))
		} else {
			data, ok := fsBytesArg(ctx, 3)
			if ok && len(data) > 0 {
				parts = append(parts, format.BufferEscape(data, limit, valLen, 2), fmt.Sprintf("%d", int32(aux)))
			} else {
				parts = append(parts, formatPointer(value), fmt.Sprintf("%d", int32(aux)))
			}
		}
	case 3, 4: // FSCONFIG_SET_PATH, FSCONFIG_SET_PATH_EMPTY
		// IMPACT: Set value path decode limit to 0 to bypass StringLimit formatting truncation for path arguments.
		valStr := fsStringArg(ctx, 3, 0)
		if int32(aux) < 0 && int32(aux) != AtFdcwd {
			valStr = strings.TrimSuffix(valStr, "...")
		}
		parts = append(parts, valStr, h.decodeScalar(ctx, "int", "dfd", aux))
	case 5: // FSCONFIG_SET_FD
		parts = append(parts, formatPointer(value), h.decodeScalar(ctx, "int", "fd", aux))
	default:
		parts = append(parts, formatPointer(value), fmt.Sprintf("%d", int32(aux)))
	}

	return parts
}

func fsStringArg(ctx *Context, argIndex int, limit int) string {
	ptr := ctx.Args[argIndex]
	if s, ok := ctx.PayloadString(argIndex, PayloadDirectionIn, ptr, limit); ok {
		if limit > 0 && !strings.HasSuffix(s, "...") {
			if section, sectionOK := ctx.Section(argIndex, PayloadKindString); sectionOK && section.CopiedLen > uint32(limit) {
				s += "..."
			}
		}
		return s
	}
	return formatPointer(ptr)
}

func fsBytesArg(ctx *Context, argIndex int) ([]byte, bool) {
	if data, ok := ctx.PayloadBytes(argIndex, PayloadDirectionIn); ok {
		return data, true
	}
	return nil, false
}

func decodeGetdentsArgs(ctx *Context) []string {
	parts := make([]string, 0, len(ctx.ScMeta.Args))
	for i, argName := range ctx.ScMeta.Args {
		val := ctx.Args[i]
		switch argName {
		case "fd":
			parts = append(parts, fmt.Sprintf("%d", int32(val)))
		case "dirent":
			parts = append(parts, formatGetdentsDirent(ctx, i, val))
		case "count":
			parts = append(parts, fmt.Sprintf("%d", uint32(val)))
		default:
			parts = append(parts, fmt.Sprintf("%#x", val))
		}
	}
	return parts
}

func formatGetdentsDirent(ctx *Context, argIndex int, ptr uint64) string {
	if ptr == 0 {
		return "NULL"
	}
	if ctx.Ret == 0 {
		if getdentsVerbose(ctx) {
			return "[]"
		}
		return fmt.Sprintf("%#x /* 0 entries */", ptr)
	}
	if ctx.Ret < 0 {
		return formatPointer(ptr)
	}
	data, ok := ctx.PayloadBytes(argIndex, PayloadDirectionOut)
	if !ok {
		return formatPointer(ptr)
	}
	layout := getdentsLayout(ctx.SysName)
	if getdentsVerbose(ctx) {
		escapeMode := 0
		if ctx.Opts != nil {
			escapeMode = ctx.Opts.HexEscapeMode
		}
		snapshot := format.DecodeDirents(data, int(ctx.Ret), layout)
		return snapshot.Verbose(escapeMode)
	}
	entries, _ := format.CountDirents(data, int(ctx.Ret), layout)
	return fmt.Sprintf("%#x /* %d entries */", ptr, entries)
}

func getdentsLayout(sysName string) format.DirentLayout {
	if sysName == "getdents" {
		return format.DirentLayoutLegacy
	}
	return format.DirentLayout64
}

func getdentsVerbose(ctx *Context) bool {
	return ctx.Opts != nil && ctx.Opts.Verbose && !ctx.Opts.VerboseDisabled[ctx.SysName]
}

func formatPointer(val uint64) string {
	if val == 0 {
		return "NULL"
	}
	return fmt.Sprintf("%#x", val)
}
