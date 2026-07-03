package handler

import (
	"fmt"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	h := &FsHandler{}
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

func (h *FsHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "fsconfig":
		res.ArgParts = h.decodeFsconfig(ctx)
	case "mount":
		// source
		res.ArgParts = append(res.ArgParts, fsStringArg(ctx, 0, 0))
		// target
		res.ArgParts = append(res.ArgParts, fsStringArg(ctx, 1, 0))
		// type
		res.ArgParts = append(res.ArgParts, fsStringArg(ctx, 2, 0))

		// flags
		flags := ctx.Args[3]
		if (flags & 0xffff0000) == 0xc0ed0000 {
			if (flags & 0x0000ffff) == 0 {
				res.ArgParts = append(res.ArgParts, "MS_MGC_VAL")
			} else {
				res.ArgParts = append(res.ArgParts, "MS_MGC_VAL|"+meta.DecodeFlags(flags&0xffff, "mount_flags"))
			}
		} else {
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(flags, "mount_flags"))
		}

		// data
		res.ArgParts = append(res.ArgParts, fsStringArg(ctx, 4, 0))

	case "umount2":
		res.ArgParts = append(res.ArgParts, fsStringArg(ctx, 0, 0))
		res.ArgParts = append(res.ArgParts, meta.DecodeFlags(ctx.Args[1], "umount_flags"))

	case "getdents64":
		for i := 0; i < len(ctx.ScMeta.Args); i++ {
			argName, _, val := ctx.ScMeta.Args[i], ctx.ScMeta.ArgTypes[i], ctx.Args[i]
			if argName == "fd" {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(val)))
				continue
			}
			if argName == "dirent" && ctx.Ret > 0 {
				count := int(ctx.Ret)
				data, ok := ctx.ExitSnapshot(BpfExitArgOffset, 512)
				if !ok {
					data = ctx.StrArgBuf[:512]
				}
				res.ArgParts = append(res.ArgParts, format.Dirents(data, count))
				continue
			}
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
		}
	}
	return res
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

func formatPointer(val uint64) string {
	if val == 0 {
		return "NULL"
	}
	return fmt.Sprintf("%#x", val)
}
