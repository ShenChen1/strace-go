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
}

type FsHandler struct {
	DefaultHandler
}

func (h *FsHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "mount":
		// source
		res.ArgParts = append(res.ArgParts, ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[0], ctx.StrArgBuf[0:512], ctx.ProbeRetEnter, ctx.SysName, 0))
		// target
		res.ArgParts = append(res.ArgParts, ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[1], ctx.StrArgBuf[512:1024], ctx.ProbeRetEnter, ctx.SysName, 0))
		// type
		res.ArgParts = append(res.ArgParts, ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[2], ctx.StrArgBuf[1024:1152], ctx.ProbeRetEnter, ctx.SysName, 0))

		// flags
		flags := ctx.Args[3]
		if (flags & 0xffff0000) == 0xc0ed0000 {
			if (flags & 0x0000ffff) == 0 {
				res.ArgParts = append(res.ArgParts, "MS_MGC_VAL")
			} else {
				res.ArgParts = append(res.ArgParts, "MS_MGC_VAL|"+meta.DecodeFlags(flags & 0xffff, "mount_flags"))
			}
		} else {
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(flags, "mount_flags"))
		}

		// data
		res.ArgParts = append(res.ArgParts, ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[4], ctx.StrArgBuf[1152:1664], ctx.ProbeRetEnter, ctx.SysName, 0))

	case "umount2":
		res.ArgParts = append(res.ArgParts, ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[0], ctx.StrArgBuf[0:512], ctx.ProbeRetEnter, ctx.SysName, 0))
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
				data := ctx.StrArgBuf[:512]
				if ctx.ProbeRetExit <= 0 {
					if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 512, true); err == nil && len(d) == 512 { data = d }
				}
				res.ArgParts = append(res.ArgParts, format.Dirents(data, count))
				continue
			}
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
		}
	}
	return res
}
