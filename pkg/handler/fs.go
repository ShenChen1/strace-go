package handler

import (
	"fmt"
	"strace-go/pkg/format"
)

func init() {
	h := &FsHandler{}
	Register("getdents64", h)
}

type FsHandler struct {
	DefaultHandler
}

func (h *FsHandler) Handle(ctx *Context) Result {
	var res Result
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
				if d, err := ctx.MemReader.ReadRobust(ctx.Tid, val, 512, true); err == nil { data = d }
			}
			res.ArgParts = append(res.ArgParts, format.Dirents(data, count))
			continue
		}

		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
	}
	return res
}
