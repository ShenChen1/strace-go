package handler

import (
	"fmt"

	"strace-go/internal/architecture"
	"strace-go/pkg/format"
)

func registerBuiltinEpoll(r *Registry) {
	h := &EpollHandler{}
	r.Register("epoll_ctl", h)
	r.Register("epoll_wait", h)
	r.Register("epoll_pwait", h)
	r.Register("epoll_pwait2", h)
}

type EpollHandler struct{}

const (
	epollEventSize          = architecture.EpollEventSize
	epollEventSnapshotLimit = 512
)

func (h *EpollHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "epoll_ctl":
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(ctx.Args[0])))
		op := uint32(ctx.Args[1])
		res.ArgParts = append(res.ArgParts, decodeFlags(ctx, uint64(op), "epollctls"))
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(ctx.Args[2])))

		// IMPACT: Only decode struct epoll_event for ADD (1) and MOD (3) operations.
		// DEL (2) doesn't read the structure in kernel.
		if op == 2 {
			if ctx.Args[3] == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[3]))
			}
		} else {
			if ctx.Args[3] == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
			} else {
				if data, ok := epollCtlEventSnapshot(ctx); ok {
					res.ArgParts = append(res.ArgParts, format.EpollEventWithCatalog(catalogForContext(ctx), data))
				} else {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[3]))
				}
			}
		}
	case "epoll_wait", "epoll_pwait", "epoll_pwait2":
		res.ArgParts = append(res.ArgParts, FormatFdWithPath(ctx, int32(ctx.Args[0])))
		ptr := ctx.Args[1]
		maxevents := int(int32(ctx.Args[2]))

		if ptr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else if ctx.Ret <= 0 {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ptr))
		} else {
			count := int(ctx.Ret)
			capLen := count * epollEventSize
			if capLen > epollEventSnapshotLimit {
				capLen = epollEventSnapshotLimit
			}
			if data, ok := epollWaitEventsSnapshot(ctx, capLen); ok {
				res.ArgParts = append(res.ArgParts, format.EpollEventsWithCatalog(catalogForContext(ctx), data, count))
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ptr))
			}
		}
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", maxevents))
		if ctx.SysName == "epoll_wait" {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(ctx.Args[3])))
		} else if ctx.SysName == "epoll_pwait" {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(ctx.Args[3])))
			res.ArgParts = append(res.ArgParts, formatPointerEpoll(ctx.Args[4], ctx.Ret))
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", ctx.Args[5]))
		} else if ctx.SysName == "epoll_pwait2" {
			if ctx.Ret < 0 || ctx.Args[3] == 0 {
				res.ArgParts = append(res.ArgParts, formatPointerEpoll(ctx.Args[3], ctx.Ret))
			} else {
				if d, ok := epollPwait2TimeoutSnapshot(ctx); ok {
					res.ArgParts = append(res.ArgParts, format.Timespec(d))
				} else {
					res.ArgParts = append(res.ArgParts, formatPointerEpoll(ctx.Args[3], ctx.Ret))
				}
			}
			res.ArgParts = append(res.ArgParts, formatPointerEpoll(ctx.Args[4], ctx.Ret))
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", ctx.Args[5]))
		}
	}
	return res
}

func epollCtlEventSnapshot(ctx *Context) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(3, PayloadDirectionIn); ok {
		return boundedBpfStructData(data, epollEventSize)
	}
	return nil, false
}

func epollWaitEventsSnapshot(ctx *Context, size int) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(1, PayloadDirectionOut); ok {
		return boundedBpfStructData(data, size)
	}
	return nil, false
}

func epollPwait2TimeoutSnapshot(ctx *Context) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(3, PayloadDirectionIn); ok {
		return boundedBpfStructData(data, 16)
	}
	return nil, false
}

func formatPointerEpoll(ptr uint64, ret int64) string {
	if ptr == 0 {
		return "NULL"
	}
	return fmt.Sprintf("%#x", ptr)
}
