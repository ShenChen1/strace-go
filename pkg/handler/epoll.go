package handler

import (
	"fmt"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	h := &EpollHandler{}
	Register("epoll_ctl", h)
	Register("epoll_wait", h)
	Register("epoll_pwait", h)
	Register("epoll_pwait2", h)
}

type EpollHandler struct{}

const (
	epollEventSize          = 12
	epollEventSnapshotLimit = 512
	epollPwait2TimeoutOff   = BpfMiscArgOffset
)

func (h *EpollHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "epoll_ctl":
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(ctx.Args[0])))
		op := uint32(ctx.Args[1])
		res.ArgParts = append(res.ArgParts, meta.DecodeFlags(uint64(op), "epollctls"))
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
				if data, ok := ctx.EnterArgSnapshot(3, BpfEnterArgOffset, epollEventSize); ok {
					res.ArgParts = append(res.ArgParts, format.EpollEvent(data))
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
			capLen := count * 12
			if capLen > epollEventSnapshotLimit {
				capLen = epollEventSnapshotLimit
			}
			if data, ok := ctx.ExitSnapshot(BpfExitArgOffset, capLen); ok {
				res.ArgParts = append(res.ArgParts, format.EpollEvents(data, count))
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
				if d, ok := ctx.EnterArgSnapshot(3, epollPwait2TimeoutOff, 16); ok {
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

func formatPointerEpoll(ptr uint64, ret int64) string {
	if ptr == 0 {
		return "NULL"
	}
	return fmt.Sprintf("%#x", ptr)
}
