package handler

import (
	"encoding/binary"
	"fmt"
)

func init() {
	h := &GetRobustListHandler{}
	Register("get_robust_list", h)
	Register("set_robust_list", &SetRobustListHandler{})
}

type GetRobustListHandler struct{}

const (
	robustListWordSize   = 8
	robustListHeadOffset = BpfExitArgOffset
	robustListLenOffset  = BpfExitArgOffset + 16
)

func (h *GetRobustListHandler) Handle(ctx *Context) Result {
	res := Result{}

	// int pid
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(ctx.Args[0])))

	// struct robust_list_head **head_ptr
	if ctx.Ret < 0 && ctx.Ret >= -4095 {
		if ctx.Args[1] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
		}
	} else {
		if ctx.Args[1] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			headVal, ok := robustListExitWord(ctx, robustListHeadOffset)
			if !ok {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%#x]", headVal))
			}
		}
	}

	// size_t *len_ptr
	if ctx.Ret < 0 && ctx.Ret >= -4095 {
		if ctx.Args[2] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
		}
	} else {
		if ctx.Args[2] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			lenVal, ok := robustListExitWord(ctx, robustListLenOffset)
			if !ok {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%d]", lenVal))
			}
		}
	}

	return res
}

func robustListExitWord(ctx *Context, offset int) (uint64, bool) {
	data, ok := ctx.ExitSnapshot(offset, robustListWordSize)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint64(data), true
}

type SetRobustListHandler struct{}

func (h *SetRobustListHandler) Handle(ctx *Context) Result {
	res := Result{}

	// struct robust_list_head *head
	if ctx.Args[0] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
	}

	// size_t len
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", ctx.Args[1]))

	return res
}
