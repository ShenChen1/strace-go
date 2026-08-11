package handler

import (
	"encoding/binary"
	"fmt"
)

func registerBuiltinGetRobustList(r *Registry) {
	h := &GetRobustListHandler{}
	r.Register("get_robust_list", h)
	r.Register("set_robust_list", &SetRobustListHandler{})
}

type GetRobustListHandler struct{}

const (
	robustListWordSize = 8
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
			headVal, ok := robustListExitWord(ctx, 1)
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
			lenVal, ok := robustListExitWord(ctx, 2)
			if !ok {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%d]", lenVal))
			}
		}
	}

	return res
}

func robustListExitWord(ctx *Context, argIndex int) (uint64, bool) {
	if data, ok := ctx.PayloadStruct(argIndex, PayloadDirectionOut); ok && len(data) >= robustListWordSize {
		return binary.LittleEndian.Uint64(data[:robustListWordSize]), true
	}
	return 0, false
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
