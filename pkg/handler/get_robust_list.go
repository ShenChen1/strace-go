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

func (h *GetRobustListHandler) Handle(ctx *Context) Result {
	res := Result{}

	// int pid
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(ctx.Args[0])))

	// struct robust_list_head **head_ptr
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		if ctx.Args[1] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
		}
	} else {
		if ctx.Args[1] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			data, ok := ctx.FetchStructDataExact(ctx.Args[1], 8, true, nil)
			if !ok {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
			} else {
				head_val := binary.LittleEndian.Uint64(data)
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%#x]", head_val))
			}
		}
	}

	// size_t *len_ptr
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		if ctx.Args[2] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
		}
	} else {
		if ctx.Args[2] == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			data, ok := ctx.FetchStructDataExact(ctx.Args[2], 8, true, nil)
			if !ok {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
			} else {
				len_val := binary.LittleEndian.Uint64(data)
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%d]", len_val))
			}
		}
	}

	return res
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
