package handler

import (
	"fmt"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	h := &FutexHandler{}
	Register("futex", h)
}

type FutexHandler struct{}

func (h *FutexHandler) Handle(ctx *Context) Result {
	res := Result{}
	uaddr := ctx.Args[0]
	op := ctx.Args[1]
	val := ctx.Args[2]
	timeout := ctx.Args[3]
	uaddr2 := ctx.Args[4]
	val3 := ctx.Args[5]

	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", uaddr))
	res.ArgParts = append(res.ArgParts, meta.DecodeFlags(op, "futexops"))
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(val)))

	baseOp := op & 0x7f
	if baseOp == 0 || baseOp == 11 || baseOp == 2 { // WAIT, WAIT_BITSET, REQUEUE
		if timeout == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			if data, ok := ctx.EnterArgSnapshot(3, BpfEnterArgOffset, 16); ok {
				res.ArgParts = append(res.ArgParts, format.Timespec(data))
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", timeout))
			}
		}
	} else {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", timeout))
	}

	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", uaddr2))
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val3))

	return res
}
