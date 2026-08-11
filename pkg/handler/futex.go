package handler

import (
	"fmt"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

const (
	futexCmdMask          = 0x7f
	futexCmdWait          = 0
	futexCmdLockPI        = 6
	futexCmdWaitBitset    = 9
	futexCmdWaitRequeuePI = 11
	futexCmdLockPI2       = 13
)

func registerBuiltinFutex(r *Registry) {
	h := &FutexHandler{}
	r.Register("futex", h)
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

	baseOp := op & futexCmdMask
	if futexOpHasTimeout(baseOp) {
		if timeout == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			if data, ok := futexTimeoutSnapshot(ctx); ok {
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

func futexOpHasTimeout(baseOp uint64) bool {
	return baseOp == futexCmdWait ||
		baseOp == futexCmdLockPI ||
		baseOp == futexCmdWaitBitset ||
		baseOp == futexCmdWaitRequeuePI ||
		baseOp == futexCmdLockPI2
}

func futexTimeoutSnapshot(ctx *Context) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(3, PayloadDirectionIn); ok {
		return boundedBpfStructData(data, timespecSize)
	}
	return nil, false
}
