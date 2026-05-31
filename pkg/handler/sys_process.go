package handler

import "sync"

func init() {
	Register("execveat", &ExecveatHandler{})
}

var (
	execveatCountLock sync.Mutex
	execveatCallCount int
)

type ExecveatHandler struct{}

func (h *ExecveatHandler) Handle(ctx *Context) Result {
	if ctx.Ret == -514 {
		execveatCountLock.Lock()
		execveatCallCount++
		execveatCountLock.Unlock()
	}
	return GetDefault().(*DefaultHandler).HandleWithCount(ctx, len(ctx.ScMeta.ArgTypes))
}
