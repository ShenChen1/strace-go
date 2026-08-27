package handler

import "fmt"

// RawHandler renders syscall arguments without dereferencing or symbolic decoding.
type RawHandler struct{}

func (h RawHandler) Handle(ctx *Context) Result {
	if ctx == nil {
		return Result{}
	}
	count := len(ctx.ScMeta.ArgTypes)
	parts := make([]string, 0, count)
	for index := 0; index < count; index++ {
		parts = append(parts, formatRawArgument(ctx.Args[index]))
	}
	return Result{ArgParts: parts}
}

func formatRawArgument(value uint64) string {
	if value == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", value)
}
