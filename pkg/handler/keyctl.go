package handler

import (
	"fmt"

	"strace-go/pkg/format"
)

const (
	keyctlJoinSessionKeyring = 1
	keyctlUpdate             = 2
	keyctlDescribe           = 6
	keyctlSearch             = 10
	keyctlRead               = 11
	keyctlGetSecurity        = 17
	keyctlInstantiate        = 12
	keyctlReject             = 19
	keyctlCapabilities       = 31
)

func registerBuiltinKeyctl(r *Registry) {
	r.Register("keyctl", &KeyctlHandler{})
}

// KeyctlHandler decodes only operation-specific values captured by BPF.
// Unsupported operations intentionally retain scalar arguments instead of
// guessing a pointer ABI that the direct provider does not own.
type KeyctlHandler struct{}

func (h *KeyctlHandler) Handle(ctx *Context) Result {
	res := Result{ArgParts: []string{decodeFlags(ctx, ctx.Args[0], "keyctl_commands")}}
	for index := 1; index < 5; index++ {
		res.ArgParts = append(res.ArgParts, keyctlArgument(ctx, index))
	}
	return res
}

func keyctlArgument(ctx *Context, index int) string {
	operation := ctx.Args[0]
	switch operation {
	case keyctlJoinSessionKeyring:
		if index == 1 {
			return keyctlStringArgument(ctx, index, PayloadDirectionIn)
		}
	case keyctlUpdate, keyctlInstantiate:
		if index == 2 {
			return keyctlBytesArgument(ctx, index, PayloadDirectionIn, int64(ctx.Args[3]))
		}
	case keyctlSearch:
		if index == 2 || index == 3 {
			return keyctlStringArgument(ctx, index, PayloadDirectionIn)
		}
	case keyctlDescribe, keyctlRead, keyctlGetSecurity:
		if index == 2 {
			return keyctlBytesArgument(ctx, index, PayloadDirectionOut, ctx.Ret)
		}
	case keyctlCapabilities:
		if index == 1 {
			return keyctlBytesArgument(ctx, index, PayloadDirectionOut, ctx.Ret)
		}
	}
	return fmt.Sprintf("%#x", ctx.Args[index])
}

func keyctlStringArgument(ctx *Context, index int, direction PayloadDirection) string {
	ptr := ctx.Args[index]
	if ptr == 0 {
		return "NULL"
	}
	if value, ok := ctx.PayloadString(index, direction, ptr, ctx.Opts.StringLimitValue()); ok {
		return value
	}
	return fmt.Sprintf("%#x", ptr)
}

func keyctlBytesArgument(
	ctx *Context,
	index int,
	direction PayloadDirection,
	actualLen int64,
) string {
	ptr := ctx.Args[index]
	if ptr == 0 {
		return "NULL"
	}
	data, ok := ctx.PayloadBytes(index, direction)
	if !ok {
		return fmt.Sprintf("%#x", ptr)
	}
	if actualLen < 0 {
		return fmt.Sprintf("%#x", ptr)
	}
	length := int(actualLen)
	if length > len(data) {
		length = len(data)
	}
	if length < 0 {
		length = 0
	}
	return format.BufferEscape(data[:length], 0, int(actualLen), 0)
}
