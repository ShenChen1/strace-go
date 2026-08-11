package handler

import (
	"fmt"

	"strace-go/pkg/format"
)

func registerBuiltinTypeStat(r *Registry) {
	r.RegisterStructDecoder("struct stat *", StructDecoderFunc(decodeStat))
	r.RegisterStructDecoder("struct stat64 *", StructDecoderFunc(decodeStat))
	r.RegisterStructDecoder("struct new_stat *", StructDecoderFunc(decodeStat))
	r.RegisterStructDecoder("struct __old_kernel_stat *", StructDecoderFunc(decodeStat))
	r.RegisterStructDecoder("struct statfs *", StructDecoderFunc(decodeStatfs))
	r.RegisterStructDecoder("struct statfs64 *", StructDecoderFunc(decodeStatfs))
}

const (
	statStructSize   = 144
	statfsStructSize = 120
)

func decodeStat(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}
	data, ok := ctx.PayloadStruct(i, PayloadDirectionOut)
	if !ok || len(data) < statStructSize {
		return fmt.Sprintf("%#x", val), true
	}
	return format.Stat(data[:statStructSize]), true
}

func decodeStatfs(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}
	data, ok := ctx.PayloadStruct(i, PayloadDirectionOut)
	if !ok || len(data) < statfsStructSize {
		return fmt.Sprintf("%#x", val), true
	}
	return format.Statfs(data[:statfsStructSize]), true
}
