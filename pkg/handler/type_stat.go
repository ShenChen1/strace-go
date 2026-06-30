package handler

import (
	"fmt"

	"strace-go/pkg/format"
)

func init() {
	RegisterStructDecoder("struct stat *", StructDecoderFunc(decodeStat))
	RegisterStructDecoder("struct stat64 *", StructDecoderFunc(decodeStat))
	RegisterStructDecoder("struct new_stat *", StructDecoderFunc(decodeStat))
	RegisterStructDecoder("struct __old_kernel_stat *", StructDecoderFunc(decodeStat))
	RegisterStructDecoder("struct statfs *", StructDecoderFunc(decodeStatfs))
	RegisterStructDecoder("struct statfs64 *", StructDecoderFunc(decodeStatfs))
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
	if !ok {
		data, ok = ctx.ExitSnapshot(BpfExitArgOffset, statStructSize)
	}
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return format.Stat(data), true
}

func decodeStatfs(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}
	data, ok := ctx.PayloadStruct(i, PayloadDirectionOut)
	if !ok {
		data, ok = ctx.ExitSnapshot(BpfExitArgOffset, statfsStructSize)
	}
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return format.Statfs(data), true
}
