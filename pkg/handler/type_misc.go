package handler

import (
	"fmt"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	RegisterStructDecoder("struct sysinfo *", StructDecoderFunc(decodeSysinfo))
	RegisterStructDecoder("struct flock *", StructDecoderFunc(decodeFlock))
	RegisterStructDecoder("struct flock64 *", StructDecoderFunc(decodeFlock))
	RegisterStructDecoder("struct f_owner_ex *", StructDecoderFunc(decodeFOwnerEx))
	RegisterStructDecoder("struct rlimit *", StructDecoderFunc(decodeRlimitPointer))
	RegisterStructDecoder("struct rlimit64 *", StructDecoderFunc(decodeRlimitPointer))
	RegisterStructDecoder("struct statfs *", StructDecoderFunc(decodeStatfs))
	RegisterStructDecoder("struct statfs64 *", StructDecoderFunc(decodeStatfs))
}

func decodeSysinfo(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}
	data, ok := ctx.FetchStructDataExact(val, 112, true, ctx.StrArgBuf[1024:1024+112])
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return format.Sysinfo(data), true
}

func decodeFlock(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}
	// For flock, we want exit data if it's F_GETLK, else enter data. 
	// Both could be useful, we just try to read exit, then fallback to enter logic.
	bpfBuf := ctx.StrArgBuf[0:32]
	isExit := false
	if ctx.ProbeRetExit >= 0 {
		bpfBuf = ctx.StrArgBuf[1024 : 1024+32]
		isExit = true
	}
	
	data, ok := ctx.FetchStructDataExact(val, 32, isExit, bpfBuf)
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	
	cmd := uint32(ctx.Args[1])
	cmdStr := meta.DecodeFlags(uint64(cmd), "fcntl_cmds")
	showsPid := strings.Contains(cmdStr, "GETLK")
	return format.Flock(data, showsPid), true
}

func decodeFOwnerEx(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}
	bpfBuf := ctx.StrArgBuf[0:8]
	isExit := false
	if ctx.ProbeRetExit >= 0 {
		bpfBuf = ctx.StrArgBuf[1024 : 1024+8]
		isExit = true
	}
	
	data, ok := ctx.FetchStructDataExact(val, 8, isExit, bpfBuf)
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return format.FOwnerEx(data), true
}

func decodeRlimitPointer(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if val == 0 {
		return "NULL", true
	}

	scName := ctx.ScMeta.Name
	var isOutput bool
	var offset int
	if scName == "getrlimit" {
		isOutput = true
		offset = 1024
	} else if scName == "setrlimit" {
		isOutput = false
		offset = 0
	} else if scName == "prlimit64" {
		if i == 2 {
			isOutput = false
			offset = 0
		} else if i == 3 {
			isOutput = true
			offset = 1024
		} else {
			return fmt.Sprintf("%#x", val), true
		}
	} else {
		return fmt.Sprintf("%#x", val), true
	}

	if isOutput && ctx.Ret < 0 {
		return fmt.Sprintf("%#x", val), true
	}

	bpfBuf := ctx.StrArgBuf[offset : offset+16]
	isExit := false
	if isOutput {
		if ctx.ProbeRetExit >= 0 {
			isExit = true
		} else {
			// If we need output and don't have exit probe data, we shouldn't use enter data
			// but FetchStructData might fallback to MemReader, which is correct since memory reflects exit state.
		}
	} else {
		// Not output, so we want enter data.
		// If we don't have enter data, FetchStructData will still try to read memory.
	}

	data, ok := ctx.FetchStructDataExact(val, 16, isExit, bpfBuf)
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}

	cur := uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 |
		uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56
	max := uint64(data[8]) | uint64(data[9])<<8 | uint64(data[10])<<16 | uint64(data[11])<<24 |
		uint64(data[12])<<32 | uint64(data[13])<<40 | uint64(data[14])<<48 | uint64(data[15])<<56

	return fmt.Sprintf("{rlim_cur=%s, rlim_max=%s}", formatRlimitVal(cur), formatRlimitVal(max)), true
}

func formatRlimitVal(v uint64) string {
	if v == ^uint64(0) {
		return "RLIM64_INFINITY"
	}
	if v > 1024 && v%1024 == 0 {
		return fmt.Sprintf("%d*1024", v/1024)
	}
	return fmt.Sprintf("%d", v)
}

func decodeStatfs(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}
	data, ok := ctx.FetchStructDataExact(val, 120, true, ctx.StrArgBuf[1024:1024+120])
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return format.Statfs(data), true
}
