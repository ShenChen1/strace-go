package handler

import (
	"bytes"
	"encoding/binary"
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
	RegisterStructDecoder("struct utsname *", StructDecoderFunc(decodeUtsname))
}

func decodeSysinfo(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}
	return ctx.DecodeStructWithFallback(val, 112, true, ctx.StrArgBuf[BpfExitArgOffset:BpfExitArgOffset+112], format.Sysinfo)

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
		bpfBuf = ctx.StrArgBuf[BpfExitArgOffset : BpfExitArgOffset+32]
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
		bpfBuf = ctx.StrArgBuf[BpfExitArgOffset : BpfExitArgOffset+8]
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

	cur := binary.LittleEndian.Uint64(data[0:8])
	max := binary.LittleEndian.Uint64(data[8:16])

	return fmt.Sprintf("{rlim_cur=%s, rlim_max=%s}", formatRlimitVal(cur), formatRlimitVal(max)), true
}

func decodeUtsname(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}

	const utsnameSize = 65 * 6
	data, ok := ctx.FetchStructDataExact(val, utsnameSize, true, ctx.StrArgBuf[BpfExitArgOffset:BpfExitArgOffset+utsnameSize])
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}

	verbose := ctx.Opts != nil && ctx.Opts.Verbose
	return formatUtsname(data, verbose), true
}

func formatUtsname(data []byte, verbose bool) string {
	fields := []string{
		"sysname=" + formatUtsField(data[0:65]),
		"nodename=" + formatUtsField(data[65:130]),
	}
	if verbose {
		fields = append(fields,
			"release="+formatUtsField(data[130:195]),
			"version="+formatUtsField(data[195:260]),
			"machine="+formatUtsField(data[260:325]),
			"domainname="+formatUtsField(data[325:390]),
		)
	} else {
		fields = append(fields, "...")
	}
	return "{" + strings.Join(fields, ", ") + "}"
}

func formatUtsField(data []byte) string {
	if idx := bytes.IndexByte(data, 0); idx >= 0 {
		data = data[:idx]
	}
	return format.BufferEscape(data, 0, len(data), 0)
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
