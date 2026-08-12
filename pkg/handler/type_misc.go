package handler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
)

func registerBuiltinTypeMisc(r *Registry) {
	r.RegisterStructDecoder("struct sysinfo *", StructDecoderFunc(decodeSysinfo))
	r.RegisterStructDecoder("struct flock *", StructDecoderFunc(decodeFlock))
	r.RegisterStructDecoder("struct flock64 *", StructDecoderFunc(decodeFlock))
	r.RegisterStructDecoder("struct f_owner_ex *", StructDecoderFunc(decodeFOwnerEx))
	r.RegisterStructDecoder("struct rlimit *", StructDecoderFunc(decodeRlimitPointer))
	r.RegisterStructDecoder("struct rlimit64 *", StructDecoderFunc(decodeRlimitPointer))
	r.RegisterStructDecoder("struct utsname *", StructDecoderFunc(decodeUtsname))
}

const (
	sysinfoStructSize = 112
	rlimitStructSize  = 16
	utsnameStructSize = 65 * 6
)

func decodeSysinfo(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}
	data, ok := miscStructSnapshot(ctx, i, PayloadDirectionOut, sysinfoStructSize)
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return format.Sysinfo(data), true
}

func decodeFlock(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}

	cmdStr := (&FcntlHandler{}).decodeCmd(ctx, uint64(uint32(ctx.Args[1])))
	isGet := strings.Contains(cmdStr, "GETLK")
	data, ok := miscFcntlSnapshot(ctx, i, isGet, fcntlFlockSize)
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return format.Flock(data, isGet), true
}

func decodeFOwnerEx(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}
	cmdStr := (&FcntlHandler{}).decodeCmd(ctx, uint64(uint32(ctx.Args[1])))
	data, ok := miscFcntlSnapshot(ctx, i, cmdStr == "F_GETOWN_EX", fcntlStructSize)
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return format.FOwnerEx(data), true
}

func miscFcntlSnapshot(ctx *Context, argIndex int, useExit bool, size int) ([]byte, bool) {
	return fcntlStructSnapshot(ctx, argIndex, useExit, size)
}

func decodeRlimitPointer(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if val == 0 {
		return "NULL", true
	}

	scName := ctx.ScMeta.Name
	var isOutput bool
	if scName == "getrlimit" {
		isOutput = true
	} else if scName == "setrlimit" {
		isOutput = false
	} else if scName == "prlimit64" {
		if i == 2 {
			isOutput = false
		} else if i == 3 {
			isOutput = true
		} else {
			return fmt.Sprintf("%#x", val), true
		}
	} else {
		return fmt.Sprintf("%#x", val), true
	}

	if isOutput && ctx.Ret < 0 {
		return fmt.Sprintf("%#x", val), true
	}

	if isOutput {
		data, ok := miscStructSnapshot(ctx, i, PayloadDirectionOut, rlimitStructSize)
		if !ok {
			return fmt.Sprintf("%#x", val), true
		}
		return formatRlimitData(ctx, data), true
	} else {
		data, ok := miscStructSnapshot(ctx, i, PayloadDirectionIn, rlimitStructSize)
		if !ok {
			return fmt.Sprintf("%#x", val), true
		}
		return formatRlimitData(ctx, data), true
	}
}

func formatRlimitData(ctx *Context, data []byte) string {
	cur := binary.LittleEndian.Uint64(data[0:8])
	max := binary.LittleEndian.Uint64(data[8:16])

	return fmt.Sprintf("{rlim_cur=%s, rlim_max=%s}", formatRlimitVal(cur, xlatFormat(ctx)), formatRlimitVal(max, xlatFormat(ctx)))
}

func decodeUtsname(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
		return fmt.Sprintf("%#x", val), true
	}

	data, ok := miscStructSnapshot(ctx, i, PayloadDirectionOut, utsnameStructSize)
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}

	verbose := ctx.Opts != nil && ctx.Opts.VerboseValue()
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

func miscStructSnapshot(ctx *Context, argIndex int, direction PayloadDirection, size int) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(argIndex, direction); ok && len(data) >= size {
		return data[:size], true
	}
	return nil, false
}

func formatRlimitVal(v uint64, xlatFormat string) string {
	raw := fmt.Sprintf("%d", v)
	symbol := ""
	if v == ^uint64(0) {
		symbol = "RLIM64_INFINITY"
	} else if v > 1024 && v%1024 == 0 {
		symbol = fmt.Sprintf("%d*1024", v/1024)
	}
	if symbol == "" || xlatFormat == "raw" {
		return raw
	}
	if xlatFormat == "verbose" {
		return fmt.Sprintf("%s /* %s */", raw, symbol)
	}
	return symbol
}
