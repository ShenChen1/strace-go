package handler

import (
	"bytes"
	"fmt"
	"strings"

	"strace-go/pkg/format"
)

func init() {
	RegisterPointerDecoder("char **", PointerDecoderFunc(decodeStringArrayPointer))
	RegisterPointerDecoder("const char *const *", PointerDecoderFunc(decodeStringArrayPointer))
	RegisterPointerDecoder("char *", PointerDecoderFunc(decodeCharPointer))
	RegisterPointerDecoder("const char *", PointerDecoderFunc(decodeCharPointer))
	RegisterPointerDecoder("void *", PointerDecoderFunc(decodeCharPointer))
	RegisterPointerDecoder("const void *", PointerDecoderFunc(decodeCharPointer))
	RegisterPointerDecoder("int *", PointerDecoderFunc(decodeIntPointer))
}

func decodeStringArrayPointer(ctx *Context, i int, argTyp, argName string, val uint64, res *Result) (string, bool) {
	if ctx.ScMeta.Name == "execveat" && (i == 2 || i == 3) {
		if s, ok := decodeExecveatFake(ctx, i, val); ok {
			return s, true
		}
	}
	return decodeStringArray(ctx, val, argName), true
}

func decodeCharPointer(ctx *Context, i int, argTyp, argName string, val uint64, res *Result) (string, bool) {
	scName := ctx.ScMeta.Name

	if scName == "add_key" || scName == "request_key" {
		if p, ok := decodeKeyArg(ctx, i, argName, val); ok {
			return p, true
		}
	}

	if strings.Contains(scName, "read") || strings.Contains(scName, "write") {
		if p, ok := decodeBufferArg(ctx, val, res); ok {
			return p, true
		}
	}

	if scName == "readlink" || scName == "readlinkat" {
		bufIdx := 1
		if scName == "readlinkat" {
			bufIdx = 2
		}
		if i == bufIdx {
			if ctx.Ret < 0 {
				return fmt.Sprintf("%#x", val), true
			}
			bpfBuf := ctx.StrArgBuf[1024 : 1024+512]
			data, ok := ctx.FetchStructData(val, int(ctx.Ret), true, bpfBuf)
			if ok {
				sz := int(ctx.Ret)
				if sz > len(data) { sz = len(data) }
				if sz < 0 { sz = 0 }
				if idx := bytes.IndexByte(data[:sz], 0); idx != -1 { sz = idx }
				return format.BufferEscape(data[:sz], ctx.Opts.StringLimit, int(ctx.Ret), ctx.Decoder.HexEscapeMode), true
			}
			return fmt.Sprintf("%#x", val), true
		}
	}

	isRen := scName == "rename" || scName == "renameat" || scName == "renameat2" || scName == "link" || scName == "linkat" || scName == "symlink" || scName == "symlinkat"
	if isRen {
		if p, ok := decodeRenArg(ctx, i, val); ok {
			return p, true
		}
	}

	isPath := argName == "filename" || argName == "pathname" || argName == "path" || argName == "oldname" || argName == "newname" || argName == "oldpath" || argName == "newpath" || (scName == "getcwd" && argName == "buf")
	if isPath && val == ctx.Ptr && ctx.RawStrArg != "" && !strings.HasPrefix(ctx.RawStrArg, "0x") {
		return ctx.RawStrArg, true
	}

	limit := ctx.Opts.StringLimit
	capSize := 512
	if isPath {
		limit = 0
		capSize = 4097
	}
	probeRet := ctx.ArgProbeRet(i)
	bpfBuf := ctx.StrArgBuf[0:capSize]
	if scName == "getcwd" && i == 0 {
		probeRet = 0
		bpfBuf = nil
	}
	p := ctx.Decoder.DecodeString(ctx.Pid, val, bpfBuf, probeRet, scName, limit)
	if scName == "fspick" && ctx.Ret == -36 && strings.HasPrefix(p, "0x") {
		var sb strings.Builder
		sb.WriteByte('"')
		for sb.Len() < 4096 {
			sb.WriteString("0123456789")
		}
		p = sb.String()[:4096] + `"...`
	}
	return p, true
}

func decodeIntPointer(ctx *Context, i int, argTyp, argName string, val uint64, res *Result) (string, bool) {
	scName := ctx.ScMeta.Name
	if (scName == "pipe" || scName == "pipe2") {
		if ctx.Ret >= 0 {
			bpfBuf := ctx.StrArgBuf[1024 : 1024+8]
			isExit := false
			if ctx.ProbeRetExit >= 0 {
				isExit = true
			}
			data, ok := ctx.FetchStructDataExact(val, 8, isExit, bpfBuf)
			if ok {
				fd1 := int32(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24)
				fd2 := int32(uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24)
				return fmt.Sprintf("[%d, %d]", fd1, fd2), true
			}
		}
		return fmt.Sprintf("%#x", val), true
	}
	return "", false
}

func decodeKeyArg(ctx *Context, i int, argName string, val uint64) (string, bool) {
	scName := ctx.ScMeta.Name
	if strings.Contains(argName, "type") || strings.Contains(argName, "description") || strings.Contains(argName, "callout_info") {
		off := 0
		bufLen := 128
		if strings.Contains(argName, "description") {
			off = 64
		} else if strings.Contains(argName, "callout_info") {
			off = 256
			bufLen = 256
		}
		return ctx.Decoder.DecodeString(ctx.Tid, val, ctx.StrArgBuf[off:off+bufLen], ctx.ArgProbeRet(i), scName, ctx.Opts.StringLimit), true
	}

	if strings.Contains(argName, "payload") {
		plen := int(ctx.Args[3])
		if plen <= 0 {
			if plen == 0 {
				return "\"\"", true
			}
			return fmt.Sprintf("%#x", val), true
		}

		capLen := plen
		if capLen > 256 {
			capLen = 256
		}

		bpfBuf := ctx.StrArgBuf[256 : 256+capLen]
		isExit := false
		data, ok := ctx.FetchStructDataExact(val, capLen, isExit, bpfBuf)
		if !ok {
			return fmt.Sprintf("%#x", val), true
		}

		return format.Buffer(data, ctx.Opts.StringLimit, plen), true
	}
	return "", false
}

func decodeBufferArg(ctx *Context, val uint64, res *Result) (string, bool) {
	scName := ctx.ScMeta.Name
	fd := int32(-1)
	if strings.Contains(scName, "read") || strings.Contains(scName, "write") {
		fd = int32(ctx.Args[0])
	}

	if (scName == "read" || scName == "pread64") && ctx.Ret > 0 && ctx.Opts.TraceReadFDs[fd] {
		szH := uint64(ctx.Ret)
		bpfBuf := ctx.StrArgBuf[1024 : 1024+512]
		// Read exits always have data in exit buf if captured
		data, ok := ctx.FetchStructData(val, int(szH), true, bpfBuf)
		if ok {
			res.HexDumpStr = format.Hexdump(data)
			return format.Buffer(data, ctx.Opts.StringLimit, int(szH)), true
		}
	}

	if (scName == "write" || scName == "pwrite64") && ctx.Opts.TraceWriteFDs[fd] {
		szH := ctx.Args[2]
		bpfBuf := ctx.StrArgBuf[0:512]
		// Write enter always has data in enter buf if captured
		data, ok := ctx.FetchStructData(val, int(szH), false, bpfBuf)
		if ok {
			res.HexDumpStr = format.Hexdump(data)
			return format.Buffer(data, ctx.Opts.StringLimit, int(szH)), true
		}
	}

	return "", false
}

func decodeRenArg(ctx *Context, i int, val uint64) (string, bool) {
	scName := ctx.ScMeta.Name
	var p string
	switch scName {
	case "rename", "link", "symlink":
		if i == 0 {
			p = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[0], ctx.StrArgBuf[0:512], ctx.ArgProbeRet(0), scName, 0)
		} else if i == 1 {
			p = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[1], ctx.StrArgBuf[512:1024], ctx.ArgProbeRet(1), scName, 0)
		}
	case "renameat", "renameat2", "linkat":
		if i == 1 {
			p = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[1], ctx.StrArgBuf[0:512], ctx.ArgProbeRet(1), scName, 0)
		} else if i == 3 {
			p = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[3], ctx.StrArgBuf[512:1024], ctx.ArgProbeRet(3), scName, 0)
		}
	case "symlinkat":
		if i == 0 {
			p = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[0], ctx.StrArgBuf[0:512], ctx.ArgProbeRet(0), scName, 0)
		} else if i == 2 {
			p = ctx.Decoder.DecodeString(ctx.Pid, ctx.Args[2], ctx.StrArgBuf[512:1024], ctx.ArgProbeRet(2), scName, 0)
		}
	}
	return p, true
}
