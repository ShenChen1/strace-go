package handler

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"

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
	if ctx.ScMeta.Name == "execve" || ctx.ScMeta.Name == "execveat" {
		if decoded, ok := decodeExecStringArraySnapshot(ctx, val, argName); ok {
			return decoded, true
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

	if isXattrSyscall(scName) {
		if p, ok := decodeXattrArg(ctx, i, argTyp, argName, val); ok {
			return p, true
		}
	}

	if isReadWriteBufferSyscall(scName) {
		if p, ok := decodeBufferArg(ctx, val, res); ok {
			return p, true
		}
		return fmt.Sprintf("%#x", val), true
	}

	if scName == "readlink" || scName == "readlinkat" || scName == "getcwd" {
		if p, ok := decodeReadlinkBuffer(ctx, i, val); ok {
			return p, true
		}
	}

	isRen := scName == "rename" || scName == "renameat" || scName == "renameat2" || scName == "link" || scName == "linkat" || scName == "symlink" || scName == "symlinkat"
	if isRen {
		if p, ok := decodeRenArg(ctx, i, val); ok {
			return p, true
		}
	}

	isPath := argName == "filename" || argName == "pathname" || argName == "path" || argName == "oldname" || argName == "newname" || argName == "oldpath" || argName == "newpath" || (scName == "getcwd" && argName == "buf")
	if isPath && shouldShowFaultingTimePathPointer(ctx, val) {
		return fmt.Sprintf("%#x", val), true
	}
	if isPath {
		if p, ok := ctx.PayloadString(i, PayloadDirectionIn, val, 0); ok {
			return p, true
		}
	}
	if isPath && val == ctx.Ptr && ctx.RawStrArg != "" && !strings.HasPrefix(ctx.RawStrArg, "0x") {
		return ctx.RawStrArg, true
	}

	if scName == "memfd_create" && i == 0 {
		if p, ok := ctx.PayloadString(i, PayloadDirectionIn, val, 250); ok {
			return p, true
		}
	}

	limit := ctx.Opts.StringLimit
	if argTyp == "void *" || argTyp == "const void *" {
		return fmt.Sprintf("%#x", val), true
	}
	capSize := 512
	if isPath {
		limit = 0
		capSize = 4097
	} else if scName == "memfd_create" && i == 0 {
		limit = 250
		capSize = 250
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

func decodeReadlinkBuffer(ctx *Context, i int, val uint64) (string, bool) {
	bufIdx := 1
	if ctx.ScMeta.Name == "readlinkat" {
		bufIdx = 2
	} else if ctx.ScMeta.Name == "getcwd" {
		bufIdx = 0
	}
	if i != bufIdx {
		return "", false
	}
	if ctx.Ret < 0 {
		return fmt.Sprintf("%#x", val), true
	}
	if ctx.Ret == 0 {
		return `""`, true
	}
	data, ok := ctx.PayloadBytes(bufIdx, PayloadDirectionOut)
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	sz := int(ctx.Ret)
	if sz > len(data) {
		sz = len(data)
	}
	if sz < 0 {
		sz = 0
	}
	if idx := bytes.IndexByte(data[:sz], 0); idx != -1 {
		sz = idx
	}
	return format.BufferEscape(data[:sz], 0, sz, ctx.Decoder.HexEscapeMode), true
}

func decodeXattrArg(ctx *Context, i int, argTyp string, argName string, val uint64) (string, bool) {
	if isXattrPathArg(ctx.ScMeta.Name, argName) || isXattrNameArg(ctx.ScMeta.Name, argName) {
		if val == 0 {
			return "NULL", true
		}
		if p, ok := ctx.PayloadString(i, PayloadDirectionIn, val, ctx.Opts.StringLimit); ok {
			return p, true
		}
		return fmt.Sprintf("%#x", val), true
	}
	return decodeXattrValueArg(ctx, i, argTyp, argName, val, ctx.Opts.StringLimit)
}

func decodeXattrValueArg(ctx *Context, i int, argTyp string, argName string, val uint64, limit int) (string, bool) {
	scName := ctx.ScMeta.Name
	if argTyp != "void *" && argTyp != "const void *" && !strings.HasSuffix(scName, "listxattr") {
		return "", false
	}
	isSetxattr := strings.HasSuffix(scName, "setxattr")
	isGetxattr := strings.HasSuffix(scName, "getxattr")
	isListxattr := strings.HasSuffix(scName, "listxattr")
	if !(isSetxattr || isGetxattr || isListxattr) || (argName != "value" && argName != "list") {
		return "", false
	}
	size, ok := xattrValueSize(ctx, isGetxattr, isListxattr)
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	if val == 0 {
		return "NULL", true
	}
	if size == 0 {
		return `""`, true
	}
	if size > 65536 {
		return fmt.Sprintf("%#x", val), true
	}
	return formatXattrSnapshot(ctx, i, val, size, limit, isGetxattr, isListxattr), true
}

func xattrValueSize(ctx *Context, isGetxattr bool, isListxattr bool) (uint64, bool) {
	size := ctx.Args[3]
	if isListxattr {
		size = ctx.Args[2]
	}
	if !isGetxattr && !isListxattr {
		return size, true
	}
	if size == 0 {
		return size, false
	}
	if ctx.Ret < 0 {
		return 0, false
	}
	return uint64(ctx.Ret), true
}

func formatXattrSnapshot(ctx *Context, argIndex int, val uint64, size uint64, limit int, isGetxattr bool, isListxattr bool) string {
	fetchSize := int(size)
	if limit > 0 && fetchSize > limit {
		fetchSize = limit
	}
	data, ok := xattrPayloadBytes(ctx, argIndex, isGetxattr, isListxattr)
	if !ok || len(data) == 0 || len(data) < fetchSize {
		return fmt.Sprintf("%#x", val)
	}
	sz := int(size)
	if sz > len(data) {
		sz = len(data)
	}
	if !isListxattr && sz == int(size) && sz > 0 && data[sz-1] == 0 {
		sz--
		size--
	}
	res := format.BufferEscape(data[:sz], limit, int(size), ctx.Decoder.HexEscapeMode)
	if len(data) < int(size) && int(size) <= limit {
		res += "..."
	}
	return res
}

func isXattrSyscall(scName string) bool {
	return strings.HasSuffix(scName, "setxattr") ||
		strings.HasSuffix(scName, "getxattr") ||
		strings.HasSuffix(scName, "listxattr") ||
		strings.HasSuffix(scName, "removexattr")
}

func isXattrPathArg(scName string, argName string) bool {
	if strings.HasPrefix(scName, "f") {
		return false
	}
	return argName == "path" || argName == "pathname" || argName == "filename"
}

func isXattrNameArg(scName string, argName string) bool {
	if argName != "name" {
		return false
	}
	return strings.HasSuffix(scName, "setxattr") ||
		strings.HasSuffix(scName, "getxattr") ||
		strings.HasSuffix(scName, "removexattr")
}

func xattrPayloadBytes(ctx *Context, argIndex int, isGetxattr bool, isListxattr bool) ([]byte, bool) {
	direction := PayloadDirectionIn
	if isGetxattr || isListxattr {
		direction = PayloadDirectionOut
	}
	return ctx.PayloadBytes(argIndex, direction)
}

func shouldShowFaultingTimePathPointer(ctx *Context, val uint64) bool {
	if ctx.Ret != -int64(syscall.EFAULT) {
		return false
	}
	switch ctx.ScMeta.Name {
	case "utime":
	case "utimes":
		if ctx.Args[1] != 0 {
			return false
		}
	case "utimensat", "futimesat":
		if ctx.Args[2] != 0 {
			return false
		}
	default:
		return false
	}
	if val == 0 {
		return false
	}
	pageSize := uint64(os.Getpagesize())
	if val%pageSize < pageSize-64 {
		return false
	}
	return true
}

func decodeKeyArg(ctx *Context, i int, argName string, val uint64) (string, bool) {
	scName := ctx.ScMeta.Name
	if strings.Contains(argName, "type") || strings.Contains(argName, "description") || strings.Contains(argName, "callout_info") {
		if text, ok := ctx.PayloadString(i, PayloadDirectionIn, val, ctx.Opts.StringLimit); ok {
			return text, true
		}
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

		data, ok := ctx.PayloadBytes(i, PayloadDirectionIn)
		if ok && len(data) > capLen {
			data = data[:capLen]
		}
		if !ok {
			data, ok = ctx.EnterArgSnapshot(i, 256, capLen)
		}
		if !ok || len(data) == 0 {
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

	if (scName == "read" || scName == "pread64") && ctx.Ret >= 0 {
		szH := uint64(ctx.Ret)
		if szH == 0 {
			return `""`, true
		}
		data, ok := ctx.PayloadBytes(1, PayloadDirectionOut)
		if ok {
			if ctx.Opts.TraceReadFDs[fd] {
				res.HexDumpStr = format.Hexdump(data, int(szH))
				if len(data) < int(szH) {
					miss := int(szH) - len(data)
					byteStr := "bytes"
					if miss == 1 {
						byteStr = "byte"
					}
					res.HexDumpStr += fmt.Sprintf(" | <Cannot fetch %d %s from pid %d @0x%x>\n", miss, byteStr, ctx.Tid, val+uint64(len(data)))
				}
			}
			return format.Buffer(data, ctx.Opts.StringLimit, int(szH)), true
		}
	}

	if scName == "write" || scName == "pwrite64" {
		szH := ctx.Args[2]
		if szH == 0 {
			return `""`, true
		}
		data, ok := ctx.PayloadBytes(1, PayloadDirectionIn)
		if ok {
			if ctx.Opts.TraceWriteFDs[fd] {
				if fileData, fileOK := ctx.FetchWrittenFileData(fd, int(szH), data); fileOK {
					data = fileData
				}
				res.HexDumpStr = format.Hexdump(data, int(szH))
				if len(data) < int(szH) {
					miss := int(szH) - len(data)
					byteStr := "bytes"
					if miss == 1 {
						byteStr = "byte"
					}
					res.HexDumpStr += fmt.Sprintf(" | <Cannot fetch %d %s from pid %d @0x%x>\n", miss, byteStr, ctx.Tid, val+uint64(len(data)))
				}
			}
			return format.Buffer(data, ctx.Opts.StringLimit, int(szH)), true
		}
	}

	return "", false
}

func isReadWriteBufferSyscall(scName string) bool {
	switch scName {
	case "read", "pread64", "write", "pwrite64":
		return true
	default:
		return false
	}
}

func decodeRenArg(ctx *Context, i int, val uint64) (string, bool) {
	if p, ok := ctx.PayloadString(i, PayloadDirectionIn, val, 0); ok {
		return p, true
	}
	scName := ctx.ScMeta.Name
	switch scName {
	case "rename", "link", "symlink":
		if i == 0 {
			return decodeRenArgSnapshot(ctx, val, 0, 0)
		}
		if i == 1 {
			return decodeRenArgSnapshot(ctx, val, 1, 512)
		}
	case "renameat", "renameat2", "linkat":
		if i == 1 {
			return decodeRenArgSnapshot(ctx, val, 1, 0)
		}
		if i == 3 {
			return decodeRenArgSnapshot(ctx, val, 3, 512)
		}
	case "symlinkat":
		if i == 0 {
			return decodeRenArgSnapshot(ctx, val, 0, 0)
		}
		if i == 2 {
			return decodeRenArgSnapshot(ctx, val, 2, 512)
		}
	}
	return "", false
}

func decodeRenArgSnapshot(ctx *Context, val uint64, argIndex int, offset int) (string, bool) {
	data, ok := ctx.EnterArgSnapshotPrefix(argIndex, offset, 512)
	if !ok {
		return fmt.Sprintf("%#x", val), true
	}
	return ctx.Decoder.DecodeString(ctx.Pid, val, data, ctx.ArgProbeRet(argIndex), ctx.ScMeta.Name, 0), true
}
