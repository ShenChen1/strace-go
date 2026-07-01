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

	if strings.Contains(scName, "read") || strings.Contains(scName, "write") {
		if p, ok := decodeBufferArg(ctx, val, res); ok {
			return p, true
		}
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

	limit := ctx.Opts.StringLimit
	if p, ok := decodeXattrValueArg(ctx, i, argTyp, argName, val, limit); ok {
		return p, true
	}
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
	if strings.HasSuffix(scName, "setxattr") || strings.HasSuffix(scName, "getxattr") || strings.HasSuffix(scName, "removexattr") {
		if !strings.HasPrefix(scName, "f") && argName == "name" {
			bpfBuf = ctx.StrArgBuf[512:768]
		}
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
	readSize := boundedSnapshotSize(int(ctx.Ret), 512)
	if readSize == 0 {
		return `""`, true
	}
	data, ok := ctx.PayloadBytes(bufIdx, PayloadDirectionOut)
	if !ok {
		data, ok = ctx.ExitSnapshot(BpfExitArgOffset, readSize)
	}
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
	offset, captureArg := xattrSnapshotOffset(ctx.ScMeta.Name, argIndex)
	readSize := boundedSnapshotSize(fetchSize, 256)
	var data []byte
	var ok bool
	if isGetxattr || isListxattr {
		data, ok = ctx.ExitSnapshot(offset, readSize)
	} else {
		data, ok = ctx.EnterArgSnapshot(captureArg, offset, readSize)
	}
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

func xattrSnapshotOffset(scName string, fallbackArg int) (int, int) {
	switch scName {
	case "fsetxattr", "fgetxattr":
		return 256, 2
	case "listxattr", "llistxattr":
		return 512, 1
	case "flistxattr":
		return 0, 1
	default:
		return 768, fallbackArg
	}
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
		readSize := boundedSnapshotSize(int(szH), 512)
		data, ok := ctx.PayloadBytes(1, PayloadDirectionOut)
		if !ok {
			data, ok = ctx.ExitSnapshot(BpfExitArgOffset, readSize)
		}
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
		readSize := boundedSnapshotSize(int(szH), 512)
		data, ok := ctx.PayloadBytes(1, PayloadDirectionIn)
		if !ok {
			data, ok = ctx.EnterArgSnapshot(1, BpfEnterArgOffset, readSize)
		}
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

func boundedSnapshotSize(requested int, maxSize int) int {
	if requested <= 0 || maxSize <= 0 {
		return 0
	}
	if requested > maxSize {
		return maxSize
	}
	return requested
}

func (ctx *Context) FetchWrittenFileData(fd int32, requestedSize int, current []byte) ([]byte, bool) {
	if ctx.Ret <= 0 || !ctx.BufferFileOffsetOK {
		return nil, false
	}
	readSize := requestedSize
	if ctx.Ret < int64(readSize) {
		readSize = int(ctx.Ret)
	}
	if readSize <= len(current) {
		return nil, false
	}

	out := make([]byte, readSize)
	if f := ctx.fdDataFile(fd); f != nil {
		n, _ := f.ReadAt(out, ctx.BufferFileOffset)
		if n > len(current) {
			return out[:n], true
		}
	}
	if path, ok := ctx.fdDataPath(fd); ok {
		f, err := os.Open(path)
		if err == nil {
			defer f.Close()
			n, _ := f.ReadAt(out, ctx.BufferFileOffset)
			if n > len(current) {
				return out[:n], true
			}
		}
	}
	return nil, false
}

func (ctx *Context) fdDataFile(fd int32) *os.File {
	if ctx.FdFiles == nil {
		return nil
	}
	return ctx.FdFiles[fmt.Sprintf("%d:%d", ctx.TargetPid, fd)]
}

func (ctx *Context) fdDataPath(fd int32) (string, bool) {
	if ctx.FdMap == nil {
		return "", false
	}
	target := ctx.FdMap[fmt.Sprintf("%d:%d", ctx.TargetPid, fd)]
	if target == "" {
		return "", false
	}
	target = strings.SplitN(target, "|", 2)[0]
	if strings.HasPrefix(target, `"`) && strings.HasSuffix(target, `"`) {
		target = target[1 : len(target)-1]
	}
	switch {
	case strings.HasPrefix(target, "socket:"),
		strings.HasPrefix(target, "socket:["),
		strings.HasPrefix(target, "pipe:"),
		strings.HasPrefix(target, "pipe:["),
		strings.HasPrefix(target, "anon_inode:"),
		strings.HasPrefix(target, "{"),
		strings.HasPrefix(target, "NETLINK:"):
		return "", false
	}
	if !strings.HasPrefix(target, "/") {
		target = CleanPath(ctx.FdMap[fmt.Sprintf("%d:cwd", ctx.TargetPid)], target)
	}
	return target, true
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
