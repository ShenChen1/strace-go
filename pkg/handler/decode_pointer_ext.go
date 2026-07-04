package handler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
)

const (
	execSnapshotMagic      = 0x45584543
	execSnapshotOffset     = 4096
	execSnapshotHeaderSize = 32
	execArgSnapshotSize    = 56
	execArgDataOffset      = 12
	execArgDataSize        = 42
	execArgSnapshotCount   = 48
	execArgDisplayCount    = 32
	execEnvSnapshotCount   = 64
)

func decodeStringArray(_ *Context, val uint64, _ string) string {
	if val == 0 {
		return "NULL"
	}
	return fmt.Sprintf("%#x", val)
}

func decodeExecStringArraySnapshot(ctx *Context, val uint64, argName string) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	snapshot, ok := execSnapshotData(ctx)
	if !ok || len(snapshot) < execSnapshotHeaderSize {
		return "", false
	}

	header := snapshot
	if binary.LittleEndian.Uint32(header[0:4]) != execSnapshotMagic {
		return "", false
	}

	argvCount := int(binary.LittleEndian.Uint16(header[4:6]))
	envCount := int(binary.LittleEndian.Uint16(header[6:8]))
	argvStatus := int32(binary.LittleEndian.Uint32(header[8:12]))
	envStatus := int32(binary.LittleEndian.Uint32(header[12:16]))
	argvNext := binary.LittleEndian.Uint64(header[16:24])
	envNext := binary.LittleEndian.Uint64(header[24:32])

	if argName == "envp" {
		if envStatus == -1 && envCount == 0 {
			return fmt.Sprintf("%#x", val), true
		}
		if ctx.Opts.Verbose {
			envOffset := execSnapshotHeaderSize + execArgSnapshotCount*execArgSnapshotSize
			return decodeExecSnapshotRecords(ctx, snapshot, envOffset, envCount, envStatus, envNext, execEnvSnapshotCount)
		}
		noun := "vars"
		if envCount == 1 {
			noun = "var"
		}
		switch envStatus {
		case 0:
			return fmt.Sprintf("%#x /* %d %s */", val, envCount, noun), true
		case -1:
			return fmt.Sprintf("%#x /* %d %s, unterminated */", val, envCount, noun), true
		default:
			return fmt.Sprintf("%#x /* %d+ %s */", val, envCount, noun), true
		}
	}

	if argvCount < 0 || argvCount > execArgSnapshotCount {
		return "", false
	}
	if argvStatus == -1 && argvCount == 0 {
		return fmt.Sprintf("%#x", val), true
	}
	if !ctx.Opts.Verbose && argvCount > execArgDisplayCount {
		argvCount = execArgDisplayCount
		argvStatus = 1
	}
	return decodeExecSnapshotRecords(ctx, snapshot, execSnapshotHeaderSize, argvCount, argvStatus, argvNext, execArgSnapshotCount)
}

func execSnapshotData(ctx *Context) ([]byte, bool) {
	argvIndex, ok := execSnapshotArgIndex(ctx)
	if ok {
		if data, ok := ctx.PayloadExecArgs(argvIndex); ok {
			return data, true
		}
	}
	return nil, false
}

func execSnapshotArgIndex(ctx *Context) (int, bool) {
	switch ctx.ScMeta.Name {
	case "execve":
		return 1, true
	case "execveat":
		return 2, true
	default:
		return 0, false
	}
}

func decodeExecSnapshotRecords(ctx *Context, snapshot []byte, baseOffset, count int, status int32, next uint64, maxCount int) (string, bool) {
	if count < 0 || count > maxCount {
		return "", false
	}
	required := baseOffset + count*execArgSnapshotSize
	if len(snapshot) < required {
		return "", false
	}

	limit := ctx.Opts.StringLimit
	var parts []string
	for i := 0; i < count; i++ {
		offset := baseOffset + i*execArgSnapshotSize
		record := snapshot[offset : offset+execArgSnapshotSize]
		ptr := binary.LittleEndian.Uint64(record[0:8])
		readLen := int32(binary.LittleEndian.Uint32(record[8:12]))
		if readLen <= 0 {
			parts = append(parts, fmt.Sprintf("%#x", ptr))
			continue
		}

		data := record[execArgDataOffset : execArgDataOffset+execArgDataSize]
		rawLen := int(readLen)
		if rawLen > len(data) {
			rawLen = len(data)
		}
		raw := data[:rawLen]
		if nul := bytes.IndexByte(raw, 0); nul >= 0 {
			raw = raw[:nul]
		}
		actualLen := len(raw)
		if int(readLen) == execArgDataSize && len(raw) == execArgDataSize-1 {
			actualLen = execArgDataSize
		}
		parts = append(parts, format.BufferEscape(raw, limit, actualLen, ctx.Decoder.HexEscapeMode))
	}

	result := "[" + strings.Join(parts, ", ")
	if status != 0 {
		if len(parts) > 0 {
			result += ", "
		}
		if status == 1 {
			result += "..."
		} else {
			result += fmt.Sprintf("... /* %#x */", next)
		}
	}
	return result + "]", true
}
