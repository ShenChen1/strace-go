package handler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
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

func decodeStringArray(ctx *Context, val uint64, argName string) string {
	if val == 0 {
		return "NULL"
	}
	ptrSize := 8
	if os.Getenv("SIZEOF_LONG") == "4" {
		ptrSize = 4
	}

	var ptrs []uint64
	terminated := false
	abbreviated := false
	var nextAddr uint64
	maxCount := 4096
	for i := 0; i < maxCount; i++ {
		addr := val + uint64(i*ptrSize)
		data, err := ctx.MemReader.ReadRobust(ctx.Pid, addr, ptrSize, false)
		if err != nil || len(data) < ptrSize {
			if i == 0 {
				return fmt.Sprintf("%#x", val)
			}
			nextAddr = addr
			break
		}
		var ptr uint64
		if ptrSize == 4 {
			ptr = uint64(binary.LittleEndian.Uint32(data))
		} else {
			ptr = binary.LittleEndian.Uint64(data)
		}
		if ptr == 0 {
			terminated = true
			break
		}
		if argName != "envp" && len(ptrs) == 32 {
			abbreviated = true
			break
		}
		ptrs = append(ptrs, ptr)
	}

	if argName == "envp" {
		noun := "vars"
		if len(ptrs) == 1 {
			noun = "var"
		}
		if !terminated {
			return fmt.Sprintf("%#x /* %d %s, unterminated */", val, len(ptrs), noun)
		}
		return fmt.Sprintf("%#x /* %d %s */", val, len(ptrs), noun)
	}

	var res []string
	for _, ptr := range ptrs {
		s := ctx.Decoder.DecodeString(ctx.Pid, ptr, nil, -1, ctx.ScMeta.Name, ctx.Opts.StringLimit)
		res = append(res, s)
	}

	retStr := "[" + strings.Join(res, ", ")
	if !terminated {
		if len(res) > 0 {
			retStr += ", "
		}
		if abbreviated {
			retStr += "..."
		} else {
			retStr += fmt.Sprintf("... /* %#x */", nextAddr)
		}
	}
	retStr += "]"
	return retStr
}

func decodeExecStringArraySnapshot(ctx *Context, val uint64, argName string) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	if len(ctx.StrArgBuf) < execSnapshotOffset+execSnapshotHeaderSize {
		return "", false
	}

	header := ctx.StrArgBuf[execSnapshotOffset:]
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
			envOffset := execSnapshotOffset + execSnapshotHeaderSize + execArgSnapshotCount*execArgSnapshotSize
			return decodeExecSnapshotRecords(ctx, envOffset, envCount, envStatus, envNext, execEnvSnapshotCount)
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
	argvOffset := execSnapshotOffset + execSnapshotHeaderSize
	return decodeExecSnapshotRecords(ctx, argvOffset, argvCount, argvStatus, argvNext, execArgSnapshotCount)
}

func decodeExecSnapshotRecords(ctx *Context, baseOffset, count int, status int32, next uint64, maxCount int) (string, bool) {
	if count < 0 || count > maxCount {
		return "", false
	}
	required := baseOffset + count*execArgSnapshotSize
	if len(ctx.StrArgBuf) < required {
		return "", false
	}

	limit := ctx.Opts.StringLimit
	var parts []string
	for i := 0; i < count; i++ {
		offset := baseOffset + i*execArgSnapshotSize
		record := ctx.StrArgBuf[offset : offset+execArgSnapshotSize]
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
