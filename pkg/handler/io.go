package handler

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func init() {
	h := &IoHandler{}
	Register("readv", h)
	Register("writev", h)
	Register("preadv", h)
	Register("pwritev", h)
	Register("preadv2", h)
	Register("pwritev2", h)
	Register("process_vm_readv", h)
	Register("process_vm_writev", h)
	Register("vmsplice", h)
}

type IoHandler struct {
	DefaultHandler
}

func (h *IoHandler) Handle(ctx *Context) Result {
	res := Result{}

	// Fallback to DefaultHandler for scalars, we only override iovec arrays
	argCount := len(ctx.ScMeta.ArgTypes)
	for i := 0; i < argCount; i++ {
		argTyp := ctx.ScMeta.ArgTypes[i]
		argName := ctx.ScMeta.Args[i]
		val := ctx.Args[i]

		if strings.Contains(argTyp, "struct iovec *") {
			// Find the corresponding count argument
			// For readv/writev/preadv/pwritev/preadv2/pwritev2, count is the next argument (iovcnt)
			// For process_vm_readv/process_vm_writev, count is the next argument (liovcnt/riovcnt)
			// For vmsplice, count is the next argument (nr_segs)
			countVal := uint64(0)
			if i+1 < argCount {
				countVal = ctx.Args[i+1]
			}

			res.ArgParts = append(res.ArgParts, DecodeIovecArray(ctx, i, val, countVal))
			continue
		}

		// If not iovec, use default logic
		if part, ok := h.decodeXlat(ctx, argName, val); ok {
			res.ArgParts = append(res.ArgParts, part)
			continue
		}

		if strings.Contains(argTyp, "*") {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}
			if part, ok := h.decodeStruct(ctx, i, argTyp, val); ok {
				res.ArgParts = append(res.ArgParts, part)
				continue
			}
			if part, ok := h.decodePointer(ctx, i, argTyp, argName, val, &res); ok {
				res.ArgParts = append(res.ArgParts, part)
				continue
			}
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
			continue
		}

		res.ArgParts = append(res.ArgParts, h.decodeScalar(ctx, argTyp, argName, val))
	}

	return res
}

const (
	iovecSize         = 16
	iovecDisplayLimit = 16
	iovecRemoteOffset = BpfMiscArgOffset
)

func DecodeIovecArray(ctx *Context, argIndex int, addr uint64, count uint64) string {
	if addr == 0 {
		return "NULL"
	}
	if count == 0 {
		return "[]"
	}

	readCount := int(count)
	if readCount > iovecDisplayLimit {
		readCount = iovecDisplayLimit
	}

	readSize := readCount * iovecSize
	offset := iovecSnapshotOffset(ctx.SysName, argIndex)
	data, ok := ctx.PayloadIovec(argIndex, PayloadDirectionIn)
	if !ok {
		data, ok = ctx.EnterArgSnapshotPrefix(argIndex, offset, readSize)
	}
	if !ok || len(data) == 0 {
		return fmt.Sprintf("%#x", addr)
	}

	actualCount := len(data) / iovecSize
	var parts []string

	for i := 0; i < actualCount; i++ {
		base := binary.LittleEndian.Uint64(data[i*iovecSize : i*iovecSize+8])
		length := binary.LittleEndian.Uint64(data[i*iovecSize+8 : i*iovecSize+iovecSize])
		parts = append(parts, fmt.Sprintf("{iov_base=%#x, iov_len=%d}", base, length))
	}

	res := "[" + strings.Join(parts, ", ") + "]"
	if len(data) < readSize || int(count) > iovecDisplayLimit {
		if len(parts) == 0 {
			return fmt.Sprintf("%#x", addr)
		}
		res = strings.TrimSuffix(res, "]") + ", ...]"
	}
	return res
}

func iovecSnapshotOffset(scName string, argIndex int) int {
	if (scName == "process_vm_readv" || scName == "process_vm_writev") && argIndex == 3 {
		return iovecRemoteOffset
	}
	return BpfEnterArgOffset
}
