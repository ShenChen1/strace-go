package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
)

func init() {
	Register("io_setup", &AioHandler{})
	Register("io_destroy", &AioHandler{})
	Register("io_submit", &AioHandler{})
	Register("io_cancel", &AioHandler{})
	Register("io_getevents", &AioHandler{})
	Register("io_pgetevents", &AioHandler{})
	Register("io_pgetevents_time64", &AioHandler{})
}

type AioHandler struct{}

const (
	// AioSubmitIocbPayloadArgBase identifies synthetic payload sections for io_submit iocb entries.
	AioSubmitIocbPayloadArgBase = 20
	// AioSubmitIovecPayloadArgBase identifies synthetic iovec array sections for PREADV/PWRITEV iocbs.
	AioSubmitIovecPayloadArgBase = 40
	// AioSubmitBufPayloadArgBase identifies synthetic data buffer sections for PWRITE iocbs.
	AioSubmitBufPayloadArgBase = 60

	aioIocbSize       = 64
	aioSetupOutSize   = 8
	aioEventsElemSize = 32
	aioSnapshotLimit  = 512
)

func aioAllBytesZero(data []byte) bool {
	for _, x := range data {
		if x != 0 {
			return false
		}
	}
	return true
}

func (h *AioHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "io_setup":
		h.formatIoSetup(ctx, &res)
	case "io_destroy":
		h.formatIoDestroy(ctx, &res)
	case "io_submit":
		h.formatIoSubmit(ctx, &res)
	case "io_cancel":
		h.formatIoCancel(ctx, &res)
	case "io_getevents", "io_pgetevents", "io_pgetevents_time64":
		h.formatIoGetevents(ctx, &res)
	}
	return res
}

func (h *AioHandler) formatIoSetup(ctx *Context, res *Result) {
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", uint32(ctx.Args[0])))
	if ctx.Args[1] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else if ctx.Ret >= 0 {
		data, ok := aioStructSnapshot(ctx, 1, PayloadDirectionOut, aioSetupOutSize)
		if ok {
			res.ArgParts = append(res.ArgParts, "["+fmt.Sprintf("%#x", binary.LittleEndian.Uint64(data))+"]")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
		}
	} else {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
	}
}

func (h *AioHandler) formatIoDestroy(ctx *Context, res *Result) {
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
}

func (h *AioHandler) formatIoSubmit(ctx *Context, res *Result) {
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int64(ctx.Args[1])))
	count := int(ctx.Args[1])
	if ctx.Args[2] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
		return
	}
	if count <= 0 {
		if count == 0 {
			res.ArgParts = append(res.ArgParts, "[]")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
		}
		return
	}

	pdata, ok := aioSubmitPointerArraySnapshot(ctx, count)
	if !ok {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
		return
	}

	var parts []string
	var i int
	limit := 16
	for i = 0; i < count && i < limit; i++ {
		if len(pdata) < (i+1)*8 {
			break
		}
		p := binary.LittleEndian.Uint64(pdata[i*8 : i*8+8])
		if p == 0 {
			parts = append(parts, "NULL")
			continue
		}

		if idata, ok := aioIocbSnapshot(ctx, i); ok {
			index := i
			parts = append(parts, format.Iocb(idata, ctx.Opts.Verbose, func(opcode uint16, buf uint64, nbytes uint64) string {
				return h.formatAioBuf(ctx, index, opcode, buf, nbytes)
			}))
		} else {
			parts = append(parts, fmt.Sprintf("%#x", p))
		}
	}
	if count > i {
		parts = append(parts, "...")
		parts[len(parts)-1] += fmt.Sprintf(" /* %#x */", ctx.Args[2]+uint64(i*8))
	}
	res.ArgParts = append(res.ArgParts, "["+strings.Join(parts, ", ")+"]")
}

func aioBoundedSize(count int, elemSize int) int {
	if count <= 0 || elemSize <= 0 {
		return 0
	}
	size := count * elemSize
	if size < 0 || size > aioSnapshotLimit {
		return aioSnapshotLimit
	}
	return size
}

func aioSubmitPointerArraySnapshot(ctx *Context, count int) ([]byte, bool) {
	readSize := aioBoundedSize(count, 8)
	if readSize == 0 {
		return nil, false
	}
	data, ok := ctx.PayloadStruct(2, PayloadDirectionIn)
	if !ok {
		return nil, false
	}
	if len(data) > readSize {
		data = data[:readSize]
	}
	usableLen := len(data) - len(data)%8
	if usableLen == 0 {
		return nil, false
	}
	return data[:usableLen], true
}

func aioIocbSnapshot(ctx *Context, index int) ([]byte, bool) {
	if index < 0 || index >= 6 {
		return nil, false
	}
	if data, ok := ctx.PayloadStruct(AioSubmitIocbPayloadArgBase+index, PayloadDirectionIn); ok && !aioAllBytesZero(data) {
		return data, true
	}
	return nil, false
}

func (h *AioHandler) formatAioBuf(ctx *Context, iocbIndex int, opcode uint16, buf uint64, nbytes uint64) string {
	if buf == 0 {
		if opcode == 7 || opcode == 8 {
			return "NULL"
		} else {
			return "0"
		}
	}
	if opcode == 7 || opcode == 8 {
		if data, ok := ctx.PayloadIovec(AioSubmitIovecPayloadArgBase+iocbIndex, PayloadDirectionIn); ok {
			return format.IovecArray(data, int(nbytes))
		}
	}
	if opcode == 1 && iocbIndex >= 0 {
		if data, ok := ctx.PayloadBytes(AioSubmitBufPayloadArgBase+iocbIndex, PayloadDirectionIn); ok && len(data) > 0 {
			return format.BufferEscape(data, len(data), int(nbytes)+1, ctx.Decoder.HexEscapeMode)
		}
	}
	return fmt.Sprintf("%#x", buf)
}

func (h *AioHandler) formatIoCancel(ctx *Context, res *Result) {
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
	if ctx.Args[1] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		if data, ok := aioStructSnapshot(ctx, 1, PayloadDirectionIn, aioIocbSize); ok {
			res.ArgParts = append(res.ArgParts, format.Iocb(data, ctx.Opts.Verbose, func(opcode uint16, buf uint64, nbytes uint64) string {
				return h.formatAioBuf(ctx, -1, opcode, buf, nbytes)
			}))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[1]))
		}
	}
	if ctx.Args[2] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[2]))
	}
}

func (h *AioHandler) formatIoGetevents(ctx *Context, res *Result) {
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[0]))
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int64(ctx.Args[1])))
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int64(ctx.Args[2])))

	h.formatIoEventsArg(ctx, res)
	h.formatIoGeteventsTimeout(ctx, res)
	if strings.Contains(ctx.SysName, "pgetevents") {
		h.formatIoPgeteventsSigset(ctx, res)
	}
}

func (h *AioHandler) formatIoEventsArg(ctx *Context, res *Result) {
	if ctx.Args[3] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else if ctx.Ret > 0 {
		count := int(ctx.Ret)
		readSize := aioBoundedSize(count, aioEventsElemSize)
		data, ok := aioStructSnapshot(ctx, 3, PayloadDirectionOut, readSize)
		if ok {
			res.ArgParts = append(res.ArgParts, format.IoEvents(data, count))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[3]))
		}
	} else {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[3]))
	}
}

func (h *AioHandler) formatIoGeteventsTimeout(ctx *Context, res *Result) {
	if ctx.Args[4] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
		return
	}

	data, ok := aioStructSnapshot(ctx, 4, PayloadDirectionIn, 16)
	if !ok {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[4]))
		return
	}
	if aioAllBytesZero(data) && ctx.Ret < 0 {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[4]))
		return
	}
	res.ArgParts = append(res.ArgParts, format.Timespec(data))
}

func (h *AioHandler) formatIoPgeteventsSigset(ctx *Context, res *Result) {
	if ctx.Args[5] == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
		return
	}

	d, ok := aioStructSnapshot(ctx, 5, PayloadDirectionIn, 16)
	if !ok {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[5]))
		return
	}
	if aioAllBytesZero(d) && ctx.Ret < 0 {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ctx.Args[5]))
		return
	}

	sigmask := binary.LittleEndian.Uint64(d[0:8])
	sigsetsize := binary.LittleEndian.Uint64(d[8:16])
	sigsetStr := fmt.Sprintf("%#x", sigmask)
	if sigsetsize <= 8 && sigsetsize > 0 {
		if maskData, ok := aioSigmaskSnapshot(ctx, int(sigsetsize)); ok {
			if s := format.Sigset(maskData); s != "" {
				sigsetStr = s
			}
		}
	}
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("{sigmask=%s, sigsetsize=%d}", sigsetStr, sigsetsize))
}

func aioStructSnapshot(ctx *Context, argIndex int, direction PayloadDirection, size int) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(argIndex, direction); ok && len(data) >= size {
		return data[:size], true
	}
	return nil, false
}

func aioSigmaskSnapshot(ctx *Context, size int) ([]byte, bool) {
	if data, ok := ctx.PayloadBytes(5, PayloadDirectionIn); ok && len(data) >= size {
		return data[:size], true
	}
	return nil, false
}
