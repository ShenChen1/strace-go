package handler

import (
	"encoding/binary"
	"fmt"
	"strace-go/pkg/format"
	"strace-go/pkg/meta"
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
	if ctx.SysName == "preadv" {
		return h.handlePreadv(ctx)
	}
	if ctx.SysName == "pwritev" {
		return h.handlePwritev(ctx)
	}
	if ctx.SysName == "preadv2" {
		return h.handlePreadv2(ctx)
	}
	if ctx.SysName == "pwritev2" {
		return h.handlePwritev2(ctx)
	}

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

	addIovecHexDump(ctx, &res, 1, ctx.Args[2])
	return res
}

func (h *IoHandler) handlePreadv(ctx *Context) Result {
	res := Result{ArgParts: []string{
		h.decodeScalar(ctx, "int", "fd", ctx.Args[0]),
		DecodeIovecArray(ctx, 1, ctx.Args[1], ctx.Args[2]),
		h.decodeScalar(ctx, "unsigned long", "vlen", ctx.Args[2]),
		fmt.Sprintf("%d", int64(ctx.Args[3])),
	}}
	addIovecHexDump(ctx, &res, 1, ctx.Args[2])
	return res
}

func (h *IoHandler) handlePwritev(ctx *Context) Result {
	res := Result{ArgParts: []string{
		h.decodeScalar(ctx, "int", "fd", ctx.Args[0]),
		DecodeIovecArray(ctx, 1, ctx.Args[1], ctx.Args[2]),
		h.decodeScalar(ctx, "unsigned long", "vlen", ctx.Args[2]),
		fmt.Sprintf("%d", int64(ctx.Args[3])),
	}}
	addIovecHexDump(ctx, &res, 1, ctx.Args[2])
	return res
}

func (h *IoHandler) handlePreadv2(ctx *Context) Result {
	return h.handlePositionedIovecV2(ctx)
}

func (h *IoHandler) handlePwritev2(ctx *Context) Result {
	return h.handlePositionedIovecV2(ctx)
}

func (h *IoHandler) handlePositionedIovecV2(ctx *Context) Result {
	res := Result{ArgParts: []string{
		h.decodeScalar(ctx, "int", "fd", ctx.Args[0]),
		DecodeIovecArray(ctx, 1, ctx.Args[1], ctx.Args[2]),
		h.decodeScalar(ctx, "unsigned long", "vlen", ctx.Args[2]),
		fmt.Sprintf("%d", int64(ctx.Args[3])),
		meta.DecodeFlags(ctx.Args[5], "rwf_flags"),
	}}
	addIovecHexDump(ctx, &res, 1, ctx.Args[2])
	return res
}

// IMPACT: iovec hexdump consumes only BPF-captured synthetic iov_base sections.
func addIovecHexDump(ctx *Context, res *Result, argIndex int, count uint64) {
	if ctx == nil || res == nil || ctx.Opts == nil || ctx.Ret <= 0 {
		return
	}
	direction, ok := iovecBasePayloadDirection(ctx, argIndex)
	if !ok || !shouldTraceIovecHexDump(ctx, direction) {
		return
	}
	entries := capturedIovecEntries(ctx, argIndex, count)
	remaining := ctx.Ret
	var b strings.Builder
	for _, entry := range entries {
		dumpLen := iovecOutDisplayLength(entry.length, &remaining)
		appendIovecEntryHexDump(ctx, &b, argIndex, direction, entry, dumpLen)
		if remaining <= 0 {
			break
		}
	}
	res.HexDumpStr = b.String()
}

const (
	iovecSize         = 16
	iovecDisplayLimit = 16

	iovecBasePayloadSlotLimit  = 7
	iovecBasePayloadArg1Base   = 120
	iovecBasePayloadArg3Base   = 140
	iovecBasePayloadArg151Base = 160
	iovecBasePayloadArg181Base = 180
	iovecBasePayloadArg211Base = 200
)

type iovecEntry struct {
	slot   int
	base   uint64
	length uint64
}

func DecodeIovecArray(ctx *Context, argIndex int, addr uint64, count uint64) string {
	if addr == 0 {
		return "NULL"
	}
	if count == 0 {
		return "[]"
	}

	displayLimit := iovecDisplayLimitForContext(ctx, argIndex)
	readCount := int(count)
	if readCount > displayLimit {
		readCount = displayLimit
	}

	readSize := readCount * iovecSize
	section, ok := iovecPayloadSection(ctx, argIndex, PayloadDirectionIn)
	if !ok || len(section.Data) == 0 {
		return fmt.Sprintf("%#x", addr)
	}
	data := section.Data

	actualCount := len(data) / iovecSize
	displayCount := actualCount
	if displayCount > readCount {
		displayCount = readCount
	}
	var parts []string
	remainingOut := iovecBasePayloadOutRemaining(ctx, argIndex)

	for i := 0; i < displayCount; i++ {
		base := binary.LittleEndian.Uint64(data[i*iovecSize : i*iovecSize+8])
		length := binary.LittleEndian.Uint64(data[i*iovecSize+8 : i*iovecSize+iovecSize])
		baseLength := length
		if remainingOut >= 0 {
			baseLength = iovecOutDisplayLength(length, &remainingOut)
		}
		baseText := formatIovecBase(ctx, argIndex, i, base, length, baseLength)
		parts = append(parts, fmt.Sprintf("{iov_base=%s, iov_len=%d}", baseText, length))
	}

	res := "[" + strings.Join(parts, ", ") + "]"
	if len(data) < readSize || displayCount < actualCount || int(count) > displayLimit {
		if len(parts) == 0 {
			return fmt.Sprintf("%#x", addr)
		}
		res = strings.TrimSuffix(res, "]") + iovecEllipsisSuffix(section, addr, count, displayCount, actualCount, displayLimit)
	}
	return res
}

func capturedIovecEntries(ctx *Context, argIndex int, count uint64) []iovecEntry {
	displayLimit := iovecDisplayLimitForContext(ctx, argIndex)
	readCount := int(count)
	if readCount > displayLimit {
		readCount = displayLimit
	}
	section, ok := iovecPayloadSection(ctx, argIndex, PayloadDirectionIn)
	if !ok || len(section.Data) == 0 {
		return nil
	}
	actualCount := len(section.Data) / iovecSize
	displayCount := actualCount
	if displayCount > readCount {
		displayCount = readCount
	}
	entries := make([]iovecEntry, 0, displayCount)
	for slot := 0; slot < displayCount; slot++ {
		off := slot * iovecSize
		entries = append(entries, iovecEntry{
			slot:   slot,
			base:   binary.LittleEndian.Uint64(section.Data[off : off+8]),
			length: binary.LittleEndian.Uint64(section.Data[off+8 : off+iovecSize]),
		})
	}
	return entries
}

func shouldTraceIovecHexDump(ctx *Context, direction PayloadDirection) bool {
	fd, ok := iovecHexDumpFD(ctx)
	if !ok {
		return false
	}
	switch direction {
	case PayloadDirectionIn:
		return ctx.Opts.TraceWriteFD(fd)
	case PayloadDirectionOut:
		return ctx.Opts.TraceReadFD(fd)
	default:
		return false
	}
}

func iovecHexDumpFD(ctx *Context) (int32, bool) {
	switch ctx.SysName {
	case "readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2", "vmsplice", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg":
		return int32(ctx.Args[0]), true
	default:
		return -1, false
	}
}

func appendIovecEntryHexDump(
	ctx *Context,
	b *strings.Builder,
	argIndex int,
	direction PayloadDirection,
	entry iovecEntry,
	dumpLen uint64,
) {
	if dumpLen == 0 || entry.base == 0 {
		return
	}
	section, ok := iovecBasePayloadSection(ctx, argIndex, entry.slot, entry.base, direction)
	if !ok {
		return
	}
	data := section.Data
	if uint64(len(data)) > dumpLen {
		data = data[:dumpLen]
	}
	fmt.Fprintf(b, " * %d bytes in buffer %d\n", dumpLen, entry.slot)
	b.WriteString(format.Hexdump(data, int(dumpLen)))
	appendIovecCannotFetch(ctx, b, entry.base, dumpLen, len(data))
}

func appendIovecCannotFetch(ctx *Context, b *strings.Builder, base uint64, dumpLen uint64, copied int) {
	if uint64(copied) >= dumpLen {
		return
	}
	miss := int(dumpLen) - copied
	byteStr := "bytes"
	if miss == 1 {
		byteStr = "byte"
	}
	fmt.Fprintf(b, " | <Cannot fetch %d %s from pid %d @0x%x>\n", miss, byteStr, ctx.Tid, base+uint64(copied))
}

func iovecPayloadSection(ctx *Context, argIndex int, direction PayloadDirection) (PayloadSection, bool) {
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex == argIndex && section.Kind == PayloadKindIovec &&
			section.Direction == direction && section.ProbeRet == 0 && len(section.Data) > 0 {
			return section, true
		}
	}
	return PayloadSection{}, false
}

func iovecDisplayLimitForContext(ctx *Context, argIndex int) int {
	limit := iovecDisplayLimit
	if ctx == nil || ctx.Opts == nil || ctx.Opts.StringLimit <= 0 {
		return limit
	}
	if ctx.Opts.StringLimit < limit {
		limit = ctx.Opts.StringLimit
	}
	if _, ok := iovecBasePayloadDirection(ctx, argIndex); ok && iovecBasePayloadSlotLimit < limit {
		limit = iovecBasePayloadSlotLimit
	}
	return limit
}

func iovecBasePayloadOutRemaining(ctx *Context, argIndex int) int64 {
	direction, ok := iovecBasePayloadDirection(ctx, argIndex)
	if !ok || direction != PayloadDirectionOut || ctx.Ret <= 0 {
		return -1
	}
	return ctx.Ret
}

func iovecOutDisplayLength(iovLen uint64, remaining *int64) uint64 {
	if remaining == nil || *remaining <= 0 {
		return 0
	}
	if uint64(*remaining) >= iovLen {
		*remaining -= int64(iovLen)
		return iovLen
	}
	outLen := uint64(*remaining)
	*remaining = 0
	return outLen
}

func iovecEllipsisSuffix(section PayloadSection, addr uint64, requestedCount uint64, displayCount int, actualCount int, displayLimit int) string {
	if section.CopiedLen < section.UserLen && (actualCount < displayLimit || requestedCount <= uint64(displayLimit+1)) {
		nextPtr := addr + uint64(displayCount*iovecSize)
		return fmt.Sprintf(", ... /* %#x */]", nextPtr)
	}
	return ", ...]"
}

func formatIovecBase(ctx *Context, argIndex int, slot int, base uint64, length uint64, displayLength uint64) string {
	if base == 0 {
		return "NULL"
	}
	if text, ok := iovecBasePayloadString(ctx, argIndex, slot, base, length, displayLength); ok {
		return text
	}
	return fmt.Sprintf("%#x", base)
}

func iovecBasePayloadString(ctx *Context, argIndex int, slot int, base uint64, length uint64, displayLength uint64) (string, bool) {
	direction, ok := iovecBasePayloadDirection(ctx, argIndex)
	if !ok {
		return "", false
	}
	if length == 0 || displayLength == 0 {
		return "\"\"", true
	}
	section, ok := iovecBasePayloadSection(ctx, argIndex, slot, base, direction)
	if !ok {
		return "", false
	}
	data := section.Data
	if uint64(len(data)) > displayLength {
		data = data[:displayLength]
	}
	limit := int(displayLength)
	if ctx.Opts != nil && ctx.Opts.StringLimit > 0 && limit > ctx.Opts.StringLimit {
		limit = ctx.Opts.StringLimit
	}
	actualLen := int(displayLength)
	return format.BufferEscape(data, limit, actualLen, ctx.Decoder.HexEscapeMode), true
}

func iovecBasePayloadDirection(ctx *Context, argIndex int) (PayloadDirection, bool) {
	if ctx == nil || (argIndex != 1 && argIndex != 151 && argIndex != 181 && argIndex != 211) {
		return "", false
	}
	switch ctx.SysName {
	case "writev", "pwritev", "pwritev2", "vmsplice", "process_vm_writev", "sendmsg", "sendmmsg":
		return PayloadDirectionIn, true
	case "readv", "preadv", "preadv2", "process_vm_readv", "recvmsg", "recvmmsg":
		return PayloadDirectionOut, true
	default:
		return "", false
	}
}

func iovecBasePayloadSection(ctx *Context, argIndex int, slot int, base uint64, direction PayloadDirection) (PayloadSection, bool) {
	payloadArg := iovecBasePayloadArgIndex(argIndex, slot)
	if payloadArg < 0 {
		return PayloadSection{}, false
	}
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex != payloadArg || section.Kind != PayloadKindBytes || section.Direction != direction {
			continue
		}
		if section.ProbeRet != 0 || len(section.Data) == 0 {
			continue
		}
		if section.UserPtr != 0 && section.UserPtr != base {
			continue
		}
		return section, true
	}
	return PayloadSection{}, false
}

func iovecBasePayloadArgIndex(argIndex int, slot int) int {
	if slot < 0 {
		return -1
	}
	switch argIndex {
	case 1:
		return iovecBasePayloadArg1Base + slot
	case 3:
		return iovecBasePayloadArg3Base + slot
	case 151:
		return iovecBasePayloadArg151Base + slot
	case 181:
		return iovecBasePayloadArg181Base + slot
	case 211:
		return iovecBasePayloadArg211Base + slot
	default:
		return -1
	}
}
