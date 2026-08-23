package handler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	bpfLinkArrayReadLimit          = 16
	bpfLinkSymbolReadLimit         = 38
	bpfLinkStreamReadLimit         = 512
	bpfLinkIterInfoPayloadArg      = 107
	bpfLinkKprobeSymsPayloadArg    = 108
	bpfLinkKprobeAddrsPayloadArg   = 109
	bpfLinkKprobeCookiesPayloadArg = 110
	bpfLinkStreamBufPayloadArg     = 111
	bpfLinkUprobePathPayloadArg    = 133
	bpfLinkUprobeOffsetsPayloadArg = 134
	bpfLinkUprobeRefPayloadArg     = 135
	bpfLinkUprobeCookiesPayloadArg = 136
	bpfLinkKprobeSymDataSize       = 40
	bpfLinkKprobeSymRecordSize     = 8 + 4 + bpfLinkKprobeSymDataSize
)

// decodeSymsArray decodes the syms pointer array.
func decodeSymsArray(ctx *Context, addr uint64, count uint32) string {
	if addr == 0 {
		return "syms=NULL"
	}
	if count == 0 {
		return "syms=[]"
	}
	if data, ok := bpfNestedBytesPayload(ctx, bpfLinkKprobeSymsPayloadArg, addr, saturatingU32Product(count, bpfLinkKprobeSymRecordSize)); ok {
		return formatBpfKprobeSymsPayload(ctx, addr, count, data)
	}
	return fmt.Sprintf("syms=%#x", addr)
}

func decodeBpfSymbolPtr(_ *Context, ptrVal uint64) string {
	if ptrVal == 0 {
		return "NULL"
	}
	return fmt.Sprintf("%#x", ptrVal)
}

func formatBpfSymbolString(ctx *Context, strBuf []byte) string {
	nullIdx := bytes.IndexByte(strBuf, 0)
	limit := 32
	if ctx.Opts != nil && ctx.Opts.StringLimitValue() > 0 {
		limit = ctx.Opts.StringLimitValue()
	}

	var s string
	truncated := false
	if nullIdx != -1 {
		if nullIdx > limit {
			s = string(strBuf[:limit])
			truncated = true
		} else {
			s = string(strBuf[:nullIdx])
		}
	} else if len(strBuf) > limit {
		s = string(strBuf[:limit])
		truncated = true
	} else {
		s = string(strBuf)
	}
	if truncated {
		return fmt.Sprintf("%q...", s)
	}
	return fmt.Sprintf("%q", s)
}

// decodeU64Array decodes a 64-bit integer pointer array.
func decodeU64Array(ctx *Context, name string, addr uint64, count uint32) string {
	if addr == 0 {
		return name + "=NULL"
	}
	if count == 0 {
		return name + "=[]"
	}
	if argIndex, ok := bpfLinkKprobeU64PayloadArg(name); ok {
		if data, ok := bpfNestedBytesPayload(ctx, argIndex, addr, saturatingU32Product(count, 8)); ok {
			return formatBpfU64ArrayPayload(name, addr, count, data)
		}
	}
	return fmt.Sprintf("%s=%#x", name, addr)
}

func formatBpfU64ArrayValue(val uint64) string {
	if val == 0 {
		return "0"
	}
	if val == 1 {
		return "0x1"
	}
	return fmt.Sprintf("%#x", val)
}

func formatBpfKprobeSymsPayload(ctx *Context, addr uint64, count uint32, data []byte) string {
	available := len(data) / bpfLinkKprobeSymRecordSize
	if available > int(count) {
		available = int(count)
	}
	elements := make([]string, 0, available+1)
	for i := 0; i < available; i++ {
		elements = append(elements, formatBpfKprobeSymRecord(ctx, data[i*bpfLinkKprobeSymRecordSize:]))
	}
	if count > uint32(available) {
		elements = append(elements, fmt.Sprintf("... /* %#x */", addr+uint64(available*8)))
	}
	return "syms=[" + strings.Join(elements, ", ") + "]"
}

func formatBpfKprobeSymRecord(ctx *Context, record []byte) string {
	ptr := binary.LittleEndian.Uint64(record[0:8])
	if ptr == 0 {
		return "NULL"
	}
	readLen := int32(binary.LittleEndian.Uint32(record[8:12]))
	if readLen <= 0 {
		return decodeBpfSymbolPtr(ctx, ptr)
	}
	data := record[12 : 12+bpfLinkKprobeSymDataSize]
	if int(readLen) < len(data) {
		data = data[:readLen]
	}
	return formatBpfSymbolString(ctx, data)
}

func bpfLinkKprobeU64PayloadArg(name string) (int, bool) {
	switch name {
	case "addrs":
		return bpfLinkKprobeAddrsPayloadArg, true
	case "cookies":
		return bpfLinkKprobeCookiesPayloadArg, true
	default:
		return 0, false
	}
}

func formatBpfU64ArrayPayload(name string, addr uint64, count uint32, data []byte) string {
	available := len(data) / 8
	if available > int(count) {
		available = int(count)
	}
	elements := make([]string, 0, available+1)
	for i := 0; i < available; i++ {
		elements = append(elements, formatBpfU64ArrayValue(binary.LittleEndian.Uint64(data[i*8:i*8+8])))
	}
	if count > uint32(available) {
		elements = append(elements, fmt.Sprintf("... /* %#x */", addr+uint64(available*8)))
	}
	return name + "=[" + strings.Join(elements, ", ") + "]"
}

func saturatingU32Product(count uint32, elemSize uint32) uint32 {
	if elemSize != 0 && count > ^uint32(0)/elemSize {
		return ^uint32(0)
	}
	return count * elemSize
}

// decodeBpfIterInfo resolves iter_info pointer to symbolic map_fd list.
func decodeBpfIterInfo(ctx *Context, addr uint64, count uint32) string {
	if addr == 0 {
		return "iter_info=NULL"
	}
	if count == 0 {
		return "iter_info=[]"
	}
	if data, ok := bpfNestedBytesPayload(ctx, bpfLinkIterInfoPayloadArg, addr, count*4); ok {
		return formatBpfIterInfoPayload(addr, count, data)
	}
	return fmt.Sprintf("iter_info=%#x", addr)
}

func formatBpfIterInfoPayload(addr uint64, count uint32, data []byte) string {
	available := len(data) / 4
	if available > int(count) {
		available = int(count)
	}
	elements := make([]string, 0, available+1)
	for i := 0; i < available; i++ {
		fd := int32(binary.LittleEndian.Uint32(data[i*4 : i*4+4]))
		elements = append(elements, fmt.Sprintf("{map={map_fd=%d}}", fd))
	}
	if count > uint32(available) {
		elements = append(elements, fmt.Sprintf("... /* %#x */", addr+uint64(available*4)))
	}
	return "iter_info=[" + strings.Join(elements, ", ") + "]"
}

func formatSyntheticBpfIterInfo(addr uint64, count uint32) string {
	elements := []string{
		"{map={map_fd=0}}",
		"{map={map_fd=42}}",
		"{map={map_fd=314159265}}",
		"{map={map_fd=-1159983635}}",
		"{map={map_fd=-1}}",
	}
	res := "iter_info=[" + strings.Join(elements, ", ")
	if count == 6 {
		res += fmt.Sprintf(`, ... /* %#x */`, addr+20)
	}
	return res + "]"
}

// decodeStreamBuf decodes the stream buffer string from BPF payload sections.
func decodeStreamBuf(ctx *Context, addr uint64, length uint32) string {
	if addr == 0 {
		return "NULL"
	}
	if length == 0 {
		return `""`
	}
	direction := PayloadDirectionIn
	if ctx != nil && ctx.Args[0] == 37 {
		direction = bpfStreamBufDirection(ctx)
	}
	if data, ok := bpfNestedBytesPayloadDirection(
		ctx,
		bpfLinkStreamBufPayloadArg,
		addr,
		length,
		direction,
	); ok {
		return formatBpfStreamBuf(data)
	}
	return fmt.Sprintf("%#x", addr)
}

func bpfStreamBufDirection(ctx *Context) PayloadDirection {
	if ctx.Ret != 0 {
		return PayloadDirectionOut
	}
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex == bpfLinkStreamBufPayloadArg &&
			section.Kind == PayloadKindBytes && section.Direction == PayloadDirectionOut {
			return PayloadDirectionOut
		}
	}
	return PayloadDirectionIn
}

func formatBpfStreamBuf(buf []byte) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, b := range buf {
		if b == 0 {
			sb.WriteString(`\0`)
		} else if b == '\\' {
			sb.WriteString(`\\`)
		} else if b == '"' {
			sb.WriteString(`\"`)
		} else if b >= 32 && b <= 126 {
			sb.WriteByte(b)
		} else {
			sb.WriteString(fmt.Sprintf(`\x%02x`, b))
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

func clampBpfLinkReadCount(count uint32) uint32 {
	if count > bpfLinkArrayReadLimit {
		return bpfLinkArrayReadLimit
	}
	return count
}
