package handler

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const bpfProgLoadLineInfoPayloadArg = 143

func decodeBpfProgLoadLineInfo(ctx *Context, addr uint64, recSize, count uint32) string {
	if addr == 0 {
		return "line_info=NULL"
	}
	if recSize < 16 || count == 0 {
		return fmt.Sprintf("line_info=%#x", addr)
	}
	data, ok := bpfNestedBytesPayload(
		ctx,
		bpfProgLoadLineInfoPayloadArg,
		addr,
		saturatingU32Product(recSize, count),
	)
	if !ok {
		return fmt.Sprintf("line_info=%#x", addr)
	}

	available := len(data) / int(recSize)
	if available > int(count) {
		available = int(count)
	}
	if available == 0 {
		return fmt.Sprintf("line_info=%#x", addr)
	}

	records := make([]string, 0, available+1)
	for i := 0; i < available; i++ {
		offset := i * int(recSize)
		records = append(records, fmt.Sprintf(
			"{insn_off=%d, file_name_off=%d, line_off=%d, line_col=%d}",
			binary.LittleEndian.Uint32(data[offset:offset+4]),
			binary.LittleEndian.Uint32(data[offset+4:offset+8]),
			binary.LittleEndian.Uint32(data[offset+8:offset+12]),
			binary.LittleEndian.Uint32(data[offset+12:offset+16]),
		))
	}
	if count > uint32(available) {
		records = append(records, fmt.Sprintf("... /* %#x */", addr+uint64(available)*uint64(recSize)))
	}
	return "line_info=[" + strings.Join(records, ", ") + "]"
}
