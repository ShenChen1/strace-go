package handler

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const bpfProgLoadCoreRelosPayloadArg = 144

func decodeBpfProgLoadCoreRelos(ctx *Context, addr uint64, recSize, count uint32) string {
	if addr == 0 {
		return "core_relos=NULL"
	}
	if recSize < 16 || count == 0 {
		return fmt.Sprintf("core_relos=%#x", addr)
	}
	data, ok := bpfNestedBytesPayload(
		ctx,
		bpfProgLoadCoreRelosPayloadArg,
		addr,
		saturatingU32Product(recSize, count),
	)
	if !ok {
		return fmt.Sprintf("core_relos=%#x", addr)
	}

	available := len(data) / int(recSize)
	if available > int(count) {
		available = int(count)
	}
	if available == 0 {
		return fmt.Sprintf("core_relos=%#x", addr)
	}

	records := make([]string, 0, available+1)
	for i := 0; i < available; i++ {
		offset := i * int(recSize)
		records = append(records, fmt.Sprintf(
			"{insn_off=%d, type_id=%d, access_str_off=%d, kind=%d}",
			binary.LittleEndian.Uint32(data[offset:offset+4]),
			binary.LittleEndian.Uint32(data[offset+4:offset+8]),
			binary.LittleEndian.Uint32(data[offset+8:offset+12]),
			binary.LittleEndian.Uint32(data[offset+12:offset+16]),
		))
	}
	if count > uint32(available) {
		records = append(records, fmt.Sprintf("... /* %#x */", addr+uint64(available)*uint64(recSize)))
	}
	return "core_relos=[" + strings.Join(records, ", ") + "]"
}
