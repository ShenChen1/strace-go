package handler

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const bpfProgLoadFuncInfoPayloadArg = 142

func decodeBpfProgLoadFuncInfo(ctx *Context, addr uint64, recSize, count uint32) string {
	if addr == 0 {
		return "func_info=NULL"
	}
	if recSize < 8 || count == 0 {
		return fmt.Sprintf("func_info=%#x", addr)
	}
	data, ok := bpfNestedBytesPayload(
		ctx,
		bpfProgLoadFuncInfoPayloadArg,
		addr,
		saturatingU32Product(recSize, count),
	)
	if !ok {
		return fmt.Sprintf("func_info=%#x", addr)
	}

	available := len(data) / int(recSize)
	if available > int(count) {
		available = int(count)
	}
	if available == 0 {
		return fmt.Sprintf("func_info=%#x", addr)
	}

	records := make([]string, 0, available+1)
	for i := 0; i < available; i++ {
		offset := i * int(recSize)
		insnOff := binary.LittleEndian.Uint32(data[offset : offset+4])
		typeID := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		records = append(records, fmt.Sprintf("{insn_off=%d, type_id=%d}", insnOff, typeID))
	}
	if count > uint32(available) {
		records = append(records, fmt.Sprintf("... /* %#x */", addr+uint64(available)*uint64(recSize)))
	}
	return "func_info=[" + strings.Join(records, ", ") + "]"
}
