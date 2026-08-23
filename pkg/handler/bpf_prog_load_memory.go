package handler

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const bpfProgLoadFDArrayPayloadArg = 141

func decodeBpfProgLoadFDArray(ctx *Context, addr uint64, count uint32) string {
	if addr == 0 {
		return "fd_array=NULL"
	}
	if count == 0 {
		return fmt.Sprintf("fd_array=%#x", addr)
	}
	data, ok := bpfNestedBytesPayload(ctx, bpfProgLoadFDArrayPayloadArg, addr, saturatingU32Product(count, 4))
	if !ok {
		return fmt.Sprintf("fd_array=%#x", addr)
	}

	available := len(data) / 4
	if available > int(count) {
		available = int(count)
	}
	elements := make([]string, 0, available+1)
	for i := 0; i < available; i++ {
		value := binary.LittleEndian.Uint32(data[i*4 : i*4+4])
		elements = append(elements, fmt.Sprintf("%d", value))
	}
	if count > uint32(available) {
		elements = append(elements, fmt.Sprintf("... /* %#x */", addr+uint64(available*4)))
	}
	return "fd_array=[" + strings.Join(elements, ", ") + "]"
}
