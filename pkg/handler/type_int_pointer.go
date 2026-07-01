package handler

import (
	"encoding/binary"
	"fmt"
)

const fdArrayPayloadSize = 8

func decodeIntPointer(ctx *Context, i int, argTyp, argName string, val uint64, res *Result) (string, bool) {
	scName := ctx.ScMeta.Name
	if scName == "pipe" || scName == "pipe2" {
		if ctx.Ret >= 0 {
			if data, ok := pipeFdArrayData(ctx, i); ok {
				fd1 := int32(binary.LittleEndian.Uint32(data[0:4]))
				fd2 := int32(binary.LittleEndian.Uint32(data[4:8]))
				return fmt.Sprintf("[%d, %d]", fd1, fd2), true
			}
		}
		return fmt.Sprintf("%#x", val), true
	}
	return "", false
}

func pipeFdArrayData(ctx *Context, argIndex int) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(argIndex, PayloadDirectionOut); ok && len(data) >= fdArrayPayloadSize {
		return data[:fdArrayPayloadSize], true
	}
	return nil, false
}
