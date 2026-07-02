package handler

import (
	"encoding/binary"
	"fmt"

	"strace-go/pkg/meta"
)

func init() {
	RegisterStructDecoder("struct open_how *", StructDecoderFunc(decodeOpenHow))
}

const (
	openHowMinSize        = 24
	openHowSnapshotOffset = 4096
	openHowSnapshotMax    = 64
)

func decodeOpenHow(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	sz := ctx.Args[3] // size is 4th argument (index 3)
	if sz < openHowMinSize {
		return "", false // Let fallback handle short structs if any
	}

	d, ok := readOpenHowSnapshot(ctx, i, sz)
	if !ok || len(d) < openHowMinSize {
		return "", false
	}

	return formatOpenHow(d, sz), true
}

func readOpenHowSnapshot(ctx *Context, argIndex int, requested uint64) ([]byte, bool) {
	readSize := openHowSnapshotMax
	if requested < uint64(readSize) {
		readSize = int(requested)
	}
	if data, ok := ctx.PayloadStruct(argIndex, PayloadDirectionIn); ok {
		if len(data) > readSize {
			return data[:readSize], true
		}
		return data, true
	}
	return nil, false
}

func formatOpenHow(d []byte, requested uint64) string {
	flagsVal := binary.LittleEndian.Uint64(d[0:8])
	flags := meta.DecodeFlags(flagsVal, "open_mode_flags")
	modeStr := ""
	if (flagsVal&0x40) != 0 || (flagsVal&0x400000) != 0 { // O_CREAT=0x40, O_TMPFILE=0x400000
		modeStr = fmt.Sprintf(", mode=0%o", binary.LittleEndian.Uint64(d[8:16]))
	}
	resolve := meta.DecodeFlags(binary.LittleEndian.Uint64(d[16:24]), "open_resolve_flags")

	res := fmt.Sprintf("{flags=%s%s, resolve=%s}", flags, modeStr, resolve)
	if requested > openHowMinSize {
		hasNonZero := false
		for i := openHowMinSize; i < len(d); i++ {
			if d[i] != 0 {
				hasNonZero = true
				break
			}
		}
		if hasNonZero {
			var hexStr string
			for i := openHowMinSize; i < len(d); i++ {
				hexStr += fmt.Sprintf("\\x%02x", d[i])
			}
			res = fmt.Sprintf("{flags=%s%s, resolve=%s, /* bytes 24..%d */ \"%s\"}", flags, modeStr, resolve, len(d)-1, hexStr)
		} else if uint64(len(d)) < requested {
			res = fmt.Sprintf("{flags=%s%s, resolve=%s, ???}", flags, modeStr, resolve)
		}
	}
	return res
}
