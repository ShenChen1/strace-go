package handler

import (
	"encoding/binary"
	"fmt"

	"strace-go/pkg/meta"
)

func init() {
	RegisterStructDecoder("struct open_how *", StructDecoderFunc(decodeOpenHow))
}

func decodeOpenHow(ctx *Context, i int, argTyp string, val uint64) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	sz := ctx.Args[3] // size is 4th argument (index 3)
	if sz < 24 {
		return "", false // Let fallback handle short structs if any
	}
	
	d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, int(sz), false)
	if err != nil || len(d) < 24 {
		return "", false
	}
	
	flagsVal := binary.LittleEndian.Uint64(d[0:8])
	flags := meta.DecodeFlags(flagsVal, "open_mode_flags")
	modeStr := ""
	if (flagsVal & 0x40) != 0 || (flagsVal & 0x400000) != 0 { // O_CREAT=0x40, O_TMPFILE=0x400000
		modeStr = fmt.Sprintf(", mode=0%o", binary.LittleEndian.Uint64(d[8:16]))
	}
	resolve := meta.DecodeFlags(binary.LittleEndian.Uint64(d[16:24]), "open_resolve_flags")
	
	res := fmt.Sprintf("{flags=%s%s, resolve=%s}", flags, modeStr, resolve)
	if sz > 24 {
		hasNonZero := false
		for i := 24; i < len(d); i++ {
			if d[i] != 0 {
				hasNonZero = true
				break
			}
		}
		if hasNonZero {
			var hexStr string
			for i := 24; i < len(d); i++ {
				hexStr += fmt.Sprintf("\\x%02x", d[i])
			}
			res = fmt.Sprintf("{flags=%s%s, resolve=%s, /* bytes 24..%d */ %q}", flags, modeStr, resolve, len(d)-1, hexStr)
			// Remove the extra quotes added by %q since we manually built the hex string
			res = res[:len(res)-1] + "" // wait, better just to not use %q
			res = fmt.Sprintf("{flags=%s%s, resolve=%s, /* bytes 24..%d */ \"%s\"}", flags, modeStr, resolve, len(d)-1, hexStr)
		} else if len(d) < int(sz) {
			res = fmt.Sprintf("{flags=%s%s, resolve=%s, ???}", flags, modeStr, resolve)
		}
	}
	return res, true
}
