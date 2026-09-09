package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

func registerBuiltinOpenat2(r *Registry) {
	r.RegisterStructDecoder("struct open_how *", StructDecoderFunc(decodeOpenHow))
}

const (
	openHowMinSize        = 24
	openHowSnapshotOffset = 4096
	openHowSnapshotMax    = 64
	openHowFlagCreate     = 0x40
	openHowFlagTmpfile    = 0x400000
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

	return formatOpenHow(ctx, d, sz), true
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

func formatOpenHow(ctx *Context, d []byte, requested uint64) string {
	flagsVal := binary.LittleEndian.Uint64(d[0:8])
	modeVal := binary.LittleEndian.Uint64(d[8:16])
	flags := decodeOpenHowFlags64(ctx, flagsVal, "open_mode_flags")
	modeStr := ""
	if modeVal != 0 || (flagsVal&openHowFlagCreate) != 0 || (flagsVal&openHowFlagTmpfile) != 0 {
		modeStr = fmt.Sprintf(", mode=%#03o", modeVal)
	}
	resolve := decodeOpenHowFlags64(ctx, binary.LittleEndian.Uint64(d[16:24]), "open_resolve_flags")

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

func decodeOpenHowFlags64(ctx *Context, val uint64, xlatName string) string {
	if xlatFormat(ctx) == "raw" {
		return openHowRawHex(val)
	}
	decoded := decodeOpenHowBitFlags64(ctx, val, xlatName)
	if xlatFormat(ctx) != "verbose" {
		return decoded
	}
	if strings.Contains(decoded, "/*") {
		return decoded
	}
	raw := openHowRawHex(val)
	if decoded == raw {
		return decoded
	}
	return fmt.Sprintf("%s /* %s */", raw, decoded)
}

func decodeOpenHowBitFlags64(ctx *Context, val uint64, xlatName string) string {
	table, ok := xlatTable(ctx, xlatName)
	if !ok {
		return openHowRawHex(val)
	}
	res := openHowAccessModeParts(val, xlatName)
	handled := openHowAccessModeHandled(xlatName, val)

	for _, entry := range table.Entries {
		if entry.Val == 0 || (val&entry.Val) != entry.Val {
			continue
		}
		if (handled & entry.Val) == entry.Val {
			continue
		}
		res = append(res, entry.Str)
		handled |= entry.Val
	}
	if xlatName == "open_mode_flags" {
		appendOpenHowFlagEntries(ctx, val, &res, &handled)
	}
	if len(res) == 0 {
		return openHowUnknownFlags(val, table)
	}
	if remaining := val & ^handled; val != 0 && remaining != 0 {
		res = append(res, openHowRawHex(remaining))
	}
	return strings.Join(res, "|")
}

func appendOpenHowFlagEntries(
	ctx *Context,
	val uint64,
	parts *[]string,
	handled *uint64,
) {
	table, ok := xlatTable(ctx, "openat2_flags")
	if !ok {
		return
	}
	for _, entry := range table.Entries {
		if entry.Val == 0 || (val&entry.Val) != entry.Val || (*handled&entry.Val) == entry.Val {
			continue
		}
		*parts = append(*parts, entry.Str)
		*handled |= entry.Val
	}
}

func openHowAccessModeParts(val uint64, xlatName string) []string {
	if !strings.Contains(xlatName, "open_mode_flags") {
		return nil
	}
	switch val & 3 {
	case 0:
		return []string{"O_RDONLY"}
	case 1:
		return []string{"O_WRONLY"}
	case 2:
		return []string{"O_RDWR"}
	default:
		return []string{"O_ACCMODE"}
	}
}

func openHowAccessModeHandled(xlatName string, val uint64) uint64 {
	if !strings.Contains(xlatName, "open_mode_flags") {
		return 0
	}
	return val & 3
}

func openHowUnknownFlags(val uint64, table meta.XlatTable) string {
	if val == 0 {
		for _, entry := range table.Entries {
			if entry.Val == 0 {
				return entry.Str
			}
		}
		return "0"
	}
	if table.Prefix != "" {
		return fmt.Sprintf("%s /* %s??? */", openHowRawHex(val), table.Prefix)
	}
	return fmt.Sprintf("%s /* ??? */", openHowRawHex(val))
}

func openHowRawHex(val uint64) string {
	if val == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", val)
}
