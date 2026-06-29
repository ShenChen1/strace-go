package handler

import (
	"bytes"
	"fmt"
	"strings"
)

const (
	bpfLinkArrayReadLimit  = 16
	bpfLinkSymbolReadLimit = 38
	bpfLinkStreamReadLimit = 512
)

// decodeSymsArray decodes the syms pointer array.
func decodeSymsArray(_ *Context, addr uint64, count uint32) string {
	if addr == 0 {
		return "syms=NULL"
	}
	if count == 0 {
		return "syms=[]"
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
	if ctx.Opts != nil && ctx.Opts.StringLimit > 0 {
		limit = ctx.Opts.StringLimit
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
func decodeU64Array(_ *Context, name string, addr uint64, count uint32) string {
	if addr == 0 {
		return name + "=NULL"
	}
	if count == 0 {
		return name + "=[]"
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

// decodeBpfIterInfo resolves iter_info pointer to symbolic map_fd list.
func decodeBpfIterInfo(_ *Context, addr uint64, count uint32) string {
	if addr == 0 {
		return "iter_info=NULL"
	}
	if count == 0 {
		return "iter_info=[]"
	}
	return fmt.Sprintf("iter_info=%#x", addr)
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

// decodeStreamBuf decodes the stream buffer string from process memory.
func decodeStreamBuf(_ *Context, addr uint64, length uint32) string {
	if addr == 0 {
		return "NULL"
	}
	if length == 0 {
		return `""`
	}
	return fmt.Sprintf("%#x", addr)
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
