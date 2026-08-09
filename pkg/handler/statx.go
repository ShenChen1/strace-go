package handler

import (
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

const statxSyncTypeMask = uint64(0x6000)

func init() {
	Register("statx", &StatxHandler{})
}

// StatxHandler formats statx arguments from probe-site snapshots.
type StatxHandler struct{}

func (h *StatxHandler) Handle(ctx *Context) Result {
	res := (&DefaultHandler{}).HandleWithCount(ctx, 2)
	res.ArgParts = append(res.ArgParts, formatStatxFlags(ctx.Args[2]))
	res.ArgParts = append(res.ArgParts, meta.DecodeFlags(ctx.Args[3], "statx_masks"))
	res.ArgParts = append(res.ArgParts, decodeStatxSnapshot(ctx, ctx.Args[4]))
	return res
}

func formatStatxFlags(value uint64) string {
	value = uint64(uint32(value))
	if meta.XlatFormat == "raw" {
		return statxRawValue(value)
	}

	named := statxNamedFlags(value)
	if meta.XlatFormat == "verbose" {
		return fmt.Sprintf("%s /* %s */", statxRawValue(value), named)
	}
	return named
}

func statxNamedFlags(value uint64) string {
	parts := []string{statxNamedFlagGroup(value&statxSyncTypeMask, "at_statx_sync_types")}
	if other := value &^ statxSyncTypeMask; other != 0 {
		parts = append(parts, statxNamedFlagGroup(other, "at_flags"))
	}
	return strings.Join(parts, "|")
}

func statxNamedFlagGroup(value uint64, tableName string) string {
	table, ok := meta.XlatTables[tableName]
	if !ok {
		return statxRawValue(value)
	}
	if value == 0 {
		for _, entry := range table.Entries {
			if entry.Val == 0 {
				return entry.Str
			}
		}
		return "0"
	}

	var parts []string
	var handled uint64
	for _, entry := range table.Entries {
		if entry.Val != 0 && value&entry.Val == entry.Val && handled&entry.Val != entry.Val {
			parts = append(parts, entry.Str)
			handled |= entry.Val
		}
	}
	if remaining := value &^ handled; remaining != 0 {
		parts = append(parts, fmt.Sprintf("%#x", remaining))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%#x /* %s??? */", value, table.Prefix)
	}
	return strings.Join(parts, "|")
}

func statxRawValue(value uint64) string {
	if value == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", value)
}

func decodeStatxSnapshot(ctx *Context, userPtr uint64) string {
	if userPtr == 0 {
		return "NULL"
	}
	data, ok := ctx.PayloadStruct(4, PayloadDirectionOut)
	if !ok || len(data) < statxStructSize {
		return fmt.Sprintf("%#x", userPtr)
	}
	return parseStatxSnapshot(data[:statxStructSize]).format(ctx.Opts != nil && ctx.Opts.Verbose)
}
