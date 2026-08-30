package handler

import (
	"fmt"
	"strings"
)

func (h *NetworkHandler) formatSocketArgument(ctx *Context, argName string, value uint64) (string, bool) {
	if ctx.ScMeta.Name != "socket" {
		return "", false
	}
	switch argName {
	case "type":
		return formatSocketType(ctx, value), true
	case "protocol":
		return formatSocketProtocol(ctx, ctx.Args[0], value), true
	default:
		return "", false
	}
}

func formatSocketType(ctx *Context, value uint64) string {
	raw := rawSocketValue(value)
	if xlatFormat(ctx) == "raw" {
		return raw
	}
	named := namedSocketType(ctx, uint32(value))
	if xlatFormat(ctx) == "verbose" && !strings.Contains(named, "/*") {
		return fmt.Sprintf("%s /* %s */", raw, named)
	}
	return named
}

func namedSocketType(ctx *Context, value uint32) string {
	const typeMask = uint32(0xf)
	parts := make([]string, 0, 3)
	handled := uint32(0)
	if name, ok := exactXlatName(ctx, "socktypes", uint64(value&typeMask)); ok {
		parts = append(parts, name)
		handled |= value & typeMask
	}
	if table, ok := xlatTable(ctx, "sock_type_flags"); ok {
		for _, entry := range table.Entries {
			flag := uint32(entry.Val)
			if flag != 0 && value&flag == flag {
				parts = append(parts, entry.Str)
				handled |= flag
			}
		}
	}
	if remaining := value &^ handled; remaining != 0 {
		parts = append(parts, fmt.Sprintf("%#x", remaining))
	}
	if len(parts) == 0 {
		return rawSocketValue(uint64(value)) + " /* SOCK_??? */"
	}
	return strings.Join(parts, "|")
}

func exactXlatName(ctx *Context, tableName string, value uint64) (string, bool) {
	table, ok := xlatTable(ctx, tableName)
	if !ok {
		return "", false
	}
	for _, entry := range table.Entries {
		if entry.Val == value {
			return entry.Str, true
		}
	}
	return "", false
}

func rawSocketValue(value uint64) string {
	if value == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", uint32(value))
}

func formatSocketProtocol(ctx *Context, family uint64, protocol uint64) string {
	switch uint32(family) {
	case 2, 10:
		return decodeFlags(ctx, protocol, "protocols")
	case 16:
		return decodeFlags(ctx, protocol, "netlink_protocols")
	default:
		return fmt.Sprintf("%d", uint32(protocol))
	}
}
