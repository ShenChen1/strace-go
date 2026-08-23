package handler

import (
	"fmt"
	"strings"
)

const (
	bpfProgQueryProgIDsArg            = 128
	bpfProgQueryProgAttachFlagsArg    = 129
	bpfProgQueryLinkIDsArg            = 130
	bpfProgQueryLinkAttachFlagsArg    = 131
	bpfProgQueryProgCntOutputArg      = 132
	bpfProgQueryProgIDsOffset         = 16
	bpfProgQueryProgCntOffset         = 24
	bpfProgQueryProgAttachFlagsOffset = 32
	bpfProgQueryLinkIDsOffset         = 40
	bpfProgQueryLinkAttachFlagsOffset = 48
)

// decodeBpfProgQuery decodes BPF_PROG_QUERY and its event-time output arrays.
// Impact: Uses only exit OUT payloads for kernel-written arrays and count.
func decodeBpfProgQuery(ctx *Context, data []byte, size uint32) string {
	parts := []string{}
	attachType := u32OrZero(data, 4)
	targetVal := u32OrZero(data, 0)
	if attachType == 46 || attachType == 47 || attachType == 54 || attachType == 55 {
		parts = append(parts, "target_ifindex="+translateIfindex(targetVal))
	} else {
		parts = append(parts, fmt.Sprintf("target_fd=%d", int32(targetVal)))
	}

	parts = append(parts, "attach_type="+decodeFlags(ctx, uint64(attachType), "bpf_attach_type"))
	parts = append(parts, "query_flags="+decodeFlags(ctx, uint64(u32OrZero(data, 8)), "bpf_query_flags"))
	parts = append(parts, "attach_flags="+decodeFlags(ctx, uint64(u32OrZero(data, 12)), "bpf_attach_flags"))

	progCnt := u32OrZero(data, bpfProgQueryProgCntOffset)
	progCnt = bpfProgQueryOutputCount(ctx, progCnt)
	parts = append(parts, formatBpfProgQueryArrayField(
		ctx,
		"prog_ids",
		bpfProgQueryProgIDsArg,
		u64OrZero(data, bpfProgQueryProgIDsOffset),
		progCnt,
		""))
	parts = append(parts, fmt.Sprintf("prog_cnt=%d", progCnt))
	decodedSize := 28

	if size >= 40 {
		parts = append(parts, formatBpfProgQueryArrayField(
			ctx,
			"prog_attach_flags",
			bpfProgQueryProgAttachFlagsArg,
			u64OrZero(data, bpfProgQueryProgAttachFlagsOffset),
			progCnt,
			"bpf_attach_flags"))
		decodedSize = 40
	}
	if size >= 64 {
		parts = append(parts, formatBpfProgQueryArrayField(
			ctx,
			"link_ids",
			bpfProgQueryLinkIDsArg,
			u64OrZero(data, bpfProgQueryLinkIDsOffset),
			progCnt,
			""))
		parts = append(parts, formatBpfProgQueryArrayField(
			ctx,
			"link_attach_flags",
			bpfProgQueryLinkAttachFlagsArg,
			u64OrZero(data, bpfProgQueryLinkAttachFlagsOffset),
			progCnt,
			"bpf_attach_flags"))
		parts = append(parts, fmt.Sprintf("revision=%#x", u64OrZero(data, 56)))
		decodedSize = 64
	}

	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{query={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

func bpfProgQueryOutputCount(ctx *Context, fallback uint32) uint32 {
	if ctx == nil || ctx.Ret != 0 || ctx.Args[1] == 0 {
		return fallback
	}
	section, ok := bpfNestedPayloadSectionDirection(
		ctx,
		bpfProgQueryProgCntOutputArg,
		PayloadKindBytes,
		ctx.Args[1]+bpfProgQueryProgCntOffset,
		PayloadDirectionOut,
	)
	if !ok || len(section.Data) < 4 {
		return fallback
	}
	return u32OrZero(section.Data, 0)
}

func formatBpfProgQueryArrayField(
	ctx *Context,
	name string,
	argIndex int,
	ptr uint64,
	count uint32,
	tableName string,
) string {
	if ptr == 0 {
		return name + "=NULL"
	}
	if count == 0 {
		return name + "=[]"
	}
	values, complete, ok := bpfProgQueryArrayPayload(ctx, argIndex, ptr, count)
	if !ok {
		return formatPtr(name, ptr)
	}
	parts := make([]string, 0, len(values)+1)
	for _, value := range values {
		if tableName == "" {
			parts = append(parts, fmt.Sprintf("%d", value))
		} else {
			parts = append(parts, decodeFlags(ctx, uint64(value), tableName))
		}
	}
	if !complete {
		parts = append(parts, "...")
	}
	return name + "=[" + strings.Join(parts, ", ") + "]"
}

func bpfProgQueryArrayPayload(
	ctx *Context,
	argIndex int,
	ptr uint64,
	count uint32,
) ([]uint32, bool, bool) {
	if ctx == nil || ctx.Ret != 0 {
		return nil, false, false
	}
	section, ok := bpfNestedPayloadSectionDirection(
		ctx,
		argIndex,
		PayloadKindBytes,
		ptr,
		PayloadDirectionOut,
	)
	if !ok {
		return nil, false, false
	}
	available := len(section.Data) / 4
	requested := int(count)
	if available < requested {
		requested = available
	}
	values := make([]uint32, requested)
	for i := range values {
		values[i] = u32OrZero(section.Data, i*4)
	}
	return values, requested == int(count), true
}
