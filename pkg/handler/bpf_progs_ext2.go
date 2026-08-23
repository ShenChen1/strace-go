package handler

import (
	"fmt"
	"strings"
)

const (
	bpfTaskFdQueryBufPayloadArg  = 137
	bpfTaskFdQueryAttrPayloadArg = 138
)

// decodeBpfTaskFdQuery decodes BPF_TASK_FD_QUERY.
// Impact: Formats task fd query properties including pid, fd, flags, buffers and probe descriptors.
func decodeBpfTaskFdQuery(ctx *Context, data []byte, size uint32) string {
	parts := []string{}
	attrData := data
	if output, ok := bpfNestedBytesPayloadDirection(
		ctx,
		bpfTaskFdQueryAttrPayloadArg,
		ctx.Args[1],
		48,
		PayloadDirectionOut,
	); ok {
		attrData = output
	}
	parts = append(parts, fmt.Sprintf("pid=%d", u32OrZero(attrData, 0)))
	parts = append(parts, fmt.Sprintf("fd=%d", int32(u32OrZero(attrData, 4))))
	parts = append(parts, fmt.Sprintf("flags=%d", u32OrZero(attrData, 8)))
	parts = append(parts, fmt.Sprintf("buf_len=%d", u32OrZero(attrData, 12)))

	bufVal := u64OrZero(attrData, 16)
	if bufText, ok := bpfNestedStringPayloadDirection(
		ctx,
		bpfTaskFdQueryBufPayloadArg,
		bufVal,
		int(u32OrZero(attrData, 12)),
		PayloadDirectionOut,
	); ok {
		parts = append(parts, "buf="+bufText)
	} else {
		parts = append(parts, formatPtr("buf", bufVal))
	}

	parts = append(parts, fmt.Sprintf("prog_id=%d", u32OrZero(attrData, 24)))
	parts = append(parts, "fd_type="+decodeFlags(ctx, uint64(u32OrZero(attrData, 28)), "bpf_fd_type"))

	probeOffset := u64OrZero(attrData, 32)
	if probeOffset == 0 {
		parts = append(parts, "probe_offset=0")
	} else {
		parts = append(parts, fmt.Sprintf("probe_offset=%#x", probeOffset))
	}

	probeAddr := u64OrZero(attrData, 40)
	if probeAddr == 0 {
		parts = append(parts, "probe_addr=0")
	} else {
		parts = append(parts, fmt.Sprintf("probe_addr=%#x", probeAddr))
	}

	decodedSize := 48
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{task_fd_query={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

// decodeBpfMapFreeze decodes BPF_MAP_FREEZE.
// Impact: Formats map freeze operation with map_fd.
func decodeBpfMapFreeze(ctx *Context, data []byte, size uint32) string {
	parts := []string{}
	parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 0))))
	decodedSize := 4
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}
