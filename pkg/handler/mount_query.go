package handler

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func registerBuiltinMountQuery(r *Registry) {
	r.Register("statmount", &StatmountHandler{})
	r.Register("listmount", &ListmountHandler{})
}

// StatmountHandler composes the shared mount request decoder with statmount OUT semantics.
type StatmountHandler struct{}

func (h *StatmountHandler) Handle(ctx *Context) Result {
	request := mntIDRequestDecoder{semantics: statmountRequestSemantics{}}
	return Result{ArgParts: []string{
		request.format(ctx, ctx.Args[0]),
		formatStatmountOutput(ctx),
		fmt.Sprintf("%d", ctx.Args[2]),
		decodeFlags(ctx, uint64(uint32(ctx.Args[3])), "statmount_flags"),
	}}
}

// ListmountHandler composes the shared mount request decoder with mount ID array semantics.
type ListmountHandler struct{}

func (h *ListmountHandler) Handle(ctx *Context) Result {
	request := mntIDRequestDecoder{semantics: listmountRequestSemantics{}}
	return Result{ArgParts: []string{
		request.format(ctx, ctx.Args[0]),
		formatListmountIDs(ctx),
		fmt.Sprintf("%d", ctx.Args[2]),
		decodeFlags(ctx, uint64(uint32(ctx.Args[3])), "listmount_flags"),
	}}
}

func formatListmountIDs(ctx *Context) string {
	userPtr := ctx.Args[1]
	count := ctx.Args[2]
	if userPtr == 0 {
		return "NULL"
	}
	if count == 0 {
		return "[]"
	}
	if ctx.Ret <= 0 {
		return formatPointer(userPtr)
	}
	section, ok := mountQueryPayloadSection(ctx, 1, PayloadKindBytes, PayloadDirectionOut)
	if !ok {
		return formatPointer(userPtr)
	}
	data := copiedSectionData(section)
	if len(data) < 8 {
		return formatPointer(userPtr)
	}

	wanted := uint64(ctx.Ret)
	if wanted > count {
		wanted = count
	}
	items := make([]string, 0, len(data)/8+1)
	for offset := 0; offset+8 <= len(data) && uint64(len(items)) < wanted; offset += 8 {
		items = append(items, formatHexValue(binary.LittleEndian.Uint64(data[offset:offset+8])))
	}
	if uint64(len(items)) < wanted {
		address := userPtr + uint64(len(items)*8)
		items = append(items, fmt.Sprintf("... /* %#x */", address))
	}
	return "[" + strings.Join(items, ", ") + "]"
}
