package handler

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

const (
	mountSetattrBaseSize = 32
	mountAttrIDMap       = uint64(0x100000)
)

func registerBuiltinMountSetattr(r *Registry) {
	r.Register("mount_setattr", &MountSetattrHandler{})
}

// MountSetattrHandler formats mount_setattr from enter-stage BPF snapshots.
type MountSetattrHandler struct{}

func (h *MountSetattrHandler) Handle(ctx *Context) Result {
	res := (&DefaultHandler{}).HandleWithCount(ctx, 2)
	res.ArgParts = append(res.ArgParts, meta.DecodeFlags(uint64(uint32(ctx.Args[2])), "mount_setattr_flags"))
	res.ArgParts = append(res.ArgParts, decodeMountSetattrAttr(ctx))
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", ctx.Args[4]))
	return res
}

type mountAttrSnapshot struct {
	attrSet     uint64
	attrClear   uint64
	propagation uint64
	usernsFD    uint64
}

func decodeMountSetattrAttr(ctx *Context) string {
	userPtr := ctx.Args[3]
	if userPtr == 0 {
		return "NULL"
	}
	if ctx.Args[4] < mountSetattrBaseSize {
		return formatPointer(userPtr)
	}
	data, ok := ctx.PayloadStruct(3, PayloadDirectionIn)
	if !ok || len(data) < mountSetattrBaseSize {
		return formatPointer(userPtr)
	}

	attr := parseMountAttrSnapshot(data)
	parts := []string{
		"attr_set=" + meta.DecodeFlags(attr.attrSet, "mount_attr_attr"),
		"attr_clr=" + meta.DecodeFlags(attr.attrClear, "mount_attr_attr"),
		"propagation=" + meta.DecodeFlags(attr.propagation, "mount_attr_propagation"),
		"userns_fd=" + formatMountAttrUsernsFD(ctx, attr),
	}
	parts = append(parts, mountSetattrExtensionParts(ctx)...)
	return "{" + strings.Join(parts, ", ") + "}"
}

func parseMountAttrSnapshot(data []byte) mountAttrSnapshot {
	return mountAttrSnapshot{
		attrSet:     binary.LittleEndian.Uint64(data[0:8]),
		attrClear:   binary.LittleEndian.Uint64(data[8:16]),
		propagation: binary.LittleEndian.Uint64(data[16:24]),
		usernsFD:    binary.LittleEndian.Uint64(data[24:32]),
	}
}

func formatMountAttrUsernsFD(ctx *Context, attr mountAttrSnapshot) string {
	if attr.usernsFD > math.MaxInt32 || (attr.attrSet|attr.attrClear)&mountAttrIDMap == 0 {
		return fmt.Sprintf("%d", attr.usernsFD)
	}
	return FormatFdWithPath(ctx, int32(attr.usernsFD))
}

func mountSetattrExtensionParts(ctx *Context) []string {
	if ctx.Args[4] <= mountSetattrBaseSize {
		return nil
	}
	section, ok := mountSetattrExtensionSection(ctx)
	if !ok || section.ProbeRet < 0 {
		return []string{"???"}
	}
	if lastNonZeroByte(section.Data) < 0 {
		if section.CopiedLen < section.UserLen {
			return []string{"???"}
		}
		return nil
	}
	data := section.Data
	if section.CopiedLen < uint32(len(data)) {
		data = data[:section.CopiedLen]
	}
	label := fmt.Sprintf("/* bytes %d..%d */ %s", mountSetattrBaseSize,
		mountSetattrBaseSize+len(data)-1, format.BufferEscape(data, len(data), len(data), 2))
	if section.CopiedLen < section.UserLen {
		return []string{label, "???"}
	}
	return []string{label}
}

func mountSetattrExtensionSection(ctx *Context) (PayloadSection, bool) {
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex == 3 && section.Kind == PayloadKindBytes && section.Direction == PayloadDirectionIn {
			return section, true
		}
	}
	return PayloadSection{}, false
}

func lastNonZeroByte(data []byte) int {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			return i
		}
	}
	return -1
}
