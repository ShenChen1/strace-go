package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
)

const (
	fileAttrBaseSize     = 24
	fileAttrExtensionMax = 256
	fileAttrPageSize     = 4096
)

func registerBuiltinFileAttr(r *Registry) {
	r.RegisterStructDecoder("struct file_attr *", StructDecoderFunc(decodeFileAttr))
}

func decodeFileAttr(ctx *Context, _ int, _ string, val uint64) (string, bool) {
	if val == 0 {
		return "NULL", true
	}
	if ctx == nil || ctx.Args[3] < fileAttrBaseSize || ctx.Args[3] > fileAttrPageSize {
		return formatPointer(val), true
	}
	direction, ok := fileAttrDirection(ctx.SysName)
	if !ok {
		return formatPointer(val), true
	}
	section, ok := fileAttrPayloadSection(ctx, PayloadKindStruct, direction)
	if !ok || section.CopiedLen < fileAttrBaseSize || len(section.Data) < fileAttrBaseSize {
		return formatPointer(val), true
	}

	data := section.Data[:fileAttrBaseSize]
	parts := []string{
		"fa_xflags=" + decodeFlags(ctx, binary.LittleEndian.Uint64(data[0:8]), "fs_xflags"),
		fmt.Sprintf("fa_extsize=%d", binary.LittleEndian.Uint32(data[8:12])),
	}
	if ctx.SysName == "file_getattr" {
		parts = append(parts, fmt.Sprintf("fa_nextents=%d", binary.LittleEndian.Uint32(data[12:16])))
	}
	parts = append(parts,
		"fa_projid="+formatFileAttrProjectID(binary.LittleEndian.Uint32(data[16:20])),
		fmt.Sprintf("fa_cowextsize=%d", binary.LittleEndian.Uint32(data[20:24])))
	parts = append(parts, fileAttrExtensionParts(ctx, direction)...)
	return "{" + strings.Join(parts, ", ") + "}", true
}

func formatFileAttrProjectID(value uint32) string {
	if value == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", value)
}

func fileAttrDirection(syscallName string) (PayloadDirection, bool) {
	switch syscallName {
	case "file_getattr":
		return PayloadDirectionOut, true
	case "file_setattr":
		return PayloadDirectionIn, true
	default:
		return "", false
	}
}

func fileAttrPayloadSection(ctx *Context, kind PayloadKind, direction PayloadDirection) (PayloadSection, bool) {
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex == 2 && section.Kind == kind && section.Direction == direction {
			return section, section.ProbeRet == 0
		}
	}
	return PayloadSection{}, false
}

func fileAttrExtensionParts(ctx *Context, direction PayloadDirection) []string {
	if ctx.Args[3] <= fileAttrBaseSize {
		return nil
	}
	section, ok := fileAttrPayloadSection(ctx, PayloadKindBytes, direction)
	if !ok || section.ProbeRet < 0 {
		return []string{"???"}
	}
	data := copiedPayloadData(section)
	if lastNonZeroByte(data) < 0 {
		if section.CopiedLen < section.UserLen {
			return []string{"???"}
		}
		return nil
	}
	parts := []string{fmt.Sprintf("/* bytes %d..%d */ %s", fileAttrBaseSize,
		fileAttrBaseSize+len(data)-1, format.BufferEscape(data, len(data), len(data), 2))}
	if section.CopiedLen < section.UserLen {
		parts = append(parts, "???")
	}
	return parts
}

func copiedPayloadData(section PayloadSection) []byte {
	length := int(section.CopiedLen)
	if length > len(section.Data) {
		length = len(section.Data)
	}
	if length < 0 {
		return nil
	}
	return section.Data[:length]
}
