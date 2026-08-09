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
	mntIDRequestVersionZeroSize = 24
	mntIDRequestVersionOneSize  = 32
)

type mntIDRequestSemantics interface {
	formatMountID(uint64) string
	formatParam(uint64) string
}

type mntIDRequestDecoder struct {
	semantics mntIDRequestSemantics
}

type statmountRequestSemantics struct{}
type listmountRequestSemantics struct{}

func (statmountRequestSemantics) formatMountID(value uint64) string {
	return formatHexValue(value)
}

func (statmountRequestSemantics) formatParam(value uint64) string {
	return meta.DecodeFlags(value, "statmount_mask")
}

func (listmountRequestSemantics) formatMountID(value uint64) string {
	if value == math.MaxUint64 {
		return "LSMT_ROOT"
	}
	return formatHexValue(value)
}

func (listmountRequestSemantics) formatParam(value uint64) string {
	return formatHexValue(value)
}

func (decoder mntIDRequestDecoder) format(ctx *Context, userPtr uint64) string {
	if userPtr == 0 {
		return "NULL"
	}
	size, ok := mntIDRequestSize(ctx)
	if !ok {
		return formatPointer(userPtr)
	}
	parts := []string{fmt.Sprintf("size=%d", size)}
	if size < mntIDRequestVersionZeroSize {
		return "{" + strings.Join(parts, ", ") + "}"
	}

	base, ok := mntIDRequestBase(ctx, size)
	if !ok {
		return "{" + strings.Join(append(parts, "???"), ", ") + "}"
	}
	parts = decoder.appendBaseFields(ctx, parts, base, size)
	parts = append(parts, mntIDRequestExtensionParts(ctx, size)...)
	return "{" + strings.Join(parts, ", ") + "}"
}

func (decoder mntIDRequestDecoder) appendBaseFields(ctx *Context, parts []string, data []byte, size uint32) []string {
	fd := int32(binary.LittleEndian.Uint32(data[4:8]))
	parts = append(parts,
		"mnt_ns_fd="+FormatFdWithPath(ctx, fd),
		"mnt_id="+decoder.semantics.formatMountID(binary.LittleEndian.Uint64(data[8:16])),
		"param="+decoder.semantics.formatParam(binary.LittleEndian.Uint64(data[16:24])))
	if size >= mntIDRequestVersionOneSize {
		parts = append(parts, "mnt_ns_id="+formatHexValue(binary.LittleEndian.Uint64(data[24:32])))
	}
	return parts
}

func mntIDRequestSize(ctx *Context) (uint32, bool) {
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex == 0 && section.Kind == PayloadKindStruct &&
			section.Direction == PayloadDirectionIn && section.UserLen == 4 &&
			section.ProbeRet == 0 && len(section.Data) >= 4 {
			return binary.LittleEndian.Uint32(section.Data[:4]), true
		}
	}
	return 0, false
}

func mntIDRequestBase(ctx *Context, size uint32) ([]byte, bool) {
	required := int(size)
	if required > mntIDRequestVersionOneSize {
		required = mntIDRequestVersionOneSize
	}
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex == 0 && section.Kind == PayloadKindStruct &&
			section.Direction == PayloadDirectionIn && section.UserLen > 4 &&
			section.ProbeRet == 0 && len(section.Data) >= required {
			return section.Data[:required], true
		}
	}
	return nil, false
}

func mntIDRequestExtensionParts(ctx *Context, size uint32) []string {
	if size <= mntIDRequestVersionOneSize {
		return nil
	}
	section, ok := mountQueryPayloadSection(ctx, 0, PayloadKindBytes, PayloadDirectionIn)
	if !ok || section.ProbeRet < 0 {
		return []string{"???"}
	}
	data := copiedSectionData(section)
	if lastNonZeroByte(data) < 0 {
		if section.CopiedLen < section.UserLen {
			return []string{"???"}
		}
		return nil
	}
	label := fmt.Sprintf("/* bytes %d..%d */ %s", mntIDRequestVersionOneSize,
		mntIDRequestVersionOneSize+len(data)-1,
		format.BufferEscape(data, len(data), len(data), 2))
	if section.CopiedLen < section.UserLen {
		return []string{label, "???"}
	}
	return []string{label}
}

func mountQueryPayloadSection(ctx *Context, arg int, kind PayloadKind, direction PayloadDirection) (PayloadSection, bool) {
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex == arg && section.Kind == kind && section.Direction == direction {
			return section, true
		}
	}
	return PayloadSection{}, false
}

func copiedSectionData(section PayloadSection) []byte {
	length := int(section.CopiedLen)
	if length > len(section.Data) {
		length = len(section.Data)
	}
	return section.Data[:length]
}

func formatHexValue(value uint64) string {
	if value == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", value)
}
