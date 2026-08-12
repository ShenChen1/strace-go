package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
)

const (
	statmountFixedSize  = 512
	statmountMaskSB     = uint64(1 << 0)
	statmountMaskMount  = uint64(1 << 1)
	statmountMaskFrom   = uint64(1 << 2)
	statmountMaskRoot   = uint64(1 << 3)
	statmountMaskPoint  = uint64(1 << 4)
	statmountMaskFS     = uint64(1 << 5)
	statmountMaskNS     = uint64(1 << 6)
	statmountMaskOpts   = uint64(1 << 7)
	statmountMaskSub    = uint64(1 << 8)
	statmountMaskSource = uint64(1 << 9)
	statmountMaskArray  = uint64(1 << 10)
	statmountMaskSec    = uint64(1 << 11)
	statmountMaskAllow  = uint64(1 << 12)
	statmountMaskUID    = uint64(1 << 13)
	statmountMaskGID    = uint64(1 << 14)
	statmountArrayLimit = 32
)

type statmountSnapshot struct {
	data        [statmountFixedSize]byte
	strings     []byte
	stringLimit int
	catalog     format.FlagDecoder
}

func (snapshot statmountSnapshot) decodeFlags(value uint64, tableName string) string {
	return snapshot.catalog.DecodeFlags(value, tableName)
}

type statmountStringArrayField struct {
	mask        uint64
	name        string
	countOffset int
	valueOffset int
}

func formatStatmountOutput(ctx *Context) string {
	userPtr := ctx.Args[1]
	if userPtr == 0 {
		return "NULL"
	}
	if ctx.Args[2] < 4 {
		return formatPointer(userPtr)
	}
	sections := mountQueryStructSections(ctx, 1, PayloadDirectionOut)
	if len(sections) < 2 {
		return formatPointer(userPtr)
	}
	base := sections[len(sections)-1]
	required := int(ctx.Args[2])
	if required > statmountFixedSize {
		required = statmountFixedSize
	}
	if base.ProbeRet < 0 || len(base.Data) < required {
		return formatPointer(userPtr)
	}

	snapshot := statmountSnapshot{}
	snapshot.catalog = catalogForContext(ctx)
	if ctx.Opts != nil {
		snapshot.stringLimit = ctx.Opts.StringLimit
	}
	copy(snapshot.data[:], base.Data)
	if section, ok := mountQueryPayloadSection(ctx, 1, PayloadKindBytes, PayloadDirectionOut); ok && section.ProbeRet == 0 {
		snapshot.strings = copiedSectionData(section)
	}
	return snapshot.format()
}

func mountQueryStructSections(ctx *Context, arg int, direction PayloadDirection) []PayloadSection {
	var sections []PayloadSection
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex == arg && section.Kind == PayloadKindStruct && section.Direction == direction {
			sections = append(sections, section)
		}
	}
	return sections
}

func (snapshot statmountSnapshot) format() string {
	data := snapshot.data[:]
	mask := binary.LittleEndian.Uint64(data[8:16])
	parts := []string{fmt.Sprintf("size=%d", binary.LittleEndian.Uint32(data[0:4]))}
	if mask&statmountMaskOpts != 0 {
		parts = append(parts, "mnt_opts="+snapshot.cstring(binary.LittleEndian.Uint32(data[4:8])))
	}
	parts = append(parts, "mask="+snapshot.decodeFlags(mask, "statmount_mask"))
	parts = snapshot.appendSuperblock(parts, mask)
	parts = snapshot.appendFilesystemType(parts, mask)
	parts = snapshot.appendMount(parts, mask)
	parts = snapshot.appendPostMountFields(parts, mask)
	parts = snapshot.appendArrays(parts, mask)
	return "{" + strings.Join(parts, ", ") + "}"
}

func (snapshot statmountSnapshot) appendFilesystemType(parts []string, mask uint64) []string {
	if mask&statmountMaskFS == 0 {
		return parts
	}
	offset := binary.LittleEndian.Uint32(snapshot.data[36:40])
	return append(parts, "fs_type="+snapshot.cstring(offset))
}

func (snapshot statmountSnapshot) appendSuperblock(parts []string, mask uint64) []string {
	if mask&statmountMaskSB == 0 {
		return parts
	}
	data := snapshot.data[:]
	return append(parts,
		fmt.Sprintf("sb_dev_major=%d", binary.LittleEndian.Uint32(data[16:20])),
		fmt.Sprintf("sb_dev_minor=%d", binary.LittleEndian.Uint32(data[20:24])),
		"sb_magic="+snapshot.decodeFlags(binary.LittleEndian.Uint64(data[24:32]), "fsmagic"),
		"sb_flags="+snapshot.decodeFlags(uint64(binary.LittleEndian.Uint32(data[32:36])), "statmount_sb_flags"))
}

func (snapshot statmountSnapshot) appendMount(parts []string, mask uint64) []string {
	if mask&statmountMaskMount == 0 {
		return parts
	}
	data := snapshot.data[:]
	return append(parts,
		"mnt_id="+formatHexValue(binary.LittleEndian.Uint64(data[40:48])),
		"mnt_parent_id="+formatHexValue(binary.LittleEndian.Uint64(data[48:56])),
		"mnt_id_old="+formatHexValue(uint64(binary.LittleEndian.Uint32(data[56:60]))),
		"mnt_parent_id_old="+formatHexValue(uint64(binary.LittleEndian.Uint32(data[60:64]))),
		"mnt_attr="+snapshot.decodeFlags(binary.LittleEndian.Uint64(data[64:72]), "mount_attr_attr"),
		"mnt_propagation="+snapshot.decodeFlags(binary.LittleEndian.Uint64(data[72:80]), "statmount_mnt_propagation"),
		"mnt_peer_group="+formatHexValue(binary.LittleEndian.Uint64(data[80:88])),
		"mnt_master="+formatHexValue(binary.LittleEndian.Uint64(data[88:96])))
}

func (snapshot statmountSnapshot) appendPostMountFields(parts []string, mask uint64) []string {
	data := snapshot.data[:]
	if mask&statmountMaskFrom != 0 {
		parts = append(parts, "propagate_from="+formatHexValue(binary.LittleEndian.Uint64(data[96:104])))
	}
	fields := []struct {
		mask   uint64
		name   string
		offset int
	}{{statmountMaskRoot, "mnt_root", 104}, {statmountMaskPoint, "mnt_point", 108}}
	for _, field := range fields {
		if mask&field.mask != 0 {
			parts = append(parts, field.name+"="+snapshot.cstring(binary.LittleEndian.Uint32(data[field.offset:field.offset+4])))
		}
	}
	if mask&statmountMaskNS != 0 {
		parts = append(parts, "mnt_ns_id="+formatHexValue(binary.LittleEndian.Uint64(data[112:120])))
	}
	if mask&statmountMaskSub != 0 {
		parts = append(parts, "fs_subtype="+snapshot.cstring(binary.LittleEndian.Uint32(data[120:124])))
	}
	if mask&statmountMaskSource != 0 {
		parts = append(parts, "sb_source="+snapshot.cstring(binary.LittleEndian.Uint32(data[124:128])))
	}
	return parts
}

func (snapshot statmountSnapshot) appendArrays(parts []string, mask uint64) []string {
	data := snapshot.data[:]
	parts = snapshot.appendStringArray(parts, mask, statmountStringArrayField{
		mask: statmountMaskArray, name: "opt", countOffset: 128, valueOffset: 132,
	})
	parts = snapshot.appendStringArray(parts, mask, statmountStringArrayField{
		mask: statmountMaskSec, name: "opt_sec", countOffset: 136, valueOffset: 140,
	})
	if mask&statmountMaskAllow != 0 {
		parts = append(parts, "supported_mask="+snapshot.decodeFlags(binary.LittleEndian.Uint64(data[144:152]), "statmount_mask"))
	}
	parts = snapshot.appendStringArray(parts, mask, statmountStringArrayField{
		mask: statmountMaskUID, name: "mnt_uidmap", countOffset: 152, valueOffset: 156,
	})
	return snapshot.appendStringArray(parts, mask, statmountStringArrayField{
		mask: statmountMaskGID, name: "mnt_gidmap", countOffset: 160, valueOffset: 164,
	})
}

func (snapshot statmountSnapshot) appendStringArray(parts []string, mask uint64, field statmountStringArrayField) []string {
	if mask&field.mask == 0 {
		return parts
	}
	data := snapshot.data[:]
	count := binary.LittleEndian.Uint32(data[field.countOffset : field.countOffset+4])
	offset := binary.LittleEndian.Uint32(data[field.valueOffset : field.valueOffset+4])
	return append(parts, fmt.Sprintf("%s_num=%d", field.name, count), field.name+"="+snapshot.cstringSequence(offset, count))
}

func (snapshot statmountSnapshot) cstring(offset uint32) string {
	if uint64(offset) >= uint64(len(snapshot.strings)) {
		return formatHexValue(uint64(offset))
	}
	data := snapshot.strings[offset:]
	if end := bytesIndexByte(data, 0); end >= 0 {
		return format.Buffer(data[:end], snapshot.stringLimit, end)
	}
	return format.Buffer(data, snapshot.stringLimit, len(data)+1)
}

func (snapshot statmountSnapshot) cstringSequence(offset, count uint32) string {
	if count == 0 {
		return "[]"
	}
	if uint64(offset) >= uint64(len(snapshot.strings)) {
		return formatHexValue(uint64(offset))
	}
	data := snapshot.strings[offset:]
	items := make([]string, 0, minInt(int(count), statmountArrayLimit)+1)
	for index := 0; index < int(count) && index < statmountArrayLimit; index++ {
		if len(data) == 0 {
			items = append(items, "???")
			break
		}
		end := bytesIndexByte(data, 0)
		if end < 0 {
			items = append(items, format.Buffer(data, snapshot.stringLimit, len(data)+1))
			if index+1 < int(count) {
				items = append(items, "???")
			}
			break
		}
		items = append(items, format.Buffer(data[:end], snapshot.stringLimit, end))
		data = data[end+1:]
	}
	if len(items) == statmountArrayLimit && int(count) > statmountArrayLimit {
		items = append(items, "...")
	}
	return "[" + strings.Join(items, ", ") + "]"
}

func bytesIndexByte(data []byte, target byte) int {
	for index, value := range data {
		if value == target {
			return index
		}
	}
	return -1
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
