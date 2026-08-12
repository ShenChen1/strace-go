package handler

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	quotaXFSOn        = uint32(0x5801)
	quotaXFSOff       = uint32(0x5802)
	quotaXFSGetQuota  = uint32(0x5803)
	quotaXFSSetQLim   = uint32(0x5804)
	quotaXFSGetQStat  = uint32(0x5805)
	quotaXFSQuotaRm   = uint32(0x5806)
	quotaXFSQuotaSync = uint32(0x5807)
	quotaXFSGetQStatV = uint32(0x5808)
	quotaXFSGetNext   = uint32(0x5809)

	quotaXFSDiskSize  = 112
	quotaXFSStatSize  = 80
	quotaXFSStatVSize = 160
)

func quotaXFSCommandData(ctx *Context, command uint32) ([]string, bool) {
	switch command {
	case quotaXFSOn, quotaXFSOff:
		return []string{formatQuotaXFSFlagsPointer(ctx, "xfs_quota_flags", "FS_QUOTA_???")}, true
	case quotaXFSQuotaRm:
		return []string{formatQuotaXFSFlagsPointer(ctx, "xfs_dqblk_flags", "FS_???_QUOTA")}, true
	case quotaXFSQuotaSync:
		return nil, true
	case quotaXFSSetQLim:
		return []string{formatQuotaID(ctx.Args[2]), formatQuotaXFSDiskPointer(ctx, PayloadDirectionIn)}, true
	case quotaXFSGetQuota, quotaXFSGetNext:
		return []string{formatQuotaID(ctx.Args[2]), formatQuotaXFSDiskPointer(ctx, PayloadDirectionOut)}, true
	case quotaXFSGetQStat:
		return []string{formatQuotaXFSStatPointer(ctx)}, true
	case quotaXFSGetQStatV:
		return []string{formatQuotaXFSStatVPointer(ctx)}, true
	default:
		return nil, false
	}
}

func formatQuotaXFSFlagsPointer(ctx *Context, tableName string, unknown string) string {
	data, ok := ctx.PayloadStruct(3, PayloadDirectionIn)
	if !ok || len(data) < 4 {
		return formatPointer(ctx.Args[3])
	}
	value := binary.LittleEndian.Uint32(data[:4])
	return "[" + formatQuotaFlags(ctx, value, tableName, unknown) + "]"
}

func formatQuotaXFSDiskPointer(ctx *Context, direction PayloadDirection) string {
	if direction == PayloadDirectionOut && ctx.Ret < 0 {
		return formatPointer(ctx.Args[3])
	}
	data, ok := ctx.PayloadStruct(3, direction)
	if !ok || len(data) < quotaXFSDiskSize {
		return formatPointer(ctx.Args[3])
	}
	parts := quotaXFSDiskCoreFields(ctx, data)
	if !quotaXFSVerbose(ctx) {
		return "{" + strings.Join(append(parts, "..."), ", ") + "}"
	}
	parts = append(parts,
		fmt.Sprintf("d_itimer=%d", int32(binary.LittleEndian.Uint32(data[56:60]))),
		fmt.Sprintf("d_btimer=%d", int32(binary.LittleEndian.Uint32(data[60:64]))),
		fmt.Sprintf("d_iwarns=%d", binary.LittleEndian.Uint16(data[64:66])),
		fmt.Sprintf("d_bwarns=%d", binary.LittleEndian.Uint16(data[66:68])),
		fmt.Sprintf("d_rtb_hardlimit=%d", binary.LittleEndian.Uint64(data[72:80])),
		fmt.Sprintf("d_rtb_softlimit=%d", binary.LittleEndian.Uint64(data[80:88])),
		fmt.Sprintf("d_rtbcount=%d", binary.LittleEndian.Uint64(data[88:96])),
		fmt.Sprintf("d_rtbtimer=%d", int32(binary.LittleEndian.Uint32(data[96:100]))),
		fmt.Sprintf("d_rtbwarns=%d", binary.LittleEndian.Uint16(data[100:102])),
	)
	return "{" + strings.Join(parts, ", ") + "}"
}

func quotaXFSDiskCoreFields(ctx *Context, data []byte) []string {
	parts := []string{
		fmt.Sprintf("d_version=%d", int8(data[0])),
		"d_flags=" + formatQuotaFlags(ctx, uint32(data[1]), "xfs_dqblk_flags", "FS_???_QUOTA"),
		fmt.Sprintf("d_fieldmask=%#x", binary.LittleEndian.Uint16(data[2:4])),
		fmt.Sprintf("d_id=%d", binary.LittleEndian.Uint32(data[4:8])),
	}
	names := []string{
		"d_blk_hardlimit", "d_blk_softlimit", "d_ino_hardlimit",
		"d_ino_softlimit", "d_bcount", "d_icount",
	}
	for index, name := range names {
		offset := 8 + index*8
		parts = append(parts, fmt.Sprintf("%s=%d", name, binary.LittleEndian.Uint64(data[offset:offset+8])))
	}
	return parts
}

func formatQuotaXFSStatPointer(ctx *Context) string {
	data, ok := quotaXFSOutputStruct(ctx, quotaXFSStatSize)
	if !ok {
		return formatPointer(ctx.Args[3])
	}
	parts := []string{fmt.Sprintf("qs_version=%d", int8(data[0]))}
	if !quotaXFSVerbose(ctx) {
		return "{" + strings.Join(append(parts, "..."), ", ") + "}"
	}
	parts = append(parts,
		"qs_flags="+formatQuotaFlags(ctx, uint32(binary.LittleEndian.Uint16(data[2:4])), "xfs_quota_flags", "FS_QUOTA_???"),
		"qs_uquota="+formatQuotaXFSFileStat(data[8:32]),
		"qs_gquota="+formatQuotaXFSFileStat(data[32:56]),
		fmt.Sprintf("qs_incoredqs=%d", binary.LittleEndian.Uint32(data[56:60])),
		fmt.Sprintf("qs_btimelimit=%d", int32(binary.LittleEndian.Uint32(data[60:64]))),
		fmt.Sprintf("qs_itimelimit=%d", int32(binary.LittleEndian.Uint32(data[64:68]))),
		fmt.Sprintf("qs_rtbtimelimit=%d", int32(binary.LittleEndian.Uint32(data[68:72]))),
		fmt.Sprintf("qs_bwarnlimit=%d", binary.LittleEndian.Uint16(data[72:74])),
		fmt.Sprintf("qs_iwarnlimit=%d", binary.LittleEndian.Uint16(data[74:76])),
	)
	return "{" + strings.Join(parts, ", ") + "}"
}

func formatQuotaXFSStatVPointer(ctx *Context) string {
	data, ok := quotaXFSOutputStruct(ctx, quotaXFSStatVSize)
	if !ok {
		return formatPointer(ctx.Args[3])
	}
	parts := []string{fmt.Sprintf("qs_version=%d", int8(data[0]))}
	if !quotaXFSVerbose(ctx) {
		return "{" + strings.Join(append(parts, "..."), ", ") + "}"
	}
	parts = append(parts,
		"qs_flags="+formatQuotaFlags(ctx, uint32(binary.LittleEndian.Uint16(data[2:4])), "xfs_quota_flags", "FS_QUOTA_???"),
		fmt.Sprintf("qs_incoredqs=%d", binary.LittleEndian.Uint32(data[4:8])),
		"qs_uquota="+formatQuotaXFSFileStat(data[8:32]),
		"qs_gquota="+formatQuotaXFSFileStat(data[32:56]),
		"qs_pquota="+formatQuotaXFSFileStat(data[56:80]),
		fmt.Sprintf("qs_btimelimit=%d", int32(binary.LittleEndian.Uint32(data[80:84]))),
		fmt.Sprintf("qs_itimelimit=%d", int32(binary.LittleEndian.Uint32(data[84:88]))),
		fmt.Sprintf("qs_rtbtimelimit=%d", int32(binary.LittleEndian.Uint32(data[88:92]))),
		fmt.Sprintf("qs_bwarnlimit=%d", binary.LittleEndian.Uint16(data[92:94])),
		fmt.Sprintf("qs_iwarnlimit=%d", binary.LittleEndian.Uint16(data[94:96])),
	)
	return "{" + strings.Join(parts, ", ") + "}"
}

func quotaXFSOutputStruct(ctx *Context, size int) ([]byte, bool) {
	if ctx.Ret < 0 {
		return nil, false
	}
	data, ok := ctx.PayloadStruct(3, PayloadDirectionOut)
	return data, ok && len(data) >= size
}

func formatQuotaXFSFileStat(data []byte) string {
	return fmt.Sprintf(
		"{qfs_ino=%d, qfs_nblks=%d, qfs_nextents=%d}",
		binary.LittleEndian.Uint64(data[0:8]),
		binary.LittleEndian.Uint64(data[8:16]),
		binary.LittleEndian.Uint32(data[16:20]),
	)
}

func quotaXFSVerbose(ctx *Context) bool {
	return ctx.Opts != nil && ctx.Opts.VerboseValue()
}
