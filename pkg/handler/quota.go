package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

const (
	quotaCommandShift = 8
	quotaTypeMask     = 0xff

	quotaSync         = uint32(0x800001)
	quotaOn           = uint32(0x800002)
	quotaOff          = uint32(0x800003)
	quotaGetFmt       = uint32(0x800004)
	quotaGetInfo      = uint32(0x800005)
	quotaSetInfo      = uint32(0x800006)
	quotaGetQuota     = uint32(0x800007)
	quotaSetQuota     = uint32(0x800008)
	quotaGetNextQuota = uint32(0x800009)

	quotaDqblkSize  = 68
	quotaDqinfoSize = 24
)

// QuotaHandler owns command-dependent quota argument direction and layout.
type QuotaHandler struct {
	DefaultHandler
}

func init() {
	handler := &QuotaHandler{}
	Register("quotactl", handler)
	Register("quotactl_fd", handler)
}

// Handle formats standard Linux quota commands from probe-time snapshots.
func (h *QuotaHandler) Handle(ctx *Context) Result {
	fdVariant := ctx.SysName == "quotactl_fd"
	commandIndex := 0
	if fdVariant {
		commandIndex = 1
	}
	qcmd := uint32(ctx.Args[commandIndex])
	command := qcmd >> quotaCommandShift
	parts := make([]string, 0, 4)
	if fdVariant {
		parts = append(parts, h.formatFdArg(ctx, "fd", ctx.Args[0]))
	}
	parts = append(parts, formatQuotaCommand(ctx, qcmd))
	if !fdVariant {
		parts = append(parts, quotaPath(ctx, 1))
	}
	parts = append(parts, quotaCommandData(ctx, command)...)
	return Result{ArgParts: parts}
}

func quotaCommandData(ctx *Context, command uint32) []string {
	switch command {
	case quotaSync, quotaOff:
		return nil
	case quotaOn:
		return []string{formatQuotaXlat(ctx, uint32(ctx.Args[2]), "quota_formats", "QFMT_???"), quotaPath(ctx, 3)}
	case quotaGetFmt:
		return []string{formatQuotaFormatPointer(ctx)}
	case quotaGetInfo:
		return []string{formatQuotaInfoPointer(ctx, PayloadDirectionOut)}
	case quotaSetInfo:
		return []string{formatQuotaInfoPointer(ctx, PayloadDirectionIn)}
	case quotaGetQuota:
		return []string{formatQuotaID(ctx.Args[2]), formatQuotaBlockPointer(ctx, PayloadDirectionOut, false)}
	case quotaSetQuota:
		return []string{formatQuotaID(ctx.Args[2]), formatQuotaBlockPointer(ctx, PayloadDirectionIn, false)}
	case quotaGetNextQuota:
		return []string{formatQuotaID(ctx.Args[2]), formatQuotaBlockPointer(ctx, PayloadDirectionOut, true)}
	default:
		return []string{formatQuotaID(ctx.Args[2]), formatPointer(ctx.Args[3])}
	}
}

func formatQuotaCommand(ctx *Context, qcmd uint32) string {
	command := qcmd >> quotaCommandShift
	quotaType := qcmd & quotaTypeMask
	decoded := fmt.Sprintf(
		"QCMD(%s, %s)",
		formatQuotaDecodedValue(command, "quotacmds", "Q_???"),
		formatQuotaDecodedValue(quotaType, "quotatypes", "???QUOTA"),
	)
	switch quotaXlatMode(ctx) {
	case "raw":
		return fmt.Sprintf("%d", qcmd)
	case "verbose":
		return fmt.Sprintf("%d /* %s */", qcmd, decoded)
	default:
		return decoded
	}
}

func formatQuotaDecodedValue(value uint32, tableName string, unknown string) string {
	if name, ok := quotaXlatName(tableName, uint64(value)); ok {
		return name
	}
	return fmt.Sprintf("%s /* %s */", quotaRawValue(value), unknown)
}

func formatQuotaXlat(ctx *Context, value uint32, tableName string, unknown string) string {
	name, ok := quotaXlatName(tableName, uint64(value))
	mode := quotaXlatMode(ctx)
	if mode == "raw" {
		return quotaRawValue(value)
	}
	if !ok {
		return fmt.Sprintf("%s /* %s */", quotaRawValue(value), unknown)
	}
	if mode == "verbose" {
		return fmt.Sprintf("%s /* %s */", quotaRawValue(value), name)
	}
	return name
}

func quotaXlatName(tableName string, value uint64) (string, bool) {
	table, ok := meta.XlatTables[tableName]
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

func quotaXlatMode(ctx *Context) string {
	if ctx != nil && ctx.Opts != nil && ctx.Opts.XlatFormat != "" {
		return ctx.Opts.XlatFormat
	}
	return "abbrev"
}

func quotaRawValue(value uint32) string {
	if value == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", value)
}

func quotaPath(ctx *Context, argIndex int) string {
	ptr := ctx.Args[argIndex]
	if text, ok := ctx.PayloadString(argIndex, PayloadDirectionIn, ptr, 0); ok {
		return text
	}
	return formatPointer(ptr)
}

func formatQuotaID(value uint64) string {
	id := uint32(value)
	if id == ^uint32(0) {
		return "-1"
	}
	return fmt.Sprintf("%d", id)
}

func formatQuotaFormatPointer(ctx *Context) string {
	data, ok := ctx.PayloadStruct(3, PayloadDirectionOut)
	if ctx.Ret < 0 || !ok || len(data) < 4 {
		return formatPointer(ctx.Args[3])
	}
	value := binary.LittleEndian.Uint32(data[:4])
	return "[" + formatQuotaXlat(ctx, value, "quota_formats", "QFMT_???") + "]"
}

func formatQuotaBlockPointer(ctx *Context, direction PayloadDirection, includeID bool) string {
	if direction == PayloadDirectionOut && ctx.Ret < 0 {
		return formatPointer(ctx.Args[3])
	}
	data, ok := ctx.PayloadStruct(3, direction)
	if !ok || len(data) < quotaDqblkSize {
		return formatPointer(ctx.Args[3])
	}
	values := make([]uint64, 8)
	for index := range values {
		values[index] = binary.LittleEndian.Uint64(data[index*8 : index*8+8])
	}
	parts := quotaBlockFields(values)
	if ctx.Opts == nil || !ctx.Opts.Verbose {
		if includeID {
			if len(data) < 72 {
				return formatPointer(ctx.Args[3])
			}
			parts = append(parts, fmt.Sprintf("dqb_id=%d", binary.LittleEndian.Uint32(data[68:72])))
		}
		parts = append(parts, "...")
		return "{" + strings.Join(parts, ", ") + "}"
	}
	parts = append(parts,
		fmt.Sprintf("dqb_btime=%d", values[6]),
		fmt.Sprintf("dqb_itime=%d", values[7]),
		"dqb_valid="+formatQuotaFlags(ctx, binary.LittleEndian.Uint32(data[64:68]), "if_dqblk_valid", "QIF_???"),
	)
	if includeID {
		if len(data) < 72 {
			return formatPointer(ctx.Args[3])
		}
		parts = append(parts, fmt.Sprintf("dqb_id=%d", binary.LittleEndian.Uint32(data[68:72])))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func quotaBlockFields(values []uint64) []string {
	names := []string{
		"dqb_bhardlimit", "dqb_bsoftlimit", "dqb_curspace",
		"dqb_ihardlimit", "dqb_isoftlimit", "dqb_curinodes",
	}
	parts := make([]string, 0, len(names)+4)
	for index, name := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", name, values[index]))
	}
	return parts
}

func formatQuotaInfoPointer(ctx *Context, direction PayloadDirection) string {
	data, ok := ctx.PayloadStruct(3, direction)
	if !ok || len(data) < quotaDqinfoSize {
		return formatPointer(ctx.Args[3])
	}
	bgrace := binary.LittleEndian.Uint64(data[0:8])
	igrace := binary.LittleEndian.Uint64(data[8:16])
	flags := binary.LittleEndian.Uint32(data[16:20])
	valid := binary.LittleEndian.Uint32(data[20:24])
	return fmt.Sprintf(
		"{dqi_bgrace=%d, dqi_igrace=%d, dqi_flags=%s, dqi_valid=%s}",
		bgrace,
		igrace,
		formatQuotaFlags(ctx, flags, "if_dqinfo_flags", "DQF_???"),
		formatQuotaFlags(ctx, valid, "if_dqinfo_valid", "IIF_???"),
	)
}

func formatQuotaFlags(ctx *Context, value uint32, tableName string, unknown string) string {
	raw := quotaRawValue(value)
	if quotaXlatMode(ctx) == "raw" {
		return raw
	}
	decoded := quotaFlagNames(value, tableName, unknown)
	if quotaXlatMode(ctx) == "verbose" {
		return fmt.Sprintf("%s /* %s */", raw, decoded)
	}
	return decoded
}

func quotaFlagNames(value uint32, tableName string, unknown string) string {
	if value == 0 {
		return "0"
	}
	remaining := uint64(value)
	parts := make([]string, 0, 4)
	for _, entry := range meta.XlatTables[tableName].Entries {
		if entry.Val != 0 && remaining&entry.Val == entry.Val {
			parts = append(parts, entry.Str)
			remaining &^= entry.Val
		}
	}
	if remaining != 0 {
		remainingText := fmt.Sprintf("%#x", remaining)
		if len(parts) == 0 {
			remainingText += fmt.Sprintf(" /* %s */", unknown)
		}
		parts = append(parts, remainingText)
	}
	return strings.Join(parts, "|")
}
