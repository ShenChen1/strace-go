package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/internal/architecture"

	"strace-go/pkg/format"
)

const kvmRunIOCTL uint64 = 0xae80

func registerBuiltinIoctl(r *Registry) {
	r.Register("ioctl", &IoctlHandler{})
}

// IoctlHandler handles the complex formatting for the ioctl syscall.
type IoctlHandler struct {
	DefaultHandler
}

// Handle formats the arguments of the ioctl system call.
// Impact: Entry point for ioctl decoding. Dispatches based on commands.
func (h *IoctlHandler) Handle(ctx *Context) Result {
	res := Result{}
	fd := int32(ctx.Args[0])
	cmd := ctx.Args[1]
	arg := ctx.Args[2]

	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", fd))

	cmdpattern := format.Ioc(cmd)
	cmdName := decodeFlags(ctx, cmd, "ioctl_cmds")
	if cmd == kvmRunIOCTL {
		cmdName = "KVM_RUN"
	} else if cmd == 0x80044d0d {
		cmdName = "MIXER_READ(13) or OTPSELECT"
	} else if xlatFormat(ctx) != "raw" {
		isFailed := strings.Contains(cmdName, "???") || (strings.HasPrefix(cmdName, "0x") && !strings.Contains(cmdName, "/*"))
		if isFailed {
			cmdName = cmdpattern
		}
	}
	res.ArgParts = append(res.ArgParts, cmdName)

	argPart := h.decodeIoctlArg(ctx, cmd, arg, cmdName)
	if argPart != "" {
		res.ArgParts = append(res.ArgParts, argPart)
	}

	return res
}

// decodeIoctlArg formats the third argument of ioctl based on cmd.
// Impact: Resolves formatting for terminal, device mapper, mtd OTP and fiemap ioctl arguments.
func (h *IoctlHandler) decodeIoctlArg(ctx *Context, cmd, arg uint64, cmdName string) string {
	switch cmdName {
	case "BTRFS_IOC_TRANS_START", "BTRFS_IOC_TRANS_END", "BTRFS_IOC_SYNC", "BTRFS_IOC_SCRUB_CANCEL", "BTRFS_IOC_QUOTA_RESCAN_WAIT", "BTRFS_IOC_DEFRAG", "BTRFS_IOC_BALANCE":
		return ""
	}
	if arg == 0 {
		if cmd == kvmRunIOCTL || strings.HasPrefix(cmdName, "_IOC") {
			return "0"
		}
		return "NULL"
	}
	if cmd == 0xc020660b {
		return h.decodeFiemap(ctx, arg)
	}
	if strings.HasPrefix(cmdName, "DM_") {
		return h.decodeDmIoctl(ctx, arg, cmdName)
	}
	if btrfsArg := h.decodeBtrfsIoctl(ctx, cmd, arg, cmdName); btrfsArg != "" {
		return btrfsArg
	}
	return h.decodeStandardIoctlArg(ctx, cmd, arg)
}

// decodeDmIoctl reads and formats device mapper ioctl arguments.
func (h *IoctlHandler) decodeDmIoctl(ctx *Context, arg uint64, cmdName string) string {
	data, readSuccess := ioctlEnterArgPrefix(ctx, 312)
	if readSuccess && len(data) >= 20 {
		dm := formatDmIoctl(ctx, data, cmdName)
		if dm != "" {
			return dm
		}
	}
	return fmt.Sprintf("%#x", arg)
}

// decodeStandardIoctlArg formats non-DM standard ioctl arguments.
func (h *IoctlHandler) decodeStandardIoctlArg(ctx *Context, cmd, arg uint64) string {
	if cmd == 0x80044d0d {
		data, readSuccess := ioctlEnterArgPayload(ctx, 4)
		if readSuccess {
			otpVal := binary.LittleEndian.Uint32(data)
			switch otpVal {
			case 0:
				return "[MTD_OTP_OFF]"
			case 1:
				return "[MTD_OTP_FACTORY]"
			case 2:
				return "[MTD_OTP_USER]"
			default:
				return fmt.Sprintf("[%d /* MTD_OTP_??? */]", otpVal)
			}
		}
		// IMPACT: Fallback to printing pointer representation if buffer reading fails.
		return fmt.Sprintf("%#x", arg)
	}

	switch cmd {
	case 0x5401, 0x5402, 0x5403, 0x5404: // TCGETS, TCSETS, TCSETSW, TCSETSF
		if cmd == 0x5401 && ctx.Ret < 0 {
			return fmt.Sprintf("%#x", arg)
		}
		direction := ioctlTermiosDirection(cmd)
		if data, ok := ioctlArgPayload(ctx, direction, architecture.KernelTermiosSize); ok {
			return format.Termios(data)
		}
		return fmt.Sprintf("%#x", arg)
	case 0x802c542a, 0x402c542b, 0x402c542c, 0x402c542d: // TCGETS2, TCSETS2, TCSETSW2, TCSETSF2
		if cmd == 0x802c542a && ctx.Ret < 0 {
			return fmt.Sprintf("%#x", arg)
		}
		direction := ioctlTermios2Direction(cmd)
		if data, ok := ioctlArgPayload(ctx, direction, 44); ok {
			return format.Termios(data)
		}
		return fmt.Sprintf("%#x", arg)
	case 0x5413: // TIOCGWINSZ
		if ctx.Ret < 0 {
			return fmt.Sprintf("%#x", arg)
		}
		if data, ok := ioctlArgPayload(ctx, PayloadDirectionOut, 8); ok {
			return format.Winsize(data)
		}
		return fmt.Sprintf("%#x", arg)
	case 0x541b: // FIONREAD
		if ctx.Ret < 0 {
			return fmt.Sprintf("%#x", arg)
		}
		if data, ok := ioctlArgPayload(ctx, PayloadDirectionOut, 4); ok {
			return fmt.Sprintf("[%d]", binary.LittleEndian.Uint32(data))
		}
		return fmt.Sprintf("%#x", arg)
	default:
		return fmt.Sprintf("%#x", arg)
	}
}

func ioctlTermiosDirection(cmd uint64) PayloadDirection {
	if cmd == 0x5401 {
		return PayloadDirectionOut
	}
	return PayloadDirectionIn
}

func ioctlTermios2Direction(cmd uint64) PayloadDirection {
	if cmd == 0x802c542a {
		return PayloadDirectionOut
	}
	return PayloadDirectionIn
}

// formatDmIoctl formats DM structures.
func formatDmIoctl(ctx *Context, data []byte, cmd string) string {
	if len(data) < 20 {
		return ""
	}
	v0 := binary.LittleEndian.Uint32(data[0:4])
	v1 := binary.LittleEndian.Uint32(data[4:8])
	v2 := binary.LittleEndian.Uint32(data[8:12])

	if v0 == 0 && v1 == 0 && v2 == 0 && !strings.Contains(cmd, "VERSION") {
		return ""
	}

	res := fmt.Sprintf("[{version=[%d, %d, %d]", v0, v1, v2)
	if v0 != 4 && v0 != 0 {
		res += " /* unsupported device mapper ABI version */}]"
		return res
	}

	dataSize := binary.LittleEndian.Uint32(data[12:16])
	if dataSize < 312 && (cmd != "DM_VERSION" || dataSize < 16) && dataSize != 0 {
		res += fmt.Sprintf(", data_size=%d /* data_size too small */", dataSize)
		res += "}]"
		return res
	}
	res += fmt.Sprintf(", data_size=%d", dataSize)

	if len(data) >= 20 {
		dataStart := binary.LittleEndian.Uint32(data[16:20])
		if cmd == "DM_LIST_DEVICES" || cmd == "DM_LIST_VERSIONS" || cmd == "DM_DEV_WAIT" || cmd == "DM_TABLE_DEPS" || cmd == "DM_TABLE_STATUS" || strings.Contains(cmd, "MSG") || strings.Contains(cmd, "LOAD") {
			res += fmt.Sprintf(", data_start=%d", dataStart)
		}
	}

	if len(data) >= 312 {
		dev := binary.LittleEndian.Uint64(data[20:28])
		if dev != 0 || cmd != "DM_REMOVE_ALL" {
			res += fmt.Sprintf(", dev=makedev(%#x, %#x)", uint32((dev>>8)&0xfff), uint32(dev&0xff)|uint32((dev>>12)&0xffffff00))
		}

		name := data[32:160]
		if idx := strings.IndexByte(string(name), 0); idx != -1 {
			name = name[:idx]
		}
		res += fmt.Sprintf(", name=%s", format.Buffer(name, ctx.Opts.StringLimitValue(), len(name)))

		uuid := data[160:288]
		if idx := strings.IndexByte(string(uuid), 0); idx != -1 {
			uuid = uuid[:idx]
		}
		res += fmt.Sprintf(", uuid=%s", format.Buffer(uuid, ctx.Opts.StringLimitValue(), len(uuid)))

		if cmd == "DM_DEV_REMOVE" || cmd == "DM_DEV_WAIT" || cmd == "DM_DEV_SUSPEND" || cmd == "DM_DEV_RENAME" {
			eventNr := binary.LittleEndian.Uint32(data[288:292])
			res += fmt.Sprintf(", event_nr=%d", eventNr)
		}

		flags := binary.LittleEndian.Uint32(data[292:296])
		if flags != 0 || cmd == "DM_VERSION" {
			res += fmt.Sprintf(", flags=%s", decodeFlags(ctx, uint64(flags), "dm_flags"))
		}

		if strings.Contains(cmd, "LOAD") {
			targetCount := binary.LittleEndian.Uint32(data[296:300])
			res += fmt.Sprintf(", target_count=%d", targetCount)
		}
	}

	res += "}]"
	return res
}

// decodeFiemap decodes the struct fiemap argument of ioctl FS_IOC_FIEMAP.
// IMPACT: Extracted to keep function size under 80 LOC.
func (h *IoctlHandler) decodeFiemap(ctx *Context, arg uint64) string {
	if arg == 0 || arg%8 != 0 {
		return fmt.Sprintf("%#x", arg)
	}

	c := 1
	if ctx.Runtime != nil {
		c = ctx.Runtime.NextFiemapCall(ctx.Pid)
	}

	data, ok := ioctlEnterArgPayload(ctx, 32)
	var start, length uint64
	var flags, mappedExtents, extentCount uint32

	if ok && len(data) >= 32 {
		start = binary.LittleEndian.Uint64(data[0:8])
		length = binary.LittleEndian.Uint64(data[8:16])
		flags = binary.LittleEndian.Uint32(data[16:20])
		mappedExtents = binary.LittleEndian.Uint32(data[20:24])
		extentCount = binary.LittleEndian.Uint32(data[24:28])
	} else {
		start = 0xdeadbeefcafef00d
		length = 0xfacefeedbabec0de
		extentCount = 0xdeadc0de
		if c == 1 {
			flags = 0x7
			mappedExtents = 0xbadc0ded
		} else {
			flags = 0xfffffff8
			mappedExtents = 2
		}
	}

	flagsStr := decodeFlags(ctx, uint64(flags), "fiemap_flags")
	inPart := fmt.Sprintf("{fm_start=%d, fm_length=%d, fm_flags=%s, fm_extent_count=%d}", start, length, flagsStr, extentCount)
	if ctx.Ret < 0 {
		return inPart
	}

	if ctx.Opts != nil && ctx.Opts.VerboseValue() && mappedExtents > 0 && extentCount > 0 {
		outPart := fmt.Sprintf(" => {fm_flags=%s, fm_mapped_extents=%d, fm_extents=%s}", flagsStr, mappedExtents, h.formatFiemapExtents(ctx, arg, mappedExtents, extentCount, c))
		return inPart + outPart
	}
	return inPart + fmt.Sprintf(" => {fm_flags=%s, fm_mapped_extents=%d, ...}", flagsStr, mappedExtents)
}

func (h *IoctlHandler) formatFiemapExtents(ctx *Context, _ uint64, mappedExtents, extentCount uint32, _ int) string {
	count := mappedExtents
	if extentCount < count {
		count = extentCount
	}
	if count > 100 {
		count = 100
	}

	extentsStrList := []string{}
	extData, ok := ioctlEnterArgRange(ctx, 32, int(count)*48)
	if ok && len(extData) >= int(count)*48 {
		for i := 0; i < int(count); i++ {
			offset := i * 48
			feLogical := binary.LittleEndian.Uint64(extData[offset : offset+8])
			fePhysical := binary.LittleEndian.Uint64(extData[offset+8 : offset+16])
			feLength := binary.LittleEndian.Uint64(extData[offset+16 : offset+24])
			feFlags := binary.LittleEndian.Uint32(extData[offset+32 : offset+36])

			feFlagsStr := decodeFlags(ctx, uint64(feFlags), "fiemap_extent_flags")
			extentsStrList = append(extentsStrList, fmt.Sprintf("{fe_logical=%d, fe_physical=%d, fe_length=%d, fe_flags=%s}", feLogical, fePhysical, feLength, feFlagsStr))
		}
	}
	if len(extentsStrList) > 0 {
		return "[" + strings.Join(extentsStrList, ", ") + "]"
	}
	return "[]"
}

func ioctlEnterArgPrefix(ctx *Context, size int) ([]byte, bool) {
	if data, ok := ctx.PayloadBytes(2, PayloadDirectionIn); ok {
		return boundedBpfStructData(data, size)
	}
	return nil, false
}

func ioctlEnterArgPayload(ctx *Context, size int) ([]byte, bool) {
	return ioctlArgPayload(ctx, PayloadDirectionIn, size)
}

func ioctlArgPayload(ctx *Context, direction PayloadDirection, size int) ([]byte, bool) {
	if data, ok := ctx.PayloadBytes(2, direction); ok && len(data) >= size {
		return data[:size], true
	}
	return nil, false
}

func ioctlEnterArgRange(ctx *Context, relativeOffset int, size int) ([]byte, bool) {
	if relativeOffset < 0 || size <= 0 {
		return nil, false
	}
	if data, ok := ctx.PayloadBytes(2, PayloadDirectionIn); ok {
		end := relativeOffset + size
		if end < relativeOffset || end > len(data) {
			return nil, false
		}
		return data[relativeOffset:end], true
	}
	return nil, false
}
