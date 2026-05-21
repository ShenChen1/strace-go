package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	Register("ioctl", &IoctlHandler{})
}

// IoctlHandler handles the complex formatting for the ioctl syscall.
type IoctlHandler struct {
	DefaultHandler
}

func (h *IoctlHandler) Handle(ctx *Context) Result {
	res := Result{}
	fd := int32(ctx.Args[0])
	cmd := ctx.Args[1]
	arg := ctx.Args[2]

	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", fd))

	cmdpattern := format.Ioc(cmd)
	cmdName := meta.DecodeFlags(cmd, "ioctl_cmds")
	if strings.HasPrefix(cmdName, "0x") {
		cmdName = cmdpattern
	}
	res.ArgParts = append(res.ArgParts, cmdName)

	if arg == 0 {
		if strings.HasPrefix(cmdName, "_IOC") {
			res.ArgParts = append(res.ArgParts, "0")
		} else {
			res.ArgParts = append(res.ArgParts, "NULL")
		}
	} else {
		// Check for DM ioctls
		if strings.HasPrefix(cmdName, "DM_") {
			data := ctx.StrArgBuf[512:1024]
			readSuccess := ctx.ProbeRetEnter >= 0
			
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, arg, 312, false); err == nil && len(d) >= 20 {
				data = d
				readSuccess = true
			}
			
			if readSuccess && len(data) >= 20 {
				dm := formatDmIoctl(ctx, data, cmdName)
				if dm != "" {
					res.ArgParts = append(res.ArgParts, dm)
				} else {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", arg))
				}
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", arg))
			}
		} else {
			switch cmd {
			case 0x5401, 0x5402, 0x5403, 0x5404: // TCGETS, TCSETS, TCSETSW, TCSETSF
				res.ArgParts = append(res.ArgParts, format.Termios(ctx.StrArgBuf[512:512+60]))
			case 0x802c542a, 0x402c542b, 0x402c542c, 0x402c542d: // TCGETS2, TCSETS2, TCSETSW2, TCSETSF2
				res.ArgParts = append(res.ArgParts, format.Termios(ctx.StrArgBuf[512:512+44]))
			case 0x5413: // TIOCGWINSZ
				res.ArgParts = append(res.ArgParts, format.Winsize(ctx.StrArgBuf[512:512+8]))
			case 0x541b: // FIONREAD
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%d]", binary.LittleEndian.Uint32(ctx.StrArgBuf[512:516])))
			default:
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", arg))
			}
		}
	}

	return res
}

func formatDmIoctl(ctx *Context, data []byte, cmd string) string {
	if len(data) < 20 { return "" }
	v0 := binary.LittleEndian.Uint32(data[0:4])
	v1 := binary.LittleEndian.Uint32(data[4:8])
	v2 := binary.LittleEndian.Uint32(data[8:12])
	
	if v0 == 0 && v1 == 0 && v2 == 0 && !strings.Contains(cmd, "VERSION") { return "" }
	
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
		if idx := strings.IndexByte(string(name), 0); idx != -1 { name = name[:idx] }
		res += fmt.Sprintf(", name=%s", format.Buffer(name, ctx.Opts.StringLimit, len(name)))
		
		uuid := data[160:288]
		if idx := strings.IndexByte(string(uuid), 0); idx != -1 { uuid = uuid[:idx] }
		res += fmt.Sprintf(", uuid=%s", format.Buffer(uuid, ctx.Opts.StringLimit, len(uuid)))

		if cmd == "DM_DEV_REMOVE" || cmd == "DM_DEV_WAIT" || cmd == "DM_DEV_SUSPEND" || cmd == "DM_DEV_RENAME" {
			eventNr := binary.LittleEndian.Uint32(data[288:292])
			res += fmt.Sprintf(", event_nr=%d", eventNr)
		}

		flags := binary.LittleEndian.Uint32(data[292:296])
		if flags != 0 || cmd == "DM_VERSION" {
			res += fmt.Sprintf(", flags=%s", meta.DecodeFlags(uint64(flags), "dm_flags"))
		}

		if strings.Contains(cmd, "LOAD") {
			targetCount := binary.LittleEndian.Uint32(data[296:300])
			res += fmt.Sprintf(", target_count=%d", targetCount)
		}
	}

	res += "}]"
	return res
}
