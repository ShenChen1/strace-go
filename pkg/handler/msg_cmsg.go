package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
)

const (
	cmsgHeaderSize        = 16
	cmsgAlignSize         = 8
	cmsgUcredSize         = 12
	cmsgTimeSize          = 16
	cmsgTimestampingCount = 3
	cmsgArrayDisplayLimit = 32
	solIP                 = 0
	solSocket             = 1
	solTCP                = 6
	ipTOS                 = 1
	ipTTL                 = 2
	ipRecvOpts            = 6
	ipRetOpts             = 7
	ipPktinfo             = 8
	ipRecvErr             = 11
	ipOrigDstAddr         = 20
	ipChecksum            = 23
	ipProtocol            = 52
	scmRights             = 1
	scmCredentials        = 2
	scmSecurity           = 3
	soTimestampOld        = 29
	soTimestampNSOld      = 35
	soTimestampingOld     = 37
	soTimestampNew        = 63
	soTimestampNSNew      = 64
	soTimestampingNew     = 65
)

func formatControlMessages(ctx *Context, controlPtr uint64, controlLen uint64, data []byte) (string, bool) {
	items := make([]string, 0, 2)
	limit := len(data)
	if controlLen < uint64(limit) {
		limit = int(controlLen)
	}
	offset := 0
	stoppedMalformed := false
	for offset+cmsgHeaderSize <= limit {
		item, cmsgLen, ok := formatControlMessage(ctx, data[offset:limit])
		if !ok {
			break
		}
		items = append(items, item)
		if cmsgLen < cmsgHeaderSize {
			offset += cmsgHeaderSize
			stoppedMalformed = true
			break
		}
		next := alignCmsgLen(cmsgLen)
		if next < cmsgHeaderSize || offset+next <= offset {
			break
		}
		offset += next
		if uint64(offset)+cmsgHeaderSize > controlLen {
			break
		}
	}
	if len(items) == 0 {
		return "", false
	}
	res := "[" + strings.Join(items, ", ")
	if (stoppedMalformed || offset+cmsgHeaderSize > limit) && uint64(offset) < controlLen && uint64(offset) <= uint64(len(data)) {
		res += fmt.Sprintf(", ... /* %#x */", controlPtr+uint64(offset))
	} else if uint64(len(data)) < controlLen {
		res += ", ..."
	}
	return res + "]", true
}

func formatControlMessage(ctx *Context, data []byte) (string, int, bool) {
	if len(data) < cmsgHeaderSize {
		return "", 0, false
	}
	cmsgLen := int(binary.LittleEndian.Uint64(data[0:8]))
	level := int32(binary.LittleEndian.Uint32(data[8:12]))
	cmsgType := int32(binary.LittleEndian.Uint32(data[12:16]))
	if cmsgLen < cmsgHeaderSize {
		return fmt.Sprintf("{cmsg_len=%d, cmsg_level=%s, cmsg_type=%s}",
			cmsgLen,
			formatCmsgLevel(level),
			formatCmsgType(level, cmsgType)), cmsgLen, true
	}
	copiedLen := cmsgLen
	if copiedLen > len(data) {
		copiedLen = len(data)
	}
	payload := data[cmsgHeaderSize:copiedLen]
	return fmt.Sprintf("{cmsg_len=%d, cmsg_level=%s, cmsg_type=%s%s}",
		cmsgLen,
		formatCmsgLevel(level),
		formatCmsgType(level, cmsgType),
		formatCmsgData(ctx, level, cmsgType, payload)), cmsgLen, true
}

func alignCmsgLen(length int) int {
	if length <= cmsgHeaderSize {
		return cmsgHeaderSize
	}
	return (length + cmsgAlignSize - 1) & ^(cmsgAlignSize - 1)
}

func formatCmsgLevel(level int32) string {
	switch level {
	case solIP:
		return "SOL_IP"
	case solSocket:
		return "SOL_SOCKET"
	case solTCP:
		return "SOL_TCP"
	default:
		return fmt.Sprintf("%#x", uint32(level))
	}
}

func formatCmsgType(level int32, cmsgType int32) string {
	if level != solSocket {
		if level == solIP {
			return formatIPCmsgType(cmsgType)
		}
		return fmt.Sprintf("%#x", uint32(cmsgType))
	}
	switch cmsgType {
	case scmRights:
		return "SCM_RIGHTS"
	case scmCredentials:
		return "SCM_CREDENTIALS"
	case scmSecurity:
		return "SCM_SECURITY"
	case soTimestampOld:
		return "SO_TIMESTAMP_OLD"
	case soTimestampNSOld:
		return "SO_TIMESTAMPNS_OLD"
	case soTimestampingOld:
		return "SO_TIMESTAMPING_OLD"
	case soTimestampNew:
		return "SO_TIMESTAMP_NEW"
	case soTimestampNSNew:
		return "SO_TIMESTAMPNS_NEW"
	case soTimestampingNew:
		return "SO_TIMESTAMPING_NEW"
	default:
		return fmt.Sprintf("%#x /* SCM_??? */", uint32(cmsgType))
	}
}

func formatIPCmsgType(cmsgType int32) string {
	switch cmsgType {
	case ipTOS:
		return "IP_TOS"
	case ipTTL:
		return "IP_TTL"
	case ipRecvOpts:
		return "IP_RECVOPTS"
	case ipRetOpts:
		return "IP_RETOPTS"
	case ipPktinfo:
		return "IP_PKTINFO"
	case ipRecvErr:
		return "IP_RECVERR"
	case ipOrigDstAddr:
		return "IP_ORIGDSTADDR"
	case ipChecksum:
		return "IP_CHECKSUM"
	case ipProtocol:
		return "IP_PROTOCOL"
	case scmSecurity:
		return "SCM_SECURITY"
	default:
		return fmt.Sprintf("%#x /* IP_??? */", uint32(cmsgType))
	}
}

func formatCmsgData(ctx *Context, level int32, cmsgType int32, data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if level == solIP {
		return formatIPCmsgData(ctx, cmsgType, data)
	}
	if level == solSocket && cmsgType == scmRights {
		return ", cmsg_data=" + formatCmsgRights(data)
	}
	if level == solSocket && cmsgType == scmCredentials && len(data) >= cmsgUcredSize {
		return ", cmsg_data=" + formatCmsgCredentials(data)
	}
	if level == solSocket && cmsgType == scmSecurity {
		return ", cmsg_data=" + formatCmsgText(ctx, data)
	}
	if level == solSocket && (cmsgType == soTimestampOld || cmsgType == soTimestampNew) {
		return ", cmsg_data=" + formatCmsgTime(data, format.Timeval)
	}
	if level == solSocket && (cmsgType == soTimestampNSOld || cmsgType == soTimestampNSNew) {
		return ", cmsg_data=" + formatCmsgTime(data, format.Timespec)
	}
	if level == solSocket && (cmsgType == soTimestampingOld || cmsgType == soTimestampingNew) {
		return ", cmsg_data=" + formatCmsgTimestamping(data)
	}
	return ", cmsg_data=" + formatCmsgHex(data)
}

func formatIPCmsgData(ctx *Context, cmsgType int32, data []byte) string {
	switch cmsgType {
	case ipPktinfo:
		if len(data) >= 12 {
			return ", cmsg_data=" + formatIPCmsgPktinfo(data)
		}
	case ipTTL, ipChecksum:
		if len(data) >= 4 {
			return ", cmsg_data=" + formatCmsgUintArray(data)
		}
	case ipRecvErr:
		if len(data) >= 32 {
			return ", cmsg_data=" + formatCmsgIPRecvErr(data)
		}
	case ipTOS, ipRecvOpts, ipRetOpts:
		return ", cmsg_data=" + formatCmsgXint8Array(data)
	case ipOrigDstAddr:
		if len(data) >= 16 {
			return ", cmsg_data=" + format.Sockaddr(data, uint32(len(data)), uint32(len(data)))
		}
	case ipProtocol:
		if len(data) >= 4 {
			return ", cmsg_data=" + formatCmsgProtocolArray(data)
		}
	case scmSecurity:
		return ", cmsg_data=" + formatCmsgText(ctx, data)
	}
	return ", cmsg_data=" + formatCmsgHex(data)
}

func formatIPCmsgPktinfo(data []byte) string {
	return fmt.Sprintf("{ipi_ifindex=%s, ipi_spec_dst=inet_addr(%q), ipi_addr=inet_addr(%q)}",
		translateIfindex(binary.LittleEndian.Uint32(data[0:4])),
		formatIPv4(data[4:8]),
		formatIPv4(data[8:12]))
}

func formatIPv4(data []byte) string {
	if len(data) < 4 {
		return "0.0.0.0"
	}
	return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
}

func formatCmsgIPRecvErr(data []byte) string {
	return fmt.Sprintf("{ee_errno=%d, ee_origin=%d, ee_type=%d, ee_code=%d, ee_info=%d, ee_data=%d, offender=%s}",
		binary.LittleEndian.Uint32(data[0:4]),
		data[4],
		data[5],
		data[6],
		binary.LittleEndian.Uint32(data[8:12]),
		binary.LittleEndian.Uint32(data[12:16]),
		format.Sockaddr(data[16:32], 16, 16))
}

func formatCmsgUintArray(data []byte) string {
	count := len(data) / 4
	items := make([]string, 0, count)
	for i := 0; i < count; i++ {
		offset := i * 4
		items = append(items, fmt.Sprintf("%d", binary.LittleEndian.Uint32(data[offset:offset+4])))
	}
	return "[" + strings.Join(items, ", ") + "]"
}

func formatCmsgXint8Array(data []byte) string {
	displayCount := len(data)
	truncated := false
	if displayCount > cmsgArrayDisplayLimit {
		displayCount = cmsgArrayDisplayLimit
		truncated = true
	}
	items := make([]string, 0, displayCount+1)
	for i := 0; i < displayCount; i++ {
		items = append(items, fmt.Sprintf("0x%02x", data[i]))
	}
	if truncated {
		items = append(items, "...")
	}
	return "[" + strings.Join(items, ", ") + "]"
}

func formatCmsgProtocolArray(data []byte) string {
	count := len(data) / 4
	items := make([]string, 0, count)
	for i := 0; i < count; i++ {
		offset := i * 4
		protocol := binary.LittleEndian.Uint32(data[offset : offset+4])
		if protocol == 255 {
			items = append(items, "IPPROTO_RAW")
			continue
		}
		items = append(items, fmt.Sprintf("%d", protocol))
	}
	return "[" + strings.Join(items, ", ") + "]"
}

func formatCmsgText(ctx *Context, data []byte) string {
	limit := len(data)
	if ctx.Opts != nil && ctx.Opts.StringLimit > 0 {
		limit = ctx.Opts.StringLimit
	}
	return format.BufferEscape(data, limit, len(data), ctx.Decoder.HexEscapeMode)
}

func formatCmsgHex(data []byte) string {
	return format.BufferEscape(data, len(data), len(data), 2)
}

func formatCmsgCredentials(data []byte) string {
	pid := int32(binary.LittleEndian.Uint32(data[0:4]))
	uid := binary.LittleEndian.Uint32(data[4:8])
	gid := binary.LittleEndian.Uint32(data[8:12])
	return fmt.Sprintf("{pid=%d, uid=%d, gid=%d}", pid, uid, gid)
}

func formatCmsgTime(data []byte, decode func([]byte) string) string {
	if len(data) < cmsgTimeSize {
		return "???"
	}
	return decode(data[:cmsgTimeSize])
}

func formatCmsgTimestamping(data []byte) string {
	if len(data) < cmsgTimeSize*cmsgTimestampingCount {
		return "???"
	}
	items := make([]string, 0, cmsgTimestampingCount)
	for offset := 0; offset < cmsgTimeSize*cmsgTimestampingCount; offset += cmsgTimeSize {
		items = append(items, format.Timespec(data[offset:offset+cmsgTimeSize]))
	}
	return "[" + strings.Join(items, ", ") + "]"
}

func formatCmsgRights(data []byte) string {
	if len(data) < 4 {
		return formatCmsgHex(data)
	}
	fdCount := len(data) / 4
	displayCount := fdCount
	truncated := false
	if displayCount > cmsgArrayDisplayLimit {
		displayCount = cmsgArrayDisplayLimit
		truncated = true
	}
	fds := make([]string, 0, displayCount+1)
	for i := 0; i < displayCount; i++ {
		offset := i * 4
		fd := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
		fds = append(fds, fmt.Sprintf("%d", fd))
	}
	if truncated {
		fds = append(fds, "...")
	}
	return "[" + strings.Join(fds, ", ") + "]"
}
