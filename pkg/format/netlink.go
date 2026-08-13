package format

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type netlinkFormatter struct {
	catalog FlagDecoder
}

// NetlinkWithCatalog formats netlink flags using the session catalog.
func NetlinkWithCatalog(catalog FlagDecoder, data []byte) string {
	return netlinkFormatter{catalog: catalog}.format(data)
}

func (f netlinkFormatter) format(data []byte) string {
	if len(data) < 16 {
		return Buffer(data, 0, len(data))
	}

	msgs := make([]string, 0)
	curr := data
	for len(curr) >= 16 {
		message, next, ok := f.formatMessage(curr)
		msgs = append(msgs, message)
		if !ok {
			break
		}
		curr = next
	}

	if len(msgs) == 1 {
		return msgs[0]
	}
	return "[" + strings.Join(msgs, ", ") + "]"
}

func (f netlinkFormatter) formatMessage(curr []byte) (string, []byte, bool) {
	length := binary.LittleEndian.Uint32(curr[0:4])
	if length < 16 {
		return f.formatHeader(curr, length), nil, false
	}
	if uint64(length) > uint64(len(curr)) {
		length = uint32(len(curr))
	}
	messageData := curr[:length]
	messageType := binary.LittleEndian.Uint16(messageData[4:6])
	message := f.formatHeader(messageData, length) + f.formatPayload(messageType, messageData[16:])
	alignedLength := (length + 3) &^ 3
	if uint64(alignedLength) >= uint64(len(curr)) {
		return message, nil, false
	}
	return message, curr[alignedLength:], true
}

func (f netlinkFormatter) formatHeader(data []byte, length uint32) string {
	messageType := binary.LittleEndian.Uint16(data[4:6])
	flags := binary.LittleEndian.Uint16(data[6:8])
	seq := binary.LittleEndian.Uint32(data[8:12])
	pid := binary.LittleEndian.Uint32(data[12:16])
	typeName := f.catalog.DecodeFlags(uint64(messageType), "netlink_types")
	flagsName := f.catalog.DecodeFlags(uint64(flags), "netlink_flags")
	return fmt.Sprintf("{nlmsg_len=%d, nlmsg_type=%s, nlmsg_flags=%s, nlmsg_seq=%d, nlmsg_pid=%d}", length, typeName, flagsName, seq, pid)
}

func (f netlinkFormatter) formatPayload(messageType uint16, payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	switch messageType {
	case 2: // NLMSG_ERROR
		return f.formatErrorPayload(payload)
	case 3: // NLMSG_DONE
		return formatDonePayload(payload)
	default:
		return ", " + Buffer(payload, 0, len(payload))
	}
}

func (f netlinkFormatter) formatErrorPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	errVal := int32(binary.LittleEndian.Uint32(payload[0:4]))
	errName := f.catalog.DecodeFlags(uint64(-errVal), "errno")
	if errVal == 0 {
		errName = "0"
	} else {
		errName = "-" + errName
	}
	result := fmt.Sprintf(", {error=%s", errName)
	if len(payload) >= 20 {
		result += ", msg=" + f.format(payload[4:])
	} else if len(payload) > 4 {
		result += ", msg=" + Buffer(payload[4:], 0, len(payload)-4)
	}
	return result + "}"
}

func formatDonePayload(payload []byte) string {
	if len(payload) == 4 {
		return fmt.Sprintf(", %d", int32(binary.LittleEndian.Uint32(payload[0:4])))
	}
	return ", " + Buffer(payload, 0, len(payload))
}
