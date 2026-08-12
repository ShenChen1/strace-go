package format

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// NetlinkWithCatalog formats netlink flags using the session catalog.
func NetlinkWithCatalog(catalog FlagDecoder, data []byte) string {
	if len(data) < 16 {
		return Buffer(data, 0, len(data))
	}

	var msgs []string
	curr := data
	for len(curr) >= 16 {
		len_ := binary.LittleEndian.Uint32(curr[0:4])
		if len_ < 16 {
			// Error or DONE message with no data?
			type_ := binary.LittleEndian.Uint16(curr[4:6])
			flags := binary.LittleEndian.Uint16(curr[6:8])
			seq := binary.LittleEndian.Uint32(curr[8:12])
			pid := binary.LittleEndian.Uint32(curr[12:16])

			typeName := catalog.DecodeFlags(uint64(type_), "netlink_types")
			flagsName := catalog.DecodeFlags(uint64(flags), "netlink_flags")

			msgs = append(msgs, fmt.Sprintf("{nlmsg_len=%d, nlmsg_type=%s, nlmsg_flags=%s, nlmsg_seq=%d, nlmsg_pid=%d}", len_, typeName, flagsName, seq, pid))
			break
		}

		if int(len_) > len(curr) {
			// Partial message?
			len_ = uint32(len(curr))
		}

		msgData := curr[:len_]
		type_ := binary.LittleEndian.Uint16(msgData[4:6])
		flags := binary.LittleEndian.Uint16(msgData[6:8])
		seq := binary.LittleEndian.Uint32(msgData[8:12])
		pid := binary.LittleEndian.Uint32(msgData[12:16])

		typeName := catalog.DecodeFlags(uint64(type_), "netlink_types")
		flagsName := catalog.DecodeFlags(uint64(flags), "netlink_flags")

		payload := msgData[16:]
		payloadStr := ""
		if len(payload) > 0 {
			if type_ == 2 { // NLMSG_ERROR
				if len(payload) >= 4 {
					errVal := int32(binary.LittleEndian.Uint32(payload[0:4]))
					errName := catalog.DecodeFlags(uint64(-errVal), "errno")
					if errVal == 0 {
						errName = "0"
					} else {
						errName = "-" + errName
					}
					payloadStr = fmt.Sprintf(", {error=%s", errName)
					if len(payload) >= 20 {
						payloadStr += ", msg=" + NetlinkWithCatalog(catalog, payload[4:])
					} else if len(payload) > 4 {
						payloadStr += ", msg=" + Buffer(payload[4:], 0, len(payload)-4)
					}
					payloadStr += "}"
				}
			} else if type_ == 3 { // NLMSG_DONE
				if len(payload) == 4 {
					val := int32(binary.LittleEndian.Uint32(payload[0:4]))
					payloadStr = fmt.Sprintf(", %d", val)
				} else {
					payloadStr = ", " + Buffer(payload, 0, len(payload))
				}
			} else {
				payloadStr = ", " + Buffer(payload, 0, len(payload))
			}
		}

		msgs = append(msgs, fmt.Sprintf("{nlmsg_len=%d, nlmsg_type=%s, nlmsg_flags=%s, nlmsg_seq=%d, nlmsg_pid=%d}%s", len_, typeName, flagsName, seq, pid, payloadStr))

		// Netlink messages are aligned to 4 bytes
		alignedLen := (len_ + 3) &^ 3
		if int(alignedLen) >= len(curr) {
			break
		}
		curr = curr[alignedLen:]
	}

	if len(msgs) == 1 {
		return msgs[0]
	}
	return "[" + strings.Join(msgs, ", ") + "]"
}
