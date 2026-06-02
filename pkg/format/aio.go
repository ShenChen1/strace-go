package format

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Iocb formats a struct iocb.
func Iocb(data []byte, verbose bool, decodeAioBuf func(opcode uint16, buf uint64, nbytes uint64) string) string {
	if len(data) < 8 {
		return "{...}"
	}
	aio_data := binary.LittleEndian.Uint64(data[0:8])
	res := "{aio_data=0"
	if aio_data != 0 {
		res = fmt.Sprintf("{aio_data=%#x", aio_data)
	}

	if len(data) >= 12 {
		aio_key := binary.LittleEndian.Uint32(data[8:12])
		if aio_key != 0 {
			res += fmt.Sprintf(", aio_key=%d", aio_key)
		}
	}

	if len(data) >= 18 {
		aio_lio_opcode := binary.LittleEndian.Uint16(data[16:18])
		opStr := fmt.Sprintf("%d", aio_lio_opcode)
		switch aio_lio_opcode {
		case 0: opStr = "IOCB_CMD_PREAD"
		case 1: opStr = "IOCB_CMD_PWRITE"
		case 2: opStr = "IOCB_CMD_FSYNC"
		case 3: opStr = "IOCB_CMD_FDSYNC"
		case 7: opStr = "IOCB_CMD_PREADV"
		case 8: opStr = "IOCB_CMD_PWRITEV"
		default: opStr = fmt.Sprintf("%d /* IOCB_CMD_??? */", aio_lio_opcode)
		}
		res += fmt.Sprintf(", aio_lio_opcode=%s", opStr)

		var aio_flags uint32
		if len(data) >= 60 {
			aio_flags = binary.LittleEndian.Uint32(data[56:60])
		}

		if len(data) >= 20 {
			aio_reqprio := int16(binary.LittleEndian.Uint16(data[18:20]))
			if aio_reqprio != 0 {
				class := uint16(aio_reqprio) >> 13
				prioData := uint16(aio_reqprio) & 0x1fff
				if class != 0 && (aio_flags&2 != 0) {
					classStr := fmt.Sprintf("%#x", class)
					if class == 1 { classStr = "IOPRIO_CLASS_RT" }
					if class == 2 { classStr = "IOPRIO_CLASS_BE" }
					if class == 3 { classStr = "IOPRIO_CLASS_IDLE" }
					res += fmt.Sprintf(", aio_reqprio=IOPRIO_PRIO_VALUE(%s /* IOPRIO_CLASS_??? */, %d)", classStr, prioData)
				} else {
					res += fmt.Sprintf(", aio_reqprio=%d", aio_reqprio)
				}
			}
		}

		if len(data) >= 24 {
			res += fmt.Sprintf(", aio_fildes=%d", int32(binary.LittleEndian.Uint32(data[20:24])))
		}

		if len(data) >= 48 && (aio_lio_opcode == 0 || aio_lio_opcode == 1 || aio_lio_opcode == 7 || aio_lio_opcode == 8 || aio_lio_opcode > 8) {
			aio_buf := binary.LittleEndian.Uint64(data[24:32])
			aio_nbytes := binary.LittleEndian.Uint64(data[32:40])
			aio_offset := int64(binary.LittleEndian.Uint64(data[40:48]))
			
			if verbose || aio_buf != 0 || aio_nbytes != 0 || aio_offset != 0 {
				var bufStr string
				if aio_buf == 0 && (aio_lio_opcode == 7 || aio_lio_opcode == 8) {
					bufStr = "0"
				} else if aio_buf == 0 {
					bufStr = "NULL"
				} else if decodeAioBuf != nil {
					bufStr = decodeAioBuf(aio_lio_opcode, aio_buf, aio_nbytes)
				}
				if bufStr == "" || bufStr == "NULL" && aio_buf == 0 && (aio_lio_opcode == 7 || aio_lio_opcode == 8) {
					bufStr = fmt.Sprintf("%#x", aio_buf)
				}
				if bufStr != "NULL" && bufStr != "0" && (aio_lio_opcode == 7 || aio_lio_opcode == 8) {
					res += fmt.Sprintf(", aio_buf=%s, aio_offset=%d", bufStr, aio_offset)
				} else {
					res += fmt.Sprintf(", aio_buf=%s, aio_nbytes=%d, aio_offset=%d", bufStr, aio_nbytes, aio_offset)
				}
			}
		}

		if len(data) >= 60 {
			if aio_flags != 0 {
				var flagStrs []string
				handled := uint32(0)
				if aio_flags&1 != 0 {
					flagStrs = append(flagStrs, "IOCB_FLAG_RESFD")
					handled |= 1
				}
				if aio_flags&2 != 0 {
					flagStrs = append(flagStrs, "IOCB_FLAG_IOPRIO")
					handled |= 2
				}
				if aio_flags != handled {
					flagStrs = append(flagStrs, fmt.Sprintf("%#x", aio_flags&^handled))
				}
				res += fmt.Sprintf(", aio_flags=%s", strings.Join(flagStrs, "|"))
				if len(data) >= 64 && (aio_flags&1 != 0) { // IOCB_FLAG_RESFD
					res += fmt.Sprintf(", aio_resfd=%d", int32(binary.LittleEndian.Uint32(data[60:64])))
				}
			}
		}
	}

	if len(data) < 64 {
		res += ", ..."
	}
	res += "}"
	return res
}

// IovecArray formats an array of struct iovec.
func IovecArray(data []byte, count int) string {
	var parts []string
	for i := 0; i < count; i++ {
		if len(data) < (i+1)*16 {
			break
		}
		base := binary.LittleEndian.Uint64(data[i*16 : i*16+8])
		length := binary.LittleEndian.Uint64(data[i*16+8 : i*16+16])
		if base == 0 {
			parts = append(parts, fmt.Sprintf("{iov_base=NULL, iov_len=%d}", length))
		} else {
			parts = append(parts, fmt.Sprintf("{iov_base=%#x, iov_len=%d}", base, length))
		}
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
