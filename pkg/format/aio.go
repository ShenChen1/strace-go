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
	res := formatIocbData(aio_data)

	if len(data) >= 12 {
		aio_key := binary.LittleEndian.Uint32(data[8:12])
		if aio_key != 0 {
			res += fmt.Sprintf(", aio_key=%d", aio_key)
		}
	}

	if len(data) >= 18 {
		aio_lio_opcode := binary.LittleEndian.Uint16(data[16:18])
		res += fmt.Sprintf(", aio_lio_opcode=%s", iocbOpcodeStr(aio_lio_opcode))

		var aio_flags uint32
		if len(data) >= 60 {
			aio_flags = binary.LittleEndian.Uint32(data[56:60])
		}

		if len(data) >= 20 {
			res += formatIocbReqprio(int16(binary.LittleEndian.Uint16(data[18:20])), aio_flags&2 != 0)
		}

		if len(data) >= 24 {
			res += fmt.Sprintf(", aio_fildes=%d", int32(binary.LittleEndian.Uint32(data[20:24])))
		}

		if len(data) >= 48 && iocbHasBuffer(aio_lio_opcode) {
			res += formatIocbBuffer(data, aio_lio_opcode, verbose, decodeAioBuf)
		}

		if len(data) >= 60 {
			res += formatIocbFlags(aio_flags, data)
		}
	}

	if len(data) < 64 {
		res += ", ..."
	}
	return res + "}"
}

func formatIocbData(aioData uint64) string {
	if aioData == 0 {
		return "{aio_data=0"
	}
	return fmt.Sprintf("{aio_data=%#x", aioData)
}

func iocbOpcodeStr(opcode uint16) string {
	switch opcode {
	case 0:
		return "IOCB_CMD_PREAD"
	case 1:
		return "IOCB_CMD_PWRITE"
	case 2:
		return "IOCB_CMD_FSYNC"
	case 3:
		return "IOCB_CMD_FDSYNC"
	case 7:
		return "IOCB_CMD_PREADV"
	case 8:
		return "IOCB_CMD_PWRITEV"
	default:
		return fmt.Sprintf("%d /* IOCB_CMD_??? */", opcode)
	}
}

func iocbHasBuffer(opcode uint16) bool {
	return opcode == 0 || opcode == 1 || opcode == 7 || opcode == 8 || opcode > 8
}

func formatIocbReqprio(reqprio int16, ioprioEnabled bool) string {
	if reqprio == 0 {
		return ""
	}
	class := uint16(reqprio) >> 13
	prioData := uint16(reqprio) & 0x1fff
	if class != 0 && ioprioEnabled {
		classStr := fmt.Sprintf("%#x", class)
		if class == 1 {
			classStr = "IOPRIO_CLASS_RT"
		}
		if class == 2 {
			classStr = "IOPRIO_CLASS_BE"
		}
		if class == 3 {
			classStr = "IOPRIO_CLASS_IDLE"
		}
		return fmt.Sprintf(", aio_reqprio=IOPRIO_PRIO_VALUE(%s /* IOPRIO_CLASS_??? */, %d)", classStr, prioData)
	}
	return fmt.Sprintf(", aio_reqprio=%d", reqprio)
}

func formatIocbBuffer(data []byte, opcode uint16, verbose bool, decodeAioBuf func(opcode uint16, buf uint64, nbytes uint64) string) string {
	aioBuf := binary.LittleEndian.Uint64(data[24:32])
	aioNbytes := binary.LittleEndian.Uint64(data[32:40])
	aioOffset := int64(binary.LittleEndian.Uint64(data[40:48]))
	if !verbose && aioBuf == 0 && aioNbytes == 0 && aioOffset == 0 {
		return ""
	}
	isIovec := opcode == 7 || opcode == 8
	bufStr := ""
	if aioBuf == 0 && isIovec {
		bufStr = "0"
	} else if aioBuf == 0 {
		bufStr = "NULL"
	} else if decodeAioBuf != nil {
		bufStr = decodeAioBuf(opcode, aioBuf, aioNbytes)
	}
	if bufStr == "" || bufStr == "NULL" && aioBuf == 0 && isIovec {
		bufStr = fmt.Sprintf("%#x", aioBuf)
	}
	if bufStr != "NULL" && bufStr != "0" && isIovec {
		return fmt.Sprintf(", aio_buf=%s, aio_offset=%d", bufStr, aioOffset)
	}
	return fmt.Sprintf(", aio_buf=%s, aio_nbytes=%d, aio_offset=%d", bufStr, aioNbytes, aioOffset)
}

func formatIocbFlags(flags uint32, data []byte) string {
	if flags == 0 {
		return ""
	}
	var flagStrs []string
	handled := uint32(0)
	if flags&1 != 0 {
		flagStrs = append(flagStrs, "IOCB_FLAG_RESFD")
		handled |= 1
	}
	if flags&2 != 0 {
		flagStrs = append(flagStrs, "IOCB_FLAG_IOPRIO")
		handled |= 2
	}
	if flags != handled {
		flagStrs = append(flagStrs, fmt.Sprintf("%#x", flags&^handled))
	}
	res := fmt.Sprintf(", aio_flags=%s", strings.Join(flagStrs, "|"))
	if len(data) >= 64 && flags&1 != 0 { // IOCB_FLAG_RESFD
		res += fmt.Sprintf(", aio_resfd=%d", int32(binary.LittleEndian.Uint32(data[60:64])))
	}
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
