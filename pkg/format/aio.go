package format

import (
	"encoding/binary"
	"fmt"

	"strace-go/pkg/meta"
)

// Iocb formats a struct iocb.
func Iocb(data []byte, verbose bool) string {
	if len(data) < 8 {
		return "{...}"
	}
	aio_data := binary.LittleEndian.Uint64(data[0:8])
	res := fmt.Sprintf("{aio_data=%#x", aio_data)

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

		if len(data) >= 20 {
			aio_reqprio := int16(binary.LittleEndian.Uint16(data[18:20]))
			if aio_reqprio != 0 {
				class := uint16(aio_reqprio) >> 13
				prioData := uint16(aio_reqprio) & 0x1fff
				if class != 0 {
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
				if aio_buf == 0 {
					res += ", aio_buf=NULL"
				} else {
					res += fmt.Sprintf(", aio_buf=%#x", aio_buf)
				}
				res += fmt.Sprintf(", aio_nbytes=%d, aio_offset=%d", aio_nbytes, aio_offset)
			}
		}

		if len(data) >= 52 {
			aio_flags := binary.LittleEndian.Uint32(data[48:52])
			if aio_flags != 0 {
				res += fmt.Sprintf(", aio_flags=%s", meta.DecodeFlags(uint64(aio_flags), "aio_iocb_flags"))
				if len(data) >= 56 && (aio_flags&1 != 0) { // IOCB_FLAG_RESFD
					res += fmt.Sprintf(", aio_resfd=%d", int32(binary.LittleEndian.Uint32(data[52:56])))
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
