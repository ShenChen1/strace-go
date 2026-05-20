package format

import (
	"encoding/binary"
	"fmt"

	"strace-go/pkg/meta"
)

// Iocb formats a struct iocb.
func Iocb(data []byte, verbose bool) string {
	if len(data) < 64 { return "{...}" }
	aio_data := binary.LittleEndian.Uint64(data[0:8])
	aio_key := binary.LittleEndian.Uint32(data[8:12])
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

	aio_reqprio := int16(binary.LittleEndian.Uint16(data[18:20]))
	aio_fildes := int32(binary.LittleEndian.Uint32(data[20:24]))
	aio_buf := binary.LittleEndian.Uint64(data[24:32])
	aio_nbytes := binary.LittleEndian.Uint64(data[32:40])
	aio_offset := int64(binary.LittleEndian.Uint64(data[40:48]))
	aio_flags := binary.LittleEndian.Uint32(data[48:52])
	aio_resfd := int32(binary.LittleEndian.Uint32(data[52:56]))

	res := fmt.Sprintf("{aio_data=%#x", aio_data)
	if aio_key != 0 {
		res += fmt.Sprintf(", aio_key=%u", aio_key)
	}
	res += fmt.Sprintf(", aio_lio_opcode=%s", opStr)

	formatPrio := func(prio int16) string {
		class := uint16(prio) >> 13
		prioData := uint16(prio) & 0x1fff
		if class != 0 {
			classStr := fmt.Sprintf("%#x", class)
			if class == 1 { classStr = "IOPRIO_CLASS_RT" }
			if class == 2 { classStr = "IOPRIO_CLASS_BE" }
			if class == 3 { classStr = "IOPRIO_CLASS_IDLE" }
			return fmt.Sprintf("IOPRIO_PRIO_VALUE(%s /* IOPRIO_CLASS_??? */, %d)", classStr, prioData)
		}
		return fmt.Sprintf("%d", prio)
	}

	if aio_reqprio != 0 {
		res += fmt.Sprintf(", aio_reqprio=%s", formatPrio(aio_reqprio))
	}
	res += fmt.Sprintf(", aio_fildes=%d", aio_fildes)
	
	if !verbose && (aio_lio_opcode == 0 || aio_lio_opcode == 1 || aio_lio_opcode == 7 || aio_lio_opcode == 8) {
		res += ", ..."
	} else {
		if aio_lio_opcode == 0 || aio_lio_opcode == 1 || aio_lio_opcode == 7 || aio_lio_opcode == 8 || aio_lio_opcode > 8 {
			if aio_buf == 0 {
				res += ", aio_buf=NULL"
			} else {
				res += fmt.Sprintf(", aio_buf=%#x", aio_buf)
			}
			res += fmt.Sprintf(", aio_nbytes=%d, aio_offset=%d", aio_nbytes, aio_offset)
		}
		
		if aio_flags != 0 {
			res += fmt.Sprintf(", aio_flags=%s", meta.DecodeFlags(uint64(aio_flags), "aio_iocb_flags"))
			if aio_flags&1 != 0 { // IOCB_FLAG_RESFD
				res += fmt.Sprintf(", aio_resfd=%d", aio_resfd)
			}
		}
	}
	res += "}"
	return res
}
