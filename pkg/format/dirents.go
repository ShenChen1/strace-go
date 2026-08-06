package format

import "encoding/binary"

const linuxDirent64ReclenOffset = 16

// Dirent64Count counts complete linux_dirent64 records in a captured buffer.
func Dirent64Count(data []byte, byteCount int) int {
	if byteCount <= 0 || len(data) == 0 {
		return 0
	}
	limit := byteCount
	if limit > len(data) {
		limit = len(data)
	}
	count := 0
	for offset := 0; offset+linuxDirent64ReclenOffset+2 <= limit; {
		reclen := int(binary.LittleEndian.Uint16(data[offset+linuxDirent64ReclenOffset : offset+linuxDirent64ReclenOffset+2]))
		if reclen <= 0 || offset+reclen > limit {
			break
		}
		count++
		offset += reclen
	}
	return count
}
