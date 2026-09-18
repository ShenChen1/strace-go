package format

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	direntReclenOffset = 16
	direntNameOffset   = 18
	dirent64NameOffset = 19
)

// DirentLayout identifies the Linux legacy and dirent64 record formats.
type DirentLayout uint8

const (
	DirentLayoutLegacy DirentLayout = iota
	DirentLayout64
)

type direntEntry struct {
	Inode        uint64
	Offset       uint64
	RecordLength uint16
	Type         byte
	Name         []byte
}

// DirentSnapshot describes complete records decoded from a bounded BPF snapshot.
type DirentSnapshot struct {
	entries  []direntEntry
	layout   DirentLayout
	complete bool
}

// DecodeDirents parses complete records without reading beyond the BPF snapshot.
func DecodeDirents(data []byte, byteCount int, layout DirentLayout) DirentSnapshot {
	snapshot := DirentSnapshot{layout: layout}
	_, snapshot.complete = walkDirents(data, byteCount, layout, func(entry direntEntry) {
		snapshot.entries = append(snapshot.entries, entry)
	})
	return snapshot
}

// CountDirents counts complete records without allocating decoded entries.
func CountDirents(data []byte, byteCount int, layout DirentLayout) (int, bool) {
	return walkDirents(data, byteCount, layout, nil)
}

func walkDirents(data []byte, byteCount int, layout DirentLayout, visit func(direntEntry)) (int, bool) {
	if byteCount <= 0 {
		return 0, true
	}
	limit := min(byteCount, len(data))
	count := 0
	for offset := 0; offset < limit; {
		entry, recordLength, ok := decodeDirentRecord(data[offset:limit], layout)
		if !ok {
			return count, false
		}
		if visit != nil {
			visit(entry)
		}
		count++
		offset += recordLength
		if offset == byteCount {
			return count, true
		}
	}
	return count, false
}

func decodeDirentRecord(data []byte, layout DirentLayout) (direntEntry, int, bool) {
	if len(data) < dirent64NameOffset {
		return direntEntry{}, 0, false
	}
	recordLength := int(binary.LittleEndian.Uint16(data[direntReclenOffset : direntReclenOffset+2]))
	if recordLength < dirent64NameOffset || recordLength > len(data) {
		return direntEntry{}, 0, false
	}
	record := data[:recordLength]
	entry := direntEntry{
		Inode:        binary.LittleEndian.Uint64(record[0:8]),
		Offset:       binary.LittleEndian.Uint64(record[8:16]),
		RecordLength: uint16(recordLength),
	}
	entry.Type, entry.Name = decodeDirentTail(record, layout)
	return entry, recordLength, true
}

func decodeDirentTail(record []byte, layout DirentLayout) (byte, []byte) {
	if layout == DirentLayout64 {
		return record[18], trimDirentName(record[dirent64NameOffset:])
	}
	return record[len(record)-1], trimDirentName(record[direntNameOffset : len(record)-1])
}

func trimDirentName(data []byte) []byte {
	if nul := bytes.IndexByte(data, 0); nul >= 0 {
		data = data[:nul]
	}
	return data
}

// Count returns the number of complete records in the bounded snapshot.
func (snapshot DirentSnapshot) Count() int {
	return len(snapshot.entries)
}

// Complete reports whether the snapshot contains all bytes returned by the syscall.
func (snapshot DirentSnapshot) Complete() bool {
	return snapshot.complete
}

// Verbose formats all complete records and marks a truncated or malformed tail.
func (snapshot DirentSnapshot) Verbose(escapeMode int) string {
	parts := make([]string, 0, len(snapshot.entries)+1)
	for _, entry := range snapshot.entries {
		parts = append(parts, formatDirentEntry(entry, snapshot.layout, escapeMode))
	}
	if !snapshot.complete {
		parts = append(parts, "...")
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func formatDirentEntry(entry direntEntry, layout DirentLayout, escapeMode int) string {
	name := BufferEscape(entry.Name, len(entry.Name), len(entry.Name), escapeMode)
	prefix := fmt.Sprintf("{d_ino=%d, d_off=%d, d_reclen=%d", entry.Inode, entry.Offset, entry.RecordLength)
	if layout == DirentLayout64 {
		return fmt.Sprintf("%s, d_type=%s, d_name=%s}", prefix, formatDirentType(entry.Type), name)
	}
	return fmt.Sprintf("%s, d_name=%s, d_type=%s}", prefix, name, formatDirentType(entry.Type))
}

func formatDirentType(value byte) string {
	switch value {
	case 0:
		return "DT_UNKNOWN"
	case 1:
		return "DT_FIFO"
	case 2:
		return "DT_CHR"
	case 4:
		return "DT_DIR"
	case 6:
		return "DT_BLK"
	case 8:
		return "DT_REG"
	case 10:
		return "DT_LNK"
	case 12:
		return "DT_SOCK"
	case 14:
		return "DT_WHT"
	default:
		return fmt.Sprintf("%#x /* DT_??? */", value)
	}
}
