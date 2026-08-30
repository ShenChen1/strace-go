package format

import (
	"encoding/binary"
	"fmt"
	"time"
)

func Timevals(data []byte) string {
	if len(data) < 32 {
		return "[{...}, {...}]"
	}
	first := timevalWithComment(data[0:16])
	second := timevalWithComment(data[16:32])
	return "[" + first + ", " + second + "]"
}

func Utimbuf(data []byte) string {
	if len(data) < 16 {
		return "{...}"
	}
	actime := int64(binary.LittleEndian.Uint64(data[0:8]))
	modtime := int64(binary.LittleEndian.Uint64(data[8:16]))
	return fmt.Sprintf("{actime=%s, modtime=%s}", secondsWithComment(actime), secondsWithComment(modtime))
}

func timevalWithComment(data []byte) string {
	sec := int64(binary.LittleEndian.Uint64(data[0:8]))
	usec := binary.LittleEndian.Uint64(data[8:16])
	text := fmt.Sprintf("{tv_sec=%d, tv_usec=%d}", sec, usec)
	if sec > 0 && sec < 253402300799 && usec < 1000000 {
		text += fmt.Sprintf(" /* %s.%06d+0000 */", time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05"), usec)
	}
	return text
}

func secondsWithComment(sec int64) string {
	text := fmt.Sprintf("%d", sec)
	if sec > 0 && sec < 253402300799 {
		text += fmt.Sprintf(" /* %s+0000 */", time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05"))
	}
	return text
}

// TimeT formats a time_t value with its UTC representation.
func TimeT(sec int64) string {
	text := fmt.Sprintf("%d", sec)
	if description := TimeTDescription(sec); description != "" {
		text += " /* " + description + " */"
	}
	return text
}

// TimeTDescription formats the parenthesized return description of time(2).
func TimeTDescription(sec int64) string {
	if sec < 0 || sec >= 253402300799 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05") + "+0000"
}
