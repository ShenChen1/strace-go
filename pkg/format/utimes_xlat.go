package format

import (
	"encoding/binary"
	"fmt"
	"time"
)

func UtimesWithXlat(data []byte, xlatFormat string) string {
	if len(data) < 32 {
		return "[{...}, {...}]"
	}
	first := timespecWithXlat(data[0:16], xlatFormat)
	second := timespecWithXlat(data[16:32], xlatFormat)
	return "[" + first + ", " + second + "]"
}

func timespecWithXlat(data []byte, xlatFormat string) string {
	sec := int64(binary.LittleEndian.Uint64(data[0:8]))
	nsec := binary.LittleEndian.Uint64(data[8:16])

	if name, ok := utimeSpecialName(nsec); ok {
		switch xlatFormat {
		case "raw":
			return fmt.Sprintf("{tv_sec=%d, tv_nsec=%d}", sec, nsec)
		case "verbose":
			return fmt.Sprintf("{tv_sec=%d, tv_nsec=%d} /* %s */", sec, nsec, name)
		default:
			return name
		}
	}

	text := fmt.Sprintf("{tv_sec=%d, tv_nsec=%d}", sec, nsec)
	if sec > 0 && sec < 253402300799 && nsec < 1000000000 {
		text += fmt.Sprintf(" /* %s.%09d+0000 */", time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05"), nsec)
	}
	return text
}

func utimeSpecialName(nsec uint64) (string, bool) {
	switch nsec {
	case 1073741823:
		return "UTIME_NOW", true
	case 1073741822:
		return "UTIME_OMIT", true
	default:
		return "", false
	}
}
