package format

import "fmt"

// Dev formats a dev_t major/minor pair in the form makedev(major, minor).
func Dev(dev uint64) string {
	return devWithFormat(dev, "abbrev")
}

func devWithFormat(dev uint64, mode string) string {
	raw := formatHexValue(dev)
	decoded := decodeDeviceNumber(dev)
	switch mode {
	case "raw":
		return raw
	case "verbose":
		return fmt.Sprintf("%s /* %s */", raw, decoded)
	default:
		return decoded
	}
}

func decodeDeviceNumber(dev uint64) string {
	major := uint32((dev >> 8) & 0xfff)
	minor := uint32(dev & 0xff)
	major |= uint32((dev >> 32) & 0xfffff000)
	minor |= uint32((dev >> 12) & 0xffffff00)
	return fmt.Sprintf("makedev(%s, %s)", formatHexValue(uint64(major)), formatHexValue(uint64(minor)))
}

func formatHexValue(value uint64) string {
	if value == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", value)
}
