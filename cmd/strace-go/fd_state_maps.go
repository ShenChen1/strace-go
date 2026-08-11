package main

func copyFDStateOffsets(offsets map[string]int64) map[string]int64 {
	if len(offsets) == 0 {
		return nil
	}
	copy := make(map[string]int64, len(offsets))
	for key, offset := range offsets {
		copy[key] = offset
	}
	return copy
}
