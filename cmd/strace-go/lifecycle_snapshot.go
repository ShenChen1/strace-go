package main

import "bytes"

func lifecycleSnapshotString(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if idx := bytes.IndexByte(data, 0); idx >= 0 {
		data = data[:idx]
	}
	return string(data)
}
