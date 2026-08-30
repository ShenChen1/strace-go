package handler

import "strings"

const signalFDPath = "anon_inode:[signalfd]"

func decodeSignalFDTarget(target string) (string, string, bool) {
	const prefix = "signalfd:["
	if !strings.HasPrefix(target, prefix) {
		return "", "", false
	}
	if !strings.HasSuffix(target, "]") {
		return signalFDPath, "", true
	}
	mask := strings.TrimSuffix(strings.TrimPrefix(target, prefix), "]")
	if strings.ContainsAny(mask, "[]<>\x00") {
		return signalFDPath, "", true
	}
	return signalFDPath, target, true
}
