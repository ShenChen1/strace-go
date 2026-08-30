package handler

import (
	"fmt"
	"strconv"
	"strings"
)

const pidFDPath = "anon_inode:[pidfd]"

func decodePIDFDTarget(target string) (string, string, bool) {
	if target == pidFDPath {
		return pidFDPath, "", true
	}
	value, ok := strings.CutPrefix(target, pidFDPath+",pid=")
	if !ok {
		return "", "", false
	}
	pid, err := strconv.ParseInt(value, 10, 32)
	if err != nil || pid <= 0 {
		return pidFDPath, "", true
	}
	return pidFDPath, fmt.Sprintf("pid:%d", pid), true
}
