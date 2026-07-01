package handler

import (
	"fmt"
	"os"
	"strings"
)

func (ctx *Context) FetchWrittenFileData(fd int32, requestedSize int, current []byte) ([]byte, bool) {
	if ctx.Ret <= 0 || !ctx.BufferFileOffsetOK {
		return nil, false
	}
	readSize := requestedSize
	if ctx.Ret < int64(readSize) {
		readSize = int(ctx.Ret)
	}
	if readSize <= len(current) {
		return nil, false
	}

	out := make([]byte, readSize)
	if f := ctx.fdDataFile(fd); f != nil {
		n, _ := f.ReadAt(out, ctx.BufferFileOffset)
		if n > len(current) {
			return out[:n], true
		}
	}
	if path, ok := ctx.fdDataPath(fd); ok {
		f, err := os.Open(path)
		if err == nil {
			defer f.Close()
			n, _ := f.ReadAt(out, ctx.BufferFileOffset)
			if n > len(current) {
				return out[:n], true
			}
		}
	}
	return nil, false
}

func (ctx *Context) fdDataFile(fd int32) *os.File {
	if ctx.FdFiles == nil {
		return nil
	}
	return ctx.FdFiles[fmt.Sprintf("%d:%d", ctx.TargetPid, fd)]
}

func (ctx *Context) fdDataPath(fd int32) (string, bool) {
	if ctx.FdMap == nil {
		return "", false
	}
	target := ctx.FdMap[fmt.Sprintf("%d:%d", ctx.TargetPid, fd)]
	if target == "" {
		return "", false
	}
	target = strings.SplitN(target, "|", 2)[0]
	if strings.HasPrefix(target, `"`) && strings.HasSuffix(target, `"`) {
		target = target[1 : len(target)-1]
	}
	switch {
	case strings.HasPrefix(target, "socket:"),
		strings.HasPrefix(target, "socket:["),
		strings.HasPrefix(target, "pipe:"),
		strings.HasPrefix(target, "pipe:["),
		strings.HasPrefix(target, "anon_inode:"),
		strings.HasPrefix(target, "{"),
		strings.HasPrefix(target, "NETLINK:"):
		return "", false
	}
	if !strings.HasPrefix(target, "/") {
		target = CleanPath(ctx.FdMap[fmt.Sprintf("%d:cwd", ctx.TargetPid)], target)
	}
	return target, true
}
