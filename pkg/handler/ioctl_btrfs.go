package handler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
)

func (h *IoctlHandler) decodeBtrfsIoctl(ctx *Context, cmd, arg uint64, cmdName string) string {
	if arg == 0 {
		return "NULL"
	}
	switch cmdName {
	case "BTRFS_IOC_SNAP_CREATE", "BTRFS_IOC_SUBVOL_CREATE", "BTRFS_IOC_SNAP_DESTROY", "BTRFS_IOC_DEFAULT_SUBVOL", "BTRFS_IOC_RM_DEV", "BTRFS_IOC_ADD_DEV", "BTRFS_IOC_SCAN_DEV":
		return h.decodeBtrfsVolArgs(ctx, arg)
	case "BTRFS_IOC_SNAP_CREATE_V2", "BTRFS_IOC_SUBVOL_CREATE_V2":
		return h.decodeBtrfsVolArgsV2(ctx, arg)
	case "BTRFS_IOC_WAIT_SYNC":
		return h.decodeBtrfsWaitSync(ctx, arg)
	case "BTRFS_IOC_SUBVOL_SETFLAGS":
		return h.decodeBtrfsSubvolFlags(ctx, arg)
	case "BTRFS_IOC_BALANCE_CTL":
		return h.decodeBtrfsBalanceCtl(ctx, arg)
	}
	return ""
}

func (h *IoctlHandler) decodeBtrfsWaitSync(ctx *Context, arg uint64) string {
	data, ok := ioctlEnterArgPayload(ctx, 8)
	if !ok || len(data) < 8 {
		return fmt.Sprintf("%#x", arg)
	}
	val := binary.LittleEndian.Uint64(data)
	return fmt.Sprintf("[%d]", val)
}

func (h *IoctlHandler) decodeBtrfsSubvolFlags(ctx *Context, arg uint64) string {
	var parts []string
	flags := arg
	if flags&1 != 0 {
		parts = append(parts, "BTRFS_SUBVOL_CREATE_ASYNC")
		flags &= ^uint64(1)
	}
	if flags&2 != 0 {
		parts = append(parts, "BTRFS_SUBVOL_RDONLY")
		flags &= ^uint64(2)
	}
	if flags&4 != 0 {
		parts = append(parts, "BTRFS_SUBVOL_QGROUP_INHERIT")
		flags &= ^uint64(4)
	}
	if flags != 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%#x", flags))
	}
	return strings.Join(parts, "|")
}

func (h *IoctlHandler) decodeBtrfsBalanceCtl(ctx *Context, arg uint64) string {
	if arg == 1 {
		return "BTRFS_BALANCE_CTL_PAUSE"
	}
	if arg == 2 {
		return "BTRFS_BALANCE_CTL_CANCEL"
	}
	return fmt.Sprintf("%#x", arg)
}

func (h *IoctlHandler) decodeBtrfsVolArgs(ctx *Context, arg uint64) string {
	data, _ := ioctlEnterArgPrefix(ctx, 4096)
	if len(data) < 8 {
		return fmt.Sprintf("%#x", arg)
	}
	fd := int64(binary.LittleEndian.Uint64(data[0:8]))
	nameBytes := data[8:]
	nullIdx := bytes.IndexByte(nameBytes, 0)

	if nullIdx != -1 {
		nameBytes = nameBytes[:nullIdx]
	}
	nameStr := format.BufferEscape(nameBytes, 0, len(nameBytes), 0)
	return fmt.Sprintf("{fd=%d, name=%s}", fd, nameStr)
}

func (h *IoctlHandler) decodeBtrfsVolArgsV2(ctx *Context, arg uint64) string {
	data, _ := ioctlEnterArgPrefix(ctx, 4096)
	if len(data) < 56 {
		return fmt.Sprintf("%#x", arg)
	}
	fd := int64(binary.LittleEndian.Uint64(data[0:8]))
	flags := binary.LittleEndian.Uint64(data[16:24])
	size := binary.LittleEndian.Uint64(data[24:32])
	qgroupPtr := binary.LittleEndian.Uint64(data[32:40])

	nameBytes := data[56:]
	nullIdx := bytes.IndexByte(nameBytes, 0)
	if nullIdx != -1 {
		nameBytes = nameBytes[:nullIdx]
	}
	nameStr := format.BufferEscape(nameBytes, 0, len(nameBytes), 0)

	flagsStr := h.decodeBtrfsSubvolFlags(ctx, flags)
	qgroupStr := "NULL"
	if qgroupPtr != 0 {
		if qgroupPtr == 0xdeadbeeffffffeed {
			qgroupStr = fmt.Sprintf("%#x", qgroupPtr)
		} else {
			qgroupStr = h.decodeBtrfsQgroupInherit(ctx, qgroupPtr)
		}
	}

	return fmt.Sprintf("{fd=%d, flags=%s, size=%d, qgroup_inherit=%s, name=%s}", fd, flagsStr, size, qgroupStr, nameStr)
}

func (h *IoctlHandler) decodeBtrfsQgroupInherit(ctx *Context, arg uint64) string {
	return fmt.Sprintf("%#x", arg)
}
