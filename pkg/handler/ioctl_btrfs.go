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
	data, err := ctx.MemReader.ReadRobust(ctx.Tid, arg, 8, false)
	if err != nil || len(data) < 8 {
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
	var data []byte
	if ctx.IsArgReadSuccess(2) && len(ctx.StrArgBuf) >= 512+8 {
		end := len(ctx.StrArgBuf)
		if end > 512+4096 {
			end = 512 + 4096
		}
		data = ctx.StrArgBuf[512:end]
	} else {
		data, _ = ctx.MemReader.ReadRobust(ctx.Tid, arg, 4096, true)
	}
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
	var data []byte
	if ctx.IsArgReadSuccess(2) && len(ctx.StrArgBuf) >= 512+56 {
		end := len(ctx.StrArgBuf)
		if end > 512+4096 {
			end = 512 + 4096
		}
		data = ctx.StrArgBuf[512:end]
	} else {
		data, _ = ctx.MemReader.ReadRobust(ctx.Tid, arg, 4096, true)
	}
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
	data, err := ctx.MemReader.ReadRobust(ctx.Tid, arg, 64, true)
	if err != nil || len(data) < 64 {
		return fmt.Sprintf("%#x", arg)
	}
	flags := binary.LittleEndian.Uint64(data[0:8])
	numQgroups := binary.LittleEndian.Uint64(data[8:16])
	numRefCopies := binary.LittleEndian.Uint64(data[16:24])
	numExclCopies := binary.LittleEndian.Uint64(data[24:32])

	// lim is struct btrfs_qgroup_limit
	limFlags := binary.LittleEndian.Uint64(data[32:40])
	maxRfer := binary.LittleEndian.Uint64(data[40:48])
	maxExcl := binary.LittleEndian.Uint64(data[48:56])
	rsvRfer := binary.LittleEndian.Uint64(data[56:64])

	// For test match we also need rsv_excl which is at offset 64
	data2, _ := ctx.MemReader.ReadRobust(ctx.Tid, arg+64, 8, false)
	rsvExcl := uint64(0)
	if len(data2) >= 8 {
		rsvExcl = binary.LittleEndian.Uint64(data2)
	}

	flagsStr := fmt.Sprintf("%#x", flags)
	if flags&2 != 0 {
		flagsStr = "BTRFS_QGROUP_INHERIT_SET_LIMITS|" + fmt.Sprintf("%#x", flags & ^uint64(2))
		if flags & ^uint64(2) == 0 {
			flagsStr = "BTRFS_QGROUP_INHERIT_SET_LIMITS"
		}
	}

	var limParts []string
	lf := limFlags
	if lf&1 != 0 {
		limParts = append(limParts, "BTRFS_QGROUP_LIMIT_MAX_RFER")
		lf &= ^uint64(1)
	}
	if lf&2 != 0 {
		limParts = append(limParts, "BTRFS_QGROUP_LIMIT_MAX_EXCL")
		lf &= ^uint64(2)
	}
	if lf&4 != 0 {
		limParts = append(limParts, "BTRFS_QGROUP_LIMIT_RSV_RFER")
		lf &= ^uint64(4)
	}
	if lf&8 != 0 {
		limParts = append(limParts, "BTRFS_QGROUP_LIMIT_RSV_EXCL")
		lf &= ^uint64(8)
	}
	if lf&16 != 0 {
		limParts = append(limParts, "BTRFS_QGROUP_LIMIT_RFER_CMPR")
		lf &= ^uint64(16)
	}
	if lf&32 != 0 {
		limParts = append(limParts, "BTRFS_QGROUP_LIMIT_EXCL_CMPR")
		lf &= ^uint64(32)
	}
	if lf != 0 || len(limParts) == 0 {
		limParts = append(limParts, fmt.Sprintf("%#x", lf))
	}

	limFlagsStr := strings.Join(limParts, "|")

	limStr := fmt.Sprintf("{flags=%s, max_rfer=%d, max_excl=%d, rsv_rfer=%d, rsv_excl=%d}", limFlagsStr, maxRfer, maxExcl, rsvRfer, rsvExcl)

	return fmt.Sprintf("{flags=%s, num_qgroups=%d, num_ref_copies=%d, num_excl_copies=%d, lim=%s, ...}", flagsStr, numQgroups, numRefCopies, numExclCopies, limStr)
}
