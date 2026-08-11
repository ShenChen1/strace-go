package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

const (
	msghdrSnapshotSize     = 56
	mmsghdrSnapshotSize    = 64
	mmsghdrDisplayLimit    = 4
	mmsghdrSecondIovArg    = 151
	mmsghdrThirdIovArg     = 181
	mmsghdrFourthIovArg    = 211
	recvmsgEFAULT          = -14
	msghdrNameOffset       = 0
	msghdrNameLenOffset    = 8
	msghdrIovOffset        = 16
	msghdrIovLenOffset     = 24
	msghdrControlOffset    = 32
	msghdrControlLenOffset = 40
	msghdrFlagsOffset      = 48
	mmsghdrMsgLenOffset    = 56
)

func registerBuiltinMsg(r *Registry) {
	h := &MsgHandler{}
	r.Register("sendmsg", h)
	r.Register("recvmsg", h)
	r.Register("sendmmsg", h)
	r.Register("recvmmsg", h)
}

type MsgHandler struct {
	DefaultHandler
}

func (h *MsgHandler) Handle(ctx *Context) Result {
	if ctx.SysName == "sendmmsg" || ctx.SysName == "recvmmsg" {
		return h.handleMmsg(ctx)
	}

	res := Result{ArgParts: []string{
		h.decodeScalar(ctx, "int", "fd", ctx.Args[0]),
		h.formatMsghdr(ctx),
		meta.DecodeFlags(ctx.Args[2], "msg_flags"),
	}}
	if snap, ok := msghdrSnapshotForFormatting(ctx); ok {
		addIovecHexDump(ctx, &res, 1, snap.iovLen)
	}
	return res
}

func (h *MsgHandler) handleMmsg(ctx *Context) Result {
	res := Result{ArgParts: []string{
		h.decodeScalar(ctx, "int", "fd", ctx.Args[0]),
		h.formatMmsghdrArray(ctx),
		h.decodeScalar(ctx, "unsigned int", "vlen", ctx.Args[2]),
		meta.DecodeFlags(ctx.Args[3], "msg_flags"),
	}}
	if ctx.SysName == "recvmmsg" {
		res.ArgParts = append(res.ArgParts, h.decodeMmsgTimeout(ctx))
	}
	for _, snap := range mmsghdrSnapshotsForFormatting(ctx) {
		addMmsgHexDump(ctx, &res, snap)
	}
	if ctx.SysName == "recvmmsg" && ctx.Ret > 0 {
		if data, ok := mmsgTimeoutPayload(ctx, PayloadDirectionOut); ok {
			res.ReturnDesc = "left " + format.Timespec(data)
		}
	}
	return res
}

type msghdrSnapshot struct {
	name       uint64
	nameLen    uint32
	iov        uint64
	iovLen     uint64
	control    uint64
	controlLen uint64
	flags      uint32
}

func (h *MsgHandler) formatMsghdr(ctx *Context) string {
	if ctx.Args[1] == 0 {
		return "NULL"
	}
	snap, ok := msghdrSnapshotForFormatting(ctx)
	if !ok {
		return fmt.Sprintf("%#x", ctx.Args[1])
	}
	if ctx.SysName == "recvmsg" && ctx.Ret == recvmsgEFAULT {
		return fmt.Sprintf("{msg_namelen=%d}", snap.nameLen)
	}
	return formatMsghdrSnapshot(ctx, snap, 1)
}

func (h *MsgHandler) formatMmsghdrArray(ctx *Context) string {
	if ctx.Args[1] == 0 {
		return "NULL"
	}
	if shouldFormatMmsgPointer(ctx) {
		return fmt.Sprintf("%#x", ctx.Args[1])
	}
	snaps := mmsghdrSnapshotsForFormatting(ctx)
	if len(snaps) == 0 {
		return fmt.Sprintf("%#x", ctx.Args[1])
	}
	items := make([]string, 0, len(snaps))
	for _, snap := range snaps {
		iovCtx := mmsgIovecContext(ctx, snap.msgLen)
		item := fmt.Sprintf("{msg_hdr=%s, msg_len=%d}", formatMsghdrSnapshot(&iovCtx, snap.msghdrSnapshot, snap.iovArg), snap.msgLen)
		items = append(items, item)
	}
	res := "[" + strings.Join(items, ", ") + "]"
	if ctx.Args[2] > uint64(len(snaps)) {
		res = strings.TrimSuffix(res, "]") + ", ...]"
	}
	return res
}

func (h *MsgHandler) decodeMmsgTimeout(ctx *Context) string {
	if ctx.Args[4] == 0 {
		return "NULL"
	}
	if data, ok := mmsgTimeoutPayload(ctx, PayloadDirectionIn); ok {
		return format.Timespec(data)
	}
	return fmt.Sprintf("%#x", ctx.Args[4])
}

func shouldFormatMmsgPointer(ctx *Context) bool {
	return ctx.SysName == "recvmmsg" && ctx.Ret < 0 && ctx.Args[4] != 0
}

func mmsgTimeoutPayload(ctx *Context, direction PayloadDirection) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(4, direction); ok {
		return boundedBpfStructData(data, timespecSize)
	}
	return nil, false
}

func formatMsghdrSnapshot(ctx *Context, snap msghdrSnapshot, iovArg int) string {
	return fmt.Sprintf("{msg_name=%s, msg_namelen=%s, msg_iov=%s, msg_iovlen=%d, %s, msg_flags=%d}",
		formatMsgName(ctx, snap),
		formatMsgNameLen(ctx, snap),
		DecodeIovecArray(ctx, iovArg, snap.iov, snap.iovLen),
		snap.iovLen,
		formatMsgControl(ctx, snap),
		snap.flags)
}

func msghdrSnapshotForFormatting(ctx *Context) (msghdrSnapshot, bool) {
	if ctx == nil {
		return msghdrSnapshot{}, false
	}
	if ctx.SysName == "recvmsg" && ctx.Ret >= 0 {
		if snap, ok := msghdrPayloadSnapshot(ctx, PayloadDirectionOut); ok {
			return snap, true
		}
	}
	return msghdrPayloadSnapshot(ctx, PayloadDirectionIn)
}

func msghdrPayloadSnapshot(ctx *Context, direction PayloadDirection) (msghdrSnapshot, bool) {
	data, ok := ctx.PayloadStruct(1, direction)
	if !ok || len(data) < msghdrSnapshotSize {
		return msghdrSnapshot{}, false
	}
	return parseMsghdrSnapshot(data)
}

func parseMsghdrSnapshot(data []byte) (msghdrSnapshot, bool) {
	if len(data) < msghdrSnapshotSize {
		return msghdrSnapshot{}, false
	}
	return msghdrSnapshot{
		name:       binary.LittleEndian.Uint64(data[msghdrNameOffset : msghdrNameOffset+8]),
		nameLen:    binary.LittleEndian.Uint32(data[msghdrNameLenOffset : msghdrNameLenOffset+4]),
		iov:        binary.LittleEndian.Uint64(data[msghdrIovOffset : msghdrIovOffset+8]),
		iovLen:     binary.LittleEndian.Uint64(data[msghdrIovLenOffset : msghdrIovLenOffset+8]),
		control:    binary.LittleEndian.Uint64(data[msghdrControlOffset : msghdrControlOffset+8]),
		controlLen: binary.LittleEndian.Uint64(data[msghdrControlLenOffset : msghdrControlLenOffset+8]),
		flags:      binary.LittleEndian.Uint32(data[msghdrFlagsOffset : msghdrFlagsOffset+4]),
	}, true
}

type mmsghdrSnapshot struct {
	msghdrSnapshot
	slot   int
	iovArg int
	msgLen uint32
}

func mmsghdrSnapshotsForFormatting(ctx *Context) []mmsghdrSnapshot {
	if ctx == nil {
		return nil
	}
	if ctx.Ret >= 0 {
		if snaps := mmsghdrPayloadSnapshots(ctx, PayloadDirectionOut); len(snaps) > 0 {
			return snaps
		}
	}
	return mmsghdrPayloadSnapshots(ctx, PayloadDirectionIn)
}

func mmsghdrPayloadSnapshots(ctx *Context, direction PayloadDirection) []mmsghdrSnapshot {
	data, ok := ctx.PayloadStruct(1, direction)
	if !ok || len(data) < mmsghdrSnapshotSize {
		return nil
	}
	count := len(data) / mmsghdrSnapshotSize
	if count > mmsghdrDisplayLimit {
		count = mmsghdrDisplayLimit
	}
	snaps := make([]mmsghdrSnapshot, 0, count)
	for slot := 0; slot < count; slot++ {
		offset := slot * mmsghdrSnapshotSize
		snap, ok := parseMsghdrSnapshot(data[offset : offset+mmsghdrSnapshotSize])
		if !ok {
			continue
		}
		snaps = append(snaps, mmsghdrSnapshot{
			msghdrSnapshot: snap,
			slot:           slot,
			iovArg:         mmsgIovecArgIndex(slot),
			msgLen:         binary.LittleEndian.Uint32(data[offset+mmsghdrMsgLenOffset : offset+mmsghdrMsgLenOffset+4]),
		})
	}
	return snaps
}

func addMmsgHexDump(ctx *Context, res *Result, snap mmsghdrSnapshot) {
	if snap.msgLen == 0 {
		return
	}
	iovCtx := mmsgIovecContext(ctx, snap.msgLen)
	part := Result{}
	addIovecHexDump(&iovCtx, &part, snap.iovArg, snap.iovLen)
	if part.HexDumpStr != "" {
		res.HexDumpStr += fmt.Sprintf(" = %d buffers in vector %d\n", snap.iovLen, snap.slot)
	}
	res.HexDumpStr += part.HexDumpStr
}

func mmsgIovecContext(ctx *Context, msgLen uint32) Context {
	iovCtx := *ctx
	iovCtx.Ret = int64(msgLen)
	return iovCtx
}

func mmsgIovecArgIndex(slot int) int {
	switch slot {
	case 1:
		return mmsghdrSecondIovArg
	case 2:
		return mmsghdrThirdIovArg
	case 3:
		return mmsghdrFourthIovArg
	default:
		return 1
	}
}

func formatMsgName(ctx *Context, snap msghdrSnapshot) string {
	if snap.name == 0 {
		return "NULL"
	}
	data, ok := ctx.payloadData(1, PayloadKindSockaddr, PayloadDirectionOut)
	if !ok {
		return fmt.Sprintf("%#x", snap.name)
	}
	displayLen := msgNameDisplayLen(ctx, snap)
	return format.Sockaddr(data, displayLen, displayLen)
}

func formatMsgNameLen(ctx *Context, snap msghdrSnapshot) string {
	if ctx.SysName == "recvmsg" && ctx.Ret >= 0 {
		if enterSnap, ok := msghdrPayloadSnapshot(ctx, PayloadDirectionIn); ok &&
			enterSnap.nameLen != 0 && enterSnap.nameLen != snap.nameLen {
			return fmt.Sprintf("%d => %d", enterSnap.nameLen, snap.nameLen)
		}
	}
	return fmt.Sprintf("%d", snap.nameLen)
}

func msgNameDisplayLen(ctx *Context, snap msghdrSnapshot) uint32 {
	if ctx.SysName == "recvmsg" && ctx.Ret >= 0 {
		if enterSnap, ok := msghdrPayloadSnapshot(ctx, PayloadDirectionIn); ok &&
			enterSnap.nameLen != 0 && enterSnap.nameLen < snap.nameLen {
			return enterSnap.nameLen
		}
	}
	return snap.nameLen
}

func formatMsgControl(ctx *Context, snap msghdrSnapshot) string {
	if snap.controlLen == 0 {
		return "msg_controllen=0"
	}
	direction := PayloadDirectionIn
	if ctx.SysName == "recvmsg" && ctx.Ret >= 0 {
		direction = PayloadDirectionOut
	}
	data, ok := ctx.PayloadCmsg(1, direction)
	if !ok || len(data) < cmsgHeaderSize {
		return fmt.Sprintf("msg_control=%#x, msg_controllen=%d", snap.control, snap.controlLen)
	}
	if control, ok := formatControlMessages(ctx, snap.control, snap.controlLen, data); ok {
		return fmt.Sprintf("msg_control=%s, msg_controllen=%d", control, snap.controlLen)
	}
	return fmt.Sprintf("msg_control=%#x, msg_controllen=%d", snap.control, snap.controlLen)
}
