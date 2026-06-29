package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

// decodeBpfIterCreate decodes BPF_ITER_CREATE.
// Impact: Decodes iterator link fd.
func decodeBpfIterCreate(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("link_fd=%d", int32(binary.LittleEndian.Uint32(data[0:4]))))
		decodedSize = 4
	}
	if len(data) >= 8 {
		parts = append(parts, "flags="+fmtHex32(binary.LittleEndian.Uint32(data[4:8])))
		decodedSize = 8
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{iter_create={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

// decodeBpfLinkDetach decodes BPF_LINK_DETACH.
// Impact: Decodes link fd to detach.
func decodeBpfLinkDetach(ctx *Context, data []byte, size uint32, attr uint64) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("link_fd=%d", int32(binary.LittleEndian.Uint32(data[0:4]))))
		decodedSize = 4
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	if len(parts) > 0 {
		return "{link_detach={" + strings.Join(parts, ", ") + "}" + extra + "}"
	}
	return fmt.Sprintf("%#x", attr)
}

// decodeBpfLinkCreate decodes BPF_LINK_CREATE.
// Impact: Decodes link creation options, attach type, flags, and specific union fields depending on attach_type.
func decodeBpfLinkCreate(ctx *Context, data []byte, size uint32) string {
	parts := []string{}
	parts = append(parts, fmt.Sprintf("prog_fd=%d", int32(u32OrZero(data, 0))))

	targetVal := u32OrZero(data, 4)
	attachType := u32OrZero(data, 8)
	flagsVal := u32OrZero(data, 12)

	// BPF_XDP (37), BPF_TCX_INGRESS (46), BPF_TCX_EGRESS (47), BPF_NETKIT_PRIMARY (54), BPF_NETKIT_PEER (55)
	if isIfindexAttachType(attachType) {
		parts = append(parts, "target_ifindex="+translateIfindex(targetVal))
	} else {
		parts = append(parts, fmt.Sprintf("target_fd=%d", int32(targetVal)))
	}
	parts = append(parts, "attach_type="+meta.DecodeFlags(uint64(attachType), "bpf_attach_type"))
	parts = append(parts, "flags="+meta.DecodeFlags(uint64(flagsVal), "bpf_attach_flags"))
	decodedSize := 16

	if size >= 20 {
		decodedSize = decodeLinkCreateUnion(ctx, data, size, attachType, flagsVal, &parts, decodedSize)
	}

	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{link_create={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

// decodeLinkCreateUnion dispatches union-specific decoding for BPF_LINK_CREATE.
// Impact: Routes to the correct union struct decoder based on attach_type.
func decodeLinkCreateUnion(ctx *Context, data []byte, size, attachType, flags uint32, parts *[]string, ds int) int {
	switch attachType {
	case 28: // BPF_TRACE_ITER
		if size >= 28 {
			*parts = append(*parts, decodeBpfIterInfo(ctx, u64OrZero(data, 16), u32OrZero(data, 24)))
			*parts = append(*parts, fmt.Sprintf("iter_info_len=%d", u32OrZero(data, 24)))
			return 28
		}
	case 24, 25, 26, 27, 58: // tracing attach types
		*parts = append(*parts, fmt.Sprintf("tracing={target_btf_id=%d, cookie=%s}", u32OrZero(data, 16), fmtHex64(u64OrZero(data, 24))))
		return 32
	case 41: // BPF_PERF_EVENT
		cookie := u64OrZero(data, 16)
		if cookie == 0 {
			*parts = append(*parts, "perf_event={bpf_cookie=0}")
		} else {
			*parts = append(*parts, fmt.Sprintf("perf_event={bpf_cookie=%#x}", cookie))
		}
		return 24
	case 42: // BPF_TRACE_KPROBE_MULTI
		*parts = append(*parts, formatKprobeMulti(ctx, u32OrZero(data, 16), u32OrZero(data, 20), u64OrZero(data, 24), u64OrZero(data, 32), u64OrZero(data, 40)))
		return 48
	case 45: // BPF_NETFILTER
		*parts = append(*parts, fmt.Sprintf("netfilter={pf=%d, hooknum=%d, priority=%d, flags=%s}", u32OrZero(data, 16), u32OrZero(data, 20), int32(u32OrZero(data, 24)), meta.DecodeFlags(uint64(u32OrZero(data, 28)), "bpf_netfilter_ip_flags")))
		return 32
	case 46, 47: // BPF_TCX_INGRESS, BPF_TCX_EGRESS
		return decodeTcxOrNetkitStruct(data, flags, parts, "tcx")
	case 48: // BPF_TRACE_UPROBE_MULTI
		return decodeUprobeMulti(data, parts)
	case 54, 55: // BPF_NETKIT_PRIMARY, BPF_NETKIT_PEER
		return decodeTcxOrNetkitStruct(data, flags, parts, "netkit")
	default:
		return decodeLinkCreateCgroupOrDefault(data, size, attachType, flags, parts, ds)
	}
	return ds
}

// decodeLinkCreateCgroupOrDefault handles cgroup and default link create union fields.
// Impact: Decodes cgroup struct (when BPF_F_BEFORE/AFTER set) or target_btf_id for cgroup types.
func decodeLinkCreateCgroupOrDefault(data []byte, size, attachType, flags uint32, parts *[]string, ds int) int {
	isCgroup := isCgroupAttachType(attachType)
	// BPF_F_BEFORE (0x8) or BPF_F_AFTER (0x10) set → cgroup struct
	if isCgroup && (flags&0x8 != 0 || flags&0x10 != 0) {
		relVal := u32OrZero(data, 16)
		if (flags & 0x20) != 0 { // BPF_F_ID
			*parts = append(*parts, fmt.Sprintf("cgroup={relative_id=%d, expected_revision=%s}", relVal, fmtHex64(u64OrZero(data, 24))))
		} else {
			*parts = append(*parts, fmt.Sprintf("cgroup={relative_fd=%d, expected_revision=%s}", int32(relVal), fmtHex64(u64OrZero(data, 24))))
		}
		return 32
	}
	// Cgroup without BPF_F_BEFORE/AFTER → target_btf_id (check #28)
	if isCgroup && size >= 20 {
		btfId := u32OrZero(data, 16)
		if btfId != 0 {
			*parts = append(*parts, fmt.Sprintf("target_btf_id=%d", btfId))
		}
		return 20
	}
	return ds
}

// formatKprobeMulti formats the kprobe_multi struct fields.
// Impact: Formats flags, cnt, and pointer array fields for kprobe_multi.
func formatKprobeMulti(ctx *Context, kflags, cnt uint32, syms, addrs, cookies uint64) string {
	var kparts []string
	if kflags == 0 {
		kparts = append(kparts, "flags=0")
	} else {
		kparts = append(kparts, "flags="+meta.DecodeFlags(uint64(kflags), "bpf_kprobe_multi_flags"))
	}
	kparts = append(kparts, fmt.Sprintf("cnt=%d", cnt))

	kparts = append(kparts, decodeSymsArray(ctx, syms, cnt))
	kparts = append(kparts, decodeU64Array(ctx, "addrs", addrs, cnt))
	kparts = append(kparts, decodeU64Array(ctx, "cookies", cookies, cnt))
	return "kprobe_multi={" + strings.Join(kparts, ", ") + "}"
}

// isIfindexAttachType returns true if the attach type uses target_ifindex instead of target_fd.
func isIfindexAttachType(t uint32) bool {
	return t == 37 || t == 46 || t == 47 || t == 54 || t == 55
}

// isCgroupAttachType checks if the attach type is a cgroup or cgroup-like type.
// Impact: Determines whether cgroup struct or target_btf_id should be decoded.
func isCgroupAttachType(t uint32) bool {
	switch t {
	case 0, 1, 2, 3, 6, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19, 20, 21, 22:
		return true
	case 29, 30, 31, 32, 34, 49, 50, 51, 52, 53:
		return true
	}
	return false
}

// decodeTcxOrNetkitStruct decodes tcx or netkit union struct in BPF_LINK_CREATE.
// Impact: Formats relative_fd/relative_id and expected_revision fields.
func decodeTcxOrNetkitStruct(data []byte, flags uint32, parts *[]string, name string) int {
	relVal := u32OrZero(data, 16)
	if (flags & 0x20) != 0 { // BPF_F_ID
		*parts = append(*parts, fmt.Sprintf("%s={relative_id=%d, expected_revision=%s}", name, relVal, fmtHex64(u64OrZero(data, 24))))
	} else {
		*parts = append(*parts, fmt.Sprintf("%s={relative_fd=%d, expected_revision=%s}", name, int32(relVal), fmtHex64(u64OrZero(data, 24))))
	}
	return 32
}

// decodeUprobeMulti decodes uprobe_multi struct in BPF_LINK_CREATE.
// Impact: Formats path, offsets, ref_ctr_offsets, cookies, cnt, flags, and pid.
func decodeUprobeMulti(data []byte, parts *[]string) int {
	var up []string
	up = append(up, formatPtr("path", u64OrZero(data, 16)))
	up = append(up, formatPtr("offsets", u64OrZero(data, 24)))
	up = append(up, formatPtr("ref_ctr_offsets", u64OrZero(data, 32)))
	up = append(up, formatPtr("cookies", u64OrZero(data, 40)))
	up = append(up, fmt.Sprintf("cnt=%d", u32OrZero(data, 48)))
	upFlags := u32OrZero(data, 52)
	if upFlags == 0 {
		up = append(up, "flags=0")
	} else {
		up = append(up, "flags="+meta.DecodeFlags(uint64(upFlags), "bpf_uprobe_multi_flags"))
	}
	up = append(up, fmt.Sprintf("pid=%d", u32OrZero(data, 56)))
	*parts = append(*parts, "uprobe_multi={"+strings.Join(up, ", ")+"}")
	return 60
}

// decodeBpfLinkUpdate decodes BPF_LINK_UPDATE.
// Impact: Decodes link update fd and prog fd details.
func decodeBpfLinkUpdate(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("link_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
	if len(data) >= 8 {
		parts = append(parts, fmt.Sprintf("new_prog_fd=%d", int32(u32OrZero(data, 4))))
		decodedSize = 8
	}
	flagsVal := uint32(0)
	if len(data) >= 12 {
		flagsVal = u32OrZero(data, 8)
		parts = append(parts, "flags="+meta.DecodeFlags(uint64(flagsVal), "bpf_attach_flags"))
		decodedSize = 12
	}
	if len(data) >= 16 && (flagsVal&4) != 0 {
		parts = append(parts, fmt.Sprintf("old_prog_fd=%d", int32(u32OrZero(data, 12))))
		decodedSize = 16
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{link_update={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

// fmtHex64 formats a 64-bit unsigned integer as hex, or "0" if zero.
func fmtHex64(val uint64) string {
	if val == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", val)
}

// fmtHex32 formats a 32-bit unsigned integer as hex, or "0" if zero.
func fmtHex32(val uint32) string {
	if val == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", val)
}

// decodeBpfProgBindMap decodes BPF_PROG_BIND_MAP.
// Impact: Decodes prog fd and map fd association details.
func decodeBpfProgBindMap(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("prog_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
	if len(data) >= 8 {
		parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 4))))
		decodedSize = 8
	}
	if len(data) >= 12 {
		parts = append(parts, "flags="+fmtHex32(u32OrZero(data, 8)))
		decodedSize = 12
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{prog_bind_map={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

// decodeBpfTokenCreate decodes BPF_TOKEN_CREATE.
// Impact: Decodes token create options.
func decodeBpfTokenCreate(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, "flags="+fmtHex32(u32OrZero(data, 0)))
		decodedSize = 4
	}
	if len(data) >= 8 {
		parts = append(parts, fmt.Sprintf("bpffs_fd=%d", int32(u32OrZero(data, 4))))
		decodedSize = 8
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{token_create={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

// decodeBpfProgStreamReadByFd decodes BPF_PROG_STREAM_READ_BY_FD.
// Impact: Decodes stream read options including buffer and file descriptors.
func decodeBpfProgStreamReadByFd(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}

	bufAddr := u64OrZero(data, 0)
	bufLen := u32OrZero(data, 8)

	if len(data) >= 8 {
		parts = append(parts, "stream_buf="+decodeStreamBuf(ctx, bufAddr, bufLen))
		decodedSize = 8
	}
	if len(data) >= 12 {
		parts = append(parts, fmt.Sprintf("stream_buf_len=%d", bufLen))
		decodedSize = 12
	}
	if len(data) >= 16 {
		parts = append(parts, fmt.Sprintf("stream_id=%d", u32OrZero(data, 12)))
		decodedSize = 16
	}
	if len(data) >= 20 {
		parts = append(parts, fmt.Sprintf("prog_fd=%d", int32(u32OrZero(data, 16))))
		decodedSize = 20
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{prog_stream_read={" + strings.Join(parts, ", ") + "}" + extra + "}"
}
