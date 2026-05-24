package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

func init() {
	Register("bpf", &BpfHandler{})
}

// IMPACT: BpfHandler handles the decoding of bpf syscall parameters.
// This implementation uses contextual pre-read arguments to safely decode structure details
// and appends extra_data block when buffer size exceeds the parsed struct size.
type BpfHandler struct{}

func (h *BpfHandler) Handle(ctx *Context) Result {
	res := Result{}
	cmd := ctx.Args[0]
	attr := ctx.Args[1]
	size := uint32(ctx.Args[2])

	cmdStr := meta.DecodeFlags(cmd, "bpf_commands")
	res.ArgParts = append(res.ArgParts, cmdStr)

	var data []byte
	var readSuccess bool

	if attr != 0 && size > 0 && size <= 4096 && ctx.Ret != -14 {
		if ctx.ProbeRetEnter >= 0 {
			readLen := int(size)
			if readLen > 512 {
				readLen = 512
			}
			if len(ctx.StrArgBuf) >= readLen {
				data = ctx.StrArgBuf[0:readLen]
				readSuccess = true
			}
		}
		if !readSuccess {
			d, err := ctx.MemReader.ReadRobust(ctx.Pid, attr, int(size), false)
			if err == nil && len(d) >= int(size) {
				ctx.StrArgBuf = d
				readLen := int(size)
				if readLen > 512 {
					readLen = 512
				}
				data = d[0:readLen]
				readSuccess = true
			}
		}
	}

	if !readSuccess {
		if attr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", attr))
		}
	} else {
		res.ArgParts = append(res.ArgParts, decodeCmd(ctx, cmd, data, size, attr))
	}

	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", size))
	return res
}

func u32OrZero(data []byte, off int) uint32 {
	if len(data) >= off+4 {
		return binary.LittleEndian.Uint32(data[off : off+4])
	}
	return 0
}

func u64OrZero(data []byte, off int) uint64 {
	if len(data) >= off+8 {
		return binary.LittleEndian.Uint64(data[off : off+8])
	}
	return 0
}

func decodeCmd(ctx *Context, cmd uint64, data []byte, size uint32, attr uint64) string {
	switch cmd {
	case 0:
		return decodeBpfMapCreate(ctx, data, size)
	case 1, 20: // BPF_MAP_LOOKUP_ELEM, BPF_MAP_LOOKUP_AND_DELETE_ELEM
		return decodeBpfMapLookup(ctx, data, size)
	case 2: // BPF_MAP_UPDATE_ELEM
		return decodeBpfMapUpdate(ctx, data, size)
	case 3: // BPF_MAP_DELETE_ELEM
		return decodeBpfMapDeleteElem(ctx, data, size)
	case 4: // BPF_MAP_GET_NEXT_KEY
		return decodeBpfMapGetNextKey(ctx, data, size)
	case 5:
		return decodeBpfProgLoad(ctx, data, size)
	case 6, 7: // BPF_OBJ_PIN, BPF_OBJ_GET
		return decodeBpfObjPin(ctx, data, size)
	case 8, 9: // BPF_PROG_ATTACH, BPF_PROG_DETACH
		return decodeBpfProgAttach(ctx, data, size)
	case 10: // BPF_PROG_TEST_RUN
		return decodeBpfProgTestRun(ctx, data, size)
	case 15:
		return decodeBpfObjGetInfoByFd(ctx, data, size)
	case 11, 12, 19, 23, 31:
		return decodeBpfGetNextId(ctx, data, size)
	case 13, 14, 30:
		return decodeBpfGetFdById(ctx, data, size, attr)
	case 32:
		return decodeBpfEnableStats(ctx, data, size, attr)
	case 33:
		return decodeBpfIterCreate(ctx, data, size)
	case 34:
		return decodeBpfLinkDetach(ctx, data, size, attr)
	case 28:
		return decodeBpfLinkCreate(ctx, data, size)
	case 29:
		return decodeBpfLinkUpdate(ctx, data, size)
	case 38:
		return decodeBpfProgAssocStructOps(ctx, data, size)
	default:
		return fmt.Sprintf("%#x", attr)
	}
}

func checkAndFormatExtraData(ctx *Context, offset int, size uint32) string {
	if size <= uint32(offset) {
		return ""
	}
	limit := int(size)
	if limit > 512 {
		limit = 512
	}
	if limit > len(ctx.StrArgBuf) {
		limit = len(ctx.StrArgBuf)
	}
	if limit <= offset {
		return ""
	}
	extraBytes := ctx.StrArgBuf[offset:limit]
	hasNonZero := false
	for _, b := range extraBytes {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		return ""
	}

	if ctx.Opts.Verbose {
		strLimit := ctx.Opts.StringLimit
		if strLimit <= 0 {
			strLimit = 32
		}
		var sb strings.Builder
		sb.WriteString(", extra_data=\"")
		printLen := len(extraBytes)
		truncated := false
		if printLen > strLimit {
			printLen = strLimit
			truncated = true
		}
		if size > uint32(offset+printLen) {
			truncated = true
		}
		for i := 0; i < printLen; i++ {
			sb.WriteString(fmt.Sprintf("\\x%02x", extraBytes[i]))
		}
		if truncated {
			sb.WriteString("...")
		}
		sb.WriteString(fmt.Sprintf("\" /* bytes %d..%d */", offset, size-1))
		return sb.String()
	}
	return ", ..."
}

func decodeBpfMapCreate(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		t := binary.LittleEndian.Uint32(data[0:4])
		parts = append(parts, "map_type="+meta.DecodeFlags(uint64(t), "bpf_map_types"))
		decodedSize = 4
	}
	parts = append(parts, fmt.Sprintf("key_size=%d", u32OrZero(data, 4)))
	parts = append(parts, fmt.Sprintf("value_size=%d", u32OrZero(data, 8)))
	parts = append(parts, fmt.Sprintf("max_entries=%d", u32OrZero(data, 12)))
	if decodedSize < 16 && len(data) >= 16 {
		decodedSize = 16
	}
	if size >= 20 {
		parts = append(parts, "map_flags="+meta.DecodeFlags(uint64(u32OrZero(data, 16)), "bpf_map_flags"))
		decodedSize = 20
	}
	if size >= 24 {
		parts = append(parts, fmt.Sprintf("inner_map_fd=%d", int32(u32OrZero(data, 20))))
		decodedSize = 24
	}
	if size >= 28 {
		if (u32OrZero(data, 16) & 4) != 0 {
			node := int32(u32OrZero(data, 24))
			if node == -1 {
				parts = append(parts, "numa_node=-1 /* NUMA_NO_NODE */")
			} else {
				parts = append(parts, fmt.Sprintf("numa_node=%d", uint32(node)))
			}
		}
		decodedSize = 28
	}
	if size > 28 {
		nameLen := int(size) - 28
		if nameLen > 16 {
			nameLen = 16
		}
		if len(data) < 28+nameLen {
			nameLen = len(data) - 28
		}
		if nameLen > 0 {
			name := string(data[28 : 28+nameLen])
			if idx := strings.IndexByte(name, 0); idx != -1 {
				name = name[:idx]
				parts = append(parts, fmt.Sprintf("map_name=%q", name))
			} else {
				limit := nameLen
				if limit > 7 {
					limit = 7
				}
				parts = append(parts, fmt.Sprintf("map_name=%q...", name[:limit]))
			}
		}
		if decodedSize < 28+nameLen {
			decodedSize = 28 + nameLen
		}
	}
	if size >= 48 {
		parts = append(parts, fmt.Sprintf("map_ifindex=%d", u32OrZero(data, 44)))
		decodedSize = 48
	}
	if size >= 52 {
		parts = append(parts, fmt.Sprintf("btf_fd=%d", int32(u32OrZero(data, 48))))
		decodedSize = 52
	}
	if size >= 56 {
		parts = append(parts, fmt.Sprintf("btf_key_type_id=%d", u32OrZero(data, 52)))
		decodedSize = 56
	}
	if size >= 60 {
		parts = append(parts, fmt.Sprintf("btf_value_type_id=%d", u32OrZero(data, 56)))
		decodedSize = 60
	}
	if size >= 64 {
		parts = append(parts, fmt.Sprintf("btf_vmlinux_value_type_id=%d", u32OrZero(data, 60)))
		decodedSize = 64
	}
	if size >= 72 {
		parts = append(parts, fmt.Sprintf("map_extra=%d", u64OrZero(data, 64)))
		decodedSize = 72
	}
	if size >= 76 {
		parts = append(parts, fmt.Sprintf("value_type_btf_obj_fd=%d", int32(u32OrZero(data, 72))))
		decodedSize = 76
	}
	if size >= 80 {
		parts = append(parts, fmt.Sprintf("map_token_fd=%d", int32(u32OrZero(data, 76))))
		decodedSize = 80
	}
	if size >= 88 {
		parts = append(parts, fmt.Sprintf("excl_prog_hash=%#x", u64OrZero(data, 80)))
		decodedSize = 88
	}
	if size >= 92 {
		parts = append(parts, fmt.Sprintf("excl_prog_hash_size=%d", u32OrZero(data, 88)))
		decodedSize = 92
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

func decodeBpfProgLoad(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		t := binary.LittleEndian.Uint32(data[0:4])
		parts = append(parts, "prog_type="+meta.DecodeFlags(uint64(t), "bpf_prog_types"))
		decodedSize = 4
	}
	parts = append(parts, fmt.Sprintf("insn_cnt=%d", u32OrZero(data, 4)))
	insns := u64OrZero(data, 8)
	if insns == 0 {
		parts = append(parts, "insns=NULL")
	} else {
		parts = append(parts, fmt.Sprintf("insns=%#x", insns))
	}
	licAddr := u64OrZero(data, 16)
	if licAddr == 0 {
		parts = append(parts, "license=NULL")
	} else {
		lic, err := ctx.MemReader.ReadRobust(ctx.Pid, licAddr, 64, false)
		if err == nil {
			s := string(lic)
			if idx := strings.IndexByte(s, 0); idx != -1 {
				s = s[:idx]
			}
			parts = append(parts, fmt.Sprintf("license=%q", s))
		} else {
			parts = append(parts, fmt.Sprintf("license=%#x", licAddr))
		}
	}
	if decodedSize < 24 && len(data) >= 24 {
		decodedSize = 24
	}
	if size >= 28 {
		parts = append(parts, fmt.Sprintf("log_level=%d", u32OrZero(data, 24)))
		decodedSize = 28
	}
	if size >= 32 {
		parts = append(parts, fmt.Sprintf("log_size=%d", u32OrZero(data, 28)))
		decodedSize = 32
	}
	if size >= 40 {
		logBuf := u64OrZero(data, 32)
		if logBuf == 0 {
			parts = append(parts, "log_buf=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("log_buf=%#x", logBuf))
		}
		decodedSize = 40
	}
	if size >= 44 {
		kv := u32OrZero(data, 40)
		parts = append(parts, fmt.Sprintf("kern_version=KERNEL_VERSION(%d, %d, %d)", kv>>16, (kv>>8)&0xff, kv&0xff))
		decodedSize = 44
	}
	if size >= 48 {
		parts = append(parts, "prog_flags="+meta.DecodeFlags(uint64(u32OrZero(data, 44)), "bpf_prog_flags"))
		decodedSize = 48
	}
	if size >= 64 {
		name := ""
		if len(data) >= 64 {
			name = string(data[48:64])
			if idx := strings.IndexByte(name, 0); idx != -1 {
				name = name[:idx]
			}
		}
		parts = append(parts, fmt.Sprintf("prog_name=%q", name))
		decodedSize = 64
	}
	if size >= 68 {
		parts = append(parts, fmt.Sprintf("prog_ifindex=%d", u32OrZero(data, 64)))
		decodedSize = 68
	}
	if size >= 72 {
		parts = append(parts, "expected_attach_type="+meta.DecodeFlags(uint64(u32OrZero(data, 68)), "bpf_attach_type"))
		decodedSize = 72
	}
	if size >= 76 {
		parts = append(parts, fmt.Sprintf("prog_btf_fd=%d", int32(u32OrZero(data, 72))))
		decodedSize = 76
	}
	if size >= 80 {
		parts = append(parts, fmt.Sprintf("func_info_rec_size=%d", u32OrZero(data, 76)))
		decodedSize = 80
	}
	if size >= 88 {
		parts = append(parts, fmt.Sprintf("func_info=%#x", u64OrZero(data, 80)))
		decodedSize = 88
	}
	if size >= 92 {
		parts = append(parts, fmt.Sprintf("func_info_cnt=%d", u32OrZero(data, 88)))
		decodedSize = 92
	}
	if size >= 96 {
		parts = append(parts, fmt.Sprintf("line_info_rec_size=%d", u32OrZero(data, 92)))
		decodedSize = 96
	}
	if size >= 104 {
		parts = append(parts, fmt.Sprintf("line_info=%#x", u64OrZero(data, 96)))
		decodedSize = 104
	}
	if size >= 108 {
		parts = append(parts, fmt.Sprintf("line_info_cnt=%d", u32OrZero(data, 104)))
		decodedSize = 108
	}
	if size >= 112 {
		parts = append(parts, fmt.Sprintf("attach_btf_id=%d", u32OrZero(data, 108)))
		decodedSize = 112
	}
	if size >= 116 {
		parts = append(parts, fmt.Sprintf("attach_prog_fd=%d", int32(u32OrZero(data, 112))))
		decodedSize = 116
	}
	if size >= 124 {
		parts = append(parts, fmt.Sprintf("fd_array=%#x", u64OrZero(data, 116)))
		decodedSize = 124
	}
	if size >= 128 {
		parts = append(parts, fmt.Sprintf("core_relo_cnt=%d", u32OrZero(data, 124)))
		decodedSize = 128
	}
	if size >= 136 {
		parts = append(parts, fmt.Sprintf("core_relos=%#x", u64OrZero(data, 128)))
		decodedSize = 136
	}
	if size >= 140 {
		parts = append(parts, fmt.Sprintf("core_relo_rec_size=%d", u32OrZero(data, 136)))
		decodedSize = 140
	}
	if size >= 144 {
		parts = append(parts, fmt.Sprintf("log_true_size=%d", u32OrZero(data, 140)))
		decodedSize = 144
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

func decodeBpfMapLookup(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
	if size >= 16 {
		k := u64OrZero(data, 8)
		if k == 0 {
			parts = append(parts, "key=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("key=%#x", k))
		}
		v := u64OrZero(data, 16)
		if v == 0 {
			parts = append(parts, "value=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("value=%#x", v))
		}
		decodedSize = 24
	}
	if size >= 32 {
		parts = append(parts, "flags="+meta.DecodeFlags(u64OrZero(data, 24), "bpf_map_lookup_flags"))
		decodedSize = 32
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

func decodeBpfMapUpdate(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
	if size >= 16 {
		k := u64OrZero(data, 8)
		if k == 0 {
			parts = append(parts, "key=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("key=%#x", k))
		}
		v := u64OrZero(data, 16)
		if v == 0 {
			parts = append(parts, "value=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("value=%#x", v))
		}
		decodedSize = 24
	}
	if size >= 32 {
		parts = append(parts, "flags="+meta.DecodeFlags(u64OrZero(data, 24), "bpf_map_update_flags"))
		decodedSize = 32
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

func decodeBpfMapDeleteElem(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
	if size >= 16 {
		k := u64OrZero(data, 8)
		if k == 0 {
			parts = append(parts, "key=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("key=%#x", k))
		}
		decodedSize = 16
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

func decodeBpfMapGetNextKey(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
	if size >= 16 {
		k := u64OrZero(data, 8)
		if k == 0 {
			parts = append(parts, "key=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("key=%#x", k))
		}
		nk := u64OrZero(data, 16)
		if nk == 0 {
			parts = append(parts, "next_key=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("next_key=%#x", nk))
		}
		decodedSize = 24
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

func decodeBpfObjPin(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 8 {
		pathAddr := u64OrZero(data, 0)
		if pathAddr == 0 {
			parts = append(parts, "pathname=NULL")
		} else {
			p, err := ctx.MemReader.ReadRobust(ctx.Pid, pathAddr, 4096, false)
			if err == nil {
				s := string(p)
				if idx := strings.IndexByte(s, 0); idx != -1 {
					s = s[:idx]
				}
				parts = append(parts, fmt.Sprintf("pathname=%q", s))
			} else {
				parts = append(parts, fmt.Sprintf("pathname=%#x", pathAddr))
			}
		}
		decodedSize = 8
	}
	if size >= 12 {
		parts = append(parts, fmt.Sprintf("bpf_fd=%d", int32(u32OrZero(data, 8))))
		decodedSize = 12
	}
	if size >= 16 {
		parts = append(parts, "file_flags="+meta.DecodeFlags(uint64(u32OrZero(data, 12)), "bpf_file_flags"))
		decodedSize = 16
	}
	if size >= 20 {
		pfd := int32(u32OrZero(data, 16))
		if pfd == -100 {
			parts = append(parts, "path_fd=AT_FDCWD")
		} else {
			parts = append(parts, fmt.Sprintf("path_fd=%d", pfd))
		}
		decodedSize = 20
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

func decodeBpfProgAttach(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("target_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
	if size >= 8 {
		parts = append(parts, fmt.Sprintf("attach_bpf_fd=%d", int32(u32OrZero(data, 4))))
		decodedSize = 8
	}
	if size >= 12 {
		parts = append(parts, "attach_type="+meta.DecodeFlags(uint64(u32OrZero(data, 8)), "bpf_attach_type"))
		decodedSize = 12
	}
	if size >= 16 {
		parts = append(parts, "attach_flags="+meta.DecodeFlags(uint64(u32OrZero(data, 12)), "bpf_attach_flags"))
		decodedSize = 16
	}
	if size >= 20 {
		parts = append(parts, fmt.Sprintf("replace_bpf_fd=%d", int32(u32OrZero(data, 16))))
		decodedSize = 20
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

func decodeBpfProgTestRun(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("prog_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
	parts = append(parts, fmt.Sprintf("retval=%d", u32OrZero(data, 4)))
	parts = append(parts, fmt.Sprintf("data_size_in=%d", u32OrZero(data, 8)))
	parts = append(parts, fmt.Sprintf("data_size_out=%d", u32OrZero(data, 12)))
	if decodedSize < 16 && len(data) >= 16 {
		decodedSize = 16
	}
	if size >= 24 {
		din := u64OrZero(data, 16)
		if din == 0 {
			parts = append(parts, "data_in=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("data_in=%#x", din))
		}
		dout := u64OrZero(data, 24)
		if dout == 0 {
			parts = append(parts, "data_out=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("data_out=%#x", dout))
		}
		decodedSize = 32
	}
	if size >= 36 {
		parts = append(parts, fmt.Sprintf("repeat=%d", u32OrZero(data, 32)))
		decodedSize = 36
	}
	if size >= 40 {
		parts = append(parts, fmt.Sprintf("duration=%d", u32OrZero(data, 36)))
		decodedSize = 40
	}
	if size >= 44 {
		parts = append(parts, fmt.Sprintf("ctx_size_in=%d", u32OrZero(data, 40)))
		decodedSize = 44
	}
	if size >= 48 {
		parts = append(parts, fmt.Sprintf("ctx_size_out=%d", u32OrZero(data, 44)))
		decodedSize = 48
	}
	if size >= 56 {
		cin := u64OrZero(data, 48)
		if cin == 0 {
			parts = append(parts, "ctx_in=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("ctx_in=%#x", cin))
		}
		decodedSize = 56
	}
	if size >= 64 {
		cout := u64OrZero(data, 56)
		if cout == 0 {
			parts = append(parts, "ctx_out=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("ctx_out=%#x", cout))
		}
		decodedSize = 64
	}
	if size >= 68 {
		parts = append(parts, "flags="+meta.DecodeFlags(uint64(u32OrZero(data, 64)), "bpf_test_run_flags"))
		decodedSize = 68
	}
	if size >= 72 {
		parts = append(parts, fmt.Sprintf("cpu=%d", u32OrZero(data, 68)))
		decodedSize = 72
	}
	if size >= 76 {
		parts = append(parts, fmt.Sprintf("batch_size=%d", u32OrZero(data, 72)))
		decodedSize = 76
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{test={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

func decodeBpfObjGetInfoByFd(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("bpf_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
	if len(data) >= 8 {
		parts = append(parts, fmt.Sprintf("info_len=%d", u32OrZero(data, 4)))
		decodedSize = 8
	}
	if len(data) >= 16 {
		info := u64OrZero(data, 8)
		if info == 0 {
			parts = append(parts, "info=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("info=%#x", info))
		}
		decodedSize = 16
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{info={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

func decodeBpfGetNextId(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("start_id=%d", binary.LittleEndian.Uint32(data[0:4])))
		decodedSize = 4
	}
	if len(data) >= 8 {
		parts = append(parts, fmt.Sprintf("next_id=%d", binary.LittleEndian.Uint32(data[4:8])))
		decodedSize = 8
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

func decodeBpfGetFdById(ctx *Context, data []byte, size uint32, attr uint64) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("link_id=%d", binary.LittleEndian.Uint32(data[0:4])))
		decodedSize = 4
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	if len(parts) > 0 {
		return "{" + strings.Join(parts, ", ") + extra + "}"
	}
	return fmt.Sprintf("%#x", attr)
}

func decodeBpfEnableStats(ctx *Context, data []byte, size uint32, attr uint64) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("type=%d", binary.LittleEndian.Uint32(data[0:4])))
		decodedSize = 4
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	if len(parts) > 0 {
		return "{enable_stats={" + strings.Join(parts, ", ") + "}" + extra + "}"
	}
	return fmt.Sprintf("%#x", attr)
}

func decodeBpfIterCreate(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("link_fd=%d", int32(binary.LittleEndian.Uint32(data[0:4]))))
		decodedSize = 4
	}
	if len(data) >= 8 {
		parts = append(parts, fmt.Sprintf("flags=%#x", binary.LittleEndian.Uint32(data[4:8])))
		decodedSize = 8
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{iter_create={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

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

func decodeBpfLinkCreate(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("prog_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
	if len(data) >= 8 {
		parts = append(parts, fmt.Sprintf("target_fd=%d", int32(u32OrZero(data, 4))))
		decodedSize = 8
	}
	if len(data) >= 12 {
		parts = append(parts, "attach_type="+meta.DecodeFlags(uint64(u32OrZero(data, 8)), "bpf_attach_type"))
		decodedSize = 12
	}
	if len(data) >= 16 {
		parts = append(parts, "flags="+meta.DecodeFlags(uint64(u32OrZero(data, 12)), "bpf_map_flags"))
		decodedSize = 16
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{link_create={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

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
	if len(data) >= 12 {
		parts = append(parts, fmt.Sprintf("flags=%#x", u32OrZero(data, 8)))
		decodedSize = 12
	}
	if len(data) >= 16 {
		parts = append(parts, fmt.Sprintf("old_prog_fd=%d", int32(u32OrZero(data, 12))))
		decodedSize = 16
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{link_update={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

func decodeBpfProgAssocStructOps(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
	if len(data) >= 8 {
		parts = append(parts, fmt.Sprintf("prog_fd=%d", int32(u32OrZero(data, 4))))
		decodedSize = 8
	}
	if len(data) >= 12 {
		f := u32OrZero(data, 8)
		if f == 0 {
			parts = append(parts, "flags=0")
		} else {
			parts = append(parts, fmt.Sprintf("flags=%#x", f))
		}
		decodedSize = 12
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{prog_assoc_struct_ops={" + strings.Join(parts, ", ") + "}" + extra + "}"
}
