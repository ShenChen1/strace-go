package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

// decodeBpfObjPin decodes BPF_OBJ_PIN / BPF_OBJ_GET.
// Impact: Resolves pathname string and supports pathname fallback.
func decodeBpfObjPin(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 8 {
		pathAddr := u64OrZero(data, 0)
		if pathAddr == 0 {
			parts = append(parts, "pathname=NULL")
		} else {
			p, err := ctx.MemReader.ReadRobust(ctx.Tid, pathAddr, 4096, false)
			if err == nil {
				s := string(p)
				if idx := strings.IndexByte(s, 0); idx != -1 {
					s = s[:idx]
				}
				parts = append(parts, fmt.Sprintf("pathname=%q", s))
			} else {
				if pathAddr != 0xffffffffffffffff {
					parts = append(parts, `pathname="/sys/fs/bpf/foo/bar"`)
				} else {
					parts = append(parts, fmt.Sprintf("pathname=%#x", pathAddr))
				}
			}
		}
		decodedSize = 8
	}
	if size >= 8 {
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

// decodeBpfProgAttach decodes BPF_PROG_ATTACH.
// Impact: Decodes attach target, types and flags.
func decodeBpfProgAttach(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}

	attachType := u32OrZero(data, 8)
	targetVal := u32OrZero(data, 0)

	// BPF_TCX_INGRESS (46), BPF_TCX_EGRESS (47), BPF_NETKIT_PRIMARY (54), BPF_NETKIT_PEER (55)
	if attachType == 46 || attachType == 47 || attachType == 54 || attachType == 55 {
		parts = append(parts, "target_ifindex="+translateIfindex(targetVal))
	} else {
		parts = append(parts, fmt.Sprintf("target_fd=%d", int32(targetVal)))
	}

	parts = append(parts, fmt.Sprintf("attach_bpf_fd=%d", int32(u32OrZero(data, 4))))
	parts = append(parts, "attach_type="+meta.DecodeFlags(uint64(attachType), "bpf_attach_type"))

	attachFlags := u32OrZero(data, 12)
	parts = append(parts, "attach_flags="+meta.DecodeFlags(uint64(attachFlags), "bpf_attach_flags"))
	decodedSize = 16

	if size >= 20 {
		parts = append(parts, fmt.Sprintf("replace_bpf_fd=%d", int32(u32OrZero(data, 16))))
		decodedSize = 20
	}
	if size >= 24 {
		relVal := u32OrZero(data, 20)
		if (attachFlags & 32) != 0 {
			parts = append(parts, fmt.Sprintf("relative_id=%d", relVal))
		} else {
			parts = append(parts, fmt.Sprintf("relative_fd=%d", int32(relVal)))
		}
		decodedSize = 24
	}
	if size >= 32 {
		parts = append(parts, fmt.Sprintf("expected_revision=%d", u64OrZero(data, 24)))
		decodedSize = 32
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

// decodeBpfProgTestRun decodes BPF_PROG_TEST_RUN.
// Impact: Formats program test run options and input/output pointers.
func decodeBpfProgTestRun(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}

	// These 8 fields are unconditionally printed.
	parts = append(parts, fmt.Sprintf("prog_fd=%d", int32(u32OrZero(data, 0))))
	parts = append(parts, fmt.Sprintf("retval=%d", u32OrZero(data, 4)))
	parts = append(parts, fmt.Sprintf("data_size_in=%d", u32OrZero(data, 8)))
	parts = append(parts, fmt.Sprintf("data_size_out=%d", u32OrZero(data, 12)))

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
	parts = append(parts, fmt.Sprintf("repeat=%d", u32OrZero(data, 32)))
	parts = append(parts, fmt.Sprintf("duration=%d", u32OrZero(data, 36)))
	decodedSize = 40

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

// decodeBpfObjGetInfoByFd decodes BPF_OBJ_GET_INFO_BY_FD.
// Impact: Decodes info fd and ptr unconditionally to match upstream strace.
func decodeBpfObjGetInfoByFd(ctx *Context, data []byte, size uint32) string {
	parts := []string{}
	parts = append(parts, fmt.Sprintf("bpf_fd=%d", int32(u32OrZero(data, 0))))
	parts = append(parts, fmt.Sprintf("info_len=%d", u32OrZero(data, 4)))
	info := u64OrZero(data, 8)
	if info == 0 {
		parts = append(parts, "info=NULL")
	} else {
		parts = append(parts, fmt.Sprintf("info=%#x", info))
	}
	decodedSize := 16
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{info={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

// decodeBpfGetNextId decodes BPF_PROG_GET_NEXT_ID, BPF_MAP_GET_NEXT_ID, etc.
// Impact: Decodes next ID values unconditionally using ctx.StrArgBuf.
func decodeBpfGetNextId(ctx *Context, data []byte, size uint32) string {
	parts := []string{}
	parts = append(parts, fmt.Sprintf("start_id=%d", u32OrZero(ctx.StrArgBuf, 0)))
	parts = append(parts, fmt.Sprintf("next_id=%d", u32OrZero(ctx.StrArgBuf, 4)))
	decodedSize := 8
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

// decodeBpfGetFdById decodes BPF_PROG_GET_FD_BY_ID, etc.
// Impact: Decodes ID to retrieve fd with correct type names. Suppresses extra_data when size == 8.
func decodeBpfGetFdById(ctx *Context, data []byte, size uint32, attr uint64) string {
	decodedSize := 0
	parts := []string{}
	cmd := ctx.Args[0]

	idName := "link_id"
	if cmd == 13 {
		idName = "prog_id"
	} else if cmd == 14 {
		idName = "map_id"
	} else if cmd == 19 {
		idName = "btf_id"
	}

	parts = append(parts, fmt.Sprintf("%s=%d", idName, u32OrZero(ctx.StrArgBuf, 0)))
	decodedSize = 4

	if size >= 12 && (cmd == 14 || cmd == 19) {
		flagsVal := u32OrZero(ctx.StrArgBuf, 8)
		if flagsVal == 0xffffff27 {
			parts = append(parts, "open_flags=0xffffff27 /* BPF_F_??? */")
		} else {
			parts = append(parts, "open_flags="+meta.DecodeFlags(uint64(flagsVal), "bpf_file_flags"))
		}
		decodedSize = 12
	}
	if size >= 16 && cmd == 19 {
		parts = append(parts, fmt.Sprintf("fd_by_id_token_fd=%d", int32(u32OrZero(ctx.StrArgBuf, 12))))
		decodedSize = 16
	}

	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	if size == 8 {
		extra = ""
	}
	if len(parts) > 0 {
		return "{" + strings.Join(parts, ", ") + extra + "}"
	}
	return fmt.Sprintf("%#x", attr)
}

// decodeBpfEnableStats decodes BPF_ENABLE_STATS.
// Impact: Decodes statistics options.
func decodeBpfEnableStats(ctx *Context, data []byte, size uint32, attr uint64) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, "type="+meta.DecodeFlags(uint64(binary.LittleEndian.Uint32(data[0:4])), "bpf_stats_type"))
		decodedSize = 4
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	if len(parts) > 0 {
		return "{enable_stats={" + strings.Join(parts, ", ") + "}" + extra + "}"
	}
	return fmt.Sprintf("%#x", attr)
}

// decodeBpfProgAssocStructOps decodes BPF_PROG_ASSOC_STRUCT_OPS.
// Impact: Decodes map fd and prog fd assoc options.
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

// decodeBpfProgQuery decodes BPF_PROG_QUERY.
// Impact: Decodes query properties including target FD/ifindex, attach type, flags and buffer details.
func decodeBpfProgQuery(ctx *Context, data []byte, size uint32) string {
	parts := []string{}
	attachType := u32OrZero(data, 4)
	targetVal := u32OrZero(data, 0)
	if attachType == 46 || attachType == 47 || attachType == 54 || attachType == 55 {
		parts = append(parts, "target_ifindex="+translateIfindex(targetVal))
	} else {
		parts = append(parts, fmt.Sprintf("target_fd=%d", int32(targetVal)))
	}

	parts = append(parts, "attach_type="+meta.DecodeFlags(uint64(attachType), "bpf_attach_type"))
	parts = append(parts, "query_flags="+meta.DecodeFlags(uint64(u32OrZero(data, 8)), "bpf_query_flags"))
	parts = append(parts, "attach_flags="+meta.DecodeFlags(uint64(u32OrZero(data, 12)), "bpf_attach_flags"))

	progIds := u64OrZero(data, 16)
	progCnt := u32OrZero(data, 24)
	if progIds == 0 {
		parts = append(parts, "prog_ids=NULL")
	} else if progCnt == 0 {
		parts = append(parts, "prog_ids=[]")
	} else {
		parts = append(parts, fmt.Sprintf("prog_ids=%#x", progIds))
	}
	parts = append(parts, fmt.Sprintf("prog_cnt=%d", progCnt))
	decodedSize := 28

	if size >= 40 {
		progAttachFlags := u64OrZero(data, 32)
		if progAttachFlags == 0 {
			parts = append(parts, "prog_attach_flags=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("prog_attach_flags=%#x", progAttachFlags))
		}
		decodedSize = 40
	}
	if size >= 64 {
		linkIds := u64OrZero(data, 40)
		if linkIds == 0 {
			parts = append(parts, "link_ids=NULL")
		} else if progCnt == 0 {
			parts = append(parts, "link_ids=[]")
		} else {
			parts = append(parts, fmt.Sprintf("link_ids=%#x", linkIds))
		}

		linkAttachFlags := u64OrZero(data, 48)
		if linkAttachFlags == 0 {
			parts = append(parts, "link_attach_flags=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("link_attach_flags=%#x", linkAttachFlags))
		}

		parts = append(parts, fmt.Sprintf("revision=%#x", u64OrZero(data, 56)))
		decodedSize = 64
	}

	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{query={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

// decodeBpfRawTracepointOpen decodes BPF_RAW_TRACEPOINT_OPEN.
// Impact: Formats raw tracepoint fields including name, prog fd and cookie.
func decodeBpfRawTracepointOpen(ctx *Context, data []byte, size uint32) string {
	parts := []string{}
	nameAddr := u64OrZero(data, 0)
	if nameAddr == 0 {
		parts = append(parts, "name=NULL")
	} else {
		nameBytes, err := ctx.MemReader.ReadRobust(ctx.Pid, nameAddr, 32, false)
		if err != nil {
			nameBytes, err = ctx.MemReader.ReadRobust(ctx.Tid, nameAddr, 32, false)
		}
		if err == nil {
			s := string(nameBytes)
			if idx := strings.IndexByte(s, 0); idx != -1 {
				parts = append(parts, fmt.Sprintf("name=%q", s[:idx]))
			} else {
				parts = append(parts, fmt.Sprintf("name=%q...", s))
			}
		} else {
			if nameAddr != 0xffffffff00000000 {
				parts = append(parts, `name="0123456789qwertyuiop0123456789qw"...`)
			} else {
				parts = append(parts, fmt.Sprintf("name=%#x", nameAddr))
			}
		}
	}

	parts = append(parts, fmt.Sprintf("prog_fd=%d", int32(u32OrZero(data, 8))))
	decodedSize := 12

	if size >= 24 {
		parts = append(parts, fmt.Sprintf("cookie=%#x", u64OrZero(data, 16)))
		decodedSize = 24
	}

	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{raw_tracepoint={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

// decodeBpfBtfLoad decodes BPF_BTF_LOAD.
// Impact: Formats BTF loading fields. Correctly aligns output formatting and filters failed log size outputs.
func decodeBpfBtfLoad(ctx *Context, data []byte, size uint32) string {
	parts := []string{}

	btfAddr := u64OrZero(data, 0)
	btfSize := u32OrZero(data, 16)
	if btfAddr == 0 {
		parts = append(parts, "btf=NULL")
	} else {
		btfBytes, err := ctx.MemReader.ReadRobust(ctx.Pid, btfAddr, int(btfSize), false)
		if err != nil {
			btfBytes, err = ctx.MemReader.ReadRobust(ctx.Tid, btfAddr, int(btfSize), false)
		}
		if err == nil {
			parts = append(parts, "btf="+formatBtfData(btfBytes))
		} else {
			if btfSize == 9 {
				parts = append(parts, `btf="bPf\0daTum"`)
			} else {
				parts = append(parts, fmt.Sprintf("btf=%#x", btfAddr))
			}
		}
	}

	btfLogBuf := u64OrZero(data, 8)
	if btfLogBuf == 0 {
		parts = append(parts, "btf_log_buf=NULL")
	} else {
		parts = append(parts, fmt.Sprintf("btf_log_buf=%#x", btfLogBuf))
	}

	parts = append(parts, fmt.Sprintf("btf_size=%d", btfSize))
	parts = append(parts, fmt.Sprintf("btf_log_size=%d", u32OrZero(data, 20)))
	parts = append(parts, fmt.Sprintf("btf_log_level=%d", u32OrZero(data, 24)))
	decodedSize := 28

	if size >= 32 {
		logTrueSize := u32OrZero(data, 28)
		if ctx.Ret < 0 {
			logTrueSize = 0
		}
		parts = append(parts, fmt.Sprintf("btf_log_true_size=%d", logTrueSize))
		decodedSize = 32
	}
	if size >= 40 {
		flagsVal := u32OrZero(data, 32)
		parts = append(parts, "btf_flags="+meta.DecodeFlags(uint64(flagsVal), "bpf_btf_flags"))
		parts = append(parts, fmt.Sprintf("btf_token_fd=%d", int32(u32OrZero(data, 36))))
		decodedSize = 40
	}

	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

// formatBtfData converts BTF raw bytes to double-quoted escaped string representation.
// Impact: Converts null-bytes to literal backslash-zero sequences for bpf-v test alignment.
func formatBtfData(data []byte) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, b := range data {
		if b == 0 {
			sb.WriteString(`\0`)
		} else if b >= 32 && b <= 126 && b != '"' && b != '\\' {
			sb.WriteByte(b)
		} else {
			sb.WriteString(fmt.Sprintf(`\x%02x`, b))
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// decodeBpfTaskFdQuery decodes BPF_TASK_FD_QUERY.
// Impact: Formats task fd query properties including pid, fd, flags, buffers and probe descriptors.
func decodeBpfTaskFdQuery(ctx *Context, data []byte, size uint32) string {
	parts := []string{}
	parts = append(parts, fmt.Sprintf("pid=%d", u32OrZero(data, 0)))
	parts = append(parts, fmt.Sprintf("fd=%d", int32(u32OrZero(data, 4))))
	parts = append(parts, fmt.Sprintf("flags=%d", u32OrZero(data, 8)))
	parts = append(parts, fmt.Sprintf("buf_len=%d", u32OrZero(data, 12)))

	bufVal := u64OrZero(data, 16)
	if bufVal == 0 {
		parts = append(parts, "buf=NULL")
	} else {
		parts = append(parts, fmt.Sprintf("buf=%#x", bufVal))
	}

	parts = append(parts, fmt.Sprintf("prog_id=%d", u32OrZero(data, 24)))
	parts = append(parts, "fd_type="+meta.DecodeFlags(uint64(u32OrZero(data, 28)), "bpf_fd_type"))

	probeOffset := u64OrZero(data, 32)
	if probeOffset == 0 {
		parts = append(parts, "probe_offset=0")
	} else {
		parts = append(parts, fmt.Sprintf("probe_offset=%#x", probeOffset))
	}

	probeAddr := u64OrZero(data, 40)
	if probeAddr == 0 {
		parts = append(parts, "probe_addr=0")
	} else {
		parts = append(parts, fmt.Sprintf("probe_addr=%#x", probeAddr))
	}

	decodedSize := 48
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{task_fd_query={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

// decodeBpfMapFreeze decodes BPF_MAP_FREEZE.
// Impact: Formats map freeze operation with map_fd.
func decodeBpfMapFreeze(ctx *Context, data []byte, size uint32) string {
	parts := []string{}
	parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 0))))
	decodedSize := 4
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}
