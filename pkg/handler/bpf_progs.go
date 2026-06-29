package handler

import (
	"encoding/binary"
	"fmt"
	"strace-go/pkg/meta"
	"strings"
)

// decodeBpfProgLoad decodes BPF_PROG_LOAD arguments.
// Impact: Core prog load attribute formatter supporting multiple API versions and extensions.
func decodeBpfProgLoad(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		t := binary.LittleEndian.Uint32(data[0:4])
		parts = append(parts, "prog_type="+meta.DecodeFlags(uint64(t), "bpf_prog_types"))
		decodedSize = 4
	}
	insnCnt := u32OrZero(data, 4)
	parts = append(parts, fmt.Sprintf("insn_cnt=%d", insnCnt))
	insns := u64OrZero(data, 8)
	parts = append(parts, decodeBpfInsns(ctx, insns, insnCnt))

	decodedSize, parts = decodeBpfProgLoadParts1(ctx, parts, data, size, decodedSize)
	decodedSize, parts = decodeBpfProgLoadParts2(parts, data, size, decodedSize)
	decodedSize, parts = decodeBpfProgLoadParts3(ctx, parts, data, size, decodedSize)

	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

// decodeBpfProgLoadParts1 decodes license and log fields up to 72 bytes.
// Impact: Appends license and log options.
func decodeBpfProgLoadParts1(ctx *Context, parts []string, data []byte, size uint32, decodedSize int) (int, []string) {
	licAddr := u64OrZero(data, 16)
	if licAddr == 0 {
		parts = append(parts, "license=NULL")
	} else {
		parts = append(parts, fmt.Sprintf("license=%#x", licAddr))
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
		parts = append(parts, formatBpfProgLoadLogBuf(ctx, data, size))
		decodedSize = 40
	}
	if size >= 44 {
		kv := u32OrZero(data, 40)
		parts = append(parts, "kern_version="+formatBpfKernelVersion(ctx, kv))
		decodedSize = 44
	}
	if size >= 48 {
		parts = append(parts, "prog_flags="+meta.DecodeFlags(uint64(u32OrZero(data, 44)), "bpf_prog_flags"))
		decodedSize = 48
	}
	if size >= 64 {
		parts = append(parts, formatBpfProgLoadName(data))
		decodedSize = 64
	}
	if size >= 68 {
		parts = append(parts, "prog_ifindex="+translateIfindex(u32OrZero(data, 64)))
		decodedSize = 68
	}
	if size >= 72 {
		parts = append(parts, "expected_attach_type="+meta.DecodeFlags(uint64(u32OrZero(data, 68)), "bpf_attach_type"))
		decodedSize = 72
	}
	return decodedSize, parts
}

func formatBpfKernelVersion(ctx *Context, kv uint32) string {
	decoded := fmt.Sprintf("KERNEL_VERSION(%d, %d, %d)", kv>>16, (kv>>8)&0xff, kv&0xff)
	if ctx == nil || ctx.Opts == nil {
		return decoded
	}
	raw := fmt.Sprintf("%#x", kv)
	switch ctx.Opts.XlatFormat {
	case "raw":
		return raw
	case "verbose":
		return fmt.Sprintf("%s /* %s */", raw, decoded)
	default:
		return decoded
	}
}

func formatBpfProgLoadLogBuf(_ *Context, data []byte, _ uint32) string {
	logBuf := u64OrZero(data, 32)
	if logBuf == 0 {
		return "log_buf=NULL"
	}
	return fmt.Sprintf("log_buf=%#x", logBuf)
}

func formatBpfProgLoadName(data []byte) string {
	name := ""
	hasNull := false
	nameLen := 16
	if len(data) < 64 {
		if len(data) > 48 {
			nameLen = len(data) - 48
		} else {
			nameLen = 0
		}
	}
	if nameLen > 0 {
		nameBytes := data[48 : 48+nameLen]
		if idx := strings.IndexByte(string(nameBytes), 0); idx != -1 {
			name = string(nameBytes[:idx])
			hasNull = true
		} else {
			limit := nameLen
			if limit == 16 {
				limit = 15
			}
			name = string(nameBytes[:limit])
		}
	}
	if hasNull || nameLen < 16 {
		return fmt.Sprintf("prog_name=%q", name)
	}
	return fmt.Sprintf("prog_name=%q...", name)
}

// decodeBpfProgLoadParts2 decodes BTF and line info up to 128 bytes.
// Impact: Appends debug types and lineage descriptors.
func decodeBpfProgLoadParts2(parts []string, data []byte, size uint32, decodedSize int) (int, []string) {
	if size >= 76 {
		parts = append(parts, fmt.Sprintf("prog_btf_fd=%d", int32(u32OrZero(data, 72))))
		decodedSize = 76
	}
	if size >= 80 {
		parts = append(parts, fmt.Sprintf("func_info_rec_size=%d", u32OrZero(data, 76)))
		decodedSize = 80
	}
	if size >= 88 {
		funcInfo := u64OrZero(data, 80)
		parts = append(parts, formatPtr("func_info", funcInfo))
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
		lineInfo := u64OrZero(data, 96)
		parts = append(parts, formatPtr("line_info", lineInfo))
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
	if size >= 132 {
		parts = append(parts, fmt.Sprintf("core_relo_cnt=%d", u32OrZero(data, 116)))
		decodedSize = 132
	}
	if size >= 128 {
		fdArr := u64OrZero(data, 120)
		parts = append(parts, formatPtr("fd_array", fdArr))
		if decodedSize < 128 {
			decodedSize = 128
		}
	}
	return decodedSize, parts
}

// decodeBpfProgLoadParts3 decodes modern elements, relocation tables and signature blocks up to 168 bytes.
// Impact: Appends core_relos, signature pointers, and security keys.
func decodeBpfProgLoadParts3(_ *Context, parts []string, data []byte, size uint32, decodedSize int) (int, []string) {
	if size >= 136 {
		coreRelos := u64OrZero(data, 128)
		parts = append(parts, formatPtr("core_relos", coreRelos))
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
	if size >= 148 {
		parts = append(parts, fmt.Sprintf("prog_token_fd=%d", int32(u32OrZero(data, 144))))
		decodedSize = 148
	}
	if size >= 152 {
		parts = append(parts, fmt.Sprintf("fd_array_cnt=%d", u32OrZero(data, 148)))
		decodedSize = 152
	}
	if size >= 160 {
		sigAddr := u64OrZero(data, 152)
		if sigAddr == 0 {
			parts = append(parts, "signature=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("signature=%#x", sigAddr))
		}
		decodedSize = 160
	}
	if size >= 164 {
		parts = append(parts, fmt.Sprintf("signature_size=%d", u32OrZero(data, 160)))
		decodedSize = 164
	}
	if size >= 168 {
		parts = append(parts, fmt.Sprintf("keyring_id=%d", int32(u32OrZero(data, 164))))
		decodedSize = 168
	}
	return decodedSize, parts
}

// formatBpfSignature converts raw signature byte slice into double-quoted hex representation.
// Impact: Custom hex buffer encoder to align signature output with strace test cases.
func formatBpfSignature(sig []byte) string {
	var sb strings.Builder
	sb.WriteString("\"")
	for _, b := range sig {
		sb.WriteString(fmt.Sprintf("\\x%02x", b))
	}
	sb.WriteString("\"")
	return sb.String()
}
