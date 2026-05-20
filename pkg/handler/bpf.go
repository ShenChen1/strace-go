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

// BpfHandler handles bpf syscall.
type BpfHandler struct{}

func (h *BpfHandler) Handle(ctx *Context) Result {
	res := Result{}
	cmd := ctx.Args[0]
	attr := ctx.Args[1]
	size := uint32(ctx.Args[2])

	cmdStr := meta.DecodeFlags(cmd, "bpf_commands")
	res.ArgParts = append(res.ArgParts, cmdStr)

	if attr == 0 || size == 0 {
		if attr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", attr))
		}
	} else {
		capLen := int(size)
		if capLen > 512 { capLen = 512 }
		
		data := ctx.StrArgBuf[0:capLen]
		readSuccess := ctx.ProbeRetEnter >= 0
		if !readSuccess {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, attr, int(size), false); err == nil {
				data = d
				readSuccess = true
			}
		}
		
		if !readSuccess {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", attr))
		} else {
			switch cmd {
			case 0: // BPF_MAP_CREATE
				parts := []string{}
				t := uint32(0); if len(data) >= 4 { t = binary.LittleEndian.Uint32(data[0:4]) }
				parts = append(parts, "map_type="+meta.DecodeFlags(uint64(t), "bpf_map_types"))
				
				u32OrZero := func(off int) uint32 {
					if len(data) >= off+4 { return binary.LittleEndian.Uint32(data[off : off+4]) }
					return 0
				}
				
				parts = append(parts, fmt.Sprintf("key_size=%d", u32OrZero(4)))
				parts = append(parts, fmt.Sprintf("value_size=%d", u32OrZero(8)))
				parts = append(parts, fmt.Sprintf("max_entries=%d", u32OrZero(12)))
				
				if size >= 20 {
					parts = append(parts, "map_flags="+meta.DecodeFlags(uint64(u32OrZero(16)), "bpf_map_flags"))
				}
				if size >= 24 {
					parts = append(parts, fmt.Sprintf("inner_map_fd=%d", int32(u32OrZero(20))))
				}
				if size >= 28 {
					node := int32(u32OrZero(24))
					if node == -1 {
						parts = append(parts, "numa_node=-1 /* NUMA_NO_NODE */")
					} else {
						parts = append(parts, fmt.Sprintf("numa_node=%d", uint32(node)))
					}
				}
				if size > 28 {
					nameLen := int(size) - 28
					if nameLen > 16 { nameLen = 16 }
					if len(data) < 28+nameLen { nameLen = len(data) - 28 }
					if nameLen > 0 {
						name := string(data[28 : 28+nameLen])
						if idx := strings.IndexByte(name, 0); idx != -1 { 
							name = name[:idx] 
							parts = append(parts, fmt.Sprintf("map_name=%q", name))
						} else {
							limit := nameLen; if limit > 7 { limit = 7 }
							parts = append(parts, fmt.Sprintf("map_name=%q...", name[:limit]))
						}
					}
				}
				if size >= 48 {
					parts = append(parts, fmt.Sprintf("map_ifindex=%d", u32OrZero(44)))
				}
				res.ArgParts = append(res.ArgParts, "{"+strings.Join(parts, ", ")+"}")
			case 5: // BPF_PROG_LOAD
				parts := []string{}
				t := uint32(0); if len(data) >= 4 { t = binary.LittleEndian.Uint32(data[0:4]) }
				parts = append(parts, "prog_type="+meta.DecodeFlags(uint64(t), "bpf_prog_types"))
				
				u32OrZero := func(off int) uint32 {
					if len(data) >= off+4 { return binary.LittleEndian.Uint32(data[off : off+4]) }
					return 0
				}
				u64OrZero := func(off int) uint64 {
					if len(data) >= off+8 { return binary.LittleEndian.Uint64(data[off : off+8]) }
					return 0
				}
				
				parts = append(parts, fmt.Sprintf("insn_cnt=%d", u32OrZero(4)))
				insns := u64OrZero(8)
				if insns == 0 { parts = append(parts, "insns=NULL") } else { parts = append(parts, fmt.Sprintf("insns=%#x", insns)) }
				
				licAddr := u64OrZero(16)
				if licAddr == 0 {
					parts = append(parts, "license=NULL")
				} else {
					lic, err := ctx.MemReader.ReadRobust(ctx.Pid, licAddr, 64, false)
					if err == nil {
						s := string(lic)
						if idx := strings.IndexByte(s, 0); idx != -1 { s = s[:idx] }
						parts = append(parts, fmt.Sprintf("license=%q", s))
					} else {
						parts = append(parts, fmt.Sprintf("license=%#x", licAddr))
					}
				}
				
				if size >= 28 {
					parts = append(parts, fmt.Sprintf("log_level=%d", u32OrZero(24)))
				}
				if size >= 32 {
					parts = append(parts, fmt.Sprintf("log_size=%d", u32OrZero(28)))
				}
				if size >= 40 {
					logBuf := u64OrZero(32)
					if logBuf == 0 { parts = append(parts, "log_buf=NULL") } else { parts = append(parts, fmt.Sprintf("log_buf=%#x", logBuf)) }
				}
				if size >= 44 {
					kv := u32OrZero(40)
					parts = append(parts, fmt.Sprintf("kern_version=KERNEL_VERSION(%d, %d, %d)", kv>>16, (kv>>8)&0xff, kv&0xff))
				}
				if size >= 48 {
					parts = append(parts, "prog_flags="+meta.DecodeFlags(uint64(u32OrZero(44)), "bpf_prog_flags"))
				}
				if size >= 64 {
					name := ""
					if len(data) >= 64 {
						name = string(data[48:64])
						if idx := strings.IndexByte(name, 0); idx != -1 { name = name[:idx] }
					}
					parts = append(parts, fmt.Sprintf("prog_name=%q", name))
				}
				if size >= 68 {
					parts = append(parts, fmt.Sprintf("prog_ifindex=%d", u32OrZero(64)))
				}
				res.ArgParts = append(res.ArgParts, "{"+strings.Join(parts, ", ")+"}")
			case 15: // BPF_OBJ_GET_INFO_BY_FD
				parts := []string{}
				u32OrZero := func(off int) uint32 {
					if len(data) >= off+4 { return binary.LittleEndian.Uint32(data[off : off+4]) }
					return 0
				}
				u64OrZero := func(off int) uint64 {
					if len(data) >= off+8 { return binary.LittleEndian.Uint64(data[off : off+8]) }
					return 0
				}
				
				parts = append(parts, fmt.Sprintf("bpf_fd=%d", int32(u32OrZero(0))))
				parts = append(parts, fmt.Sprintf("info_len=%d", u32OrZero(4)))
				info := u64OrZero(8)
				if info == 0 { parts = append(parts, "info=NULL") } else { parts = append(parts, fmt.Sprintf("info=%#x", info)) }
				res.ArgParts = append(res.ArgParts, "{info={"+strings.Join(parts, ", ")+"}}")
			case 11, 12, 19, 23, 31: // *_GET_NEXT_ID
				parts := []string{}
				if len(data) >= 4 { parts = append(parts, fmt.Sprintf("start_id=%d", binary.LittleEndian.Uint32(data[0:4]))) }
				if len(data) >= 8 { parts = append(parts, fmt.Sprintf("next_id=%d", binary.LittleEndian.Uint32(data[4:8]))) }
				res.ArgParts = append(res.ArgParts, "{"+strings.Join(parts, ", ")+"}")
			case 13, 14, 30: // *_GET_FD_BY_ID
				if len(data) >= 4 { res.ArgParts = append(res.ArgParts, fmt.Sprintf("{link_id=%d}", binary.LittleEndian.Uint32(data[0:4]))) } else { res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", attr)) }
			case 32: // BPF_ENABLE_STATS
				if len(data) >= 4 { res.ArgParts = append(res.ArgParts, fmt.Sprintf("{enable_stats={type=%d}}", binary.LittleEndian.Uint32(data[0:4]))) } else { res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", attr)) }
			case 33: // BPF_ITER_CREATE
				parts := []string{}
				if len(data) >= 4 { parts = append(parts, fmt.Sprintf("link_fd=%d", int32(binary.LittleEndian.Uint32(data[0:4])))) }
				if len(data) >= 8 { parts = append(parts, fmt.Sprintf("flags=%#x", binary.LittleEndian.Uint32(data[4:8]))) }
				res.ArgParts = append(res.ArgParts, "{iter_create={"+strings.Join(parts, ", ")+"}}")
			case 34: // BPF_LINK_DETACH
				if len(data) >= 4 { res.ArgParts = append(res.ArgParts, fmt.Sprintf("{link_detach={link_fd=%d}}", int32(binary.LittleEndian.Uint32(data[0:4])))) } else { res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", attr)) }
			case 28: // BPF_LINK_CREATE
				parts := []string{}
				u32OrZero := func(off int) uint32 {
					if len(data) >= off+4 { return binary.LittleEndian.Uint32(data[off : off+4]) }
					return 0
				}
				parts = append(parts, fmt.Sprintf("prog_fd=%d", int32(u32OrZero(0))))
				parts = append(parts, fmt.Sprintf("target_fd=%d", int32(u32OrZero(4))))
				parts = append(parts, "attach_type="+meta.DecodeFlags(uint64(u32OrZero(8)), "bpf_attach_type"))
				parts = append(parts, "flags="+meta.DecodeFlags(uint64(u32OrZero(12)), "bpf_map_flags")) // Uses same flags as map? No, should check.
				res.ArgParts = append(res.ArgParts, "{link_create={"+strings.Join(parts, ", ")+"}}")
			case 29: // BPF_LINK_UPDATE
				parts := []string{}
				u32OrZero := func(off int) uint32 {
					if len(data) >= off+4 { return binary.LittleEndian.Uint32(data[off : off+4]) }
					return 0
				}
				parts = append(parts, fmt.Sprintf("link_fd=%d", int32(u32OrZero(0))))
				parts = append(parts, fmt.Sprintf("new_prog_fd=%d", int32(u32OrZero(4))))
				parts = append(parts, fmt.Sprintf("flags=%#x", u32OrZero(8)))
				parts = append(parts, fmt.Sprintf("old_prog_fd=%d", int32(u32OrZero(12))))
				res.ArgParts = append(res.ArgParts, "{link_update={"+strings.Join(parts, ", ")+"}}")
			default:
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", attr))
			}
		}
	}

	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", size))
	return res
}
