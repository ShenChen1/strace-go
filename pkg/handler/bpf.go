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

	if attr == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		data, err := ctx.MemReader.Read(ctx.Tid, attr, int(size))
		
		if err != nil || len(data) == 0 {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", attr))
		} else {
			switch cmd {
			case 0: // BPF_MAP_CREATE
				parts := []string{}
				if len(data) >= 4 {
					t := binary.LittleEndian.Uint32(data[0:4])
					parts = append(parts, "map_type="+meta.DecodeFlags(uint64(t), "bpf_map_types"))
				}
				if len(data) >= 8 { parts = append(parts, fmt.Sprintf("key_size=%d", binary.LittleEndian.Uint32(data[4:8]))) }
				if len(data) >= 12 { parts = append(parts, fmt.Sprintf("value_size=%d", binary.LittleEndian.Uint32(data[8:12]))) }
				if len(data) >= 16 { parts = append(parts, fmt.Sprintf("max_entries=%d", binary.LittleEndian.Uint32(data[12:16]))) }
				if len(data) >= 20 { parts = append(parts, "map_flags="+meta.DecodeFlags(uint64(binary.LittleEndian.Uint32(data[16:20])), "bpf_map_flags")) }
				if len(data) >= 24 { parts = append(parts, fmt.Sprintf("inner_map_fd=%d", int32(binary.LittleEndian.Uint32(data[20:24])))) }
				if len(data) >= 28 { parts = append(parts, fmt.Sprintf("numa_node=%d", int32(binary.LittleEndian.Uint32(data[24:28])))) }
				if len(data) >= 44 {
					name := string(data[28:44])
					if idx := strings.IndexByte(name, 0); idx != -1 { name = name[:idx] }
					parts = append(parts, fmt.Sprintf("map_name=%q", name))
				}
				if len(parts) > 0 {
					res.ArgParts = append(res.ArgParts, "{"+strings.Join(parts, ", ")+"}")
				} else {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", attr))
				}
			case 23, 24, 25, 26, 27, 31: // *_GET_NEXT_ID
				id := binary.LittleEndian.Uint32(data[0:4])
				if len(data) >= 8 {
					next := binary.LittleEndian.Uint32(data[4:8])
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("{start_id=%d, next_id=%d}", id, next))
				} else {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("{start_id=%d}", id))
				}
			default:
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", attr))
			}
		}
	}

	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", size))
	return res
}
