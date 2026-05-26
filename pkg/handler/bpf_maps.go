package handler

import (
	"encoding/binary"
	"fmt"
	"strings"
	"strace-go/pkg/meta"
)

// decodeBpfMapCreate decodes BPF_MAP_CREATE command arguments.
// Impact: Formats map creation attributes like keys, values, and flags.
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
		parts = decodeBpfMapCreateNode(parts, data)
		decodedSize = 28
	}
	
	decodedSize, parts = decodeBpfMapCreateName(parts, data, size, decodedSize)
	decodedSize, parts = decodeBpfMapCreateBtf(parts, data, size, decodedSize)

	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

// decodeBpfMapCreateNode helper to format NUMA node config.
// Impact: Formats numa_node attribute.
func decodeBpfMapCreateNode(parts []string, data []byte) []string {
	if (u32OrZero(data, 16) & 4) != 0 {
		node := int32(u32OrZero(data, 24))
		if node == -1 {
			parts = append(parts, "numa_node=4294967295 /* NUMA_NO_NODE */")
		} else {
			parts = append(parts, fmt.Sprintf("numa_node=%d", uint32(node)))
		}
	}
	return parts
}

// decodeBpfMapCreateName helper to format map name.
// Impact: Truncates and quotes map name attribute.
func decodeBpfMapCreateName(parts []string, data []byte, size uint32, decodedSize int) (int, []string) {
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
				limit := nameLen - 1
				if limit > 15 { limit = 15 }
				if limit < 0 { limit = 0 }
				parts = append(parts, fmt.Sprintf("map_name=%q...", name[:limit]))
			}
		}
		if decodedSize < 28+nameLen {
			decodedSize = 28 + nameLen
		}
	}
	return decodedSize, parts
}

// decodeBpfMapCreateBtf helper to decode BTF and modern map attributes.
// Impact: Appends btf and map_extra info to mapped parts.
func decodeBpfMapCreateBtf(parts []string, data []byte, size uint32, decodedSize int) (int, []string) {
	if size >= 48 {
		parts = append(parts, "map_ifindex="+translateIfindex(u32OrZero(data, 44)))
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
	return decodedSize, parts
}

// decodeBpfMapLookup decodes BPF_MAP_LOOKUP_ELEM.
// Impact: Decodes map lookup key and value ptr.
func decodeBpfMapLookup(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
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

	if size >= 32 {
		parts = append(parts, "flags="+meta.DecodeFlags(u64OrZero(data, 24), "bpf_map_lookup_flags"))
		decodedSize = 32
	}
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

// decodeBpfMapUpdate decodes BPF_MAP_UPDATE_ELEM.
// Impact: Decodes map update key, value ptr and flags.
func decodeBpfMapUpdate(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
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

	flagsVal := u64OrZero(data, 24)
	parts = append(parts, "flags="+meta.DecodeFlags(flagsVal, "bpf_map_update_flags"))
	decodedSize = 32

	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

// decodeBpfMapDeleteElem decodes BPF_MAP_DELETE_ELEM.
// Impact: Decodes map delete fd and key.
func decodeBpfMapDeleteElem(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
	k := u64OrZero(data, 8)
	if k == 0 {
		parts = append(parts, "key=NULL")
	} else {
		parts = append(parts, fmt.Sprintf("key=%#x", k))
	}
	decodedSize = 16
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

// decodeBpfMapGetNextKey decodes BPF_MAP_GET_NEXT_KEY.
// Impact: Decodes map get next key pointers.
func decodeBpfMapGetNextKey(ctx *Context, data []byte, size uint32) string {
	decodedSize := 0
	parts := []string{}
	if len(data) >= 4 {
		parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 0))))
		decodedSize = 4
	}
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
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{" + strings.Join(parts, ", ") + extra + "}"
}

// decodeBpfMapBatch decodes BPF batch commands including lookup, update, and delete.
// Impact: Formats batch attributes for in_batch, out_batch, keys, values, count, map_fd, elem_flags, and flags.
func decodeBpfMapBatch(ctx *Context, data []byte, size uint32) string {
	parts := []string{}
	cmd := ctx.Args[0]

	// 1. in_batch & out_batch (only for Lookup / Lookup & Delete)
	if cmd == 24 || cmd == 25 {
		inBatch := u64OrZero(data, 0)
		if inBatch == 0 {
			parts = append(parts, "in_batch=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("in_batch=%#x", inBatch))
		}
		outBatch := u64OrZero(data, 8)
		if outBatch == 0 {
			parts = append(parts, "out_batch=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("out_batch=%#x", outBatch))
		}
	}

	// 2. keys (all batch commands)
	keys := u64OrZero(data, 16)
	if keys == 0 {
		parts = append(parts, "keys=NULL")
	} else {
		parts = append(parts, fmt.Sprintf("keys=%#x", keys))
	}

	// 3. values (Lookup, Lookup & Delete, Update; not for Delete)
	if cmd != 27 {
		values := u64OrZero(data, 24)
		if values == 0 {
			parts = append(parts, "values=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("values=%#x", values))
		}
	}

	// 4. Common fields: count, map_fd, elem_flags, flags
	parts = append(parts, fmt.Sprintf("count=%d", u32OrZero(data, 32)))
	parts = append(parts, fmt.Sprintf("map_fd=%d", int32(u32OrZero(data, 36))))

	elemFlags := u64OrZero(data, 40)
	xlatName := "bpf_map_lookup_flags"
	if cmd == 26 {
		xlatName = "bpf_map_update_flags"
	}
	parts = append(parts, "elem_flags="+meta.DecodeFlags(elemFlags, xlatName))

	flagsVal := u64OrZero(data, 48)
	if flagsVal == 0 {
		parts = append(parts, "flags=0")
	} else {
		parts = append(parts, fmt.Sprintf("flags=%#x", flagsVal))
	}

	decodedSize := 56
	extra := checkAndFormatExtraData(ctx, decodedSize, size)
	return "{batch={" + strings.Join(parts, ", ") + "}" + extra + "}"
}

