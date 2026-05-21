package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

func init() {
	Register("clone3", &ProcessHandler{})
}

type ProcessHandler struct{}

func (h *ProcessHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "clone3":
		uargs := ctx.Args[0]
		size := uint64(ctx.Args[1])

		if uargs == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else if size < 64 {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", uargs))
		} else {
			capLen := int(size)
			if capLen > 256 { capLen = 256 }
			data := ctx.StrArgBuf[0:capLen]
			readSuccess := ctx.ProbeRetEnter >= 0
			if !readSuccess {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, uargs, capLen, false); err == nil && len(d) == capLen {
					data = d
					readSuccess = true
				}
			}

			if !readSuccess {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", uargs))
			} else {
				parts := []string{}
				u64OrZero := func(off int) uint64 {
					if len(data) >= off+8 { return binary.LittleEndian.Uint64(data[off : off+8]) }
					return 0
				}
				
				flags := u64OrZero(0)
				if size >= 8 {
					parts = append(parts, "flags="+meta.DecodeFlags(flags, "clone3_flags"))
				}
				if size >= 16 && (flags&0x00001000 != 0) { // CLONE_PIDFD
					pfd := u64OrZero(8)
					if pfd == 0 { parts = append(parts, "pidfd=NULL") } else { parts = append(parts, fmt.Sprintf("pidfd=%#x", pfd)) }
				}
				if size >= 24 && (flags&0x01000000 != 0) { // CLONE_CHILD_SETTID
					ctid := u64OrZero(16)
					if ctid == 0 { parts = append(parts, "child_tid=NULL") } else { parts = append(parts, fmt.Sprintf("child_tid=%#x", ctid)) }
				}
				if size >= 32 && (flags&0x00100000 != 0) { // CLONE_PARENT_SETTID
					ptid := u64OrZero(24)
					if ptid == 0 { parts = append(parts, "parent_tid=NULL") } else { parts = append(parts, fmt.Sprintf("parent_tid=%#x", ptid)) }
				}
				if size >= 40 {
					sig := u64OrZero(32)
					if sig == 0 {
						parts = append(parts, "exit_signal=0")
					} else {
						parts = append(parts, fmt.Sprintf("exit_signal=%s", meta.DecodeFlags(sig, "signalnames")))
					}
				}
				if size >= 48 {
					stack := u64OrZero(40)
					if stack == 0 { parts = append(parts, "stack=NULL") } else { parts = append(parts, fmt.Sprintf("stack=%#x", stack)) }
				}
				if size >= 56 {
					ssz := u64OrZero(48)
					if ssz == 0 {
						parts = append(parts, "stack_size=0")
					} else {
						parts = append(parts, fmt.Sprintf("stack_size=%#x", ssz))
					}
				}
				if size >= 64 && (flags&0x00080000 != 0) { // CLONE_SETTLS
					tls := u64OrZero(56)
					if tls == 0 { parts = append(parts, "tls=NULL") } else { parts = append(parts, fmt.Sprintf("tls=%#x", tls)) }
				}
				
				if size >= 80 {
					set_tid_ptr := u64OrZero(64)
					set_tid_size := u64OrZero(72)
					if set_tid_ptr != 0 && set_tid_size > 0 {
						count := int(set_tid_size)
						if count > 32 { count = 32 }
						d, _ := ctx.MemReader.ReadRobust(ctx.Pid, set_tid_ptr, count*4, false)
						if len(d) > 0 {
							var tids []string
							for i := 0; i < len(d)/4; i++ {
								tids = append(tids, fmt.Sprintf("%d", int32(binary.LittleEndian.Uint32(d[i*4:i*4+4]))))
							}
							parts = append(parts, fmt.Sprintf("set_tid=[%s], set_tid_size=%d", strings.Join(tids, ", "), set_tid_size))
						} else {
							parts = append(parts, fmt.Sprintf("set_tid=%#x, set_tid_size=%d", set_tid_ptr, set_tid_size))
						}
					} else if set_tid_ptr != 0 || set_tid_size != 0 {
						if set_tid_ptr == 0 { parts = append(parts, "set_tid=NULL") } else { parts = append(parts, fmt.Sprintf("set_tid=%#x", set_tid_ptr)) }
						parts = append(parts, fmt.Sprintf("set_tid_size=%d", set_tid_size))
					}
				}
				if size >= 88 && (flags&0x000000000200000000 != 0 || flags&0x200000000 != 0) { // CLONE_INTO_CGROUP
					cg := u64OrZero(80)
					parts = append(parts, fmt.Sprintf("cgroup=%d", cg))
				}
				
				structStr := "{"+strings.Join(parts, ", ")+"}"
				
				// Post-syscall decoding
				if ctx.Ret > 0 {
					postParts := []string{}
					if size >= 32 && (flags&0x00100000 != 0) { // CLONE_PARENT_SETTID
						ptidPtr := u64OrZero(24)
						if ptidPtr != 0 {
							if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ptidPtr, 4, true); err == nil {
								tid := binary.LittleEndian.Uint32(d)
								postParts = append(postParts, fmt.Sprintf("parent_tid=[%d]", tid))
							}
						} else {
							postParts = append(postParts, "parent_tid=NULL")
						}
					}
					if len(postParts) > 0 {
						structStr += " => {" + strings.Join(postParts, ", ") + "}"
					}
				}
				res.ArgParts = append(res.ArgParts, structStr)
			}
		}
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", size))
	}
	return res
}
