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
		} else {
			capLen := int(size)
			if capLen > 256 { capLen = 256 }
			data := ctx.StrArgBuf[0:capLen]
			readSuccess := ctx.ProbeRetEnter >= 0
			if !readSuccess {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, uargs, capLen, false); err == nil {
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
				
				if size >= 8 {
					parts = append(parts, "flags="+meta.DecodeFlags(u64OrZero(0), "clone3_flags"))
				}
				if size >= 16 {
					pfd := u64OrZero(8)
					if pfd != 0 || (u64OrZero(0)&0x00001000 != 0) { // CLONE_PIDFD
						if pfd == 0 { parts = append(parts, "pidfd=NULL") } else { parts = append(parts, fmt.Sprintf("pidfd=%#x", pfd)) }
					}
				}
				if size >= 24 {
					ctid := u64OrZero(16)
					if ctid != 0 || (u64OrZero(0)&0x01000000 != 0) { // CLONE_CHILD_SETTID
						if ctid == 0 { parts = append(parts, "child_tid=NULL") } else { parts = append(parts, fmt.Sprintf("child_tid=%#x", ctid)) }
					}
				}
				if size >= 32 {
					ptid := u64OrZero(24)
					if ptid != 0 || (u64OrZero(0)&0x00100000 != 0) { // CLONE_PARENT_SETTID
						if ptid == 0 { parts = append(parts, "parent_tid=NULL") } else { parts = append(parts, fmt.Sprintf("parent_tid=%#x", ptid)) }
					}
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
				if size >= 64 {
					tls := u64OrZero(56)
					if tls != 0 || (u64OrZero(0)&0x00080000 != 0) { // CLONE_SETTLS
						if tls == 0 { parts = append(parts, "tls=NULL") } else { parts = append(parts, fmt.Sprintf("tls=%#x", tls)) }
					}
				}
				
				if size >= 80 {
					set_tid_ptr := u64OrZero(64)
					set_tid_size := u64OrZero(72)
					if set_tid_ptr != 0 && set_tid_size > 0 {
						// Read pid_t array
						count := int(set_tid_size)
						if count > 32 { count = 32 }
						d, err := ctx.MemReader.ReadRobust(ctx.Pid, set_tid_ptr, count*4, false)
						if err == nil {
							var tids []string
							for i := 0; i < len(d)/4; i++ {
								tids = append(tids, fmt.Sprintf("%d", int32(binary.LittleEndian.Uint32(d[i*4:i*4+4]))))
							}
							parts = append(parts, fmt.Sprintf("set_tid=[%s], set_tid_size=%d", strings.Join(tids, ", "), set_tid_size))
						} else {
							parts = append(parts, fmt.Sprintf("set_tid=%#x, set_tid_size=%d", set_tid_ptr, set_tid_size))
						}
					} else if set_tid_ptr != 0 || set_tid_size != 0 {
						parts = append(parts, fmt.Sprintf("set_tid=%#x, set_tid_size=%d", set_tid_ptr, set_tid_size))
					}
				}
				if size >= 88 {
					cg := u64OrZero(80)
					if cg != 0 || (u64OrZero(0)&0x4000000000 != 0) { // CLONE_INTO_CGROUP
						parts = append(parts, fmt.Sprintf("cgroup=%d", cg))
					}
				}
				
				res.ArgParts = append(res.ArgParts, "{"+strings.Join(parts, ", ")+"}")
				
				// Post-syscall decoding for pointers
				if ctx.Ret >= 0 {
					postParts := []string{}
					if size >= 32 && (u64OrZero(0)&0x00100000 != 0) { // CLONE_PARENT_SETTID
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
						res.ArgParts[len(res.ArgParts)-1] += " => {" + strings.Join(postParts, ", ") + "}"
					}
				}
			}
		}
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", size))
	}
	return res
}
