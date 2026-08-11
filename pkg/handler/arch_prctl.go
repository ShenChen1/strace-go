package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

func registerBuiltinArchPrctl(r *Registry) {
	r.Register("arch_prctl", &ArchPrctlHandler{})
}

// ArchPrctlHandler handles x86_64 specific arch_prctl.
type ArchPrctlHandler struct {
	DefaultHandler
}

const archPrctlOutSize = 8

func (h *ArchPrctlHandler) Handle(ctx *Context) Result {
	var res Result

	for i := 0; i < len(ctx.ScMeta.Args); i++ {
		val := ctx.Args[i]

		if i == 0 {
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(val, "archvals"))
			continue
		}

		if i == 1 {
			opt := ctx.Args[0]
			if opt == 0x1011 {
				continue
			} // ARCH_GET_CPUID ignored here

			isGET := (opt == 0x1003 || opt == 0x1004 || opt == 0x1011 || opt == 0x1021 || opt == 0x1022 || opt == 0x1024)

			if val == 0 {
				if opt == 0x1023 || opt == 0x1025 {
					if ctx.Opts != nil && ctx.Opts.XlatFormat == "raw" {
						res.ArgParts = append(res.ArgParts, "0")
					} else {
						res.ArgParts = append(res.ArgParts, "0 /* XFEATURE_FP */")
					}
				} else if isGET {
					res.ArgParts = append(res.ArgParts, "NULL")
				} else {
					res.ArgParts = append(res.ArgParts, "0")
				}
			} else {
				if isGET {
					if ctx.Ret >= 0 {
						outV := uint64(0)
						if data, ok := archPrctlOutData(ctx); ok {
							outV = binary.LittleEndian.Uint64(data)
						}
						if outV == 0 {
							res.ArgParts = append(res.ArgParts, "[NULL]")
						} else {
							if opt >= 0x1021 && opt <= 0x1024 {
								decoded := meta.DecodeFlags(outV, "x86_xfeatures")
								if ctx.Opts != nil && ctx.Opts.XlatFormat == "raw" {
									res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%s]", decoded))
								} else if strings.HasPrefix(decoded, "0x") && strings.Contains(decoded, "/*") {
									res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%s]", decoded))
								} else {
									res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%#x /* %s */]", outV, decoded))
								}
							} else {
								res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%#x]", outV))
							}
						}
					} else {
						res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
					}
				} else if opt == 0x1023 || opt == 0x1025 {
					res.ArgParts = append(res.ArgParts, meta.DecodeFlags(val, "x86_xfeature_bits"))
				} else {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				}
			}
			continue
		}
	}
	return res
}

func archPrctlOutData(ctx *Context) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(1, PayloadDirectionOut); ok && len(data) >= archPrctlOutSize {
		return data[:archPrctlOutSize], true
	}
	return nil, false
}
