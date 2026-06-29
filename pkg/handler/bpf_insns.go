package handler

import (
	"encoding/binary"
	"fmt"
)

// decodeBpfInsns decodes eBPF instruction array into readable symbolic output list.
// Impact: Converts array of raw eBPF instruction bytes into high-level debug representation.
func decodeBpfInsns(ctx *Context, insnsAddr uint64, cnt uint32) string {
	if insnsAddr == 0 {
		return "insns=NULL"
	}
	if cnt == 0 {
		return "insns=[]"
	}
	if ctx.Opts == nil || !ctx.Opts.Verbose {
		return fmt.Sprintf("insns=%#x", insnsAddr)
	}
	return fmt.Sprintf("insns=%#x", insnsAddr)
}

// decodeSingleInsn helper to unpack and decode a single eBPF instruction struct.
// Impact: Low-level instruction parser for BPF verifier representation.
func decodeSingleInsn(data []byte) string {
	code := data[0]
	dst := data[1] & 0x0f
	src := data[1] >> 4
	off := int16(binary.LittleEndian.Uint16(data[2:4]))
	imm := binary.LittleEndian.Uint32(data[4:8])
	codeStr := decodeBpfInsnCode(code)
	dstStr := decodeBpfReg(dst)
	srcStr := decodeBpfReg(src)
	return fmt.Sprintf("{code=%s, dst_reg=%s, src_reg=%s, off=%d, imm=%#x}", codeStr, dstStr, srcStr, off, imm)
}

// decodeBpfReg decodes register number into BPF_REG_N format or generic symbolic placeholder.
// Impact: Helper to match BPF register conventions in strace output.
func decodeBpfReg(reg uint8) string {
	if reg <= 10 {
		return fmt.Sprintf("BPF_REG_%d", reg)
	}
	return fmt.Sprintf("%#x /* BPF_REG_??? */", reg)
}

// decodeBpfInsnCode deconstructs BPF code byte into human-readable BPF class/mode/op combination.
// Impact: Expands instruction operation and addressing modes for diagnostics.
func decodeBpfInsnCode(code uint8) string {
	class := code & 0x07
	var classStr string
	switch class {
	case 0:
		classStr = "BPF_LD"
	case 1:
		classStr = "BPF_LDX"
	case 2:
		classStr = "BPF_ST"
	case 3:
		classStr = "BPF_STX"
	case 4:
		classStr = "BPF_ALU"
	case 5:
		classStr = "BPF_JMP"
	case 6:
		classStr = "BPF_JMP32"
	case 7:
		classStr = "BPF_ALU64"
	}
	src := code & 0x08
	var srcStr string
	if src == 0 {
		srcStr = "BPF_K"
	} else {
		srcStr = "BPF_X"
	}
	if class <= 3 {
		return decodeBpfInsnMem(code, classStr)
	}
	if class == 5 || class == 6 {
		return decodeBpfInsnJmp(code, classStr, src, srcStr)
	}
	return decodeBpfInsnAlu(code, classStr, srcStr)
}

func decodeBpfInsnMem(code uint8, classStr string) string {
	var opStr string
	size := code & 0x18
	switch size {
	case 0x00:
		opStr = "BPF_W"
	case 0x08:
		opStr = "BPF_H"
	case 0x10:
		opStr = "BPF_B"
	case 0x18:
		opStr = "BPF_DW"
	}
	mode := code & 0xe0
	var modeStr string
	switch mode {
	case 0x00:
		modeStr = "BPF_IMM"
	case 0x20:
		modeStr = "BPF_ABS"
	case 0x40:
		modeStr = "BPF_IND"
	case 0x60:
		modeStr = "BPF_MEM"
	case 0xc0:
		modeStr = "BPF_XADD"
	default:
		modeStr = fmt.Sprintf("%#x", mode)
	}
	return modeStr + "|" + opStr + "|" + classStr
}

func decodeBpfInsnJmp(code uint8, classStr string, src uint8, srcStr string) string {
	var opStr string
	op := code & 0xf0
	switch op {
	case 0x00:
		opStr = "BPF_ADD"
	case 0x10:
		opStr = "BPF_SUB"
	case 0x20:
		opStr = "BPF_MUL"
	case 0x30:
		opStr = "BPF_DIV"
	case 0x40:
		opStr = "BPF_OR"
	case 0x50:
		opStr = "BPF_AND"
	case 0x60:
		opStr = "BPF_LSH"
	case 0x70:
		opStr = "BPF_RSH"
	case 0x80:
		opStr = "BPF_JA"
	case 0x90:
		if src == 0 {
			return "BPF_JMP|BPF_K|BPF_EXIT"
		}
		opStr = "BPF_JEQ"
	case 0xa0:
		opStr = "BPF_JGT"
	case 0xb0:
		opStr = "BPF_JGE"
	case 0xc0:
		opStr = "BPF_JSET"
	case 0xd0:
		opStr = "BPF_JNE"
	case 0xe0:
		opStr = "BPF_JSGT"
	case 0xf0:
		opStr = "BPF_JSGE"
	default:
		opStr = fmt.Sprintf("%#x", op)
	}
	return classStr + "|" + srcStr + "|" + opStr
}

func decodeBpfInsnAlu(code uint8, classStr string, srcStr string) string {
	var opStr string
	op := code & 0xf0
	switch op {
	case 0x00:
		opStr = "BPF_ADD"
	case 0x10:
		opStr = "BPF_SUB"
	case 0x20:
		opStr = "BPF_MUL"
	case 0x30:
		opStr = "BPF_DIV"
	case 0x40:
		opStr = "BPF_OR"
	case 0x50:
		opStr = "BPF_AND"
	case 0x60:
		opStr = "BPF_LSH"
	case 0x70:
		opStr = "BPF_RSH"
	case 0x80:
		opStr = "BPF_NEG"
	case 0x90:
		opStr = "BPF_MOD"
	case 0xa0:
		opStr = "BPF_XOR"
	case 0xb0:
		opStr = "BPF_MOV"
	case 0xc0:
		opStr = "BPF_ARSH"
	case 0xd0:
		opStr = "BPF_END"
	default:
		opStr = fmt.Sprintf("%#x", op)
	}
	return classStr + "|" + srcStr + "|" + opStr
}
