package handler

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

const (
	statxStructSize      = 256
	statxType            = uint32(0x0001)
	statxMode            = uint32(0x0002)
	statxNlink           = uint32(0x0004)
	statxUID             = uint32(0x0008)
	statxGID             = uint32(0x0010)
	statxAtime           = uint32(0x0020)
	statxMtime           = uint32(0x0040)
	statxCtime           = uint32(0x0080)
	statxIno             = uint32(0x0100)
	statxSize            = uint32(0x0200)
	statxBlocks          = uint32(0x0400)
	statxBtime           = uint32(0x0800)
	statxMntID           = uint32(0x1000)
	statxDioAlign        = uint32(0x2000)
	statxSubvol          = uint32(0x8000)
	statxDioReadAlign    = uint32(0x20000)
	statxAttrWriteAtomic = uint64(0x400000)
)

type statxTimestamp struct {
	sec  int64
	nsec uint32
}

type statxSnapshot struct {
	mask, blockSize, nlink, uid, gid uint32
	mode                             uint16
	attributes, inode, size, blocks  uint64
	attributesMask                   uint64
	atime, btime, ctime, mtime       statxTimestamp
	rdevMajor, rdevMinor             uint32
	devMajor, devMinor               uint32
	mountID, subvolume               uint64
	dioMemAlign, dioOffsetAlign      uint32
	atomicMin, atomicMax             uint32
	atomicSegments, dioReadAlign     uint32
	atomicMaxOpt                     uint32
}

func parseStatxSnapshot(data []byte) statxSnapshot {
	return statxSnapshot{
		mask: binary.LittleEndian.Uint32(data[0:4]), blockSize: binary.LittleEndian.Uint32(data[4:8]),
		attributes: binary.LittleEndian.Uint64(data[8:16]), nlink: binary.LittleEndian.Uint32(data[16:20]),
		uid: binary.LittleEndian.Uint32(data[20:24]), gid: binary.LittleEndian.Uint32(data[24:28]),
		mode: binary.LittleEndian.Uint16(data[28:30]), inode: binary.LittleEndian.Uint64(data[32:40]),
		size: binary.LittleEndian.Uint64(data[40:48]), blocks: binary.LittleEndian.Uint64(data[48:56]),
		attributesMask: binary.LittleEndian.Uint64(data[56:64]), atime: parseStatxTimestamp(data[64:80]),
		btime: parseStatxTimestamp(data[80:96]), ctime: parseStatxTimestamp(data[96:112]),
		mtime: parseStatxTimestamp(data[112:128]), rdevMajor: binary.LittleEndian.Uint32(data[128:132]),
		rdevMinor: binary.LittleEndian.Uint32(data[132:136]), devMajor: binary.LittleEndian.Uint32(data[136:140]),
		devMinor: binary.LittleEndian.Uint32(data[140:144]), mountID: binary.LittleEndian.Uint64(data[144:152]),
		dioMemAlign: binary.LittleEndian.Uint32(data[152:156]), dioOffsetAlign: binary.LittleEndian.Uint32(data[156:160]),
		subvolume: binary.LittleEndian.Uint64(data[160:168]), atomicMin: binary.LittleEndian.Uint32(data[168:172]),
		atomicMax: binary.LittleEndian.Uint32(data[172:176]), atomicSegments: binary.LittleEndian.Uint32(data[176:180]),
		dioReadAlign: binary.LittleEndian.Uint32(data[180:184]), atomicMaxOpt: binary.LittleEndian.Uint32(data[184:188]),
	}
}

func parseStatxTimestamp(data []byte) statxTimestamp {
	return statxTimestamp{sec: int64(binary.LittleEndian.Uint64(data[0:8])), nsec: binary.LittleEndian.Uint32(data[8:12])}
}

func (s statxSnapshot) format(verbose bool) string {
	parts := []string{"stx_mask=" + meta.DecodeFlags(uint64(s.mask), "statx_masks")}
	if verbose {
		parts = append(parts, fmt.Sprintf("stx_blksize=%d", s.blockSize))
	}
	parts = append(parts, "stx_attributes="+meta.DecodeFlags(s.attributes, "statx_attrs"))
	parts = s.appendBasicFields(parts, verbose)
	if !verbose {
		return "{" + strings.Join(parts, ", ") + ", ...}"
	}
	parts = append(parts, "stx_attributes_mask="+meta.DecodeFlags(s.attributesMask, "statx_attrs"))
	parts = s.appendTimeFields(parts)
	parts = s.appendDeviceFields(parts)
	parts = s.appendExtendedFields(parts)
	return "{" + strings.Join(parts, ", ") + "}"
}

func (s statxSnapshot) appendBasicFields(parts []string, verbose bool) []string {
	if verbose && s.mask&statxNlink != 0 {
		parts = append(parts, fmt.Sprintf("stx_nlink=%d", s.nlink))
	}
	if verbose && s.mask&statxUID != 0 {
		parts = append(parts, fmt.Sprintf("stx_uid=%d", s.uid))
	}
	if verbose && s.mask&statxGID != 0 {
		parts = append(parts, fmt.Sprintf("stx_gid=%d", s.gid))
	}
	if s.mask&(statxType|statxMode) != 0 {
		parts = append(parts, "stx_mode="+format.MknodMode(s.mode))
	}
	if verbose && s.mask&statxIno != 0 {
		parts = append(parts, fmt.Sprintf("stx_ino=%d", s.inode))
	}
	if s.mask&statxSize != 0 {
		parts = append(parts, fmt.Sprintf("stx_size=%d", s.size))
	}
	if verbose && s.mask&statxBlocks != 0 {
		parts = append(parts, fmt.Sprintf("stx_blocks=%d", s.blocks))
	}
	return parts
}

func (s statxSnapshot) appendTimeFields(parts []string) []string {
	if s.mask&statxAtime != 0 {
		parts = append(parts, "stx_atime="+s.atime.format())
	}
	if s.mask&statxBtime != 0 {
		parts = append(parts, "stx_btime="+s.btime.format())
	}
	if s.mask&statxCtime != 0 {
		parts = append(parts, "stx_ctime="+s.ctime.format())
	}
	if s.mask&statxMtime != 0 {
		parts = append(parts, "stx_mtime="+s.mtime.format())
	}
	return parts
}

func (s statxSnapshot) appendDeviceFields(parts []string) []string {
	return append(parts,
		fmt.Sprintf("stx_rdev_major=%d", s.rdevMajor), fmt.Sprintf("stx_rdev_minor=%d", s.rdevMinor),
		fmt.Sprintf("stx_dev_major=%d", s.devMajor), fmt.Sprintf("stx_dev_minor=%d", s.devMinor))
}

func (s statxSnapshot) appendExtendedFields(parts []string) []string {
	if s.mask&statxMntID != 0 {
		parts = append(parts, fmt.Sprintf("stx_mnt_id=%#x", s.mountID))
	}
	if s.mask&statxDioAlign != 0 {
		parts = append(parts, fmt.Sprintf("stx_dio_mem_align=%d", s.dioMemAlign), fmt.Sprintf("stx_dio_offset_align=%d", s.dioOffsetAlign))
	}
	if s.mask&statxSubvol != 0 {
		parts = append(parts, fmt.Sprintf("stx_subvol=%#x", s.subvolume))
	}
	if s.attributes&statxAttrWriteAtomic != 0 {
		parts = append(parts, fmt.Sprintf("stx_atomic_write_unit_min=%d", s.atomicMin), fmt.Sprintf("stx_atomic_write_unit_max=%d", s.atomicMax),
			fmt.Sprintf("stx_atomic_write_segments_max=%d", s.atomicSegments))
	}
	if s.mask&statxDioReadAlign != 0 {
		parts = append(parts, fmt.Sprintf("stx_dio_read_offset_align=%d", s.dioReadAlign))
	}
	if s.attributes&statxAttrWriteAtomic != 0 {
		parts = append(parts, fmt.Sprintf("stx_atomic_write_unit_max_opt=%d", s.atomicMaxOpt))
	}
	return parts
}

func (ts statxTimestamp) format() string {
	base := fmt.Sprintf("{tv_sec=%d, tv_nsec=%d}", ts.sec, ts.nsec)
	stamp := time.Unix(ts.sec, int64(ts.nsec)).UTC().Format("2006-01-02T15:04:05.000000000-0700")
	return fmt.Sprintf("%s /* %s */", base, stamp)
}
