package main

import (
	"fmt"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

const (
	defaultStringSnapshotCap = 512
	pathStringSnapshotCap    = 4097
)

type syscallEventContext struct {
	raw                *bpfEvent
	statePID           int
	tid                int
	meta               meta.Syscall
	isPath             bool
	rawStrArg          string
	shouldPrint        bool
	pendingEnter       *pendingSyscallState
	handlerContext     *handler.Context
	bufferFileOffset   int64
	bufferFileOffsetOK bool
}

func newSyscallEventContext(s *traceSession, eventRaw *bpfEvent, statePID int, pendingEnter *pendingSyscallState) syscallEventContext {
	scMeta := syscallMeta(eventRaw.SysId)
	isPath := syscallHasPathArg(scMeta)
	rawStrArg := decodeRawStringArg(s, eventRaw, scMeta, isPath)
	shouldPrint := true
	if s.opts != nil {
		shouldPrint = checkShouldPrint(eventRaw, scMeta, rawStrArg, isPath, statePID, s.opts, s.fdMap)
	}
	bufferFileOffset, bufferFileOffsetOK := s.bufferFileOffset(eventRaw, scMeta)
	ev := syscallEventContext{
		raw:                eventRaw,
		statePID:           statePID,
		tid:                int(eventRaw.Tid),
		meta:               scMeta,
		isPath:             isPath,
		rawStrArg:          rawStrArg,
		shouldPrint:        shouldPrint,
		pendingEnter:       pendingEnter,
		bufferFileOffset:   bufferFileOffset,
		bufferFileOffsetOK: bufferFileOffsetOK,
	}
	ev.handlerContext = ev.newHandlerContext(s)
	return ev
}

func syscallMeta(sysID uint32) meta.Syscall {
	if scMeta, ok := meta.SyscallTable[sysID]; ok {
		return scMeta
	}
	return meta.Syscall{Name: unknownSyscallName(sysID)}
}

func unknownSyscallName(sysID uint32) string {
	return fmt.Sprintf("sys_%d", sysID)
}

func syscallHasPathArg(scMeta meta.Syscall) bool {
	for _, argName := range scMeta.Args {
		switch argName {
		case "filename", "pathname", "path", "oldname", "newname", "fs_name":
			return true
		}
	}
	return false
}

func decodeRawStringArg(s *traceSession, eventRaw *bpfEvent, scMeta meta.Syscall, isPath bool) string {
	capSize := defaultStringSnapshotCap
	if isPath {
		capSize = pathStringSnapshotCap
	}
	return s.decoder.DecodeString(
		int(eventRaw.Tid),
		eventRaw.Ptr,
		eventRaw.StrArg[:capSize],
		resolvePtrProbeRet(eventRaw),
		scMeta.Name,
		0,
	)
}

func (ev syscallEventContext) newHandlerContext(s *traceSession) *handler.Context {
	return &handler.Context{
		Pid: int(ev.raw.Pid), Tid: ev.tid, TargetPid: ev.statePID, SysId: ev.raw.SysId,
		SysName: ev.meta.Name, Args: ev.raw.Args, Ret: ev.raw.Ret,
		ProbeRetEnter: ev.raw.ProbeRetEnter, ProbeRetExit: ev.raw.ProbeRetExit,
		Ptr: ev.raw.Ptr, DataLen: ev.raw.DataLen, StrArgBuf: ev.raw.StrArg[:], RawStrArg: ev.rawStrArg,
		PayloadSections:  payloadSectionsForEvent(ev.raw, ev.meta),
		BufferFileOffset: ev.bufferFileOffset, BufferFileOffsetOK: ev.bufferFileOffsetOK,
		ScMeta: ev.meta, Decoder: s.decoder, Opts: s.opts, FdMap: s.fdMap,
		FdFiles: s.fdFiles,
	}
}

func (s *traceSession) updateSummaryStats(ev syscallEventContext) {
	if s.opts == nil || (!s.opts.SummaryOnly && !s.opts.SummaryAndPrint) || !ev.shouldPrint {
		return
	}
	if s.stats == nil {
		s.stats = make(map[string]*syscallStat)
	}
	stat := s.stats[ev.meta.Name]
	if stat == nil {
		stat = &syscallStat{}
		s.stats[ev.meta.Name] = stat
	}
	stat.calls++
	stat.duration += ev.raw.Duration
	if ev.raw.Ret < 0 && ev.raw.Ret >= -4095 {
		stat.errors++
	}
}

func (ev syscallEventContext) isFDStateSyscall() bool {
	switch ev.meta.Name {
	case "open", "openat", "openat2", "creat", "dup", "dup2", "dup3", "close",
		"faccessat", "faccessat2", "chmodat", "mkdirat", "newfstatat", "fstat", "chdir", "fchdir":
		return true
	default:
		return false
	}
}

func (s *traceSession) updateFDState(ev syscallEventContext) {
	updateFDMap(ev.raw, ev.meta, ev.rawStrArg, s.decoder, ev.statePID, s.fdMap)
}

func (s *traceSession) cleanupClosedFD(ev syscallEventContext) {
	if ev.meta.Name != "close" || ev.raw.Ret != 0 {
		return
	}
	key := fdStateKey(ev.statePID, int32(ev.raw.Args[0]))
	delete(s.fdMap, key)
	delete(s.fdOffsets, key)
	if f := s.fdFiles[key]; f != nil {
		f.Close()
		delete(s.fdFiles, key)
	}
}
