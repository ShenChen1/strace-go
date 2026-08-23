package main

import (
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// tracepointSpec declares one required tracepoint program attachment.
type tracepointSpec struct {
	program  *ebpf.Program
	category string
	name     string
}

// bpfAttacher owns the program attachment policy for the eBPF runtime.
// It keeps runtime loading separate from program-to-tracepoint wiring and
// makes that wiring declarative and unit-testable.
type bpfAttacher struct {
	core     bpfMapProvider
	programs bpfProgramProvider
}

func newBpfAttacher(core bpfCoreResourceProvider) *bpfAttacher {
	return newBpfAttacherWithPrograms(core, core)
}

func newBpfAttacherWithPrograms(
	core bpfMapProvider,
	programs bpfProgramProvider,
) *bpfAttacher {
	return &bpfAttacher{core: core, programs: programs}
}

// attachAll attaches every raw syscall, lifecycle and recvmsg kretprobe program.
func (a *bpfAttacher) attachAll() ([]link.Link, error) {
	if a == nil || a.core == nil {
		return nil, fmt.Errorf("BPF core resources are nil")
	}
	if err := a.populateProgArrays(); err != nil {
		return nil, fmt.Errorf("populate tail call prog arrays: %w", err)
	}
	links, err := a.attachRequired()
	if err != nil {
		return nil, errors.Join(err, closeTracepointLinks(links))
	}
	if kp, err := a.attachOptionalRecvmsg(); err != nil {
		log.Printf("recvmsg kretprobe unavailable; nested OUT payloads may fall back to bounded tracepoint data: %v", err)
	} else if kp != nil {
		links = append(links, kp)
	}
	return links, nil
}

// attachRequired owns only the raw syscall and lifecycle links. Partial links
// are returned so the caller can roll them back when a later attach fails.
func (a *bpfAttacher) attachRequired() ([]link.Link, error) {
	if a == nil || a.core == nil {
		return nil, fmt.Errorf("BPF core resources are nil")
	}
	links, err := a.attachTracepoints(rawSyscallTracepointSpecs(a.programs))
	if err != nil {
		return links, err
	}
	lifecycleLinks, err := a.attachTracepoints(lifecycleTracepointSpecs(a.programs))
	if err != nil {
		return append(links, lifecycleLinks...), err
	}
	return append(links, lifecycleLinks...), nil
}

func (a *bpfAttacher) attachOptionalRecvmsg() (link.Link, error) {
	return a.attachOptionalRecvmsgFor(true)
}

func (a *bpfAttacher) attachOptionalRecvmsgFor(enabled bool) (link.Link, error) {
	if a == nil || a.core == nil {
		return nil, fmt.Errorf("BPF core resources are nil")
	}
	if !enabled {
		return nil, nil
	}
	return a.attachRecvmsgKretprobe()
}

// rawSyscallTracepointSpecs lists the raw_syscalls programs that must attach.
//
// IMPACT: raw syscall programs are required; a failure to attach any of them
// aborts the session because syscall observation would be incomplete. Family
// handlers are not attached here; they live in enter_progs/exit_progs and are
// dispatched via bpf_tail_call (see populateProgArrays).
func rawSyscallTracepointSpecs(programs bpfProgramProvider) []tracepointSpec {
	return bpfCoreTracepointSpecs(programs, bpfRawSyscallTracepointCategory)
}

// Tail call prog array indices, kept in sync with bpf/enter_dispatch.h and
// bpf/exit_dispatch.h. The BPF source gate test enforces the mapping.
const (
	enterProgTerminating      = 1
	enterProgExec             = 2
	enterProgPathStat         = 3
	enterProgPathOnly         = 4
	enterProgDualPath         = 5
	enterProgOpenat2          = 6
	enterProgReadlink         = 7
	enterProgMiscStruct       = 8
	enterProgSmallStruct      = 9
	enterProgItimer           = 10
	enterProgTimeStruct       = 11
	enterProgSignal           = 12
	enterProgFileTime         = 13
	enterProgSleep            = 14
	enterProgFutex            = 15
	enterProgCachestat        = 16
	enterProgCapability       = 17
	enterProgMemfd            = 18
	enterProgPrctl            = 19
	enterProgClone3           = 20
	enterProgBpf              = 21
	enterProgBpfUprobeMulti   = 51
	enterProgBpfProgLoad      = 52
	enterProgBpfProgLoadDebug = 53
	enterProgIovec            = 22
	enterProgMsg              = 23
	enterProgMmsg             = 24
	enterProgFcntl            = 25
	enterProgIoctl            = 26
	enterProgNetwork          = 27
	enterProgKey              = 28
	enterProgXattr            = 29
	enterProgFs               = 30
	enterProgAio              = 31
	enterProgPoll             = 32
	enterProgSelect           = 33
	enterProgEpoll            = 34
	enterProgNoPayload        = 35
	enterProgPayload          = 36
	enterProgIovecBase        = 37
	enterProgSendmsgBase      = 38
	enterProgMmsgB01          = 39
	enterProgMmsgB2           = 40
	enterProgMmsgB3           = 41
	enterProgAioIovec         = 42
	enterProgAioBuf           = 43
	enterProgQuota            = 44
	enterProgMountPath        = 45
	enterProgNoPayloadGeneric = 46
	enterProgNestedFDPath0    = 47
	enterProgNestedFDPath1    = 48
	enterProgNestedFDPath2    = 49
	enterProgNestedFDPath3    = 50
)

const (
	exitProgGeneric        = 0
	exitProgIovecBase      = 1
	exitProgMsg            = 2
	exitProgMmsgFinal      = 3
	exitProgRecvmmsgBase01 = 4
	exitProgRecvmmsgBase23 = 5
	exitProgQuota          = 6
	exitProgMountQuery     = 7
	exitProgPath           = 8
	exitProgFDTime         = 9
	exitProgStruct         = 10
	exitProgAsync          = 11
	exitProgIO             = 12
	exitProgControl        = 13
	exitProgNestedFDPath0  = 14
	exitProgNestedFDPath1  = 15
	exitProgNestedFDPath2  = 16
	exitProgNestedFDPath3  = 17
)

const (
	recvmsgProgName    = 0
	recvmsgProgControl = 1
	recvmsgProgFinal   = 2
)

const (
	mmsgBytesProgBase0 = 0
	mmsgBytesProgBase1 = 1
	mmsgBytesProgBase2 = 2
	mmsgBytesProgBase3 = 3
)

type progArrayEntry struct {
	index uint32
	prog  *ebpf.Program
}

// progArrayWriter is the minimal map operation needed to populate a tail-call array.
type progArrayWriter interface {
	Put(key, value interface{}) error
}

func enterProgArrayEntries(programs bpfProgramProvider) []progArrayEntry {
	return bpfTailCallProgramEntries(programs, bpfEnterProgramCatalog)
}

func exitProgArrayEntries(programs bpfProgramProvider) []progArrayEntry {
	return bpfTailCallProgramEntries(programs, bpfExitProgramCatalog)
}

func recvmsgProgArrayEntries(programs bpfProgramProvider) []progArrayEntry {
	return bpfTailCallProgramEntries(programs, bpfRecvmsgProgramCatalog)
}

func mmsgBytesProgArrayEntries(programs bpfProgramProvider) []progArrayEntry {
	return bpfTailCallProgramEntries(programs, bpfMmsgByteProgramCatalog)
}

func bpfProgram(provider bpfProgramProvider, name string) *ebpf.Program {
	if provider == nil {
		return nil
	}
	return provider.program(name)
}

// putProgArrayEntries validates and writes one complete tail-call array.
func putProgArrayEntries(name string, writer progArrayWriter, entries []progArrayEntry) error {
	for _, entry := range entries {
		if entry.prog == nil {
			return fmt.Errorf("%s[%d]: nil handler", name, entry.index)
		}
		if err := writer.Put(entry.index, entry.prog); err != nil {
			return fmt.Errorf("%s[%d]: %w", name, entry.index, err)
		}
	}
	return nil
}

// populateProgArrays fills the tail call prog arrays before any raw syscall
// tracepoint is attached; an empty slot would silently drop that family.
func (a *bpfAttacher) populateProgArrays() error {
	return a.populateProgArraysFor(bpfProgramSelection{loadAll: true})
}

func (a *bpfAttacher) populateProgArraysFor(selection bpfProgramSelection) error {
	if a == nil || a.core == nil {
		return fmt.Errorf("BPF core resources are nil")
	}
	enterProgs := a.core.coreMap(bpfMapEnterProgs)
	mmsgBytesProgs := a.core.coreMap(bpfMapMmsgBytesProgs)
	exitProgs := a.core.coreMap(bpfMapExitProgs)
	recvmsgProgs := a.core.coreMap(bpfMapRecvmsgProgs)
	if enterProgs == nil || mmsgBytesProgs == nil || exitProgs == nil || recvmsgProgs == nil {
		return fmt.Errorf("BPF tail-call prog arrays are unavailable")
	}
	enterEntries := selectedProgArrayEntries(
		enterProgArrayEntries(a.programs),
		selection.enterSlots,
		selection.loadAll,
	)
	if err := putProgArrayEntries(bpfMapEnterProgs, enterProgs, enterEntries); err != nil {
		return err
	}
	mmsgByteEntries := selectedProgArrayEntries(
		mmsgBytesProgArrayEntries(a.programs),
		selection.mmsgByteSlots,
		selection.loadAll,
	)
	if err := putProgArrayEntries(bpfMapMmsgBytesProgs, mmsgBytesProgs, mmsgByteEntries); err != nil {
		return err
	}
	exitEntries := selectedProgArrayEntries(
		exitProgArrayEntries(a.programs),
		selection.exitSlots,
		selection.loadAll,
	)
	if err := putProgArrayEntries(bpfMapExitProgs, exitProgs, exitEntries); err != nil {
		return err
	}
	recvmsgEntries := selectedProgArrayEntries(
		recvmsgProgArrayEntries(a.programs),
		selection.recvmsgSlots,
		selection.loadAll,
	)
	return putProgArrayEntries(bpfMapRecvmsgProgs, recvmsgProgs, recvmsgEntries)
}

// lifecycleTracepointSpecs lists the sched lifecycle programs required by the
// event-sourced task state contract.
func lifecycleTracepointSpecs(programs bpfProgramProvider) []tracepointSpec {
	return bpfCoreTracepointSpecs(programs, bpfLifecycleTracepointCategory)
}

func bpfCoreTracepointSpecs(programs bpfProgramProvider, category string) []tracepointSpec {
	specs := make([]tracepointSpec, 0)
	for _, program := range bpfCoreProgramCatalog {
		if program.category != category {
			continue
		}
		var loaded *ebpf.Program
		if programs != nil {
			loaded = programs.program(program.name)
		}
		specs = append(specs, tracepointSpec{
			program:  loaded,
			category: program.category,
			name:     program.tracepoint,
		})
	}
	return specs
}

// attachTracepoints attaches each required spec and aborts on the first
// failure so the session never runs with incomplete event facts.
func (a *bpfAttacher) attachTracepoints(specs []tracepointSpec) ([]link.Link, error) {
	var links []link.Link
	for _, spec := range specs {
		tp, err := link.Tracepoint(spec.category, spec.name, spec.program, nil)
		if err != nil {
			return links, fmt.Errorf("attach %s/%s tracepoint: %w", spec.category, spec.name, err)
		}
		links = append(links, tp)
	}
	return links, nil
}

// attachRecvmsgKretprobe attaches the single recvmsg return dispatcher.
func (a *bpfAttacher) attachRecvmsgKretprobe() (link.Link, error) {
	program := bpfProgram(a.programs, bpfRecvmsgDispatchProgramName)
	if program == nil {
		return nil, fmt.Errorf("recvmsg kretprobe program is unavailable")
	}
	var lastErr error
	for _, symbol := range []string{"__sys_recvmsg", "__x64_sys_recvmsg"} {
		kp, err := link.Kretprobe(symbol, program, nil)
		if err == nil {
			return kp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		return nil, fmt.Errorf("no recvmsg kretprobe symbol available")
	}
	return nil, fmt.Errorf("recvmsg symbols: %w", lastErr)
}

func closeTracepointLinks(links []link.Link) error {
	return closeTracepointLinksWithDiagnostics(links, nil, nil)
}

func closeTracepointLinksWithDiagnostics(
	links []link.Link,
	clock traceClock,
	observer traceCleanupObserver,
) error {
	var closeErr error
	for index, l := range links {
		if l != nil {
			startNS := cleanupClockNowNS(clock)
			if err := l.Close(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("close BPF link %d: %w", index, err))
			}
			recordBPFResourceTiming(observer, fmt.Sprintf("bpf_link_%d", index), startNS, cleanupClockNowNS(clock))
		}
	}
	return closeErr
}

func closeTracepointLinksParallelWithDiagnostics(
	links []link.Link,
	clock traceClock,
	observer traceCleanupObserver,
) error {
	resources := make([]traceBPFResource, 0, len(links))
	for index, current := range links {
		if current == nil {
			continue
		}
		resources = append(resources, traceBPFResource{
			Name:   fmt.Sprintf("bpf_link_%d", index),
			Closer: tracepointLinkCloser{index: index, closer: current},
		})
	}
	return closeNamedBPFResourcesParallel(resources, clock, observer)
}

type tracepointLinkCloser struct {
	index  int
	closer io.Closer
}

func (c tracepointLinkCloser) Close() error {
	if c.closer == nil {
		return nil
	}
	if err := c.closer.Close(); err != nil {
		return fmt.Errorf("close BPF link %d: %w", c.index, err)
	}
	return nil
}
