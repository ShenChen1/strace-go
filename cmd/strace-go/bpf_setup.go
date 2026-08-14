package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"strace-go/pkg/meta"
)

type traceBPFSetupStage string

const (
	bpfSetupMemlockStage          traceBPFSetupStage = "bpf_memlock"
	bpfSetupSpecStage             traceBPFSetupStage = "bpf_spec"
	bpfSetupObjectsStage          traceBPFSetupStage = "bpf_objects"
	bpfSetupRoutePlanStage        traceBPFSetupStage = "bpf_route_plan"
	bpfSetupRouteMapsStage        traceBPFSetupStage = "bpf_route_maps"
	bpfSetupProgArraysStage       traceBPFSetupStage = "bpf_prog_arrays"
	bpfSetupTracepointsStage      traceBPFSetupStage = "bpf_tracepoints"
	bpfSetupRecvmsgKretprobeStage traceBPFSetupStage = "bpf_recvmsg_kretprobe"
)

type traceBPFSetupTiming struct {
	Stage   traceBPFSetupStage
	StartNS uint64
	EndNS   uint64
}

// traceBPFSetupObserver receives completed setup stages without owning BPF resources.
type traceBPFSetupObserver interface {
	RecordBPFSetupStage(timing traceBPFSetupTiming)
}

type bpfSetupRecorder struct {
	timings []traceBPFSetupTiming
}

func newBPFSetupRecorder() *bpfSetupRecorder {
	return &bpfSetupRecorder{}
}

func (r *bpfSetupRecorder) RecordBPFSetupStage(timing traceBPFSetupTiming) {
	if r == nil {
		return
	}
	r.timings = append(r.timings, timing)
}

func (r *bpfSetupRecorder) Timings() []traceBPFSetupTiming {
	if r == nil {
		return nil
	}
	return append([]traceBPFSetupTiming(nil), r.timings...)
}

func measureBPFSetupStage(
	clock traceClock,
	observer traceBPFSetupObserver,
	stage traceBPFSetupStage,
	action func() error,
) error {
	if clock == nil {
		return fmt.Errorf("BPF setup clock is nil")
	}
	if action == nil {
		return fmt.Errorf("BPF setup action for %s is nil", stage)
	}
	startNS := clock.NowMonoNs()
	err := action()
	endNS := clock.NowMonoNs()
	if observer != nil {
		observer.RecordBPFSetupStage(traceBPFSetupTiming{
			Stage:   stage,
			StartNS: startNS,
			EndNS:   endNS,
		})
	}
	return err
}

func setupBPF() (*traceBPFRuntime, error) {
	return setupBPFWithClock(systemTraceClock{})
}

func setupBPFWithClock(clock traceClock) (*traceBPFRuntime, error) {
	if clock == nil {
		return nil, fmt.Errorf("BPF setup clock is nil")
	}
	recorder := newBPFSetupRecorder()
	if err := measureBPFSetupStage(clock, recorder, bpfSetupMemlockStage, rlimit.RemoveMemlock); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var spec *ebpf.CollectionSpec
	if err := measureBPFSetupStage(clock, recorder, bpfSetupSpecStage, func() error {
		var err error
		spec, err = loadBpf()
		if err != nil {
			return fmt.Errorf("load BPF spec: %w", err)
		}
		if err := setSyscallVariables(spec); err != nil {
			return fmt.Errorf("resolve BPF syscall variables: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	objects := &bpfObjects{}
	if err := measureBPFSetupStage(clock, recorder, bpfSetupObjectsStage, func() error {
		if err := spec.LoadAndAssign(objects, nil); err != nil {
			return fmt.Errorf("load and assign BPF objects: %w", err)
		}
		return nil
	}); err != nil {
		return nil, errors.Join(err, objects.Close())
	}

	var routePlan bpfRoutePlan
	if err := measureBPFSetupStage(clock, recorder, bpfSetupRoutePlanStage, func() error {
		var err error
		routePlan, err = newBPFRoutePlan(meta.SyscallTable)
		return err
	}); err != nil {
		return nil, fmt.Errorf("build BPF route plan: %w", errors.Join(err, objects.Close()))
	}
	if err := measureBPFSetupStage(clock, recorder, bpfSetupRouteMapsStage, func() error {
		return configureBPFRouteMaps(objects, routePlan)
	}); err != nil {
		return nil, fmt.Errorf("configure BPF route maps: %w", errors.Join(err, objects.Close()))
	}

	attacher := newBpfAttacher(objects)
	if err := measureBPFSetupStage(clock, recorder, bpfSetupProgArraysStage, attacher.populateProgArrays); err != nil {
		return nil, fmt.Errorf("populate BPF program arrays: %w", errors.Join(err, objects.Close()))
	}
	var links []link.Link
	if err := measureBPFSetupStage(clock, recorder, bpfSetupTracepointsStage, func() error {
		var err error
		links, err = attacher.attachRequired()
		return err
	}); err != nil {
		return nil, fmt.Errorf("attach required BPF programs: %w", errors.Join(err, closeTracepointLinks(links), objects.Close()))
	}
	if err := measureBPFSetupStage(clock, recorder, bpfSetupRecvmsgKretprobeStage, func() error {
		kprobe, err := attacher.attachOptionalRecvmsg()
		if err != nil {
			log.Printf("recvmsg kretprobe unavailable; nested OUT payloads may fall back to bounded tracepoint data: %v", err)
			return nil
		}
		if kprobe != nil {
			links = append(links, kprobe)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("attach optional BPF programs: %w", errors.Join(err, closeTracepointLinks(links), objects.Close()))
	}

	return &traceBPFRuntime{
		objects:      objects,
		links:        links,
		setupTimings: recorder.Timings(),
	}, nil
}
