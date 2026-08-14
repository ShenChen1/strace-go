package main

import (
	"errors"
	"io"
	"sync"
)

type traceBPFResource struct {
	Name   string
	Closer io.Closer
}

// closeBPFResourcesParallel closes independent BPF resources concurrently.
// Each worker owns one error slot, so the event path and cleanup path need no mutex.
func closeBPFResourcesParallel(resources []io.Closer) error {
	named := make([]traceBPFResource, len(resources))
	for index, resource := range resources {
		named[index] = traceBPFResource{
			Name:   "bpf_resource",
			Closer: resource,
		}
	}
	return closeNamedBPFResourcesParallel(named, nil, nil)
}

func closeNamedBPFResourcesParallel(
	resources []traceBPFResource,
	clock traceClock,
	observer traceCleanupObserver,
) error {
	if len(resources) == 0 {
		return nil
	}
	errs := make([]error, len(resources))
	timings := make([]traceCleanupTiming, len(resources))
	var workers sync.WaitGroup
	workers.Add(len(resources))
	for index, resource := range resources {
		if resource.Closer == nil {
			workers.Done()
			continue
		}
		go func(index int, resource traceBPFResource) {
			defer workers.Done()
			startNS := cleanupClockNowNS(clock)
			errs[index] = resource.Closer.Close()
			timings[index] = traceCleanupTiming{
				Name:    resource.Name,
				StartNS: startNS,
				EndNS:   cleanupClockNowNS(clock),
			}
		}(index, resource)
	}
	workers.Wait()
	if observer != nil {
		for index, resource := range resources {
			if resource.Closer != nil {
				observer.RecordCleanupStep(timings[index])
			}
		}
	}
	return errors.Join(errs...)
}

func cleanupClockNowNS(clock traceClock) uint64 {
	if clock == nil {
		return 0
	}
	return clock.NowMonoNs()
}
