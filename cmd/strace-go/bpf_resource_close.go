package main

import (
	"errors"
	"io"
	"sync"
)

// closeBPFResourcesParallel closes independent BPF resources concurrently.
// Each worker owns one error slot, so the event path and cleanup path need no mutex.
func closeBPFResourcesParallel(resources []io.Closer) error {
	if len(resources) == 0 {
		return nil
	}
	errs := make([]error, len(resources))
	var workers sync.WaitGroup
	workers.Add(len(resources))
	for index, resource := range resources {
		if resource == nil {
			workers.Done()
			continue
		}
		go func(index int, resource io.Closer) {
			defer workers.Done()
			errs[index] = resource.Close()
		}(index, resource)
	}
	workers.Wait()
	return errors.Join(errs...)
}
