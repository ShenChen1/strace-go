package main

import (
	"fmt"
	"io"
)

// bpfResourceOwner holds named resources until setup transfers or closes them.
// Ownership moves by slice transfer; no concurrent mutation is permitted.
type bpfResourceOwner struct {
	resources []traceBPFResource
}

func (o *bpfResourceOwner) add(name string, closer io.Closer) {
	if o == nil || name == "" || closer == nil {
		return
	}
	o.resources = append(o.resources, traceBPFResource{Name: name, Closer: closer})
}

func (o *bpfResourceOwner) addGroup(prefix string, closers []io.Closer) {
	if o == nil || prefix == "" {
		return
	}
	for index, closer := range closers {
		o.add(fmt.Sprintf("%s_%d", prefix, index), closer)
	}
}

func (o *bpfResourceOwner) transfer() bpfResourceOwner {
	if o == nil {
		return bpfResourceOwner{}
	}
	transferred := bpfResourceOwner{resources: o.resources}
	o.resources = nil
	return transferred
}

func (o *bpfResourceOwner) take() []traceBPFResource {
	return o.transfer().resources
}

func (o *bpfResourceOwner) close() error {
	return closeNamedBPFResourcesParallel(o.take(), nil, nil)
}
