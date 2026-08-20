package main

import "strace-go/pkg/handler"

// handlerContextRecycler owns one reusable context for the single event consumer.
type handlerContextRecycler struct {
	cached *handler.Context
}

func newHandlerContextRecycler() *handlerContextRecycler {
	return &handlerContextRecycler{}
}

func (r *handlerContextRecycler) acquire() *handler.Context {
	if r == nil || r.cached == nil {
		return &handler.Context{}
	}
	context := r.cached
	r.cached = nil
	return context
}

func (r *handlerContextRecycler) release(context *handler.Context) {
	if r == nil || context == nil {
		return
	}
	*context = handler.Context{}
	r.cached = context
}
