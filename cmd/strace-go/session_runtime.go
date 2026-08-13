package main

import "strace-go/pkg/handler"

type traceSession struct {
	dependencies traceSessionDeps
	components   *traceSessionComponents
}

func (s *traceSession) runtimeService() handler.RuntimeServices {
	if s == nil {
		return nil
	}
	return s.dependencies.Runtime
}

func (s *traceSession) eventContextDependencies() syscallEventContextDeps {
	if s == nil {
		return syscallEventContextDeps{}
	}
	deps := s.dependencies
	contextDeps := syscallEventContextDeps{
		decoder: deps.Decoder,
		catalog: deps.Catalog,
		fdState: deps.FDState,
		fdPath:  deps.FDState,
		runtime: deps.Runtime,
	}
	if s.components != nil {
		contextDeps.registry = s.components.handlerRegistry
	}
	if deps.EventPolicy != nil {
		contextDeps.handlerOpts = deps.EventPolicy.HandlerOptions()
		contextDeps.filter = deps.EventPolicy.FilterOptions()
	}
	return contextDeps
}
