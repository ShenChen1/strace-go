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
	var registry handler.RegistryPort
	var handlerDispatch handler.HandlerDispatchPort
	if s.components != nil {
		registry = s.components.handlerRegistry
		handlerDispatch = s.components.handlerDispatch
	}
	deps := s.dependencies.eventContextDependencies(registry)
	deps.handlerDispatch = handlerDispatch
	return deps
}

func (deps traceSessionDeps) eventContextDependencies(registry handler.RegistryPort) syscallEventContextDeps {
	contextDeps := syscallEventContextDeps{
		decoder:  deps.Decoder,
		catalog:  deps.Catalog,
		fdState:  deps.FDState,
		fdPath:   deps.FDState,
		registry: registry,
		runtime:  deps.Runtime,
	}
	if deps.EventPolicy != nil {
		contextDeps.handlerOpts = deps.EventPolicy.HandlerOptions()
		contextDeps.filter = deps.EventPolicy.FilterOptions()
	}
	return contextDeps
}
