package main

import "strace-go/pkg/handler"

type traceSession struct {
	dependencies traceSessionDeps
	eventPolicy  *cliTraceEventPolicy
	components   *traceSessionComponents
}

func (s *traceSession) runtimeService() handler.RuntimeServices {
	if s == nil {
		return nil
	}
	return s.dependencies.Runtime
}
