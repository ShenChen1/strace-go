package main

import "strace-go/pkg/handler"

func (s *traceSession) runtimeService() handler.RuntimeServices {
	if s == nil {
		return nil
	}
	if s.runtime == nil {
		s.runtime = handler.NewRuntime()
	}
	return s.runtime
}
