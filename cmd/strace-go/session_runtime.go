package main

import "strace-go/pkg/handler"

func (s *traceSession) runtimeService() handler.RuntimeServices {
	if s == nil {
		return nil
	}
	return s.runtime
}
