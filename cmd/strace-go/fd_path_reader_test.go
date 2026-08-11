package main

import "fmt"

type testFDPathReader struct {
	paths map[string]string
}

func (reader testFDPathReader) Path(pid int, fd int32) (string, bool) {
	path, ok := reader.paths[fmt.Sprintf("%d:%d", pid, fd)]
	return path, ok
}

func (reader testFDPathReader) Cwd(pid int) (string, bool) {
	path, ok := reader.paths[fmt.Sprintf("%d:cwd", pid)]
	return path, ok
}
