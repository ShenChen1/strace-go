package event

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

type testEventFDPathReader struct {
	paths map[int32]string
	cwd   string
}

func (reader testEventFDPathReader) Path(fd int32) (string, bool) {
	path, ok := reader.paths[fd]
	return path, ok
}

func (reader testEventFDPathReader) Cwd() (string, bool) {
	return reader.cwd, reader.cwd != ""
}
