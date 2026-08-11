package main

import (
	"fmt"
	"path/filepath"
)

type fdStateSeed struct {
	paths map[string]string
}

func newFDStateSeed(paths map[string]string) fdStateSeed {
	return fdStateSeed{paths: copyFDStatePaths(paths)}
}

func newCwdFDStateSeed(targetPID int, cwd string) fdStateSeed {
	if targetPID <= 0 || cwd == "" {
		return fdStateSeed{}
	}
	cleaned := filepath.Clean(cwd)
	if !filepath.IsAbs(cleaned) {
		return fdStateSeed{}
	}
	return newFDStateSeed(map[string]string{
		fmt.Sprintf("%d:cwd", targetPID): cleaned,
	})
}

func (seed *fdStateSeed) merge(other fdStateSeed) {
	if seed == nil || len(other.paths) == 0 {
		return
	}
	if seed.paths == nil {
		seed.paths = make(map[string]string, len(other.paths))
	}
	for key, path := range other.paths {
		seed.paths[key] = path
	}
}

func copyFDStatePaths(paths map[string]string) map[string]string {
	if len(paths) == 0 {
		return nil
	}
	copy := make(map[string]string, len(paths))
	for key, path := range paths {
		copy[key] = path
	}
	return copy
}
