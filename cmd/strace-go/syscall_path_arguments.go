package main

import (
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func syscallHasPathArg(scMeta meta.Syscall) bool {
	if scMeta.Name == "fsconfig" {
		return true
	}
	for _, argName := range scMeta.Args {
		switch argName {
		case "filename", "pathname", "path", "oldname", "newname", "oldpath", "newpath",
			"from_pathname", "to_pathname", "fs_name":
			return true
		}
	}
	return false
}

func decodePathArguments(
	deps syscallEventContextDeps,
	view syscallEventView,
	scMeta meta.Syscall,
	payloadSections []handler.PayloadSection,
) []event.PathArgument {
	indices := pathFilterArgIndices(scMeta.Name, view.args)
	if len(indices) == 0 && syscallHasPathArg(scMeta) {
		if index, ok := primaryPathArgIndex(scMeta); ok {
			indices = []int{index}
		}
	}
	paths := make([]event.PathArgument, 0, len(indices))
	for _, index := range indices {
		if index < 0 || index >= len(scMeta.Args) || index >= len(view.args) {
			continue
		}
		text := pathArgumentText(deps, view, scMeta, payloadSections, index)
		paths = append(paths, event.PathArgument{
			Text:  text,
			DirFD: pathArgumentDirFD(scMeta, view.args, index),
		})
	}
	return paths
}

func pathArgumentText(
	deps syscallEventContextDeps,
	view syscallEventView,
	scMeta meta.Syscall,
	payloadSections []handler.PayloadSection,
	argIndex int,
) string {
	if text, ok := stringPayloadSectionText(deps, view, scMeta, payloadSections, argIndex); ok {
		return text
	}
	return deps.decoder.DecodeString(int(view.tid), view.args[argIndex], nil, -1, scMeta.Name, 0)
}

func pathFilterArgIndices(scName string, args [6]uint64) []int {
	switch scName {
	case "move_mount", "renameat", "renameat2", "linkat":
		return []int{1, 3}
	case "rename", "link", "mount", "pivot_root":
		return []int{0, 1}
	case "symlink":
		return []int{1}
	case "symlinkat":
		return []int{2}
	case "fsconfig":
		if uint32(args[1]) == 3 || uint32(args[1]) == 4 {
			return []int{3}
		}
		return nil
	default:
		if index, ok := simplePathPayloadArgIndex(scName); ok {
			return []int{index}
		}
		return nil
	}
}

func pathArgumentDirFD(scMeta meta.Syscall, args [6]uint64, pathIndex int) int32 {
	if scMeta.Name == "fsconfig" {
		return int32(args[4])
	}
	if pathIndex > 0 && pathIndex-1 < len(scMeta.Args) && isFdArgName(scMeta.Args[pathIndex-1]) {
		return int32(args[pathIndex-1])
	}
	return handler.AtFdcwd
}

func primaryPathText(paths []event.PathArgument) string {
	if len(paths) == 0 {
		return ""
	}
	return paths[0].Text
}

func stringPayloadSectionText(
	deps syscallEventContextDeps,
	view syscallEventView,
	scMeta meta.Syscall,
	payloadSections []handler.PayloadSection,
	argIndex int,
) (string, bool) {
	for _, section := range payloadSections {
		if section.Kind == handler.PayloadKindString &&
			section.Direction == handler.PayloadDirectionIn &&
			section.ArgIndex == argIndex &&
			section.ProbeRet == 0 && len(section.Data) > 0 {
			return deps.decoder.DecodeString(
				int(view.tid), section.UserPtr, section.Data, section.ProbeRet, scMeta.Name, 0,
			), true
		}
	}
	return "", false
}
