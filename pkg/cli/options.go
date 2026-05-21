// Package cli parses command-line arguments for strace-go,
// supporting the same flags as the original strace.
package cli

import (
	"fmt"
	"strings"
)

// Options holds all parsed command-line options.
type Options struct {
	CmdArgs       []string
	OutFile       string
	AlignCol      int
	StringLimit   int
	TraceSyscalls map[string]bool
	TracePaths    map[string]bool
	TraceReadFDs  map[int32]bool
	TraceWriteFDs map[int32]bool
	ShowPaths     bool
	Verbose       bool
}

// ParseArgs parses strace-go command-line arguments and returns Options.
// args should be os.Args[1:].
func ParseArgs(args []string) *Options {
	opts := &Options{
		AlignCol:      40,
		StringLimit:   32,
		TraceSyscalls: make(map[string]bool),
		TracePaths:    make(map[string]bool),
		TraceReadFDs:  make(map[int32]bool),
		TraceWriteFDs: make(map[int32]bool),
		ShowPaths:     false,
		Verbose:       false,
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]; val := ""; hasVal := false
		if strings.HasPrefix(arg, "-v") && len(arg) > 2 {
			opts.Verbose = true
			arg = "-" + arg[2:]
		}
		if arg == "-y" {
			opts.ShowPaths = true
			continue
		}
		if arg == "-v" {
			opts.Verbose = true
			continue
		}
		if strings.HasPrefix(arg, "--trace=") {
			val = strings.TrimPrefix(arg, "--trace=")
			for _, s := range strings.Split(val, ",") {
				opts.TraceSyscalls[s] = true
			}
			continue
		}
		if strings.HasPrefix(arg, "-o") {
			if len(arg) > 2 { val = arg[2:]; hasVal = true } else if i+1 < len(args) { val = args[i+1]; i++; hasVal = true }
			if hasVal { opts.OutFile = val }
		} else if strings.HasPrefix(arg, "-a") {
			if len(arg) > 2 { val = arg[2:]; hasVal = true } else if i+1 < len(args) { val = args[i+1]; i++; hasVal = true }
			if hasVal { fmt.Sscanf(val, "%d", &opts.AlignCol) }
		} else if strings.HasPrefix(arg, "-s") {
			if len(arg) > 2 { val = arg[2:]; hasVal = true } else if i+1 < len(args) { val = args[i+1]; i++; hasVal = true }
			if hasVal { fmt.Sscanf(val, "%d", &opts.StringLimit) }
		} else if strings.HasPrefix(arg, "-P") {
			if len(arg) > 2 { val = arg[2:]; hasVal = true } else if i+1 < len(args) { val = args[i+1]; i++; hasVal = true }
			if hasVal { opts.TracePaths[val] = true }
		} else if strings.HasPrefix(arg, "--trace-path=") { opts.TracePaths[strings.TrimPrefix(arg, "--trace-path=")] = true
		} else if arg == "--trace-path" { if i+1 < len(args) { opts.TracePaths[args[i+1]] = true; i++ }
		} else if strings.HasPrefix(arg, "-e") {
			if len(arg) > 2 { val = arg[2:]; hasVal = true } else if i+1 < len(args) { val = args[i+1]; i++; hasVal = true }
			if hasVal {
				addT := func(s string) {
					opts.TraceSyscalls[s] = true
					if s == "access" { opts.TraceSyscalls["faccessat"] = true; opts.TraceSyscalls["faccessat2"] = true }
					if s == "stat" { opts.TraceSyscalls["newfstatat"] = true }
					if s == "lstat" { opts.TraceSyscalls["newfstatat"] = true }
					if s == "chmod" { opts.TraceSyscalls["chmodat"] = true }
					if s == "mkdir" { opts.TraceSyscalls["mkdirat"] = true }
					if s == "rename" { opts.TraceSyscalls["renameat"] = true; opts.TraceSyscalls["renameat2"] = true }
					if s == "chdir" { opts.TraceSyscalls["fchdir"] = true }
					if s == "chown" { opts.TraceSyscalls["fchown"] = true; opts.TraceSyscalls["lchown"] = true; opts.TraceSyscalls["fchownat"] = true }
				}
				if strings.HasPrefix(val, "trace=") {
					for _, s := range strings.Split(strings.TrimPrefix(val, "trace="), ",") { addT(s) }
				} else if strings.HasPrefix(val, "read=") {
					for _, s := range strings.Split(strings.TrimPrefix(val, "read="), ",") { var fd int32; if n, _ := fmt.Sscanf(s, "%d", &fd); n == 1 { opts.TraceReadFDs[fd] = true } }
				} else if strings.HasPrefix(val, "write=") {
					for _, s := range strings.Split(strings.TrimPrefix(val, "write="), ",") { var fd int32; if n, _ := fmt.Sscanf(s, "%d", &fd); n == 1 { opts.TraceWriteFDs[fd] = true } }
				} else {
					for _, s := range strings.Split(val, ",") { addT(s) }
				}
			}
		} else if !strings.HasPrefix(arg, "-") { opts.CmdArgs = args[i:]; break }
	}
	return opts
}
