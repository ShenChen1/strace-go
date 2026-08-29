package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestRunOrchestratorConsumesLaunchSnapshot(t *testing.T) {
	root := repoRootForTest(t)
	mainSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/main.go"))
	for _, forbidden := range []string{
		"func runTraceSession(opts *cli.Options",
		"func resolveTraceTargets(opts *cli.Options",
		"func abortTraceTargets(opts *cli.Options",
		"func traceTargetPIDs(opts *cli.Options",
	} {
		if strings.Contains(mainSource, forbidden) {
			t.Fatalf("run bootstrap still consumes CLI options directly: %q", forbidden)
		}
	}
	launchSource := readTextFile(t, filepath.Join(root, "cmd/strace-go/launch_config.go"))
	if !strings.Contains(launchSource, "type traceLaunchConfig struct") ||
		!strings.Contains(launchSource, "type traceTargetConfig struct") {
		t.Fatal("launch snapshot types are missing")
	}
	if !strings.Contains(mainSource, "config := newTraceLaunchConfig(opts)") ||
		!strings.Contains(mainSource, "runTraceSession(config, systemTraceClock{})") {
		t.Fatal("runMain must form launch snapshot before run orchestration")
	}
}

func TestNewTraceLaunchConfigSnapshotsBootstrapInputs(t *testing.T) {
	opts := cli.ParseArgs([]string{"-f", "/bin/true", "original"})
	opts.EnvActions = []string{"TRACE=original"}
	opts.Argv0 = "original-argv0"
	opts.Argv0Set = true
	opts.KillOnExit = true
	opts.RunAsUser = "1000:1001"
	opts.AttachPids = []int{101, 202}
	opts.OutFile = "/tmp/original.trace"
	opts.OutAppendMode = true
	opts.OutputSeparate = true
	opts.TipsMode = cli.TipsModeFull
	opts.TipsID = 7
	config := newTraceLaunchConfig(opts)
	if config == nil {
		t.Fatal("newTraceLaunchConfig() returned nil for non-nil options")
	}

	opts.CmdArgs[1] = "mutated"
	opts.EnvActions[0] = "TRACE=mutated"
	opts.Argv0 = "mutated-argv0"
	opts.AttachPids[0] = 303
	opts.OutFile = "/tmp/mutated.trace"
	opts.OutAppendMode = false
	opts.OutputSeparate = false
	opts.TipsMode = cli.TipsModeNone
	opts.TipsID = 9

	if config.targets.command.args[1] != "original" || config.targets.command.envActions[0] != "TRACE=original" ||
		config.targets.command.argv0 != "original-argv0" || !config.targets.command.argv0Set || !config.targets.command.killOnExit ||
		config.targets.command.runAsUser != "1000:1001" {
		t.Fatalf("launch command snapshot aliases CLI slices: %+v", config.targets.command)
	}
	if config.targets.attachPIDs[0] != 101 || config.outputPath != "/tmp/original.trace" ||
		!config.outputAppend || !config.outputSeparate {
		t.Fatalf("launch scalar/slice snapshot changed after CLI mutation: %+v", config)
	}
	if config.tipsMode != cli.TipsModeFull || config.tipsID != 7 {
		t.Fatalf("launch tips snapshot changed after CLI mutation: %+v", config)
	}
}

func TestNewTraceLaunchConfigNilOptions(t *testing.T) {
	if config := newTraceLaunchConfig(nil); config != nil {
		t.Fatalf("nil options produced launch config: %+v", config)
	}
}
