package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type CaptureRule struct {
	Syscalls []string     `yaml:"syscalls"`
	Enter    CapturePoint `yaml:"enter"`
	Exit     CapturePoint `yaml:"exit"`
}

type CapturePoint struct {
	PtrArg *int          `yaml:"ptr_arg"`
	Reads  []CaptureRead `yaml:"reads"`
}

type CaptureRead struct {
	Arg    int    `yaml:"arg"`
	Size   int    `yaml:"size"`
	Offset int    `yaml:"offset"`
	Type   string `yaml:"type"`
}

type Config struct {
	Rules []CaptureRule `yaml:"rules"`
}

var globalConfig Config

func loadCapturePolicy(path string) error {
	configData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(configData, &globalConfig); err != nil {
		return fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return nil
}
