package main

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

type ArgXlatMap struct {
	Syscalls map[string]map[string]string `yaml:"syscalls"`
}

func main() {
	argXlat := readArgXlatMap()
	out := createXlatOutput()
	writeXlatAutoFile(out, argXlat, "../../strace-upstream/src/xlat")
	if err := out.Close(); err != nil {
		panic(fmt.Sprintf("failed to close ../../pkg/meta/xlat_auto.go: %v", err))
	}
}

func readArgXlatMap() ArgXlatMap {
	data, err := os.ReadFile("arg_xlat_map.yaml")
	if err != nil {
		data, err = os.ReadFile("../generate-xlats/arg_xlat_map.yaml")
		if err != nil {
			panic(fmt.Sprintf("failed to read arg_xlat_map.yaml: %v", err))
		}
	}
	var argXlat ArgXlatMap
	if err := yaml.Unmarshal(data, &argXlat); err != nil {
		panic(fmt.Sprintf("Failed to unmarshal YAML: %v", err))
	}
	return argXlat
}

func createXlatOutput() *os.File {
	out, err := os.Create("../../pkg/meta/xlat_auto.go")
	if err != nil {
		panic(fmt.Sprintf("failed to create ../../pkg/meta/xlat_auto.go: %v", err))
	}
	return out
}
