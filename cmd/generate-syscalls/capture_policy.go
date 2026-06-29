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
	PtrArg   *int             `yaml:"ptr_arg"`
	Reads    []CaptureRead    `yaml:"reads"`
	Payloads []CapturePayload `yaml:"payloads"`
}

type CaptureRead struct {
	Arg          int    `yaml:"arg"`
	Size         int    `yaml:"size"`
	Offset       int    `yaml:"offset"`
	Type         string `yaml:"type"`
	Max          int    `yaml:"-"`
	LenFromArg   *int   `yaml:"-"`
	LenFromRet   bool   `yaml:"-"`
	CountFromArg *int   `yaml:"-"`
	ElemSize     int    `yaml:"-"`
}

type CapturePayload struct {
	Arg          int    `yaml:"arg"`
	Kind         string `yaml:"kind"`
	Direction    string `yaml:"direction"`
	Offset       int    `yaml:"offset"`
	Max          int    `yaml:"max"`
	LenFromArg   *int   `yaml:"len_from_arg"`
	LenFromRet   bool   `yaml:"len_from_ret"`
	CountFromArg *int   `yaml:"count_from_arg"`
	ElemSize     int    `yaml:"elem_size"`
	Size         int    `yaml:"size"`
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
	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return fmt.Errorf("unmarshal %s: %w", path, err)
	}
	if err := normalizeCapturePolicy(&config); err != nil {
		return fmt.Errorf("normalize %s: %w", path, err)
	}
	globalConfig = config
	return nil
}

func normalizeCapturePolicy(config *Config) error {
	for i := range config.Rules {
		rule := &config.Rules[i]
		scope := fmt.Sprintf("rule %d (%v)", i, rule.Syscalls)
		enter, err := normalizeCapturePoint(rule.Enter, scope+".enter")
		if err != nil {
			return err
		}
		exit, err := normalizeCapturePoint(rule.Exit, scope+".exit")
		if err != nil {
			return err
		}
		rule.Enter = enter
		rule.Exit = exit
	}
	return nil
}

func normalizeCapturePoint(point CapturePoint, scope string) (CapturePoint, error) {
	if len(point.Payloads) == 0 {
		return point, nil
	}
	if len(point.Reads) != 0 {
		return CapturePoint{}, fmt.Errorf("%s cannot mix reads and payloads", scope)
	}
	reads := make([]CaptureRead, 0, len(point.Payloads))
	for i, payload := range point.Payloads {
		read, err := payload.toCaptureRead()
		if err != nil {
			return CapturePoint{}, fmt.Errorf("%s payload %d: %w", scope, i, err)
		}
		reads = append(reads, read)
	}
	point.Reads = reads
	return point, nil
}

func (p CapturePayload) toCaptureRead() (CaptureRead, error) {
	if p.Arg < 0 {
		return CaptureRead{}, fmt.Errorf("arg must be non-negative")
	}
	if p.Offset < 0 {
		return CaptureRead{}, fmt.Errorf("offset must be non-negative")
	}
	if p.Max < 0 {
		return CaptureRead{}, fmt.Errorf("max must be non-negative")
	}
	if p.Size < 0 {
		return CaptureRead{}, fmt.Errorf("size must be non-negative")
	}
	if p.ElemSize < 0 {
		return CaptureRead{}, fmt.Errorf("elem_size must be non-negative")
	}
	if p.LenFromArg != nil && *p.LenFromArg < 0 {
		return CaptureRead{}, fmt.Errorf("len_from_arg must be non-negative")
	}
	if p.CountFromArg != nil && *p.CountFromArg < 0 {
		return CaptureRead{}, fmt.Errorf("count_from_arg must be non-negative")
	}
	if p.LenFromArg != nil && p.LenFromRet {
		return CaptureRead{}, fmt.Errorf("len_from_arg and len_from_ret are mutually exclusive")
	}
	if p.CountFromArg != nil && (p.LenFromArg != nil || p.LenFromRet) {
		return CaptureRead{}, fmt.Errorf("count_from_arg cannot be combined with len_from_arg or len_from_ret")
	}
	if p.CountFromArg != nil && p.ElemSize == 0 {
		return CaptureRead{}, fmt.Errorf("count_from_arg requires elem_size")
	}
	if (p.LenFromArg != nil || p.LenFromRet || p.CountFromArg != nil) && p.Max == 0 {
		return CaptureRead{}, fmt.Errorf("dynamic payload length requires max")
	}
	if p.Direction != "" && p.Direction != "in" && p.Direction != "out" {
		return CaptureRead{}, fmt.Errorf("unsupported direction %q", p.Direction)
	}
	readType, err := payloadReadType(p.Kind)
	if err != nil {
		return CaptureRead{}, err
	}
	size := p.Size
	if p.LenFromArg != nil || p.LenFromRet || p.CountFromArg != nil {
		size = 0
	} else if size == 0 {
		size = p.Max
	}
	return CaptureRead{
		Arg:          p.Arg,
		Size:         size,
		Offset:       p.Offset,
		Type:         readType,
		Max:          p.Max,
		LenFromArg:   p.LenFromArg,
		LenFromRet:   p.LenFromRet,
		CountFromArg: p.CountFromArg,
		ElemSize:     p.ElemSize,
	}, nil
}

func payloadReadType(kind string) (string, error) {
	switch kind {
	case "string":
		return "string", nil
	case "bytes", "raw", "struct", "iovec":
		return "raw", nil
	case "double_ptr":
		return "double_ptr", nil
	default:
		return "", fmt.Errorf("unsupported kind %q", kind)
	}
}
