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
	Arg                int    `yaml:"arg"`
	Size               int    `yaml:"size"`
	Offset             int    `yaml:"offset"`
	Type               string `yaml:"type"`
	Min                int    `yaml:"-"`
	Max                int    `yaml:"-"`
	LenFromArg         *int   `yaml:"-"`
	LenFromRet         bool   `yaml:"-"`
	LenFromUserArg     *int   `yaml:"-"`
	LenFromArgBits     *ArgBitsLength
	LenFromArgCases    *ArgCasesLength
	StringBytesSwitch  *StringBytesSwitch
	ClampU32FromOffset *int `yaml:"-"`
	CountFromArg       *int `yaml:"-"`
	CountFromRet       bool `yaml:"-"`
	ElemSize           int  `yaml:"-"`
	SplitFirst         int  `yaml:"-"`
}

type CapturePayload struct {
	Arg                int                `yaml:"arg"`
	Kind               string             `yaml:"kind"`
	Direction          string             `yaml:"direction"`
	Offset             int                `yaml:"offset"`
	Min                int                `yaml:"min"`
	Max                int                `yaml:"max"`
	LenFromArg         *int               `yaml:"len_from_arg"`
	LenFromRet         bool               `yaml:"len_from_ret"`
	LenFromUserArg     *int               `yaml:"len_from_user_arg"`
	LenFromArgBits     *ArgBitsLength     `yaml:"len_from_arg_bits"`
	LenFromArgCases    *ArgCasesLength    `yaml:"len_from_arg_cases"`
	StringBytesSwitch  *StringBytesSwitch `yaml:"string_bytes_switch"`
	ClampU32FromOffset *int               `yaml:"clamp_u32_from_offset"`
	CountFromArg       *int               `yaml:"count_from_arg"`
	CountFromRet       bool               `yaml:"count_from_ret"`
	ElemSize           int                `yaml:"elem_size"`
	SplitFirst         int                `yaml:"split_first"`
	Size               int                `yaml:"size"`
}

type ArgBitsLength struct {
	Arg     int `yaml:"arg"`
	Shift   int `yaml:"shift"`
	Mask    int `yaml:"mask"`
	ZeroLen int `yaml:"zero_len"`
}

type ArgCasesLength struct {
	Arg   int             `yaml:"arg"`
	Cases []ArgLengthCase `yaml:"cases"`
}

type ArgLengthCase struct {
	Size   int   `yaml:"size"`
	Values []int `yaml:"values"`
}

type StringBytesSwitch struct {
	SelectorArg int `yaml:"selector_arg"`
	BytesValue  int `yaml:"bytes_value"`
	LenFromArg  int `yaml:"len_from_arg"`
	LenMask     int `yaml:"len_mask"`
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
	if p.Min < 0 {
		return CaptureRead{}, fmt.Errorf("min must be non-negative")
	}
	if p.Max < 0 {
		return CaptureRead{}, fmt.Errorf("max must be non-negative")
	}
	if p.Max > 0 && p.Min > p.Max {
		return CaptureRead{}, fmt.Errorf("min must not exceed max")
	}
	if p.Size < 0 {
		return CaptureRead{}, fmt.Errorf("size must be non-negative")
	}
	if p.ElemSize < 0 {
		return CaptureRead{}, fmt.Errorf("elem_size must be non-negative")
	}
	if p.SplitFirst < 0 {
		return CaptureRead{}, fmt.Errorf("split_first must be non-negative")
	}
	if p.LenFromArg != nil && *p.LenFromArg < 0 {
		return CaptureRead{}, fmt.Errorf("len_from_arg must be non-negative")
	}
	if p.LenFromUserArg != nil && *p.LenFromUserArg < 0 {
		return CaptureRead{}, fmt.Errorf("len_from_user_arg must be non-negative")
	}
	if err := p.LenFromArgBits.validate(); err != nil {
		return CaptureRead{}, err
	}
	if err := p.LenFromArgCases.validate(); err != nil {
		return CaptureRead{}, err
	}
	if err := p.StringBytesSwitch.validate(); err != nil {
		return CaptureRead{}, err
	}
	if p.ClampU32FromOffset != nil && *p.ClampU32FromOffset < 0 {
		return CaptureRead{}, fmt.Errorf("clamp_u32_from_offset must be non-negative")
	}
	if p.CountFromArg != nil && *p.CountFromArg < 0 {
		return CaptureRead{}, fmt.Errorf("count_from_arg must be non-negative")
	}
	dynamicSources := 0
	for _, enabled := range []bool{p.LenFromArg != nil, p.LenFromRet, p.LenFromUserArg != nil, p.LenFromArgBits != nil, p.LenFromArgCases != nil, p.StringBytesSwitch != nil, p.CountFromArg != nil, p.CountFromRet} {
		if enabled {
			dynamicSources++
		}
	}
	if dynamicSources > 1 {
		return CaptureRead{}, fmt.Errorf("dynamic payload length sources are mutually exclusive")
	}
	if p.ClampU32FromOffset != nil && p.LenFromUserArg == nil {
		return CaptureRead{}, fmt.Errorf("clamp_u32_from_offset requires len_from_user_arg")
	}
	if p.CountFromArg != nil && p.ElemSize == 0 {
		return CaptureRead{}, fmt.Errorf("count_from_arg requires elem_size")
	}
	if p.SplitFirst > 0 && p.CountFromArg == nil {
		return CaptureRead{}, fmt.Errorf("split_first requires count_from_arg")
	}
	if p.SplitFirst > 0 && p.ElemSize > 0 && p.SplitFirst > p.ElemSize {
		return CaptureRead{}, fmt.Errorf("split_first must not exceed elem_size")
	}
	if p.SplitFirst > 0 && p.Max > 0 && p.ElemSize > 0 && p.Max < p.ElemSize {
		return CaptureRead{}, fmt.Errorf("split_first requires max to cover at least one element")
	}
	if p.SplitFirst > 0 && p.Max > 0 && p.SplitFirst > p.Max {
		return CaptureRead{}, fmt.Errorf("split_first must not exceed max")
	}
	if p.CountFromRet && p.ElemSize == 0 {
		return CaptureRead{}, fmt.Errorf("count_from_ret requires elem_size")
	}
	if dynamicSources > 0 && p.Max == 0 {
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
	if dynamicSources > 0 {
		size = 0
	} else if size == 0 {
		size = p.Max
	}
	return CaptureRead{
		Arg:                p.Arg,
		Size:               size,
		Offset:             p.Offset,
		Type:               readType,
		Min:                p.Min,
		Max:                p.Max,
		LenFromArg:         p.LenFromArg,
		LenFromRet:         p.LenFromRet,
		LenFromUserArg:     p.LenFromUserArg,
		LenFromArgBits:     p.LenFromArgBits,
		LenFromArgCases:    p.LenFromArgCases,
		StringBytesSwitch:  p.StringBytesSwitch,
		ClampU32FromOffset: p.ClampU32FromOffset,
		CountFromArg:       p.CountFromArg,
		CountFromRet:       p.CountFromRet,
		ElemSize:           p.ElemSize,
		SplitFirst:         p.SplitFirst,
	}, nil
}

func (p *ArgBitsLength) validate() error {
	if p == nil {
		return nil
	}
	if p.Arg < 0 {
		return fmt.Errorf("len_from_arg_bits.arg must be non-negative")
	}
	if p.Shift < 0 {
		return fmt.Errorf("len_from_arg_bits.shift must be non-negative")
	}
	if p.Mask <= 0 {
		return fmt.Errorf("len_from_arg_bits.mask must be positive")
	}
	if p.ZeroLen < 0 {
		return fmt.Errorf("len_from_arg_bits.zero_len must be non-negative")
	}
	return nil
}

func (p *ArgCasesLength) validate() error {
	if p == nil {
		return nil
	}
	if p.Arg < 0 {
		return fmt.Errorf("len_from_arg_cases.arg must be non-negative")
	}
	if len(p.Cases) == 0 {
		return fmt.Errorf("len_from_arg_cases.cases must not be empty")
	}
	for i, c := range p.Cases {
		if c.Size <= 0 {
			return fmt.Errorf("len_from_arg_cases.cases[%d].size must be positive", i)
		}
		if len(c.Values) == 0 {
			return fmt.Errorf("len_from_arg_cases.cases[%d].values must not be empty", i)
		}
		for j, v := range c.Values {
			if v < 0 {
				return fmt.Errorf("len_from_arg_cases.cases[%d].values[%d] must be non-negative", i, j)
			}
		}
	}
	return nil
}

func (p *StringBytesSwitch) validate() error {
	if p == nil {
		return nil
	}
	if p.SelectorArg < 0 {
		return fmt.Errorf("string_bytes_switch.selector_arg must be non-negative")
	}
	if p.BytesValue < 0 {
		return fmt.Errorf("string_bytes_switch.bytes_value must be non-negative")
	}
	if p.LenFromArg < 0 {
		return fmt.Errorf("string_bytes_switch.len_from_arg must be non-negative")
	}
	if p.LenMask < 0 {
		return fmt.Errorf("string_bytes_switch.len_mask must be non-negative")
	}
	return nil
}

func payloadReadType(kind string) (string, error) {
	switch kind {
	case "string":
		return "string", nil
	case "bytes", "raw", "struct", "iovec", "string_or_bytes":
		return "raw", nil
	case "double_ptr":
		return "double_ptr", nil
	default:
		return "", fmt.Errorf("unsupported kind %q", kind)
	}
}
