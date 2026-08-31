package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const pidNamespaceMaxLevel = 32

type pidNamespaceConfig struct {
	Nonce uint32
	Level uint32
	Inum  uint32
	Ready uint32
}

func newPIDNamespaceNonce() (uint32, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, fmt.Errorf("generate PID namespace handshake nonce: %w", err)
	}
	return binary.LittleEndian.Uint32(raw[:]) | 1<<31, nil
}

func configurePIDNamespaceIdentity(config traceBPFConfig, maps bpfMapProvider) error {
	if !config.decodePIDsPIDNS {
		return nil
	}
	if maps == nil {
		return fmt.Errorf("BPF PID namespace config map is unavailable")
	}
	configMap := maps.coreMap(bpfMapPIDNamespaceConfig)
	if configMap == nil {
		return fmt.Errorf("BPF PID namespace config map is unavailable")
	}
	nonce, err := newPIDNamespaceNonce()
	if err != nil {
		return err
	}
	request := pidNamespaceConfig{Nonce: nonce}
	if err := configMap.Update(uint32(0), request, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("arm BPF PID namespace handshake: %w", err)
	}
	_, _ = unix.Getpgid(int(int32(nonce)))

	var observed pidNamespaceConfig
	if err := configMap.Lookup(uint32(0), &observed); err != nil {
		return fmt.Errorf("read BPF PID namespace handshake: %w", err)
	}
	if observed.Ready != 1 || observed.Inum == 0 || observed.Level > pidNamespaceMaxLevel {
		return fmt.Errorf("BPF PID namespace handshake did not capture tracer identity")
	}
	return nil
}
