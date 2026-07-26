package main

const (
	// payloadEnterArgOffset is the fixed-buffer window for syscall-enter payload snapshots.
	payloadEnterArgOffset = 0
	// payloadMiscArgOffset is the fixed-buffer window for secondary payload snapshots.
	payloadMiscArgOffset = 512
	// payloadExitArgOffset is the fixed-buffer window for syscall-exit payload snapshots.
	payloadExitArgOffset = 1024
)
