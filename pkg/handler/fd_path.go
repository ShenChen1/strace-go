package handler

import "bytes"

// DecodeFDPathOnly decodes a probe-site path payload without interpreting a
// possible FD_STATE prefix. CWD sections always use this wire form.
func DecodeFDPathOnly(data []byte) (string, bool) {
	return decodeFDPathText(data)
}

// DecodeFDPathSnapshot decodes the bounded path payload emitted at sys_enter.
// The state prefix is optional so a path remains useful when inode reads fail.
func DecodeFDPathSnapshot(data []byte) (FDPathSnapshot, bool) {
	pathData := data
	var snapshot FDPathSnapshot
	if len(data) >= FDPathStatePrefixSize {
		observation, ok := DecodeFDStateObservation(data[:FDPathStatePrefixSize])
		if ok && observation.FD >= 0 && observation.Flags&^(FDStateFlagIdentity|FDStateFlagOffset) == 0 {
			snapshot.Observation = observation
			snapshot.HasObservation = true
			pathData = data[FDPathStatePrefixSize:]
		}
	}
	path, ok := decodeFDPathText(pathData)
	if !ok {
		return snapshot, false
	}
	snapshot.Path = path
	return snapshot, true
}

func decodeFDPathText(data []byte) (string, bool) {
	data = bytes.TrimRight(data, "\x00")
	if len(data) == 0 {
		return "", false
	}
	return string(data), true
}
