package main

import "testing"

func TestArchitectureCapabilities(t *testing.T) {
	for _, tc := range []struct {
		target       string
		kvm, allowed bool
	}{
		{"amd64", true, true}, {"arm64", false, true}, {"arm64", true, false}, {"riscv64", false, false},
	} {
		if err := validateArchitectureCapabilities(tc.target, tc.kvm); (err == nil) != tc.allowed {
			t.Fatalf("capabilities(%s, %v) = %v", tc.target, tc.kvm, err)
		}
	}
}
