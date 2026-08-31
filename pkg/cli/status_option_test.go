package cli

import "testing"

func TestParseStatusSetSupportsComplements(t *testing.T) {
	tests := []struct {
		value string
		want  map[string]bool
	}{
		{value: "!unavailable", want: map[string]bool{"successful": true, "failed": true, "unfinished": true, "detached": true}},
		{value: "successful,failed", want: map[string]bool{"successful": true, "failed": true}},
		{value: "all", want: map[string]bool{"successful": true, "failed": true, "unfinished": true, "unavailable": true, "detached": true}},
		{value: "!all", want: map[string]bool{}},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			opts := ParseArgs([]string{"--status=" + tt.value, "/bin/true"})
			if len(opts.TraceStatus) != len(tt.want) {
				t.Fatalf("status set = %v, want %v", opts.TraceStatus, tt.want)
			}
			for status := range tt.want {
				if !opts.TraceStatus[status] {
					t.Fatalf("status set = %v, missing %q", opts.TraceStatus, status)
				}
			}
		})
	}
}
