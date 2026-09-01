package cli

import "testing"

func TestParseVersionVerbosity(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "short", args: []string{"-V"}, want: 1},
		{name: "long", args: []string{"--version"}, want: 1},
		{name: "cluster", args: []string{"-VVVV"}, want: 4},
		{name: "repeated clusters", args: []string{"-VVVV", "-VVVV", "-VVVV", "-VVVV"}, want: 16},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := ParseArgs(test.args)
			if opts.VersionLevel != test.want {
				t.Fatalf("VersionLevel = %d, want %d", opts.VersionLevel, test.want)
			}
		})
	}
}
