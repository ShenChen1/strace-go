package cli

import "testing"

func TestParseRunAsUser(t *testing.T) {
	for _, args := range [][]string{
		{"-u", "nobody", "/bin/true"},
		{"-unobody", "/bin/true"},
		{"--user=1000:1001", "/bin/true"},
		{"--user", "nobody", "/bin/true"},
	} {
		opts := ParseArgs(args)
		if opts.RunAsUser == "" {
			t.Fatalf("ParseArgs(%q) RunAsUser is empty", args)
		}
	}
}
