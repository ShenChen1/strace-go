package cli

import "testing"

func TestParseShortOutputSeparatelyEnablesFollowForks(t *testing.T) {
	opts := ParseArgs([]string{"-ff", "-o", "trace", "/bin/true"})
	if !opts.FollowForks || !opts.OutputSeparate {
		t.Fatalf("-ff = follow:%v separate:%v", opts.FollowForks, opts.OutputSeparate)
	}
}

func TestParseLongOutputSeparatelyPreservesExplicitFollowForks(t *testing.T) {
	opts := ParseArgs([]string{"--follow-forks", "--output-separately", "-o", "trace", "/bin/true"})
	if !opts.FollowForks || !opts.OutputSeparate {
		t.Fatalf("long flags = follow:%v separate:%v", opts.FollowForks, opts.OutputSeparate)
	}
}
