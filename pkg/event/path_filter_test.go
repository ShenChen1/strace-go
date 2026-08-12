package event

import "testing"

type fakePathFilter struct {
	paths map[string]bool
}

func (filter fakePathFilter) Empty() bool {
	return len(filter.paths) == 0
}

func (filter fakePathFilter) Matches(path string) bool {
	return filter.paths[path]
}

var _ PathFilter = fakePathFilter{}

func TestMatchPathConsumesPathFilterPort(t *testing.T) {
	req := PathMatchRequest{
		PathArguments: []PathArgument{{Text: `"/tmp/input"`, DirFD: -100}},
		TracePaths:    fakePathFilter{paths: map[string]bool{"/tmp/input": true}},
	}
	if !MatchPath(req) {
		t.Fatal("path match rejected an injected PathFilter")
	}

	req.TracePaths = fakePathFilter{paths: map[string]bool{"/tmp/other": true}}
	if MatchPath(req) {
		t.Fatal("path match accepted a nonmatching injected PathFilter")
	}
}

func TestTracePathSetMatchesQuotedDescendant(t *testing.T) {
	filter := TracePathSet{"/tmp": true}
	if filter.Empty() || !filter.Matches(`"/tmp/input"`) {
		t.Fatal("TracePathSet did not normalize a quoted descendant path")
	}
}
