package event

import "testing"

func TestMatchPathUsesEachPathArgumentDirFD(t *testing.T) {
	req := PathMatchRequest{
		Pid: 101,
		PathArguments: []PathArgument{
			{Text: `"source"`, DirFD: 3},
			{Text: `"target"`, DirFD: 4},
		},
		TracePaths: map[string]bool{"/to/target": true},
		FDState: testFDPathReader{paths: map[string]string{
			"101:3": "/from",
			"101:4": "/to",
		}},
	}

	if !MatchPath(req) {
		t.Fatal("second relative path did not use its own directory fd")
	}
}

func TestMatchPathDoesNotPairPathWithUnrelatedDirFD(t *testing.T) {
	req := PathMatchRequest{
		Pid: 101,
		PathArguments: []PathArgument{
			{Text: `"source"`, DirFD: 3},
			{Text: `"target"`, DirFD: 4},
		},
		TracePaths: map[string]bool{"/to/source": true},
		FDState: testFDPathReader{paths: map[string]string{
			"101:3": "/from",
			"101:4": "/to",
		}},
	}

	if MatchPath(req) {
		t.Fatal("path filter incorrectly paired source with target directory fd")
	}
}
