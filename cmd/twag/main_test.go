package main

import (
	"runtime"
	"strings"
	"testing"
)

func TestBuildInfoIncludesVersionMetadata(t *testing.T) {
	oldVersion, oldCommit, oldBuildDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = oldVersion, oldCommit, oldBuildDate
	})
	version = "test-version"
	commit = "test-commit"
	buildDate = "2026-05-08T00:00:00Z"

	info := buildInfo()
	for _, want := range []string{
		"VectorCore TWAG test-version",
		"commit: test-commit",
		"build_date: 2026-05-08T00:00:00Z",
		"go: " + runtime.Version(),
	} {
		if !strings.Contains(info, want) {
			t.Fatalf("buildInfo() = %q, missing %q", info, want)
		}
	}
}
