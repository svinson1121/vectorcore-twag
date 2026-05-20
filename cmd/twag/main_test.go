package main

import (
	"log/slog"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/vectorcore/twag/internal/config"
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

func TestRealAAAAttach(t *testing.T) {
	cfgPath := os.Getenv("TWAG_REAL_AAA_CONFIG")
	attachPath := os.Getenv("TWAG_REAL_AAA_ATTACH")
	if cfgPath == "" || attachPath == "" {
		t.Skip("set TWAG_REAL_AAA_CONFIG and TWAG_REAL_AAA_ATTACH to run the real AAA attach test")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	detach := os.Getenv("TWAG_REAL_AAA_ATTACH_DETACH") == "1"
	if err := run(cfg, slog.New(slog.DiscardHandler), attachPath, "", detach, false); err != nil {
		t.Fatalf("real AAA test attach failed: %v", err)
	}
}
