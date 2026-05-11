package logging

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vectorcore/twag/internal/config"
)

func TestNewWritesJSONLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "twag.log")
	logger, err := New(config.LoggingConfig{Level: "info", File: path}, false)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	logger.Info("service start", "session_id", "twag-test")
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	record := readFirstJSONRecord(t, path)
	if record["level"] != "INFO" || record["msg"] != "service start" || record["session_id"] != "twag-test" {
		t.Fatalf("unexpected record: %#v", record)
	}
	if _, ok := record["source"]; !ok {
		t.Fatalf("record missing source: %#v", record)
	}
}

func TestDebugConsoleDoesNotRaiseFileLevel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "twag.log")
	stderr := captureStderr(t)
	logger, err := New(config.LoggingConfig{Level: "info", File: path}, true)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	logger.Debug("debug only")
	logger.Info("info line")
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	console := stderr()
	if !strings.Contains(console, "debug only") {
		t.Fatalf("debug console output missing debug line: %s", console)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if strings.Contains(string(b), "debug only") {
		t.Fatalf("debug line leaked into info-level file log: %s", string(b))
	}
	if !strings.Contains(string(b), "info line") {
		t.Fatalf("info line missing from file log: %s", string(b))
	}
}

func TestDebugConsoleFallbackWhenFileCannotOpen(t *testing.T) {
	stderr := captureStderr(t)
	logger, err := New(config.LoggingConfig{Level: "info", File: "/proc/vectorcore-twag/nope.log"}, true)
	if err != nil {
		t.Fatalf("New() with debug fallback error = %v", err)
	}
	logger.Info("fallback active")
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	out := stderr()
	if !strings.Contains(out, "cannot open log file") || !strings.Contains(out, "fallback active") {
		t.Fatalf("unexpected stderr fallback output: %s", out)
	}
}

func TestNoSinkFails(t *testing.T) {
	if _, err := New(config.LoggingConfig{}, false); err == nil {
		t.Fatalf("expected no sink error")
	}
}

func readFirstJSONRecord(t *testing.T, path string) map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer f.Close() //nolint:errcheck
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatalf("log file is empty")
	}
	var record map[string]any
	if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
		t.Fatalf("decode log record: %v", err)
	}
	return record
}

func captureStderr(t *testing.T) func() string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	return func() string {
		_ = w.Close()
		os.Stderr = old
		b, _ := io.ReadAll(r)
		_ = r.Close()
		return string(b)
	}
}
