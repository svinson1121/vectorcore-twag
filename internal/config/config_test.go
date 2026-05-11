package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "examples", "basic.yaml"))
	if err != nil {
		t.Fatalf("Load(example) error = %v", err)
	}
	if cfg.Access.Mode != "ethernet" {
		t.Fatalf("unexpected access mode %q", cfg.Access.Mode)
	}
	if cfg.Logging.Level != "info" {
		t.Fatalf("unexpected logging level %q", cfg.Logging.Level)
	}
}

func TestDefaults(t *testing.T) {
	cfg := mustLoadYAML(t, `
twag:
  name: twag-test
  realm: epc.example
access:
  interface: eth1
aaa:
  swx:
    origin_host: twag.epc.example
    origin_realm: epc.example
    destination_realm: ims.example
    peer_addr: 127.0.0.1:3868
ipam:
  pool: 10.200.0.0/24
  gateway: 10.200.0.1
`)
	if cfg.Access.Mode != "ethernet" {
		t.Fatalf("access.mode default = %q", cfg.Access.Mode)
	}
	if cfg.AAA.Mode != "swx" {
		t.Fatalf("aaa.mode default = %q", cfg.AAA.Mode)
	}
	if cfg.PGW.Mode != "stub" {
		t.Fatalf("pgw.mode default = %q", cfg.PGW.Mode)
	}
	if cfg.AAA.SWx.VendorID != SWxVendorID {
		t.Fatalf("swx vendor id = %d", cfg.AAA.SWx.VendorID)
	}
	if cfg.AAA.SWx.AuthApplicationID != SWxAuthApplicationID {
		t.Fatalf("swx auth application id = %d", cfg.AAA.SWx.AuthApplicationID)
	}
}

func TestMissingSWxConfigFailsClearly(t *testing.T) {
	_, err := loadYAML(t, `
twag:
  name: twag-test
  realm: epc.example
access:
  interface: eth1
aaa:
  mode: swx
ipam:
  pool: 10.200.0.0/24
  gateway: 10.200.0.1
`)
	if err == nil {
		t.Fatal("expected missing SWx config error")
	}
	for _, want := range []string{
		"aaa.swx.origin_host is required",
		"aaa.swx.peer_addr is required",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

func TestGREDoesNotRequireEthernetInterface(t *testing.T) {
	cfg := mustLoadYAML(t, `
twag:
  name: twag-test
  realm: epc.example
access:
  mode: gre
aaa:
  mode: static
ipam:
  pool: 10.200.0.0/24
  gateway: 10.200.0.1
`)
	if cfg.Access.Mode != "gre" {
		t.Fatalf("access mode = %q", cfg.Access.Mode)
	}
}

func TestUnknownYAMLFieldFails(t *testing.T) {
	_, err := loadYAML(t, `
twag:
  name: twag-test
  realm: epc.example
  typo_field: nope
access:
  interface: eth1
aaa:
  mode: static
ipam:
  pool: 10.200.0.0/24
  gateway: 10.200.0.1
`)
	if err == nil {
		t.Fatal("expected unknown field error")
	}
	if !strings.Contains(err.Error(), "field typo_field not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNATRequiresInterface(t *testing.T) {
	_, err := loadYAML(t, `
twag:
  name: twag-test
  realm: epc.example
access:
  interface: eth1
aaa:
  mode: static
ipam:
  pool: 10.200.0.0/24
  gateway: 10.200.0.1
routing:
  nat_enabled: true
`)
	if err == nil {
		t.Fatal("expected missing nat interface error")
	}
	if !strings.Contains(err.Error(), "routing.nat_interface is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustLoadYAML(t *testing.T, content string) *Config {
	t.Helper()
	cfg, err := loadYAML(t, content)
	if err != nil {
		t.Fatalf("loadYAML() error = %v", err)
	}
	return cfg
}

func loadYAML(t *testing.T, content string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return Load(path)
}
