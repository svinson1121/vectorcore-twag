package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "examples", "twag.yaml"))
	if err != nil {
		t.Fatalf("Load(example) error = %v", err)
	}
	if cfg.Access.Interface != "enp0s8" {
		t.Fatalf("unexpected access interface %q", cfg.Access.Interface)
	}
	if cfg.Radius.Enabled != true {
		t.Fatal("radius.enabled = false, want true")
	}
}

func TestDefaultsAndAccessFanout(t *testing.T) {
	cfg := mustLoadYAML(t, minimalConfig())
	if cfg.Access.Netmask != "255.255.255.0" {
		t.Fatalf("access.netmask default = %q", cfg.Access.Netmask)
	}
	if cfg.Access.DHCP.Interface != cfg.Access.Interface {
		t.Fatalf("dhcp interface = %q, want %q", cfg.Access.DHCP.Interface, cfg.Access.Interface)
	}
	if cfg.Access.DHCP.Router != cfg.Access.GatewayIP {
		t.Fatalf("dhcp router = %q, want %q", cfg.Access.DHCP.Router, cfg.Access.GatewayIP)
	}
	if cfg.Access.ARPProxy.GatewayIP != cfg.Access.GatewayIP {
		t.Fatalf("arp gateway = %q, want %q", cfg.Access.ARPProxy.GatewayIP, cfg.Access.GatewayIP)
	}
	if cfg.Access.Forwarding.VirtualGatewayIP != cfg.Access.GatewayIP {
		t.Fatalf("forwarding gateway = %q, want %q", cfg.Access.Forwarding.VirtualGatewayIP, cfg.Access.GatewayIP)
	}
	if cfg.Radius.VLANID != 10 {
		t.Fatalf("radius.vlan_id default = %d", cfg.Radius.VLANID)
	}
	if !cfg.GTP.Echo.Enabled || !cfg.GTP.Echo.StartupProbe {
		t.Fatalf("gtp echo defaults disabled: %#v", cfg.GTP.Echo)
	}
	if cfg.GTP.Echo.IntervalSeconds != 30 || cfg.GTP.Echo.TimeoutSeconds != 5 || cfg.GTP.Echo.MaxFailures != 3 {
		t.Fatalf("unexpected gtp echo defaults: %#v", cfg.GTP.Echo)
	}
	if cfg.GTP.KernelInterface != "gtp0" {
		t.Fatalf("gtp.kernel_interface default = %q", cfg.GTP.KernelInterface)
	}
	if cfg.AAA.STa.VendorID != STaVendorID {
		t.Fatalf("sta vendor id = %d", cfg.AAA.STa.VendorID)
	}
	if cfg.AAA.STa.AuthApplicationID != STaAuthApplicationID {
		t.Fatalf("sta auth application id = %d", cfg.AAA.STa.AuthApplicationID)
	}
	if !cfg.Recovery.Enabled || !cfg.Recovery.ReasonGTPUError {
		t.Fatalf("session recovery defaults disabled: %#v", cfg.Recovery)
	}
	if cfg.Lifecycle.DuplicateAttachPolicy != "reuse_existing" {
		t.Fatalf("duplicate attach policy default = %q", cfg.Lifecycle.DuplicateAttachPolicy)
	}
	if cfg.Lifecycle.DuplicateAttachCleanupTimeoutSeconds != 5 {
		t.Fatalf("duplicate attach cleanup timeout default = %d", cfg.Lifecycle.DuplicateAttachCleanupTimeoutSeconds)
	}
	if cfg.Lifecycle.PerSubscriberLockTimeoutSeconds != 10 {
		t.Fatalf("subscriber lock timeout default = %d", cfg.Lifecycle.PerSubscriberLockTimeoutSeconds)
	}
}

func TestGTPEchoConfigOverride(t *testing.T) {
	cfg := mustLoadYAML(t, baseConfigNoGTP()+`
gtp:
  local_gtpc_ip: 127.0.0.1
  local_gtpu_ip: 127.0.0.1
  remote_pgw_gtpc_ip: 127.0.0.2
  remote_pgw_gtpu_ip: 127.0.0.2
  charging_characteristics: "0800"
  echo:
    enabled: false
    interval_seconds: 10
    timeout_seconds: 2
    max_failures: 4
    startup_probe: false
radius:
  secret: testing123
`)
	if cfg.GTP.Echo.Enabled {
		t.Fatal("gtp.echo.enabled = true, want false")
	}
	if cfg.GTP.Echo.IntervalSeconds != 10 || cfg.GTP.Echo.TimeoutSeconds != 2 || cfg.GTP.Echo.MaxFailures != 4 {
		t.Fatalf("unexpected gtp echo config: %#v", cfg.GTP.Echo)
	}
	if cfg.GTP.Echo.StartupProbe {
		t.Fatal("gtp.echo.startup_probe = true, want false")
	}
}

func TestGTPEchoValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "interval", body: "interval_seconds: -1", want: "gtp.echo.interval_seconds must be greater than 0"},
		{name: "timeout", body: "timeout_seconds: -1", want: "gtp.echo.timeout_seconds must be greater than 0"},
		{name: "max failures", body: "max_failures: -1", want: "gtp.echo.max_failures must be greater than 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, baseConfigNoGTP()+`
gtp:
  local_gtpc_ip: 127.0.0.1
  local_gtpu_ip: 127.0.0.1
  remote_pgw_gtpc_ip: 127.0.0.2
  remote_pgw_gtpu_ip: 127.0.0.2
  echo:
    `+tc.body+`
radius:
  secret: testing123
`)
			if err == nil {
				t.Fatal("expected gtp echo validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestMissingSTaConfigFailsClearly(t *testing.T) {
	_, err := loadYAML(t, `
twag:
  name: twag-test
  realm: epc.example
access:
  interface: eth1
  gateway_ip: 100.64.0.1
gtp:
  local_gtpc_ip: 127.0.0.1
  local_gtpu_ip: 127.0.0.1
  remote_pgw_gtpc_ip: 127.0.0.2
  remote_pgw_gtpu_ip: 127.0.0.2
aaa:
  sta: {}
`)
	if err == nil {
		t.Fatal("expected missing STa config error")
	}
	for _, want := range []string{
		"aaa.sta.origin_host is required",
		"aaa.sta.peer_addr is required",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

func TestGTPChargingCharacteristicsValidation(t *testing.T) {
	for _, value := range []string{"08", "080000", "xyz", "08xx"} {
		_, err := loadYAML(t, baseConfigNoGTP()+`
gtp:
  local_gtpc_ip: 127.0.0.1
  local_gtpu_ip: 127.0.0.1
  remote_pgw_gtpc_ip: 127.0.0.2
  remote_pgw_gtpu_ip: 127.0.0.2
  charging_characteristics: "`+value+`"
radius:
  secret: testing123
`)
		if err == nil {
			t.Fatalf("expected charging characteristics validation error for %q", value)
		}
		if !strings.Contains(err.Error(), "gtp.charging_characteristics must be exactly 4 hex characters") {
			t.Fatalf("unexpected error for %q: %v", value, err)
		}
	}
}

func TestUnknownYAMLFieldFails(t *testing.T) {
	_, err := loadYAML(t, minimalConfig()+`
pgw:
  mode: gtp
`)
	if err == nil {
		t.Fatal("expected unknown field error")
	}
	if !strings.Contains(err.Error(), "field pgw not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRadiusVLANIDOverride(t *testing.T) {
	cfg := mustLoadYAML(t, strings.Replace(minimalConfig(), "radius:\n  secret: testing123\n", "radius:\n  secret: testing123\n  vlan_id: 37\n", 1))
	if cfg.Radius.VLANID != 37 {
		t.Fatalf("radius.vlan_id = %d, want 37", cfg.Radius.VLANID)
	}
}

func TestRadiusVLANIDValidation(t *testing.T) {
	for _, value := range []string{"4095", "-1"} {
		_, err := loadYAML(t, strings.Replace(minimalConfig(), "radius:\n  secret: testing123\n", "radius:\n  secret: testing123\n  vlan_id: "+value+"\n", 1))
		if err == nil {
			t.Fatalf("expected radius vlan validation error for %s", value)
		}
		if !strings.Contains(err.Error(), "radius.vlan_id must be between 1 and 4094") {
			t.Fatalf("unexpected error for %s: %v", value, err)
		}
	}
}

func TestPolicyRoutingDefaults(t *testing.T) {
	cfg := mustLoadYAML(t, minimalConfig()+`
routing:
  policy_routing: true
`)
	if cfg.Routing.PolicyTable != 200 {
		t.Fatalf("routing.policy_table = %d, want 200", cfg.Routing.PolicyTable)
	}
	if cfg.Routing.PolicyPriority != 10000 {
		t.Fatalf("routing.policy_priority = %d, want 10000", cfg.Routing.PolicyPriority)
	}
}

func TestSessionLifecycleValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "policy", body: "duplicate_attach_policy: invalid", want: "session_lifecycle.duplicate_attach_policy must be reuse_existing or replace_existing"},
		{name: "cleanup timeout", body: "duplicate_attach_cleanup_timeout_seconds: -1", want: "session_lifecycle.duplicate_attach_cleanup_timeout_seconds must be greater than 0"},
		{name: "lock timeout", body: "per_subscriber_lock_timeout_seconds: -1", want: "session_lifecycle.per_subscriber_lock_timeout_seconds must be greater than 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, minimalConfig()+`
session_lifecycle:
  `+tc.body+`
`)
			if err == nil {
				t.Fatal("expected session lifecycle validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func minimalConfig() string {
	return baseConfigNoGTP() + `
gtp:
  local_gtpc_ip: 127.0.0.1
  local_gtpu_ip: 127.0.0.1
  remote_pgw_gtpc_ip: 127.0.0.2
  remote_pgw_gtpu_ip: 127.0.0.2
radius:
  secret: testing123
`
}

func baseConfigNoGTP() string {
	return `
twag:
  name: twag-test
  realm: epc.example
access:
  interface: eth1
  gateway_ip: 100.64.0.1
  dns:
    - 8.8.8.8
aaa:
  sta:
    origin_host: twag.epc.example
    origin_realm: epc.example
    destination_realm: ims.example
    peer_addr: 127.0.0.1:3868
`
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
