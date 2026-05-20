package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	STaVendorID          uint32 = 10415
	STaAuthApplicationID uint32 = 16777250
)

type Config struct {
	TWAG       TWAGConfig       `yaml:"twag"`
	Logging    LoggingConfig    `yaml:"logging"`
	Access     AccessConfig     `yaml:"access"`
	Radius     RadiusConfig     `yaml:"radius"`
	AAA        AAAConfig        `yaml:"aaa"`
	Subscriber SubscriberConfig `yaml:"subscriber"`
	GTP        GTPConfig        `yaml:"gtp"`
	Recovery   RecoveryConfig   `yaml:"session_recovery"`
	Lifecycle  LifecycleConfig  `yaml:"session_lifecycle"`
	Routing    RoutingConfig    `yaml:"routing"`
	IPAM       IPAMConfig       `yaml:"-"`
}

type TWAGConfig struct {
	Name  string `yaml:"name"`
	Realm string `yaml:"realm"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

type AccessConfig struct {
	Interface  string           `yaml:"interface"`
	GatewayIP  string           `yaml:"gateway_ip"`
	Netmask    string           `yaml:"netmask"`
	DNS        []string         `yaml:"dns"`
	DHCP       DHCPConfig       `yaml:"dhcp"`
	ARPProxy   ARPProxyConfig   `yaml:"arp_proxy"`
	Forwarding ForwardingConfig `yaml:"forwarding"`
}

type DHCPConfig struct {
	Enabled                  bool     `yaml:"enabled"`
	RequireAuthorizedSession bool     `yaml:"require_authorized_session"`
	LeaseTimeSeconds         uint32   `yaml:"lease_time_seconds"`
	RenewalTimeSeconds       uint32   `yaml:"renewal_time_seconds"`
	RebindingTimeSeconds     uint32   `yaml:"rebinding_time_seconds"`
	Interface                string   `yaml:"-"`
	Mode                     string   `yaml:"-"`
	Netmask                  string   `yaml:"-"`
	Router                   string   `yaml:"-"`
	ServerIdentifier         string   `yaml:"-"`
	DNS                      []string `yaml:"-"`
}

type ARPProxyConfig struct {
	Enabled                  bool   `yaml:"enabled"`
	Interface                string `yaml:"-"`
	GatewayIP                string `yaml:"-"`
	RequireAuthorizedSession bool   `yaml:"require_authorized_session"`
}

type ForwardingConfig struct {
	Enabled                  bool   `yaml:"enabled"`
	Interface                string `yaml:"-"`
	RequireAuthorizedSession bool   `yaml:"require_authorized_session"`
	VirtualGatewayIP         string `yaml:"-"`
}

type RadiusConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Secret     string `yaml:"secret"`
	VLANID     int    `yaml:"vlan_id"`
}

type AAAConfig struct {
	STa STaConfig `yaml:"sta"`
}

type STaConfig struct {
	OriginHost        string `yaml:"origin_host"`
	OriginRealm       string `yaml:"origin_realm"`
	DestinationRealm  string `yaml:"destination_realm"`
	DestinationHost   string `yaml:"destination_host"`
	PeerAddr          string `yaml:"peer_addr"`
	VendorID          uint32 `yaml:"-"`
	AuthApplicationID uint32 `yaml:"-"`
}

type SubscriberConfig struct {
	DefaultAPN   string `yaml:"default_apn"`
	DefaultRealm string `yaml:"default_realm"`
}

type IPAMConfig struct {
	Pool    string
	Gateway string
	DNS     []string
}

type GTPConfig struct {
	LocalGTPCIP             string        `yaml:"local_gtpc_ip"`
	LocalGTPUIP             string        `yaml:"local_gtpu_ip"`
	RemotePGWGTPCIP         string        `yaml:"remote_pgw_gtpc_ip"`
	RemotePGWGTPUIP         string        `yaml:"remote_pgw_gtpu_ip"`
	APN                     string        `yaml:"apn"`
	ChargingCharacteristics string        `yaml:"charging_characteristics"`
	KernelInterface         string        `yaml:"kernel_interface"`
	Echo                    GTPEchoConfig `yaml:"echo"`
}

type PGWConfig = GTPConfig

type GTPEchoConfig struct {
	Enabled         bool `yaml:"enabled"`
	IntervalSeconds int  `yaml:"interval_seconds"`
	TimeoutSeconds  int  `yaml:"timeout_seconds"`
	MaxFailures     int  `yaml:"max_failures"`
	StartupProbe    bool `yaml:"startup_probe"`
}

type RecoveryConfig struct {
	Enabled                  bool   `yaml:"enabled"`
	ReasonGTPUError          bool   `yaml:"reason_gtpu_error_indication"`
	RecoveryWindowSeconds    int    `yaml:"recovery_window_seconds"`
	StaleClientGraceSeconds  int    `yaml:"stale_client_grace_seconds"`
	CleanupOnDuplicateAttach bool   `yaml:"cleanup_on_duplicate_attach"`
	AllowSameMACReattach     bool   `yaml:"allow_same_mac_reattach"`
	RejectOldDHCPIP          bool   `yaml:"reject_old_dhcp_ip"`
	DHCPStaleRequestAction   string `yaml:"dhcp_stale_request_action"`
}

type LifecycleConfig struct {
	DuplicateAttachPolicy                string `yaml:"duplicate_attach_policy"`
	DuplicateAttachCleanupTimeoutSeconds int    `yaml:"duplicate_attach_cleanup_timeout_seconds"`
	SuppressDuplicateCreateSession       bool   `yaml:"suppress_duplicate_create_session"`
	PerSubscriberLockTimeoutSeconds      int    `yaml:"per_subscriber_lock_timeout_seconds"`
}

type UserPlaneConfig struct {
	Mode         string `yaml:"mode"`
	GTPInterface string `yaml:"gtp_interface"`
}

type RoutingConfig struct {
	EnableIPForwarding bool `yaml:"enable_ip_forwarding"`
	DisableRPFilter    bool `yaml:"disable_rp_filter"`
	PolicyRouting      bool `yaml:"policy_routing"`
	PolicyTable        int  `yaml:"policy_table"`
	PolicyPriority     int  `yaml:"policy_priority"`
	InstallRoutes      bool `yaml:"-"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Default() *Config {
	return &Config{
		Logging: LoggingConfig{
			Level: "info",
			File:  "/var/log/vectorcore/twag/twag.log",
		},
		Access: AccessConfig{
			Netmask: "255.255.255.0",
			DHCP: DHCPConfig{
				Mode:                     "proxy",
				RequireAuthorizedSession: true,
				LeaseTimeSeconds:         600,
				RenewalTimeSeconds:       300,
				RebindingTimeSeconds:     525,
			},
			ARPProxy: ARPProxyConfig{
				RequireAuthorizedSession: true,
			},
			Forwarding: ForwardingConfig{
				RequireAuthorizedSession: true,
			},
		},
		Radius: RadiusConfig{Enabled: true},
		AAA: AAAConfig{
			STa: STaConfig{
				VendorID:          STaVendorID,
				AuthApplicationID: STaAuthApplicationID,
			},
		},
		GTP:       GTPConfig{ChargingCharacteristics: "0800", KernelInterface: "gtp0", Echo: GTPEchoConfig{Enabled: true, IntervalSeconds: 30, TimeoutSeconds: 5, MaxFailures: 3, StartupProbe: true}},
		Recovery:  RecoveryConfig{Enabled: true, ReasonGTPUError: true, RecoveryWindowSeconds: 60, StaleClientGraceSeconds: 10, CleanupOnDuplicateAttach: true, AllowSameMACReattach: true, RejectOldDHCPIP: true, DHCPStaleRequestAction: "ignore"},
		Lifecycle: LifecycleConfig{DuplicateAttachPolicy: "reuse_existing", DuplicateAttachCleanupTimeoutSeconds: 5, SuppressDuplicateCreateSession: true, PerSubscriberLockTimeoutSeconds: 10},
		Routing:   RoutingConfig{InstallRoutes: true},
	}
}

func (c *Config) ApplyDefaults() {
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.File == "" {
		c.Logging.File = "/var/log/vectorcore/twag/twag.log"
	}
	if c.Access.Netmask == "" {
		c.Access.Netmask = "255.255.255.0"
	}
	if c.Access.DHCP.Mode == "" {
		c.Access.DHCP.Mode = "proxy"
	}
	c.Access.DHCP.Interface = c.Access.Interface
	c.Access.DHCP.Netmask = c.Access.Netmask
	c.Access.DHCP.Router = c.Access.GatewayIP
	c.Access.DHCP.ServerIdentifier = c.Access.GatewayIP
	c.Access.DHCP.DNS = append([]string(nil), c.Access.DNS...)
	if c.Access.DHCP.LeaseTimeSeconds == 0 {
		c.Access.DHCP.LeaseTimeSeconds = 600
	}
	if c.Access.DHCP.RenewalTimeSeconds == 0 {
		c.Access.DHCP.RenewalTimeSeconds = 300
	}
	if c.Access.DHCP.RebindingTimeSeconds == 0 {
		c.Access.DHCP.RebindingTimeSeconds = 525
	}
	c.Access.ARPProxy.Interface = c.Access.Interface
	c.Access.ARPProxy.GatewayIP = c.Access.GatewayIP
	c.Access.Forwarding.Interface = c.Access.Interface
	c.Access.Forwarding.VirtualGatewayIP = c.Access.GatewayIP
	if c.Radius.ListenAddr == "" {
		c.Radius.ListenAddr = "0.0.0.0:1812"
	}
	if c.Radius.VLANID == 0 {
		c.Radius.VLANID = 10
	}
	if c.GTP.ChargingCharacteristics == "" {
		c.GTP.ChargingCharacteristics = "0800"
	}
	if c.GTP.KernelInterface == "" {
		c.GTP.KernelInterface = "gtp0"
	}
	if c.GTP.Echo.IntervalSeconds == 0 {
		c.GTP.Echo.IntervalSeconds = 30
	}
	if c.GTP.Echo.TimeoutSeconds == 0 {
		c.GTP.Echo.TimeoutSeconds = 5
	}
	if c.GTP.Echo.MaxFailures == 0 {
		c.GTP.Echo.MaxFailures = 3
	}
	if c.Recovery.RecoveryWindowSeconds == 0 {
		c.Recovery.RecoveryWindowSeconds = 60
	}
	if c.Recovery.StaleClientGraceSeconds == 0 {
		c.Recovery.StaleClientGraceSeconds = 10
	}
	if c.Recovery.DHCPStaleRequestAction == "" {
		c.Recovery.DHCPStaleRequestAction = "ignore"
	}
	if c.Lifecycle.DuplicateAttachPolicy == "" {
		c.Lifecycle.DuplicateAttachPolicy = "reuse_existing"
	}
	if c.Lifecycle.DuplicateAttachCleanupTimeoutSeconds == 0 {
		c.Lifecycle.DuplicateAttachCleanupTimeoutSeconds = 5
	}
	if c.Lifecycle.PerSubscriberLockTimeoutSeconds == 0 {
		c.Lifecycle.PerSubscriberLockTimeoutSeconds = 10
	}
	c.Routing.InstallRoutes = true
	if c.Routing.PolicyRouting {
		if c.Routing.PolicyTable == 0 {
			c.Routing.PolicyTable = 200
		}
		if c.Routing.PolicyPriority == 0 {
			c.Routing.PolicyPriority = 10000
		}
	}
	c.AAA.STa.VendorID = STaVendorID
	c.AAA.STa.AuthApplicationID = STaAuthApplicationID
}

func (c *Config) Validate() error {
	var errs []string
	if c.TWAG.Name == "" {
		errs = append(errs, "twag.name is required")
	}
	if c.TWAG.Realm == "" {
		errs = append(errs, "twag.realm is required")
	}
	switch c.Logging.Level {
	case "debug", "info", "warn", "warning", "error":
	default:
		errs = append(errs, "logging.level must be one of debug, info, warn, error")
	}
	if c.Access.Interface == "" {
		errs = append(errs, "access.interface is required")
	}
	errs = append(errs, validateRequiredPlainIP("access.gateway_ip", c.Access.GatewayIP)...)
	errs = append(errs, validateRequiredPlainIP("access.netmask", c.Access.Netmask)...)
	for i, dns := range c.Access.DNS {
		if net.ParseIP(dns) == nil {
			errs = append(errs, fmt.Sprintf("access.dns[%d] is invalid", i))
		}
	}
	if c.Access.DHCP.Enabled {
		if c.Access.DHCP.Interface == "" {
			errs = append(errs, "access.dhcp interface defaulting failed")
		}
		if c.Access.DHCP.Mode != "proxy" {
			errs = append(errs, "access.dhcp.mode must be proxy")
		}
	}
	if c.Access.ARPProxy.Enabled {
		if c.Access.ARPProxy.Interface == "" {
			errs = append(errs, "access.arp_proxy interface defaulting failed")
		}
	}
	if c.Access.Forwarding.Enabled {
		if c.Access.Forwarding.Interface == "" {
			errs = append(errs, "access.forwarding interface defaulting failed")
		}
	}
	if c.Radius.Enabled {
		if c.Radius.Secret == "" {
			errs = append(errs, "radius.secret is required when radius.enabled is true")
		}
		if c.Radius.ListenAddr == "" {
			errs = append(errs, "radius.listen_addr is required when radius.enabled is true")
		}
	}
	if c.Radius.VLANID < 1 || c.Radius.VLANID > 4094 {
		errs = append(errs, "radius.vlan_id must be between 1 and 4094")
	}
	errs = append(errs, validateSTa(c.AAA.STa)...)
	errs = append(errs, validateRequiredIP("gtp.local_gtpc_ip", c.GTP.LocalGTPCIP)...)
	errs = append(errs, validateRequiredIP("gtp.local_gtpu_ip", c.GTP.LocalGTPUIP)...)
	errs = append(errs, validateRequiredIP("gtp.remote_pgw_gtpc_ip", c.GTP.RemotePGWGTPCIP)...)
	errs = append(errs, validateRequiredIP("gtp.remote_pgw_gtpu_ip", c.GTP.RemotePGWGTPUIP)...)
	if !validTwoOctetHex(c.GTP.ChargingCharacteristics) {
		errs = append(errs, "gtp.charging_characteristics must be exactly 4 hex characters")
	}
	if c.GTP.KernelInterface == "" {
		errs = append(errs, "gtp.kernel_interface is required")
	}
	if c.GTP.Echo.IntervalSeconds <= 0 {
		errs = append(errs, "gtp.echo.interval_seconds must be greater than 0")
	}
	if c.GTP.Echo.TimeoutSeconds <= 0 {
		errs = append(errs, "gtp.echo.timeout_seconds must be greater than 0")
	}
	if c.GTP.Echo.MaxFailures <= 0 {
		errs = append(errs, "gtp.echo.max_failures must be greater than 0")
	}
	if c.Recovery.RecoveryWindowSeconds <= 0 {
		errs = append(errs, "session_recovery.recovery_window_seconds must be greater than 0")
	}
	if c.Recovery.StaleClientGraceSeconds <= 0 {
		errs = append(errs, "session_recovery.stale_client_grace_seconds must be greater than 0")
	}
	if c.Recovery.DHCPStaleRequestAction != "ignore" && c.Recovery.DHCPStaleRequestAction != "nak" {
		errs = append(errs, "session_recovery.dhcp_stale_request_action must be ignore or nak")
	}
	if c.Lifecycle.DuplicateAttachPolicy != "reuse_existing" && c.Lifecycle.DuplicateAttachPolicy != "replace_existing" {
		errs = append(errs, "session_lifecycle.duplicate_attach_policy must be reuse_existing or replace_existing")
	}
	if c.Lifecycle.DuplicateAttachCleanupTimeoutSeconds <= 0 {
		errs = append(errs, "session_lifecycle.duplicate_attach_cleanup_timeout_seconds must be greater than 0")
	}
	if c.Lifecycle.PerSubscriberLockTimeoutSeconds <= 0 {
		errs = append(errs, "session_lifecycle.per_subscriber_lock_timeout_seconds must be greater than 0")
	}
	if c.Routing.PolicyRouting {
		if c.Routing.PolicyTable <= 0 {
			errs = append(errs, "routing.policy_table must be greater than 0 when routing.policy_routing is true")
		}
		if c.Routing.PolicyPriority <= 0 {
			errs = append(errs, "routing.policy_priority must be greater than 0 when routing.policy_routing is true")
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("config validation failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

func validTwoOctetHex(s string) bool {
	if utf8.RuneCountInString(s) != 4 {
		return false
	}
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}

func validateSTa(s STaConfig) []string {
	var errs []string
	if s.OriginHost == "" {
		errs = append(errs, "aaa.sta.origin_host is required when aaa.mode is sta")
	}
	if s.OriginRealm == "" {
		errs = append(errs, "aaa.sta.origin_realm is required when aaa.mode is sta")
	}
	if s.DestinationRealm == "" {
		errs = append(errs, "aaa.sta.destination_realm is required when aaa.mode is sta")
	}
	if s.PeerAddr == "" {
		errs = append(errs, "aaa.sta.peer_addr is required when aaa.mode is sta")
	} else if _, _, err := net.SplitHostPort(s.PeerAddr); err != nil {
		errs = append(errs, fmt.Sprintf("aaa.sta.peer_addr is invalid: %v", err))
	}
	return errs
}

func validateRequiredIP(name, value string) []string {
	if value == "" {
		return []string{name + " is required when pgw.mode is gtp"}
	}
	if net.ParseIP(value) == nil {
		return []string{name + " is invalid"}
	}
	return nil
}

func validateRequiredPlainIP(name, value string) []string {
	if value == "" {
		return []string{name + " is required"}
	}
	if net.ParseIP(value) == nil {
		return []string{name + " is invalid"}
	}
	return nil
}
