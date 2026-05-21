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

	MinGTPEchoIntervalSeconds = 60
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
	Warnings   []string         `yaml:"-"`
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
	RecoverFromAuthCache     bool     `yaml:"recover_from_auth_cache"`
	LeaseTimeSeconds         uint32   `yaml:"lease_time_seconds"`
	RenewalTimeSeconds       uint32   `yaml:"renewal_time_seconds"`
	RebindingTimeSeconds     uint32   `yaml:"rebinding_time_seconds"`
	Interface                string   `yaml:"-"`
	Mode                     string   `yaml:"-"`
	Netmask                  string   `yaml:"-"`
	Router                   string   `yaml:"-"`
	ServerIdentifier         string   `yaml:"-"`
	DNS                      []string `yaml:"-"`
	StaleRequestAction       string   `yaml:"-"`
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
	Enabled              bool                       `yaml:"enabled"`
	ListenAddr           string                     `yaml:"listen_addr"`
	Secret               string                     `yaml:"secret"`
	VLANID               int                        `yaml:"vlan_id"`
	AllowedSourceSubnets []string                   `yaml:"allowed_source_subnets"`
	AuthCache            RadiusAuthCacheConfig      `yaml:"auth_cache"`
	AccessAccept         RadiusAccessAcceptConfig   `yaml:"access_accept"`
	Accounting           RadiusAccountingConfig     `yaml:"accounting"`
	DynamicAuthorization DynamicAuthorizationConfig `yaml:"dynamic_authorization"`
}

type RadiusAuthCacheConfig struct {
	Enabled           bool `yaml:"enabled"`
	DefaultTTLSeconds int  `yaml:"default_ttl_seconds"`
	MaxTTLSeconds     int  `yaml:"max_ttl_seconds"`
}

type RadiusAccessAcceptConfig struct {
	SessionTimeoutSeconds int    `yaml:"session_timeout_seconds"`
	TerminationAction     string `yaml:"termination_action"`
	IdleTimeoutSeconds    int    `yaml:"idle_timeout_seconds"`
}

type RadiusAccountingConfig struct {
	Enabled                   bool   `yaml:"enabled"`
	ListenAddr                string `yaml:"listen_addr"`
	Secret                    string `yaml:"secret"`
	ClearSessionOnStop        bool   `yaml:"clear_session_on_stop"`
	ClearAuthCacheOnStop      bool   `yaml:"clear_auth_cache_on_stop"`
	InterimUpdateLiveness     bool   `yaml:"interim_update_liveness"`
	AccountingOffAction       string `yaml:"accounting_off_action"`
	StartWithoutSessionAction string `yaml:"start_without_session_action"`
	StartWithoutAuthAction    string `yaml:"start_without_auth_action"`
}

type DynamicAuthorizationConfig struct {
	DefaultPort         int    `yaml:"default_port"`
	Secret              string `yaml:"secret"`
	PreferDiscoveredNAS bool   `yaml:"prefer_discovered_nas"`
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
	LocalGTPCIP             string            `yaml:"local_gtpc_ip"`
	LocalGTPUIP             string            `yaml:"local_gtpu_ip"`
	RemotePGWGTPCIP         string            `yaml:"remote_pgw_gtpc_ip"`
	RemotePGWGTPUIP         string            `yaml:"remote_pgw_gtpu_ip"`
	APN                     string            `yaml:"apn"`
	ChargingCharacteristics string            `yaml:"charging_characteristics"`
	KernelInterface         string            `yaml:"kernel_interface"`
	Echo                    GTPEchoConfig     `yaml:"echo"`
	ControlEcho             GTPEchoConfig     `yaml:"control_echo"`
	UserEcho                GTPUserEchoConfig `yaml:"user_echo"`
	legacyEchoSet           bool
	controlEchoSet          bool
	userEchoSet             bool
}

func (g *GTPConfig) UnmarshalYAML(value *yaml.Node) error {
	type plain GTPConfig
	var decoded plain = plain(*g)
	if err := value.Decode(&decoded); err != nil {
		return err
	}
	*g = GTPConfig(decoded)
	for i := 0; i+1 < len(value.Content); i += 2 {
		switch value.Content[i].Value {
		case "echo":
			g.legacyEchoSet = true
		case "control_echo":
			g.controlEchoSet = true
		case "user_echo":
			g.userEchoSet = true
		}
	}
	return nil
}

type PGWConfig = GTPConfig

type GTPEchoConfig struct {
	Enabled         bool `yaml:"enabled"`
	IntervalSeconds int  `yaml:"interval_seconds"`
	TimeoutSeconds  int  `yaml:"timeout_seconds"`
	MaxFailures     int  `yaml:"max_failures"`
	StartupProbe    bool `yaml:"startup_probe"`
}

type GTPUserEchoConfig struct {
	Enabled              bool   `yaml:"enabled"`
	Mode                 string `yaml:"mode"`
	IntervalSeconds      int    `yaml:"interval_seconds"`
	TimeoutSeconds       int    `yaml:"timeout_seconds"`
	MaxFailures          int    `yaml:"max_failures"`
	StartupProbe         bool   `yaml:"startup_probe"`
	RequireKernelSupport bool   `yaml:"require_kernel_support"`
}

type RecoveryConfig struct {
	Enabled                  bool                          `yaml:"enabled"`
	ReasonGTPUError          bool                          `yaml:"reason_gtpu_error_indication"`
	RecoveryWindowSeconds    int                           `yaml:"recovery_window_seconds"`
	StaleClientGraceSeconds  int                           `yaml:"stale_client_grace_seconds"`
	CleanupOnDuplicateAttach bool                          `yaml:"cleanup_on_duplicate_attach"`
	AllowSameMACReattach     bool                          `yaml:"allow_same_mac_reattach"`
	RejectOldDHCPIP          bool                          `yaml:"reject_old_dhcp_ip"`
	DHCPStaleRequestAction   string                        `yaml:"dhcp_stale_request_action"`
	RadiusDisconnect         RadiusDisconnectConfig        `yaml:"radius_disconnect"`
	AccountingStartRecovery  AccountingStartRecoveryConfig `yaml:"accounting_start_recovery"`
}

type AccountingStartRecoveryConfig struct {
	Enabled              bool `yaml:"enabled"`
	CooldownSeconds      int  `yaml:"cooldown_seconds"`
	MaxAttemptsPerMinute int  `yaml:"max_attempts_per_minute"`
}

type RadiusDisconnectConfig struct {
	Enabled                      bool   `yaml:"enabled"`
	NASPort                      int    `yaml:"nas_port"`
	Secret                       string `yaml:"secret"`
	TimeoutSeconds               int    `yaml:"timeout_seconds"`
	Retries                      int    `yaml:"retries"`
	RequestType                  string `yaml:"request_type"`
	WaitForAccountingStop        bool   `yaml:"wait_for_accounting_stop"`
	AccountingStopTimeoutSeconds int    `yaml:"accounting_stop_timeout_seconds"`
	FallbackToRecoveryTombstone  bool   `yaml:"fallback_to_recovery_tombstone"`
}

type LifecycleConfig struct {
	DuplicateAttachPolicy                string                         `yaml:"duplicate_attach_policy"`
	DuplicateAttachCleanupTimeoutSeconds int                            `yaml:"duplicate_attach_cleanup_timeout_seconds"`
	SuppressDuplicateCreateSession       bool                           `yaml:"suppress_duplicate_create_session"`
	PerSubscriberLockTimeoutSeconds      int                            `yaml:"per_subscriber_lock_timeout_seconds"`
	PostActivationValidation             PostActivationValidationConfig `yaml:"post_activation_validation"`
}

type PostActivationValidationConfig struct {
	Enabled                   bool   `yaml:"enabled"`
	FailAction                string `yaml:"fail_action"`
	FirstPacketTimeoutSeconds int    `yaml:"first_packet_timeout_seconds"`
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
				RecoverFromAuthCache:     true,
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
		Radius: RadiusConfig{
			Enabled:              true,
			AuthCache:            RadiusAuthCacheConfig{Enabled: true, DefaultTTLSeconds: 3600, MaxTTLSeconds: 86400},
			AccessAccept:         RadiusAccessAcceptConfig{SessionTimeoutSeconds: 3600, TerminationAction: "radius_request"},
			Accounting:           RadiusAccountingConfig{ListenAddr: "0.0.0.0:1813", ClearSessionOnStop: true, InterimUpdateLiveness: true, AccountingOffAction: "mark_at_risk", StartWithoutSessionAction: "recover_if_auth_valid", StartWithoutAuthAction: "disconnect"},
			DynamicAuthorization: DynamicAuthorizationConfig{DefaultPort: 3799, PreferDiscoveredNAS: true},
		},
		AAA: AAAConfig{
			STa: STaConfig{
				VendorID:          STaVendorID,
				AuthApplicationID: STaAuthApplicationID,
			},
		},
		GTP:       GTPConfig{ChargingCharacteristics: "0800", KernelInterface: "gtp0", ControlEcho: GTPEchoConfig{Enabled: true, IntervalSeconds: MinGTPEchoIntervalSeconds, TimeoutSeconds: 5, MaxFailures: 3, StartupProbe: true}, UserEcho: GTPUserEchoConfig{Mode: "kernel_netlink", IntervalSeconds: MinGTPEchoIntervalSeconds, TimeoutSeconds: 5, MaxFailures: 3}},
		Recovery:  RecoveryConfig{Enabled: true, ReasonGTPUError: true, RecoveryWindowSeconds: 60, StaleClientGraceSeconds: 10, CleanupOnDuplicateAttach: true, AllowSameMACReattach: true, RejectOldDHCPIP: true, DHCPStaleRequestAction: "nak", RadiusDisconnect: RadiusDisconnectConfig{NASPort: 3799, TimeoutSeconds: 3, Retries: 2, RequestType: "disconnect", AccountingStopTimeoutSeconds: 10, FallbackToRecoveryTombstone: true}, AccountingStartRecovery: AccountingStartRecoveryConfig{Enabled: true, CooldownSeconds: 10, MaxAttemptsPerMinute: 3}},
		Lifecycle: LifecycleConfig{DuplicateAttachPolicy: "reuse_existing", DuplicateAttachCleanupTimeoutSeconds: 5, SuppressDuplicateCreateSession: true, PerSubscriberLockTimeoutSeconds: 10, PostActivationValidation: PostActivationValidationConfig{Enabled: true, FailAction: "trigger_recovery"}},
		Routing:   RoutingConfig{InstallRoutes: true},
	}
}

func (c *Config) ApplyDefaults() {
	c.Warnings = nil
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
	c.Access.DHCP.RecoverFromAuthCache = true
	c.Access.DHCP.Interface = c.Access.Interface
	c.Access.DHCP.Netmask = c.Access.Netmask
	c.Access.DHCP.Router = c.Access.GatewayIP
	c.Access.DHCP.ServerIdentifier = c.Access.GatewayIP
	c.Access.DHCP.DNS = append([]string(nil), c.Access.DNS...)
	c.Access.DHCP.StaleRequestAction = c.Recovery.DHCPStaleRequestAction
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
	if len(c.Radius.AllowedSourceSubnets) == 0 {
		c.warn("RADIUS allowed_source_subnets is empty; accepting RADIUS from any source")
	}
	if c.Radius.AccessAccept.SessionTimeoutSeconds == 0 {
		c.Radius.AccessAccept.SessionTimeoutSeconds = 3600
	}
	c.Radius.AuthCache.Enabled = true
	if c.Radius.AuthCache.DefaultTTLSeconds == 0 {
		c.Radius.AuthCache.DefaultTTLSeconds = c.Radius.AccessAccept.SessionTimeoutSeconds
	}
	if c.Radius.AuthCache.DefaultTTLSeconds == 0 {
		c.Radius.AuthCache.DefaultTTLSeconds = 3600
	}
	if c.Radius.AuthCache.MaxTTLSeconds == 0 {
		c.Radius.AuthCache.MaxTTLSeconds = 86400
	}
	if c.Radius.AuthCache.DefaultTTLSeconds > c.Radius.AuthCache.MaxTTLSeconds {
		c.Radius.AuthCache.DefaultTTLSeconds = c.Radius.AuthCache.MaxTTLSeconds
	}
	if c.Radius.AccessAccept.TerminationAction == "" {
		c.Radius.AccessAccept.TerminationAction = "radius_request"
	}
	if c.Radius.Accounting.ListenAddr == "" {
		c.Radius.Accounting.ListenAddr = "0.0.0.0:1813"
	}
	if c.Radius.Accounting.Secret == "" {
		c.Radius.Accounting.Secret = c.Radius.Secret
	}
	c.Radius.Accounting.ClearSessionOnStop = true
	c.Radius.Accounting.InterimUpdateLiveness = true
	if c.Radius.Accounting.AccountingOffAction == "" {
		c.Radius.Accounting.AccountingOffAction = "mark_at_risk"
	}
	if c.Radius.Accounting.StartWithoutSessionAction == "" {
		c.Radius.Accounting.StartWithoutSessionAction = "recover_if_auth_valid"
	}
	if c.Radius.Accounting.StartWithoutAuthAction == "" {
		c.Radius.Accounting.StartWithoutAuthAction = "disconnect"
	}
	if c.Radius.DynamicAuthorization.DefaultPort == 0 {
		c.Radius.DynamicAuthorization.DefaultPort = 3799
	}
	if c.Radius.DynamicAuthorization.Secret == "" {
		c.Radius.DynamicAuthorization.Secret = c.Radius.Secret
	}
	c.Radius.DynamicAuthorization.PreferDiscoveredNAS = true
	if c.GTP.ChargingCharacteristics == "" {
		c.GTP.ChargingCharacteristics = "0800"
	}
	if c.GTP.KernelInterface == "" {
		c.GTP.KernelInterface = "gtp0"
	}
	if c.GTP.legacyEchoSet && !c.GTP.controlEchoSet {
		c.GTP.ControlEcho = c.GTP.Echo
	}
	controlEchoPath := "gtp.control_echo"
	if c.GTP.legacyEchoSet && !c.GTP.controlEchoSet {
		controlEchoPath = "gtp.echo"
	}
	c.GTP.ControlEcho = normalizeGTPEchoConfig(c.GTP.ControlEcho, controlEchoPath, &c.Warnings)
	c.GTP.Echo = c.GTP.ControlEcho
	c.GTP.UserEcho = normalizeGTPUserEchoConfig(c.GTP.UserEcho, "gtp.user_echo", &c.Warnings)
	if c.GTP.UserEcho.Enabled && c.GTP.UserEcho.TimeoutSeconds >= c.GTP.UserEcho.IntervalSeconds {
		c.warn("gtp.user_echo.timeout_seconds should be less than interval_seconds")
	}
	if c.Recovery.RecoveryWindowSeconds == 0 {
		c.Recovery.RecoveryWindowSeconds = 60
	}
	if c.Recovery.StaleClientGraceSeconds == 0 {
		c.Recovery.StaleClientGraceSeconds = 10
	}
	if c.Recovery.DHCPStaleRequestAction == "" {
		c.Recovery.DHCPStaleRequestAction = "nak"
	}
	if c.Recovery.RejectOldDHCPIP {
		c.Recovery.DHCPStaleRequestAction = "nak"
	}
	c.Access.DHCP.StaleRequestAction = c.Recovery.DHCPStaleRequestAction
	if c.Recovery.RadiusDisconnect.NASPort == 0 {
		c.Recovery.RadiusDisconnect.NASPort = 3799
	}
	if c.Recovery.RadiusDisconnect.TimeoutSeconds == 0 {
		c.Recovery.RadiusDisconnect.TimeoutSeconds = 3
	}
	if c.Recovery.RadiusDisconnect.Retries == 0 {
		c.Recovery.RadiusDisconnect.Retries = 2
	}
	if c.Recovery.RadiusDisconnect.RequestType == "" {
		c.Recovery.RadiusDisconnect.RequestType = "disconnect"
	}
	if c.Radius.Accounting.Enabled {
		c.Recovery.RadiusDisconnect.WaitForAccountingStop = true
	}
	if c.Recovery.RadiusDisconnect.AccountingStopTimeoutSeconds == 0 {
		c.Recovery.RadiusDisconnect.AccountingStopTimeoutSeconds = 10
	}
	c.Recovery.RadiusDisconnect.FallbackToRecoveryTombstone = true
	c.Recovery.AccountingStartRecovery.Enabled = true
	if c.Recovery.AccountingStartRecovery.CooldownSeconds == 0 {
		c.Recovery.AccountingStartRecovery.CooldownSeconds = 10
	}
	if c.Recovery.AccountingStartRecovery.MaxAttemptsPerMinute == 0 {
		c.Recovery.AccountingStartRecovery.MaxAttemptsPerMinute = 3
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
	c.Lifecycle.PostActivationValidation.Enabled = true
	if c.Lifecycle.PostActivationValidation.FailAction == "" {
		c.Lifecycle.PostActivationValidation.FailAction = "trigger_recovery"
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

func (c *Config) warn(message string) {
	c.Warnings = append(c.Warnings, message)
	fmt.Fprintf(os.Stderr, "VectorCore TWAG: warning: %s\n", message)
}

func normalizeGTPEchoConfig(cfg GTPEchoConfig, path string, warnings *[]string) GTPEchoConfig {
	if cfg.IntervalSeconds == 0 {
		cfg.IntervalSeconds = MinGTPEchoIntervalSeconds
	} else if cfg.IntervalSeconds > 0 && cfg.IntervalSeconds < MinGTPEchoIntervalSeconds {
		warnGTPEchoIntervalClamped(path, cfg.IntervalSeconds, warnings)
		cfg.IntervalSeconds = MinGTPEchoIntervalSeconds
	}
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 5
	}
	if cfg.MaxFailures == 0 {
		cfg.MaxFailures = 3
	}
	return cfg
}

func normalizeGTPUserEchoConfig(cfg GTPUserEchoConfig, path string, warnings *[]string) GTPUserEchoConfig {
	if cfg.Mode == "" {
		cfg.Mode = "kernel_netlink"
	}
	if cfg.IntervalSeconds == 0 {
		cfg.IntervalSeconds = MinGTPEchoIntervalSeconds
	} else if cfg.IntervalSeconds > 0 && cfg.IntervalSeconds < MinGTPEchoIntervalSeconds {
		warnGTPEchoIntervalClamped(path, cfg.IntervalSeconds, warnings)
		cfg.IntervalSeconds = MinGTPEchoIntervalSeconds
	}
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 5
	}
	if cfg.MaxFailures == 0 {
		cfg.MaxFailures = 3
	}
	return cfg
}

func warnGTPEchoIntervalClamped(path string, configured int, warnings *[]string) {
	msg := fmt.Sprintf("%s.interval_seconds configured below %d seconds; clamping configured value %d to %d to avoid sending GTP Echo too frequently", path, MinGTPEchoIntervalSeconds, configured, MinGTPEchoIntervalSeconds)
	*warnings = append(*warnings, msg)
	fmt.Fprintf(os.Stderr, "VectorCore TWAG: warning: %s\n", msg)
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
	if c.Radius.AccessAccept.SessionTimeoutSeconds <= 0 {
		errs = append(errs, "radius.access_accept.session_timeout_seconds must be greater than 0")
	}
	if c.Radius.AccessAccept.TerminationAction != "radius_request" && c.Radius.AccessAccept.TerminationAction != "default" {
		errs = append(errs, "radius.access_accept.termination_action must be radius_request or default")
	}
	if c.Radius.AccessAccept.IdleTimeoutSeconds < 0 {
		errs = append(errs, "radius.access_accept.idle_timeout_seconds must be greater than or equal to 0")
	}
	for i, cidr := range c.Radius.AllowedSourceSubnets {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			errs = append(errs, fmt.Sprintf("radius.allowed_source_subnets[%d] must be a valid CIDR", i))
		}
	}
	if c.Radius.Accounting.Enabled {
		if c.Radius.Accounting.ListenAddr == "" {
			errs = append(errs, "radius.accounting.listen_addr is required when accounting.enabled is true")
		}
		if c.Radius.Accounting.Secret == "" {
			errs = append(errs, "radius.accounting.secret is required when accounting.enabled is true")
		}
	}
	switch c.Radius.Accounting.AccountingOffAction {
	case "mark_at_risk", "clear_sessions", "ignore":
	default:
		errs = append(errs, "radius.accounting.accounting_off_action must be mark_at_risk, clear_sessions, or ignore")
	}
	switch c.Radius.Accounting.StartWithoutSessionAction {
	case "recover_if_auth_valid", "disconnect", "ignore":
	default:
		errs = append(errs, "radius.accounting.start_without_session_action must be recover_if_auth_valid, disconnect, or ignore")
	}
	switch c.Radius.Accounting.StartWithoutAuthAction {
	case "disconnect", "ignore", "log_only":
	default:
		errs = append(errs, "radius.accounting.start_without_auth_action must be disconnect, ignore, or log_only")
	}
	if c.Radius.DynamicAuthorization.DefaultPort < 0 || c.Radius.DynamicAuthorization.DefaultPort > 65535 {
		errs = append(errs, "radius.dynamic_authorization.default_port must be between 0 and 65535")
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
	if c.GTP.ControlEcho.IntervalSeconds <= 0 {
		errs = append(errs, "gtp.control_echo.interval_seconds must be greater than 0")
	}
	if c.GTP.ControlEcho.TimeoutSeconds <= 0 {
		errs = append(errs, "gtp.control_echo.timeout_seconds must be greater than 0")
	}
	if c.GTP.ControlEcho.MaxFailures <= 0 {
		errs = append(errs, "gtp.control_echo.max_failures must be greater than 0")
	}
	if c.GTP.UserEcho.Enabled {
		if c.GTP.UserEcho.Mode != "kernel_netlink" {
			errs = append(errs, "gtp.user_echo.mode must be kernel_netlink")
		}
		if c.GTP.UserEcho.IntervalSeconds <= 0 {
			errs = append(errs, "gtp.user_echo.interval_seconds must be greater than 0")
		}
		if c.GTP.UserEcho.TimeoutSeconds <= 0 {
			errs = append(errs, "gtp.user_echo.timeout_seconds must be greater than 0")
		}
		if c.GTP.UserEcho.MaxFailures <= 0 {
			errs = append(errs, "gtp.user_echo.max_failures must be greater than 0")
		}
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
	if c.Recovery.RadiusDisconnect.Enabled {
		if c.Recovery.RadiusDisconnect.Secret == "" {
			errs = append(errs, "session_recovery.radius_disconnect.secret is required when enabled")
		}
	}
	if c.Recovery.RadiusDisconnect.NASPort <= 0 || c.Recovery.RadiusDisconnect.NASPort > 65535 {
		errs = append(errs, "session_recovery.radius_disconnect.nas_port must be between 1 and 65535")
	}
	if c.Recovery.RadiusDisconnect.AccountingStopTimeoutSeconds <= 0 {
		errs = append(errs, "session_recovery.radius_disconnect.accounting_stop_timeout_seconds must be greater than 0")
	}
	if c.Recovery.RadiusDisconnect.TimeoutSeconds <= 0 {
		errs = append(errs, "session_recovery.radius_disconnect.timeout_seconds must be greater than 0")
	}
	if c.Recovery.RadiusDisconnect.Retries < 0 {
		errs = append(errs, "session_recovery.radius_disconnect.retries must be greater than or equal to 0")
	}
	if c.Recovery.RadiusDisconnect.RequestType != "disconnect" && c.Recovery.RadiusDisconnect.RequestType != "coa" {
		errs = append(errs, "session_recovery.radius_disconnect.request_type must be disconnect or coa")
	}
	if c.Recovery.AccountingStartRecovery.CooldownSeconds <= 0 {
		errs = append(errs, "session_recovery.accounting_start_recovery.cooldown_seconds must be greater than 0")
	}
	if c.Recovery.AccountingStartRecovery.MaxAttemptsPerMinute <= 0 {
		errs = append(errs, "session_recovery.accounting_start_recovery.max_attempts_per_minute must be greater than 0")
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
	switch c.Lifecycle.PostActivationValidation.FailAction {
	case "trigger_recovery", "reject_access", "log_only":
	default:
		errs = append(errs, "session_lifecycle.post_activation_validation.fail_action must be trigger_recovery, reject_access, or log_only")
	}
	if c.Lifecycle.PostActivationValidation.FirstPacketTimeoutSeconds < 0 {
		errs = append(errs, "session_lifecycle.post_activation_validation.first_packet_timeout_seconds must be greater than or equal to 0")
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
