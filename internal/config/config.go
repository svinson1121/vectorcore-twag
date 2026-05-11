package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	SWxVendorID          uint32 = 10415
	SWxAuthApplicationID uint32 = 16777265
)

type Config struct {
	TWAG       TWAGConfig       `yaml:"twag"`
	Logging    LoggingConfig    `yaml:"logging"`
	Access     AccessConfig     `yaml:"access"`
	AAA        AAAConfig        `yaml:"aaa"`
	Subscriber SubscriberConfig `yaml:"subscriber"`
	IPAM       IPAMConfig       `yaml:"ipam"`
	PGW        PGWConfig        `yaml:"pgw"`
	Routing    RoutingConfig    `yaml:"routing"`
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
	Mode      string `yaml:"mode"`
	Interface string `yaml:"interface"`
}

type AAAConfig struct {
	Mode string    `yaml:"mode"`
	SWx  SWxConfig `yaml:"swx"`
}

type SWxConfig struct {
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
	Pool    string   `yaml:"pool"`
	Gateway string   `yaml:"gateway"`
	DNS     []string `yaml:"dns"`
}

type PGWConfig struct {
	Mode            string `yaml:"mode"`
	LocalGTPCIP     string `yaml:"local_gtpc_ip"`
	LocalGTPUIP     string `yaml:"local_gtpu_ip"`
	RemotePGWGTPCIP string `yaml:"remote_pgw_gtpc_ip"`
	RemotePGWGTPUIP string `yaml:"remote_pgw_gtpu_ip"`
	APN             string `yaml:"apn"`
}

type RoutingConfig struct {
	EnableIPForwarding bool   `yaml:"enable_ip_forwarding"`
	InstallRoutes      bool   `yaml:"install_routes"`
	NATEnabled         bool   `yaml:"nat_enabled"`
	NATInterface       string `yaml:"nat_interface"`
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
		Access: AccessConfig{Mode: "ethernet"},
		AAA: AAAConfig{
			Mode: "swx",
			SWx: SWxConfig{
				VendorID:          SWxVendorID,
				AuthApplicationID: SWxAuthApplicationID,
			},
		},
		PGW: PGWConfig{Mode: "stub"},
	}
}

func (c *Config) ApplyDefaults() {
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.File == "" {
		c.Logging.File = "/var/log/vectorcore/twag/twag.log"
	}
	if c.Access.Mode == "" {
		c.Access.Mode = "ethernet"
	}
	if c.AAA.Mode == "" {
		c.AAA.Mode = "swx"
	}
	if c.PGW.Mode == "" {
		c.PGW.Mode = "stub"
	}
	c.AAA.SWx.VendorID = SWxVendorID
	c.AAA.SWx.AuthApplicationID = SWxAuthApplicationID
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
	if c.Access.Mode != "ethernet" && c.Access.Mode != "gre" && c.Access.Mode != "l2tpv3" {
		errs = append(errs, "access.mode must be ethernet, gre, or l2tpv3")
	}
	if c.Access.Mode == "ethernet" && c.Access.Interface == "" {
		errs = append(errs, "access.interface is required when access.mode is ethernet")
	}
	if c.AAA.Mode != "swx" && c.AAA.Mode != "static" {
		errs = append(errs, "aaa.mode must be swx or static")
	}
	if c.AAA.Mode == "swx" {
		errs = append(errs, validateSWx(c.AAA.SWx)...)
	}
	if c.IPAM.Pool == "" {
		errs = append(errs, "ipam.pool is required")
	} else if _, _, err := net.ParseCIDR(c.IPAM.Pool); err != nil {
		errs = append(errs, fmt.Sprintf("ipam.pool is invalid: %v", err))
	}
	if c.IPAM.Gateway == "" {
		errs = append(errs, "ipam.gateway is required")
	} else if net.ParseIP(c.IPAM.Gateway) == nil {
		errs = append(errs, "ipam.gateway is invalid")
	}
	for i, dns := range c.IPAM.DNS {
		if net.ParseIP(dns) == nil {
			errs = append(errs, fmt.Sprintf("ipam.dns[%d] is invalid", i))
		}
	}
	if c.PGW.Mode != "stub" && c.PGW.Mode != "gtp" {
		errs = append(errs, "pgw.mode must be stub or gtp")
	}
	if c.PGW.Mode == "gtp" {
		errs = append(errs, validateRequiredIP("pgw.local_gtpc_ip", c.PGW.LocalGTPCIP)...)
		errs = append(errs, validateRequiredIP("pgw.local_gtpu_ip", c.PGW.LocalGTPUIP)...)
		errs = append(errs, validateRequiredIP("pgw.remote_pgw_gtpc_ip", c.PGW.RemotePGWGTPCIP)...)
		errs = append(errs, validateRequiredIP("pgw.remote_pgw_gtpu_ip", c.PGW.RemotePGWGTPUIP)...)
	}
	if c.Routing.NATEnabled && c.Routing.NATInterface == "" {
		errs = append(errs, "routing.nat_interface is required when routing.nat_enabled is true")
	}
	if len(errs) > 0 {
		return fmt.Errorf("config validation failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

func validateSWx(s SWxConfig) []string {
	var errs []string
	if s.OriginHost == "" {
		errs = append(errs, "aaa.swx.origin_host is required when aaa.mode is swx")
	}
	if s.OriginRealm == "" {
		errs = append(errs, "aaa.swx.origin_realm is required when aaa.mode is swx")
	}
	if s.DestinationRealm == "" {
		errs = append(errs, "aaa.swx.destination_realm is required when aaa.mode is swx")
	}
	if s.PeerAddr == "" {
		errs = append(errs, "aaa.swx.peer_addr is required when aaa.mode is swx")
	} else if _, _, err := net.SplitHostPort(s.PeerAddr); err != nil {
		errs = append(errs, fmt.Sprintf("aaa.swx.peer_addr is invalid: %v", err))
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
