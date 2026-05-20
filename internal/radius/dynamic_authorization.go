package radius

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/vectorcore/twag/internal/config"
	"github.com/vectorcore/twag/internal/session"
	radiustransport "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc3576"
)

type DynamicAuthorizer struct {
	cfg config.RadiusDisconnectConfig
	log *slog.Logger
}

func NewDynamicAuthorizer(cfg config.RadiusDisconnectConfig, log *slog.Logger) *DynamicAuthorizer {
	return &DynamicAuthorizer{cfg: cfg, log: log}
}

func (d *DynamicAuthorizer) DisconnectOrCoA(ctx context.Context, tombstone *session.RecoveryTombstone) error {
	if tombstone == nil {
		return fmt.Errorf("recovery tombstone is required")
	}
	if !d.cfg.Enabled {
		return fmt.Errorf("RADIUS dynamic authorization disabled")
	}
	nasIP := tombstone.NASIP
	if net.ParseIP(nasIP) == nil {
		return fmt.Errorf("RADIUS dynamic authorization destination NAS IP unavailable for session")
	}
	addr := fmt.Sprintf("%s:%d", nasIP, d.cfg.NASPort)
	code := radiustransport.CodeDisconnectRequest
	ack := radiustransport.CodeDisconnectACK
	nak := radiustransport.CodeDisconnectNAK
	requestType := "disconnect"
	if d.cfg.RequestType == "coa" {
		code = radiustransport.CodeCoARequest
		ack = radiustransport.CodeCoAACK
		nak = radiustransport.CodeCoANAK
		requestType = "coa"
	}
	attempts := d.cfg.Retries + 1
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		packet := radiustransport.New(code, []byte(d.cfg.Secret))
		addDynamicAuthorizationAttributes(packet, tombstone, nasIP)
		timeout := time.Duration(d.cfg.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = 3 * time.Second
		}
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		msg := "RADIUS Disconnect-Request sent for session recovery"
		if requestType == "coa" {
			msg = "RADIUS CoA-Request sent for session recovery"
		}
		d.log.Info(msg,
			"request_type", requestType,
			"attempt", attempt,
			"max_attempts", attempts,
			"nas_ip", nasIP,
			"nas_port", d.cfg.NASPort,
			"old_session_id", tombstone.OldSessionID,
			"imsi", tombstone.IMSI,
			"mac", tombstone.MAC.String(),
			"old_subscriber_ip", ipString(tombstone.OldSubscriberIP),
		)
		resp, err := radiustransport.Exchange(attemptCtx, packet, addr)
		cancel()
		if err != nil {
			lastErr = err
			d.log.Warn("RADIUS dynamic authorization request failed",
				"request_type", requestType,
				"attempt", attempt,
				"max_attempts", attempts,
				"nas_addr", addr,
				"old_session_id", tombstone.OldSessionID,
				"error", err,
			)
			continue
		}
		if resp.Code == ack {
			d.log.Info("RADIUS dynamic authorization ACK received",
				"request_type", requestType,
				"nas_addr", addr,
				"old_session_id", tombstone.OldSessionID,
				"imsi", tombstone.IMSI,
				"mac", tombstone.MAC.String(),
			)
			return nil
		}
		if resp.Code == nak {
			cause := rfc3576.ErrorCause_Get(resp)
			return fmt.Errorf("RADIUS %s NAK received: error_cause=%s", requestType, cause.String())
		}
		lastErr = fmt.Errorf("unexpected RADIUS dynamic authorization response code %s", resp.Code.String())
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("RADIUS dynamic authorization timed out")
	}
	return lastErr
}

func addDynamicAuthorizationAttributes(packet *radiustransport.Packet, tombstone *session.RecoveryTombstone, nasIP string) {
	if tombstone.OriginalUsername != "" {
		_ = rfc2865.UserName_SetString(packet, tombstone.OriginalUsername)
	} else if tombstone.IMSI != "" {
		_ = rfc2865.UserName_SetString(packet, tombstone.IMSI)
	}
	callingStationID := tombstone.CallingStationID
	if callingStationID == "" && tombstone.MAC != nil {
		callingStationID = tombstone.MAC.String()
	}
	if callingStationID != "" {
		_ = rfc2865.CallingStationID_SetString(packet, callingStationID)
	}
	if tombstone.CalledStationID != "" {
		_ = rfc2865.CalledStationID_SetString(packet, tombstone.CalledStationID)
	}
	if ip := net.ParseIP(nasIP); ip != nil {
		_ = rfc2865.NASIPAddress_Set(packet, ip)
	}
	if tombstone.NASIdentifier != "" {
		_ = rfc2865.NASIdentifier_SetString(packet, tombstone.NASIdentifier)
	}
	if tombstone.AcctSessionID != "" {
		_ = rfc2866.AcctSessionID_SetString(packet, tombstone.AcctSessionID)
	} else if tombstone.OldSessionID != "" {
		_ = rfc2866.AcctSessionID_SetString(packet, tombstone.OldSessionID)
	}
	if len(tombstone.Class) > 0 {
		_ = rfc2865.Class_Set(packet, tombstone.Class)
	} else if tombstone.OldSessionID != "" {
		_ = rfc2865.Class_SetString(packet, tombstone.OldSessionID)
	}
	if tombstone.OldSubscriberIP != nil {
		_ = rfc2865.FramedIPAddress_Set(packet, tombstone.OldSubscriberIP)
	}
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
