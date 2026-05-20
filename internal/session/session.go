package session

import (
	"net"
	"time"
)

type State string

const (
	Pending     State = "pending"
	AuthPending State = "auth_pending"
	Authorized  State = "authorized"
	IPAllocated State = "ip_allocated"
	PGWPending  State = "pgw_pending"
	Active      State = "active"
	Recovering  State = "recovering"
	Terminating State = "terminating"
	Terminated  State = "terminated"
	Failed      State = "failed"
)

type Session struct {
	ID                string    `json:"id"`
	IMSI              string    `json:"imsi,omitempty"`
	MSISDN            string    `json:"msisdn,omitempty"`
	MACAddress        string    `json:"mac,omitempty"`
	APN               string    `json:"apn,omitempty"`
	Realm             string    `json:"realm,omitempty"`
	SubscriberIP      net.IP    `json:"subscriber_ip,omitempty"`
	GatewayIP         net.IP    `json:"gateway_ip,omitempty"`
	AccessType        string    `json:"access_type,omitempty"`
	AccessInterface   string    `json:"access_interface,omitempty"`
	PGWControlIP      net.IP    `json:"pgw_control_ip,omitempty"`
	PGWUserIP         net.IP    `json:"pgw_user_ip,omitempty"`
	GTPCTEID          uint32    `json:"gtpc_teid,omitempty"`
	LocalGTPUTEID     uint32    `json:"local_gtpu_teid,omitempty"`
	RemoteGTPUTEID    uint32    `json:"remote_gtpu_teid,omitempty"`
	GTPUErrorCount    uint64    `json:"gtpu_error_indications_received,omitempty"`
	LastGTPUErrorAt   time.Time `json:"last_gtpu_error_time,omitempty"`
	LastGTPUErrorTEID uint32    `json:"last_gtpu_error_teid,omitempty"`
	Authenticated     bool      `json:"authenticated"`
	Authorized        bool      `json:"authorized"`
	State             State     `json:"state"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	ExpiresAt         time.Time `json:"expires_at,omitempty"`
	Reason            string    `json:"reason,omitempty"`
}

type RecoveryTombstone struct {
	MAC             net.HardwareAddr `json:"mac,omitempty"`
	IMSI            string           `json:"imsi,omitempty"`
	APN             string           `json:"apn,omitempty"`
	OldSubscriberIP net.IP           `json:"old_subscriber_ip,omitempty"`
	OldSessionID    string           `json:"old_session_id,omitempty"`
	OldRemoteTEID   uint32           `json:"old_remote_teid,omitempty"`
	OldLocalTEID    uint32           `json:"old_local_teid,omitempty"`
	Reason          string           `json:"reason,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	ExpiresAt       time.Time        `json:"expires_at"`
}
