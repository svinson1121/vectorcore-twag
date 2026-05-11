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
	Terminating State = "terminating"
	Terminated  State = "terminated"
	Failed      State = "failed"
)

type Session struct {
	ID              string    `json:"id"`
	IMSI            string    `json:"imsi,omitempty"`
	MSISDN          string    `json:"msisdn,omitempty"`
	MACAddress      string    `json:"mac,omitempty"`
	APN             string    `json:"apn,omitempty"`
	Realm           string    `json:"realm,omitempty"`
	SubscriberIP    net.IP    `json:"subscriber_ip,omitempty"`
	GatewayIP       net.IP    `json:"gateway_ip,omitempty"`
	AccessType      string    `json:"access_type,omitempty"`
	AccessInterface string    `json:"access_interface,omitempty"`
	PGWControlIP    net.IP    `json:"pgw_control_ip,omitempty"`
	PGWUserIP       net.IP    `json:"pgw_user_ip,omitempty"`
	GTPCTEID        uint32    `json:"gtpc_teid,omitempty"`
	LocalGTPUTEID   uint32    `json:"local_gtpu_teid,omitempty"`
	RemoteGTPUTEID  uint32    `json:"remote_gtpu_teid,omitempty"`
	Authenticated   bool      `json:"authenticated"`
	Authorized      bool      `json:"authorized"`
	State           State     `json:"state"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
	Reason          string    `json:"reason,omitempty"`
}
