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

type RecoveryState string

const (
	RecoveryNone          RecoveryState = "none"
	RecoveryRequired      RecoveryState = "recovery_required"
	RecoveryDisconnecting RecoveryState = "disconnecting"
	RecoveryWaitingReauth RecoveryState = "waiting_reauth"
	RecoveryFallback      RecoveryState = "fallback_tombstone"
	RecoveryCompleted     RecoveryState = "completed"
	RecoveryExpired       RecoveryState = "expired"
)

type Session struct {
	ID                string    `json:"id"`
	IMSI              string    `json:"imsi,omitempty"`
	MSISDN            string    `json:"msisdn,omitempty"`
	MACAddress        string    `json:"mac,omitempty"`
	APN               string    `json:"apn,omitempty"`
	Realm             string    `json:"realm,omitempty"`
	Username          string    `json:"username,omitempty"`
	EAPIdentity       string    `json:"eap_identity,omitempty"`
	CallingStationID  string    `json:"calling_station_id,omitempty"`
	CalledStationID   string    `json:"called_station_id,omitempty"`
	NASIP             string    `json:"nas_ip,omitempty"`
	NASIdentifier     string    `json:"nas_identifier,omitempty"`
	AcctSessionID     string    `json:"acct_session_id,omitempty"`
	RadiusState       string    `json:"radius_state,omitempty"`
	RadiusClass       []byte    `json:"radius_class,omitempty"`
	ConnectInfo       string    `json:"connect_info,omitempty"`
	FramedMTU         uint32    `json:"framed_mtu,omitempty"`
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
	MAC              net.HardwareAddr `json:"mac,omitempty"`
	IMSI             string           `json:"imsi,omitempty"`
	APN              string           `json:"apn,omitempty"`
	OldSubscriberIP  net.IP           `json:"old_subscriber_ip,omitempty"`
	OldSessionID     string           `json:"old_session_id,omitempty"`
	OldRemoteTEID    uint32           `json:"old_remote_teid,omitempty"`
	OldLocalTEID     uint32           `json:"old_local_teid,omitempty"`
	OriginalUsername string           `json:"original_username,omitempty"`
	EAPIdentity      string           `json:"eap_identity,omitempty"`
	RadiusState      string           `json:"radius_state,omitempty"`
	NASIP            string           `json:"nas_ip,omitempty"`
	NASIdentifier    string           `json:"nas_identifier,omitempty"`
	AcctSessionID    string           `json:"acct_session_id,omitempty"`
	CallingStationID string           `json:"calling_station_id,omitempty"`
	CalledStationID  string           `json:"called_station_id,omitempty"`
	Class            []byte           `json:"class,omitempty"`
	ConnectInfo      string           `json:"connect_info,omitempty"`
	FramedMTU        uint32           `json:"framed_mtu,omitempty"`
	Reason           string           `json:"reason,omitempty"`
	State            RecoveryState    `json:"state"`
	CreatedAt        time.Time        `json:"created_at"`
	ExpiresAt        time.Time        `json:"expires_at"`
	LastAction       string           `json:"last_action,omitempty"`
	LastError        string           `json:"last_error,omitempty"`
}
