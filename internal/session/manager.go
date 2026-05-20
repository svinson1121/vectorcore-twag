package session

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

type CreateInput struct {
	IMSI             string
	MSISDN           string
	MACAddress       string
	APN              string
	Realm            string
	Username         string
	EAPIdentity      string
	CallingStationID string
	CalledStationID  string
	NASIP            string
	NASIdentifier    string
	AcctSessionID    string
	RadiusState      string
	RadiusClass      []byte
	ConnectInfo      string
	FramedMTU        uint32
	AccessType       string
	AccessInterface  string
	GatewayIP        net.IP
	TTL              time.Duration
}

type Manager struct {
	log *slog.Logger

	mu     sync.RWMutex
	next   uint64
	byID   map[string]*Session
	byIMSI map[string]*Session
	byMAC  map[string]*Session
	byIP   map[string]*Session
	byTEID map[uint32]*Session

	recoveryByMAC     map[string]*RecoveryTombstone
	recoveryByIMSI    map[string]*RecoveryTombstone
	recoveryByIP      map[string]*RecoveryTombstone
	recoveryByRemoteT map[uint32]*RecoveryTombstone
}

var ErrInvalidTransition = errors.New("invalid session state transition")

func NewManager(log *slog.Logger) *Manager {
	return &Manager{
		log:               log,
		byID:              make(map[string]*Session),
		byIMSI:            make(map[string]*Session),
		byMAC:             make(map[string]*Session),
		byIP:              make(map[string]*Session),
		byTEID:            make(map[uint32]*Session),
		recoveryByMAC:     make(map[string]*RecoveryTombstone),
		recoveryByIMSI:    make(map[string]*RecoveryTombstone),
		recoveryByIP:      make(map[string]*RecoveryTombstone),
		recoveryByRemoteT: make(map[uint32]*RecoveryTombstone),
	}
}

func (m *Manager) Create(input CreateInput) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	now := time.Now().UTC()
	s := &Session{
		ID:               fmt.Sprintf("twag-%d-%d", now.UnixNano(), m.next),
		IMSI:             input.IMSI,
		MSISDN:           input.MSISDN,
		MACAddress:       input.MACAddress,
		APN:              input.APN,
		Realm:            input.Realm,
		Username:         input.Username,
		EAPIdentity:      input.EAPIdentity,
		CallingStationID: input.CallingStationID,
		CalledStationID:  input.CalledStationID,
		NASIP:            input.NASIP,
		NASIdentifier:    input.NASIdentifier,
		AcctSessionID:    input.AcctSessionID,
		RadiusState:      input.RadiusState,
		RadiusClass:      append([]byte(nil), input.RadiusClass...),
		ConnectInfo:      input.ConnectInfo,
		FramedMTU:        input.FramedMTU,
		AccessType:       input.AccessType,
		AccessInterface:  input.AccessInterface,
		GatewayIP:        cloneIP(input.GatewayIP),
		State:            Pending,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if input.TTL > 0 {
		s.ExpiresAt = now.Add(input.TTL)
	}
	m.indexLocked(s)
	m.log.Info("session created pending", "session_id", s.ID, "imsi", s.IMSI, "msisdn", s.MSISDN, "mac", s.MACAddress, "apn", s.APN, "state", s.State)
	return clone(s)
}

func (m *Manager) MarkAuthPending(id string) (*Session, error) {
	return m.transition(id, AuthPending, func(s *Session) {})
}

func (m *Manager) MarkAuthorized(id string) (*Session, error) {
	return m.transition(id, Authorized, func(s *Session) {
		s.Authenticated = true
		s.Authorized = true
	})
}

func (m *Manager) ApplyAuthResult(id, imsi, msisdn, apn, reason string) (*Session, error) {
	return m.transition(id, Authorized, func(s *Session) {
		m.unindexLocked(s)
		if imsi != "" {
			s.IMSI = imsi
		}
		if msisdn != "" {
			s.MSISDN = msisdn
		}
		if apn != "" {
			s.APN = apn
		}
		s.Reason = reason
		s.Authenticated = true
		s.Authorized = true
		m.indexLocked(s)
	})
}

func (m *Manager) SetSubscriberIP(id string, ip net.IP) (*Session, error) {
	return m.transition(id, IPAllocated, func(s *Session) {
		if s.SubscriberIP != nil {
			delete(m.byIP, s.SubscriberIP.String())
		}
		s.SubscriberIP = cloneIP(ip)
		m.byIP[s.SubscriberIP.String()] = s
	})
}

func (m *Manager) UpdateSubscriberIP(id string, ip net.IP) (*Session, error) {
	return m.update(id, func(s *Session) {
		if s.SubscriberIP != nil {
			delete(m.byIP, s.SubscriberIP.String())
		}
		s.SubscriberIP = cloneIP(ip)
		if s.SubscriberIP != nil {
			m.byIP[s.SubscriberIP.String()] = s
		}
	})
}

func (m *Manager) MarkPGWPending(id string) (*Session, error) {
	return m.transition(id, PGWPending, func(s *Session) {})
}

func (m *Manager) MarkActive(id string) (*Session, error) {
	return m.transition(id, Active, func(s *Session) {})
}

func (m *Manager) MarkRecovering(id, reason string) (*Session, error) {
	return m.transition(id, Recovering, func(s *Session) {
		s.Reason = reason
	})
}

func (m *Manager) MarkTerminating(id string) (*Session, error) {
	return m.transition(id, Terminating, func(s *Session) {})
}

func (m *Manager) MarkFailed(id, reason string) (*Session, error) {
	return m.transition(id, Failed, func(s *Session) {
		s.Reason = reason
	})
}

func (m *Manager) BindTEIDs(id string, gtpc, localGTpu, remoteGTpu uint32) (*Session, error) {
	return m.update(id, func(s *Session) {
		if s.GTPCTEID != 0 {
			delete(m.byTEID, s.GTPCTEID)
		}
		s.GTPCTEID = gtpc
		s.LocalGTPUTEID = localGTpu
		s.RemoteGTPUTEID = remoteGTpu
		if s.GTPCTEID != 0 {
			m.byTEID[s.GTPCTEID] = s
		}
	})
}

func (m *Manager) ApplyPGWResult(id string, pgwControlIP, pgwUserIP net.IP, gtpc, localGTpu, remoteGTpu uint32) (*Session, error) {
	return m.update(id, func(s *Session) {
		if s.GTPCTEID != 0 {
			delete(m.byTEID, s.GTPCTEID)
		}
		s.PGWControlIP = cloneIP(pgwControlIP)
		s.PGWUserIP = cloneIP(pgwUserIP)
		s.GTPCTEID = gtpc
		s.LocalGTPUTEID = localGTpu
		s.RemoteGTPUTEID = remoteGTpu
		if s.GTPCTEID != 0 {
			m.byTEID[s.GTPCTEID] = s
		}
	})
}

func (m *Manager) Delete(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok {
		return nil, false
	}
	if !validTransition(s.State, Terminated) {
		return nil, false
	}
	m.unindexLocked(s)
	s.State = Terminated
	s.UpdatedAt = time.Now().UTC()
	return clone(s), true
}

func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.byID[id]
	return clone(s), ok
}

func (m *Manager) List() []Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Session, 0, len(m.byID))
	for _, s := range m.byID {
		out = append(out, *clone(s))
	}
	return out
}

func (m *Manager) ExpireInactive(now time.Time) []Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	var expired []Session
	for id, s := range m.byID {
		if s.ExpiresAt.IsZero() || now.Before(s.ExpiresAt) {
			continue
		}
		m.unindexLocked(s)
		delete(m.byID, id)
		s.State = Terminated
		s.UpdatedAt = now
		expired = append(expired, *clone(s))
	}
	return expired
}

func (m *Manager) LookupByIMSI(imsi string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.byIMSI[imsi]
	return clone(s), ok
}

func (m *Manager) LookupByMAC(mac string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.byMAC[mac]
	if !ok {
		if hw, err := net.ParseMAC(mac); err == nil {
			s, ok = m.byMAC[hw.String()]
		}
	}
	return clone(s), ok
}

func (m *Manager) LookupByMACAddr(mac net.HardwareAddr) (*Session, bool) {
	if mac == nil {
		return nil, false
	}
	return m.LookupByMAC(mac.String())
}

func (m *Manager) FindActiveBySubscriber(imsi, mac, apn string) (*Session, bool) {
	return m.findBySubscriber(imsi, mac, apn, true)
}

func (m *Manager) FindAnyBySubscriber(imsi, mac, apn string) (*Session, bool) {
	return m.findBySubscriber(imsi, mac, apn, false)
}

func (m *Manager) FindByMAC(mac string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0)
	for _, s := range m.byID {
		if macMatches(s.MACAddress, mac) {
			out = append(out, clone(s))
		}
	}
	return out
}

func (m *Manager) FindByIMSIAPN(imsi, apn string) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0)
	for _, s := range m.byID {
		if s.IMSI == imsi && sameAPN(s.APN, apn) {
			out = append(out, clone(s))
		}
	}
	return out
}

func (m *Manager) LookupByIP(ip net.IP) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.byIP[ip.String()]
	return clone(s), ok
}

func (m *Manager) LookupByTEID(teid uint32) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.byTEID[teid]
	return clone(s), ok
}

func (m *Manager) LookupByRemoteGTPUTEID(teid uint32) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.byID {
		if s.RemoteGTPUTEID == teid {
			return clone(s), true
		}
	}
	return nil, false
}

func (m *Manager) LookupByLocalGTPUTEID(teid uint32) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.byID {
		if s.LocalGTPUTEID == teid {
			return clone(s), true
		}
	}
	return nil, false
}

func (m *Manager) RecordGTPUError(id string, teid uint32, at time.Time) (*Session, error) {
	return m.update(id, func(s *Session) {
		s.GTPUErrorCount++
		s.LastGTPUErrorAt = at
		s.LastGTPUErrorTEID = teid
		s.Reason = fmt.Sprintf("GTP-U Error Indication for TEID 0x%08x", teid)
	})
}

func (m *Manager) AddRecoveryTombstone(sess *Session, reason string, ttl time.Duration) (*RecoveryTombstone, bool) {
	if sess == nil || ttl <= 0 {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	t := &RecoveryTombstone{
		IMSI:             sess.IMSI,
		APN:              sess.APN,
		OldSubscriberIP:  cloneIP(sess.SubscriberIP),
		OldSessionID:     sess.ID,
		OldRemoteTEID:    sess.RemoteGTPUTEID,
		OldLocalTEID:     sess.LocalGTPUTEID,
		OriginalUsername: sess.Username,
		EAPIdentity:      sess.EAPIdentity,
		RadiusState:      sess.RadiusState,
		NASIP:            sess.NASIP,
		NASIdentifier:    sess.NASIdentifier,
		AcctSessionID:    sess.AcctSessionID,
		CallingStationID: sess.CallingStationID,
		CalledStationID:  sess.CalledStationID,
		Class:            append([]byte(nil), sess.RadiusClass...),
		ConnectInfo:      sess.ConnectInfo,
		FramedMTU:        sess.FramedMTU,
		Reason:           reason,
		State:            RecoveryRequired,
		CreatedAt:        now,
		ExpiresAt:        now.Add(ttl),
	}
	if sess.MACAddress != "" {
		if mac, err := net.ParseMAC(sess.MACAddress); err == nil {
			t.MAC = append(net.HardwareAddr(nil), mac...)
			if t.CallingStationID == "" {
				t.CallingStationID = mac.String()
			}
		}
	}
	m.indexRecoveryLocked(t)
	return cloneRecovery(t), true
}

func (m *Manager) UpdateRecovery(oldSessionID string, fn func(*RecoveryTombstone)) (*RecoveryTombstone, bool) {
	if oldSessionID == "" {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var t *RecoveryTombstone
	for _, candidate := range m.recoveryByMAC {
		if candidate.OldSessionID == oldSessionID {
			t = candidate
			break
		}
	}
	if t == nil {
		for _, candidate := range m.recoveryByIMSI {
			if candidate.OldSessionID == oldSessionID {
				t = candidate
				break
			}
		}
	}
	if m.recoveryExpiredLocked(t) {
		return nil, false
	}
	if t == nil {
		return nil, false
	}
	m.unindexRecoveryLocked(t)
	fn(t)
	m.indexRecoveryLocked(t)
	return cloneRecovery(t), true
}

func (m *Manager) LookupRecoveryByMACAddr(mac net.HardwareAddr) (*RecoveryTombstone, bool) {
	if mac == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.recoveryByMAC[mac.String()]
	if m.recoveryExpiredLocked(t) {
		return nil, false
	}
	return cloneRecovery(t), t != nil
}

func (m *Manager) LookupRecoveryByIP(ip net.IP) (*RecoveryTombstone, bool) {
	if ip == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.recoveryByIP[ip.String()]
	if m.recoveryExpiredLocked(t) {
		return nil, false
	}
	return cloneRecovery(t), t != nil
}

func (m *Manager) FindRecovery(imsi, mac string) (*RecoveryTombstone, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var t *RecoveryTombstone
	if mac != "" {
		if hw, err := net.ParseMAC(mac); err == nil {
			t = m.recoveryByMAC[hw.String()]
		} else {
			t = m.recoveryByMAC[mac]
		}
	}
	if t == nil && imsi != "" {
		t = m.recoveryByIMSI[imsi]
	}
	if m.recoveryExpiredLocked(t) {
		return nil, false
	}
	return cloneRecovery(t), t != nil
}

func (m *Manager) CompleteRecoveryFor(sess *Session) (*RecoveryTombstone, bool) {
	if sess == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var t *RecoveryTombstone
	if sess.MACAddress != "" {
		if hw, err := net.ParseMAC(sess.MACAddress); err == nil {
			t = m.recoveryByMAC[hw.String()]
		}
	}
	if t == nil && sess.IMSI != "" {
		t = m.recoveryByIMSI[sess.IMSI]
	}
	if m.recoveryExpiredLocked(t) {
		return nil, false
	}
	m.unindexRecoveryLocked(t)
	return cloneRecovery(t), t != nil
}

func (m *Manager) findBySubscriber(imsi, mac, apn string, activeOnly bool) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.byID {
		if activeOnly && s.State != Active {
			continue
		}
		if !subscriberMatches(s, imsi, mac, apn) {
			continue
		}
		return clone(s), true
	}
	return nil, false
}

func (m *Manager) update(id string, fn func(*Session)) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok {
		return nil, fmt.Errorf("session %q not found", id)
	}
	fn(s)
	s.UpdatedAt = time.Now().UTC()
	return clone(s), nil
}

func (m *Manager) transition(id string, next State, fn func(*Session)) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok {
		return nil, fmt.Errorf("session %q not found", id)
	}
	if !validTransition(s.State, next) {
		return nil, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, s.State, next)
	}
	fn(s)
	s.State = next
	s.UpdatedAt = time.Now().UTC()
	return clone(s), nil
}

func validTransition(from, to State) bool {
	if from == to {
		return true
	}
	if to == Failed {
		return from != Terminated
	}
	switch from {
	case Pending:
		return to == AuthPending || to == Terminating
	case AuthPending:
		return to == Authorized || to == Terminating
	case Authorized:
		return to == IPAllocated || to == PGWPending || to == Terminating
	case IPAllocated:
		return to == PGWPending || to == Terminating
	case PGWPending:
		return to == Active || to == Terminating
	case Active:
		return to == Terminating || to == Recovering
	case Recovering:
		return to == Terminating || to == Failed
	case Terminating:
		return to == Terminated
	case Terminated, Failed:
		return false
	default:
		return false
	}
}

func subscriberMatches(s *Session, imsi, mac, apn string) bool {
	if s == nil {
		return false
	}
	if imsi != "" && s.IMSI != "" && s.IMSI != imsi {
		return false
	}
	if mac != "" && s.MACAddress != "" && !macMatches(s.MACAddress, mac) {
		return false
	}
	if apn != "" && s.APN != "" && !sameAPN(s.APN, apn) {
		return false
	}
	if imsi != "" && s.IMSI == imsi {
		return true
	}
	if mac != "" && macMatches(s.MACAddress, mac) {
		return true
	}
	return false
}

func macMatches(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return normalizeMAC(a) == normalizeMAC(b)
}

func normalizeMAC(mac string) string {
	if hw, err := net.ParseMAC(mac); err == nil {
		return strings.ToLower(hw.String())
	}
	return strings.ToLower(mac)
}

func sameAPN(a, b string) bool {
	return strings.EqualFold(a, b)
}

func (m *Manager) indexRecoveryLocked(t *RecoveryTombstone) {
	if t == nil {
		return
	}
	if t.MAC != nil {
		m.recoveryByMAC[t.MAC.String()] = t
	}
	if t.IMSI != "" {
		m.recoveryByIMSI[t.IMSI] = t
	}
	if t.OldSubscriberIP != nil {
		m.recoveryByIP[t.OldSubscriberIP.String()] = t
	}
	if t.OldRemoteTEID != 0 {
		m.recoveryByRemoteT[t.OldRemoteTEID] = t
	}
}

func (m *Manager) unindexRecoveryLocked(t *RecoveryTombstone) {
	if t == nil {
		return
	}
	if t.MAC != nil {
		delete(m.recoveryByMAC, t.MAC.String())
	}
	if t.IMSI != "" {
		delete(m.recoveryByIMSI, t.IMSI)
	}
	if t.OldSubscriberIP != nil {
		delete(m.recoveryByIP, t.OldSubscriberIP.String())
	}
	if t.OldRemoteTEID != 0 {
		delete(m.recoveryByRemoteT, t.OldRemoteTEID)
	}
}

func (m *Manager) recoveryExpiredLocked(t *RecoveryTombstone) bool {
	if t == nil {
		return false
	}
	if !t.ExpiresAt.IsZero() && time.Now().UTC().After(t.ExpiresAt) {
		m.unindexRecoveryLocked(t)
		return true
	}
	return false
}

func (m *Manager) indexLocked(s *Session) {
	m.byID[s.ID] = s
	if s.IMSI != "" {
		m.byIMSI[s.IMSI] = s
	}
	if s.MACAddress != "" {
		m.byMAC[s.MACAddress] = s
	}
	if s.SubscriberIP != nil {
		m.byIP[s.SubscriberIP.String()] = s
	}
	if s.GTPCTEID != 0 {
		m.byTEID[s.GTPCTEID] = s
	}
}

func (m *Manager) unindexLocked(s *Session) {
	delete(m.byID, s.ID)
	delete(m.byIMSI, s.IMSI)
	delete(m.byMAC, s.MACAddress)
	if s.SubscriberIP != nil {
		delete(m.byIP, s.SubscriberIP.String())
	}
	if s.GTPCTEID != 0 {
		delete(m.byTEID, s.GTPCTEID)
	}
}

func clone(s *Session) *Session {
	if s == nil {
		return nil
	}
	cp := *s
	cp.SubscriberIP = cloneIP(s.SubscriberIP)
	cp.GatewayIP = cloneIP(s.GatewayIP)
	cp.PGWControlIP = cloneIP(s.PGWControlIP)
	cp.PGWUserIP = cloneIP(s.PGWUserIP)
	cp.RadiusClass = append([]byte(nil), s.RadiusClass...)
	return &cp
}

func cloneRecovery(t *RecoveryTombstone) *RecoveryTombstone {
	if t == nil {
		return nil
	}
	cp := *t
	cp.MAC = append(net.HardwareAddr(nil), t.MAC...)
	cp.OldSubscriberIP = cloneIP(t.OldSubscriberIP)
	cp.Class = append([]byte(nil), t.Class...)
	return &cp
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}
