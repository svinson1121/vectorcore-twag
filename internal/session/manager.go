package session

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

type CreateInput struct {
	IMSI            string
	MSISDN          string
	MACAddress      string
	APN             string
	Realm           string
	AccessType      string
	AccessInterface string
	GatewayIP       net.IP
	TTL             time.Duration
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
}

var ErrInvalidTransition = errors.New("invalid session state transition")

func NewManager(log *slog.Logger) *Manager {
	return &Manager{
		log:    log,
		byID:   make(map[string]*Session),
		byIMSI: make(map[string]*Session),
		byMAC:  make(map[string]*Session),
		byIP:   make(map[string]*Session),
		byTEID: make(map[uint32]*Session),
	}
}

func (m *Manager) Create(input CreateInput) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	now := time.Now().UTC()
	s := &Session{
		ID:              fmt.Sprintf("twag-%d-%d", now.UnixNano(), m.next),
		IMSI:            input.IMSI,
		MSISDN:          input.MSISDN,
		MACAddress:      input.MACAddress,
		APN:             input.APN,
		Realm:           input.Realm,
		AccessType:      input.AccessType,
		AccessInterface: input.AccessInterface,
		GatewayIP:       cloneIP(input.GatewayIP),
		State:           Pending,
		CreatedAt:       now,
		UpdatedAt:       now,
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
	return clone(s), ok
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
		return to == IPAllocated || to == Terminating
	case IPAllocated:
		return to == PGWPending || to == Terminating
	case PGWPending:
		return to == Active || to == Terminating
	case Active:
		return to == Terminating
	case Terminating:
		return to == Terminated
	case Terminated, Failed:
		return false
	default:
		return false
	}
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
	return &cp
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}
