package ipam

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"

	"github.com/vectorcore/twag/internal/config"
)

type IPAM interface {
	Allocate(sessionID string) (net.IP, error)
	Release(sessionID string) error
	Lookup(sessionID string) (net.IP, bool)
}

type Lease struct {
	SessionID string `json:"session_id"`
	IP        net.IP `json:"ip"`
}

type Status struct {
	Pool        string  `json:"pool"`
	Gateway     net.IP  `json:"gateway"`
	TotalUsable int     `json:"total_usable"`
	Used        int     `json:"used"`
	Free        int     `json:"free"`
	Leases      []Lease `json:"leases"`
}

type MemoryIPAM struct {
	pool    *net.IPNet
	gateway net.IP
	log     *slog.Logger
	total   int

	mu       sync.Mutex
	leases   map[string]net.IP
	assigned map[string]string
}

func NewMemory(cfg config.IPAMConfig, log *slog.Logger) (*MemoryIPAM, error) {
	_, pool, err := net.ParseCIDR(cfg.Pool)
	if err != nil {
		return nil, err
	}
	gateway := net.ParseIP(cfg.Gateway).To4()
	if gateway == nil {
		return nil, fmt.Errorf("gateway must be IPv4")
	}
	if !pool.Contains(gateway) {
		return nil, fmt.Errorf("gateway %s is outside pool %s", gateway, pool)
	}
	total := usableCount(pool, gateway)
	if total == 0 {
		return nil, fmt.Errorf("ip pool %s has no usable subscriber addresses", pool)
	}
	log.Info("IPAM pool initialized", "pool", cfg.Pool, "gateway", gateway.String(), "usable_ips", total)
	return &MemoryIPAM{
		pool:     pool,
		gateway:  gateway,
		log:      log,
		total:    total,
		leases:   make(map[string]net.IP),
		assigned: make(map[string]string),
	}, nil
}

func (m *MemoryIPAM) Allocate(sessionID string) (net.IP, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session id is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ip, ok := m.leases[sessionID]; ok {
		return cloneIP(ip), nil
	}
	for ip := firstUsable(m.pool); m.pool.Contains(ip); incIPv4(ip) {
		if ip.Equal(m.gateway) || isBroadcast(m.pool, ip) {
			continue
		}
		key := ip.String()
		if _, ok := m.assigned[key]; ok {
			continue
		}
		lease := cloneIP(ip)
		m.leases[sessionID] = lease
		m.assigned[key] = sessionID
		m.log.Info("IP allocated", "session_id", sessionID, "subscriber_ip", lease.String())
		return cloneIP(lease), nil
	}
	return nil, fmt.Errorf("ip pool exhausted")
}

func (m *MemoryIPAM) Release(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ip, ok := m.leases[sessionID]
	if !ok {
		return nil
	}
	delete(m.leases, sessionID)
	delete(m.assigned, ip.String())
	m.log.Info("IP released", "session_id", sessionID, "subscriber_ip", ip.String())
	return nil
}

func (m *MemoryIPAM) Lookup(sessionID string) (net.IP, bool) {
	if sessionID == "" {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ip, ok := m.leases[sessionID]
	return cloneIP(ip), ok
}

func (m *MemoryIPAM) Gateway() net.IP { return cloneIP(m.gateway) }

func (m *MemoryIPAM) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	leases := make([]Lease, 0, len(m.leases))
	for sessionID, ip := range m.leases {
		leases = append(leases, Lease{SessionID: sessionID, IP: cloneIP(ip)})
	}
	sort.Slice(leases, func(i, j int) bool {
		return leases[i].SessionID < leases[j].SessionID
	})
	used := len(m.leases)
	return Status{
		Pool:        m.pool.String(),
		Gateway:     cloneIP(m.gateway),
		TotalUsable: m.total,
		Used:        used,
		Free:        m.total - used,
		Leases:      leases,
	}
}

func firstUsable(pool *net.IPNet) net.IP {
	ip := pool.IP.To4()
	if ip == nil {
		return nil
	}
	out := cloneIP(ip)
	incIPv4(out)
	return out
}

func usableCount(pool *net.IPNet, gateway net.IP) int {
	count := 0
	for ip := firstUsable(pool); ip != nil && pool.Contains(ip); incIPv4(ip) {
		if ip.Equal(gateway) || isBroadcast(pool, ip) {
			continue
		}
		count++
	}
	return count
}

func isBroadcast(pool *net.IPNet, ip net.IP) bool {
	ip4 := ip.To4()
	poolIP := pool.IP.To4()
	if ip4 == nil || poolIP == nil {
		return false
	}
	broadcast := make(net.IP, net.IPv4len)
	for i := 0; i < net.IPv4len; i++ {
		broadcast[i] = poolIP[i] | ^pool.Mask[i]
	}
	return ip4.Equal(broadcast)
}

func incIPv4(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}
