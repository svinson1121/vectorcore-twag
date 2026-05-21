package radius

import (
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

type APObservation struct {
	SourceIP         string
	NASIP            string
	NASIdentifier    string
	CalledStationID  string
	AccountingPacket bool
}

type APRecord struct {
	SourceIP               string
	NASIP                  string
	NASIdentifier          string
	CalledStationID        string
	BSSID                  string
	SSID                   string
	FirstSeen              time.Time
	LastSeen               time.Time
	AuthRequestCount       uint64
	AccountingRequestCount uint64
}

type APRegistry struct {
	mu      sync.RWMutex
	records map[string]*APRecord
	log     *slog.Logger
}

func NewAPRegistry(log *slog.Logger) *APRegistry {
	return &APRegistry{records: make(map[string]*APRecord), log: log}
}

func (r *APRegistry) Update(obs APObservation) APRecord {
	now := time.Now().UTC()
	key := coalesceString(obs.SourceIP, obs.NASIP, obs.NASIdentifier, obs.CalledStationID)
	if key == "" {
		key = "unknown"
	}
	bssid, ssid := parseCalledStationID(obs.CalledStationID)
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.records[key]
	if rec == nil {
		rec = &APRecord{SourceIP: obs.SourceIP, FirstSeen: now}
		r.records[key] = rec
	}
	rec.LastSeen = now
	rec.SourceIP = coalesceString(obs.SourceIP, rec.SourceIP)
	rec.NASIP = coalesceString(obs.NASIP, rec.NASIP)
	rec.NASIdentifier = coalesceString(obs.NASIdentifier, rec.NASIdentifier)
	rec.CalledStationID = coalesceString(obs.CalledStationID, rec.CalledStationID)
	rec.BSSID = coalesceString(bssid, rec.BSSID)
	rec.SSID = coalesceString(ssid, rec.SSID)
	if obs.AccountingPacket {
		rec.AccountingRequestCount++
	} else {
		rec.AuthRequestCount++
	}
	if r.log != nil {
		r.log.Info("AP/NAS registry updated",
			"source_ip", rec.SourceIP,
			"nas_ip", rec.NASIP,
			"nas_identifier", rec.NASIdentifier,
			"called_station_id", rec.CalledStationID,
			"ssid", rec.SSID,
		)
	}
	return *rec
}

func parseCalledStationID(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	for _, sep := range []string{":", " "} {
		parts := strings.SplitN(value, sep, 2)
		if len(parts) != 2 {
			continue
		}
		if _, err := net.ParseMAC(parts[0]); err == nil {
			return strings.ToLower(parts[0]), strings.TrimSpace(parts[1])
		}
	}
	return "", ""
}
