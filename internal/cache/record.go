package cache

import (
	"bytes"
	"encoding/json"
	"math"
)

// Record is the JSON value stored as the credential-store secret. The field
// order and names match the Python helper so existing entries stay readable.
type Record struct {
	Password   string  `json:"password"`
	CreatedAt  float64 `json:"created_at"`
	TTLSeconds int     `json:"ttl_seconds"`
}

// Meta is the non-secret part of a record.
type Meta struct {
	CreatedAt  float64
	TTLSeconds int
}

// Fresh reports whether a record created at m.CreatedAt is still inside both
// its original TTL and the currently configured ttl. The deadline never slides.
func Fresh(m *Meta, ttl int, now float64) bool {
	if m == nil || ttl <= 0 || m.TTLSeconds <= 0 {
		return false
	}
	if math.IsNaN(m.CreatedAt) || math.IsInf(m.CreatedAt, 0) {
		return false
	}
	age := now - m.CreatedAt
	return age >= 0 && age < float64(min(ttl, m.TTLSeconds))
}

// ParseRecord decodes a stored secret. Malformed values yield nil.
func ParseRecord(data []byte) *Record {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(data), &raw); err != nil {
		return nil
	}
	var r Record
	if json.Unmarshal(raw["password"], &r.Password) != nil {
		return nil
	}
	// Reject booleans and strings; accept integer or float timestamps.
	if json.Unmarshal(raw["created_at"], &r.CreatedAt) != nil {
		return nil
	}
	if json.Unmarshal(raw["ttl_seconds"], &r.TTLSeconds) != nil {
		return nil
	}
	return &r
}

// Meta returns the non-secret part of r.
func (r *Record) Meta() *Meta {
	if r == nil {
		return nil
	}
	return &Meta{CreatedAt: r.CreatedAt, TTLSeconds: r.TTLSeconds}
}

// Encode serialises r for storage.
func (r Record) Encode() []byte {
	data, _ := json.Marshal(r)
	return data
}
