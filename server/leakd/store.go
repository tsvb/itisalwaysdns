package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Observation is one recursive resolver caught querying our authoritative server
// for a session's probe names.
type Observation struct {
	ResolverIP string    `json:"resolver_ip"`
	FirstSeen  time.Time `json:"first_seen"`
	QTypes     []string  `json:"qtypes"`
}

// Session is one leak test: a set of unique probe names and the resolvers that
// have been observed resolving them.
type Session struct {
	Token     string    `json:"token"`
	Probes    []string  `json:"probes"`
	ClientIP  string    `json:"client_ip"`
	CreatedAt time.Time `json:"created_at"`

	mu       sync.Mutex
	observed map[string]*Observation // keyed by resolver IP
}

// Observations returns a snapshot copy, safe to read without holding the lock.
func (s *Session) Observations() []Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Observation, 0, len(s.observed))
	for _, o := range s.observed {
		out = append(out, *o)
	}
	return out
}

// Store is an in-memory session store with TTL-based purging. Sessions hold only
// resolver IPs and random tokens — no user identity — and expire quickly.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
}

func NewStore(ttl time.Duration) *Store {
	return &Store{sessions: map[string]*Session{}, ttl: ttl}
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Create issues a new session with v4 A-only and v6 AAAA-only probe names. Each
// probe carries a unique random label so resolver caching can't mask anyone and
// concurrent sessions never collide.
func (s *Store) Create(zone, clientIP string, v4, v6 int) *Session {
	token := randToken(8) // 16 hex chars, DNS-label safe
	probes := make([]string, 0, v4+v6)
	for i := 0; i < v4; i++ {
		probes = append(probes, randToken(4)+"-a."+token+"."+zone)
	}
	for i := 0; i < v6; i++ {
		probes = append(probes, randToken(4)+"-aaaa."+token+"."+zone)
	}
	sess := &Session{
		Token:     token,
		Probes:    probes,
		ClientIP:  clientIP,
		CreatedAt: time.Now(),
		observed:  map[string]*Observation{},
	}
	s.mu.Lock()
	s.sessions[token] = sess
	s.mu.Unlock()
	return sess
}

func (s *Store) Get(token string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[token]
	return sess, ok
}

// Record notes that resolverIP queried for a probe belonging to token. Returns
// false if the token is unknown (so the authoritative server doesn't accumulate
// observations for sessions that don't exist).
func (s *Store) Record(token, resolverIP, qtype string) bool {
	s.mu.RLock()
	sess, ok := s.sessions[token]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	obs, exists := sess.observed[resolverIP]
	if !exists {
		obs = &Observation{ResolverIP: resolverIP, FirstSeen: time.Now()}
		sess.observed[resolverIP] = obs
	}
	for _, q := range obs.QTypes {
		if q == qtype {
			return true
		}
	}
	obs.QTypes = append(obs.QTypes, qtype)
	return true
}

// purgeLoop removes sessions older than the TTL once a minute.
func (s *Store) purgeLoop(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			cutoff := time.Now().Add(-s.ttl)
			s.mu.Lock()
			for token, sess := range s.sessions {
				if sess.CreatedAt.Before(cutoff) {
					delete(s.sessions, token)
				}
			}
			s.mu.Unlock()
		}
	}
}
