package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestExtractToken(t *testing.T) {
	d := NewDNSServer("leak.example.test", NewStore(time.Minute), nil)
	cases := map[string]string{
		"ab12-a.deadbeef.leak.example.test.":     "deadbeef",
		"xy.token123.leak.example.test.":         "token123",
		"LEAK.EXAMPLE.TEST.":                     "", // apex, no token
		"something.else.com.":                    "", // out of zone
	}
	for name, want := range cases {
		if got := d.extractToken(name); got != want {
			t.Errorf("extractToken(%q) = %q, want %q", name, got, want)
		}
	}
}

// End-to-end: a query for a probe name is answered with the sink address AND the
// querying resolver is recorded against the session token.
func TestDNSObservation(t *testing.T) {
	store := NewStore(time.Minute)
	d := NewDNSServer("leak.example.test", store, []string{"ns1.leak.example.test"})
	udp, tcp, bound, err := StartServers(d, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer udp.Shutdown()
	defer tcp.Shutdown()

	sess := store.Create("leak.example.test", "203.0.113.9", 1, 0)
	probe := dns.Fqdn(sess.Probes[0])

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(probe, dns.TypeA)
	resp, _, err := c.Exchange(m, bound.String())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "192.0.2.1" {
		t.Fatalf("answer = %v, want A 192.0.2.1", resp.Answer[0])
	}

	obs := sess.Observations()
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1", len(obs))
	}
	if obs[0].ResolverIP != "127.0.0.1" {
		t.Errorf("resolver IP = %q, want 127.0.0.1", obs[0].ResolverIP)
	}
	if len(obs[0].QTypes) != 1 || obs[0].QTypes[0] != "A" {
		t.Errorf("qtypes = %v, want [A]", obs[0].QTypes)
	}
}

func TestOutOfZoneRefused(t *testing.T) {
	store := NewStore(time.Minute)
	d := NewDNSServer("leak.example.test", store, nil)
	udp, tcp, bound, err := StartServers(d, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer udp.Shutdown()
	defer tcp.Shutdown()

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("www.google.com.", dns.TypeA)
	resp, _, err := c.Exchange(m, bound.String())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

// fakeEnricher avoids real reverse-DNS lookups in the API test.
type fakeEnricher struct{}

func (fakeEnricher) Enrich(ip string) ResolverInfo {
	return ResolverInfo{IP: ip, PTR: "test.", ASN: "AS65000", Org: "TestNet", Country: "US"}
}

func TestAPIFlow(t *testing.T) {
	store := NewStore(time.Minute)
	api := &API{store: store, zone: "leak.example.test", enricher: fakeEnricher{}, probesV4: 3, probesV6: 2}
	srv := httptest.NewServer(api.routes())
	defer srv.Close()

	// 1. Create a session.
	resp, err := http.Post(srv.URL+"/v1/session", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	var created sessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if len(created.Probes) != 5 {
		t.Fatalf("got %d probes, want 5", len(created.Probes))
	}
	for _, p := range created.Probes {
		if !strings.Contains(p, created.Token) || !strings.HasSuffix(p, "leak.example.test") {
			t.Errorf("malformed probe %q", p)
		}
	}

	// 2. Simulate the authoritative server observing two resolvers.
	store.Record(created.Token, "8.8.8.8", "A")
	store.Record(created.Token, "1.1.1.1", "AAAA")

	// 3. Fetch results.
	resp, err = http.Get(srv.URL + "/v1/session/" + created.Token + "/results")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var results resultsResponse
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if results.Count != 2 {
		t.Fatalf("count = %d, want 2", results.Count)
	}
	seen := map[string]bool{}
	for _, r := range results.ObservedResolvers {
		seen[r.IP] = true
		if r.Org != "TestNet" {
			t.Errorf("enrichment missing for %s", r.IP)
		}
	}
	if !seen["8.8.8.8"] || !seen["1.1.1.1"] {
		t.Errorf("missing observed resolvers: %v", seen)
	}
}

func TestUnknownSession404(t *testing.T) {
	api := &API{store: NewStore(time.Minute), zone: "leak.example.test", enricher: fakeEnricher{}}
	srv := httptest.NewServer(api.routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/session/nope/results")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}
