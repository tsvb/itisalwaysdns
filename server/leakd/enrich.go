package main

import "net"

// ResolverInfo is an observed resolver IP plus the enrichment a verdict relies on.
type ResolverInfo struct {
	IP      string `json:"ip"`
	PTR     string `json:"ptr,omitempty"`
	ASN     string `json:"asn,omitempty"`
	Org     string `json:"org,omitempty"`
	Country string `json:"country,omitempty"`
}

// Enricher turns a bare resolver IP into something a human (or the verdict engine)
// can reason about.
type Enricher interface {
	Enrich(ip string) ResolverInfo
}

// GeoASN is the pluggable IP-to-ASN/geo source. Wire a MaxMind GeoLite2 reader
// here in production; the null implementation keeps the rest honest meanwhile.
type GeoASN interface {
	Lookup(ip string) (asn, org, country string)
}

type nullGeoASN struct{}

func (nullGeoASN) Lookup(string) (string, string, string) { return "", "", "" }

// defaultEnricher does a real reverse-DNS (PTR) lookup and delegates ASN/geo.
type defaultEnricher struct {
	geo GeoASN
}

func newEnricher() defaultEnricher { return defaultEnricher{geo: nullGeoASN{}} }

func (e defaultEnricher) Enrich(ip string) ResolverInfo {
	info := ResolverInfo{IP: ip}
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		info.PTR = names[0]
	}
	if e.geo != nil {
		info.ASN, info.Org, info.Country = e.geo.Lookup(ip)
	}
	return info
}
