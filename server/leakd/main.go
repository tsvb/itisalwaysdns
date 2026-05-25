// Command leakd is the self-hosted DNS leak-test backend: an authoritative DNS
// responder for a delegated zone plus an HTTP API that issues test sessions and
// reports the resolvers observed querying the zone.
package main

import (
	"flag"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	zone := flag.String("zone", "leak.example.test", "authoritative zone (delegate this to leakd)")
	dnsAddr := flag.String("dns", ":53", "DNS listen address (needs root for :53)")
	httpAddr := flag.String("http", ":8080", "HTTP API listen address")
	nsList := flag.String("ns", "ns1.leak.example.test", "comma-separated NS names for the zone apex")
	v4 := flag.Int("probes-v4", 5, "IPv4 (A-only) probe names per session")
	v6 := flag.Int("probes-v6", 5, "IPv6 (AAAA-only) probe names per session")
	ttlMin := flag.Int("session-ttl-min", 30, "session lifetime in minutes")
	flag.Parse()

	zoneClean := strings.TrimSuffix(*zone, ".")

	store := NewStore(time.Duration(*ttlMin) * time.Minute)
	go store.purgeLoop(make(chan struct{}))

	dnsServer := NewDNSServer(zoneClean, store, strings.Split(*nsList, ","))
	udp, tcp, bound, err := StartServers(dnsServer, *dnsAddr)
	if err != nil {
		log.Fatalf("leakd: DNS listen failed: %v", err)
	}
	defer func() { _ = udp.Shutdown() }()
	defer func() { _ = tcp.Shutdown() }()
	log.Printf("leakd: authoritative for %q on %s (udp+tcp)", zoneClean, bound)

	api := &API{
		store:    store,
		zone:     zoneClean,
		enricher: newEnricher(),
		probesV4: *v4,
		probesV6: *v6,
	}
	log.Printf("leakd: HTTP API on %s", *httpAddr)
	log.Fatal(http.ListenAndServe(*httpAddr, api.routes()))
}
