package main

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// DNSServer is the authoritative responder for the leak-test zone. It answers
// A/AAAA for any probe name with a non-routable sink address, logs the querying
// resolver, and refuses everything outside its zone.
//
// Abuse hardening: authoritative-only (never recursive), refuses out-of-zone,
// and treats ANY as NODATA so it can't be used for amplification. (Production
// should add per-source response-rate-limiting in front.)
type DNSServer struct {
	zone   string // lowercased, no trailing dot
	store  *Store
	ns     []string
	sinkV4 net.IP
	sinkV6 net.IP
	ttl    uint32
}

func NewDNSServer(zone string, store *Store, ns []string) *DNSServer {
	return &DNSServer{
		zone:   strings.ToLower(strings.TrimSuffix(zone, ".")),
		store:  store,
		ns:     ns,
		sinkV4: net.ParseIP("192.0.2.1").To4(), // RFC 5737 TEST-NET-1
		sinkV6: net.ParseIP("2001:db8::1"),     // RFC 3849 documentation range
		ttl:    10,
	}
}

func (d *DNSServer) fqdn() string { return d.zone + "." }

func (d *DNSServer) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) != 1 {
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	name := strings.ToLower(q.Name)
	zoneFqdn := d.fqdn()

	// Authoritative only for our zone — anything else is refused.
	if name != zoneFqdn && !strings.HasSuffix(name, "."+zoneFqdn) {
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	// Apex: serve SOA / NS.
	if name == zoneFqdn {
		switch q.Qtype {
		case dns.TypeSOA:
			m.Answer = append(m.Answer, d.soaRecord())
		case dns.TypeNS:
			for _, ns := range d.ns {
				m.Answer = append(m.Answer, &dns.NS{Hdr: d.hdr(zoneFqdn, dns.TypeNS), Ns: dns.Fqdn(ns)})
			}
		default:
			m.Ns = append(m.Ns, d.soaRecord())
		}
		_ = w.WriteMsg(m)
		return
	}

	// Probe query: log the resolver that reached us, then answer the sink.
	if token := d.extractToken(name); token != "" {
		d.store.Record(token, remoteIP(w.RemoteAddr()), dns.TypeToString[q.Qtype])
	}

	switch q.Qtype {
	case dns.TypeA:
		m.Answer = append(m.Answer, &dns.A{Hdr: d.hdr(q.Name, dns.TypeA), A: d.sinkV4})
	case dns.TypeAAAA:
		m.Answer = append(m.Answer, &dns.AAAA{Hdr: d.hdr(q.Name, dns.TypeAAAA), AAAA: d.sinkV6})
	default:
		// NODATA (including ANY — no amplification).
		m.Ns = append(m.Ns, d.soaRecord())
	}
	_ = w.WriteMsg(m)
}

// extractToken returns the label immediately to the left of the zone:
// "rand-a.<token>.leak.example.test." -> "<token>".
func (d *DNSServer) extractToken(name string) string {
	suffix := "." + d.fqdn()
	lower := strings.ToLower(name)
	if !strings.HasSuffix(lower, suffix) {
		return ""
	}
	prefix := strings.TrimSuffix(lower, suffix)
	if prefix == "" {
		return ""
	}
	labels := strings.Split(prefix, ".")
	return labels[len(labels)-1]
}

func (d *DNSServer) hdr(name string, t uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: d.ttl}
}

func (d *DNSServer) soaRecord() *dns.SOA {
	ns := "ns1." + d.fqdn()
	if len(d.ns) > 0 {
		ns = dns.Fqdn(d.ns[0])
	}
	return &dns.SOA{
		Hdr:     d.hdr(d.fqdn(), dns.TypeSOA),
		Ns:      ns,
		Mbox:    "hostmaster." + d.fqdn(),
		Serial:  1,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  60,
	}
}

func remoteIP(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.TCPAddr:
		return a.IP.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}

// StartServers brings up the authoritative responder on UDP and TCP at addr and
// returns both servers plus the bound UDP address (useful when addr uses port 0).
func StartServers(d *DNSServer, addr string) (udp, tcp *dns.Server, bound net.Addr, err error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, nil, nil, err
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		return nil, nil, nil, err
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", d.handle)
	udp = &dns.Server{PacketConn: pc, Handler: mux}
	tcp = &dns.Server{Listener: l, Handler: mux}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	return udp, tcp, pc.LocalAddr(), nil
}
