# It Is Always DNS (`iiadns`) — Design

A comprehensive, platform-native DNS troubleshooting tool for macOS.
First iteration: **nail the fundamentals** of two features — **nslookup** (outbound: what does this name resolve to, from where, and why) and **DNS leak testing** (privacy: is my resolver actually who I think it is).

- **Platform:** macOS 26 (Tahoe), native Swift + SwiftUI, Liquid Glass.
- **Form factor:** main window (deep troubleshooting) + menu bar item (quick status / one-click leak check).
- **Distribution:** Developer ID, notarized (Homebrew cask / direct download). **Not sandboxed**, so we get full low-level networking.
- **Leak test:** **self-hosted backend** — our own authoritative DNS zone + reporting API (gold-standard accuracy).

---

## 1. Goals & non-goals

### v1 goals
- A DNS query tool that exposes what `dig`/`nslookup` expose, but with a native UI: arbitrary record types, explicit resolver selection, transport control, raw + decoded responses, latency, RCODE and header flags, and **side-by-side multi-resolver comparison** (the single most useful troubleshooting feature).
- A leak test that reports the resolvers that *actually* served your queries (observed at an authoritative server we control), enriched with reverse DNS / ASN / geo, and a clear **evidence-based verdict** — not a binary green light.
- A live view of the system's real DNS configuration (the `scutil --dns` picture), per interface, with VPN detection.
- Menu bar glance: current resolver(s), VPN active?, last leak verdict.

### Non-goals (v1)
- Encrypted transports in the resolver (DoH/DoT/DoQ) — designed for, deferred to v1.1.
- DNSSEC chain validation/visualization — deferred.
- iterative `dig +trace` from root — deferred.
- iOS/iPadOS — the engine is built portable, but no iOS target yet.
- Mac App Store build — Developer ID only for now.

### Design principle
> A troubleshooting tool earns trust by **showing its work**. Every result exposes the raw bytes, the exact server queried, and the timing. The leak test shows the evidence, then the verdict — never the verdict alone.

---

## 2. System architecture

Three components, in one repo:

```
┌─────────────────────────────────────────────┐
│  iiadns.app  (SwiftUI, macOS 26, Dev ID)     │
│  ┌────────────┐  ┌──────────────────────┐    │
│  │  Main win  │  │   MenuBarExtra        │    │
│  │ NavSplit:  │  │  resolver / VPN /     │    │
│  │  Lookup    │  │  last verdict         │    │
│  │  Leak Test │  └──────────────────────┘    │
│  │  Resolvers │                               │
│  │  History   │                               │
│  └────────────┘                               │
│         │ depends on                          │
│  ┌──────▼───────────────────────────────┐    │
│  │  DNSKit  (Swift Package)              │    │
│  │  Message codec · Transport (UDP/TCP) │    │
│  │  Resolver · SystemDNS · LeakClient   │    │
│  └──────────────────────────────────────┘    │
└───────────────┬──────────────────────────────┘
                │  HTTPS (session API)        DNS (system path)
                ▼                                  ▼
┌──────────────────────────┐        ┌──────────────────────────┐
│  leakd HTTP API          │◀──────▶│  leakd authoritative DNS  │
│  /v1/session  (issue)    │  logs  │  zone: leak.<domain>      │
│  /v1/session/{t}/results │◀───────│  logs resolver IP+token   │
│  enrichment: ASN/geo/PTR │        │  dual-stack, RRL          │
└──────────────────────────┘        └──────────────────────────┘
        self-hosted backend ("the price of gold-standard accuracy")
```

1. **`iiadns.app`** — the native macOS app (UI + orchestration).
2. **`DNSKit`** — a standalone Swift package: the DNS engine. Separated so it is unit-testable against golden wire-format vectors and reusable (future CLI / iOS).
3. **`leakd`** — the self-hosted leak-test backend: an authoritative DNS responder for a dedicated zone + an HTTP API that issues sessions and reports observed resolvers.

---

## 3. The macOS app

### 3.1 Stack & conventions
- **Swift 6**, strict concurrency. `async/await` throughout; DNS calls are `async` and cancellable.
- **SwiftUI**, target **macOS 26.0** (develop on the 26 SDK, use Liquid Glass natively). Lowering the deployment target to macOS 15 later is possible behind `if #available`; v1 keeps it simple at 26.0.
- **State:** the modern **MV pattern** with `@Observable` model classes (no ceremony-heavy MVVM). Views observe models; models call `DNSKit`.
- **Persistence:** **SwiftData** for history and saved resolver presets.
- **Scenes:** `WindowGroup` (main) + `MenuBarExtra` (`.menuBarExtraStyle(.window)` for a rich popover).

### 3.2 Main window — `NavigationSplitView`
Sidebar → detail. Sidebar sections:

| Section      | Purpose                                                            | v1 |
|--------------|-------------------------------------------------------------------|----|
| **Lookup**   | nslookup: query builder + results + multi-resolver compare        | ✅ |
| **Leak Test**| run test, show observed resolvers + verdict                       | ✅ |
| **Resolvers**| live system DNS config per interface, VPN detection               | ✅ |
| **History**  | past lookups & leak runs; re-run, compare, export                 | ✅ |

### 3.3 Lookup view (the nslookup feature)
**Query builder**
- Name field (FQDN or reverse target; auto-build `in-addr.arpa` / `ip6.arpa` for PTR).
- Record type: `A AAAA CNAME MX TXT NS SOA PTR SRV CAA ANY` (extensible enum; unknown types accepted as numeric).
- Resolver selector: **System default**, presets (Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9 `9.9.9.9`), or custom `IP[:port]`. Multi-select → fan-out.
- Transport: **UDP** (default, auto-fallback to TCP on truncation) or **TCP**. (DoH/DoT/DoQ greyed, "v1.1".)
- Advanced: Recursion Desired (RD), DNSSEC OK (DO bit via EDNS0), EDNS UDP buffer size, query timeout, retries.

**Results**
- Structured table: `name · type · TTL · class · rdata`, grouped by Answer / Authority / Additional section.
- Metadata bar: resolver used · transport · latency (ms) · RCODE (`NOERROR/NXDOMAIN/SERVFAIL/...`) · header flags (`AA TC RD RA AD CD`) · request/response sizes.
- **Raw view:** hex dump + decoded breakdown of the response packet.
- **Multi-resolver compare:** same query across selected resolvers, columns side-by-side; differences (different A records, TTLs, RCODEs, missing AD bit) highlighted. This is *the* "why does it resolve differently on my network" answer.
- One-click reverse lookup on any returned IP; copy as `dig`-style text; save to history.

### 3.4 Leak Test view
- One primary **Run Leak Test** button; live progress as probes resolve and results stream back.
- Shows:
  - **Your apparent public IP** (as seen by the API) + its ASN/org + geo.
  - **Configured resolvers** (from system config) — what the OS *says* it uses.
  - **Observed resolvers** (from the backend) — what *actually* served the queries — each with IP, reverse DNS, ASN/org, country/city.
  - **Verdict**: `Pass` / `Leak detected` / `Inconclusive`, with the specific evidence that drove it (see §5.5).
- Context strip: active network interface, VPN/`utun` active?, default-route interface.

### 3.5 Resolvers view
Live read of the system DNS picture (equivalent to `scutil --dns`), per interface/scope:
- Resolver addresses, ports, search domains, scoped/split resolvers.
- Which interface (Wi-Fi / Ethernet / VPN `utun`) and which is primary.
- Whether an encrypted-DNS profile (DoH/DoT) is configured at the OS level.
- Auto-refreshes on network change (SystemConfiguration notifications).

### 3.6 Menu bar (`MenuBarExtra`)
Compact popover: primary resolver(s) · VPN active? · last leak verdict + timestamp · buttons: **Run leak test**, **Open window**. Icon reflects state (neutral / VPN-on / last-leak-failed).

### 3.7 Permissions, entitlements, notarization
- **Hardened Runtime** (required for notarization). `com.apple.security.network.client` declared (harmless without sandbox; good hygiene).
- **`NSLocalNetworkUsageDescription`** in `Info.plist` — **required**: querying the system resolver or a router at an RFC1918 address triggers the macOS 26 local-network prompt. Message e.g.: *"iiadns queries DNS resolvers on your local network to diagnose name resolution and detect leaks."*
  - **Tahoe gotcha:** on macOS 26 the grant is currently dropped after reboot ([FB/dev-forum reports](https://developer.apple.com/forums//thread/792453)). Detect the symptom (local queries silently fail after a reboot) and surface an inline remediation: *"macOS may have reset local-network access. Toggle it in System Settings ▸ Privacy & Security ▸ Local Network."* Deep-link to that pane.
- No special entitlement needed for SystemConfiguration reads.
- Notarization pipeline in CI (codesign → notarytool → staple → DMG/cask).

---

## 4. `DNSKit` — the DNS engine (Swift package)

Standalone, no UI, fully unit-testable. Public surface is small; internals do the wire work.

### 4.1 Modules
- **`Message`** — DNS wire-format codec (RFC 1035) + EDNS0 (RFC 6891).
  - Encode: Header (ID, flags, counts), Question, optional OPT pseudo-RR (DO bit, UDP buffer size). No name compression on encode (simpler; legal).
  - Decode: full parser including **name compression** (`0xC0` pointers), RR sections (Answer/Authority/Additional).
  - RR types as an enum with typed rdata for `A AAAA NS CNAME SOA PTR MX TXT SRV CAA OPT`; unknown types preserved as raw rdata + numeric type (never drop data).
- **`Transport`**
  - **UDP**: `NWConnection(host:port:using:.udp)` — send query datagram, await response, parse; on `TC` (truncated) flag, retry over TCP.
  - **TCP**: `NWConnection(.tcp)` with the 2-byte length prefix (RFC 1035 §4.2.2); also used for large responses / AXFR-style needs later.
  - Timeouts, retries, and **parallel fan-out** to multiple servers (structured concurrency `TaskGroup`).
  - Seam for future **DoH** (URLSession, `application/dns-message`, RFC 8484), **DoT** (NWConnection + TLS :853), **DoQ** (QUIC :853, RFC 9250).
- **`Resolver`** — orchestration. `query(name:type:server:options) -> Answer`. `Answer` carries decoded sections + RCODE + flags + timing + the raw `Data`. Also `queryAll(servers:)` for the compare feature.
- **`SystemDNS`** — read the live system config via **SystemConfiguration** (`SCDynamicStore`): `State:/Network/Global/DNS` (global resolvers/search), per-service `State:/Network/Service/<id>/DNS`, `State:/Network/Global/IPv4` (primary service + interface). Enumerate interfaces; **detect VPN** (primary interface is `utunX`, or a VPN service owns the default route). Subscribe to change notifications. This is the programmatic `scutil --dns`.
- **`LeakClient`** — drives the leak-test protocol against `leakd` (§5).

### 4.2 Why a custom resolver (not `getaddrinfo` / `dns_sd`)?
- `getaddrinfo`/`nw_resolver` hide everything we need: you can't pick the server, see RCODE/flags/TTL/raw bytes, or query arbitrary types.
- `dns_sd` (`DNSServiceQueryRecord`) gives record-level access but routes through mDNSResponder's system path — you can't target an arbitrary server or see wire-level detail.
- Crafting wire format over `NWConnection(.udp)` to a chosen `host:port` gives total control, and Developer ID (non-sandboxed) distribution makes it frictionless. *(Confirmed viable in research.)*

### 4.3 Important: the leak test uses the **system path**, not the custom resolver
The Lookup feature targets explicit servers. The leak test must measure what the **OS/VPN actually does**, so `LeakClient` resolves probe hostnames via the **system resolution path** (`getaddrinfo` / `NWConnection` *by hostname*), **not** our custom resolver pointed at a fixed server. Getting this backwards would make the leak test meaningless. Called out here because it's the easiest mistake to make.

### 4.4 Testing
- Golden wire-format vectors (hand-built byte arrays ↔ decoded structs) for every supported RR type, including compression-pointer edge cases and malformed input (fuzz the decoder).
- Live integration tests against public resolvers (network-gated, skippable in CI offline).

---

## 5. `leakd` — the self-hosted leak-test backend

This is what "self-hosted, gold-standard" buys — and what it costs (you run authoritative DNS infra).

### 5.1 Principle
Determine which **recursive resolvers actually serve your queries** by observing them at an authoritative server we control. Resolvers reveal themselves the moment they walk the DNS chain to our zone.

### 5.2 Pieces
1. **Dedicated zone + authoritative server.** Delegate a zone you control — e.g. `leak.timvbs.com` (a subdomain you already own works; point its `NS` at the `leakd` hosts) or a separate throwaway domain to isolate risk. `leakd` answers authoritatively for `*.<token>.leak.<domain>` and logs each query.
   - **Dual-stack is mandatory** — without IPv6 (`AAAA` + reachable over v6) you miss IPv6 leaks, a common real case.
   - Recommend ≥2 authoritative instances for reliability.
2. **Session issue (API).** App calls `POST /v1/session` → returns a unique random `sessionToken` and **N probe hostnames**: `<rand>.<token>.leak.<domain>`. Generate, say, **25 A-only + 25 AAAA-only** names so caching can't mask a resolver and concurrent users never collide.
3. **Trigger resolution (client, system path).** App resolves each probe via the **system resolver** (§4.3). Those queries flow to whatever recursive resolvers the OS/VPN actually uses, which forward to `leakd`'s authoritative server.
4. **Authoritative logging.** `leakd` records, per query: source IP (the recursive resolver), qname (carries the token), qtype, timestamp; keyed by `sessionToken`.
5. **Results (API).** App polls `GET /v1/session/{token}/results` → observed resolver IPs, **enriched**: reverse DNS (PTR), **ASN + org** (Team Cymru / MaxMind ASN), **geo** (MaxMind GeoLite2). Plus the client's **apparent public IP** (source IP the HTTPS call arrived from) with its ASN/geo, for comparison.

### 5.3 Verdict logic (client-side, backend-enriched)
Inputs: client public IP ASN/geo · observed resolvers (ASN/geo/org) · system-configured resolvers · VPN-active flag.

Heuristics:
- VPN active **and** an observed resolver's ASN/org matches the **underlying ISP** (consumer-ISP ASN at your real geo) → **Leak**.
- Observed resolver country ≠ VPN exit country → **suspicious**.
- Configured resolver is a private/router IP but the **observed** resolver is your ISP (router forwards upstream) → classic **ISP leak**.
- Observed set includes unexpected orgs beyond the configured/expected resolvers → flag.

Output: `Pass` / `Leak detected` / `Inconclusive` **plus the evidence table**. Never a bare verdict; heuristics can be wrong, so show why.

### 5.4 Security, privacy, abuse (your responsibility now that it's self-hosted)
- **Amplification:** an authoritative server is a DDoS-amplification target. Mitigate: **authoritative-only (no recursion)**, **Response Rate Limiting (RRL)**, refuse/minimize `ANY`, keep responses small, answer only for our zone.
- **Privacy:** the backend inevitably sees resolver IPs and your public IP. Store only what's needed, **short TTL on session data** (purge ≤24h), no user identity, publish a privacy policy. Probe names are random tokens, not user data.
- **Transport:** TLS on the HTTP API; the authoritative server is necessarily plaintext DNS on :53 (resolvers reach it that way).
- **Rate-limit** the API per source.

### 5.5 Backend tech recommendation
- **Go** single binary using **`miekg/dns`** for the authoritative responder (battle-tested) + a small HTTP API in the same binary. Easy ops, trivial dual-stack.
  - *Alternative:* Swift-on-server (SwiftNIO) for stack uniformity — but the authoritative-DNS ecosystem is weaker; Go is the pragmatic pick.
- Enrichment data: **MaxMind GeoLite2** (City + ASN) loaded locally; optional Team Cymru IP-to-ASN as fallback.
- Deploy: containerized, ≥2 dual-stack hosts with stable IPs, `NS` delegation at the registrar. Keep v1 minimal.

---

## 6. Data model (SwiftData)

- **`LookupRecord`** — `id, timestamp, name, type, resolver, transport, options, rcode, flags, latencyMs, sections(Codable), rawResponse(Data)`.
- **`LeakTestRun`** — `id, timestamp, sessionToken, clientPublicIP, clientASN, clientGeo, vpnActive, configuredResolvers[], observedResolvers[](IP+PTR+ASN+geo), verdict, evidence`.
- **`SavedResolver`** — `name, address, port, transport` (picker presets).

---

## 7. Repository layout

```
itisalwaysdns/
├── README.md
├── DESIGN.md                  ← this document
├── apps/
│   └── iiadns/                Xcode project (SwiftUI app)
│       ├── iiadns/            scenes, views, @Observable models, Info.plist
│       ├── iiadnsTests/
│       └── iiadns.xcodeproj
├── packages/
│   └── DNSKit/                Swift Package (engine)
│       ├── Sources/DNSKit/    Message, Transport, Resolver, SystemDNS, LeakClient
│       └── Tests/DNSKitTests/ golden vectors + integration
└── server/
    └── leakd/                 Go: authoritative DNS + HTTP API
        ├── cmd/leakd/
        ├── internal/auth/     DNS responder (miekg/dns)
        ├── internal/api/      session + results
        ├── internal/enrich/   ASN/geo/PTR
        └── deploy/            Dockerfile, NS-delegation + infra notes
```

---

## 8. Build roadmap (fundamentals first)

| Phase | Deliverable | Why this order |
|-------|-------------|----------------|
| **0 — Skeleton** | Xcode app + `DNSKit` package + empty `leakd`; Dev ID signing; app shell with `NavigationSplitView` + `MenuBarExtra` placeholders; CI. | Walking skeleton end-to-end. |
| **1 — Engine + Lookup** | `Message` codec (tested), UDP + TCP-fallback transport, `Resolver`, Lookup UI incl. multi-resolver compare + raw view + history. | First shippable fundamental; pure client, no infra. |
| **2 — System DNS** | `SystemDNS` reader, VPN/interface detection, **local-network permission handling (+ Tahoe reboot remediation)**, Resolvers view, menu bar status. | Needed before the leak test, and valuable alone. |
| **3 — Leak backend** | `leakd`: zone delegated, authoritative responder, session API, ASN/geo/PTR enrichment, RRL + rate limits, dual-stack deploy. | Infra must exist before the client can test against it. |
| **4 — Leak client + verdict** | `LeakClient` (system-path probing), results polling, verdict engine, Leak Test UI. End-to-end VPN on/off validation. | Completes the second fundamental. |
| **5 — Polish** | History/export, Liquid Glass refinement, error/empty states, accessibility, notarization + cask. | Ship-ready. |

**Post-v1 stretch:** DoH/DoT/DoQ in the resolver · `dig +trace` iterative mode · DNSSEC chain visualization · query/result diffing · a CLI sharing `DNSKit` · encrypted-DNS profile management.

---

## 9. Key risks & decisions to watch

1. **Local-network privacy prompt + Tahoe reboot bug** — must include the usage string and ship in-app remediation. (§3.7)
2. **Leak test must use the system resolution path**, not the custom resolver — easiest mistake to make. (§4.3)
3. **Authoritative-server amplification abuse** — RRL, no recursion, no `ANY`, small responses. (§5.4)
4. **IPv6** — backend dual-stack or you miss real leaks. (§5.2)
5. **Verdict is heuristic** — present evidence, never a bare "you're safe." (§5.3)
6. **Backend ops cost** — the price of choosing gold-standard self-hosted accuracy; budget for ≥2 dual-stack hosts + a delegated zone.

---

## 10. Open questions
- **Domain for the leak zone:** delegate a subdomain of `timvbs.com` (cheap, fast) or register a dedicated domain (cleaner risk isolation)?
- **Minimum deployment target:** macOS 26.0 only (simplest, full Liquid Glass) vs. macOS 15+ (wider reach, some `#available` branches)?
- **Probe count / mix:** 25+25 (thorough) vs. a faster default (e.g. 10+10) with a "thorough" toggle?
- **Backend hosting:** which provider, and do you already have one with reliable dual-stack + static IPs?
