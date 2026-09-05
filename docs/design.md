# obserwrt — Design

> Lightweight eBPF network observability for OpenWrt.
>
> Observe facts, not network policy. Observe what the Linux data plane
> actually saw, let downstream systems assign meaning.

## 1. Goal

`obserwrt` is an OpenWrt-native network observation agent built around eBPF
and a lightweight C++23 agent. It was introduced as a ucode agent; the ucode
VM's CPU/RAM footprint on low-end MIPS routers drove a rewrite in C++ (v0.2.6)
where the eBPF program and the normalized observation model stayed unchanged,
and the ucode implementation was removed. It provides data-plane visibility:

- who is communicating with whom;
- which Linux network device traffic actually traverses;
- whether traffic is ingress or egress;
- how many packets/bytes a flow carries;
- when flows start and stop;
- how traffic distribution changes over time.

The immediate deployment is an AmneziaWG VPN mesh, but AWG, BIRD, Akvorado and
the VPN topology are **not** part of the core data model. The agent must work on
arbitrary OpenWrt network devices: AWG/WireGuard, WAN, LAN/bridge, TUN, routed/
VXLAN, physical Ethernet.

## 2. Principles

**Observe facts, not policy.** obserwrt must not understand BIRD, OSPF, BGP,
VPN hubs, PBR, Akvorado, service identity, or whether an address is internal or
external. That meaning belongs to downstream enrichment.

**OpenWrt-native first, portable host.** v2 uses a C++23 agent (libbpf,
rtnetlink, libuci/libstdc++ on OpenWrt; a plain UDP/IPFIX/syslog/socket path on
Linux), UCI/procd on OpenWrt and a systemd/.conf path on plain Linux. The eBPF
programs and the normalized observation model must nonetheless avoid
unnecessary OpenWrt-specific semantics so the same programs could be reused by
a future general Linux agent.

**Backend-independent internal model.** IPFIX is the first production exporter
(Akvorado is the initial backend), but the internal flow representation must not
be designed as an IPFIX record.

```text
eBPF
  │
  ▼
raw flow state
  │
  ▼
obserwrt agent (C++23)
  │
  ▼
normalized observation
  │
  ├── IPFIX exporter
  ├── syslog exporter
  └── future exporters
```

**Dynamic interfaces are normal.** OpenWrt tunnel devices frequently disappear
during `ifdown` and receive a new kernel ifIndex when recreated. obserwrt must
start with zero configured devices present, attach automatically when devices
appear, tolerate disappearance, and re-attach using the current real kernel
ifIndex. It must never require all configured devices to exist at startup.

**Preserve the boundary:**

> eBPF observes packets, the agent manages observations, exporters encode them,
> and downstream systems assign meaning.

## 3. Architecture

```text
                  Linux network devices
                         │
                  TC ingress/egress
                         │
                         ▼
                    eBPF programs
                         │
                         ▼
BPF flow maps
                          │
                       libbpf
                          │
                          ▼
                   obserwrt agent
                  ┌──────┴──────┐
                  │             │
            flow lifecycle   rtnetlink
                  │          reconciliation
                  ▼
          normalized observations
                  │
             ┌────┴─────┐
              ▼          ▼
            IPFIX       debug
              │
              ▼
          Akvorado
```

TC (not XDP) is used because the observation point is a Linux netdev and both
ingress and egress observations matter. Traffic seen at one observation point is
a flow observation; a packet may legitimately be observed multiple times across
devices/directions and must not be globally deduplicated.

## 4. Flow identity

Initial flow-cache key:

```text
observation:
    ifindex
    direction          # INGRESS | EGRESS
network:
    family             # 4 | 6 (retained for struct alignment / debug parity)
    protocol
    source_address
    destination_address
transport:
    source_port
    destination_port

icmp:
    icmp_type          # for ICMP/ICMPv6, else 0
    icmp_code          # for ICMP/ICMPv6, else 0
```

The same 5-tuple observed on two interfaces, or on ingress and egress, is two
different observations.

The flow key is purely L3/L4: the **VLAN id and L2 MAC addresses are not part of it**.
This is unambiguous as long as each VLAN carries a distinct L3 subnet (the usual
case — every VLAN is a different `/24`), because the src/dst addresses already
separate flows across VLANs. **Caveat:** if two VLANs reuse overlapping L3
addresses (e.g. RFC 1918 reuse behind different VLANs on the same bridge), their
flows would collapse in the cache. In that situation the parser still reaches
the IP header correctly across up to two 802.1Q/802.1ad tags (VLANs are walked
to find L3, not dropped), but a future option could add `vlanId` to the key or
value to disambiguate. L2 MACs / VLAN id are currently only enrichment
candidates, not identity.

**Packet parsing** (in `obserwrt-bpf.c`): IPv6 walks up to 8 extension headers
(Hop-by-Hop, Routing, Destination Options, AH, Fragment); the IPv4 path
validates IHL ≥ 20. Non-first fragments (IPv4 offset ≠ 0, or an IPv6 Fragment
header with non-zero offset) carry no transport header, so they are accounted
as **IP-only** flows (`sport/dport/icmp = 0`, `proto` kept) — note this is a
*distinct* flow key from the first fragment (which has ports), so a fragmented
flow appears as two keys. Arbitrary IP protocols (OSPF 89, GRE 47, …) are
retained with ports 0, not dropped.

L2 is intentionally not part of identity (see above). MACs would become relevant
for bond member tracking or observing bridge/VXLAN; VXLAN-over-OSPF currently
appears as the outer UDP `4789` tunnel flow (and the OSPF underlay is now visible
as `proto=89`), while the *inner* MAC/IP would need VXLAN decapsulation — a
future parser extension, not planned for v1.

## 5. eBPF layout

### 5.1 Flow key (46 bytes, packed, native endian)

| field     | offset | struct    | width |
|-----------|--------|-----------|-------|
| ifindex   | 0      | `u32`     | 4     |
| direction | 4      | `u8`      | 1     |
| family    | 5      | `u8`      | 1     |
| protocol  | 6      | `u8`      | 1     |
| reserved  | 7      | `u8`      | 1     |
| src       | 8      | `u8[16]`  | 16    |
| dst       | 24     | `u8[16]`  | 16    |
| sport     | 40     | `u16`     | 2     |
| dport     | 42     | `u16`     | 2     |
| icmp_type | 44     | `u8`      | 1     |
| icmp_code | 45     | `u8`      | 1     |

The structs live once in `bpf/obserwrt-flow.h`, shared by the eBPF program and
the C++ agent (`flow.hpp` types them as `FlowKey`/`FlowValue`). Native byte
order on the local machine — the map is written and read on the same host.
The reported byte offsets above are the `_Static_assert`-pinned layout; the
reserved byte keeps `src` and `dst` 4-byte aligned within the packed struct.

`direction` is 0 for ingress, 1 for egress. `family` and `protocol` are 8-bit
(the IP protocol number and address family are both ≤ 255), avoiding wasted 32-bit
fields while keeping a clean, aligned struct. `icmp_type`/`icmp_code` distinguish
ICMP flows (e.g. echo request vs reply) and are 0 for TCP/UDP; `sport`/`dport`
are 0 for ICMP.

### 5.2 Flow value (40 bytes, native endian)

The value keeps the `u64` counters **naturally aligned** (the 8-byte fields must
be 8-byte aligned so atomic increments are valid in BPF), so the `struct`
size is 40 bytes (8×4 counters + a 16-bit `tcp_flags` + 6 trailing pad).

| field      | struct | width |
|------------|--------|-------|
| packets    | `u64`  | 8     |
| bytes      | `u64`  | 8     |
| first_seen | `u64`  | 8     |
| last_seen  | `u64`  | 8     |
| tcp_flags  | `u16`  | 2     |

`tcp_flags` is a 16-bit `tcpControlBits` (the standard low-8 TCP flags are
accumulated with OR across the flow's packets, never summed).

### 5.3 Address normalization

RPF: IPv4 addresses are stored in the 16-byte `src`/`dst` fields using IPv4-
mapped IPv6 notation `::ffff:a.b.c.d` (RFC 4291). A real IPv6 address never
starts with `::ffff:`, so the address form is unambiguous; `family` is retained
as a first-class field for struct alignment and debug parity.

### 5.4 eBPF responsibilities

Parse IPv4/IPv6 and TCP/UDP/ICMP, extract ports, read `skb->ifindex`, determine
ingress/egress from the attach point, and update counters/`tcp_flags`/
first-last seen timestamps.

**Not** in eBPF: IPFIX encoding, routing interpretation, service/DNS
classification, topology knowledge, BIRD integration.

## 6. Interface identity and reconciliation

Use the **real Linux kernel ifIndex**, read at attach time by
`if_nametoindex()` inside `tc_attach`. A recreated device therefore:

```text
awg0 ifIndex 17  →  delete/recreate  →  awg0 ifIndex 29
```

The lifecycle must attach the program to the new incarnation and never keep a
stale attachment active. Using the real ifIndex preserves interoperability with
SNMP and other tooling (IPFIX `OutIf=23` / SNMP `ifName.23`).

### 6.1 Model

```text
desired devices/patterns
        +
currently existing netdevs
        ↓
desired TC attachment state
```

### 6.2 Mechanism: netifd events only (v1)

- **Startup enumeration:** after connecting to ubus, enumerate current matching
  devices once and attach to anything already present. This covers starting after
  devices exist (netifd will not re-emit `add`).
- **Runtime events:** subscribe to netifd `network.device` and react to
  `add`/`up` (attach) and `remove`/`down` (detach + purge that device's entries).
  Events carry `name`, `present`, `active`, `link_active`.

Any interface that can be bound to a firewall zone must exist as a netifd device,
so external netdevs (openvpn tuns, VXLAN, TUN) surface as `network.device`
events too. This makes netifd authoritative for essentially every observation
point we would select.

- **No periodic rescan in v1.** A device configured by name but never managed by
  netifd (never zone-attached) will produce no events; that is a documented
  limitation. A `rescan_interval` toggle (0 = off) may be offered later.
- **Startup with zero matching devices is success** (service becomes READY).

## 7. Flow lifecycle

Packet: `lookup(key)` → `create/update` → `packets++`, `bytes += len`,
`last_seen = now`, accumulate `tcp_flags`. Userspace periodically reads the map.

Each pass hands the exporter the **delta** since the last export (the C++
`Lifecycle` tracks last-exported counters per flow key), so active flows
contribute their interval growth rather than cumulative totals — the sum of
deltas over a flow's lifetime equals its total, and the collector is not
double-counted. A flow with **no new traffic since the last pass is not
re-emitted** (its delta is zero, so the record would be valueless). The pass is
O(map size) in userspace, so this keeps per-tick work proportional to actual
activity rather than map occupancy; on large maps (sites run up to 32k flows)
every-tick re-export of idle flows pinned a core. The delta tracker is keyed by
the packed `FlowKey` struct (hash functor over the raw 46 bytes), and pruned
each pass so LRU-evicted flows do not leak state.

Flows idle longer than their **per-protocol** timeout are exported as expired
and deleted from the map (timeouts configurable, see §10):

- TCP ≈ 300 s, UDP ≈ 60 s, ICMP ≈ 30 s, other protocols ≈ 10 s;
- active flows with activity are re-exported on the lifecycle tick (active
  timeout stays informational; re-export cadence is the lifecycle tick).

Correctness and bounded memory outrank sophisticated expiry.

## 8. Exporters

Exporters consume normalized observations:

```text
emit(flow, delta)
   ├── ipfix.emit(flow, delta)
   └── syslog.emit(flow, delta)
```

Additional exporters require no eBPF data-model changes. Dynamic plugin loading
is not required.

### 8.1 IPFIX exporter

- UDP, default port **4739**.
- IPFIX message headers, template sets, data sets, sequence numbers,
  observation domain, periodic template retransmission, batching multiple
  records per datagram, datagram sizing safely below ~1400 bytes unless
  configurable otherwise.
- Wire encoding is big-endian (network byte order, no padding): the C++
  exporter builds `std::byte` datagram buffers with `std::byteswap` appenders
  and hands them to the owned UDP socket as spans.
- Two templates branching on the `::ffff:` prefix:
  - mapped `::ffff:*` → `sourceIPv4Address`/`destinationIPv4Address`
    (emitting only the final 4 bytes);
  - otherwise → `sourceIPv6Address`/`destinationIPv6Address`.
- Interface fields: ingress observation → `ingressInterface = ifIndex`,
  `egressInterface = 0`; egress observation → the reverse.
- The collector `destination` accepts either an IP address or a hostname
  (resolved via the target's resolver, e.g. `resolv`), as does the
  bind/source address.
- Abstract source-address selection with an optional bind/source-address option;
  no hard-coded backend assumptions.

Initial fields (IPv4/IPv6 records may use separate templates):

```text
sourceIPv4Address / sourceIPv6Address
destinationIPv4Address / destinationIPv6Address
sourceTransportPort
destinationTransportPort
protocolIdentifier
packetDeltaCount
octetDeltaCount
flowStartMilliseconds
flowEndMilliseconds
tcpControlBits
ingressInterface
egressInterface
```

### 8.2 Syslog exporter

The syslog exporter carries the normalized observation as JSON or logfmt. It is
intended for development, troubleshooting, and generic log pipelines; it does
not classify routes, services, or address scope.

- Empty `syslog_host` writes through the process-local OpenWrt syslog facility.
- A non-empty `syslog_host` is resolved once and sent over a connected UDP
  socket, default port **514**. An optional `source_address` pins the local
  source IP, mirroring the IPFIX exporter bind/source-address option.
- `protocol` is currently limited to `udp`; `tcp` is reserved for a future
  implementation.
- Remote messages use RFC 5424-compatible framing with `obserwrt` as the
  application name and an RFC 3339 UTC TIMESTAMP. The configurable `hostname`
  option (defaulting to the router hostname) fills the RFC 5424 HOSTNAME so a
  collector can tell which probe sent a message.
- The exporter includes both the numeric kernel `ifindex` and the current
  `ifname` for human readability; interface names are not used as identity.

Example JSON payload:

```json
{
  "ifindex": 17,
  "ifname": "awg0",
  "direction": "egress",
  "family": 4,
  "protocol": 6,
  "src": "192.0.2.10",
  "sport": 49152,
  "dst": "198.51.100.20",
  "dport": 443,
  "packets": 42,
  "bytes": 31981,
  "first_seen_ns": 123456789,
  "last_seen_ns": 123456999,
  "expired": false
}
```

## 9. Self-observability

Individual flows are **never** placed into Prometheus labels. Metrics come from
two sources, split honestly between BPF truth and userspace:

- **counters, BPF truth** (`obserwrt_stats` map, incremented in-kernel, exact
  even under LRU eviction):
  `obserwrt_packets_total` / `obserwrt_bytes_total` (everything the TC filter
  saw, including non-IP like ARP), `obserwrt_packets_accounted_total` (the
  subset that entered flow accounting — all IP, incl. non-first fragments and
  non-TCP/UDP/ICMP protocols), `obserwrt_flows_created_total` (new flow inserts).
  The `accounted/seen` ratio hence shows how much non-IP/unsupported traffic the
  observation point carries (useful on WAN/Ethernet; near 1 on AWG/L3).
- **counters, userspace**: `obserwrt_flows_exported_total`, `obserwrt_export_errors_total`.
- **gauges**: `obserwrt_flows_active`, `obserwrt_bpf_map_entries`,
  `obserwrt_bpf_map_limit` (baked to the built map size), `obserwrt_devices_attached`,
  and per-netdev `obserwrt_device_attached{ifname="..."}`.

Metrics are published via the **Prometheus textfile collector**: the C++
`metrics` module writes a `.prom` file atomically (temp file + rename,
all-or-nothing) that a node-exporter instance scrapes. obserwrt does **not**
implement an HTTP server. Formatting (labels, escaping) uses the internal
`prometheus` exposition builder. The feature is enabled by setting
`main.prometheus_textfile` to a writable path; `main.prometheus_interval`
(default 20s) is the cadence of a dedicated timer that rewrites the file,
independent of the 5s lifecycle flush.

The flow map is an **LRU hash**, so at capacity it evicts rather than failing;
saturation is visible as `obserwrt_bpf_map_entries` approaching
`obserwrt_bpf_map_limit`. LRU eviction itself is not directly observable;
signs of table pressure are high `obserwrt_flows_created_total` churn combined
with `obserwrt_bpf_map_entries` near the limit while userspace dispatched
counts lag behind flows created.

## 10. Configuration (UCI)

```uci
config obserwrt 'main'
    list device 'awg_*'
    option tcp_timeout '300'       # per-protocol idle timeouts (s)
    option udp_timeout '60'
    option icmp_timeout '30'
    option general_timeout '10'
    # option prometheus_textfile '/run/prometheus/textfile/obserwrt.prom'  # unset = disabled
    option prometheus_interval '20'

config exporter 'ipfix'
    option type 'ipfix'
    option destination 'collector.example.net'   # IP address or hostname
    option port '4739'
    option observation_domain '1'   # per-router observation domain

config exporter_syslog 'syslog'
    option enabled '0'
    option syslog_host ''       # empty = local syslog
    option syslog_port '514'
    option protocol 'udp'
    option format 'json'        # json or logfmt
    # option hostname ''        # RFC 5424 HOSTNAME; empty = router hostname
    # option source_address ''  # pin local source IP
```

`device` entries are exact Linux netdev names or simple glob patterns. Both
ingress and egress are attached to every selected device. There is **no
implicit attach-to-everything default**. No per-interface sections until a real
need for differing per-device behavior exists.

The lifecycle timeouts (`inactive_timeout`, `active_timeout`) live in the `main`
section, and the per-router IPFIX `observation_domain` in the exporter section,
so each router can carve out its own domain for multi-collector deployments.

Likely future options (only when actually needed):
`template_interval`, `max_flows`, `rescan_interval`.

## 11. Deployment (package)

- Feed layout puts everything under an `obserwrt/` package directory so the repo
  is directly usable as an OpenWrt feed:

```text
obserwrt/
├── CMakeLists.txt          # one build for OpenWrt (cmake.mk) and Linux (CPack)
├── src/                    # C++23 agent (main, flow, lifecycle, reconcile,
│                           #  bpf, exporter_ipfix/syslog, metrics, config_*)
├── bpf/                    # eBPF program + shared §5 flow layout
│   ├── obserwrt-bpf.c      # TC ingress/egress flow observation
│   └── obserwrt-flow.h     # flow_key/flow_val PODs (single source)
├── vendor/                 # 3rd-party headers (nlohmann/json, inifile-cpp)
├── linux/                  # systemd unit + .conf for the plain-Linux .deb
├── obserwrt/
│   ├── Makefile            # OpenWrt package (cmake.mk + bpf.mk)
│   └── files/obserwrt.init # procd script (flat)
│   └── files/obserwrt.conf # UCI config (flat)
└── tests/, scripts/        # golden harness + goflow2 e2e (native emitter)
```

- Dependencies (OpenWrt): `libbpf`, `libuci`, `libstdcpp` (+ runtime eBPF
  support as needed). On plain Linux: `libbpf1`, `libstdc++6`. The eBPF object
  is built on-device-from-source via `include/bpf.mk` (OpenWrt) or clang
  (Linux CMake), not checked in as a binary.
- procd service: starts at boot, respawns on failure, does not fail when
  configured devices are absent.
- No auto-attach to every interface after installation.

## 12. Akvorado integration

Expected integration:

```text
obserwrt → IPFIX → Akvorado → {SNMP interface enrichment, BIRD BMP routing,
                               ClickHouse}
```

Using the real kernel ifIndex lets Akvorado correlate IPFIX interface IDs with
SNMP interface data. Backend-specific workarounds stay confined to the IPFIX
exporter.

**Live (v0.2/soak):** flows land in the ClickHouse **`default`** database:
`default.flows` (raw, ~37M rows and growing), rolled-up `flows_1m0s`/`_5m0s`/`_1h0m0s`,
and the `exporters` (294), `asns`, `protocols`, `tcp`, `udp`, `icmp` dimensions.
`ExporterSite` currently shows **6 mesh sites**. Outlet enrichment (SNMP
ifIndex->name, BGP ASN/routing) is active; a few spokes still need an snmpd
answering at the expected community so their interface names resolve.

## 13. Milestones

Status of the roadmap items (`[x]` = done, `[~]` = partial, `[ ]` = open):

- **[x] P0 — TC visibility:** decrypted traffic visible on AWG netdevs; confirmed
  per-ifindex/direction/family/proto on ingress and egress.
- **[x] P1 — Flow tracking:** 5-tuple accounting validated against live traffic.
- **[x] P2 — Dynamic devices:** `ifup/ifdown/ifup` attach/detach verified on
  target, new ifIndex used, recreated devices handled.
- **[x] P3 — Syslog export:** local (logd) and remote (RFC 5424 to VictoriaLogs)
  both verified on-device.
- **[x] P4 — IPFIX:** emitted flows decode live; goflow2 -> Akvorado inlet.
- **[x] P5 — Akvorado:** flows reach the real Akvorado (inlet -> Kafka -> outlet ->
  ClickHouse), with SNMP ifIndex/interface enrichment and BGP routing enrichment.
- **[~] P6 — Real mesh deployment:** **soak is live.** obserwrt is running across
  the mesh into Akvorado/ClickHouse; ~37M flows ingested, **6 mesh sites**,
  294 exporters, 1m/5m/1h aggregations running. Long-term monitoring of map
  occupancy, `flows_created` churn, `accounted/seen`, CPU/mem continues; bridge/
  bond and VXLAN observations remain open v0.3 items.

## 14. Non-goals for v1

Routing decisions; OSPF/BGP parsing; BIRD control; BMP; SNMP polling; DPI;
application/YouTube classification; DNS correlation; SOCKS flow correlation;
NAT/conntrack correlation; TCP RTT/retransmission analysis; anomaly detection;
topology reconstruction; general Linux packaging; sFlow; NetFlow v5/v9.
(Note: OSPF/GRE and other arbitrary IP protocols are *observed* as `proto`
flows — that is accounting, not protocol parsing.)

## 15. Future probes (architecture space only)

TCP health (retransmissions, RTT, connection latency, resets);
conntrack original↔translated tuple correlation; proxy/socket correlation
(e.g. hev-socks5-tunnel SOCKS associations); a native exporter able to carry
richer observations than standard IPFIX.

## 16. Release criteria

### v0.1 — met (initial end-to-end)

An OpenWrt user can: add the repo as a feed; build/install the package;
configure a device list + IPFIX/syslog collector; start with absent devices;
create/delete selected interfaces without restart; observe IPv4/IPv6
TCP/UDP/ICMP on TC ingress/egress; export valid IPFIX with real kernel ifIndex;
see the same observations via syslog; consume the flows in Akvorado/goflow2.
Unit tests + CI (static, native golden harness, goflow2 e2e via the native
emitter) are in place.

### v0.2 — in progress (dataplane correctness; released as `0.2`)

- Packet-parser hardening: IPv6 extension-header walk, IPv4/IPv6 fragmentation
  (non-first fragments accounted as IP-only flows), Ethernet EtherType + 1/2
  VLAN tags, arbitrary-IP-protocol preservation, IPv4 IHL validation.
- BPF-truth metrics (packets/bytes/accounted/flows-created) + configurable
  (Kconfig) flow-map size baked into `bpf_map_limit`.
- **Active-flow delta accounting** so repeated active exports don't double-count.
- Per-protocol idle timeouts (tcp/udp/icmp/general).
- Flows confirmed correct (not just present) in Akvorado/ClickHouse; full-mesh
  soak running (see §12/§13).

### v0.3 — targets

The aim is to make obserwrt trustworthy across the whole mesh / LAN:

- **Soak (ONGOING):** multi-spoke/hub run over `awg_*`, `tun_*`, WAN, and
  bridges; ~37M flows in ClickHouse across 6 sites as of the v0.2 unlock. Watch
  map occupancy, `flows_created`, `accounted/seen`, CPU/mem, and validate
  against interface counters/tcpdump over days, not hours.
- **Bridge / bond observation** (`br-ex`, `br-lan`, bond members): decide and
  implement the L2 story — likely `vlan_id`/`src_mac` as value enrichment/IPFIX
  IEs, with an explicit decision whether any of it belongs in the key.
- **VXLAN-over-OSPF fabric**: decide whether inner-flow (decapsulated) identity
  is wanted; if so add VXLAN decap parsing; confirm OSPF-underlay visibility.
- Per-protocol/more-precise expiry and any LRU/map-sizing follow-up driven by
  the soak's measurements, not by theory.
- **Live flow-map limit (done).** The C++ agent reads the real
  `bpf_map_info.max_entries` directly via libbpf (no module patch); the map
  size is set at load from `main.max_flows` (or the baked 4096 default), and
  `obserwrt_bpf_map_limit` reflects the live value.
