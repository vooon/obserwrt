# obserwrt — Design

> Lightweight eBPF network observability for OpenWrt.
>
> Observe facts, not network policy. Observe what the Linux data plane
> actually saw, let downstream systems assign meaning.

## 1. Goal

`obserwrt` is an OpenWrt-native network observation agent built around eBPF
and ucode. It provides data-plane visibility:

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

**OpenWrt-native first.** v1 uses ucode, `ucode-mod-bpf`, ubus/netifd, UCI and
procd. The eBPF programs and the normalized observation model must nonetheless
avoid unnecessary OpenWrt-specific semantics so the same programs could be
reused by a future general Linux agent.

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
ucode
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

> eBPF observes packets, ucode manages observations, exporters encode them,
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
                  ucode-mod-bpf
                         │
                         ▼
                   obserwrt agent
                  ┌──────┴──────┐
                  │             │
            flow lifecycle   netifd/ubus
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

`struct`/`pack` format (little-endian targets): `"<LBBBx16s16sHHBB"`.
Big-endian targets use the `>` prefix. The leading reserved byte keeps `src` and
`dst` 4-byte aligned within the packed struct.

`direction` is 0 for ingress, 1 for egress. `family` and `protocol` are 8-bit
(the IP protocol number and address family are both ≤ 255), avoiding wasted 32-bit
fields while keeping a clean, aligned struct. `icmp_type`/`icmp_code` distinguish
ICMP flows (e.g. echo request vs reply) and are 0 for TCP/UDP; `sport`/`dport`
are 0 for ICMP.

### 5.2 Flow value (40 bytes, native endian)

The value keeps the `u64` counters **naturally aligned** (the 8-byte fields must
be 8-byte aligned so atomic increments are valid in BPF), so the packed/`struct`
size is 40 bytes (8×4 counters + a 16-bit `tcp_flags` + 6 trailing pad).

`struct`/`pack` format (little-endian targets): `"<QQQQH6x"`.

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

Initial behavior:

- inactive timeout ≈ 10 s;
- active timeout ≈ 60 s (re-export long-lived flows);
- expire inactive flows;
- exported on inactive expiry and periodically otherwise.

Timeouts become configurable later. Correctness and bounded memory outrank
sophisticated expiry in v1.

## 8. Exporters

Exporters consume normalized observations:

```text
emit(flow)
   ├── ipfix.emit(flow)
   └── syslog.emit(flow)
```

Additional exporters require no eBPF data-model changes. Dynamic plugin loading
is not required.

### 8.1 IPFIX exporter

- UDP, default port **4739**.
- IPFIX message headers, template sets, data sets, sequence numbers,
  observation domain, periodic template retransmission, batching multiple
  records per datagram, datagram sizing safely below ~1400 bytes unless
  configurable otherwise.
- Wire encoding with `struct.buffer()` / precompiled `struct.new('!…')`
  (network/big-endian, no padding).
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

Do not put individual flows into Prometheus labels. Future aggregate metrics may
expose e.g. `obserwrt_packets_total`, `obserwrt_bytes_total`,
`obserwrt_flows_active`, `obserwrt_flows_exported_total`,
`obserwrt_export_errors_total`, `obserwrt_bpf_map_entries`,
`obserwrt_devices_attached`.

Metrics are published via the **Prometheus textfile collector**: obserwrt writes
a `.prom` file (e.g. `/run/prometheus/textfile/obserwrt.prom`) that a node-exporter
instance scrapes. obserwrt does **not** implement an HTTP
server. Files are written atomically (temp file + rename) as an all-or-nothing
snapshot on each flow/export cycle. Prometheus is not required for the initial
flow-export milestone.

## 10. Configuration (UCI)

```uci
config obserwrt 'main'
    list device 'awg_*'
    option inactive_timeout '10'    # expire/delete idle flows after this (s)
    option active_timeout '60'      # active timeout: re-export long-lived flows

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
├── README.md
├── LICENSE
├── docs/design.md
└── obserwrt/
    ├── Makefile
    ├── files/etc/config/obserwrt
    ├── files/etc/init.d/obserwrt
    ├── files/usr/share/ucode/obserwrt/obserwrt.uc  # procd entry
    ├── files/usr/share/ucode/obserwrt/flow.uc
    ├── files/usr/share/ucode/obserwrt/reconcile.uc
    ├── files/usr/share/ucode/obserwrt/lifecycle.uc
    └── src/obserwrt-bpf.c
```

- Dependencies: `ucode`, `ucode-mod-bpf`, `ucode-mod-ubus`, `ucode-mod-struct`,
  `ucode-mod-log`
  (+ runtime eBPF support as needed). The eBPF object is built on-device-from-
  source via `include/bpf.mk` (BPF toolchain), not checked in as a binary.
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

## 13. Milestones

- **P0 — TC visibility:** prove decrypted traffic is visible on AWG netdevs.
  Sample `/127` AWG links carry ordinary inner IPv4; generate e.g. ping/iperf
  between the endpoints and confirm per-ifindex/direction/family/proto counter
  deltas on both ingress and egress.
- **P1 — Flow tracking:** 5-tuple accounting; validate against ping/TCP/UDP,
  IPv4/IPv6; compare against interface/tcpdump totals within explainable deltas.
- **P2 — Dynamic devices:** start with devices absent, then `ifup/ifdown/ifup`;
  verify daemon stays alive, attach auto-appears, deletion is harmless, new
  ifIndex used, other devices unaffected.
- **P3 — Syslog export:** validate normalized observations independent of IPFIX.
- **P4 — IPFIX:** capture with tcpdump/Wireshark; verify templates, data records,
  sequence behavior, IPv4/IPv6, interface IDs, timestamps, counters.
- **P5 — Akvorado:** flows accepted; src/dst correct; ingress/egress interface
  populated; SNMP resolves kernel ifIndex; BIRD/BMP enrichment continues to work.
- **P6 — Real mesh deployment:** observe `awg_*`, `tun_*`, WAN; query by real
  path/interface.

## 14. Non-goals for v1

Routing decisions; OSPF/BGP parsing; BIRD control; BMP; SNMP polling; DPI;
application/YouTube classification; DNS correlation; SOCKS flow correlation;
NAT/conntrack correlation; TCP RTT/retransmission analysis; anomaly detection;
topology reconstruction; general Linux packaging; sFlow; NetFlow v5/v9.

## 15. Future probes (architecture space only)

TCP health (retransmissions, RTT, connection latency, resets);
conntrack original↔translated tuple correlation; proxy/socket correlation
(e.g. hev-socks5-tunnel SOCKS associations); a native exporter able to carry
richer observations than standard IPFIX.

## 16. Release criteria (v0.1)

An OpenWrt user can: add the repo as a feed; build/install the package;
configure a device list + IPFIX/syslog collector; start with absent devices; create/
delete selected interfaces without restart; observe IPv4/IPv6 TCP/UDP/ICMP on
TC ingress/egress; export valid IPFIX with real kernel ifIndex; inspect the same
observations via syslog; consume the flows in Akvorado.
