# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

`obserwrt` — lightweight eBPF network observability for OpenWrt, built on ucode
and `ucode-mod-bpf`. It observes traffic on selected Linux netdevs via TC
ingress/egress, tracks flows in a BPF hash map, and exports normalized
observations to IPFIX (Akvorado) and a debug exporter.

Authoritative design: [`docs/design.md`](docs/design.md). Read it before making
architectural changes. Do not let the implementation drift from it.

## Core rule (do not violate)

> **eBPF observes packets, ucode manages observations, exporters encode them,
> and downstream systems assign meaning.**

- eBPF only parses packets and updates the flow map. No IPFIX encoding, routing
  interpretation, service/DNS classification, topology, or BIRD logic in eBPF.
- obserwrt must not interpret BIRD/OSPF/BGP/VPN-hub/Akvorado semantics or
  whether an address is internal/external.
- A single packet may be observed multiple times across (ifindex, direction);
  obserwrt must **not** globally deduplicate.
- No implicit "attach to everything" default; observation points are explicit.
- Startup with zero matching devices is a successful READY state.

## Key design decisions (locked)

- **Flow key (44 B, packed, native endian):** `u32 ifindex; u8 direction; u8
  family; u8 protocol; u8 reserved; u8 src[16]; u8 dst[16]; u16 sport; u16 dport`.
  struct format: `"<LBBBx16s16sHH"` (little-endian; use `>` prefix on big-endian
  targets). The reserved byte keeps `src`/`dst` 4-byte aligned.
- **Flow value (40 B):** `u64 packets; u64 bytes; u64 first_seen; u64 last_seen;
  u8 tcp_flags` (naturally aligned: counters must be 8-byte aligned for atomic
  increments). struct format `"<QQQQB7x"`.
- **Address normalization:** IPv4 stored as IPv4-mapped IPv6 `::ffff:a.b.c.d`
  in the 16-byte fields. `family` is retained in the key for alignment/debug.
- **Interface identity:** real kernel ifIndex, read at attach time via
  `if_nametoindex`. Recreated devices get a new ifIndex; always attach to the
  current incarnation. Never invent static obserwrt interface IDs.
- **Reconciliation (netifd-only in v1):** startup enumeration of existing
  devices, then subscribe to netifd `network.device` events and react to
  `add`/`up` (attach) and `remove`/`down` (detach + purge that device's
  entries). **No periodic rescan** in v1.
- **Self-observability:** Prometheus via the node-exporter textfile collector
  (`/run/prometheus/textfile/obserwrt.prom`, atomic temp+rename). obserwrt
  must **not** implement an HTTP server. No per-flow labels.
- **IPFIX:** `destination` accepts an IP or hostname (resolved via the target's
  resolver). Two templates branching on the `::ffff:` prefix — v4 emits
  `sourceIPv4Address`/`destinationIPv4Address` (last 4 bytes), otherwise IPv6
  IEs. Wire encoding via `struct.buffer()` / `struct.new('!…')`.

## Directory layout

```text
obserwrt/                     # OpenWrt package (also a feed root)
├── files/etc/config/obserwrt # UCI
├── files/etc/init.d/obserwrt # procd
├── files/usr/libexec/obserwrt/obserwrt.uc
└── src/obserwrt-bpf.c        # TC ingress/egress sections
```

The repo is used directly as an OpenWrt package feed; package sources under the
top-level `obserwrt/` package dir (all other top-level dirs, `.github`, `docs`,
are non-package).

## Dependencies

`ucode`, `ucode-mod-bpf`, `ucode-mod-ubus`, `ucode-mod-struct`. eBPF object is
built from source via `include/bpf.mk` (BPF toolchain), never checked in.

## Commands

Checks (defined in `.github/workflows/ci.yml`):

```sh
# Shell-syntax check the procd service (POSIX sh)
shellcheck obserwrt/files/etc/init.d/obserwrt

# ucode bytecode/compile check (no exec; `-c`)
ucode -c obserwrt/files/usr/libexec/obserwrt/obserwrt.uc

# eBPF compile smoke, both byte orders
clang -O2 -g -target bpfel -Iobserwrt/src/include -c obserwrt/src/obserwrt-bpf.c -o /tmp/bpfel.o
clang -O2 -g -target bpfeb -Iobserwrt/src/include -c obserwrt/src/obserwrt-bpf.c -o /tmp/bpfeb.o
```

There is no test suite yet; CI runs the above and a feed-layout check. Run them
after any change to `.uc`, `init.d`, or `.c`.

Run the ucode agent directly with a config-files path during development:

```sh
ucode -lstruct -lubus -lbpf -e 'import("obserwrt/files/usr/libexec/obserwrt/obserwrt.uc")'
```

## Conventions

- **ucode byte packing:** use `struct.pack`/`unpack`/`struct.buffer` from
  `ucode-mod-struct`. Do not hand-assemble byte strings or use `chr`/`ord`
  loops for binary structures.
- Match the native endianness of the eBPF object: `<` for little-endian targets
  (`bpfel`), `>` for big-endian (`bpfeb`).
- Blocking loops run on the procd/uloop event loop; keep the agent responsive
  while reconciling devices and reading the flow map.
- Do not check in compiled `.o`/eBPF objects; build from source.

## Do not

- Expose real/internal device names or IPs in examples/docs — use generic
  placeholders (`awg0`, `awg_*`, `tun_*`, `br-lan`, `eth0`) and RFC 5737 test
  addresses (`192.0.2.0/24`, `198.51.100.0/24`).
- Implement an HTTP/metrics server in obserwrt.
- Add dependencies beyond those actually needed; keep the package lean.
- Begin an IPFIX feature before the P0 TC-visibility probe is proven.

## Milestones (see design §13)

P0 TC visibility → P1 flow tracking → P2 dynamic devices → P3 debug export →
P4 IPFIX → P5 Akvorado → P6 real mesh. Gate each export/exporter step on the
prior probe.