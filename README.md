# obserwrt

Lightweight eBPF network observability for OpenWrt and plain Linux.

## What it is

obserwrt observes traffic on the netdevs you choose via TC ingress/egress eBPF
programs and tracks flows in a BPF hash map. A C++23 agent reads the map
periodically and exports the observations as IPFIX (Akvorado / goflow2) and
syslog.

## Why obserwrt instead of softflowd?

`softflowd` is the already-packaged OpenWrt option, but it sniffs packets into
userspace (`AF_PACKET`): every packet crosses the kernel↔user boundary and is
re-classified in userspace, so its CPU cost scales with the traffic *rate* and
low-end MIPS routers start dropping under load. It also doesn't follow OpenWrt
tunnels, which are torn down and recreated with a **new kernel ifIndex** on
`ifup`/`ifdown`.

obserwrt is built for how OpenWrt actually works:

- **In-kernel, exact accounting.** TC eBPF hooks see every packet and update the
  flow map; userspace work is proportional to the number of *flows*, not the
  packet/byte rate. No sampling, no userspace per-packet copies.
- **Follows recreated devices.** Devices are reconciled over rtnetlink, so a
  tunnel that appears, disappears, and reappears is always attached to its
  current incarnation — no restart, no stale snapshots.
- **Native IPFIX with the real kernel ifIndex.** Records carry the kernel
  interface index (never the reserved `0` for the observed direction), so
  Akvorado can correlate the exporter's interfaces with SNMP/interface
  enrichment out of the box — no silent drops on unknown 0-index interfaces.
- **More than a flow collector.** Syslog export, Prometheus textfile
  self-observability, delta accounting (no double-counting of active flows) and
  golden-vector + goflow2 e2e tests.

## Status

- **v0.3.2** — the ucode agent was rewritten in C++23 for the CPU/RAM footprint
  on MIPS routers; a real OpenWrt **mesh is live** exporting IPFIX into
  **Akvorado + ClickHouse**.
- **Design:** [`docs/design.md`](docs/design.md)

## Use as an OpenWrt feed

The repository is intended to be used directly as an OpenWrt package feed:

```sh
# feeds.conf / feeds.conf.default
src-git obserwrt https://github.com/vooon/obserwrt.git
```

```sh
./scripts/feeds update obserwrt
./scripts/feeds install obserwrt
```