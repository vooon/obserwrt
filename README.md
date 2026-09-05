# obserwrt

Lightweight eBPF Network Observability for OpenWrt and plain Linux.

- **Design:** [`docs/design.md`](docs/design.md)
- **Status:** v0.3.0 — the ucode agent was rewritten in C++23 (CPU/RAM
  footprint on MIPS routers); a real OpenWrt **mesh is live** exporting IPFIX
  into **Akvorado + ClickHouse**.
- **Features:** TC ingress/egress eBPF flow tracking; IPFIX and syslog
  exporters; Prometheus textfile self-observability; dynamic device
  reconciliation over rtnetlink; structured diagnostics (logfmt); feed package
  with CI, golden-vector harness and goflow2 e2e tests.

The eBPF program and the C++ agent share one wire-format header
(`bpf/obserwrt-flow.h`); the agent reads the flow map natively, so there is no
packing layer between the two.

The repository is intended to be used directly as an OpenWrt package feed:

```sh
# feeds.conf / feeds.conf.default
src-git obserwrt https://github.com/vooon/obserwrt.git
```

```sh
./scripts/feeds update obserwrt
./scripts/feeds install obserwrt
```