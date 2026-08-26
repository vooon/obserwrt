# obserwrt

Lightweight eBPF Network Observability for OpenWrt.

- **Design:** [`docs/design.md`](docs/design.md)
- **Status:** v0.1 shipped; v0.2 (dataplane correctness) in progress; a full
  OpenWrt **mesh is live** exporting IPFIX into **Akvorado + ClickHouse**.
- **Features:** TC ingress/egress eBPF flow tracking; IPFIX and syslog
  (local or remote RFC 5424) exporters; Prometheus textfile self-observability;
  device reconciliation via netifd; feed package with CI + unit/e2e tests.

The repository is intended to be used directly as an OpenWrt package feed:

```sh
# feeds.conf / feeds.conf.default
src-git obserwrt https://github.com/vooon/obserwrt.git
```

```sh
./scripts/feeds update obserwrt
./scripts/feeds install obserwrt
```