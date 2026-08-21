# obserwrt

Lightweight eBPF Network Observability for OpenWrt.

- **Design:** [`docs/design.md`](docs/design.md)
- **Status:** initial design; implementation in progress (see design milestones).

The repository is intended to be used directly as an OpenWrt package feed:

```sh
# feeds.conf / feeds.conf.default
src-git obserwrt https://github.com/vooon/obserwrt.git
```

```sh
./scripts/feeds update obserwrt
./scripts/feeds install obserwrt
```
