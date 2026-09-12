# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

`obserwrt` — lightweight eBPF network observability for OpenWrt and plain Linux,
built on a C++23 agent (libbpf, rtnetlink, libuci). It observes traffic on
selected Linux netdevs via TC ingress/egress, tracks flows in a BPF hash map,
and exports normalized observations to IPFIX (Akvorado) and a syslog exporter.
The original ucode agent (≤ v0.2.6) was rewritten to C++ for the CPU/RAM
footprint of the ucode VM on low-end MIPS routers, released as v0.3.0, and the
ucode implementation removed; the eBPF program and the observation model are
unchanged.

Authoritative design: [`docs/design.md`](docs/design.md). Read it before making
architectural changes. Do not let the implementation drift from it. Sections
below link to it rather than restating it; keep them as pointers, not copies.

## Core rule (do not violate)

> **eBPF observes packets, the agent manages observations, exporters encode
> them, and downstream systems assign meaning.**

- eBPF only parses packets and updates the flow map. No IPFIX encoding, routing
  interpretation, service/DNS classification, topology, or BIRD logic in eBPF.
- obserwrt must not interpret BIRD/OSPF/BGP/VPN-hub/Akvorado semantics or
  whether an address is internal/external.
- A single packet may be observed multiple times across (ifindex, direction);
  obserwrt must **not** globally deduplicate.
- No implicit "attach to everything" default; observation points are explicit.
- Startup with zero matching devices is a successful READY state.

## Do not

- Expose real/internal device names or IPs in examples/docs — use generic
  placeholders (`awg0`, `awg_*`, `tun_*`, `br-lan`, `eth0`) and RFC 5737 test
  addresses (`192.0.2.0/24`, `198.51.100.0/24`).
- Implement an HTTP/metrics server in obserwrt.
- Add dependencies beyond those actually needed; keep the package lean.

## Locked design decisions

The authoritative detail lives in `docs/design.md`; do not change these without
deliberate, incompatible intent (see design §4/§5/§6/§8):

- **Wire format (§5):** flow key/value PODs live once in
  `bpf/obserwrt-flow.h` (shared by eBPF and the agent via `flow.hpp`), native
  byte order, `_Static_assert`-pinned sizes. Changing the key/value layout or an
  IPFIX metric NAME is a deliberate incompatibility.
- **Address normalization (§5.3):** IPv4 stored as IPv4-mapped IPv6 `::ffff:`
  in the 16-byte fields.
- **Interface identity (§6):** real kernel ifIndex via `if_nametoindex`, read at
  attach time; always attach to the current incarnation of a recreated device.
- **Reconciliation (§6.2):** rtnetlink only — startup `RTM_GETLINK`, live
  `RTM_NEWLINK`/`RTM_DELLINK`; no periodic rescan, no netifd/ubus.
- **IPFIX (§8.1):** two templates branching on the `::ffff:` prefix; big-endian
  wire encoding; `MAX_UDP` datagrams handed to the transport as `std::byte`
  spans.
- **Self-observability (§9):** Prometheus textfile collector only — obserwrt
  must **not** implement an HTTP server. No per-flow labels.

## Dependencies

Running the OpenWrt package: `libbpf`, `libuci`, `libstdcpp`. Plain Linux:
`libbpf1`, `libstdc++6`. Vendored single headers: `nlohmann/json`,
`inifile-cpp` (MIT). The eBPF object is built from source — via
`include/bpf.mk` (OpenWrt) or clang (Linux CMake) — never checked in.

## Layout

Source map (see design §11 for the full feed layout):

| path | role |
|------|------|
| `src/main.cpp` | epoll loop, exporters, reconcile wiring |
| `src/bpf.cpp` | libbpf: map, walk, tcx attach, stats |
| `src/lifecycle.cpp` | delta accounting + per-proto expiry |
| `src/reconcile.cpp` | rtnetlink dump + RTM_NEWLINK/RTM_DELLINK |
| `src/exporter_ipfix.cpp` | IPFIX (templates 256/257, chunking) |
| `src/exporter_syslog.cpp` | RFC 5424 json/logfmt, local/remote |
| `src/metrics.cpp` | Prometheus textfile + build_info |
| `src/config_uci.cpp` / `src/config_mini.cpp` | UCI / INI config backends |
| `src/udp_client.cpp` | dual-stack (v4/v6) remote UDP endpoint |
| `src/log.hpp` / `src/version.hpp` | DAEMON_LOG, build_info |
| `bpf/obserwrt-bpf.c` / `bpf/obserwrt-flow.h` | eBPF program + shared §5 header |
| `vendor/`, `linux/`, `obserwrt/files/` | headers, systemd unit/.conf, procd scripts |
| `tests/`, `scripts/` | golden harness + goflow2 e2e emitter |

## Commands

Checks (defined in `.github/workflows/ci.yml`):

```sh
# Native build + golden-vector harness (from the repo root; needs libbpf-dev)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DOBSEWRRT_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure

# Formatting + static analysis
clang-format --dry-run --Werror $(find src tests -name '*.[ch]pp')
clang-tidy -p build -checks="-*,clang-analyzer-*,bugprone-*,-bugprone-easily-swappable-parameters,performance-*" \
  -warnings-as-errors='*' src/*.cpp

# eBPF compile smoke, both byte orders (real headers, OpenWrt bpf.mk `uapi/` style)
# Needs the system kernel UAPI + libbpf headers (linux-libc-dev, libbpf-dev):
#   mkdir -p /tmp/uapi && ln -s /usr/include/linux /tmp/uapi/linux
#   inc="-I/tmp/uapi -I/usr/include/x86_64-linux-gnu -I/usr/include"
#   clang -O2 -g -target bpfel $inc -c bpf/obserwrt-bpf.c -o /tmp/bpfel.o
#   clang -O2 -g -target bpfeb $inc -c bpf/obserwrt-bpf.c -o /tmp/bpfeb.o
```

CI runs the native build/harness, the clang-format + clang-tidy gates, the eBPF
smoke, and a feed-layout check.

Run the daemon directly with `-c` during development:

```sh
# Plain Linux:
build/obserwrt -c linux/obserwrt.conf
# OpenWrt (after package install): /etc/init.d/obserwrt {start,restart,info}
```

## Testing (see also `.github/workflows/ci.yml`)

- **goflow2 e2e** (`scripts/test-ipfix.sh`, native): builds `obserwrt-emit`
  (`tests/emit_native.cpp`, drives the C++ `IpfixExporter`+`UdpClient` with a
  fixed IPv4 TCP + IPv6 UDP flow) and asserts an independent collector (goflow2
  via `GOFLOW2`/`docker`) decodes the expected fields. Run:
  `cmake --build build --target obserwrt-emit && OBSERWRT_EMIT=$PWD/build/obserwrt-emit sh scripts/test-ipfix.sh`
- **Golden harness** (`tests/harness.cpp`, `ctest`): pins the IPFIX v4/v6 wire
  bytes (templates 256/257 incl. IE 152/153), the §5 key/value layouts, the
  lifecycle delta/expiry contract, syslog JSON/logfmt/envelopes, the Prometheus
  exposition, and both config backends.

## Conventions

- **C++23**, exceptions-free (`-fno-exceptions`; inifile-cpp is the only TU
  compiled with `-fexceptions`), no iostream. Optimization follows the image/
  host toolchain (`-Os`/`-O2`); never hardcode it.
- Wire formats are owned by `bpf/obserwrt-flow.h` and the golden harness (see
  Locked design decisions).
- Big-endian safeness: the BPF map is native-endian; only the IPFIX wire
  encoding byte-swaps (via `std::byteswap` in the exporter).
- Daemon diagnostics go through `DAEMON_LOG` (`src/log.hpp`), gated by
  `main.log_level`; never `setlogmask()` (it would mute the syslog exporter's
  local flow records). Device/link events are observable at `debug`.
- Config lives behind the `Config` facade (`config_uci.cpp`/`config_mini.cpp`);
  one option set, two backends.
- Do not check in compiled `.o`/eBPF objects; build from source.
