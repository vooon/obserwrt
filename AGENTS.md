# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

`obserwrt` — lightweight eBPF network observability for OpenWrt and plain Linux,
built on a C++23 agent (libbpf, rtnetlink, libuci). It observes traffic on
selected Linux netdevs via TC ingress/egress, tracks flows in a BPF hash map,
and exports normalized observations to IPFIX (Akvorado) and a syslog exporter.
Until v0.2.6 the agent was implemented in ucode; it was rewritten in C++ for
the CPU/RAM footprint of the ucode VM on low-end MIPS routers (the eBPF
program and the observation model are unchanged).

Authoritative design: [`docs/design.md`](docs/design.md). Read it before making
architectural changes. Do not let the implementation drift from it.

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

## Key design decisions (locked)

- **Flow key (46 B, packed, native endian):** `u32 ifindex; u8 direction; u8
  family; u8 protocol; u8 icmp_type; u8 icmp_code; u8 reserved; u8 src[16]; u8
  dst[16]; u16 sport; u16 dport`.
  struct format: `"<LBBBx16s16sHHBB"` (little-endian; use `>` prefix on big-endian
  targets). The reserved byte keeps `src`/`dst` 4-byte aligned; `icmp_type`/
  `icmp_code` are 0 for TCP/UDP, and `sport`/`dport` are 0 for ICMP.
- **Flow value (40 B):** `u64 packets; u64 bytes; u64 first_seen; u64 last_seen;
  u16 tcp_flags` (naturally aligned: counters must be 8-byte aligned for atomic
  increments). `tcp_flags` is a 16-bit `tcpControlBits` union (only the standard
  low-8 TCP flags are accumulated; use OR, not sum). struct format `"<QQQQH6x"`.
- **Address normalization:** IPv4 stored as IPv4-mapped IPv6 `::ffff:a.b.c.d`
  in the 16-byte fields. `family` is retained in the key for alignment/debug.
- **Interface identity:** real kernel ifIndex, read at attach time via
  `if_nametoindex`. Recreated devices get a new ifIndex; always attach to the
  current incarnation. Never invent static obserwrt interface IDs.
- **Reconciliation (rtnetlink):** startup `RTM_GETLINK` enumeration of existing
  devices, then subscribe to live `RTM_NEWLINK`/`RTM_DELLINK` (the group must
  be in the `bind()` sockaddr — `netlink_bind` replaces prior setsockopt
  membership). `up`/`add` -> attach, `down`/remove -> detach + purge that
  device's entries. A rename of an attached device detaches when it no longer
  matches, else refreshes the stored name. **No periodic rescan.**
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
├── CMakeLists.txt            # one build for OpenWrt (cmake.mk) and Linux (CPack)
├── src/                      # C++23 agent
│   ├── main.cpp              # epoll loop, exporters, reconcile wiring
│   ├── flow.hpp              # §5 key/value PODs + endian pack/unpack
│   ├── bpf.cpp               # libbpf: map, batch-walk, tcx attach, stats
│   ├── lifecycle.cpp         # delta accounting + per-proto expiry
│   ├── reconcile.cpp         # rtnetlink dump + RTM_NEWLINK/RTM_DELLINK
│   ├── exporter_ipfix.cpp    # IPFIX (templates 256/257, chunking)
│   ├── exporter_syslog.cpp   # RFC 5424 json/logfmt, local/remote
│   ├── metrics.cpp           # Prometheus textfile + build_info
│   ├── config_uci.cpp        # OpenWrt libuci backend
│   ├── config_mini.cpp       # plain-Linux inifile-cpp backend
│   ├── udp_client.cpp        # dual-stack (v4/v6) remote UDP endpoint
│   ├── prometheus.cpp        # exposition builder (HELP/TYPE once, labels)
│   ├── log.hpp               # DAEMON_LOG gated by main.log_level
│   └── version.hpp           # build_info {version,commit,os,arch}
├── src/obserwrt-bpf.c        # the eBPF program (shared, unchanged)
├── vendor/                   # 3rd-party headers (nlohmann/json, inifile-cpp)
├── linux/                    # systemd unit + .conf for the plain-Linux .deb
├── obserwrt/
│   ├── Makefile              # OpenWrt package (cmake.mk + bpf.mk)
│   └── files/obserwrt.init   # procd script (flat)
│   └── files/obserwrt.conf   # UCI config (flat)
├── tests/                    # golden harness + native goflow2 e2e emitter
└── scripts/                  # e2e driver + transitional ucode helper scripts
```

The repo is used directly as an OpenWrt package feed; package sources under the
top-level `obserwrt/` package dir (all other top-level dirs — `.github`,
`docs`, `scripts`, `src`, `tests`, `linux`, `vendor` — are non-package).

## Dependencies

Running the OpenWrt package: `libbpf`, `libuci`, `libstdcpp`. Plain Linux:
`libbpf1`, `libstdc++6`. Vendored single headers: `nlohmann/json`,
`inifile-cpp` (MIT). The eBPF object is built from source — via
`include/bpf.mk` (OpenWrt) or clang (Linux CMake) — never checked in.

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
#   clang -O2 -g -target bpfel $inc -c src/obserwrt-bpf.c -o /tmp/bpfel.o
#   clang -O2 -g -target bpfeb $inc -c src/obserwrt-bpf.c -o /tmp/bpfeb.o
```

CI runs the native build/harness, the clang-format + clang-tidy gates, the eBPF
smoke, and a feed-layout check.

Run the daemon directly with `-c` during development:

```sh
# Plain Linux:
build/obserwrt -c linux/obserwrt.conf
# OpenWrt (after package install): /etc/init.d/obserwrt {start,restart,info}
```

## Conventions

- **C++23**, exceptions-free (`-fno-exceptions`; inifile-cpp is the only TU
  compiled with `-fexceptions`), no iostream. Optimization follows the image/
  host toolchain (`-Os`/`-O2`); never hardcode it.
- Wire formats are owned by `flow.hpp` (PODs with `static_assert` sizes) and
  the golden harness; change the `§5` key/value layout or any IPFIX metric NAME
  only as a deliberate incompatibility.
- Big-endian safeness: the BPF map is native-endian; pack/unpack explicitly.
- Daemon diagnostics go through `DAEMON_LOG` (`src/log.hpp`), gated by
  `main.log_level`; never `setlogmask()` (it would mute the syslog exporter's
  local flow records). Device/link events are observable at `debug`.
- Config lives behind the `Config` facade (`config_uci.cpp`/`config_mini.cpp`);
  one option set, two backends.
- Do not check in compiled `.o`/eBPF objects; build from source.

## Transitional ucode files

The deprecated ucode agent (`obserwrt/files/usr/share/ucode/obserwrt/`,
`scripts/emit-test.uc`, the fw4-style `obserwrt/tests/*.uc`) is retained until
the C++ agent flips in production. It is superseded by `src/` — do not extend
it. ucode-specific guidance (trailing `;` on `export function`, no function
hoisting, no `arr.push()`, `for (x in arr)` yields elements, etc.) applies only
to those files; see `docs/design.md` §1 for the v0.2.6→C++ history.

## Do not

- Expose real/internal device names or IPs in examples/docs — use generic
  placeholders (`awg0`, `awg_*`, `tun_*`, `br-lan`, `eth0`) and RFC 5737 test
  addresses (`192.0.2.0/24`, `198.51.100.0/24`).
- Implement an HTTP/metrics server in obserwrt.
- Add dependencies beyond those actually needed; keep the package lean.
- Begin an IPFIX feature before the P0 TC-visibility probe is proven.

## Testing (see also `.github/workflows/ci.yml`)

- **goflow2 e2e** (`scripts/test-ipfix.sh`, native): builds `obserwrt-emit`
  (`tests/emit_native.cpp`, drives the C++ `IpfixExporter`+`UdpClient` with a
  fixed IPv4 TCP + IPv6 UDP flow) and asserts an independent collector (goflow2
  via `GOFLOW2`/`docker`) decodes the expected fields. Run:
  `cmake --build build --target obserwrt-emit && OBSERWRT_EMIT=$PWD/build/obserwrt-emit sh scripts/test-ipfix.sh`
- **Golden harness** (`tests/harness.cpp`, `ctest`): pins the IPFIX v4/v6 wire
  bytes (templates 256/257 incl. IE 152/153), the §5 key/value layouts, the
  lifecycle delta/expiry contract, syslog JSON/logfmt/envelopes, the Prometheus
  exposition, and both config backends, against the ucode agent's expectations.
- **Transitional ucode tests** (`obserwrt/tests/run_tests.sh`): fw4-style
  declarative tests for the deprecated agent; retained until the flip. Uses
  OpenWrt's fw4 ISC-licensed mock framework; attribution retained.

## Milestones (see design §13)

P0 TC visibility → P1 flow tracking → P2 dynamic devices → P3 debug export →
P4 IPFIX → P5 Akvorado → P6 real mesh. Gate each export/exporter step on the
prior probe.
