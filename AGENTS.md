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
├── files/usr/share/ucode/obserwrt/obserwrt.uc    # procd entry
├── files/usr/share/ucode/obserwrt/flow.uc        # BPF map access
├── files/usr/share/ucode/obserwrt/reconcile.uc   # device lifecycle + reporting
├── files/usr/share/ucode/obserwrt/lifecycle.uc   # flow expiry/export pass
└── src/obserwrt-bpf.c        # TC ingress/egress sections
```

The `.uc` scripts are split into modules under `/usr/share/ucode/obserwrt/`
(OpenWrt ucode convention — cf. `fw4.uc`, `cli/`, `node-exporter/`). The entry
`obserwrt.uc` imports `flow.uc`, `reconcile.uc` and `lifecycle.uc`. ucode `.uc`
modules use `export function foo(){…};` (trailing `;` required) and
`import { foo } from './flow.uc'`.

The repo is used directly as an OpenWrt package feed; package sources under the
top-level `obserwrt/` package dir (all other top-level dirs, `.github`, `docs`,
are non-package).

## Dependencies

`ucode`, `ucode-mod-bpf`, `ucode-mod-ubus`, `ucode-mod-struct`, `ucode-mod-log`,
`ucode-mod-fs`, `ucode-mod-uloop`.
eBPF object is built from source via `include/bpf.mk` (BPF toolchain), never
checked in.

## Commands

Checks (defined in `.github/workflows/ci.yml`):

```sh
# Shell-syntax check the procd service (POSIX sh)
shellcheck obserwrt/files/etc/init.d/obserwrt

# ucode bytecode/compile check (no exec; `-c`; requires stubbing imports)
# for f in obserwrt/files/usr/share/ucode/obserwrt/*.uc; do ...; done

# Fast ucode lint (node ESM parse + ucode rules; no FP toolchain needed)
node scripts/uc-lint.mjs

# eBPF compile smoke, both byte orders (real headers, OpenWrt bpf.mk `uapi/` style)
# Needs the system kernel UAPI + libbpf headers (linux-libc-dev, libbpf-dev):
#   mkdir -p /tmp/uapi && ln -s /usr/include/linux /tmp/uapi/linux
#   inc="-I/tmp/uapi -I/usr/include/x86_64-linux-gnu -I/usr/include"
#   clang -O2 -g -target bpfel $inc -c src/obserwrt-bpf.c -o /tmp/bpfel.o
#   clang -O2 -g -target bpfeb $inc -c src/obserwrt-bpf.c -o /tmp/bpfeb.o
```

There is no test suite yet; CI runs the above and a feed-layout check. Run them
after any change to `.uc`, `init.d`, or `.c`.

Run the ucode agent directly with a config-files path during development:

```sh
ucode -e 'import("obserwrt/files/usr/share/ucode/obserwrt/obserwrt.uc")'
```

## ucode (the agent language) is NOT JavaScript

ucode is ECMAScript-inspired but is a distinct language with a smaller
standard library. Do not assume JS features. Write code against the official
docs, which are authoritative:

- **Language/tutorials:** https://ucode.mein.io (Usage, Syntax, Memory,
  Arrays, Dictionaries tutorials)
- **Core module:** https://ucode.mein.io/module-core.html
- **Log:** https://ucode.mein.io/module-log.html
- **Struct:** https://ucode.mein.io/module-struct.html
- **UCI:** https://ucode.mein.io/module-uci.html
- **Ubus:** https://ucode.mein.io/module-ubus.html
- **Uloop:** https://ucode.mein.io/module-uloop.html

Known non-JS gotchas that have already bitten this project:

- **`export function foo(){…}` must end with `;` in a `.uc` module** (this ucode
  parses the export as an expression statement, so `export function f(){};`).
  Import with `import { foo } from './foo.uc'` (relative path, like
  node-exporter's `import { fetch_json } from '../http_client.uc'`).
- **No function hoisting.** A function declared later in the file is undefined
  when called earlier. Declare before use, or assign at the bottom near `main()`.
- **No `arr.push()` / `arr.map()` etc. as methods.** Arrays use *global*
  functions: `push(arr, …)`, `filter(arr, fn)`, `map(arr, fn)`, `pop(arr)`.
- **No string `[]` indexing.** `s[i]` raises `left-hand side expression is not an
  array or object`. Use `substr(s, i, 1)` or `ord(s, i)` to read a character.
- **`for (x in arr)` yields elements, not indices** (on objects it yields keys).
  Use `for (item in arr)` directly when you want the elements; iterate
  `i = 0..length(arr)-1` only when you need the index.
- **No `throw` statement** (there is `try`/`catch`; use `die()` to raise).
- **No `RegExp` / `new RegExp`.** Use `regexp(source, flags)` plus `match(str, re)`,
  or the built-in `wildcard(subject, pattern[, nocase])` (fnmatch-based glob) for
  simple glob/pattern matching.
- **No `{const x} = y` / `for (const i in …)`** — no `const` in loop heads; use
  `let`.
- **No implicit adjacent-string concatenation** (`'a' 'b'` is invalid) — use `+`.
- **Object iteration**: `for (let k in obj)` gives keys; `keys(obj)` also works.
  `for..in` over an object value that is actually null/other throws — guard first.
- Undefined identifiers raise runtime "left-hand side is not a function"-style
  errors, and `import` resolution needs the `ucode-mod-*` `.so` present (so a
  CLI `ucode -c` syntax check requires stubbing imports — see CI).
- **uci option values are strings.** Parse explicitly: `int(ctx.get('obserwrt',
  'main', 'x'))` for a number, and for a bool use `int()`/explicit truthy
  (`v == '1' && v`). List options (`list device …`) return an array.

When in doubt, check the docs rather than assuming ECMAScript semantics.

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
