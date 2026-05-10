# rmap

A high-performance network scanner written in Rust. Supports **ICMP host discovery** and **TCP port scanning** with an interactive TUI.

## Features

- **ICMP sweep** — ping-based host discovery
- **TCP port scan** — connect scan with `Open / Closed / Filtered` states
- **High concurrency** — async I/O via Tokio + Semaphore-controlled parallelism
- **Interactive TUI** — tree-style table with expand/collapse per host (`-o tui`)
- **Multiple output formats** — plain text, JSON (`-o json`), interactive TUI (`-o tui`)
- **Flexible targets** — single IP, CIDR (`/24`), dash ranges (`1.1.1.1-50`)
- **Top-1000 ports** — nmap-compatible default port list

## Installation

### Pre-built binaries

Download the latest binary for your platform from the [Releases](../../releases) page.

```bash
# Linux / macOS
tar -xzf rmap-<version>-<target>.tar.gz
sudo mv rmap /usr/local/bin/

# Windows — extract rmap.exe and add to PATH
```

### Build from source

```bash
cargo install --git https://github.com/lihongjie0209/rmap
```

Or clone and build:

```bash
git clone https://github.com/lihongjie0209/rmap
cd rmap
cargo build --release
```

## Usage

> **Note**: ICMP scanning requires elevated privileges — run with `sudo` on Linux/macOS or as Administrator on Windows. Use `--port-only` to skip ICMP if privileges are unavailable.

```
rmap [OPTIONS] <TARGETS>...

Arguments:
  <TARGETS>...  IP, CIDR, or range  (e.g. 192.168.1.1  10.0.0.0/24  10.0.0.1-50)

Options:
  -p, --ports <PORTS>          Port spec (e.g. 22,80,443,1-1024)  [default: top1000]
      --icmp-only              ICMP host discovery only, skip port scan
      --port-only              Skip ICMP, scan ports on all targets
  -c, --concurrency <N>        Max concurrent probes  [default: 1000]
      --timeout <MS>           Per-probe timeout in ms  [default: 1000]
      --all                    Show all ports including closed/filtered (default: open only)
  -o, --output <FORMAT>        plain | json | tui  [default: plain]
  -h, --help                   Print help
  -V, --version                Print version
```

### Examples

```bash
# Scan common ports on a single host
sudo rmap 192.168.1.1 -p 22,80,443,3389

# Full subnet scan — ICMP sweep then top-1000 ports
sudo rmap 192.168.1.0/24

# Port-only (no ICMP required)
rmap 10.0.0.1-20 --port-only -p 80,443,8080

# Interactive TUI with expand/collapse
sudo rmap 192.168.1.0/24 -o tui

# JSON output for scripting
rmap 10.0.0.1 --port-only -p 1-1024 -o json | jq '.[] | select(.ports[].status == "open")'

# Fast sweep with reduced timeout
sudo rmap 10.0.0.0/24 --icmp-only -c 512 --timeout 500
```

### TUI Key Bindings

| Key | Action |
|-----|--------|
| `↑` / `↓` or `k` / `j` | Move selection |
| `Enter` / `Space` | Expand / collapse host |
| `→` / `l` | Expand and jump to first port |
| `←` / `h` | Collapse (from port row → returns to host) |
| `a` | Toggle expand all |
| `Home` / `End` | Jump to first / last row |
| `PgUp` / `PgDn` | Page navigation |
| `q` / `Esc` | Quit |

## Performance Notes

- Default concurrency: **1000** concurrent futures (adjust with `-c`)
- ICMP concurrency is capped at 256 to avoid blocking-thread exhaustion
- For large subnets (`/16`+), consider `--timeout 300 -c 2000`
- Linux: raise `ulimit -n` if scanning many hosts with many ports

## Platform Notes

| Platform | ICMP | TCP |
|----------|------|-----|
| Linux    | Requires `sudo` or `CAP_NET_RAW` | No special permissions |
| macOS    | Requires `sudo` | No special permissions |
| Windows  | Requires Administrator | No special permissions |

## License

MIT
