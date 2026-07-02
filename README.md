# *NULL* — a terminal network sniffer

```
      ::::    ::: :::    ::: :::        :::
     :┼:┼:   :┼: :┼:    :┼: :┼:        :┼:
    :┼:┼:┼  ┼:┼ ┼:┼    ┼:┼ ┼:┼        ┼:┼
   ┼#┼ ┼:┼ ┼#┼ ┼#┼    ┼:┼ ┼#┼        ┼#┼
  ┼#┼  ┼#┼#┼# ┼#┼    ┼#┼ ┼#┼        ┼#┼
 #┼#   #┼#┼# #┼#    #┼# #┼#        #┼#
###    ####  ########  ########## ##########
```

A lightweight, root-only command-line packet sniffer for Linux. *NULL* captures live traffic with `libpcap`, decodes it enough to be useful, and shows it either as a live-scrolling, color-coded `ncurses` dashboard or as plain streamed text — with optional CSV logging on the side.

---

## Table of contents

- [General information](#general-information)
- [Installation](#installation)
- [Available arguments](#available-arguments)
- [Usage](#usage)
- [Bug reports](#bug-reports)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## General information

*NULL* is a small, dependency-light packet sniffer built directly on `libpcap` and `ncurses`, with no other third-party libraries involved. It aims to be a fast, readable alternative to reaching for `tcpdump`/`wireshark` when you just want to eyeball what's crossing an interface.

**Core capabilities:**

- **Live packet capture** via `libpcap`, in immediate mode with a configurable snapshot length and a large capture buffer for low-loss capture on busy interfaces.
- **Protocol decoding**: Ethernet (including 802.1Q VLAN tags), ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, IGMP, GRE, ESP, AH, SCTP, and OSPF.
- **Application-layer inspection**:
  - **DNS** query-name extraction (from the first question in non-response packets).
  - **HTTP** request-line and `Host:` header parsing (method, path, hostname).
  - **TLS** ClientHello SNI extraction (TCP port 443 traffic).
  - **QUIC** Initial-packet SNI sniffing, so HTTP/3 hostnames show up too (UDP port 443 traffic).
- **Two display modes**: a full-screen, color-coded, scrollable `ncurses` TUI, or a plain, pipeable text stream (`--no-color`) for logging/scripting/headless boxes.
- **Flexible filtering**: capture-side BPF filters (port, host, raw BPF expression) combined with protocol shortcuts (`--dns`, `--http`, `--https`/`--tls`, `--icmp`), plus a hard packet-count limit.
- **CSV export** of every matching packet (timestamp, protocol, addresses, ports, length, service name, hostname, HTTP method/path), unlimited or capped at the first *N* packets.
- **Interface enumeration** (`--list-interfaces`), so you don't have to guess device names.
- **Clean shutdown** on `Ctrl+C`/`SIGTERM`, with capture and CSV totals printed on exit.

**Project layout:**

```
include/    Public headers (cli, sniffer, packet, csv_logger, tui)
src/        Implementation files, one per header, plus main.cpp
Makefile    Build, install, debug, and run targets
```

## Installation

### Requirements

- **Linux** (the code depends on `libpcap`'s Ethernet capture, `netinet/*` headers, and `ncurses`; it is not portable to Windows/macOS as written).
- **Root privileges** (or `CAP_NET_RAW`/`CAP_NET_ADMIN` on the binary) — raw packet capture requires elevated access.
- **A C++17-capable compiler** (GCC or Clang).
- **Development libraries**: `libpcap` and `ncurses` (headers + link libraries), `make`.

### Install build dependencies

Pick the section for your distro, then build as described below.

**Debian / Ubuntu / Linux Mint / Pop!_OS / Kali:**

```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev libncurses-dev
```

**Fedora:**

```bash
sudo dnf install -y gcc-c++ make libpcap-devel ncurses-devel
```

**RHEL / CentOS / Rocky Linux / AlmaLinux:**

```bash
sudo dnf install -y gcc-c++ make libpcap-devel ncurses-devel
# On older RHEL/CentOS releases using yum:
sudo yum install -y gcc-c++ make libpcap-devel ncurses-devel
```

**Arch Linux / Manjaro / EndeavourOS:**

```bash
sudo pacman -Syu --needed base-devel libpcap ncurses
```

**openSUSE (Tumbleweed / Leap):**

```bash
sudo zypper install -y gcc-c++ make libpcap-devel ncurses-devel
```

**Alpine Linux:**

```bash
sudo apk add build-base libpcap-dev ncurses-dev
```

**Void Linux:**

```bash
sudo xbps-install -S base-devel libpcap-devel ncurses-devel
```

**Gentoo:**

```bash
sudo emerge --ask net-libs/libpcap sys-libs/ncurses
```

### Build

The project builds with the included `Makefile` — no CMake or other build system needed. Object files are written to `build/`, with automatic dependency tracking so incremental rebuilds only recompile what changed.

```bash
git clone https://github.com/miasmaer/NULL
cd null
make            # builds ./null
```

Other Makefile targets:

```bash
make debug      # rebuild from clean with -g -O0 -DDEBUG (for gdb/valgrind)
make run        # build, then run with sudo
make install    # install to /usr/local/bin/null
make uninstall  # remove from /usr/local/bin
make clean      # remove build/ and the null binary
```

Under the hood, `make` compiles each `src/*.cpp` with:

```
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -MMD -MP -c <file>.cpp -o build/<file>.o
```

and links with:

```
g++ build/*.o -o null -lpcap -lncurses -pthread
```

(`-pthread` is required since the TUI runs capture on a background thread.)

## Available arguments

```
Capture options:
  -i <iface>         Interface to listen on (default: first active)
  -p <port>          Filter by port number
  --host <ip>        Filter by source or destination IP
  --filter "<expr>"  Raw BPF expression (appended to built-in filter)
  -c <n>             Stop after n packets

Protocol shortcuts:
  --dns              Show only DNS queries
  --http             Show only HTTP traffic
  --https, --tls     Show only HTTPS / TLS traffic
  --icmp             Show only ICMP packets

Display:
  -v, --verbose      Show extra detail (length)
  --no-color         Disable colours (also disables TUI)

Logging:
  --sf [n]           Save captured packets to a CSV file.
                      With a number, saves only the first n packets.
                      Without a number, saves all captured packets.

Utility:
  --list-interfaces  List capture interfaces and exit
  -h, --help         Show this help and exit
  --version          Print version and exit
```

Notes:

- The protocol shortcuts (`--dns`, `--http`, `--https`/`--tls`, `--icmp`) are combined with **OR** logic against each other, but everything is **AND**ed with `-p`, `--host`, and `--filter`. For example, `-p 8080 --http` captures traffic on port 8080 **and** matching the HTTP shortcut's BPF clause.
- `--sf` without a following number logs every matching packet for the whole session; `--sf 500` stops writing new CSV rows after 500 (capture itself continues until you quit or `-c` is hit).
- Other arguments will be added soon.

## Usage

Raw capture requires elevated privileges, so run with `sudo`:

```bash
sudo ./null [options]
```

**Examples:**

```bash
# Sniff DNS queries on eth0
sudo ./null -i eth0 --dns

# Sniff HTTPS/TLS traffic on wlan0, with extra detail
sudo ./null -i wlan0 --https -v

# Watch HTTP traffic on a custom port
sudo ./null -p 8080 --http

# Only packets to/from a specific host
sudo ./null --host 8.8.8.8

# Pass a raw BPF filter and cap capture at 100 packets
sudo ./null --filter "tcp port 22" -c 100

# Log the first 500 matching packets to a timestamped CSV file
sudo ./null --sf 500

# Log everything to CSV, uncapped
sudo ./null --sf

# Headless/plain output, good for piping or logging to a file
sudo ./null -i eth0 --no-color > capture.log

# List available capture interfaces
sudo ./null --list-interfaces
```

**The TUI** (default mode, unless `--no-color` is passed) shows a header bar (interface, filter, clock), live protocol-count "pills" (DNS/HTTP/TLS/UDP/ICMP/TCP/ARP/other) with total packet and byte counts, and a scrolling, color-coded packet table (time, protocol, source, destination, service, and a hostname/HTTP/length info column).

Keybindings:

| Key             | Action                   |
|-----------------|--------------------------|
| `q` / `Q` / `Esc` | Quit                   |
| `↓` / `j`         | Scroll down one row    |
| `↑` / `k`         | Scroll up one row      |
| `Page Down`       | Scroll down one page   |
| `Page Up`         | Scroll up one page     |
| `g` / `Home`      | Jump to top            |
| `G` / `End`       | Jump to bottom (latest)|

**CSV output** (`--sf`) is written to `NULL_capture_YYYYMMDD_HHMMSS.csv` in the current directory, with columns: `time, proto, src_ip, src_port, dst_ip, dst_port, length, service, hostname, http_method, http_path`.

## Bug reports

Found a crash, a parsing bug, a build failure on your distro, or something that just looks wrong in the TUI? Please open a **GitHub Issue** on this repository.

When filing an issue, it helps a lot to include:

- Your distro and version.
- Compiler and version.
- The exact command you ran.
- What you expected vs. what happened (including any error output).
- If it's a capture/parsing bug, the interface type involved (Ethernet, Wi-Fi, VPN, container bridge, etc.) if relevant.

Feature requests and pull requests are welcome through the same Issues tab.
**NOTE** IF YOU FOUND SECURITY ISSUE PLEASE HEAD TO SECURITY.md FOR FURTHER HELP

## License

This project is licensed under the **MIT License** see: [`LICENSE`](LICENSE) for the full text.

## Disclaimer

The creator of this project is not responsible for how it is used. This tool is intended for research, learning, and authorized network diagnostics only.

You use this software entirely at your own risk. You are free to use, copy, modify, or build derivative projects based on this code, but any such project **may not use this project's name and must not be presented as being affiliated with or endorsed by it**.

Only capture traffic on networks and interfaces you own or have explicit permission to monitor. Unauthorized packet capture may be illegal in your jurisdiction.
