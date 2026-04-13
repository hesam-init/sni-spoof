# SNI-Spoofing-Go

A high-performance **Go implementation** of the [SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) DPI bypass tool, originally written in Python by [@patterniha](https://github.com/patterniha).

Cross-platform: **Windows** (WinDivert) and **Linux/OpenWrt** (nfqueue + raw socket).

## Credits & Acknowledgments

This project is a complete port of the original **[SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)** by **[@patterniha](https://github.com/patterniha)**. All credit for the original concept, algorithm, and DPI bypass technique goes to them. Thank you for creating and open-sourcing this tool. 🙏

This Go version maintains full compatibility with the original Python logic while adding:
- Native concurrency with goroutines
- Cross-compilation to any OS/architecture with a single command
- Single static binary — no Python interpreter or pip dependencies needed
- Linux/OpenWrt support via nfqueue (the original is Windows-only)

## How it works

This tool acts as a local TCP proxy that:

1. **Listens** on a local port for incoming connections
2. **Connects** to the target server (e.g., a Cloudflare IP on port 443)
3. **Intercepts** the TCP handshake using kernel-level packet capture
4. **Injects** a fake TLS ClientHello with a spoofed SNI using a deliberately **wrong TCP sequence number** — DPI reads the fake SNI while the real server ignores the invalid packet
5. **Relays** traffic bidirectionally after the injection

## Platform Support

| Platform | Packet Interception | Fake Injection | Requirements |
|---|---|---|---|
| **Windows** | WinDivert driver | WinDivert send | `WinDivert.dll` + `WinDivert64.sys` |
| **Linux/OpenWrt** | nfqueue (netfilter) | Raw socket | `iptables`, `nfnetlink_queue` kernel module |

## Quick Start

See **[BUILD.md](BUILD.md)** for detailed build instructions, all supported platforms, requirements, and usage guide.

### Build

```bash
# Windows x64
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o sni-spoofing.exe -ldflags "-s -w" .

# Linux ARM64 (OpenWrt / Cortex-A53)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o sni-spoofing-linux-arm64 -ldflags "-s -w" .
```

### Configure

Create `config.json`:

```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "188.114.98.0",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "auth.vercel.com"
}
```

### Run

```bash
# Windows (as Administrator)
.\sni-spoofing.exe

# Linux/OpenWrt (as root)
cd /etc/sni && sni
```

## Project Structure

```
SNI-Spoofing-Go/
├── main.go                      # Entry point (platform-agnostic)
├── dial_windows.go              # Windows dial helper
├── dial_linux.go                # Linux dial helper
├── config/config.go             # Config struct + JSON loader
├── network/network.go           # Local interface IP detection
├── packet/
│   ├── templates.go             # TLS ClientHello builder
│   ├── tcp.go                   # Raw TCP/IP header parser
│   └── packet_test.go           # Unit tests
├── connection/monitor.go        # Connection state tracking
├── injection/
│   ├── common.go                # Shared types
│   ├── injector_windows.go      # WinDivert implementation
│   └── injector_linux.go        # nfqueue + raw socket implementation
├── config.json                  # Runtime configuration
├── BUILD.md                     # Full build & usage guide
└── LICENSE                      # GPL-3.0 (same as original)
```

## License

This project is licensed under the **GNU General Public License v3.0** — the same license as the [original SNI-Spoofing project](https://github.com/patterniha/SNI-Spoofing).

See [LICENSE](LICENSE) for details.

## Original Project

- **Repository:** https://github.com/patterniha/SNI-Spoofing
- **Author:** [@patterniha](https://github.com/patterniha)
- **Language:** Python
- **License:** GPL-3.0
