# SNI-Spoofing-Go — Build & Usage Guide

## Supported Platforms

| OS | Architecture | Target Device Examples | Status |
|---|---|---|---|
| Windows | x86_64 (amd64) | Desktop PC, Laptop | ✅ Tested |
| Linux | aarch64 (arm64) | OpenWrt routers (GL-MT3000, RPi 4, etc.) | ✅ Tested |
| Linux | x86_64 (amd64) | Linux server, VPS | ✅ Supported |
| Linux | ARMv7 (arm) | Older routers, RPi 2/3 | ✅ Supported |
| Linux | MIPS (mipsle) | Older OpenWrt routers (TP-Link, etc.) | ✅ Supported |
| Linux | MIPS (mips) | Big-endian MIPS routers | ✅ Supported |

> **Note:** macOS/FreeBSD are NOT supported — WinDivert is Windows-only, and nfqueue is Linux-only.

---

## Prerequisites

### Build Machine (where you compile)

- **Go 1.21+** — https://go.dev/dl/
- **Git** — to clone the project
- No C compiler needed — all builds are pure Go (`CGO_ENABLED=0`)

### Target Machine (where you run it)

#### Windows
| Requirement | Details |
|---|---|
| OS | Windows 7 / 10 / 11 (64-bit) |
| Privileges | **Administrator** (right-click → Run as administrator) |
| WinDivert | `WinDivert.dll` + `WinDivert64.sys` in the same folder as the exe |
| Download | https://reqrypt.org/windivert.html → Download v2.2 → extract the `amd64` files |

#### Linux / OpenWrt
| Requirement | Details |
|---|---|
| OS | Any Linux with kernel 3.13+ (nfqueue support) |
| Privileges | **Root** or `CAP_NET_ADMIN` + `CAP_NET_RAW` |
| iptables | Must be installed (the tool creates rules automatically) |
| Kernel module | `nfnetlink_queue` must be loaded |

**OpenWrt package install:**
```bash
opkg update
opkg install iptables-mod-nfqueue kmod-nfnetlink-queue
```

**Regular Linux (Debian/Ubuntu):**
```bash
sudo apt install iptables
sudo modprobe nfnetlink_queue
```

---

## Build Commands

### Setup

```bash
git clone <repo-url>
cd SNI-Spoofing-Go
go mod download
```

### Windows x64

```bash
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0
go build -o sni-spoofing.exe -ldflags "-s -w" .
```

**PowerShell:**
```powershell
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -o sni-spoofing.exe -ldflags "-s -w" .
```

**Output:** `sni-spoofing.exe` (~2.9 MB)

---

### Linux x86_64 (amd64)

For Linux servers, VPS, x86 routers:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o sni-spoofing-linux-amd64 -ldflags "-s -w" .
```

**Output:** `sni-spoofing-linux-amd64` (~3.0 MB)

---

### Linux ARM64 / aarch64 (OpenWrt Cortex-A53/A72)

For GL-MT3000, RPi 4, NanoPi, AX6000, and other arm64 routers:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o sni-spoofing-linux-arm64 -ldflags "-s -w" .
```

**Output:** `sni-spoofing-linux-arm64` (~3.0 MB)

---

### Linux ARMv7 (32-bit ARM)

For Raspberry Pi 2/3, older ARM routers:

```bash
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -o sni-spoofing-linux-armv7 -ldflags "-s -w" .
```

**Output:** `sni-spoofing-linux-armv7` (~3.0 MB)

---

### Linux MIPS Little-Endian (mipsle)

For many TP-Link, Xiaomi, and budget OpenWrt routers:

```bash
GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0 go build -o sni-spoofing-linux-mipsle -ldflags "-s -w" .
```

> Use `GOMIPS=softfloat` for routers without hardware floating-point (most MIPS routers).

**Output:** `sni-spoofing-linux-mipsle` (~3.3 MB)

---

### Linux MIPS Big-Endian (mips)

For some older routers (Atheros-based):

```bash
GOOS=linux GOARCH=mips GOMIPS=softfloat CGO_ENABLED=0 go build -o sni-spoofing-linux-mips -ldflags "-s -w" .
```

**Output:** `sni-spoofing-linux-mips` (~3.3 MB)

---

### Build All at Once

**Linux/macOS build machine:**
```bash
#!/bin/bash
LDFLAGS="-s -w"

CGO_ENABLED=0 GOOS=windows GOARCH=amd64           go build -o dist/sni-spoofing.exe            -ldflags "$LDFLAGS" .
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64            go build -o dist/sni-spoofing-linux-amd64    -ldflags "$LDFLAGS" .
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64            go build -o dist/sni-spoofing-linux-arm64    -ldflags "$LDFLAGS" .
CGO_ENABLED=0 GOOS=linux   GOARCH=arm   GOARM=7    go build -o dist/sni-spoofing-linux-armv7    -ldflags "$LDFLAGS" .
CGO_ENABLED=0 GOOS=linux   GOARCH=mipsle GOMIPS=softfloat go build -o dist/sni-spoofing-linux-mipsle -ldflags "$LDFLAGS" .
CGO_ENABLED=0 GOOS=linux   GOARCH=mips  GOMIPS=softfloat  go build -o dist/sni-spoofing-linux-mips   -ldflags "$LDFLAGS" .

echo "Done! Binaries in dist/"
ls -lh dist/
```

**PowerShell build machine:**
```powershell
$ldflags = "-s -w"
New-Item -ItemType Directory -Force -Path dist | Out-Null

@(
    @{GOOS="windows"; GOARCH="amd64"; OUT="dist/sni-spoofing.exe"},
    @{GOOS="linux";   GOARCH="amd64"; OUT="dist/sni-spoofing-linux-amd64"},
    @{GOOS="linux";   GOARCH="arm64"; OUT="dist/sni-spoofing-linux-arm64"},
    @{GOOS="linux";   GOARCH="arm";   OUT="dist/sni-spoofing-linux-armv7"; EXTRA="GOARM=7"},
    @{GOOS="linux";   GOARCH="mipsle";OUT="dist/sni-spoofing-linux-mipsle"; EXTRA="GOMIPS=softfloat"},
    @{GOOS="linux";   GOARCH="mips";  OUT="dist/sni-spoofing-linux-mips"; EXTRA="GOMIPS=softfloat"}
) | ForEach-Object {
    $env:GOOS = $_.GOOS; $env:GOARCH = $_.GOARCH; $env:CGO_ENABLED = "0"
    if ($_.EXTRA -match "GOARM=(.*)") { $env:GOARM = $Matches[1] } else { $env:GOARM = "" }
    if ($_.EXTRA -match "GOMIPS=(.*)") { $env:GOMIPS = $Matches[1] } else { $env:GOMIPS = "" }
    Write-Host "Building $($_.OUT)..."
    go build -o $_.OUT -ldflags $ldflags .
}
Write-Host "Done!"
Get-ChildItem dist/ | Format-Table Name, @{N="Size MB";E={[math]::Round($_.Length/1MB,2)}}
```

---

## Configuration

Create `config.json` in the same directory as the binary (or in your working directory):

```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "188.114.98.0",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "auth.vercel.com"
}
```

| Field | Description |
|---|---|
| `LISTEN_HOST` | IP to listen on (`0.0.0.0` = all interfaces, `127.0.0.1` = local only) |
| `LISTEN_PORT` | Local port to listen on |
| `CONNECT_IP` | Target server's IP address (the real server you want to reach) |
| `CONNECT_PORT` | Target server's port (usually `443`) |
| `FAKE_SNI` | Domain name to put in the fake ClientHello (any allowed domain) |

---

## Usage

### Windows

1. Place `sni-spoofing.exe`, `config.json`, `WinDivert.dll`, and `WinDivert64.sys` in the same folder
2. Right-click `sni-spoofing.exe` → **Run as administrator**

```
Local interface: 192.168.1.100
Listening on 0.0.0.0:40443
```

### Linux / OpenWrt

1. Copy the binary to the device:
```bash
scp sni-spoofing-linux-arm64 root@192.168.8.1:/usr/bin/sni
```

2. SSH into the router and create the config directory:
```bash
ssh root@192.168.8.1
mkdir -p /etc/sni
```

3. Create `config.json` on the router:
```bash
cat > /etc/sni/config.json << 'EOF'
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "188.114.98.0",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "auth.vercel.com"
}
EOF
```

> **Edit the values for your setup:**
> - `CONNECT_IP` → the real IP of your target server
> - `CONNECT_PORT` → usually `443`
> - `FAKE_SNI` → any domain that is NOT blocked (e.g. `auth.vercel.com`, `www.google.com`)
> - `LISTEN_PORT` → any free port on the router

To edit later:
```bash
vi /etc/sni/config.json
```

4. Make the binary executable and run:
```bash
chmod +x /usr/bin/sni
cd /etc/sni && sni
```

```
Local interface: 192.168.2.136
iptables rules set up (queue 100, mark 0x1337)
Listening on 0.0.0.0:40443
```

5. Press **Ctrl+C** to stop (iptables rules are cleaned up automatically).

### Connect Through the Proxy

In your proxy client (Xray, V2Ray, Clash, Nekobox, etc.), set the server to:

| Setting | Value |
|---|---|
| Address | IP of the machine running `sni` |
| Port | `40443` (or whatever `LISTEN_PORT` you set) |
| TLS / SNI | Your **real** domain (unchanged) |

The tool injects a fake ClientHello with `FAKE_SNI` to bypass DPI, then transparently relays your real TLS traffic.

---

## How to Find Your Router's Architecture

On OpenWrt:
```bash
uname -m
# aarch64 → use arm64 build
# armv7l  → use armv7 build
# mips    → use mips build
# x86_64  → use amd64 build
```

Or:
```bash
cat /etc/openwrt_release
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `Failed to create injector` (Windows) | Run as Administrator + ensure WinDivert files are present |
| `Failed to create injector` (Linux) | Run as root + install `kmod-nfnetlink-queue` |
| `iptables rules` error (Linux) | Install `iptables-mod-nfqueue`: `opkg install iptables-mod-nfqueue` |
| `config.json not found` | Run from the directory containing `config.json`, or place it next to the binary |
| TLS handshake failure | `CONNECT_IP` doesn't serve the domain you're connecting to |
| Cloudflare 1016 error | Wrong `CONNECT_IP` — use the correct IP for your domain |
| Connection timeout | Firewall blocking port 40443 or target IP unreachable |
