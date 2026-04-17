# 🛠 Fix v2raya Transparent Proxy Infinite Loop

## 💥 Problem

When enabling transparent proxy, traffic loops:

```
v2ray → spoof (127.0.0.1:443) → system → v2ray → ...
```

Cause: proxy captures its **own traffic**

### 1. Exclude localhost from rules (REQUIRED)

Add to v2raya rules:

```yaml
ip(127.0.0.0/8)->direct
ip(geoip:private)->direct

default: proxy
```

### 2. Settings for V2raya (REQUIRED)

- Transparent Proxy/System Proxy Implementation -> `Tproxy`
- Traffic Splitting Mode of Rule Port -> `RoutingA`
- Prevent DNS Spoofing -> `Forward DNS Request`

**Tips** :

- Reset dns resolvers like `dnsmasq` | `dnsproxy` after transparent proxy
- Set `1.1.1.1` | `8.8.8.8` dns as upstream
