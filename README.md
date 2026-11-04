# 5G Home Internet IP Rotator & Dual-WiFi Proxy Switcher (`5g-home-ip-proxy` `v1.4.0`)

[![CI & Windows EXE Release](https://github.com/Maverick0351a/5g-home-ip-proxy/actions/workflows/ci-and-release.yml/badge.svg)](https://github.com/Maverick0351a/5g-home-ip-proxy/actions/workflows/ci-and-release.yml)
[![Latest Release](https://img.shields.io/github/v/release/Maverick0351a/5g-home-ip-proxy?label=Windows%20EXE%20%2B%20Extension)](https://github.com/Maverick0351a/5g-home-ip-proxy/releases/latest)

Turn your **Verizon 5G Home Internet** (`192.168.1.1`), **T-Mobile 5G Home Internet** (`192.168.12.1`), or **Xfinity Home Internet / `xfinitywifi`** (`10.0.0.1`) gateway into a **self-hosted residential HTTP / HTTPS CONNECT / SOCKS5 proxy** with **1-click WAN IP rotation**, **dual-Wi-Fi adapter binding**, a **Hardened Manifest V3 Chrome/Brave Extension**, and **Agent-Native MCP + Proxy Username DSL** for autonomous Red-Team / Bug-Bounty agents.

---

## Key Capabilities (`v1.4.0`)

### 1. Everyday Privacy & Multi-ISP Users
- **Zero-Dependency HTTP / HTTPS CONNECT / SOCKS5 Proxy (`127.0.0.1:8888`)**: Strips proxy-identifying headers (`Via`, `X-Forwarded-For`, `Forwarded`, `X-Real-IP`, `Client-IP`) and blocks DNS-rebinding / loopback / link-local SSRF probes.
- **Dual-Wi-Fi Source-IP Binding (`--interface` / `--source-ip`)**: Keep your PC on your main Wi-Fi while binding your browser, scraper, or test suite exclusively to your secondary 5G Home or `xfinitywifi` adapter (fail-closed kill-switch).
- **1-Click WAN IP Lease Rotation**: Renew your DHCPv4/v6 WAN lease on Verizon 5G (`ASK-NCM1100` / `LVSKIHP`), Xfinity (`10.0.0.1`), or T-Mobile 5G (`192.168.12.1`) with TOFU SHA-256 certificate pinning.

### 2. Authorized Red-Team & Bug-Bounty Testers (Chrome/Brave MV3 Extension)
- **Store-Ready Title:** `5G Home Internet IP Rotator & Dual-WiFi Proxy Switcher`
- **3-Way Toolbar Routing Switcher (`OFF` / `5G` / `BURP`) + Automatic WebRTC Leak Lock**:
  - **Direct**: Standard browser connection.
  - **5G Proxy (`127.0.0.1:8888`)**: Routes browser traffic out of your 5G Home / Xfinity adapter and sets `webRTCIPHandlingPolicy: disable_non_proxied_udp`.
  - **Burp / OWASP ZAP / Caido Chain (`127.0.0.1:8080 -> 127.0.0.1:8888`)**: Chains local intercepting proxy traffic upstream through your rotating 5G Home IP.
- **1-Click "Fresh 5G Identity" (`activeTab` Scoped)**: Rotates your 5G WAN IP and clears cookies, `localStorage`, `indexedDB`, and cache for the active target tab's origin.
- **RAM-Only Credentials & SHA-256 Hash-Chained ROE Audit Log**: Sensitive tokens stay strictly in `chrome.storage.session` (RAM-only), and `/api/audit-log` exports a tamper-evident SHA-256 hash chain for SOC deconfliction.

### 3. Agent-Native Red-Team Integration (Claude Code, Codex, Playwright, Nuclei)
- **Built-In Model Context Protocol (`MCP`) Server (`python home_ip_proxy.py mcp`)**:
  Exposes 4 native MCP `stdio` tools to AI agents:
  - `get_5g_egress_status`
  - `rotate_5g_wan_ip`
  - `switch_egress_adapter`
  - `get_signed_roe_audit_log`
- **Inline Proxy-Auth Username DSL (`isp-<provider>` & `session-<id>`)**:
  Control multi-ISP routing and WAN IP rotation directly inside any proxy URL:
  ```powershell
  # Route request specifically out of Verizon 5G adapter and trigger rotation for session 'run42'
  curl.exe -x socks5h://isp-verizon-session-run42:token@127.0.0.1:8888 https://api.ipify.org?format=json

  # Route a parallel scanner or Playwright context out of Xfinity Wi-Fi on the same port
  curl.exe -x socks5h://isp-xfinity:token@127.0.0.1:8888 https://api.ipify.org?format=json
  ```

---

## Quick Start

### Option A: Download Standalone Windows `.exe` (No Python Required)
Download `5g-home-ip-proxy.exe` and `5g-home-ip-proxy-chrome-extension.zip` from the [**Releases Page**](https://github.com/Maverick0351a/5g-home-ip-proxy/releases/latest):
```powershell
.\5g-home-ip-proxy.exe ui --proxy-port 8888 --ui-port 8889
```

### Option B: Add to Claude Code / Codex / Cursor MCP Config
```json
{
  "mcpServers": {
    "5g-home-ip-proxy": {
      "command": "python",
      "args": ["/path/to/5g-home-ip-proxy/home_ip_proxy.py", "mcp"]
    }
  }
}
```

## Run Offline Unit Tests
```powershell
python test_home_ip_proxy.py
```
