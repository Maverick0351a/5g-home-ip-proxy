# Chrome Web Store Listing & Permission Justifications (`v1.4.0`)

## 1. Store Listing Copy

- **Extension Name (54 chars — Zero Trademark Friction):**
  `5G Home Internet IP Rotator & Dual-WiFi Proxy Switcher`
- **Short Description (130 chars max):**
  `Rotate 5G Home gateway WAN IPs in 1 click, switch dual-WiFi adapters, lock WebRTC leaks, and chain local SOCKS5 or Burp/ZAP proxies.`
- **Category:** Developer Tools / Workflow & Planning

### Detailed Description
Turn your **5G Home Internet gateway** (compatible with Verizon 5G Home `192.168.1.1`, T-Mobile 5G Home `192.168.12.1`, and Xfinity Home `10.0.0.1`) into a 1-click self-hosted residential proxy and authorized security testing egress node.

**Key Features for Everyday Users & Developers:**
- **1-Click 5G Home WAN IP Rotation:** Trigger clean DHCPv4/v6 lease renewals on your local 5G Home gateway from your browser toolbar without logging into router admin pages.
- **Dual-Wi-Fi Adapter Switching:** Instantly switch outgoing proxy traffic between your primary 5G Home Wi-Fi interface and a secondary USB Wi-Fi adapter without changing your operating system default route.
- **Automatic WebRTC Leak Protection:** Prevents non-proxied UDP packets from leaking your primary ISP IP while proxy routing is active.
- **Scheduled Auto-Rotation:** Automatically rotate your residential WAN IP every 5, 15, or 30 minutes.

**Key Features for Authorized Red-Team & Bug-Bounty Testers:**
- **1-Click Fresh 5G Identity:** Simultaneously rotates your 5G WAN IP and clears site cookies, storage, and cache for the active target tab so WAFs and rate limiters see a clean residential session.
- **Intercepting Proxy Chaining:** Switch between Direct mode, 5G Proxy (`127.0.0.1:8888`), or Intercepting Proxy Chain (`Browser -> 127.0.0.1:8080 -> 127.0.0.1:8888` for Burp Suite, OWASP ZAP, or Caido).
- **SHA-256 Signed ROE / SOC Egress Audit Log Export:** Export a cryptographically hash-chained JSON timeline of every public WAN IP lease change for Rules of Engagement (ROE) compliance and SOC deconfliction.

---

## 2. Permission Justifications (For Chrome Web Store Review)

| Permission | Justification |
|---|---|
| `proxy` | Required to switch browser traffic between Direct connection, the user's local 5G Home SOCKS5/HTTP proxy (`127.0.0.1:8888`), and local security testing proxies (`127.0.0.1:8080`). |
| `privacy` | Required to set `chrome.privacy.network.webRTCIPHandlingPolicy` to `disable_non_proxied_udp` while proxy modes are active so WebRTC STUN UDP packets cannot leak the user's primary ISP IP outside the 5G proxy tunnel. |
| `storage` | Required to persist non-sensitive proxy preferences in `chrome.storage.local` and keep sensitive credentials (`gatewayPassword`, `controlToken`) exclusively in RAM-only `chrome.storage.session`. |
| `alarms` | Required to run user-configured periodic WAN IP auto-rotation (every 5, 15, or 30 minutes) reliably in Manifest V3. |
| `browsingData` | Required exclusively when the user clicks the "1-Click Fresh Identity" button to clear cookies, localStorage, and cache for the active tab's origin alongside a WAN IP rotation. |
| `activeTab` | Required to read the active tab's origin URL when the user clicks "1-Click Fresh Identity" in the popup, avoiding the global `"tabs"` browsing-history permission warning. |
| `host_permissions` (`http://127.0.0.1/*`, `http://localhost/*`) | Required to communicate with the open-source `home_ip_proxy.py` local control daemon running on `127.0.0.1:8889`. |

---

## 3. Privacy Policy Summary
- **Zero External Telemetry or Data Collection:** This extension communicates exclusively with the user's own local daemon (`127.0.0.1` / `localhost`) or user-configured LAN gateway. No browsing history, credentials, IP addresses, or analytics are ever transmitted to any third-party server.
