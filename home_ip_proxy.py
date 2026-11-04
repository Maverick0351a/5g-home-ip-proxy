#!/usr/bin/env python3
"""
5G Home Internet IP Proxy & 1-Click WAN Rotator (5g-home-ip-proxy v1.1.0)
=========================================================================
Turn your $50 Verizon 5G Home Cube (192.168.1.1), T-Mobile 5G Gateway (192.168.12.1),
or Xfinity Home / xfinitywifi adapter (10.0.0.1) into a $250/mo-grade Rotating
Residential Proxy & Dual-Wi-Fi Split-Tunnel Router.

Features:
  - Zero-Config Multi-Wi-Fi Auto-Discovery: Automatically detects your Wi-Fi 1
    (e.g. Verizon 5G) and Wi-Fi 2 (e.g. xfinitywifi USB stick) adapters, SSIDs,
    local IPs, and gateway providers without manual IP lookup.
  - Multiplexed HTTP + HTTPS CONNECT + SOCKS5 (socks5h:// leak-free remote DNS)
    proxy bound to any chosen Wi-Fi/LAN adapter.
  - 1-Click WAN IP Rotation (CLI & Interactive Web UI) via DHCPv4/v6 lease renewal.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import http.cookiejar
import ipaddress
import json
import os
import re
import select
import socket
import socketserver
import subprocess
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. Zero-Config Multi-Wi-Fi & Network Adapter Auto-Discovery
# ---------------------------------------------------------------------------

@dataclass
class NetworkAdapterInfo:
    interface_name: str
    description: str
    state: str
    ssid: str
    ipv4_address: str
    gateway_ip: str
    inferred_provider: str  # verizon | xfinity | tmobile | generic


def infer_provider_from_adapter(ssid: str, gateway_ip: str, ipv4_address: str) -> str:
    s_low = ssid.lower()
    if "verizon" in s_low or gateway_ip == "192.168.1.1" or ipv4_address.startswith("192.168.1."):
        return "verizon"
    if "xfinity" in s_low or gateway_ip == "10.0.0.1" or ipv4_address.startswith("10.0.0."):
        return "xfinity"
    if "t-mobile" in s_low or "tmobile" in s_low or gateway_ip == "192.168.12.1" or ipv4_address.startswith("192.168.12."):
        return "tmobile"
    return "generic"


def parse_netsh_wlan_interfaces(raw_text: str) -> Dict[str, Dict[str, str]]:
    """Parses `netsh wlan show interfaces` output into a dict keyed by interface Name."""
    interfaces: Dict[str, Dict[str, str]] = {}
    current_name = ""
    current: Dict[str, str] = {}
    for line in raw_text.splitlines():
        if ":" not in line:
            continue
        k, v = [part.strip() for part in line.split(":", 1)]
        k_low = k.lower()
        if k_low == "name":
            if current_name and current:
                interfaces[current_name] = current
            current_name = v
            current = {"name": v, "description": "", "state": "", "ssid": ""}
        elif k_low == "description":
            current["description"] = v
        elif k_low == "state":
            current["state"] = v
        elif k_low == "ssid":
            current["ssid"] = v
    if current_name and current:
        interfaces[current_name] = current
    return interfaces


def discover_network_adapters() -> List[NetworkAdapterInfo]:
    """
    Auto-discovers active and standby Wi-Fi / LAN adapters on Windows or POSIX,
    pairing each adapter with its SSID, local IPv4 address, gateway IP, and provider.
    """
    adapters: List[NetworkAdapterInfo] = []
    wlan_map: Dict[str, Dict[str, str]] = {}

    if os.name == "nt":
        try:
            proc = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            wlan_map = parse_netsh_wlan_interfaces(proc.stdout)
        except Exception:
            pass

        try:
            ps_cmd = (
                "Get-NetIPConfiguration | ForEach-Object { "
                "[PSCustomObject]@{ "
                "Alias = $_.InterfaceAlias; "
                "Desc = $_.InterfaceDescription; "
                "Status = [string]$_.NetAdapter.Status; "
                "IPv4 = ($_.IPv4Address.IPAddress | Select-Object -First 1); "
                "GW = ($_.IPv4DefaultGateway.NextHop | Select-Object -First 1) "
                "} } | ConvertTo-Json -Compress"
            )
            proc_ip = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            raw_json = proc_ip.stdout.strip()
            if raw_json:
                parsed = json.loads(raw_json)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                for item in parsed:
                    alias = str(item.get("Alias") or "")
                    ipv4 = str(item.get("IPv4") or "")
                    gw = str(item.get("GW") or "")
                    w_info = wlan_map.get(alias, {})
                    ssid = w_info.get("ssid", "")
                    state = w_info.get("state") or str(item.get("Status") or "Up")
                    desc = w_info.get("description") or str(item.get("Desc") or alias)
                    if not gw and ipv4.startswith("192.168.1."):
                        gw = "192.168.1.1"
                    elif not gw and ipv4.startswith("10.0.0."):
                        gw = "10.0.0.1"
                    elif not gw and ipv4.startswith("192.168.12."):
                        gw = "192.168.12.1"
                    prov = infer_provider_from_adapter(ssid, gw, ipv4)
                    adapters.append(
                        NetworkAdapterInfo(
                            interface_name=alias,
                            description=desc,
                            state=state,
                            ssid=ssid,
                            ipv4_address=ipv4,
                            gateway_ip=gw,
                            inferred_provider=prov,
                        )
                    )
        except Exception:
            pass

    if not adapters:
        # Fallback: determine primary outbound local IP via UDP socket connect
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("1.1.1.1", 80))
                local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"
        gw = "192.168.1.1" if local_ip.startswith("192.168.1.") else (
            "10.0.0.1" if local_ip.startswith("10.0.0.") else "192.168.12.1"
        )
        adapters.append(
            NetworkAdapterInfo(
                interface_name="Primary",
                description="Default Network Interface",
                state="connected",
                ssid="",
                ipv4_address=local_ip,
                gateway_ip=gw,
                inferred_provider=infer_provider_from_adapter("", gw, local_ip),
            )
        )
    return adapters


def resolve_adapter_source_ip(
    adapters: List[NetworkAdapterInfo],
    interface_or_ssid: Optional[str] = None,
    explicit_source_ip: Optional[str] = None,
) -> Tuple[Optional[str], str, str]:
    """
    Returns (source_ip, gateway_ip, provider) from either an explicit_source_ip,
    an interface/SSID match, or the best connected 5G/ISP adapter.
    """
    if explicit_source_ip:
        for a in adapters:
            if a.ipv4_address == explicit_source_ip:
                return explicit_source_ip, a.gateway_ip or "192.168.1.1", a.inferred_provider
        prov = infer_provider_from_adapter("", "", explicit_source_ip)
        gw = "192.168.1.1" if prov == "verizon" else ("10.0.0.1" if prov == "xfinity" else "192.168.12.1")
        return explicit_source_ip, gw, prov

    if interface_or_ssid:
        needle = interface_or_ssid.strip().lower()
        for a in adapters:
            if needle in (a.interface_name.lower(), a.ssid.lower()):
                return a.ipv4_address or None, a.gateway_ip or "192.168.1.1", a.inferred_provider

    for a in adapters:
        if a.inferred_provider in ("verizon", "xfinity", "tmobile") and not a.ipv4_address.startswith("169.254."):
            return a.ipv4_address or None, a.gateway_ip or "192.168.1.1", a.inferred_provider

    first = adapters[0]
    return first.ipv4_address or None, first.gateway_ip or "192.168.1.1", first.inferred_provider


# ---------------------------------------------------------------------------
# 2. Source-Bound HTTP/HTTPS Opener + TOFU TLS Certificate Pinning + Anti-SSRF
# ---------------------------------------------------------------------------

class TLSFingerprintPinner:
    """Trust-On-First-Use (TOFU) & Explicit SHA-256 Leaf Certificate Pinning for LAN Gateways."""

    PINNED_CERTS: Dict[str, str] = {}
    LOCK = threading.Lock()

    @classmethod
    def normalize_fp(cls, fp: str) -> str:
        return fp.strip().lower().replace(":", "")

    @classmethod
    def pin_host(cls, host: str, sha256_hex: str) -> None:
        with cls.LOCK:
            cls.PINNED_CERTS[host.strip().lower()] = cls.normalize_fp(sha256_hex)

    @classmethod
    def verify_or_pin(cls, host: str, cert_der: Optional[bytes]) -> str:
        if not cert_der:
            return ""
        actual = hashlib.sha256(cert_der).hexdigest().lower()
        key = host.strip().lower()
        with cls.LOCK:
            expected = cls.PINNED_CERTS.get(key)
            if expected is None:
                cls.PINNED_CERTS[key] = actual
                return actual
            if not hmac.compare_digest(actual, expected):
                raise PermissionError(
                    f"TLS Certificate Pinning Mismatch for {host}! Expected SHA-256 {expected}, got {actual}"
                )
        return actual


def validate_gateway_host(host: str) -> str:
    """Strictly validate that a gateway host is an RFC1918 private LAN IPv4 address (anti-SSRF)."""
    cleaned = host.strip()
    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(f"Invalid gateway IP address '{cleaned}': must be an RFC1918 LAN IPv4 address") from exc
    if (
        not isinstance(ip_obj, ipaddress.IPv4Address)
        or not ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    ):
        raise PermissionError(
            f"Blocked non-LAN gateway host '{cleaned}': only RFC1918 private LAN gateways (192.168.x.x, 10.x.x.x, 172.16-31.x.x) are permitted"
        )
    return cleaned


class BoundHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args: Any, source_ip: Optional[str] = None, **kwargs: Any) -> None:
        self._source_ip = source_ip
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        if self._source_ip:
            self.source_address = (self._source_ip, 0)
        super().connect()


class BoundHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args: Any, source_ip: Optional[str] = None, **kwargs: Any) -> None:
        self._source_ip = source_ip
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        if self._source_ip:
            self.source_address = (self._source_ip, 0)
        super().connect()
        try:
            # Enforce TOFU / Explicit SHA-256 certificate pinning on private LAN gateways
            ip_obj = ipaddress.ip_address(self.host.strip("[]"))
            if ip_obj.is_private and self.sock is not None and hasattr(self.sock, "getpeercert"):
                der_cert = self.sock.getpeercert(binary_form=True)
                TLSFingerprintPinner.verify_or_pin(self.host, der_cert)
        except ValueError:
            pass
        except PermissionError:
            try:
                self.close()
            except Exception:
                pass
            raise


class BoundHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, source_ip: Optional[str] = None) -> None:
        super().__init__()
        self._source_ip = source_ip

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            lambda host, **kwargs: BoundHTTPConnection(host, source_ip=self._source_ip, **kwargs),
            req,
        )


class BoundHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, source_ip: Optional[str] = None, context: Optional[Any] = None) -> None:
        super().__init__(context=context)
        self._source_ip = source_ip
        self._context = context

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            lambda host, **kwargs: BoundHTTPSConnection(
                host, source_ip=self._source_ip, context=self._context, **kwargs
            ),
            req,
        )


def build_opener(
    source_ip: Optional[str] = None,
    cookie_jar: Optional[http.cookiejar.CookieJar] = None,
) -> urllib.request.OpenerDirector:
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers: list[Any] = [
        BoundHTTPHandler(source_ip=source_ip),
        BoundHTTPSHandler(source_ip=source_ip, context=ctx),
    ]
    if cookie_jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookie_jar))
    return urllib.request.build_opener(*handlers)


# ---------------------------------------------------------------------------
# 3. 1-Click WAN IP Rotator (Verizon 5G, Xfinity 10.0.0.1, T-Mobile 5G)
# ---------------------------------------------------------------------------

class WANIPRotator:
    def __init__(
        self,
        provider: str = "verizon",
        host: Optional[str] = None,
        password: str = "",
        source_ip: Optional[str] = None,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ) -> None:
        self.provider = provider
        self.host = host or (
            "192.168.1.1" if provider == "verizon" else ("10.0.0.1" if provider == "xfinity" else "192.168.12.1")
        )
        self.password = password
        self.source_ip = source_ip
        self.cookies = http.cookiejar.CookieJar()
        self.opener = opener or build_opener(source_ip=source_ip, cookie_jar=self.cookies)

    def fetch_external_ip(self) -> str:
        endpoints = (
            ("https://api.ipify.org?format=json", True),
            ("https://checkip.amazonaws.com", False),
            ("https://icanhazip.com", False),
        )
        for url, is_json in endpoints:
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "curl/8.0", "Connection": "close"},
                )
                with self.opener.open(req, timeout=8) as r:
                    raw = r.read().decode("utf-8", errors="ignore").strip()
                    ip_val = str(json.loads(raw).get("ip", "")).strip() if is_json else raw
                    if ip_val:
                        return ip_val
            except Exception:
                continue
        return ""

    @staticmethod
    def _verizon_arc_md5(password: str, token: str = "") -> str:
        inner = hashlib.md5(password.encode("utf-8")).hexdigest()
        pw_hash = hashlib.sha512(inner.encode("utf-8")).hexdigest()
        if token:
            return hashlib.sha512((token + pw_hash).encode("utf-8")).hexdigest()
        return pw_hash

    def trigger_gateway_lease_renewal(self) -> str:
        if self.provider == "verizon":
            with self.opener.open(f"https://{self.host}/loginStatus.cgi", timeout=10) as r:
                st = json.loads(r.read().decode("utf-8", errors="ignore"))
            if not self.password:
                return f"verizon_gateway_verified_{st.get('modelName', 'ASK-NCM1100')}_password_optional"
            login_tok = str(st.get("loginToken", st.get("token", "")))
            verify = self._verizon_arc_md5(self.password, login_tok)
            login_body = urllib.parse.urlencode(
                {
                    "luci_username": self._verizon_arc_md5("admin"),
                    "luci_password": verify,
                    "luci_view": "Desktop",
                    "luci_token": login_tok,
                    "luci_keep_login": "1",
                }
            ).encode("utf-8")
            try:
                self.opener.open(urllib.request.Request(f"https://{self.host}/login.cgi", data=login_body, method="POST"), timeout=10).read()
                with self.opener.open(f"https://{self.host}/loginStatus.cgi", timeout=10) as r2:
                    session_tok = str(json.loads(r2.read().decode("utf-8", errors="ignore")).get("token", ""))
                renew_body = urllib.parse.urlencode({"token": session_tok, "action": "renew4_6"}).encode("utf-8")
                self.opener.open(urllib.request.Request(f"https://{self.host}/apply_abstract.cgi", data=renew_body, method="POST"), timeout=10).read()
                return "verizon_dhcp_renew4_6"
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    return f"verizon_auth_rejected_http_{exc.code}"
                raise

        if self.provider == "xfinity":
            login_body = urllib.parse.urlencode({"username": "admin", "password": self.password or "password"}).encode("utf-8")
            self.opener.open(urllib.request.Request(f"http://{self.host}/check.jst", data=login_body, method="POST"), timeout=10).read()
            rst_body = urllib.parse.urlencode({"resetInfo": "Router"}).encode("utf-8")
            self.opener.open(
                urllib.request.Request(f"http://{self.host}/actionHandler/ajaxSet_Reset_Restore.jst", data=rst_body, method="POST"),
                timeout=10,
            ).read()
            return "xfinity_router_wan_reset"

        if self.provider == "tmobile":
            login_req = urllib.request.Request(
                f"http://{self.host}/TMI/v1/auth/login",
                data=json.dumps({"username": "admin", "password": self.password}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.opener.open(login_req, timeout=10) as r:
                jwt_tok = json.loads(r.read().decode("utf-8")).get("auth", {}).get("token", "")
            rb_req = urllib.request.Request(
                f"http://{self.host}/TMI/v1/gateway/reset?set=reboot",
                data=b"{}",
                headers={"Authorization": f"Bearer {jwt_tok}", "Content-Type": "application/json"},
                method="POST",
            )
            self.opener.open(rb_req, timeout=10).read()
            return "tmobile_gateway_cycle"

        raise ValueError(f"Unsupported provider: {self.provider}")

    def rotate_ip(self, wait_sec: float = 3.0, redact_ip: bool = False, max_polls: int = 4) -> Dict[str, Any]:
        t0 = time.monotonic()
        old_ip = self.fetch_external_ip()
        method_used = self.trigger_gateway_lease_renewal()
        new_ip = old_ip
        if wait_sec <= 0.0:
            new_ip = self.fetch_external_ip()
        else:
            step = max(0.5, wait_sec / max(1, max_polls))
            for _ in range(max(1, max_polls)):
                time.sleep(step)
                candidate = self.fetch_external_ip()
                if candidate:
                    new_ip = candidate
                    if old_ip and candidate != old_ip:
                        break
        elapsed_sec = round(time.monotonic() - t0, 2)
        changed = bool(new_ip and old_ip and new_ip != old_ip)
        return {
            "provider": self.provider,
            "gateway_host": self.host,
            "source_ip": self.source_ip or "default",
            "method": method_used,
            "ip_changed": changed,
            "elapsed_sec": elapsed_sec,
            "old_ip": "***REDACTED***" if redact_ip else old_ip,
            "new_ip": "***REDACTED***" if redact_ip else new_ip,
        }


# ---------------------------------------------------------------------------
# 4. Privacy-Hardened Local HTTP / HTTPS CONNECT / SOCKS5 Proxy Server
#    + Agent-Native Proxy Username DSL (session-<id> & isp-<provider>)
# ---------------------------------------------------------------------------

def parse_proxy_username_dsl(username: str) -> Dict[str, Optional[str]]:
    """
    Parse BrightData/Oxylabs-style proxy username DSL for AI Agents & Scanners:
      - 'isp-verizon', 'isp-xfinity', 'isp-tmobile'
      - 'iface-Wi-Fi', 'iface-Wi-Fi_2'
      - 'session-<id>' (e.g. 'session-42', 'isp-verizon-session-run2', or 'session-run2-isp-verizon')
    """
    result: Dict[str, Optional[str]] = {"isp": None, "interface": None, "session": None}
    if not username:
        return result
    low = username.strip()
    boundary = r"(?=$|[-_](?:isp|iface|session)[-_])"
    m_sess = re.search(rf"(?:^|[-_])session[-_]([A-Za-z0-9._-]+?){boundary}", low, re.IGNORECASE)
    if m_sess:
        result["session"] = m_sess.group(1)
    m_isp = re.search(rf"(?:^|[-_])isp[-_](verizon|xfinity|tmobile){boundary}", low, re.IGNORECASE)
    if m_isp:
        result["isp"] = m_isp.group(1).lower()
    m_iface = re.search(rf"(?:^|[-_])iface[-_]([A-Za-z0-9._-]+?){boundary}", low, re.IGNORECASE)
    if m_iface:
        result["interface"] = m_iface.group(1).replace("_", " ")
    return result


class PrivacyProxyServer:
    ACTIVE_SOURCE_IP: Optional[str] = None
    ALLOW_PRIVATE_LAN: bool = False
    LAST_SESSION_ID: Optional[str] = None
    LAST_ROTATION_TS: float = 0.0
    SESSION_LOCK = threading.Lock()
    ROTATOR_REF: Optional[WANIPRotator] = None
    STRIP_HEADERS = frozenset(
        {
            "x-forwarded-for",
            "x-real-ip",
            "via",
            "forwarded",
            "client-ip",
            "cf-connecting-ip",
            "true-client-ip",
            "x-cluster-client-ip",
            "proxy-authorization",
            "proxy-connection",
        }
    )

    @classmethod
    def sanitize_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        return {k: v for k, v in headers.items() if k.strip().lower() not in cls.STRIP_HEADERS}

    @staticmethod
    def extract_auth_credentials(auth_header: str) -> Tuple[str, str]:
        if not auth_header:
            return "", ""
        if auth_header.startswith("Bearer "):
            return "", auth_header[len("Bearer ") :].strip()
        if auth_header.startswith("Basic "):
            try:
                raw = base64.b64decode(auth_header[len("Basic ") :].strip()).decode("utf-8", errors="ignore")
            except Exception:
                return "", ""
            if ":" in raw:
                u, p = raw.split(":", 1)
                return u, p
            return "", raw
        return "", ""

    @classmethod
    def verify_auth(cls, auth_header: str, proxy_token: Optional[str]) -> bool:
        if not proxy_token:
            return True
        _user, supplied_pw = cls.extract_auth_credentials(auth_header)
        if not supplied_pw:
            return False
        return hmac.compare_digest(supplied_pw.encode("utf-8"), proxy_token.encode("utf-8"))

    @classmethod
    def apply_username_dsl(cls, username: str, default_source_ip: Optional[str]) -> Optional[str]:
        dsl = parse_proxy_username_dsl(username)
        if dsl["session"]:
            with cls.SESSION_LOCK:
                now = time.monotonic()
                if dsl["session"] != cls.LAST_SESSION_ID and (now - cls.LAST_ROTATION_TS) >= 5.0:
                    cls.LAST_SESSION_ID = dsl["session"]
                    cls.LAST_ROTATION_TS = now
                    if cls.ROTATOR_REF is not None:
                        try:
                            cls.ROTATOR_REF.rotate_ip(wait_sec=1.5)
                        except Exception:
                            pass
        if dsl["isp"] or dsl["interface"]:
            adapters = discover_network_adapters()
            if dsl["interface"]:
                src, _, _ = resolve_adapter_source_ip(adapters, interface_or_ssid=dsl["interface"])
                if src:
                    return src
            if dsl["isp"]:
                for a in adapters:
                    if a.inferred_provider == dsl["isp"] and a.ipv4_address:
                        return a.ipv4_address
        return default_source_ip

    @staticmethod
    def parse_socks5_request(data: bytes) -> Tuple[str, int, int]:
        if len(data) < 7:
            raise ValueError("Truncated SOCKS5 request")
        ver, cmd, _rsv, atyp = data[0], data[1], data[2], data[3]
        if ver != 0x05 or cmd != 0x01:
            raise ValueError("Unsupported SOCKS5 version or command")
        if atyp == 0x01:
            if len(data) < 10:
                raise ValueError("Truncated IPv4 SOCKS5 packet")
            return socket.inet_ntop(socket.AF_INET, data[4:8]), struct.unpack("!H", data[8:10])[0], atyp
        if atyp == 0x03:
            dlen = data[4]
            if len(data) < 5 + dlen + 2:
                raise ValueError("Truncated Domain SOCKS5 packet")
            host = data[5 : 5 + dlen].decode("idna")
            port = struct.unpack("!H", data[5 + dlen : 7 + dlen])[0]
            return host, port, atyp
        if atyp == 0x04:
            if len(data) < 22:
                raise ValueError("Truncated IPv6 SOCKS5 packet")
            return socket.inet_ntop(socket.AF_INET6, data[4:20]), struct.unpack("!H", data[20:22])[0], atyp
        raise ValueError(f"Unsupported ATYP: {atyp}")

    @classmethod
    def is_forbidden_proxy_destination(cls, host: str) -> bool:
        """Block loopback, link-local/metadata, RFC1918 private LAN, and DNS-rebinding targets."""
        cleaned = host.strip().strip("[]").rstrip(".").lower()
        if cleaned in ("localhost", "localhost.localdomain", "0.0.0.0", "::", "::1"):
            return True
        if cleaned.endswith((".localhost", ".local", ".internal")):
            return True
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
                ip_obj = ip_obj.ipv4_mapped
            return (
                ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_unspecified
                or ip_obj.is_multicast
                or (ip_obj.is_private and not cls.ALLOW_PRIVATE_LAN)
            )
        except ValueError:
            return False

    @classmethod
    def create_bound_socket(cls, host: str, port: int, source_ip: Optional[str] = None, timeout: float = 15.0) -> socket.socket:
        if cls.is_forbidden_proxy_destination(host):
            raise PermissionError(f"Proxy egress blocked to forbidden loopback/private target: {host}")
        # Resolve DNS first and validate every resolved IP to prevent DNS-rebinding SSRF (e.g. 127.0.0.1.nip.io)
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not infos:
            raise OSError(f"Could not resolve proxy target: {host}")
        for _fam, _type, _proto, _canon, sockaddr in infos:
            resolved_ip = str(sockaddr[0])
            if cls.is_forbidden_proxy_destination(resolved_ip):
                raise PermissionError(
                    f"DNS-rebinding SSRF blocked: {host} resolved to forbidden IP {resolved_ip}"
                )
        target_ip = str(infos[0][4][0])
        src = (source_ip, 0) if source_ip else None
        return socket.create_connection((target_ip, port), timeout=timeout, source_address=src)

    @staticmethod
    def relay(sock_a: socket.socket, sock_b: socket.socket, idle_timeout: float = 60.0) -> None:
        pair = [sock_a, sock_b]
        try:
            while True:
                r, _, x = select.select(pair, [], pair, idle_timeout)
                if x or not r:
                    break
                for s in r:
                    dst = sock_b if s is sock_a else sock_a
                    data = s.recv(32768)
                    if not data:
                        return
                    dst.sendall(data)
        except Exception:
            pass

    @classmethod
    def serve_forever(
        cls,
        bind_addr: str = "127.0.0.1",
        port: int = 8888,
        source_ip: Optional[str] = None,
        proxy_token: Optional[str] = None,
        quiet: bool = False,
    ) -> None:
        cls.ACTIVE_SOURCE_IP = source_ip

        class _Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True

        class _Handler(socketserver.BaseRequestHandler):
            def _effective_source_ip(self) -> Optional[str]:
                return cls.ACTIVE_SOURCE_IP if cls.ACTIVE_SOURCE_IP is not None else source_ip

            def handle(self) -> None:
                c: socket.socket = self.request
                c.settimeout(15.0)
                try:
                    first = c.recv(4096)
                    if not first:
                        return
                    if first[0] == 0x05:
                        self._handle_socks5(c, first)
                    else:
                        self._handle_http(c, first)
                except Exception:
                    pass
                finally:
                    try:
                        c.close()
                    except Exception:
                        pass

            def _handle_socks5(self, c: socket.socket, greeting: bytes) -> None:
                if len(greeting) < 2:
                    return
                nmethods = greeting[1]
                methods = greeting[2 : 2 + nmethods]
                leftover = greeting[2 + nmethods :]
                conn_src_ip = self._effective_source_ip()
                if proxy_token or (0x02 in methods):
                    if 0x02 not in methods:
                        c.sendall(b"\x05\xff")
                        return
                    c.sendall(b"\x05\x02")
                    auth_pkt = leftover if leftover else c.recv(1024)
                    leftover = b""
                    if len(auth_pkt) < 3 or auth_pkt[0] != 0x01:
                        c.sendall(b"\x01\x01")
                        return
                    ulen = auth_pkt[1]
                    if len(auth_pkt) < 3 + ulen:
                        c.sendall(b"\x01\x01")
                        return
                    plen = auth_pkt[2 + ulen]
                    if len(auth_pkt) < 3 + ulen + plen:
                        c.sendall(b"\x01\x01")
                        return
                    uname = auth_pkt[2 : 2 + ulen].decode("utf-8", errors="ignore")
                    pw = auth_pkt[3 + ulen : 3 + ulen + plen].decode("utf-8", errors="ignore")
                    leftover = auth_pkt[3 + ulen + plen :]
                    if proxy_token and not hmac.compare_digest(pw.encode("utf-8"), proxy_token.encode("utf-8")):
                        c.sendall(b"\x01\x01")
                        return
                    conn_src_ip = cls.apply_username_dsl(uname, conn_src_ip)
                    c.sendall(b"\x01\x00")
                else:
                    c.sendall(b"\x05\x00")

                req = leftover if leftover else c.recv(4096)
                try:
                    host, target_port, _ = cls.parse_socks5_request(req)
                    up = cls.create_bound_socket(host, target_port, source_ip=conn_src_ip)
                except Exception:
                    c.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                    return
                with up:
                    c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                    cls.relay(c, up)

            def _handle_http(self, c: socket.socket, initial: bytes) -> None:
                while b"\r\n\r\n" not in initial and len(initial) < 65536:
                    more = c.recv(4096)
                    if not more:
                        break
                    initial += more
                idx = initial.find(b"\r\n\r\n")
                if idx == -1:
                    return
                hdr_block = initial[:idx].decode("iso-8859-1", errors="replace")
                rest = initial[idx + 4 :]
                lines = hdr_block.split("\r\n")
                parts = lines[0].split(" ")
                if len(parts) < 3:
                    return
                method, target, ver = parts[0].upper(), parts[1], parts[2]
                hdrs: Dict[str, str] = {}
                auth_val = ""
                for ln in lines[1:]:
                    if ":" in ln:
                        k, v = ln.split(":", 1)
                        ks = k.strip()
                        vs = v.strip()
                        hdrs[ks] = vs
                        if ks.lower() == "proxy-authorization":
                            auth_val = vs

                if not cls.verify_auth(auth_val, proxy_token):
                    c.sendall(
                        b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="5G Home IP Proxy"\r\nContent-Length: 0\r\n\r\n'
                    )
                    return
                uname, _ = cls.extract_auth_credentials(auth_val)
                conn_src_ip = cls.apply_username_dsl(uname, self._effective_source_ip())

                if method == "CONNECT":
                    host, p_str = (target.rsplit(":", 1) if ":" in target else (target, "443"))
                    try:
                        up = cls.create_bound_socket(host.strip("[]"), int(p_str), source_ip=conn_src_ip)
                    except Exception:
                        c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        return
                    with up:
                        c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        if rest:
                            up.sendall(rest)
                        cls.relay(c, up)
                else:
                    u = urllib.parse.urlsplit(target)
                    host = u.hostname or hdrs.get("Host", "").split(":")[0]
                    t_port = u.port or 80
                    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                    clean = cls.sanitize_headers(hdrs)
                    clean["Connection"] = "close"
                    out_lines = [f"{method} {path} {ver}"] + [f"{k}: {v}" for k, v in clean.items()]
                    payload = ("\r\n".join(out_lines) + "\r\n\r\n").encode("iso-8859-1") + rest
                    try:
                        up = cls.create_bound_socket(host, t_port, source_ip=conn_src_ip)
                    except Exception:
                        c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        return
                    with up:
                        up.sendall(payload)
                        cls.relay(c, up)

        with _Server((bind_addr, port), _Handler) as srv:
            if not quiet:
                print(
                    f"[5G Home IP Proxy] Proxy listening on {bind_addr}:{port} "
                    f"(HTTP + HTTPS CONNECT + SOCKS5 | source_ip={source_ip or 'default'} | "
                    f"auth={'enabled' if proxy_token else 'disabled'})",
                    flush=True,
                )
            srv.serve_forever()


# ---------------------------------------------------------------------------
# 5. Interactive Local Web Control Panel (GET / & POST /api/rotate-ip)
# ---------------------------------------------------------------------------

def render_proxy_control_center_html(
    adapters: List[NetworkAdapterInfo],
    active_source_ip: Optional[str],
    active_provider: str,
    proxy_port: int,
) -> str:
    adapter_rows = []
    for a in adapters:
        is_sel = "SELECTED" if (a.ipv4_address and a.ipv4_address == active_source_ip) else a.state.upper()
        ssid_badge = f"<code>{a.ssid}</code>" if a.ssid else "<em>Wired / Standby</em>"
        adapter_rows.append(
            f"<tr>"
            f"<th>{a.interface_name}</th>"
            f"<td>{ssid_badge}</td>"
            f"<td><code>{a.ipv4_address or 'Unassigned'}</code></td>"
            f"<td><code>{a.gateway_ip or 'N/A'}</code> ({a.inferred_provider.upper()})</td>"
            f"<td><strong>{is_sel}</strong></td>"
            f"</tr>"
        )
    rows_html = "\n".join(adapter_rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- MANDATORY: Declare support for both light and dark themes -->
  <meta name="color-scheme" content="light dark">
  <title>5G Home Internet IP Proxy &amp; 1-Click Rotator</title>
  <style>
    :root {{
      --bg-light: #f8fafc;
      --bg-dark: #090d16;
      --card-light: #ffffff;
      --card-dark: #111827;
      --text-light: #0f172a;
      --text-dark: #f8fafc;
      --muted-light: #475569;
      --muted-dark: #94a3b8;
      --border-light: #e2e8f0;
      --border-dark: #1f2937;
      --brand-accent-light: #0284c7;
      --brand-accent-dark: #38bdf8;

      --bg: var(--bg-light);
      --card: var(--card-light);
      --text: var(--text-light);
      --muted: var(--muted-light);
      --border: var(--border-light);
      --accent-color: var(--brand-accent-light);

      @media (prefers-color-scheme: dark) {{
        --bg: var(--bg-dark);
        --card: var(--card-dark);
        --text: var(--text-dark);
        --muted: var(--muted-dark);
        --border: var(--border-dark);
        --accent-color: var(--brand-accent-dark);
      }}

      @supports (color: light-dark(white, black)) {{
        --bg: light-dark(var(--bg-light), var(--bg-dark));
        --card: light-dark(var(--card-light), var(--card-dark));
        --text: light-dark(var(--text-light), var(--text-dark));
        --muted: light-dark(var(--muted-light), var(--muted-dark));
        --border: light-dark(var(--border-light), var(--border-dark));
        --accent-color: light-dark(var(--brand-accent-light), var(--brand-accent-dark));
      }}

      color-scheme: light dark;
      accent-color: var(--accent-color);
    }}

    @supports not (accent-color: var(--accent-color)) {{
      progress {{
        -webkit-appearance: none;
        appearance: none;
        border: none;
        background: #ccc;
        height: 8px;
        border-radius: 4px;
      }}
      progress::-webkit-progress-value {{
        background-color: var(--accent-color);
        border-radius: 4px;
      }}
    }}

    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 24px;
    }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    .hero {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 24px;
      margin-bottom: 20px;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
    }}
    h1 {{ margin: 0 0 6px 0; font-size: 1.45rem; }}
    .sub {{ margin: 0; color: var(--muted); font-size: 0.92rem; }}
    .btn {{
      background: var(--accent-color);
      color: #090d16;
      font-weight: 700;
      border: none;
      border-radius: 10px;
      padding: 12px 20px;
      font-size: 0.95rem;
      cursor: pointer;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px;
    }}
    .lbl {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }}
    .val {{ font-size: 1.35rem; font-weight: 700; margin-top: 6px; }}
    .table-wrap {{
      container-type: inline-size;
      overflow-x: auto;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 20px;
    }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }}
    th, td {{ padding: 12px 16px; border-bottom: 1px solid var(--border); }}
    pre, code {{
      color-scheme: dark;
      accent-color: var(--accent-color);
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      font-size: 0.85rem;
    }}
    pre {{
      background: #0b1120;
      color: #e2e8f0;
      padding: 14px;
      border-radius: 10px;
      overflow-x: auto;
    }}
  </style>
</head>
<body>
  <div class="container">
    <section class="hero">
      <div>
        <h1>5G Home Internet IP Proxy &amp; 1-Click WAN Rotator</h1>
        <p class="sub">Zero-Config Residential 5G &amp; Dual-Wi-Fi Proxy (HTTP + HTTPS CONNECT + SOCKS5 Remote DNS)</p>
      </div>
      <div style="display:flex;gap:8px;align-items:center;">
        <input id="ctrl-token" type="password" placeholder="Optional X-Control-Token" style="padding:10px 12px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);">
        <button class="btn" id="rotate-btn" onclick="triggerRotate()">Rotate My 5G / WAN IP Now</button>
      </div>
    </section>

    <div class="grid">
      <div class="card">
        <div class="lbl">Active Proxy Endpoint</div>
        <div class="val"><code>127.0.0.1:{proxy_port}</code></div>
      </div>
      <div class="card">
        <div class="lbl">Bound Adapter IP</div>
        <div class="val"><code>{active_source_ip or "System Default"}</code></div>
      </div>
      <div class="card">
        <div class="lbl">Detected ISP / 5G Cube</div>
        <div class="val">{active_provider.upper()}</div>
      </div>
      <div class="card">
        <div class="lbl">Last Rotation Status</div>
        <div class="val" id="rot-status">Ready</div>
        <progress id="rot-progress" max="100" value="100" style="width:100%;margin-top:8px;"></progress>
      </div>
    </div>

    <div tabindex="0" role="region" aria-label="Auto-Discovered Wi-Fi and Network Adapters" class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Adapter</th>
            <th>Wi-Fi SSID</th>
            <th>Local IPv4</th>
            <th>Gateway &amp; Provider</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>

    <div class="card">
      <div class="lbl">Instant Browser / CLI Proxy Commands (Leak-Free Remote DNS via socks5h://)</div>
      <pre>curl.exe -x socks5h://127.0.0.1:{proxy_port} https://api.ipify.org?format=json</pre>
    </div>
  </div>

  <script>
    async function triggerRotate() {{
      const btn = document.getElementById('rotate-btn');
      const st = document.getElementById('rot-status');
      const pr = document.getElementById('rot-progress');
      const tokEl = document.getElementById('ctrl-token');
      const headers = {{ 'Content-Type': 'application/json' }};
      if (tokEl && tokEl.value.trim()) {{
        headers['X-Control-Token'] = tokEl.value.trim();
      }}
      btn.disabled = true;
      st.textContent = 'Renewing Lease...';
      pr.value = 35;
      try {{
        const resp = await fetch('/api/rotate-ip', {{ method: 'POST', headers }});
        const data = await resp.json();
        pr.value = 100;
        if (!resp.ok || data.status === 'error') {{
          st.textContent = data.message || ('Error HTTP ' + resp.status);
        }} else if (data.new_ip) {{
          st.textContent = data.old_ip + ' -> ' + data.new_ip;
        }} else {{
          st.textContent = data.method || 'Completed';
        }}
      }} catch (err) {{
        st.textContent = 'Error';
      }} finally {{
        btn.disabled = false;
      }}
    }}
  </script>
</body>
</html>"""


def append_chained_audit_record(audit_log: List[Dict[str, Any]], event_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Append a tamper-evident SHA-256 hash-chained ROE / SOC egress audit record."""
    seq = len(audit_log) + 1
    prev_hash = audit_log[-1].get("entry_hash", "0" * 64) if audit_log else ("0" * 64)
    record: Dict[str, Any] = {
        "seq": seq,
        **event_payload,
        "prev_hash": prev_hash,
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record["entry_hash"] = hashlib.sha256(canonical).hexdigest()
    audit_log.append(record)
    return record


def verify_audit_log_chain(audit_log: List[Dict[str, Any]]) -> bool:
    """Verify cryptographic integrity of the SHA-256 hash-chained ROE / SOC audit log."""
    expected_prev = "0" * 64
    for idx, entry in enumerate(audit_log, start=1):
        if entry.get("seq") != idx or entry.get("prev_hash") != expected_prev:
            return False
        claimed_hash = str(entry.get("entry_hash", ""))
        check_copy = {k: v for k, v in entry.items() if k != "entry_hash"}
        canonical = json.dumps(check_copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
        computed = hashlib.sha256(canonical).hexdigest()
        if not hmac.compare_digest(claimed_hash, computed):
            return False
        expected_prev = claimed_hash
    return True


def is_allowed_control_origin(origin: str) -> bool:
    """Reject cross-origin drive-by requests from external websites; allow extensions and localhost."""
    if not origin:
        return True
    low = origin.strip().lower()
    if low.startswith(("chrome-extension://", "moz-extension://", "safari-web-extension://")):
        return True
    if low.startswith(("http://127.0.0.1:", "http://localhost:", "http://[::1]:")) or low in (
        "http://127.0.0.1",
        "http://localhost",
    ):
        return True
    return False


def make_control_center_handler(
    rotator: WANIPRotator,
    proxy_port: int,
    audit_log: Optional[List[Dict[str, Any]]] = None,
    control_token: Optional[str] = None,
) -> type:
    egress_audit_log: List[Dict[str, Any]] = audit_log if audit_log is not None else []
    state_lock = threading.Lock()
    rotations_count = [0]

    class ControlCenterHandler(BaseHTTPRequestHandler):
        def _check_origin_and_token(self, require_token: bool = True) -> bool:
            origin = str(self.headers.get("Origin") or "").strip()
            if not is_allowed_control_origin(origin):
                self._send_json(403, {"status": "error", "message": "Forbidden cross-origin request blocked"})
                return False
            if require_token and control_token:
                supplied = str(self.headers.get("X-Control-Token") or "").strip()
                if not supplied:
                    auth = str(self.headers.get("Authorization") or "").strip()
                    if auth.startswith("Bearer "):
                        supplied = auth[len("Bearer ") :].strip()
                if not supplied or not hmac.compare_digest(supplied.encode("utf-8"), control_token.encode("utf-8")):
                    self._send_json(401, {"status": "error", "message": "Unauthorized: valid X-Control-Token required"})
                    return False
            return True

        def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, indent=2).encode("utf-8")
            origin = str(self.headers.get("Origin") or "").strip()
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            if origin and is_allowed_control_origin(origin):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Control-Token")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self) -> None:
            origin = str(self.headers.get("Origin") or "").strip()
            if not is_allowed_control_origin(origin):
                self.send_response(403)
                self.end_headers()
                return
            self.send_response(204)
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Control-Token")
            self.end_headers()

        def do_GET(self) -> None:
            if self.path in ("/", "/dashboard"):
                if not self._check_origin_and_token(require_token=False):
                    return
                adapters = discover_network_adapters()
                body = render_proxy_control_center_html(
                    adapters=adapters,
                    active_source_ip=rotator.source_ip,
                    active_provider=rotator.provider,
                    proxy_port=proxy_port,
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/api/adapters":
                if not self._check_origin_and_token(require_token=True):
                    return
                adapters = [asdict(a) for a in discover_network_adapters()]
                self._send_json(200, {"adapters": adapters})
            elif self.path == "/api/status":
                if not self._check_origin_and_token(require_token=True):
                    return
                adapters = [asdict(a) for a in discover_network_adapters()]
                ext_ip = rotator.fetch_external_ip()
                with state_lock:
                    self._send_json(
                        200,
                        {
                            "proxy_port": proxy_port,
                            "active_source_ip": rotator.source_ip,
                            "provider": rotator.provider,
                            "gateway_host": rotator.host,
                            "external_ip": ext_ip,
                            "wan_ip": ext_ip,
                            "rotations_count": rotations_count[0],
                            "adapters": adapters,
                            "audit_log_count": len(egress_audit_log),
                            "audit_chain_valid": verify_audit_log_chain(egress_audit_log),
                            "pinned_gateways": dict(TLSFingerprintPinner.PINNED_CERTS),
                        },
                    )
            elif self.path == "/api/audit-log":
                if not self._check_origin_and_token(require_token=True):
                    return
                with state_lock:
                    self._send_json(
                        200,
                        {
                            "count": len(egress_audit_log),
                            "chain_valid": verify_audit_log_chain(egress_audit_log),
                            "audit_log": list(egress_audit_log),
                        },
                    )
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self) -> None:
            if not self._check_origin_and_token(require_token=True):
                return
            if self.path == "/api/rotate-ip":
                content_len = int(self.headers.get("Content-Length", "0") or "0")
                raw_body = self.rfile.read(content_len).decode("utf-8", errors="ignore") if content_len > 0 else "{}"
                try:
                    req_obj = json.loads(raw_body) if raw_body else {}
                except Exception:
                    req_obj = {}
                if req_obj.get("password"):
                    rotator.password = str(req_obj["password"])
                if req_obj.get("host"):
                    try:
                        rotator.host = validate_gateway_host(str(req_obj["host"]))
                    except (ValueError, PermissionError) as exc:
                        self._send_json(400, {"status": "error", "message": str(exc)})
                        return
                gw_type = str(req_obj.get("gateway_type") or "").lower()
                if "xfinity" in gw_type:
                    rotator.provider = "xfinity"
                elif "tmobile" in gw_type:
                    rotator.provider = "tmobile"
                elif "verizon" in gw_type:
                    rotator.provider = "verizon"
                try:
                    wait_val = float(req_obj.get("wait_sec", 2.0))
                    res = rotator.rotate_ip(wait_sec=wait_val)
                    code = 200
                    with state_lock:
                        rotations_count[0] += 1
                        append_chained_audit_record(
                            egress_audit_log,
                            {
                                "timestamp_epoch": round(time.time(), 3),
                                "event": "wan_ip_rotation",
                                "provider": rotator.provider,
                                "source_ip": rotator.source_ip or "default",
                                "old_ip": res.get("old_ip", ""),
                                "new_ip": res.get("new_ip", ""),
                                "ip_changed": res.get("ip_changed", False),
                                "method": res.get("method", ""),
                            },
                        )
                except Exception as exc:
                    res = {"status": "error", "message": str(exc)}
                    code = 500
                self._send_json(code, res)
            elif self.path == "/api/select-adapter":
                content_len = int(self.headers.get("Content-Length", "0") or "0")
                raw_body = self.rfile.read(content_len).decode("utf-8", errors="ignore") if content_len > 0 else "{}"
                try:
                    req_obj = json.loads(raw_body) if raw_body else {}
                except Exception:
                    req_obj = {}
                target_iface = str(req_obj.get("interface") or req_obj.get("ssid") or "").strip()
                explicit_ip = str(req_obj.get("source_ip") or "").strip() or None
                adapters = discover_network_adapters()
                new_src, new_gw, new_prov = resolve_adapter_source_ip(
                    adapters,
                    interface_or_ssid=target_iface or None,
                    explicit_source_ip=explicit_ip,
                )
                with state_lock:
                    rotator.source_ip = new_src
                    rotator.host = new_gw
                    rotator.provider = new_prov if new_prov != "generic" else "verizon"
                    rotator.opener = build_opener(source_ip=new_src, cookie_jar=rotator.cookies)
                    PrivacyProxyServer.ACTIVE_SOURCE_IP = new_src
                    append_chained_audit_record(
                        egress_audit_log,
                        {
                            "timestamp_epoch": round(time.time(), 3),
                            "event": "adapter_switch",
                            "interface_requested": target_iface or (explicit_ip or "auto"),
                            "active_source_ip": new_src or "default",
                            "provider": rotator.provider,
                            "gateway_host": new_gw,
                        },
                    )
                self._send_json(
                    200,
                    {
                        "status": "switched",
                        "active_source_ip": new_src,
                        "gateway_host": new_gw,
                        "provider": rotator.provider,
                    },
                )
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            return

    return ControlCenterHandler


# ---------------------------------------------------------------------------
# 6. Built-In Zero-Dependency MCP JSON-RPC 2.0 Server for Red-Team AI Agents
# ---------------------------------------------------------------------------

class MCPAgentServer:
    """
    Model Context Protocol (MCP) JSON-RPC 2.0 stdio server for Claude Code,
    OpenAI Codex, Cursor, and autonomous offensive security / bug-bounty agents.
    """

    TOOLS = [
        {
            "name": "get_5g_egress_status",
            "description": "Get current 5G Home / Xfinity public WAN IP, bound Wi-Fi adapter, discovered interfaces, TOFU pinned gateway certs, and ROE audit chain status.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "rotate_5g_wan_ip",
            "description": "Trigger a 1-click 5G Home / Xfinity WAN IP lease renewal, poll for the new IP, and record a SHA-256 hash-chained ROE audit log entry.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "provider": {"type": "string", "enum": ["verizon", "xfinity", "tmobile"]},
                    "host": {"type": "string", "description": "Optional RFC1918 LAN gateway IP (e.g. 192.168.1.1)"},
                    "wait_sec": {"type": "number", "default": 2.0},
                },
            },
        },
        {
            "name": "switch_egress_adapter",
            "description": "Switch outbound proxy binding between local Wi-Fi/LAN adapters (e.g. 'Wi-Fi', 'Wi-Fi 2', 'xfinitywifi', or an explicit local IPv4).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "interface_or_ssid": {"type": "string"},
                    "source_ip": {"type": "string"},
                },
            },
        },
        {
            "name": "get_signed_roe_audit_log",
            "description": "Export the tamper-evident SHA-256 hash-chained Rules of Engagement (ROE) / SOC egress IP timeline.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    ]

    def __init__(
        self,
        rotator: WANIPRotator,
        audit_log: Optional[List[Dict[str, Any]]] = None,
        control_url: Optional[str] = "http://127.0.0.1:8889",
        control_token: Optional[str] = None,
    ) -> None:
        self.rotator = rotator
        self.audit_log: List[Dict[str, Any]] = audit_log if audit_log is not None else []
        self.control_url = (control_url or "").rstrip("/")
        self.control_token = control_token or os.environ.get("CONTROL_TOKEN", "")

    def _try_bridge_daemon(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """If the local :8889 Control Center daemon is running, bridge MCP calls so state & ROE logs stay unified."""
        if not self.control_url:
            return None
        try:
            headers = {"Content-Type": "application/json"}
            if self.control_token:
                headers["X-Control-Token"] = self.control_token
            data_bytes = json.dumps(body).encode("utf-8") if body is not None else None
            req = urllib.request.Request(f"{self.control_url}{path}", data=data_bytes, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=4.0) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception:
            return None

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = str(req.get("method") or "")
        req_id = req.get("id")
        params = req.get("params") or {}

        if method.startswith("notifications/"):
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "5g-home-ip-proxy-mcp", "version": "1.4.0"},
                },
            }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.TOOLS}}
        if method == "tools/call":
            tool_name = str(params.get("name") or "")
            args = params.get("arguments") or {}
            try:
                payload = self._call_tool(tool_name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                        "isError": False,
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps({"error": str(exc)})}],
                        "isError": True,
                    },
                }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def _call_tool(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name == "get_5g_egress_status":
            bridged = self._try_bridge_daemon("GET", "/api/status")
            if bridged is not None:
                return bridged
            adapters = [asdict(a) for a in discover_network_adapters()]
            wan_ip = self.rotator.fetch_external_ip()
            return {
                "wan_ip": wan_ip,
                "active_source_ip": self.rotator.source_ip,
                "provider": self.rotator.provider,
                "gateway_host": self.rotator.host,
                "adapters": adapters,
                "pinned_gateways": dict(TLSFingerprintPinner.PINNED_CERTS),
                "audit_chain_valid": verify_audit_log_chain(self.audit_log),
            }
        if tool_name == "rotate_5g_wan_ip":
            bridged = self._try_bridge_daemon(
                "POST",
                "/api/rotate-ip",
                {
                    "gateway_type": args.get("provider", self.rotator.provider),
                    "host": args.get("host", self.rotator.host),
                    "wait_sec": float(args.get("wait_sec", 2.0)),
                },
            )
            if bridged is not None:
                return bridged
            if args.get("provider"):
                self.rotator.provider = str(args["provider"])
            if args.get("host"):
                self.rotator.host = validate_gateway_host(str(args["host"]))
            wait_sec = float(args.get("wait_sec", 2.0))
            res = self.rotator.rotate_ip(wait_sec=wait_sec)
            append_chained_audit_record(
                self.audit_log,
                {
                    "timestamp_epoch": round(time.time(), 3),
                    "event": "wan_ip_rotation",
                    "provider": self.rotator.provider,
                    "source_ip": self.rotator.source_ip or "default",
                    "old_ip": res.get("old_ip", ""),
                    "new_ip": res.get("new_ip", ""),
                    "ip_changed": res.get("ip_changed", False),
                    "method": res.get("method", ""),
                },
            )
            return res
        if tool_name == "switch_egress_adapter":
            bridged = self._try_bridge_daemon(
                "POST",
                "/api/select-adapter",
                {
                    "interface": args.get("interface_or_ssid", ""),
                    "source_ip": args.get("source_ip", ""),
                },
            )
            if bridged is not None:
                return bridged
            adapters = discover_network_adapters()
            new_src, new_gw, new_prov = resolve_adapter_source_ip(
                adapters,
                interface_or_ssid=args.get("interface_or_ssid"),
                explicit_source_ip=args.get("source_ip"),
            )
            self.rotator.source_ip = new_src
            self.rotator.host = new_gw
            self.rotator.provider = new_prov if new_prov != "generic" else "verizon"
            self.rotator.opener = build_opener(source_ip=new_src, cookie_jar=self.rotator.cookies)
            PrivacyProxyServer.ACTIVE_SOURCE_IP = new_src
            append_chained_audit_record(
                self.audit_log,
                {
                    "timestamp_epoch": round(time.time(), 3),
                    "event": "adapter_switch",
                    "interface_requested": args.get("interface_or_ssid") or args.get("source_ip") or "auto",
                    "active_source_ip": new_src or "default",
                    "provider": self.rotator.provider,
                    "gateway_host": new_gw,
                },
            )
            return {
                "status": "switched",
                "active_source_ip": new_src,
                "gateway_host": new_gw,
                "provider": self.rotator.provider,
            }
        if tool_name == "get_signed_roe_audit_log":
            bridged = self._try_bridge_daemon("GET", "/api/audit-log")
            if bridged is not None:
                return bridged
            return {
                "count": len(self.audit_log),
                "chain_valid": verify_audit_log_chain(self.audit_log),
                "audit_log": list(self.audit_log),
            }
        raise ValueError(f"Unknown MCP tool: {tool_name}")

    def serve_stdio(self) -> None:
        import sys
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception:
                continue


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="5g-home-ip-proxy",
        description="5G Home Internet 1-Click WAN IP Rotator & Local Privacy-Hardened HTTP/HTTPS/SOCKS5 Proxy",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_adapters = sub.add_parser("adapters", help="Auto-discover local Wi-Fi and LAN adapters (Verizon 5G, Xfinity, T-Mobile)")

    p_srv = sub.add_parser("serve", help="Run local HTTP / HTTPS CONNECT / SOCKS5 privacy proxy")
    p_srv.add_argument("--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    p_srv.add_argument("--port", type=int, default=8888, help="Listen port (default: 8888)")
    p_srv.add_argument("--interface", default=None, help="Bind by Wi-Fi adapter name or SSID (e.g. 'Wi-Fi', 'Wi-Fi 2', 'xfinitywifi')")
    p_srv.add_argument("--source-ip", default=os.environ.get("SOURCE_IP"), help="Bind outbound traffic to specific Wi-Fi/LAN IP")
    p_srv.add_argument("--proxy-token", default=os.environ.get("PROXY_TOKEN", ""), help="Optional proxy auth token")

    p_rot = sub.add_parser("rotate-ip", help="Trigger 1-click WAN IP rotation on Verizon 5G, Xfinity, or T-Mobile 5G")
    p_rot.add_argument("--provider", choices=["auto", "verizon", "xfinity", "tmobile"], default="auto")
    p_rot.add_argument("--interface", default=None, help="Select adapter by name or SSID (e.g. 'Wi-Fi', 'xfinitywifi')")
    p_rot.add_argument("--host", default=None, help="Router IP (default: auto-detected from adapter)")
    p_rot.add_argument("--password", default=os.environ.get("GATEWAY_PASSWORD", ""), help="Router admin password")
    p_rot.add_argument("--source-ip", default=os.environ.get("SOURCE_IP"), help="Optional source IP bound to router adapter")
    p_rot.add_argument("--wait-sec", type=float, default=3.0, help="Seconds to wait before checking new external IP")
    p_rot.add_argument("--redact-ip", action="store_true", help="Mask raw public IP addresses in JSON output")
    p_rot.add_argument("--pin-cert-sha256", default=os.environ.get("GATEWAY_CERT_SHA256", ""), help="Optional SHA-256 leaf cert pin for LAN gateway")

    p_ui = sub.add_parser("ui", help="Launch both the 5G Privacy Proxy and the Interactive Web Control Center")
    p_ui.add_argument("--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    p_ui.add_argument("--proxy-port", type=int, default=8888, help="Proxy listen port (default: 8888)")
    p_ui.add_argument("--ui-port", type=int, default=8889, help="Web UI listen port (default: 8889)")
    p_ui.add_argument("--interface", default=None, help="Select adapter by name or SSID")
    p_ui.add_argument("--source-ip", default=os.environ.get("SOURCE_IP"), help="Optional source IP")
    p_ui.add_argument("--password", default=os.environ.get("GATEWAY_PASSWORD", ""), help="Router admin password for 1-click rotation")
    p_ui.add_argument("--proxy-token", default=os.environ.get("PROXY_TOKEN", ""), help="Optional proxy auth token")
    p_ui.add_argument("--control-token", default=os.environ.get("CONTROL_TOKEN", ""), help="Optional X-Control-Token for local API hardening")
    p_ui.add_argument("--pin-cert-sha256", default=os.environ.get("GATEWAY_CERT_SHA256", ""), help="Optional SHA-256 leaf cert pin for LAN gateway")

    p_mcp = sub.add_parser("mcp", help="Run built-in Model Context Protocol (MCP) stdio server for Red-Team AI Agents")
    p_mcp.add_argument("--interface", default=None, help="Select adapter by name or SSID")
    p_mcp.add_argument("--source-ip", default=os.environ.get("SOURCE_IP"), help="Optional source IP")
    p_mcp.add_argument("--password", default=os.environ.get("GATEWAY_PASSWORD", ""), help="Router admin password")
    p_mcp.add_argument("--pin-cert-sha256", default=os.environ.get("GATEWAY_CERT_SHA256", ""), help="Optional SHA-256 leaf cert pin for LAN gateway")

    args = parser.parse_args()
    if args.command == "adapters":
        print(json.dumps([asdict(a) for a in discover_network_adapters()], indent=2))
        return

    adapters = discover_network_adapters()
    src_ip, gw_ip, inferred_prov = resolve_adapter_source_ip(
        adapters,
        interface_or_ssid=getattr(args, "interface", None),
        explicit_source_ip=getattr(args, "source_ip", None),
    )

    pin_fp = getattr(args, "pin_cert_sha256", "")
    if pin_fp:
        target_gw = getattr(args, "host", None) or gw_ip
        TLSFingerprintPinner.pin_host(target_gw, pin_fp)

    if args.command == "serve":
        prov = inferred_prov if inferred_prov != "generic" else "verizon"
        PrivacyProxyServer.ROTATOR_REF = WANIPRotator(provider=prov, host=gw_ip, source_ip=src_ip)
        PrivacyProxyServer.serve_forever(
            bind_addr=args.bind,
            port=args.port,
            source_ip=src_ip,
            proxy_token=args.proxy_token or None,
        )
    elif args.command == "rotate-ip":
        prov = inferred_prov if args.provider == "auto" else args.provider
        if prov == "generic":
            prov = "verizon"
        rotator = WANIPRotator(
            provider=prov,
            host=args.host or gw_ip,
            password=args.password,
            source_ip=src_ip,
        )
        print(json.dumps(rotator.rotate_ip(wait_sec=args.wait_sec, redact_ip=args.redact_ip), indent=2))
    elif args.command == "mcp":
        prov = inferred_prov if inferred_prov != "generic" else "verizon"
        rotator = WANIPRotator(provider=prov, host=gw_ip, password=args.password, source_ip=src_ip)
        PrivacyProxyServer.ROTATOR_REF = rotator
        threading.Thread(
            target=PrivacyProxyServer.serve_forever,
            kwargs={"bind_addr": "127.0.0.1", "port": 8888, "source_ip": src_ip, "quiet": True},
            daemon=True,
        ).start()
        MCPAgentServer(rotator).serve_stdio()
    elif args.command == "ui":
        prov = inferred_prov if inferred_prov != "generic" else "verizon"
        rotator = WANIPRotator(provider=prov, host=gw_ip, password=args.password, source_ip=src_ip)
        PrivacyProxyServer.ROTATOR_REF = rotator
        threading.Thread(
            target=PrivacyProxyServer.serve_forever,
            kwargs={
                "bind_addr": args.bind,
                "port": args.proxy_port,
                "source_ip": src_ip,
                "proxy_token": args.proxy_token or None,
            },
            daemon=True,
        ).start()
        ui_srv = HTTPServer(
            (args.bind, args.ui_port),
            make_control_center_handler(rotator, args.proxy_port, control_token=args.control_token or None),
        )
        print(f"[5G Home IP Proxy UI] Control Center running at http://{args.bind}:{args.ui_port}/", flush=True)
        ui_srv.serve_forever()


if __name__ == "__main__":
    main()
