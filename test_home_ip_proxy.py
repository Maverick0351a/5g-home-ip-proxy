#!/usr/bin/env python3
"""
Offline Socket-Free Unit Test Suite for 5G Home IP Proxy & WAN IP Rotator (v1.1.0)
"""

import base64
import io
import json
import os
import struct
import unittest
from typing import List

from home_ip_proxy import (
    MCPAgentServer,
    NetworkAdapterInfo,
    PrivacyProxyServer,
    TLSFingerprintPinner,
    WANIPRotator,
    make_control_center_handler,
    parse_netsh_wlan_interfaces,
    parse_proxy_username_dsl,
    render_proxy_control_center_html,
    resolve_adapter_source_ip,
    validate_gateway_host,
    verify_audit_log_chain,
)


class DummyResp:
    def __init__(self, payload: dict) -> None:
        self._raw = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self) -> bytes:
        return self._raw


class TestHomeIPProxy(unittest.TestCase):
    def test_1_privacy_header_stripping_and_auth(self) -> None:
        hdrs = {
            "Host": "example.org",
            "User-Agent": "Mozilla/5.0",
            "X-Forwarded-For": "10.0.0.55",
            "Via": "1.1 proxy",
            "X-Real-IP": "10.0.0.55",
            "Proxy-Authorization": "Bearer secret-123",
        }
        cleaned = PrivacyProxyServer.sanitize_headers(hdrs)
        self.assertEqual(cleaned, {"Host": "example.org", "User-Agent": "Mozilla/5.0"})

        self.assertTrue(PrivacyProxyServer.verify_auth("Bearer secret-123", "secret-123"))
        self.assertFalse(PrivacyProxyServer.verify_auth("Bearer wrong", "secret-123"))
        basic = "Basic " + base64.b64encode(b"user:secret-123").decode("ascii")
        self.assertTrue(PrivacyProxyServer.verify_auth(basic, "secret-123"))

    def test_2_socks5_domain_and_ipv4_parsing(self) -> None:
        dom = b"api.ipify.org"
        pkt = b"\x05\x01\x00\x03" + bytes([len(dom)]) + dom + (443).to_bytes(2, "big")
        host, port, atyp = PrivacyProxyServer.parse_socks5_request(pkt)
        self.assertEqual((host, port, atyp), ("api.ipify.org", 443, 0x03))

        pkt4 = b"\x05\x01\x00\x01" + bytes([198, 51, 100, 77]) + (8080).to_bytes(2, "big")
        self.assertEqual(PrivacyProxyServer.parse_socks5_request(pkt4), ("198.51.100.77", 8080, 0x01))

    def test_3_verizon_and_xfinity_wan_ip_rotation(self) -> None:
        called_urls: List[str] = []
        ip_idx = [0]

        class FakeOpener:
            def open(self, req_or_url, timeout=10):
                url = req_or_url if isinstance(req_or_url, str) else req_or_url.full_url
                called_urls.append(url)
                if "api.ipify.org" in url:
                    ip_idx[0] += 1
                    return DummyResp({"ip": "198.51.100.10" if ip_idx[0] == 1 else "198.51.100.99"})
                if "loginStatus.cgi" in url:
                    return DummyResp({"token": "tok123"})
                return DummyResp({"ok": True})

        rot_vz = WANIPRotator(provider="verizon", password="pw", opener=FakeOpener())  # type: ignore
        res_vz = rot_vz.rotate_ip(wait_sec=0.0)
        self.assertTrue(res_vz["ip_changed"])
        self.assertEqual(res_vz["method"], "verizon_dhcp_renew4_6")
        self.assertEqual(res_vz["old_ip"], "198.51.100.10")
        self.assertEqual(res_vz["new_ip"], "198.51.100.99")

        ip_idx[0] = 0
        rot_xf = WANIPRotator(provider="xfinity", password="password", opener=FakeOpener())  # type: ignore
        res_xf = rot_xf.rotate_ip(wait_sec=0.0)
        self.assertTrue(res_xf["ip_changed"])
        self.assertEqual(res_xf["method"], "xfinity_router_wan_reset")

    def test_4_auto_adapter_discovery_and_ui_rendering(self) -> None:
        sample_netsh = """
    Name                   : Wi-Fi
    Description            : Killer(TM) Wi-Fi 7 BE1750x
    State                  : connected
    SSID                   : Verizon_Home_5G

    Name                   : Wi-Fi 2
    Description            : 802.11n USB Wireless LAN Card
    State                  : connected
    SSID                   : xfinitywifi
        """
        parsed = parse_netsh_wlan_interfaces(sample_netsh)
        self.assertEqual(parsed["Wi-Fi"]["ssid"], "Verizon_Home_5G")
        self.assertEqual(parsed["Wi-Fi 2"]["ssid"], "xfinitywifi")

        adapters = [
            NetworkAdapterInfo("Wi-Fi", "Killer Wi-Fi 7", "connected", "Verizon_Home_5G", "192.168.1.153", "192.168.1.1", "verizon"),
            NetworkAdapterInfo("Wi-Fi 2", "USB Wireless", "connected", "xfinitywifi", "10.0.0.44", "10.0.0.1", "xfinity"),
        ]
        src, gw, prov = resolve_adapter_source_ip(adapters, interface_or_ssid="xfinitywifi")
        self.assertEqual((src, gw, prov), ("10.0.0.44", "10.0.0.1", "xfinity"))

        html = render_proxy_control_center_html(adapters, "192.168.1.153", "verizon", 8888)
        self.assertIn('<meta name="color-scheme" content="light dark">', html)
        self.assertIn("Rotate My 5G / WAN IP Now", html)
        self.assertIn("Verizon_Home_5G", html)
        self.assertIn("xfinitywifi", html)

    def test_5_mv3_extension_and_redteam_audit_api(self) -> None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        manifest_path = os.path.join(base_dir, "extension", "manifest.json")
        self.assertTrue(os.path.isfile(manifest_path))
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(manifest["manifest_version"], 3)
        self.assertEqual(manifest["name"], "5G Home Internet IP Rotator & Dual-WiFi Proxy Switcher")
        for perm in ("proxy", "privacy", "storage", "alarms", "browsingData", "activeTab"):
            self.assertIn(perm, manifest["permissions"])
        self.assertNotIn("tabs", manifest["permissions"])

        for sz_str, rel_path in manifest["icons"].items():
            expected_sz = int(sz_str)
            full_icon = os.path.join(base_dir, "extension", rel_path)
            self.assertTrue(os.path.isfile(full_icon))
            with open(full_icon, "rb") as img:
                sig = img.read(8)
                self.assertEqual(sig, b"\x89PNG\r\n\x1a\n")
                _len, tag = struct.unpack("!I4s", img.read(8))
                self.assertEqual(tag, b"IHDR")
                w, h = struct.unpack("!II", img.read(8))
                self.assertEqual((w, h), (expected_sz, expected_sz))

        audit_log: list = []

        class FakeOpener:
            def open(self, req_or_url, timeout=10):
                url = req_or_url if isinstance(req_or_url, str) else req_or_url.full_url
                if "api.ipify.org" in url:
                    return DummyResp({"ip": "198.51.100.200"})
                return DummyResp({"token": "tok"})

        rotator = WANIPRotator(provider="verizon", password="pw", source_ip="192.168.1.153", opener=FakeOpener())  # type: ignore
        handler_cls = make_control_center_handler(rotator, proxy_port=8888, audit_log=audit_log)

        class DummyRequestHandler(handler_cls):  # type: ignore
            def __init__(self, method: str, path: str, body: bytes = b"") -> None:
                self.command = method
                self.path = path
                self.headers = {"Content-Length": str(len(body))}
                self.rfile = io.BytesIO(body)
                self.wfile = io.BytesIO()
                self.status_code = 0

            def send_response(self, code: int, message=None) -> None:
                self.status_code = code

            def send_header(self, k: str, v: str) -> None:
                pass

            def end_headers(self) -> None:
                pass

        h_rot = DummyRequestHandler("POST", "/api/rotate-ip", json.dumps({"gateway_type": "verizon_askey", "wait_sec": 0.0}).encode("utf-8"))
        h_rot.do_POST()
        self.assertEqual(h_rot.status_code, 200)

        h_aud = DummyRequestHandler("GET", "/api/audit-log")
        h_aud.do_GET()
        self.assertEqual(h_aud.status_code, 200)
        aud_payload = json.loads(h_aud.wfile.getvalue().decode("utf-8"))
        self.assertEqual(aud_payload["count"], 1)
        self.assertTrue(aud_payload["chain_valid"])
        self.assertEqual(aud_payload["audit_log"][0]["event"], "wan_ip_rotation")

    def test_6_security_hardening_v1_3_0(self) -> None:
        # 1. Gateway RFC1918 Anti-SSRF Host Whitelist
        self.assertEqual(validate_gateway_host("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_gateway_host("10.0.0.1"), "10.0.0.1")
        self.assertEqual(validate_gateway_host("192.168.12.1"), "192.168.12.1")
        for forbidden_gw in ("127.0.0.1", "169.254.169.254", "8.8.8.8", "0.0.0.0"):
            with self.assertRaises(PermissionError):
                validate_gateway_host(forbidden_gw)

        # 2. Proxy Egress Loopback & Cloud Metadata SSRF Block
        for blocked_dst in ("127.0.0.1", "localhost", "::1", "169.254.169.254", "0.0.0.0"):
            self.assertTrue(PrivacyProxyServer.is_forbidden_proxy_destination(blocked_dst))
            with self.assertRaises(PermissionError):
                PrivacyProxyServer.create_bound_socket(blocked_dst, 80)
        self.assertFalse(PrivacyProxyServer.is_forbidden_proxy_destination("93.184.216.34"))

        # 3. TOFU / Explicit SHA-256 Leaf Certificate Pinning
        TLSFingerprintPinner.PINNED_CERTS.clear()
        fp1 = TLSFingerprintPinner.verify_or_pin("192.168.1.1", b"askey-legit-der-cert")
        self.assertEqual(len(fp1), 64)
        self.assertEqual(TLSFingerprintPinner.verify_or_pin("192.168.1.1", b"askey-legit-der-cert"), fp1)
        with self.assertRaises(PermissionError):
            TLSFingerprintPinner.verify_or_pin("192.168.1.1", b"evil-twin-mitm-cert")
        TLSFingerprintPinner.PINNED_CERTS.clear()

        # 4. Drive-By Web Attack Origin Lock, X-Control-Token Auth, and SHA-256 Hash-Chained Audit Log
        audit_log: list = []

        class FakeOpener:
            def open(self, req_or_url, timeout=10):
                url = req_or_url if isinstance(req_or_url, str) else req_or_url.full_url
                if "api.ipify.org" in url:
                    return DummyResp({"ip": "198.51.100.200"})
                return DummyResp({"token": "tok"})

        rotator = WANIPRotator(provider="verizon", password="pw", source_ip="192.168.1.153", opener=FakeOpener())  # type: ignore
        handler_cls = make_control_center_handler(
            rotator, proxy_port=8888, audit_log=audit_log, control_token="redteam-secret-token"
        )

        class HardenedDummyHandler(handler_cls):  # type: ignore
            def __init__(self, method: str, path: str, body: bytes = b"", headers: dict | None = None) -> None:
                self.command = method
                self.path = path
                self.headers = {"Content-Length": str(len(body)), **(headers or {})}
                self.rfile = io.BytesIO(body)
                self.wfile = io.BytesIO()
                self.status_code = 0

            def send_response(self, code: int, message=None) -> None:
                self.status_code = code

            def send_header(self, k: str, v: str) -> None:
                pass

            def end_headers(self) -> None:
                pass

        # 4a. Block cross-origin drive-by web attack (Origin: https://evil.example.com) -> 403
        h_evil = HardenedDummyHandler(
            "POST",
            "/api/rotate-ip",
            b"{}",
            headers={"Origin": "https://evil.example.com", "X-Control-Token": "redteam-secret-token"},
        )
        h_evil.do_POST()
        self.assertEqual(h_evil.status_code, 403)

        # 4b. Block missing/invalid X-Control-Token -> 401
        h_unauth = HardenedDummyHandler(
            "GET",
            "/api/status",
            headers={"Origin": "chrome-extension://abcdefghijklmnop"},
        )
        h_unauth.do_GET()
        self.assertEqual(h_unauth.status_code, 401)

        # 4c. Block SSRF host in POST /api/rotate-ip -> 400
        h_ssrf = HardenedDummyHandler(
            "POST",
            "/api/rotate-ip",
            json.dumps({"host": "169.254.169.254"}).encode("utf-8"),
            headers={"Origin": "chrome-extension://abcdefghijklmnop", "X-Control-Token": "redteam-secret-token"},
        )
        h_ssrf.do_POST()
        self.assertEqual(h_ssrf.status_code, 400)

        # 4d. Valid authenticated rotation & SHA-256 hash chain tamper detection
        for _ in range(2):
            h_ok = HardenedDummyHandler(
                "POST",
                "/api/rotate-ip",
                json.dumps({"host": "192.168.1.1", "wait_sec": 0.0}).encode("utf-8"),
                headers={"Origin": "chrome-extension://abcdefghijklmnop", "X-Control-Token": "redteam-secret-token"},
            )
            h_ok.do_POST()
            self.assertEqual(h_ok.status_code, 200)

        self.assertEqual(len(audit_log), 2)
        self.assertTrue(verify_audit_log_chain(audit_log))
        # Tamper with record #1 and confirm verify_audit_log_chain detects it
        audit_log[0]["new_ip"] = "203.0.113.99"
        self.assertFalse(verify_audit_log_chain(audit_log))

    def test_7_agent_native_mcp_and_proxy_username_dsl(self) -> None:
        # 1. Proxy Username DSL parsing (BrightData / Oxylabs style, any token order)
        dsl1 = parse_proxy_username_dsl("isp-verizon-session-run42")
        self.assertEqual(dsl1["isp"], "verizon")
        self.assertEqual(dsl1["session"], "run42")

        dsl1_rev = parse_proxy_username_dsl("session-run42-isp-verizon")
        self.assertEqual(dsl1_rev["isp"], "verizon")
        self.assertEqual(dsl1_rev["session"], "run42")

        dsl2 = parse_proxy_username_dsl("isp-xfinity")
        self.assertEqual(dsl2["isp"], "xfinity")
        self.assertIsNone(dsl2["session"])

        dsl3 = parse_proxy_username_dsl("iface-Wi-Fi_2-session-alpha9")
        self.assertEqual(dsl3["interface"], "Wi-Fi 2")
        self.assertEqual(dsl3["session"], "alpha9")

        # 1b. IPv4-mapped IPv6 SSRF unwrapping
        self.assertTrue(PrivacyProxyServer.is_forbidden_proxy_destination("::ffff:127.0.0.1"))
        self.assertTrue(PrivacyProxyServer.is_forbidden_proxy_destination("::ffff:169.254.169.254"))

        # 2. Built-in MCP Server JSON-RPC 2.0 protocol & tool execution (standalone mode)
        class FakeOpener:
            def open(self, req_or_url, timeout=10):
                url = req_or_url if isinstance(req_or_url, str) else req_or_url.full_url
                if "api.ipify.org" in url:
                    return DummyResp({"ip": "198.51.100.250"})
                return DummyResp({"token": "tok"})

        rotator = WANIPRotator(provider="verizon", password="pw", source_ip="192.168.1.153", opener=FakeOpener())  # type: ignore
        mcp = MCPAgentServer(rotator, control_url="")

        init_resp = mcp.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertIsNotNone(init_resp)
        self.assertEqual(init_resp["result"]["serverInfo"]["version"], "1.4.0")  # type: ignore

        tools_resp = mcp.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tool_names = [t["name"] for t in tools_resp["result"]["tools"]]  # type: ignore
        self.assertIn("get_5g_egress_status", tool_names)
        self.assertIn("rotate_5g_wan_ip", tool_names)
        self.assertIn("switch_egress_adapter", tool_names)
        self.assertIn("get_signed_roe_audit_log", tool_names)

        rot_call = mcp.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "rotate_5g_wan_ip", "arguments": {"wait_sec": 0.0}},
            }
        )
        self.assertFalse(rot_call["result"]["isError"])  # type: ignore

        log_call = mcp.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "get_signed_roe_audit_log", "arguments": {}},
            }
        )
        log_data = json.loads(log_call["result"]["content"][0]["text"])  # type: ignore
        self.assertEqual(log_data["count"], 1)
        self.assertTrue(log_data["chain_valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
