"""
M8 — Active probing.

Sends several types of crafted payloads to the tunnel server's raw TCP port
and observes the response behaviour.  A real HTTPS server and a VPN server
respond very differently to garbage, partial TLS, and valid HTTP.

Probes run sequentially with short timeouts so the overall wall-clock time
stays under ~15 s.
"""
import json
import logging
import random
import socket
import statistics
import struct
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_TIMEOUT = 2.5   # seconds per probe


def analyze(server_addr: str, output_dir: Path) -> dict:
    """
    Run all probes against *server_addr* ("host:port") and return M8 metrics.
    """
    host, port_s = server_addr.rsplit(":", 1)
    port = int(port_s)

    probe_fns = {
        "random_bytes":   lambda: _probe_random(host, port),
        "partial_tls":    lambda: _probe_partial_tls(host, port),
        "valid_tls_hello": lambda: _probe_valid_tls(host, port),
        "http_get":       lambda: _probe_http(host, port),
        "empty_connect":  lambda: _probe_empty(host, port),
    }

    raw: dict = {}
    for name, fn in probe_fns.items():
        try:
            raw[name] = fn()
            log.debug("probe %-20s → %s", name, raw[name])
        except Exception as exc:
            raw[name] = {"error": str(exc), "responded": False}
            log.debug("probe %-20s → error: %s", name, exc)

    (output_dir / "probe_results.json").write_text(
        json.dumps(raw, indent=2, default=str)
    )
    return _metrics(raw)


# ── Individual probes ────────────────────────────────────────────────────────

def _tcp(host: str, port: int) -> Optional[socket.socket]:
    try:
        return socket.create_connection((host, port), timeout=_TIMEOUT)
    except OSError:
        return None


def _probe_random(host: str, port: int) -> dict:
    """32 random bytes → observe response."""
    s = _tcp(host, port)
    if not s:
        return {"connected": False}
    payload = bytes(random.randint(0, 255) for _ in range(32))
    t0 = time.monotonic()
    try:
        s.sendall(payload)
        s.settimeout(_TIMEOUT)
        resp = s.recv(4096)
        ttfb = (time.monotonic() - t0) * 1000
        s.close()
        return {
            "connected":      True,
            "responded":      True,
            "ttfb_ms":        round(ttfb, 1),
            "response_bytes": len(resp),
            "response_hex":   resp[:16].hex(),
        }
    except socket.timeout:
        s.close()
        return {"connected": True, "responded": False, "silent": True}
    except ConnectionResetError:
        return {"connected": True, "responded": False, "rst": True}


def _probe_partial_tls(host: str, port: int) -> dict:
    """Truncated TLS record header → observe response."""
    s = _tcp(host, port)
    if not s:
        return {"connected": False}
    # TLS record: content_type=22 (handshake), legacy version 0x0301, incomplete
    partial = bytes([0x16, 0x03, 0x01, 0x01, 0x00])   # claims 256 bytes but sends 0
    t0 = time.monotonic()
    try:
        s.sendall(partial)
        s.settimeout(_TIMEOUT)
        resp = s.recv(4096)
        ttfb = (time.monotonic() - t0) * 1000
        s.close()
        return {
            "connected":      True,
            "responded":      True,
            "ttfb_ms":        round(ttfb, 1),
            "response_bytes": len(resp),
        }
    except socket.timeout:
        s.close()
        return {"connected": True, "responded": False, "silent": True}
    except ConnectionResetError:
        return {"connected": True, "responded": False, "rst": True}


def _probe_valid_tls(host: str, port: int) -> dict:
    """Well-formed TLS 1.3 ClientHello → observe response."""
    s = _tcp(host, port)
    if not s:
        return {"connected": False}
    hello = _build_client_hello(host)
    t0 = time.monotonic()
    try:
        s.sendall(hello)
        s.settimeout(_TIMEOUT)
        resp = s.recv(4096)
        ttfb = (time.monotonic() - t0) * 1000
        s.close()
        is_tls = len(resp) >= 5 and resp[0] == 0x16
        return {
            "connected":       True,
            "responded":       True,
            "ttfb_ms":         round(ttfb, 1),
            "response_bytes":  len(resp),
            "looks_like_tls":  is_tls,
        }
    except socket.timeout:
        s.close()
        return {"connected": True, "responded": False, "silent": True}
    except ConnectionResetError:
        return {"connected": True, "responded": False, "rst": True}


def _probe_http(host: str, port: int) -> dict:
    """Plain HTTP GET → check if server speaks HTTP."""
    s = _tcp(host, port)
    if not s:
        return {"connected": False}
    req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    t0 = time.monotonic()
    try:
        s.sendall(req)
        s.settimeout(_TIMEOUT)
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 8192:
                break
        ttfb = (time.monotonic() - t0) * 1000
        s.close()
        is_http = resp.startswith(b"HTTP/")
        status = resp[:80].decode("utf-8", errors="replace").split("\r\n")[0] if resp else ""
        return {
            "connected":       True,
            "responded":       True,
            "ttfb_ms":         round(ttfb, 1),
            "response_bytes":  len(resp),
            "looks_like_http": is_http,
            "status_line":     status,
        }
    except (socket.timeout, ConnectionResetError) as exc:
        s.close()
        return {
            "connected": True,
            "responded": False,
            "rst":       isinstance(exc, ConnectionResetError),
        }


def _probe_empty(host: str, port: int) -> dict:
    """Connect but send nothing → check if server speaks first."""
    s = _tcp(host, port)
    if not s:
        return {"connected": False}
    t0 = time.monotonic()
    try:
        s.settimeout(_TIMEOUT)
        resp = s.recv(4096)
        ttfb = (time.monotonic() - t0) * 1000
        s.close()
        return {
            "connected":          True,
            "server_speaks_first": True,
            "ttfb_ms":            round(ttfb, 1),
            "response_bytes":     len(resp),
        }
    except socket.timeout:
        s.close()
        return {"connected": True, "server_speaks_first": False}
    except ConnectionResetError:
        return {"connected": True, "server_speaks_first": False, "rst": True}


# ── TLS ClientHello builder ──────────────────────────────────────────────────

def _build_client_hello(sni: str) -> bytes:
    """Minimal TLS 1.3 ClientHello with SNI extension."""
    rand32 = bytes(random.randint(0, 255) for _ in range(32))

    # Cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    ciphers = b"\x13\x01\x13\x02"

    # Extension: SNI
    sni_b   = sni.encode()
    sni_ext = (
        b"\x00\x00"                              # ext type: server_name
        + struct.pack("!H", len(sni_b) + 5)
        + struct.pack("!H", len(sni_b) + 3)
        + b"\x00"
        + struct.pack("!H", len(sni_b))
        + sni_b
    )

    # Extension: supported_versions = TLS 1.3
    sv_ext = b"\x00\x2b\x00\x05\x04\x03\x04\x03\x03"

    # Extension: supported_groups = x25519
    sg_ext = b"\x00\x0a\x00\x04\x00\x02\x00\x1d"

    extensions = sni_ext + sv_ext + sg_ext
    ext_block = struct.pack("!H", len(extensions)) + extensions

    hello_body = (
        b"\x03\x03"                              # legacy version
        + rand32
        + b"\x00"                                # session ID length
        + struct.pack("!H", len(ciphers)) + ciphers
        + b"\x01\x00"                            # compression: null
        + ext_block
    )

    hs  = b"\x01" + b"\x00" + struct.pack("!H", len(hello_body)) + hello_body
    rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    return rec


# ── Metric computation ───────────────────────────────────────────────────────

def _metrics(results: dict) -> dict:
    """
    Compute distinguishable_ratio: how many checks flag the server as
    NOT behaving like a real HTTPS/web server.

    Three canonical checks (matching the methodology in the thesis):
      C1. Responds to random bytes  → suspicious (real TLS server ignores/closes)
      C2. Does NOT respond to HTTP GET with an HTTP status line  → suspicious
      C3. Server speaks first on empty connect  → suspicious
    """
    flags = 0

    rb = results.get("random_bytes", {})
    if rb.get("responded"):
        flags += 1                # C1

    http = results.get("http_get", {})
    if not http.get("looks_like_http") and http.get("connected"):
        flags += 1                # C2

    empty = results.get("empty_connect", {})
    if empty.get("server_speaks_first"):
        flags += 1                # C3

    ttfbs = [
        r["ttfb_ms"] for r in results.values()
        if isinstance(r.get("ttfb_ms"), (int, float))
    ]

    return {
        "distinguishable_ratio":        round(flags / 3, 3),
        "distinguishable_flags":         flags,
        "check_random_bytes_responded":  rb.get("responded", False),
        "check_http_looks_http":         http.get("looks_like_http", False),
        "check_server_speaks_first":     empty.get("server_speaks_first", False),
        "ttfb_mean_ms":                  round(statistics.mean(ttfbs), 1) if ttfbs else None,
        "ttfb_values_ms":                ttfbs,
        "probe_count":                   len(results),
    }
