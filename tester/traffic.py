"""Traffic generation through a SOCKS5 proxy.

Three scenarios:
  web   — repeated HTTP GET requests to a few well-known hosts
  bulk  — continuous large download (stress-tests padding + framing)
  idle  — single long-lived TCP connection with minimal data
"""
import logging
import socket
import struct
import time
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# SOCKS5 raw helper (no external deps)
# --------------------------------------------------------------------------- #

def _socks5_connect(proxy: str, dst_host: str, dst_port: int,
                    timeout: float = 5.0) -> socket.socket:
    """Open a TCP socket through a SOCKS5 proxy."""
    ph, pp = proxy.rsplit(":", 1)
    s = socket.create_connection((ph, int(pp)), timeout=timeout)

    s.sendall(b"\x05\x01\x00")          # SOCKS5, 1 method, no-auth
    ver, method = s.recv(2)
    if ver != 5 or method != 0:
        s.close()
        raise RuntimeError(f"SOCKS5 auth failed (ver={ver} method={method})")

    host_b = dst_host.encode()
    req = (
        bytes([0x05, 0x01, 0x00, 0x03, len(host_b)])
        + host_b
        + struct.pack("!H", dst_port)
    )
    s.sendall(req)
    resp = s.recv(10)
    if len(resp) < 2 or resp[1] != 0:
        s.close()
        raise RuntimeError(f"SOCKS5 CONNECT failed (reply={resp[1] if len(resp)>1 else '?'})")
    return s


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #

def run_web_scenario(socks5_addr: str, duration: int, output_dir: Path) -> None:
    """
    Send repeated HTTP GET requests through the proxy.
    Prefers requests+PySocks; falls back to raw SOCKS5 socket.
    """
    try:
        import requests  # type: ignore
        _web_requests(socks5_addr, duration)
    except ImportError:
        log.warning("requests not installed — using raw HTTP fallback")
        _web_raw(socks5_addr, duration)


def run_bulk_scenario(socks5_addr: str, duration: int, output_dir: Path) -> None:
    """Download a large response to stress-test framing / padding."""
    try:
        import requests  # type: ignore
        proxies = {
            "http":  f"socks5h://{socks5_addr}",
            "https": f"socks5h://{socks5_addr}",
        }
        deadline = time.time() + duration
        total_bytes = 0
        while time.time() < deadline:
            try:
                # httpbin returns exactly N random bytes
                r = requests.get(
                    "http://httpbin.org/bytes/524288",  # 512 KiB
                    proxies=proxies, timeout=10, stream=True,
                )
                for chunk in r.iter_content(65536):
                    total_bytes += len(chunk)
                    if time.time() >= deadline:
                        break
            except Exception as e:
                log.debug(f"bulk chunk error: {e}")
                time.sleep(1)
        log.info(f"Bulk scenario: {total_bytes / 1024:.0f} KiB transferred in {duration} s")
    except ImportError:
        _web_raw(socks5_addr, duration)


def run_idle_scenario(socks5_addr: str, duration: int, output_dir: Path) -> None:
    """Hold one idle connection open for `duration` seconds."""
    try:
        s = _socks5_connect(socks5_addr, "example.com", 80)
        s.sendall(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"
        )
        s.settimeout(duration + 5)
        time.sleep(duration)
        s.close()
        log.info(f"Idle scenario: held connection for {duration} s")
    except Exception as e:
        log.warning(f"Idle scenario error: {e}")


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #

def _web_requests(socks5_addr: str, duration: int) -> None:
    import requests  # type: ignore
    proxies = {
        "http":  f"socks5h://{socks5_addr}",
        "https": f"socks5h://{socks5_addr}",
    }
    targets = [
        "http://example.com",
        "http://example.org",
        "http://httpbin.org/get",
        "http://httpbin.org/headers",
    ]
    deadline = time.time() + duration
    count = 0
    idx = 0
    while time.time() < deadline:
        url = targets[idx % len(targets)]
        idx += 1
        try:
            r = requests.get(url, proxies=proxies, timeout=5)
            count += 1
            log.debug(f"GET {url} → {r.status_code}")
        except Exception as e:
            log.debug(f"GET {url} failed: {e}")
        time.sleep(0.3)
    log.info(f"Web scenario: {count} requests in {duration} s")


def _web_raw(socks5_addr: str, duration: int) -> None:
    deadline = time.time() + duration
    count = 0
    while time.time() < deadline:
        try:
            s = _socks5_connect(socks5_addr, "example.com", 80, timeout=5)
            s.sendall(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            s.settimeout(5)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            s.close()
            count += 1
        except Exception as e:
            log.debug(f"raw HTTP error: {e}")
            time.sleep(1)
    log.info(f"Raw web scenario: {count} requests in {duration} s")
