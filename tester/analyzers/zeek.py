"""
M3 — JA3/TLS metadata via Zeek + byte-entropy analysis of TCP payloads.

Two complementary detection methods:

1. **Zeek** (Docker): extracts ssl.log + conn.log → JA3 fingerprints,
   TLS version/SNI, unknown-service connection count.

2. **Payload entropy** (Python/dpkt, no Docker): reads raw TCP payload bytes
   and computes per-stream Shannon entropy.  Encrypted/random streams have
   entropy ≈ 7.8–8.0 bits; plain HTTP/text is typically 4–6 bits.
   This catches raw Noise-protocol tunnels that produce no TLS at all.

Windows / cyrillic-path note
─────────────────────────────
Same workaround as Suricata: stage files in a temp ASCII directory when the
host paths contain non-ASCII characters.

Volume-mount fix
─────────────────
The old code used str(zeek_out) as a dict key twice (for /logs and /scripts),
so Python silently dropped the /logs mapping and Zeek had nowhere to write.
Fixed by using a scripts/ subdirectory so keys are distinct.
"""
import logging
import math
import shutil
import struct
import sys
import tempfile
from pathlib import Path
from typing import Dict, Iterator, List, Set

from ..utils.docker_run import docker_run, docker_available, pull_if_missing

log = logging.getLogger(__name__)

ZEEK_IMAGE = "zeek/zeek:latest"

# Known browser JA3 fingerprints (illustrative — shift with every release)
BROWSER_JA3: Dict[str, str] = {
    "Chrome-120":  "8f52d1ce3e845a97d2804a2e4e0f5699",
    "Firefox-120": "25b4dbb5ff6d68c1e91e3d1f741f5bec",
    "Safari-17":   "773906b0efdefa24a7f2b8eb6985bf37",
    "Edge-120":    "b32309a26951912be7dba376398abc3b",
}

# Zeek script embedded as a string so no external file is needed.
# Loaded from /scripts/local.zeek inside the container.
_LOCAL_ZEEK = """\
@load base/protocols/conn
@load base/protocols/ssl
@load policy/protocols/ssl/ssl-log-ext
"""

# ── entropy / protocol-detection thresholds ──────────────────────────────────
# Byte-level Shannon entropy of a truly random/encrypted byte sequence is ≈8.0.
# We flag a TCP stream as "high-entropy" when its sampled payload exceeds this.
_ENTROPY_THRESHOLD     = 6.5   # bits  (TLS ≈7.7, Noise/raw ≈7.9, HTTP ≈4.5)
_MIN_SUSPICIOUS_BYTES  = 500   # ignore very short streams
_MAX_SAMPLE_PER_STREAM = 4096  # bytes to sample per stream for entropy


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def analyze(pcap_path: Path, output_dir: Path) -> dict:
    """Run Zeek + entropy analysis on *pcap_path*.  Returns M3 metrics."""

    # --- entropy analysis (Python-side, always runs, no Docker required) -----
    entropy_info = _compute_payload_entropy(pcap_path)

    # --- Zeek via Docker -----------------------------------------------------
    if not docker_available():
        log.warning("Docker unavailable — skipping Zeek JA3 (M3)")
        result = _empty_zeek_result()
    elif not pull_if_missing(ZEEK_IMAGE):
        result = _empty_zeek_result()
    else:
        zeek_out = output_dir / "zeek"
        zeek_out.mkdir(exist_ok=True)

        if sys.platform == "win32" and _has_non_ascii(pcap_path, output_dir):
            result = _analyze_via_tempdir(pcap_path, zeek_out)
        else:
            result = _run_zeek(pcap_path, zeek_out)

    # Merge entropy data into Zeek result (entropy fields take precedence)
    result.update(entropy_info)
    return result


def _empty_zeek_result() -> dict:
    return {
        "ja3_hashes":    [],
        "ja3s_hashes":   [],
        "snis":          [],
        "cipher_suites": [],
        "tls_versions":  [],
        "browser_matches":  [],
        "ja3_is_browser":   False,
        "unique_ja3_count": 0,
        "conn_count":       0,
        "unknown_service_conns": 0,
    }


def _has_non_ascii(*paths: Path) -> bool:
    return any(not str(p).isascii() for p in paths)


# ─────────────────────────────────────────────────────────────────────────────
# Cyrillic-path workaround
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_via_tempdir(pcap_path: Path, zeek_out: Path) -> dict:
    """Copy files to an ASCII-safe temp directory, run Zeek, copy results back."""
    tmp_base = Path("C:/Temp") if Path("C:/Temp").exists() else None
    with tempfile.TemporaryDirectory(prefix="zeek_", dir=tmp_base) as tmp_str:
        tmp         = Path(tmp_str)
        tmp_pcap    = tmp / "capture.pcap"
        tmp_scripts = tmp / "scripts"
        tmp_logs    = tmp / "logs"
        tmp_scripts.mkdir()
        tmp_logs.mkdir()

        shutil.copy2(pcap_path, tmp_pcap)
        _write_scripts(tmp_scripts)

        result = _run_zeek(tmp_pcap, tmp_logs, scripts_dir=tmp_scripts)

        # Copy output logs back for archiving
        for f in tmp_logs.glob("*.log"):
            shutil.copy2(f, zeek_out / f.name)

        return result


def _write_scripts(scripts_dir: Path) -> None:
    (scripts_dir / "local.zeek").write_text(_LOCAL_ZEEK, encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Docker invocation
# ─────────────────────────────────────────────────────────────────────────────

def _run_zeek(pcap_path: Path, logs_dir: Path,
              scripts_dir: Path | None = None) -> dict:
    """Invoke Zeek in Docker and parse the output logs.

    Volume layout inside the container:
      /capture.pcap  — input PCAP (read-only)
      /logs/         — working directory; Zeek writes all *.log files here
      /scripts/      — local.zeek (read-only)
    """
    if scripts_dir is None:
        # Place scripts in a sibling directory so both mount points are distinct
        scripts_dir = logs_dir.parent / "zeek_scripts"
        scripts_dir.mkdir(exist_ok=True)
        _write_scripts(scripts_dir)

    rc, stdout, stderr = docker_run(
        image=ZEEK_IMAGE,
        cmd=["zeek", "-r", "/capture.pcap", "/scripts/local.zeek"],
        volumes={
            str(pcap_path):   "/capture.pcap:ro",
            str(logs_dir):    "/logs",           # output  — distinct key!
            str(scripts_dir): "/scripts:ro",     # scripts — distinct key!
        },
        workdir="/logs",
        timeout=120,
    )

    if rc != 0:
        log.warning("Zeek exit %d: %s", rc, (stdout + stderr)[:300])

    return _parse_logs(logs_dir)


# ─────────────────────────────────────────────────────────────────────────────
# Log parsing
# ─────────────────────────────────────────────────────────────────────────────

def _parse_logs(log_dir: Path) -> dict:
    ja3_hashes:  Set[str] = set()
    ja3s_hashes: Set[str] = set()
    snis:        Set[str] = set()
    ciphers:     Set[str] = set()
    tls_vers:    Set[str] = set()

    ssl_log = log_dir / "ssl.log"
    if ssl_log.exists():
        for rec in _parse_tsv(ssl_log):
            for field, target in (
                ("ja3",         ja3_hashes),
                ("ja3s",        ja3s_hashes),
                ("server_name", snis),
                ("cipher",      ciphers),
                ("version",     tls_vers),
            ):
                if val := rec.get(field):
                    if val not in ("-", "(empty)"):
                        target.add(val)

    conn_count = 0
    unknown_service_conns = 0
    conn_log = log_dir / "conn.log"
    if conn_log.exists():
        for rec in _parse_tsv(conn_log):
            conn_count += 1
            svc = rec.get("service", "-")
            # In Zeek TSV, an unknown service is "-" (or empty/unset)
            if svc in ("-", "", "(empty)"):
                try:
                    orig_b = int(rec.get("orig_bytes", "0") or "0")
                    resp_b = int(rec.get("resp_bytes", "0") or "0")
                except ValueError:
                    orig_b = resp_b = 0
                if orig_b + resp_b >= _MIN_SUSPICIOUS_BYTES:
                    unknown_service_conns += 1

    browser_matches: List[str] = [
        browser for browser, known in BROWSER_JA3.items()
        if known in ja3_hashes
    ]

    return {
        "ja3_hashes":    sorted(ja3_hashes),
        "ja3s_hashes":   sorted(ja3s_hashes),
        "snis":          sorted(snis),
        "cipher_suites": sorted(ciphers),
        "tls_versions":  sorted(tls_vers),
        "browser_matches":       browser_matches,
        "ja3_is_browser":        len(browser_matches) > 0,
        "unique_ja3_count":      len(ja3_hashes),
        "conn_count":            conn_count,
        "unknown_service_conns": unknown_service_conns,
    }


def _parse_tsv(path: Path) -> Iterator[dict]:
    """Parse Zeek's TSV log format."""
    headers = None
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("#fields"):
            headers = line.split("\t")[1:]
        elif line.startswith("#"):
            continue
        elif headers:
            parts = line.split("\t")
            if len(parts) == len(headers):
                yield dict(zip(headers, parts))


# ─────────────────────────────────────────────────────────────────────────────
# Payload byte-entropy analysis (Python / dpkt — no Docker)
# ─────────────────────────────────────────────────────────────────────────────

def _compute_payload_entropy(pcap_path: Path) -> dict:
    """
    Sample raw TCP payload bytes per stream and compute byte-level entropy.

    Returns:
        payload_byte_entropy  — overall Shannon entropy (bits, 0–8) of sampled
                                bytes across all streams.
        high_entropy_streams  — number of streams whose payload entropy exceeds
                                _ENTROPY_THRESHOLD and whose service is unknown
                                (i.e. not TLS/HTTP by signature check).
        entropy_sample_size   — total bytes sampled.
    """
    try:
        import dpkt  # type: ignore
        return _dpkt_entropy(pcap_path, dpkt)
    except ImportError:
        log.debug("dpkt not available — skipping entropy analysis")
    except Exception as exc:
        log.debug("Entropy analysis failed: %s", exc)

    return {
        "payload_byte_entropy": None,
        "high_entropy_streams": 0,
        "entropy_sample_size":  0,
    }


def _dpkt_entropy(pcap_path: Path, dpkt) -> dict:
    """Core entropy computation using dpkt."""
    # streams: (src, dst, sport, dport) → bytearray of sampled payload
    streams: Dict[tuple, bytearray] = {}

    with open(pcap_path, "rb") as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)  # type: ignore

        link = reader.datalink()

        for _ts, buf in reader:
            ip = _extract_ip(buf, link, dpkt)
            if ip is None:
                continue
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            payload = bytes(tcp.data)
            if not payload:
                continue

            import socket as _sock
            key = (_sock.inet_ntoa(ip.src), _sock.inet_ntoa(ip.dst),
                   tcp.sport, tcp.dport)
            buf_ = streams.setdefault(key, bytearray())
            if len(buf_) < _MAX_SAMPLE_PER_STREAM:
                buf_.extend(payload[:_MAX_SAMPLE_PER_STREAM - len(buf_)])

    # Analyse per-stream
    high_entropy_streams = 0
    all_sample = bytearray()

    for key, sample in streams.items():
        if len(sample) < 64:
            continue
        all_sample.extend(sample[:1024])

        if len(sample) < _MIN_SUSPICIOUS_BYTES:
            continue

        proto = _proto_hint(bytes(sample))
        if proto != "unknown":
            continue  # TLS / HTTP already handled elsewhere

        ent = _byte_entropy(sample)
        if ent > _ENTROPY_THRESHOLD:
            high_entropy_streams += 1
            log.debug("High-entropy stream %s:%d→%s:%d  entropy=%.2f",
                      key[0], key[2], key[1], key[3], ent)

    global_entropy = _byte_entropy(all_sample) if all_sample else 0.0

    return {
        "payload_byte_entropy": round(global_entropy, 3),
        "high_entropy_streams": high_entropy_streams,
        "entropy_sample_size":  len(all_sample),
    }


def _proto_hint(payload: bytes) -> str:
    """Quick protocol signature check on the first few bytes of a TCP stream."""
    if len(payload) < 2:
        return "unknown"
    # TLS record header: content-type 0x16 (handshake) + version 0x03 xx
    if payload[0] == 0x16 and payload[1] == 0x03:
        return "tls"
    # Plaintext HTTP request / response
    if payload[:4] in (b"GET ", b"POST", b"HEAD", b"HTTP", b"PUT ", b"DELE"):
        return "http"
    # SSH banner
    if payload[:4] == b"SSH-":
        return "ssh"
    # SOCKS5 server reply (VER=5, METHOD=0 no-auth  OR  CONNECT success=0)
    # Byte pattern 0x05 0x00 covers both the auth-negotiation response and
    # the CONNECT response first two bytes — filters out SOCKS5 proxy streams
    # that carry high-entropy proxied content.
    if payload[:2] == b"\x05\x00":
        return "socks5"
    # SOCKS5 client greeting  (VER=5, NMETHODS=1, METHOD=0)
    if payload[:3] in (b"\x05\x01\x00", b"\x05\x02\x00"):
        return "socks5"
    return "unknown"


def _byte_entropy(data: (bytes, bytearray)) -> float:
    """Shannon entropy of byte values (0–255), result in bits (0–8)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    ent = 0.0
    for f in freq:
        if f > 0:
            p = f / total
            ent -= p * math.log2(p)
    return ent


def _extract_ip(buf: bytes, link_type: int, dpkt):
    """Extract the IP object from a raw captured frame."""
    try:
        if link_type == dpkt.pcap.DLT_EN10MB:       # 1 — Ethernet
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                return eth.data
        elif link_type == dpkt.pcap.DLT_NULL:        # 0 — BSD/Windows loopback
            if len(buf) < 4:
                return None
            af = struct.unpack("<I", buf[:4])[0]
            if af != 2:                              # AF_INET only
                return None
            return dpkt.ip.IP(buf[4:])
        elif link_type == 101:                       # DLT_RAW
            return dpkt.ip.IP(buf)
    except Exception:
        pass
    return None
