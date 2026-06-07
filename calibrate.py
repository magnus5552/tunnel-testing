"""
calibrate.py — Calibrate M6/M7 reference distributions for the local test environment.

Problem
───────
The default M6/M7 reference distributions in flow_ml.py were measured from
real internet HTTPS traffic.  On a loopback test stand all packets are delivered
in <1 ms, which makes KL(tunnel ‖ reference) ≈ 0.5 even for perfectly-behaving
tunnels — the threshold can never be met.

Solution
────────
Capture "baseline" HTTPS traffic under the *same local conditions* as the tunnel
tests: a minimal pass-through SOCKS5 proxy on loopback that forwards web requests
to the real internet.  The captured packet-length and IAT distributions become the
new reference.  Both the reference and the tunnel captures are now affected by the
same loopback overhead, so the KL score reflects genuine differences between
tunnelled and plain HTTPS traffic rather than loopback artefacts.

The calibrated distributions are saved to  tester/reference_distributions.json
and loaded automatically by flow_ml.py on subsequent runs.

Usage
─────
    # One-time calibration (needs internet, tcpdump, ~30 seconds)
    python calibrate.py

    # Custom duration / proxy port
    python calibrate.py --duration 60 --proxy-port 19080

    # Show what's currently saved
    python calibrate.py --show
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)

_HERE = Path(__file__).parent
_REF_JSON = _HERE / "tester" / "reference_distributions.json"

# Histogram bins — must match flow_ml.py exactly
LEN_BINS = [0, 100, 300, 600, 900, 1200, 1600, 10_000]
IAT_BINS = [0, 1, 5, 20, 100, 500, 10_000]  # milliseconds

# URLs for the reference web-browsing scenario
_URLS = [
    "https://example.com",
    "https://example.org",
    "https://httpbin.org/get",
    "https://www.wikipedia.org",
    "https://www.iana.org",
]


# ─────────────────────────────────────────────────────────────────────────────
# Minimal SOCKS5 pass-through proxy
# ─────────────────────────────────────────────────────────────────────────────

def _socks5_handle(conn: socket.socket) -> None:
    """Handle one SOCKS5 client connection (CONNECT only, no auth)."""
    try:
        # Greeting
        data = conn.recv(256)
        if len(data) < 2 or data[0] != 5:
            return
        conn.sendall(b"\x05\x00")  # version 5, no authentication

        # Request
        req = conn.recv(256)
        if len(req) < 7 or req[0] != 5 or req[1] != 1:  # CMD=CONNECT only
            conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        addr_type = req[3]
        if addr_type == 1:      # IPv4
            host = socket.inet_ntoa(req[4:8])
            port = int.from_bytes(req[8:10], "big")
        elif addr_type == 3:    # domain name
            n = req[4]
            host = req[5 : 5 + n].decode("ascii", errors="replace")
            port = int.from_bytes(req[5 + n : 5 + n + 2], "big")
        else:
            conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        try:
            remote = socket.create_connection((host, port), timeout=15)
        except OSError as exc:
            log.debug("SOCKS5 connect %s:%d failed: %s", host, port, exc)
            conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        # Success reply
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        # Bidirectional relay
        def _relay(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    r, _, _ = select.select([src], [], [], 30)
                    if not r:
                        break
                    chunk = src.recv(65536)
                    if not chunk:
                        break
                    dst.sendall(chunk)
            except Exception:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    s.close()

        t = threading.Thread(target=_relay, args=(remote, conn), daemon=True)
        t.start()
        _relay(conn, remote)
    except Exception as exc:
        log.debug("SOCKS5 handler: %s", exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def start_socks5_proxy(port: int) -> threading.Event:
    """
    Start a minimal SOCKS5 pass-through proxy in a background thread.
    Returns a stop_event — set it to stop the proxy.
    """
    stop = threading.Event()

    def _server() -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(32)
        srv.settimeout(0.5)
        log.info("SOCKS5 proxy listening on 127.0.0.1:%d", port)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                threading.Thread(
                    target=_socks5_handle, args=(conn,), daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as exc:
                log.debug("proxy accept: %s", exc)
        srv.close()
        log.info("SOCKS5 proxy stopped")

    threading.Thread(target=_server, daemon=True).start()
    time.sleep(0.2)   # let the socket bind
    return stop


# ─────────────────────────────────────────────────────────────────────────────
# Reference traffic generation
# ─────────────────────────────────────────────────────────────────────────────

def _run_web_scenario(socks5_port: int, duration: int) -> None:
    """Make HTTPS requests through the SOCKS5 proxy for *duration* seconds."""
    try:
        import requests
        import socks as _socks

        session = requests.Session()
        session.proxies = {
            "http":  f"socks5h://127.0.0.1:{socks5_port}",
            "https": f"socks5h://127.0.0.1:{socks5_port}",
        }

        deadline = time.time() + duration
        i = 0
        while time.time() < deadline:
            url = _URLS[i % len(_URLS)]
            try:
                session.get(url, timeout=10, verify=False)
            except Exception as exc:
                log.debug("request %s: %s", url, exc)
            i += 1
            time.sleep(0.3)
    except ImportError:
        # Fallback: raw SOCKS5 via subprocess curl
        deadline = time.time() + duration
        i = 0
        while time.time() < deadline:
            url = _URLS[i % len(_URLS)]
            try:
                subprocess.run(
                    ["curl", "-s", "-o", "/dev/null",
                     "--socks5", f"127.0.0.1:{socks5_port}",
                     "--max-time", "10", url],
                    capture_output=True, timeout=12,
                )
            except Exception as exc:
                log.debug("curl %s: %s", url, exc)
            i += 1
            time.sleep(0.3)


# ─────────────────────────────────────────────────────────────────────────────
# PCAP capture
# ─────────────────────────────────────────────────────────────────────────────

def _find_capture_binary() -> tuple[str, str]:
    """
    Return (binary_path, loopback_iface) for the available packet capture tool.
    Supports tcpdump (Linux/macOS) and tshark/dumpcap (Windows via Wireshark).
    """
    import shutil
    _WIRESHARK = Path("C:/Program Files/Wireshark")

    if shutil.which("tcpdump"):
        return shutil.which("tcpdump"), "lo"

    for candidate in [
        _WIRESHARK / "tshark.exe",
        _WIRESHARK / "dumpcap.exe",
    ]:
        if candidate.exists():
            return str(candidate), r"\Device\NPF_Loopback"

    for name in ("tshark", "dumpcap"):
        found = shutil.which(name)
        if found:
            return found, r"\Device\NPF_Loopback"

    raise RuntimeError(
        "No packet capture tool found. "
        "Install Wireshark (Windows) or tcpdump (Linux/macOS)."
    )


def _start_tcpdump(pcap_path: Path, port: int) -> subprocess.Popen:
    binary, iface = _find_capture_binary()
    name = Path(binary).stem.lower()

    if name == "tcpdump":
        cmd = [binary, "-i", iface, "-w", str(pcap_path), "-s", "0",
               f"tcp port {port}"]
    else:
        # tshark or dumpcap
        cmd = [binary, "-i", iface, "-w", str(pcap_path), "-s", "0",
               "-f", f"tcp port {port}"]

    log.info("Capture command: %s", " ".join(cmd))
    return subprocess.Popen(cmd, stderr=subprocess.DEVNULL)


# ─────────────────────────────────────────────────────────────────────────────
# Distribution extraction from PCAP
# ─────────────────────────────────────────────────────────────────────────────

def _compute_distributions(pcap_path: Path) -> dict:
    """Parse PCAP and return {len_probs, iat_probs, len_counts, iat_counts, n_pkts}."""
    sys.path.insert(0, str(_HERE))
    from tester.utils.pcap_parse import parse_pcap

    packets = parse_pcap(pcap_path)
    if not packets:
        raise RuntimeError("No packets parsed from reference capture")

    pkts = sorted(packets, key=lambda p: p.ts)
    lengths = [p.length for p in pkts if p.length > 0]
    iats_ms = [
        (pkts[i + 1].ts - pkts[i].ts) * 1000.0
        for i in range(len(pkts) - 1)
        if pkts[i + 1].ts - pkts[i].ts >= 0
    ]

    def _histogram(values: list[float], bins: list[float]) -> list[int]:
        n = len(bins) - 1
        counts = [0] * n
        for v in values:
            placed = False
            for i in range(n):
                if bins[i] <= v < bins[i + 1]:
                    counts[i] += 1
                    placed = True
                    break
            if not placed:
                counts[-1] += 1
        return counts

    def _to_probs(counts: list[int]) -> list[float]:
        total = sum(counts) or 1
        return [c / total for c in counts]

    len_counts = _histogram(lengths, LEN_BINS)
    iat_counts = _histogram(iats_ms, IAT_BINS)

    return {
        "len_probs":  _to_probs(len_counts),
        "iat_probs":  _to_probs(iat_counts),
        "len_counts": len_counts,
        "iat_counts": iat_counts,
        "n_packets":  len(pkts),
        "n_lengths":  len(lengths),
        "n_iats":     len(iats_ms),
    }


# ─────────────────────────────────────────────────────────────────────────────
# KL helper (for reporting)
# ─────────────────────────────────────────────────────────────────────────────

def _kl(p: list[float], q: list[float]) -> float:
    eps = 1e-9
    return sum(pi * math.log((pi + eps) / (qi + eps)) for pi, qi in zip(p, q) if pi > 0)


# ─────────────────────────────────────────────────────────────────────────────
# Main calibration flow
# ─────────────────────────────────────────────────────────────────────────────

def calibrate(duration: int = 30, proxy_port: int = 19080) -> dict:
    old_len = [0.32, 0.08, 0.07, 0.07, 0.10, 0.24, 0.12]
    old_iat = [0.38, 0.15, 0.15, 0.15, 0.12, 0.05]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        pcap_path = Path(tf.name)

    print(f"\n[1/4] Starting SOCKS5 pass-through proxy on 127.0.0.1:{proxy_port}")
    stop_proxy = start_socks5_proxy(proxy_port)

    print(f"[2/4] Starting tcpdump capture on loopback port {proxy_port}")
    tcpdump = _start_tcpdump(pcap_path, proxy_port)
    time.sleep(0.5)

    print(f"[3/4] Running web scenario for {duration}s …")
    _run_web_scenario(proxy_port, duration)

    print("[4/4] Stopping capture and proxy …")
    tcpdump.terminate()
    tcpdump.wait(timeout=5)
    stop_proxy.set()
    time.sleep(0.3)

    print(f"\nPCAP: {pcap_path}  ({pcap_path.stat().st_size:,} bytes)")

    dists = _compute_distributions(pcap_path)
    pcap_path.unlink(missing_ok=True)

    new_len = dists["len_probs"]
    new_iat = dists["iat_probs"]

    # ── Report ────────────────────────────────────────────────────────────────
    len_bin_labels = ["0-100", "100-300", "300-600", "600-900",
                      "900-1200", "1200-1600", "1600+"]
    iat_bin_labels = ["0-1ms", "1-5ms", "5-20ms", "20-100ms", "100-500ms", "500ms+"]

    print(f"\n{'─'*60}")
    print(f"  Reference capture: {dists['n_packets']} packets")
    print(f"{'─'*60}")
    print(f"\n  Packet length distribution (bytes):")
    print(f"  {'Bin':12s}  {'Old':8s}  {'New':8s}  {'Count':>8s}")
    for label, old, new, cnt in zip(len_bin_labels, old_len, new_len, dists["len_counts"]):
        arrow = "←" if abs(new - old) > 0.05 else " "
        print(f"  {label:12s}  {old:.3f}     {new:.3f}  {arrow}  {cnt:>8d}")

    print(f"\n  IAT distribution (ms):")
    print(f"  {'Bin':12s}  {'Old':8s}  {'New':8s}  {'Count':>8s}")
    for label, old, new, cnt in zip(iat_bin_labels, old_iat, new_iat, dists["iat_counts"]):
        arrow = "←" if abs(new - old) > 0.05 else " "
        print(f"  {label:12s}  {old:.3f}     {new:.3f}  {arrow}  {cnt:>8d}")

    kl_len = _kl(old_len, new_len)
    kl_iat = _kl(old_iat, new_iat)
    print(f"\n  KL(old ‖ new): len={kl_len:.3f}  iat={kl_iat:.3f}")

    # ── Save ─────────────────────────────────────────────────────────────────
    output = {
        "calibrated_at":    time.strftime("%Y-%m-%dT%H:%M:%S"),
        "duration_s":       duration,
        "proxy_port":       proxy_port,
        "n_packets":        dists["n_packets"],
        "len_bins":         LEN_BINS,
        "iat_bins":         IAT_BINS,
        "len_probs":        new_len,
        "iat_probs":        new_iat,
        "len_counts":       dists["len_counts"],
        "iat_counts":       dists["iat_counts"],
        "original_len_probs": old_len,
        "original_iat_probs": old_iat,
    }
    _REF_JSON.write_text(json.dumps(output, indent=2))
    print(f"\n  Saved → {_REF_JSON}")
    return output


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def show_current() -> None:
    if not _REF_JSON.exists():
        print("No calibration file found. Run without --show to calibrate.")
        return
    data = json.loads(_REF_JSON.read_text())
    print(f"\nCalibrated at : {data['calibrated_at']}")
    print(f"Packets used  : {data['n_packets']}")
    print(f"Duration      : {data['duration_s']}s")

    iat_labels = ["0-1ms", "1-5ms", "5-20ms", "20-100ms", "100-500ms", "500ms+"]
    len_labels = ["0-100", "100-300", "300-600", "600-900", "900-1200", "1200-1600", "1600+"]

    print("\nPacket length probabilities:")
    for label, p, p_old in zip(len_labels, data["len_probs"], data["original_len_probs"]):
        bar = "█" * int(p * 40)
        print(f"  {label:12s}  {p:.3f}  (was {p_old:.3f})  {bar}")

    print("\nIAT probabilities:")
    for label, p, p_old in zip(iat_labels, data["iat_probs"], data["original_iat_probs"]):
        bar = "█" * int(p * 40)
        print(f"  {label:12s}  {p:.3f}  (was {p_old:.3f})  {bar}")


def main() -> None:
    p = argparse.ArgumentParser(
        description="Calibrate M6/M7 reference distributions for the local test environment"
    )
    p.add_argument("--duration",   type=int, default=30,
                   help="Capture duration in seconds (default: 30)")
    p.add_argument("--proxy-port", type=int, default=19080, dest="proxy_port",
                   help="SOCKS5 proxy port (default: 19080)")
    p.add_argument("--show",       action="store_true",
                   help="Print current calibration and exit")
    p.add_argument("--log-level",  default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = p.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s — %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.show:
        show_current()
        return

    calibrate(duration=args.duration, proxy_port=args.proxy_port)


if __name__ == "__main__":
    main()
