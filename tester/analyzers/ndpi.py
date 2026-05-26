"""
M1 — nDPI deep-packet inspection via Docker (tunnel-testing/ndpi:latest).

Build the image once:
    docker build -t tunnel-testing/ndpi:latest docker/ndpi/

The image wraps ndpiReader 4.2 with a pcap-normalisation helper that converts
DLT_NULL (Windows loopback, link type 0) to DLT_RAW so ndpiReader can process
loopback captures.

Output format
─────────────
ndpiReader 4.2 dropped JSON output (-J is broken).  We use the per-flow CSV
flag (-C) instead, which provides richer data anyway: protocol name, JA3
fingerprints, SNI, TLS version, byte counts per flow.

Windows / cyrillic-path note
─────────────────────────────
Same workaround as Suricata/Zeek: when host paths contain non-ASCII characters
(e.g. the Cyrillic «диплом» directory), Docker volume mounts fail on Windows.
Files are staged to a temp ASCII directory under C:/Temp before the Docker run.
"""
import csv
import io
import logging
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Set

from ..utils.docker_run import docker_run, docker_available, pull_if_missing

log = logging.getLogger(__name__)

NDPI_IMAGE = "tunnel-testing/ndpi:latest"

# Protocols that unambiguously identify VPN / tunnel traffic
KNOWN_VPN = {
    "OpenVPN", "WireGuard", "Shadowsocks", "VMess",
    "Tor", "I2P", "GRE", "L2TP", "PPTP", "IPIP",
}

# Protocols acceptable in "looks like HTTPS" traffic
ACCEPTABLE = {"TLS", "HTTPS", "TLSv1", "TLSv1.2", "TLSv1.3", "QUIC", "Unknown", "UNKNOWN"}


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def analyze(pcap_path: Path, output_dir: Path) -> dict:
    """Run ndpiReader on *pcap_path* and return M1 metrics."""
    if not docker_available():
        log.warning("Docker unavailable — skipping nDPI (M1)")
        return {"skipped": True, "reason": "docker_unavailable"}

    if not pull_if_missing(NDPI_IMAGE):
        return {"skipped": True, "reason": f"image {NDPI_IMAGE} not available"}

    # On Windows, paths with non-ASCII chars (e.g. Cyrillic) break Docker mounts.
    if sys.platform == "win32" and _has_non_ascii(pcap_path, output_dir):
        return _analyze_via_tempdir(pcap_path, output_dir)

    return _run_ndpi(pcap_path, output_dir)


def _has_non_ascii(*paths: Path) -> bool:
    return any(not str(p).isascii() for p in paths)


# ─────────────────────────────────────────────────────────────────────────────
# Cyrillic-path workaround
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_via_tempdir(pcap_path: Path, output_dir: Path) -> dict:
    """Copy files to an ASCII-safe temp directory, run nDPI, copy results back."""
    tmp_base = Path("C:/Temp") if Path("C:/Temp").exists() else None
    with tempfile.TemporaryDirectory(prefix="ndpi_", dir=tmp_base) as tmp_str:
        tmp      = Path(tmp_str)
        tmp_pcap = tmp / "capture.pcap"
        tmp_out  = tmp / "output"
        tmp_out.mkdir()

        shutil.copy2(pcap_path, tmp_pcap)
        result = _run_ndpi(tmp_pcap, tmp_out)

        # Copy output files back for archiving
        for fname in ("ndpi_flows.csv", "ndpi_summary.txt"):
            src = tmp_out / fname
            if src.exists():
                shutil.copy2(src, output_dir / fname)

        return result


# ─────────────────────────────────────────────────────────────────────────────
# Docker invocation
# ─────────────────────────────────────────────────────────────────────────────

def _run_ndpi(pcap_path: Path, output_dir: Path) -> dict:
    """
    Run ndpiReader via Docker.

    Flags used:
      -i /capture.pcap       input pcap (DLT_NULL auto-converted by entrypoint)
      -q                     quiet mode (suppress the ASCII-art banner)
      -C /output/flows.csv   per-flow CSV with protocol, JA3, SNI, TLS version
      -w /output/summary.txt text summary (protocol counts)
    """
    csv_file = output_dir / "ndpi_flows.csv"
    txt_file = output_dir / "ndpi_summary.txt"

    rc, stdout, stderr = docker_run(
        image=NDPI_IMAGE,
        cmd=[
            "-i", "/capture.pcap",
            "-q",
            "-C", "/output/ndpi_flows.csv",
            "-w", "/output/ndpi_summary.txt",
        ],
        volumes={
            str(pcap_path):  "/capture.pcap:ro",
            str(output_dir): "/output",
        },
        timeout=180,
    )

    if rc != 0:
        log.warning("ndpiReader exit %d: %s", rc, (stdout + stderr)[:300])

    if not csv_file.exists():
        log.error("nDPI produced no CSV output (rc=%d): %s", rc, stderr[:200])
        return {"error": "no CSV output", "rc": rc, "stderr": stderr[:200]}

    return _parse_csv(csv_file, txt_file)


# ─────────────────────────────────────────────────────────────────────────────
# Output parsing
# ─────────────────────────────────────────────────────────────────────────────

def _parse_csv(csv_path: Path, summary_path: Path) -> dict:
    """Parse the per-flow CSV written by ndpiReader -C."""
    proto_counts: Dict[str, int] = {}
    ja3_set:  Set[str] = set()
    ja4_set:  Set[str] = set()
    sni_set:  Set[str] = set()
    tls_vers: Set[str] = set()
    flow_count = 0

    try:
        text = csv_path.read_text(encoding="utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            flow_count += 1
            proto = row.get("ndpi_proto", "Unknown").strip()
            proto_counts[proto] = proto_counts.get(proto, 0) + 1

            if ja3 := row.get("ja3c", "").strip():
                if ja3 not in ("-", ""):
                    ja3_set.add(ja3)
            if ja3s := row.get("ja3s", "").strip():
                if ja3s not in ("-", ""):
                    ja4_set.add(ja3s)   # re-use ja4 slot for ja3s server hash
            if sni := row.get("server_name_sni", "").strip():
                if sni not in ("-", ""):
                    sni_set.add(sni)
            if ver := row.get("tls_version", "").strip():
                if ver not in ("-", "", "0"):
                    tls_vers.add(ver)
    except Exception as exc:
        log.warning("nDPI CSV parse error: %s", exc)
        return {"error": str(exc)}

    # Dominant protocol (most flows)
    top = max(proto_counts, key=proto_counts.get) if proto_counts else "Unknown"

    # Read summary text for additional context
    known_flow_count = 0
    if summary_path.exists():
        for line in summary_path.read_text(errors="replace").splitlines():
            if "Confidence DPI" in line:
                try:
                    known_flow_count = int(line.split(":")[1].split("(")[0].strip())
                except (IndexError, ValueError):
                    pass

    return {
        "classified_as":         top,
        "is_known_vpn":          top in KNOWN_VPN,
        "is_acceptable":         top in ACCEPTABLE or top not in KNOWN_VPN,
        "flow_count":            flow_count,
        "known_flow_count":      known_flow_count,
        "protocol_distribution": proto_counts,
        "ja3_hashes":            sorted(ja3_set),
        "ja4_hashes":            sorted(ja4_set),
        "sni_set":               sorted(sni_set),
        "tls_versions":          sorted(tls_vers),
    }
