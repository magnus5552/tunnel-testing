#!/usr/bin/env python3
"""
compare.py — side-by-side comparison of multiple tunnel configs.

Runs each config through the detection test suite and prints a combined
results table, making it easy to compare evasion quality across configs.

Usage examples
──────────────
# Compare three configs (auto-determine root from config paths)
python compare.py \\
    --configs \\
        ../tunnel-gen/examples/baseline-plain-tls.yaml \\
        ../tunnel-gen/examples/tls-token.yaml \\
        ../tunnel-gen/examples/detectable-raw-noise.yaml \\
        ../tunnel-gen/examples/detectable-no-sni-tls.yaml \\
    --root  ../tunnel-gen \\
    --output ./compare-results

# Quick run: 15-second scenarios, skip heavy external analyzers
python compare.py \\
    --configs ../tunnel-gen/examples/*.yaml \\
    --root    ../tunnel-gen \\
    --duration 15 \\
    --skip suricata zeek ndpi \\
    --output ./compare-results

# Use existing result directories (no re-run)
python compare.py --load ./compare-results
"""
import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

# ── Windows: request admin once for tshark ───────────────────────────────────
if sys.platform == "win32":
    from tester.utils.windows_admin import ensure_admin_for_capture
    ensure_admin_for_capture()

from tester.config import TestConfig
from tester.runner import TestRunner


# ── Column definitions ────────────────────────────────────────────────────────

_COLUMNS = [
    # (key_in_checks,      display_label,  width,  is_numeric,  threshold)
    ("M1_ndpi",           "M1 nDPI",      9,      False,       None),
    ("M2_suricata",       "M2 IDS",       9,      False,       None),
    ("M3_ja3",            "M3 JA3/ent",  12,      False,       None),
    ("M4_vpn_prob",       "M4 vpn",       8,      True,        0.65),
    ("M5_vpn_prob_seq",   "M5 seq",       8,      True,        0.65),
    ("M6_kl_len",         "M6 KL-L",      8,      True,        0.30),
    ("M7_kl_iat",         "M7 KL-I",      8,      True,        0.30),
    ("M8_probe",          "M8 probe",     9,      False,       None),
]

_VERDICT_WIDTH = 8
_NAME_WIDTH    = 32


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="compare.py",
        description="Side-by-side tunnel-config detection comparison (M1-M8)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--configs", nargs="+", metavar="YAML",
        help="DSL config YAML files to test",
    )
    g.add_argument(
        "--load", metavar="DIR",
        help="Load existing result directories instead of re-running tests",
    )

    p.add_argument(
        "--root", "-r", metavar="PATH",
        help="Path to tunnel-gen repository root (required when --configs is used)",
    )
    p.add_argument(
        "--scenario", "-s", choices=["web", "bulk", "idle"], default="web",
    )
    p.add_argument(
        "--duration", "-d", type=int, default=20, metavar="SECS",
        help="Scenario duration per config in seconds (default: 20)",
    )
    p.add_argument(
        "--socks5", default="127.0.0.1:9080", metavar="HOST:PORT",
    )
    p.add_argument(
        "--iface", "-i", default="lo", metavar="IFACE",
    )
    p.add_argument(
        "--skip", nargs="*", default=[], metavar="ANALYZER",
        help="Analyzers to skip: ndpi suricata zeek flow_ml probe",
    )
    p.add_argument(
        "--only", nargs="*", default=[], metavar="ANALYZER",
        help="Run only these analyzers",
    )
    p.add_argument(
        "--output", "-o", default="./compare-results", metavar="DIR",
        help="Output directory for per-config results (default: ./compare-results)",
    )
    p.add_argument(
        "--https-baseline", action="store_true",
        help="Capture plain HTTPS traffic (no tunnel) and add it as a reference row",
    )
    p.add_argument(
        "--https-iface", default=None, metavar="IFACE",
        help="Interface for HTTPS baseline capture (auto-detected if omitted). "
             "Use the number from 'tshark -D' on Windows.",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Also write compare-results/summary.json",
    )
    p.add_argument(
        "--log-level", default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: WARNING — keeps output clean)",
    )
    return p.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    args = _parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.load:
        reports = _load_reports(Path(args.load))
    else:
        if not args.root:
            print("ERROR: --root is required when --configs is used", file=sys.stderr)
            return 1
        root_path = Path(args.root).resolve()
        if not root_path.exists():
            print(f"ERROR: tunnel-gen root not found: {root_path}", file=sys.stderr)
            return 1

        all_analyzers = {"ndpi", "suricata", "zeek", "flow_ml", "probe"}
        skip = (all_analyzers - set(args.only)) if args.only else set(args.skip)

        reports = _run_all(
            config_paths=[Path(c).resolve() for c in args.configs],
            root_path=root_path,
            output_dir=output_dir,
            scenario=args.scenario,
            duration=args.duration,
            socks5=args.socks5,
            iface=args.iface,
            skip=skip,
        )

    # Optional: capture plain HTTPS reference (no tunnel)
    if getattr(args, "https_baseline", False):
        baseline = _run_https_baseline(
            output_dir=output_dir,
            iface=getattr(args, "https_iface", None),
            duration=getattr(args, "duration", 20),
        )
        if baseline:
            reports.insert(0, baseline)

    _print_table(reports)

    if args.json:
        summary_path = output_dir / "summary.json"
        summary_path.write_text(json.dumps(reports, indent=2, default=str))
        print(f"\nSummary written → {summary_path}")

    failed = sum(1 for r in reports if r.get("verdict") != "PASS")
    return 0 if failed == 0 else 2


# ── Runner ────────────────────────────────────────────────────────────────────

def _run_all(
    config_paths: List[Path],
    root_path: Path,
    output_dir: Path,
    scenario: str,
    duration: int,
    socks5: str,
    iface: str,
    skip: set,
) -> List[dict]:
    results = []
    total = len(config_paths)

    for idx, config_path in enumerate(config_paths, 1):
        name = config_path.stem
        print(f"\n[{idx}/{total}] Testing {name} …", flush=True)

        run_dir = output_dir / name
        run_dir.mkdir(parents=True, exist_ok=True)

        cfg = TestConfig(
            dsl_config=config_path,
            tunnel_gen_root=root_path,
            scenario=scenario,
            duration=duration,
            output_dir=run_dir,
            existing_pcap=None,
            skip_analyzers=skip,
            no_start_tunnel=False,
            socks5_addr=socks5,
            capture_iface=iface,
        )

        t0 = time.time()
        try:
            runner = TestRunner(cfg)
            report = runner.run()
        except Exception as exc:
            logging.error("Run failed for %s: %s", name, exc)
            report = {
                "verdict": "ERROR",
                "error": str(exc),
                "config": {"dsl_config": str(config_path)},
                "checks": {},
            }
        elapsed = time.time() - t0
        report["_elapsed_s"] = round(elapsed, 1)
        report["_config_name"] = name
        results.append(report)

    return results


# ── Loader ────────────────────────────────────────────────────────────────────

def _load_reports(base_dir: Path) -> List[dict]:
    reports = []
    for report_path in sorted(base_dir.glob("*/report.json")):
        try:
            report = json.loads(report_path.read_text())
            report["_config_name"] = report_path.parent.name
            reports.append(report)
        except Exception as exc:
            print(f"Warning: could not load {report_path}: {exc}", file=sys.stderr)
    if not reports:
        print(f"No report.json files found under {base_dir}", file=sys.stderr)
    return reports


# ── Plain-HTTPS baseline capture ─────────────────────────────────────────────

def _find_internet_iface(tshark_binary: str) -> str:
    """
    Detect the tshark interface number that carries TCP-443 HTTPS traffic.

    Strategy:
      1. Build a ranked candidate list (non-virtual/loopback interfaces first,
         then VPN adapters, as a fallback for machines that route via VPN).
      2. For each candidate, run a 3-second tshark probe with filter
         'tcp port 443' while fetching one HTTPS URL.
      3. Return the first interface that captures at least one packet.
      4. Fall back to "1" if nothing works.
    """
    import socket, subprocess, tempfile, threading

    # Step 1 — build candidate list from tshark -D
    _ALWAYS_SKIP = (
        "loopback", "npcap loopback",
        "vethernet", "hyper-v", "wsl",
        "bluetooth",
        "etw", "etwdump", "ciscodump", "sshdump", "udpdump", "randpkt",
        "default switch",
    )
    _VPN_KEYWORDS = (
        "zerotier", "vpn", "openvpn", "amnezia", "radmin", "nordvpn",
        "wireguard", "tailscale", "proton", "expressvpn",
    )

    candidates_primary = []   # physical Wi-Fi / Ethernet
    candidates_vpn     = []   # VPN adapters (fallback if machine routes via VPN)

    try:
        r = subprocess.run([tshark_binary, "-D"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            lo = line.lower()
            num = line.split(".")[0].strip()
            if not num.isdigit():
                continue
            if any(k in lo for k in _ALWAYS_SKIP):
                continue
            if any(k in lo for k in _VPN_KEYWORDS):
                candidates_vpn.append(num)
            else:
                candidates_primary.append(num)
    except Exception:
        return "1"

    all_candidates = candidates_primary + candidates_vpn
    if not all_candidates:
        return "1"

    # Helper: trigger one HTTPS request in background during probe
    def _fetch_one():
        try:
            import urllib.request
            urllib.request.urlopen("https://www.google.com", timeout=5)
        except Exception:
            pass

    # Step 2 — probe each candidate with a 3-second capture
    print("  Baseline: probing interfaces for HTTPS traffic …", flush=True)
    with tempfile.TemporaryDirectory() as tmp:
        for num in all_candidates:
            probe_pcap = Path(tmp) / f"probe_{num}.pcap"
            t = threading.Thread(target=_fetch_one, daemon=True)

            try:
                proc = subprocess.Popen(
                    [tshark_binary, "-i", num, "-f", "tcp port 443",
                     "-w", str(probe_pcap), "-F", "pcap", "-q"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                t.start()
                time.sleep(3)
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
            except Exception:
                continue

            size = probe_pcap.stat().st_size if probe_pcap.exists() else 0
            logging.debug("Interface %s probe: %d bytes", num, size)
            if size > 100:
                print(f"  Baseline: using interface {num} (first with TCP-443 traffic)",
                      flush=True)
                return num

    print("  Baseline: no interface with TCP-443 traffic found; falling back to '1'",
          flush=True)
    return "1"


def _run_https_baseline(output_dir: Path, iface: Optional[str],
                        duration: int) -> Optional[dict]:
    """
    Capture real HTTPS traffic (no tunnel) as a detection reference.

    Makes direct HTTPS requests to known sites while recording traffic on the
    internet-facing interface.  Only M4-M7 (statistical checks) are evaluated;
    M1/M2/M3/M8 require a running tunnel server and are marked SKIP.

    Parameters
    ----------
    iface : str or None
        tshark interface name/number to capture on.  Auto-detected if None.
    """
    print("\n[0/*] Capturing plain-HTTPS baseline …", flush=True)
    run_dir = output_dir / "_plain-https-baseline"
    run_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = run_dir / "capture.pcap"

    try:
        import requests as req_lib  # type: ignore
    except ImportError:
        print("  Warning: requests not installed — skipping HTTPS baseline",
              file=sys.stderr)
        return None

    # Resolve the capture interface
    from tester.capture import Capture, _find_capture_binary
    binary = _find_capture_binary()
    if binary is None:
        print("  Warning: no capture tool found — skipping HTTPS baseline",
              file=sys.stderr)
        return None

    if iface is None:
        iface = _find_internet_iface(binary)

    print(f"  Capture interface: {iface}", flush=True)

    # Sites to fetch — use only TCP/443 HTTPS, not HTTP/3 (QUIC/UDP)
    sites = [
        "https://www.google.com",
        "https://www.microsoft.com",
        "https://www.cloudflare.com",
        "https://www.github.com",
        "https://www.wikipedia.org",
    ]

    # Use BPF filter to limit to TLS (TCP 443) and reduce noise
    capture = Capture(interface=iface, path=pcap_path, bpf="tcp port 443")
    report: dict = {
        "_config_name": "plain-HTTPS (reference)",
        "verdict": "REFERENCE",
        "checks": {},
        "config": {"dsl_config": "direct HTTPS (no tunnel)"},
    }

    try:
        with capture:
            deadline = time.time() + duration
            session = req_lib.Session()
            # Disable HTTP/2 → force TLS/1.x over TCP (avoids QUIC on UDP)
            session.headers.update({"Connection": "close"})
            idx = 0
            fetched = 0
            while time.time() < deadline:
                url = sites[idx % len(sites)]
                idx += 1
                try:
                    r = session.get(url, timeout=8, verify=True)
                    fetched += 1
                    logging.debug("GET %s → %d (%d bytes)",
                                  url, r.status_code, len(r.content))
                except Exception as exc:
                    logging.debug("baseline fetch %s: %s", url, exc)
                time.sleep(0.8)
        print(f"  Fetched {fetched} HTTPS responses", flush=True)
    except Exception as exc:
        print(f"  Warning: HTTPS baseline capture failed: {exc}", file=sys.stderr)
        return None

    size = pcap_path.stat().st_size if pcap_path.exists() else 0
    if size < 200:
        print(
            f"  Warning: HTTPS baseline PCAP is too small ({size} bytes).\n"
            f"  The capture interface '{iface}' may be wrong.\n"
            f"  Run 'tshark -D' and pass the correct number via --https-iface.",
            file=sys.stderr,
        )
        return None

    print(f"  PCAP: {size:,} bytes", flush=True)

    # Run only statistical analyzers (M4-M7)
    try:
        from tester.analyzers.flow_ml import analyze as ml_analyze
        ml_result = ml_analyze(pcap_path, run_dir, model_path=None)
    except Exception as exc:
        print(f"  Warning: M4-M7 analysis of baseline failed: {exc}", file=sys.stderr)
        return None

    _VPN_THR = 0.65
    _KL_THR  = 0.30

    def _skip_check():
        return {"result": "SKIP", "detail": {"reason": "not applicable for direct HTTPS"}}

    def _numeric_check(value: Optional[float], threshold: float, key: str) -> dict:
        if value is None:
            return _skip_check()
        return {
            "result": "PASS" if value < threshold else "FAIL",
            "detail": {key: value},
        }

    report["checks"] = {
        "M1_ndpi":         _skip_check(),
        "M2_suricata":     _skip_check(),
        "M3_ja3":          _skip_check(),
        "M4_vpn_prob":     _numeric_check(ml_result.get("vpn_prob"),     _VPN_THR, "vpn_prob"),
        "M5_vpn_prob_seq": _numeric_check(ml_result.get("vpn_prob_seq"), _VPN_THR, "vpn_prob_seq"),
        "M6_kl_len":       _numeric_check(ml_result.get("kl_len"),       _KL_THR,  "kl_len"),
        "M7_kl_iat":       _numeric_check(ml_result.get("kl_iat"),       _KL_THR,  "kl_iat"),
        "M8_probe":        _skip_check(),
    }

    report_path = run_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"  Baseline report → {report_path}", flush=True)
    return report


# ── Table printer ─────────────────────────────────────────────────────────────

def _print_table(reports: List[dict]) -> None:
    if not reports:
        print("No results to display.")
        return

    # ── Header ──────────────────────────────────────────────────────────────
    col_headers = [f"{label:^{w}}" for _, label, w, _, _ in _COLUMNS]
    header_row = (
        f"  {'Config':<{_NAME_WIDTH}}  "
        + "  ".join(col_headers)
        + f"  {'Verdict':^{_VERDICT_WIDTH}}"
    )
    sep = "─" * len(header_row)

    print()
    print(sep)
    print(header_row)
    print(sep)

    # ── Rows ─────────────────────────────────────────────────────────────────
    for report in reports:
        name    = report.get("_config_name", "?")
        verdict = report.get("verdict", "ERROR")
        checks  = report.get("checks", {})

        cells = []
        for key, label, w, is_numeric, threshold in _COLUMNS:
            chk = checks.get(key, {})
            result = chk.get("result", "SKIP")
            detail = chk.get("detail", {})

            if result == "SKIP":
                cell = f"{'·':^{w}}"
            elif key == "M3_ja3":
                # Special rendering: show entropy when it is the deciding signal,
                # or browser/JA3 info when TLS is present.
                marker = "✓" if result == "PASS" else "✗"
                n_ja3 = detail.get("unique_ja3_count", 0)
                hi_ent = detail.get("high_entropy_streams", 0)
                ent = detail.get("payload_byte_entropy")
                if n_ja3 > 0 and detail.get("ja3_is_browser"):
                    inner = f"{marker}ja3-ok"
                elif n_ja3 > 0:
                    inner = f"{marker}ja3-bad"
                elif hi_ent > 0 and ent is not None:
                    inner = f"{marker}ent={ent:.2f}"
                else:
                    inner = f"{marker}"
                cell = inner.center(w)
            elif is_numeric:
                # Find the relevant numeric value in detail
                val = _first_float(detail)
                if val is None:
                    cell = f"{'?':^{w}}"
                else:
                    marker = "✓" if result == "PASS" else "✗"
                    cell = f"{marker}{val:.3f}".center(w)
            else:
                marker = "✓" if result == "PASS" else "✗"
                cell = f"{marker}".center(w)

            cells.append(cell)

        verdict_marker = (
            "✓ PASS"   if verdict == "PASS"      else
            "✗ FAIL"   if verdict == "FAIL"      else
            "~ REF"    if verdict == "REFERENCE" else
            "! ERROR"
        )
        name_trunc = name[:_NAME_WIDTH]
        row = (
            f"  {name_trunc:<{_NAME_WIDTH}}  "
            + "  ".join(cells)
            + f"  {verdict_marker:^{_VERDICT_WIDTH}}"
        )
        print(row)

    print(sep)
    _print_legend()


def _first_float(d: dict) -> Optional[float]:
    for v in d.values():
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return float(v)
    return None


def _print_legend() -> None:
    print()
    print("  Legend:")
    print("    ✓  PASS — check passed (threshold satisfied)")
    print("    ✗  FAIL — check failed (tunnel is detectable by this method)")
    print("    ·  SKIP — analyzer not run or produced an error")
    print()
    print("  Thresholds / display:")
    print("    M2 IDS:    0 Suricata alerts required for PASS")
    print("    M3 JA3:    browser JA3, OR (no JA3 AND no high-entropy unknown streams)")
    print("               Cell shows: ja3-ok / ja3-bad / ent=<entropy>")
    print("               Payload byte entropy > 6.5 bits flags raw encrypted tunnel.")
    print("    M4 vpn_prob   < 0.65  (heuristic VPN flow classifier)")
    print("    M5 vpn_seq    < 0.65  (first-20-packet sequence classifier)")
    print("    M6 KL-len     < 0.30  (packet-length divergence from HTTPS reference)")
    print("    M7 KL-iat     < 0.30  (inter-arrival-time divergence from HTTPS reference)")
    print("    M8 probe:  distinguishable_ratio < 0.67  (active probing response)")
    print()
    print("  Numeric cells show the raw metric value alongside the pass/fail marker.")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(main())
