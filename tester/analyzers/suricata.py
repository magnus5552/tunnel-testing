"""
M2 — Suricata IDS analysis via Docker (jasonish/suricata).

Downloads ET Open rules on first run; caches them in the rules/ directory.

Windows / cyrillic-path note
─────────────────────────────
Docker on Windows fails to mount volumes whose host paths contain non-ASCII
characters (e.g. Cyrillic directory names).  To work around this, the
analyzer copies the PCAP and rules into a temporary ASCII-safe directory
under the system temp folder before invoking Docker, then copies the
eve.json output back.
"""
import json
import logging
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import List

from ..utils.docker_run import docker_run, docker_available, pull_if_missing

log = logging.getLogger(__name__)

SURICATA_IMAGE = "jasonish/suricata:latest"
ET_RULES_URL = (
    "https://rules.emergingthreats.net/open/suricata-7.0/rules/emerging-all.rules"
)


def analyze(pcap_path: Path, output_dir: Path, rules_dir: Path) -> dict:
    """Run Suricata offline on *pcap_path* and return M2 metrics."""
    if not docker_available():
        log.warning("Docker unavailable — skipping Suricata (M2)")
        return {"skipped": True, "reason": "docker_unavailable"}

    if not pull_if_missing(SURICATA_IMAGE):
        return {"skipped": True, "reason": f"image {SURICATA_IMAGE} not available"}

    rules_dir.mkdir(parents=True, exist_ok=True)
    rules_file = rules_dir / "emerging-all.rules"
    if not rules_file.exists():
        _download_rules(rules_file)

    suricata_out = output_dir / "suricata"
    suricata_out.mkdir(exist_ok=True)

    # On Windows, paths with non-ASCII chars (e.g. Cyrillic) break Docker
    # volume mounts.  Use a temporary ASCII-safe staging directory.
    if sys.platform == "win32" and _has_non_ascii(pcap_path, output_dir, rules_dir):
        return _analyze_via_tempdir(pcap_path, suricata_out, rules_dir,
                                    rules_file, rules_dir / "custom.rules")

    return _run_suricata(pcap_path, suricata_out, rules_file,
                         rules_dir / "custom.rules", rules_dir)


def _has_non_ascii(*paths: Path) -> bool:
    return any(not str(p).isascii() for p in paths)


def _analyze_via_tempdir(pcap_path: Path, suricata_out: Path,
                          rules_dir: Path, et_rules: Path,
                          custom_rules: Path) -> dict:
    """Copy files to an ASCII temp dir, run Suricata, copy results back."""
    # Use C:/Temp if it exists, otherwise fall back to the system default
    tmp_base = Path("C:/Temp") if Path("C:/Temp").exists() else None
    with tempfile.TemporaryDirectory(prefix="suricata_", dir=tmp_base) as tmp_str:
        tmp = Path(tmp_str)
        tmp_pcap    = tmp / "capture.pcap"
        tmp_rules   = tmp / "rules"
        tmp_out     = tmp / "output"
        tmp_rules.mkdir()
        tmp_out.mkdir()

        # Copy PCAP
        shutil.copy2(pcap_path, tmp_pcap)

        # Merge ET Open rules + custom rules into a single file.
        # Suricata 8.x does not support multiple -S flags.
        combined = tmp_rules / "all.rules"
        with open(combined, "w", encoding="utf-8") as fout:
            if et_rules.exists():
                fout.write(et_rules.read_text(encoding="utf-8", errors="replace"))
                fout.write("\n")
            if custom_rules.exists():
                fout.write(custom_rules.read_text(encoding="utf-8", errors="replace"))
                fout.write("\n")
                log.debug("Merged custom rules into combined file")

        result = _run_suricata(tmp_pcap, tmp_out, combined, tmp_rules)

        # Copy output files back for archiving
        for fname in ("eve.json", "fast.log", "stats.log", "suricata.log"):
            src = tmp_out / fname
            if src.exists():
                shutil.copy2(src, suricata_out / fname)

        return result


def _run_suricata(pcap_path: Path, suricata_out: Path,
                   rules_file: Path, rules_dir: Path) -> dict:
    """Build the Docker command and invoke Suricata.

    Suricata 8.x accepts only ONE -S argument; callers must pre-merge rules.
    """
    cmd = [
        "-r", "/capture.pcap",
        "-l", "/output",
        "-S", "/rules/all.rules",   # single combined rules file
        "-k", "none",
        "--runmode=single",
    ]
    log.debug("Suricata rules: %s (%d bytes)",
              rules_file, rules_file.stat().st_size if rules_file.exists() else 0)

    rc, stdout, stderr = docker_run(
        image=SURICATA_IMAGE,
        cmd=cmd,
        volumes={
            str(pcap_path):    "/capture.pcap:ro",
            str(suricata_out): "/output",
            str(rules_dir):    "/rules:ro",
        },
        timeout=300,
    )

    if rc not in (0, 1):
        log.warning("Suricata exit %d: %s", rc, (stdout + stderr)[:300])

    return _parse_eve(suricata_out)


# --------------------------------------------------------------------------- #

def _parse_eve(output_dir: Path) -> dict:
    eve = output_dir / "eve.json"
    if not eve.exists():
        return {"error": "eve.json not produced", "alert_count": 0}

    alerts: List[dict] = []
    flows:  List[dict] = []
    tls:    List[dict] = []

    for raw in eve.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            continue
        t = ev.get("event_type")
        if t == "alert":
            a = ev.get("alert", {})
            alerts.append({
                "signature": a.get("signature", ""),
                "category":  a.get("category", ""),
                "severity":  a.get("severity", 0),
                "src":       ev.get("src_ip"),
                "dst":       ev.get("dest_ip"),
                "dport":     ev.get("dest_port"),
            })
        elif t == "flow":
            flows.append(ev.get("flow", {}))
        elif t == "tls":
            tls.append(ev.get("tls", {}))

    return {
        "alert_count":   len(alerts),
        "alerts":        alerts[:20],
        "flow_count":    len(flows),
        "tls_count":     len(tls),
        "tls_versions":  sorted({t.get("version") for t in tls if t.get("version")}),
        "tls_sni":       sorted({t.get("sni")     for t in tls if t.get("sni")}),
        "categories":    sorted({a["category"] for a in alerts if a["category"]}),
    }


def _download_rules(dest: Path) -> None:
    log.info("Downloading ET Open rules → %s  (this may take a while)…", dest)
    try:
        urllib.request.urlretrieve(ET_RULES_URL, dest)
        log.info("Rules saved: %s bytes", f"{dest.stat().st_size:,}")
    except Exception as exc:
        log.error("Rules download failed: %s", exc)
        dest.write_text("# download failed — no rules active\n")
