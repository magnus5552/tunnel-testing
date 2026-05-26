"""
Windows UAC elevation helper.

Problem
-------
tshark (and dumpcap) on Windows require Administrator privileges to open
network interfaces via Npcap *unless* Npcap was installed with the
"Allow capturing without admin privileges" option.

When privileges ARE required and the Python process is not elevated, the OS
shows a UAC consent dialog for every tshark invocation — once per capture
start, and more if tests are batched.

Solution
--------
Call ``ensure_admin_for_capture()`` once at process start-up.  The function:

  1. Returns immediately if already running as Administrator.
  2. Probes whether tshark works without elevation (quick dry-run capture).
     If the probe succeeds, no elevation is needed → returns immediately.
  3. If the probe fails (permission denied), re-launches the *entire* Python
     command with ``runas`` (single UAC prompt) and exits the current process
     with the elevated child's exit code.

From that point on every subprocess — including all subsequent tshark calls —
inherits the elevated token and never triggers UAC again.

Usage (run_test.py, before argparse)
-------------------------------------
    from tester.utils.windows_admin import ensure_admin_for_capture
    ensure_admin_for_capture()
"""
import ctypes
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


# ── Public API ────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ensure_admin_for_capture(tshark_path: Optional[str] = None) -> None:
    """
    Ensure the process can run tshark for packet capture.

    Steps:
      1. Already admin → done.
      2. Probe tshark with a 0-second capture on the loopback interface.
         If it succeeds → Npcap allows non-admin capture → done.
      3. Otherwise → re-launch this process elevated (one UAC prompt).

    Parameters
    ----------
    tshark_path : str or None
        Explicit path to tshark.exe.  Auto-detected if None.
    """
    if sys.platform != "win32":
        return
    if is_admin():
        log.debug("windows_admin: already running as Administrator")
        return

    binary = tshark_path or _find_tshark()
    if binary is None:
        log.debug("windows_admin: tshark not found, skipping elevation check")
        return

    if _probe_capture(binary):
        log.debug("windows_admin: non-admin capture works (Npcap unrestricted mode)")
        return

    # Capture probe failed — we need admin
    _relaunch_elevated()   # never returns


# ── Internal helpers ──────────────────────────────────────────────────────────

_WIRESHARK_DIR = Path("C:/Program Files/Wireshark")


def _find_tshark() -> Optional[str]:
    """Return path to tshark.exe, or None if not found."""
    import shutil
    candidate = _WIRESHARK_DIR / "tshark.exe"
    if candidate.exists():
        return str(candidate)
    return shutil.which("tshark")


def _probe_capture(binary: str) -> bool:
    """
    Try a 0-second capture on the loopback interface.
    Returns True if tshark exits cleanly (permission granted),
    False if it exits with an error related to permissions.
    """
    with tempfile.TemporaryDirectory() as tmp:
        probe_pcap = str(Path(tmp) / "probe.pcap")
        try:
            result = subprocess.run(
                [
                    binary,
                    "-i", "\\Device\\NPF_Loopback",
                    "-w", probe_pcap,
                    "-F", "pcap",
                    "-a", "duration:0",   # capture for 0 seconds then stop
                    "-q",
                ],
                capture_output=True,
                text=True,
                timeout=8,
            )
            stderr_lower = result.stderr.lower()
            # Permission-related errors contain these keywords
            if any(kw in stderr_lower for kw in (
                "permission", "access denied", "forbidden", "unauthor",
                "not have permission", "administrator",
            )):
                log.debug("windows_admin probe: permission error — %s", result.stderr.strip())
                return False
            log.debug("windows_admin probe: exit %d — elevation not needed", result.returncode)
            return True
        except subprocess.TimeoutExpired:
            log.debug("windows_admin probe: timed out")
            return True   # if it took too long, assume it works (just slow)
        except Exception as exc:
            log.debug("windows_admin probe failed: %s", exc)
            return True   # can't tell → don't elevate speculatively


def _relaunch_elevated() -> None:
    """
    Re-launch ``sys.executable sys.argv`` with ``runas`` via PowerShell.

    Opens a single UAC consent dialog.  Waits for the elevated process to
    finish and forwards its exit code.  Never returns.
    """
    print(
        "\n[tunnel-testing] Administrator privileges are required for packet capture.\n"
        "                  A UAC consent dialog will appear — this happens only ONCE.\n",
        flush=True,
    )

    exe  = sys.executable
    argv = sys.argv

    def _ps_str(s: str) -> str:
        """Escape a string for PowerShell single-quoted literal."""
        return "'" + s.replace("'", "''") + "'"

    arg_array = "@(" + ",".join(_ps_str(a) for a in argv) + ")"

    ps_script = (
        f"$p = Start-Process "
        f"-FilePath {_ps_str(exe)} "
        f"-ArgumentList {arg_array} "
        f"-Verb RunAs "
        f"-Wait "
        f"-PassThru; "
        f"if ($p) {{ exit $p.ExitCode }} else {{ exit 1 }}"
    )

    log.debug("Launching elevated: %s %s", exe, " ".join(argv))

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            ps_script,
        ]
    )

    sys.exit(result.returncode)
