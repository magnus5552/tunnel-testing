"""PCAP capture via tcpdump (Linux/macOS) or tshark (Windows)."""
import logging
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

log = logging.getLogger(__name__)

_IS_WINDOWS = sys.platform == "win32"

# Wireshark ships tshark.exe and dumpcap.exe
_WIRESHARK_DIR = Path("C:/Program Files/Wireshark")


def _find_capture_binary() -> Optional[str]:
    """Return the path to the best available capture tool."""
    # tcpdump first (Linux/macOS)
    if shutil.which("tcpdump"):
        return "tcpdump"
    # tshark from Wireshark on Windows
    tshark = _WIRESHARK_DIR / "tshark.exe"
    if tshark.exists():
        return str(tshark)
    if shutil.which("tshark"):
        return shutil.which("tshark")
    # dumpcap (part of Wireshark, lower overhead)
    dumpcap = _WIRESHARK_DIR / "dumpcap.exe"
    if dumpcap.exists():
        return str(dumpcap)
    if shutil.which("dumpcap"):
        return shutil.which("dumpcap")
    return None


def _build_cmd(binary: str, interface: str, path: Path, bpf: str) -> List[str]:
    """Build the capture command for the detected binary."""
    name = Path(binary).stem.lower()   # "tcpdump", "tshark", "dumpcap"

    if name == "tcpdump":
        cmd = [
            binary,
            "-i", interface,
            "-w", str(path),
            "-n",
            "--immediate-mode",
            "-s", "0",
        ]
        if bpf:
            cmd.append(bpf)

    elif name in ("tshark", "dumpcap"):
        # Force legacy pcap format so our struct parser can read it
        cmd = [
            binary,
            "-i", interface,
            "-w", str(path),
            "-F", "pcap",          # pcap not pcapng
        ]
        if name == "tshark":
            cmd += ["-q"]          # quiet: no per-packet output
        if bpf:
            cmd += ["-f", bpf]

    else:
        raise RuntimeError(f"Unknown capture binary: {binary}")

    return cmd


class Capture:
    """
    Starts tcpdump or tshark in the background and writes a PCAP file.

    Usage::
        with Capture("lo", Path("out.pcap"), bpf="tcp port 7000") as cap:
            # traffic happens here
        # cap.path is ready

    On Windows the interface name should be the adapter number as shown by
    ``tshark -D`` (e.g. ``"1"`` for the first interface) or its full name.
    Use ``iface="lo"`` / ``iface="1"`` for the loopback adapter.
    """

    def __init__(self, interface: str, path: Path, bpf: str = ""):
        self.interface = interface
        self.path = path
        self.bpf = bpf
        self._proc: Optional[subprocess.Popen] = None
        self._binary: Optional[str] = None

    # ------------------------------------------------------------------
    def start(self) -> None:
        binary = _find_capture_binary()
        if binary is None:
            raise RuntimeError(
                "No packet capture tool found. "
                "Install tcpdump (Linux/macOS) or Wireshark (Windows)."
            )

        # On Windows, tshark uses interface *numbers* (1, 2, …) or full names.
        # Map common aliases: "lo" → "1" (usually loopback on Windows).
        iface = self.interface
        if _IS_WINDOWS and iface in ("lo", "loopback"):
            iface = _resolve_loopback_iface(binary)

        cmd = _build_cmd(binary, iface, self.path, self.bpf)
        self._binary = binary

        log.info("Capture start: %s", " ".join(cmd))
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.5)   # give capture tool time to open the interface

    def stop(self) -> None:
        if self._proc is None:
            return
        try:
            if _IS_WINDOWS:
                # SIGINT is not reliably deliverable on Windows; terminate() works
                self._proc.terminate()
            else:
                self._proc.send_signal(signal.SIGINT)
            self._proc.wait(timeout=8)
        except (subprocess.TimeoutExpired, ProcessLookupError):
            self._proc.kill()
        size = self.path.stat().st_size if self.path.exists() else 0
        log.info("Capture stopped: %s  (%s bytes)", self.path, f"{size:,}")
        self._proc = None

    # ------------------------------------------------------------------
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()


# ── helpers ──────────────────────────────────────────────────────────────────

def _resolve_loopback_iface(binary: str) -> str:
    """
    Ask tshark/dumpcap for the loopback interface number on Windows.
    Falls back to "1" if detection fails.
    """
    try:
        result = subprocess.run(
            [binary, "-D"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            lower = line.lower()
            if "loopback" in lower or "lo0" in lower or "npcap loopback" in lower:
                # lines look like:  "1. \Device\NPF_Loopback (Adapter for loopback ...)"
                num = line.split(".")[0].strip()
                if num.isdigit():
                    log.debug("Resolved loopback interface: %s (%s)", num, line.strip())
                    return num
    except Exception as exc:
        log.debug("loopback detection failed: %s", exc)
    return "1"   # safe default on most Windows systems
