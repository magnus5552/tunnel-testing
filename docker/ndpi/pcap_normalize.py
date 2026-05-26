#!/usr/bin/env python3
"""
pcap_normalize.py — convert DLT_NULL (BSD/Windows loopback, link type 0)
to DLT_RAW (raw IP, link type 101) so that ndpiReader can process it.

ndpiReader 4.x does not handle DLT_NULL frames.  On Windows every loopback
capture has link type 0 with a 4-byte address-family prefix (0x02000000 =
AF_INET) before the IP header.  This script strips that prefix and patches
the global PCAP header so ndpiReader sees plain raw-IP packets.

Usage
─────
    python3 pcap_normalize.py <input.pcap> <output.pcap>

If the input is NOT DLT_NULL the file is copied unchanged.
Exit code 0 on success, non-zero on error.
"""
import shutil
import struct
import sys
from pathlib import Path

# PCAP global-header magic numbers (read as little-endian uint32)
_LE_MAGIC     = 0xa1b2c3d4   # standard native (little-endian on x86)
_BE_MAGIC     = 0xd4c3b2a1   # big-endian file
_LE_MAGIC_NS  = 0xa1b23c4d   # nanosecond timestamps, LE
_BE_MAGIC_NS  = 0x4d3cb2a1   # nanosecond timestamps, BE

DLT_NULL = 0
DLT_RAW  = 101


def _endian_fmt(raw: bytes) -> str:
    """Return '<' or '>' based on the pcap magic number."""
    magic_le = struct.unpack("<I", raw[:4])[0]
    # If the file is big-endian, reading the magic as LE gives the byte-swapped value.
    if magic_le in (_LE_MAGIC, _LE_MAGIC_NS):
        return "<"
    if magic_le in (_BE_MAGIC, _BE_MAGIC_NS):
        return ">"
    raise ValueError(f"Unrecognised pcap magic: {magic_le:#010x}")


def convert(src: Path, dst: Path) -> bool:
    """
    Convert src to dst.  Returns True if a conversion was performed,
    False if the file was copied unchanged.
    """
    raw = src.read_bytes()
    if len(raw) < 24:
        raise ValueError("File too short to be a valid pcap")

    e = _endian_fmt(raw)
    gh_fmt = f"{e}IHHiIII"   # global header: 7 fields, 24 bytes

    magic, vmaj, vmin, tz, sig, snap, linktype = struct.unpack_from(gh_fmt, raw)

    if linktype != DLT_NULL:
        shutil.copy2(src, dst)
        return False

    # Build new global header with DLT_RAW
    new_gh = struct.pack(gh_fmt, magic, vmaj, vmin, tz, sig, snap, DLT_RAW)

    # Rewrite packet records: strip the 4-byte AF prefix from each one
    ph_fmt = f"{e}IIII"      # per-packet header: ts_sec, ts_usec, incl_len, orig_len
    out = bytearray(new_gh)
    off = 24
    while off + 16 <= len(raw):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(ph_fmt, raw, off)
        off += 16
        data = raw[off : off + incl_len]
        off += incl_len

        if len(data) < 4:
            # Packet too short to contain AF header — skip
            continue

        # AF header is the first 4 bytes; everything after is the IP packet
        ip_bytes = data[4:]
        new_incl = len(ip_bytes)
        new_orig = max(0, orig_len - 4)
        out += struct.pack(ph_fmt, ts_sec, ts_usec, new_incl, new_orig)
        out += ip_bytes

    dst.write_bytes(bytes(out))
    return True


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.pcap> <output.pcap>", file=sys.stderr)
        return 1
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    try:
        converted = convert(src, dst)
        if converted:
            print(f"pcap_normalize: DLT_NULL→DLT_RAW  {src.stat().st_size}→{dst.stat().st_size} bytes",
                  flush=True)
        return 0
    except Exception as exc:
        print(f"pcap_normalize error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
