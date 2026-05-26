"""
PCAP / PCAPng parsing and flow-feature extraction.

Uses dpkt as primary library; falls back to scapy if dpkt is absent.
Both libraries handle all link types (including Windows loopback DLT_NULL=0).
"""
import logging
import math
import socket
import statistics
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Packet:
    ts: float       # Unix timestamp (seconds)
    src: str        # source IP
    dst: str        # destination IP
    sport: int
    dport: int
    proto: int      # 6=TCP, 17=UDP
    length: int     # transport payload length (bytes)
    ip_len: int     # total IP datagram length


@dataclass
class Flow:
    """Bidirectional flow keyed by canonical 5-tuple."""
    key: Tuple      # (src, dst, sport, dport, proto) — initiating direction
    packets: List[Packet] = field(default_factory=list)

    def fwd(self) -> List[Packet]:
        return [p for p in self.packets
                if (p.src, p.sport) == (self.key[0], self.key[2])]

    def bwd(self) -> List[Packet]:
        return [p for p in self.packets
                if (p.src, p.sport) != (self.key[0], self.key[2])]

    def duration(self) -> float:
        if len(self.packets) < 2:
            return 0.0
        return self.packets[-1].ts - self.packets[0].ts


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def parse_pcap(path: Path) -> List[Packet]:
    """Parse PCAP or PCAPng and return a time-sorted list of Packets."""
    try:
        pkts = _dpkt_parse(path)
        log.debug("dpkt parsed %d packets from %s", len(pkts), path.name)
        return pkts
    except ImportError:
        log.debug("dpkt not installed, trying scapy")
    except Exception as exc:
        log.warning("dpkt failed (%s), trying scapy", exc)

    try:
        pkts = _scapy_parse(path)
        log.debug("scapy parsed %d packets from %s", len(pkts), path.name)
        return pkts
    except ImportError:
        pass
    except Exception as exc:
        log.warning("scapy failed: %s", exc)

    raise RuntimeError(
        f"Cannot parse {path.name}: install dpkt or scapy  "
        "(pip install dpkt)"
    )


def extract_flows(packets: List[Packet]) -> Dict[Tuple, Flow]:
    """Group packets into bidirectional flows."""
    flows: Dict[Tuple, Flow] = {}
    for p in packets:
        bidi = tuple(sorted([(p.src, p.sport), (p.dst, p.dport)])) + (p.proto,)
        if bidi not in flows:
            flows[bidi] = Flow(key=(p.src, p.dst, p.sport, p.dport, p.proto))
        flows[bidi].packets.append(p)
    return flows


def extract_features(flow: Flow) -> dict:
    """
    Extract ~35 CICFlowMeter-style statistical features from a flow.
    All time values are in milliseconds; lengths in bytes.
    """

    def _stats(vals: List[float]) -> dict:
        if not vals:
            return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "sum": 0.0}
        return {
            "mean": statistics.mean(vals),
            "std":  statistics.pstdev(vals) if len(vals) > 1 else 0.0,
            "min":  min(vals),
            "max":  max(vals),
            "sum":  sum(vals),
        }

    def _iats(pkts: List[Packet]) -> List[float]:
        if len(pkts) < 2:
            return []
        return [(pkts[i+1].ts - pkts[i].ts) * 1000.0 for i in range(len(pkts)-1)]

    fwd, bwd = flow.fwd(), flow.bwd()
    all_pkts = sorted(flow.packets, key=lambda p: p.ts)

    fl = [p.length for p in fwd]
    bl = [p.length for p in bwd]
    al = [p.length for p in all_pkts]

    fi = _iats(sorted(fwd, key=lambda p: p.ts))
    bi = _iats(sorted(bwd, key=lambda p: p.ts))
    ai = _iats(all_pkts)

    feat: dict = {
        "duration_s":      flow.duration(),
        "fwd_pkts":        len(fwd),
        "bwd_pkts":        len(bwd),
        "pkt_ratio":       len(fwd) / max(len(bwd), 1),
        "byte_ratio":      sum(fl) / max(sum(bl), 1),
        "small_pkt_ratio": sum(1 for l in al if l < 100) / max(len(al), 1),
        "large_pkt_ratio": sum(1 for l in al if l > 1200) / max(len(al), 1),
        "payload_entropy": _entropy([p.length for p in all_pkts]),
    }

    for prefix, vals in (("fwd_len", fl), ("bwd_len", bl), ("all_len", al),
                          ("fwd_iat", fi), ("bwd_iat", bi), ("all_iat", ai)):
        for k, v in _stats(vals).items():
            feat[f"{prefix}_{k}"] = v

    return feat


def _entropy(lengths: List[int]) -> float:
    """Shannon entropy of the packet length distribution (bits)."""
    if not lengths:
        return 0.0
    total = len(lengths)
    freq: Dict[int, int] = {}
    for ln in lengths:
        freq[ln] = freq.get(ln, 0) + 1
    return -sum((c/total) * math.log2(c/total) for c in freq.values())


# --------------------------------------------------------------------------- #
# dpkt-based parser (primary)
# --------------------------------------------------------------------------- #

def _dpkt_parse(path: Path) -> List[Packet]:
    import dpkt  # type: ignore

    packets: List[Packet] = []

    with open(path, "rb") as f:
        # Try pcap first, then pcapng
        try:
            reader = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)  # type: ignore

        link_type = reader.datalink()
        log.debug("PCAP link type: %d", link_type)

        for ts, buf in reader:
            pkt = _dpkt_frame_to_packet(ts, buf, link_type)
            if pkt is not None:
                packets.append(pkt)

    return packets


def _dpkt_frame_to_packet(ts: float, buf: bytes, link_type: int) -> Optional[Packet]:
    import dpkt  # type: ignore

    # ── extract IP layer ─────────────────────────────────────────────────────
    ip = None

    if link_type == dpkt.pcap.DLT_EN10MB:          # 1 — Ethernet
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
        except Exception:
            return None

    elif link_type == dpkt.pcap.DLT_NULL:           # 0 — BSD NULL / loopback
        if len(buf) < 4:
            return None
        # 4-byte address-family field (little-endian on Windows/BSD)
        af = struct.unpack("<I", buf[:4])[0]
        if af != 2:                                 # 2 = AF_INET (IPv4)
            return None
        try:
            ip = dpkt.ip.IP(buf[4:])
        except Exception:
            return None

    elif link_type == 101:                          # raw IP (DLT_RAW)
        try:
            ip = dpkt.ip.IP(buf)
        except Exception:
            return None

    else:
        return None

    if ip is None:
        return None

    # ── extract transport layer ──────────────────────────────────────────────
    try:
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        ip_len = ip.len

        if isinstance(ip.data, dpkt.tcp.TCP):
            t = ip.data
            return Packet(ts=ts, src=src, dst=dst,
                          sport=t.sport, dport=t.dport,
                          proto=6, length=len(t.data), ip_len=ip_len)

        if isinstance(ip.data, dpkt.udp.UDP):
            u = ip.data
            return Packet(ts=ts, src=src, dst=dst,
                          sport=u.sport, dport=u.dport,
                          proto=17, length=len(u.data), ip_len=ip_len)
    except Exception:
        pass

    return None


# --------------------------------------------------------------------------- #
# scapy-based parser (fallback)
# --------------------------------------------------------------------------- #

def _scapy_parse(path: Path) -> List[Packet]:
    from scapy.all import rdpcap, IP, TCP, UDP  # type: ignore

    result = []
    for pkt in rdpcap(str(path)):
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        proto = sport = dport = payload = 0
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            proto, sport, dport, payload = 6, t.sport, t.dport, len(bytes(t.payload))
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            proto, sport, dport, payload = 17, u.sport, u.dport, len(bytes(u.payload))
        else:
            continue
        result.append(Packet(
            ts=float(pkt.time), src=ip.src, dst=ip.dst,
            sport=sport, dport=dport, proto=proto,
            length=payload, ip_len=ip.len,
        ))
    return result
