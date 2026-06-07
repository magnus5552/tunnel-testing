"""
M4 — ML flow classifier (heuristic + optional sklearn model)
M5 — Packet-sequence classifier (first 20 packets)
M6 — KL divergence for packet-length distribution vs. HTTPS reference
M7 — KL divergence for inter-arrival-time distribution vs. HTTPS reference

Reference distributions are loaded from  tester/reference_distributions.json
if that file exists (produced by  calibrate.py).  Otherwise the module falls
back to empirical approximations from published research on HTTPS/TLS traffic.

To calibrate for your local test environment:
    python calibrate.py          # from the tunnel-testing/ directory
"""
import csv
import json
import logging
import math
import statistics
from pathlib import Path
from typing import List, Optional

log = logging.getLogger(__name__)

# ── Reference HTTPS distributions (fallback / defaults) ────────────────────
# Packet length bins (bytes) and empirical probabilities
_LEN_BINS          = [0, 100, 300, 600, 900, 1200, 1600, 10000]
_LEN_PROBS_DEFAULT = [0.32, 0.08, 0.07, 0.07, 0.10, 0.24, 0.12]

# IAT bins (milliseconds) and empirical probabilities
_IAT_BINS          = [0, 1, 5, 20, 100, 500, 10_000]
_IAT_PROBS_DEFAULT = [0.38, 0.15, 0.15, 0.15, 0.12, 0.05]

_EPS = 1e-9   # smoothing constant for KL divergence


def _load_reference() -> tuple[list, list]:
    """
    Load calibrated reference distributions from tester/reference_distributions.json.

    Strategy:
      - IAT probs: always use calibrated values when available.
        IAT is highly environment-dependent (loopback ≈ 0 ms vs. WAN ≈ 20–100 ms);
        the calibration captures real internet RTT embedded in loopback SOCKS5 traffic,
        making the IAT baseline match actual test conditions.
      - LEN probs: keep the original research-based values.
        Packet-length distribution reflects protocol behaviour (AEAD frame sizes,
        TLS record overhead) rather than network latency, so the published empirical
        distribution remains a better reference than a short calibration capture.

    Falls back entirely to built-in defaults if the file is missing or malformed.
    Returns (len_probs, iat_probs).
    """
    ref_path = Path(__file__).parent.parent / "reference_distributions.json"
    if ref_path.exists():
        try:
            data = json.loads(ref_path.read_text(encoding="utf-8"))
            iat_p = data["iat_probs"]
            if len(iat_p) == len(_IAT_PROBS_DEFAULT):
                log.debug(
                    "Using calibrated IAT reference from %s  (n_packets=%s, "
                    "calibrated_at=%s); LEN reference kept from built-in defaults.",
                    ref_path,
                    data.get("n_packets", "?"),
                    data.get("calibrated_at", "?"),
                )
                return _LEN_PROBS_DEFAULT, iat_p
        except Exception as exc:
            log.warning("Could not load reference_distributions.json: %s", exc)
    return _LEN_PROBS_DEFAULT, _IAT_PROBS_DEFAULT


# Load once at import time
_LEN_PROBS, _IAT_PROBS = _load_reference()


def analyze(pcap_path: Path, output_dir: Path,
            model_path: Optional[Path] = None) -> dict:
    from ..utils.pcap_parse import parse_pcap, extract_flows, extract_features

    packets = parse_pcap(pcap_path)
    if not packets:
        return {"error": "no_packets_parsed"}

    sorted_pkts = sorted(packets, key=lambda p: p.ts)

    all_lengths = [p.length for p in sorted_pkts if p.length > 0]
    all_iats    = [
        (sorted_pkts[i+1].ts - sorted_pkts[i].ts) * 1000.0
        for i in range(len(sorted_pkts)-1)
        if sorted_pkts[i+1].ts - sorted_pkts[i].ts >= 0
    ]

    flows        = extract_flows(packets)
    features_all = [extract_features(f) for f in flows.values()]

    # ── M6 / M7: KL divergences ──────────────────────────────────────────
    kl_len = _kl_divergence(all_lengths, _LEN_BINS, _LEN_PROBS)
    kl_iat = _kl_divergence(all_iats,   _IAT_BINS, _IAT_PROBS)

    # ── M4: flow-level VPN probability ───────────────────────────────────
    vpn_prob = _heuristic_vpn_prob(all_lengths, all_iats, features_all, model_path)

    # ── M5: packet-sequence VPN probability ──────────────────────────────
    vpn_prob_seq = _sequence_vpn_prob(sorted_pkts[:20])

    # Save raw features for offline ML training
    _save_features_csv(features_all, output_dir / "flow_features.csv")

    # Summary stats
    mean_len = statistics.mean(all_lengths) if all_lengths else 0.0
    std_len  = statistics.pstdev(all_lengths) if len(all_lengths) > 1 else 0.0
    mean_iat = statistics.mean(all_iats) if all_iats else 0.0

    return {
        # Main metrics
        "vpn_prob":     round(vpn_prob,     4),
        "vpn_prob_seq": round(vpn_prob_seq, 4),
        "kl_len":       round(kl_len, 4),
        "kl_iat":       round(kl_iat, 4),
        # Descriptive stats
        "total_packets":  len(packets),
        "total_flows":    len(flows),
        "total_bytes":    sum(p.ip_len for p in packets),
        "duration_s":     round(sorted_pkts[-1].ts - sorted_pkts[0].ts, 2)
                          if len(sorted_pkts) > 1 else 0.0,
        "pkt_len_mean":   round(mean_len, 1),
        "pkt_len_std":    round(std_len,  1),
        "iat_mean_ms":    round(mean_iat, 2),
        "small_pkt_pct":  round(
            sum(1 for l in all_lengths if l < 100) / max(len(all_lengths), 1) * 100, 1
        ),
        "large_pkt_pct":  round(
            sum(1 for l in all_lengths if l > 1200) / max(len(all_lengths), 1) * 100, 1
        ),
        "model_used": "sklearn" if model_path else "heuristic",
    }


# ── KL divergence ───────────────────────────────────────────────────────────

def _kl_divergence(values: List[float], bins: List[float],
                   ref_probs: List[float]) -> float:
    """Compute KL(observed ‖ reference) using the given histogram bins."""
    if not values:
        return 0.0

    n_bins = len(bins) - 1
    counts = [0] * n_bins
    for v in values:
        placed = False
        for i in range(n_bins):
            if bins[i] <= v < bins[i+1]:
                counts[i] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1      # overflow → last bin

    n = sum(counts)
    if n == 0:
        return 0.0

    kl = 0.0
    for cnt, ref in zip(counts, ref_probs):
        p = cnt / n + _EPS
        q = ref + _EPS
        kl += p * math.log(p / q)
    return max(0.0, kl)


# ── Heuristic VPN classifier (M4) ───────────────────────────────────────────

def _heuristic_vpn_prob(lengths: List[float], iats: List[float],
                        features: list,
                        model_path: Optional[Path]) -> float:
    """
    Returns a VPN probability in [0, 1].

    If a serialized sklearn model exists at *model_path*, it is loaded and
    used for the primary prediction.  Otherwise, a rule-based heuristic
    serves as a drop-in substitute (suitable for bootstrapping before you
    have labelled training data).
    """
    if model_path and model_path.exists():
        return _sklearn_predict(features, model_path)

    return _rule_based_prob(lengths, iats, features)


def _sklearn_predict(features: list, model_path: Path) -> float:
    try:
        import pickle
        import numpy as np

        with open(model_path, "rb") as f:
            model = pickle.load(f)

        if not features:
            return 0.5

        # Use the first (largest) flow for prediction
        feat = features[0]
        keys = sorted(feat.keys())
        X    = np.array([[feat[k] for k in keys]])
        prob = model.predict_proba(X)[0][1]   # P(class=1 = VPN)
        return float(prob)
    except Exception as exc:
        log.warning(f"sklearn predict failed ({exc}); falling back to heuristic")
        return _rule_based_prob(features[0] if features else {}, [], [])


def _rule_based_prob(lengths, iats, features) -> float:
    """
    Simple rule-based heuristic.

    Encrypted VPN tunnels tend to exhibit:
      1. High mean payload size  (near MTU)
      2. Low coefficient of variation (uniform frame sizes → CBC / AEAD padding)
      3. Low proportion of tiny packets
      4. Symmetric byte ratio between directions
      5. More regular inter-arrival times (constant-rate shaping)
    """
    if not lengths:
        return 0.5

    score = 0.0

    # 1. Mean payload
    mean = statistics.mean(lengths)
    score += 0.30 * min(mean / 1300, 1.0)

    # 2. CV of lengths (lower → more VPN-like)
    if len(lengths) > 1:
        cv = statistics.pstdev(lengths) / (mean + 1.0)
        score += 0.20 * max(0.0, 1.0 - cv / 0.8)

    # 3. Tiny-packet fraction
    tiny = sum(1 for l in lengths if l < 100) / len(lengths)
    score += 0.20 * max(0.0, 1.0 - tiny / 0.3)

    # 4. Byte-ratio symmetry
    for feat in features:
        ratio = feat.get("byte_ratio", 1.0)
        sym = min(ratio, 1.0 / max(ratio, 1e-9))
        score += 0.15 * sym
        break

    # 5. IAT regularity
    if len(iats) > 1:
        cv_iat = statistics.pstdev(iats) / (statistics.mean(iats) + 1.0)
        score += 0.15 * max(0.0, 1.0 - cv_iat / 3.0)

    return round(min(1.0, score), 4)


# ── Packet-sequence heuristic (M5) ──────────────────────────────────────────

def _sequence_vpn_prob(packets) -> float:
    """
    Probability estimate from the first ≤ 20 packets.

    Checks:
      - First-5 packets are large (handshake frames)
      - High fraction of large packets overall
      - Low size variance
    """
    from ..utils.pcap_parse import Packet as Pkt
    lengths = [p.length for p in packets if p.length > 0]
    if not lengths:
        return 0.5

    score = 0.0

    first5 = lengths[:5]
    score += 0.30 * min(statistics.mean(first5) / 300, 1.0)

    large = sum(1 for l in lengths if l > 500) / len(lengths)
    score += 0.40 * large

    if len(lengths) > 2:
        cv = statistics.pstdev(lengths) / (statistics.mean(lengths) + 1.0)
        score += 0.30 * max(0.0, 1.0 - cv / 1.0)

    return round(min(1.0, score), 4)


# ── CSV export ───────────────────────────────────────────────────────────────

def _save_features_csv(features: list, path: Path) -> None:
    if not features:
        return
    keys = sorted(features[0].keys())
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(features)
    log.debug(f"Flow features → {path}  ({len(features)} rows)")
