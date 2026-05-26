#!/usr/bin/env python3
"""
tunnel-testing — CLI entry point.

Usage examples
──────────────
# Full run: start tunnel, generate traffic, analyse, report
python run_test.py \\
    --config   ../tunnel-gen/configs/example.yaml \\
    --root     ../tunnel-gen \\
    --scenario web \\
    --duration 30 \\
    --output   ./results/run-01

# Analyse an existing PCAP only (no tunnel required)
python run_test.py \\
    --config   ../tunnel-gen/configs/example.yaml \\
    --root     ../tunnel-gen \\
    --pcap     ./capture.pcap \\
    --output   ./results/run-01

# Skip specific analyzers
python run_test.py \\
    --config ../tunnel-gen/configs/example.yaml \\
    --root   ../tunnel-gen \\
    --skip   suricata zeek
"""
import argparse
import logging
import sys
from pathlib import Path

# ── Windows: request admin once so tshark never triggers UAC again ───────────
# Runs before argparse: the re-launched elevated process will re-enter here,
# find is_admin()==True or probe succeeding, and skip the UAC step.
if sys.platform == "win32":
    from tester.utils.windows_admin import ensure_admin_for_capture
    ensure_admin_for_capture()

from tester.config import TestConfig
from tester.runner import TestRunner


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="run_test.py",
        description="Tunnel detection testing framework (M1-M8)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Required
    p.add_argument(
        "--config", "-c", required=True, metavar="PATH",
        help="Path to the tunnel-gen DSL config YAML",
    )
    p.add_argument(
        "--root", "-r", required=True, metavar="PATH",
        help="Path to the tunnel-gen repository root (for go build)",
    )

    # Optional — traffic
    p.add_argument(
        "--scenario", "-s",
        choices=["web", "bulk", "idle"],
        default="web",
        help="Traffic scenario (default: web)",
    )
    p.add_argument(
        "--duration", "-d", type=int, default=30, metavar="SECS",
        help="Scenario duration in seconds (default: 30)",
    )
    p.add_argument(
        "--socks5", default="127.0.0.1:9080", metavar="HOST:PORT",
        help="SOCKS5 proxy address (default: 127.0.0.1:9080)",
    )
    p.add_argument(
        "--iface", "-i", default="lo", metavar="IFACE",
        help="Network interface to capture on (default: lo)",
    )

    # Optional — PCAP
    p.add_argument(
        "--pcap", metavar="PATH",
        help="Use existing PCAP instead of capturing live traffic",
    )
    p.add_argument(
        "--no-tunnel", action="store_true",
        help="Do not start tunnel server/client (use with --pcap or when "
             "tunnel is already running)",
    )

    # Optional — analyzers
    p.add_argument(
        "--skip", nargs="*", default=[],
        metavar="ANALYZER",
        help="Analyzers to skip: ndpi suricata zeek flow_ml probe",
    )
    p.add_argument(
        "--only", nargs="*", default=[],
        metavar="ANALYZER",
        help="Run only these analyzers (overrides --skip)",
    )

    # Optional — output
    p.add_argument(
        "--output", "-o", default="./results", metavar="PATH",
        help="Output directory (default: ./results)",
    )

    # Logging
    p.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )

    return p.parse_args()


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> int:
    args = _parse_args()
    _configure_logging(args.log_level)

    config_path = Path(args.config).resolve()
    root_path   = Path(args.root).resolve()
    output_dir  = Path(args.output).resolve()

    if not config_path.exists():
        logging.error("Config not found: %s", config_path)
        return 1
    if not root_path.exists():
        logging.error("tunnel-gen root not found: %s", root_path)
        return 1

    # Build skip-set
    all_analyzers = {"ndpi", "suricata", "zeek", "flow_ml", "probe"}
    if args.only:
        skip = all_analyzers - set(args.only)
    else:
        skip = set(args.skip)

    cfg = TestConfig(
        dsl_config=config_path,
        tunnel_gen_root=root_path,
        scenario=args.scenario,
        duration=args.duration,
        output_dir=output_dir,
        existing_pcap=Path(args.pcap).resolve() if args.pcap else None,
        skip_analyzers=skip,
        no_start_tunnel=args.no_tunnel or bool(args.pcap),
        socks5_addr=args.socks5,
        capture_iface=args.iface,
    )

    runner = TestRunner(cfg)
    report = runner.run()

    return 0 if report.get("verdict") == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
