"""
TestRunner — main orchestrator.

Sequence:
  1. (Optional) Start tunnel server + client processes
  2. Start tcpdump capture
  3. Run traffic scenario through SOCKS5 proxy
  4. Stop capture → PCAP file
  5. Run all analyzers (M1-M8) in turn
  6. Build and save report
"""
import logging
import time
from pathlib import Path
from typing import Optional

from .config import TestConfig
from .capture import Capture
from .traffic import run_web_scenario, run_bulk_scenario, run_idle_scenario
from .tunnel import tunnel_processes
from .report import build_report, save_report

log = logging.getLogger(__name__)


class TestRunner:
    def __init__(self, cfg: TestConfig) -> None:
        self.cfg = cfg

    def run(self) -> dict:
        cfg = self.cfg
        cfg.output_dir.mkdir(parents=True, exist_ok=True)

        log.info("=== tunnel-testing run ===")
        log.info("  config:   %s", cfg.dsl_config)
        log.info("  scenario: %s  duration: %ds", cfg.scenario, cfg.duration)
        log.info("  output:   %s", cfg.output_dir)

        # ── 1. Determine PCAP path ──────────────────────────────────────────
        if cfg.existing_pcap:
            pcap_path = cfg.existing_pcap
            log.info("Using existing PCAP: %s", pcap_path)
            raw = self._run_analyzers(pcap_path)
        else:
            pcap_path = cfg.output_dir / "capture.pcap"
            raw = self._run_with_capture(pcap_path)

        # ── 2. Build report ─────────────────────────────────────────────────
        report = build_report(raw, cfg)
        save_report(report, cfg.output_dir / "report.json")

        log.info("=== done — verdict: %s ===", report.get("verdict", "?"))
        return report

    # ── Private helpers ──────────────────────────────────────────────────────

    def _run_with_capture(self, pcap_path: Path) -> dict:
        cfg = self.cfg

        ctx_managers = []

        # Tunnel processes (server + client)
        if not cfg.no_start_tunnel:
            tunnel_ctx = tunnel_processes(
                config_path=cfg.dsl_config,
                tunnel_gen_root=cfg.tunnel_gen_root,
                socks5_addr=cfg.socks5_addr,
            )
            ctx_managers.append(("tunnel", tunnel_ctx))

        # Capture
        capture_ctx = Capture(
            interface=cfg.capture_iface,
            path=pcap_path,
        )
        ctx_managers.append(("capture", capture_ctx))

        # Start everything
        entered = []
        try:
            for name, ctx in ctx_managers:
                log.info("Starting %s…", name)
                ctx.__enter__()
                entered.append((name, ctx))
        except Exception as exc:
            log.error("Startup failed: %s", exc)
            self._exit_all(entered, exc)
            raise

        # Run traffic + M8 probe (while tunnel is still up)
        m8_result: dict = {}
        try:
            time.sleep(1.0)   # let tunnel stabilise
            self._run_scenario()
            time.sleep(0.3)   # flush last packets

            # M8 must run before the tunnel stops
            if "probe" not in self.cfg.skip_analyzers:
                server_addr = self._probe_addr()
                if server_addr:
                    log.info("Running M8 (active probing) → %s…", server_addr)
                    try:
                        from .analyzers.probe import analyze as probe_analyze
                        m8_result = probe_analyze(server_addr, self.cfg.output_dir)
                    except Exception as exc:
                        log.error("M8 (probe) failed: %s", exc)
                        m8_result = {"error": str(exc)}
                else:
                    m8_result = {"skipped": True, "reason": "no_server_addr"}
        finally:
            self._exit_all(entered, None)

        raw = self._run_analyzers(pcap_path)
        if m8_result:
            raw["m8_probe"] = m8_result
        return raw

    def _run_scenario(self) -> None:
        cfg = self.cfg
        log.info("Running scenario '%s' for %ds…", cfg.scenario, cfg.duration)

        if cfg.scenario == "web":
            run_web_scenario(cfg.socks5_addr, duration=cfg.duration, output_dir=cfg.output_dir)
        elif cfg.scenario == "bulk":
            run_bulk_scenario(cfg.socks5_addr, duration=cfg.duration, output_dir=cfg.output_dir)
        elif cfg.scenario == "idle":
            run_idle_scenario(cfg.socks5_addr, duration=cfg.duration, output_dir=cfg.output_dir)
        else:
            raise ValueError(f"Unknown scenario: {cfg.scenario!r}")

    def _run_analyzers(self, pcap_path: Path) -> dict:
        cfg = self.cfg
        results: dict = {"pcap_path": str(pcap_path)}

        # ── M1: nDPI ────────────────────────────────────────────────────────
        if "ndpi" not in cfg.skip_analyzers:
            log.info("Running M1 (nDPI)…")
            try:
                from .analyzers.ndpi import analyze as ndpi_analyze
                results["m1_ndpi"] = ndpi_analyze(pcap_path, cfg.output_dir)
            except Exception as exc:
                log.error("M1 (nDPI) failed: %s", exc)
                results["m1_ndpi"] = {"error": str(exc)}

        # ── M2: Suricata ─────────────────────────────────────────────────────
        if "suricata" not in cfg.skip_analyzers:
            log.info("Running M2 (Suricata)…")
            try:
                from .analyzers.suricata import analyze as suricata_analyze
                # rules/ lives next to run_test.py, i.e. in the tunnel-testing root
                _here = Path(__file__).parent.parent   # tester/ → tunnel-testing/
                rules_dir = _here / "rules"
                results["m2_suricata"] = suricata_analyze(
                    pcap_path, cfg.output_dir, rules_dir=rules_dir
                )
            except Exception as exc:
                log.error("M2 (Suricata) failed: %s", exc)
                results["m2_suricata"] = {"error": str(exc)}

        # ── M3: Zeek / JA3 ──────────────────────────────────────────────────
        if "zeek" not in cfg.skip_analyzers:
            log.info("Running M3 (Zeek)…")
            try:
                from .analyzers.zeek import analyze as zeek_analyze
                results["m3_zeek"] = zeek_analyze(pcap_path, cfg.output_dir)
            except Exception as exc:
                log.error("M3 (Zeek) failed: %s", exc)
                results["m3_zeek"] = {"error": str(exc)}

        # ── M4-M7: flow_ml ───────────────────────────────────────────────────
        if "flow_ml" not in cfg.skip_analyzers:
            log.info("Running M4-M7 (flow_ml)…")
            try:
                from .analyzers.flow_ml import analyze as ml_analyze
                model_path: Optional[Path] = None
                model_candidate = cfg.output_dir.parent / "model.pkl"
                if model_candidate.exists():
                    model_path = model_candidate
                results["m4_m7_flow"] = ml_analyze(
                    pcap_path, cfg.output_dir, model_path=model_path
                )
            except Exception as exc:
                log.error("M4-M7 (flow_ml) failed: %s", exc)
                results["m4_m7_flow"] = {"error": str(exc)}

        # M8 is NOT run here — it runs while the tunnel is still up in
        # _run_with_capture(), or if existing_pcap is used, it is skipped
        # (no live server available).
        if cfg.existing_pcap and "probe" not in cfg.skip_analyzers:
            server_addr = self._probe_addr()
            if server_addr:
                log.info("Running M8 (active probing) → %s…", server_addr)
                try:
                    from .analyzers.probe import analyze as probe_analyze
                    results["m8_probe"] = probe_analyze(server_addr, cfg.output_dir)
                except Exception as exc:
                    log.error("M8 (probe) failed: %s", exc)
                    results["m8_probe"] = {"error": str(exc)}
            else:
                results["m8_probe"] = {"skipped": True, "reason": "no_server_addr"}

        return results

    def _probe_addr(self) -> Optional[str]:
        """Return host:port for the tunnel server's raw TCP port."""
        try:
            from .tunnel import read_dsl_port
            port = read_dsl_port(self.cfg.dsl_config)
            if port:
                return f"127.0.0.1:{port}"
        except Exception:
            pass
        return None

    @staticmethod
    def _exit_all(entered, exc):
        for name, ctx in reversed(entered):
            try:
                ctx.__exit__(type(exc) if exc else None,
                             exc, exc.__traceback__ if exc else None)
            except Exception as e2:
                log.warning("Error stopping %s: %s", name, e2)
