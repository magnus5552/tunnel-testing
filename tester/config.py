"""TestConfig — runtime parameters for a single detection test run."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Set


@dataclass
class TestConfig:
    dsl_config: Path          # DSL YAML config to test
    tunnel_gen_root: Path     # tunnel-gen project root (for `go build`)
    scenario: str             # "web" | "bulk" | "idle"
    duration: int             # traffic generation duration in seconds
    output_dir: Path          # where to save all artifacts

    existing_pcap: Optional[Path] = None   # skip capture, analyse this PCAP
    skip_analyzers: Set[str] = field(default_factory=set)

    no_start_tunnel: bool = False          # don't launch server/client
    socks5_addr: str = "127.0.0.1:9080"   # SOCKS5 proxy for traffic gen
    capture_iface: str = "lo"             # tcpdump interface
