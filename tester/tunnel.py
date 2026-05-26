"""Start / stop tunnel-gen server and client processes."""
import logging
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

_EXE = ".exe" if sys.platform == "win32" else ""


def read_dsl_port(config_path: Path) -> int:
    """Extract transport.port from a DSL YAML config."""
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    return int(cfg.get("transport", {}).get("port", 0))


def _wait_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _build(tunnel_gen_root: Path, cmd_name: str) -> Path:
    """Build a tunnel-gen binary and return its path."""
    out = tunnel_gen_root / f"{cmd_name}{_EXE}"
    log.info(f"Building {cmd_name}...")
    result = subprocess.run(
        ["go", "build", "-o", str(out), f"./cmd/{cmd_name.replace('tunnel-', '')}"],
        cwd=tunnel_gen_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"go build {cmd_name} failed:\n{result.stderr}"
        )
    log.info(f"Built: {out}")
    return out


@contextmanager
def tunnel_processes(config_path: Path, tunnel_gen_root: Path, socks5_addr: str):
    """
    Context manager that builds, starts, and stops tunnel-server + tunnel-client.

    Usage::
        with tunnel_processes(config, root, "127.0.0.1:1080"):
            # server and client are running
            ...
        # processes stopped here
    """
    server_bin = _build(tunnel_gen_root, "tunnel-server")
    client_bin = _build(tunnel_gen_root, "tunnel-client")

    server_port = read_dsl_port(config_path)

    # Run server/client from the config's parent directory so that relative
    # paths inside the YAML (cert_file, key_file, …) resolve correctly.
    config_dir = str(config_path.parent)

    # ── server ────────────────────────────────────────────────────────────────
    server = subprocess.Popen(
        [str(server_bin), "-config", str(config_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=config_dir,
    )
    log.info(f"Server started  pid={server.pid}  port={server_port}  cwd={config_dir}")

    if server_port and not _wait_port("127.0.0.1", server_port, timeout=10):
        # Grab whatever the server printed before dying
        try:
            out, _ = server.communicate(timeout=1)
            log.error("Server output:\n%s", out.decode(errors="replace"))
        except subprocess.TimeoutExpired:
            server.kill()
        raise RuntimeError(f"Server did not listen on port {server_port} within 10 s")

    # ── client ────────────────────────────────────────────────────────────────
    socks_host, socks_port = socks5_addr.rsplit(":", 1)
    client = subprocess.Popen(
        [str(client_bin), "-config", str(config_path), "-socks5", socks5_addr],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=config_dir,
    )
    log.info(f"Client started  pid={client.pid}  socks5={socks5_addr}  cwd={config_dir}")

    if not _wait_port(socks_host, int(socks_port), timeout=10):
        client.kill()
        server.kill()
        raise RuntimeError(f"Client SOCKS5 did not become ready on {socks5_addr}")

    try:
        yield
    finally:
        for proc, name in ((client, "client"), (server, "server")):
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            log.info(f"{name} stopped")
