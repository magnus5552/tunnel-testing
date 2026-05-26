"""Thin subprocess wrapper for `docker run --rm …`."""
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


def docker_available() -> bool:
    return shutil.which("docker") is not None


def docker_run(
    image: str,
    cmd: List[str],
    volumes: Optional[Dict[str, str]] = None,
    env: Optional[Dict[str, str]] = None,
    workdir: Optional[str] = None,
    timeout: int = 300,
) -> Tuple[int, str, str]:
    """
    Run ``docker run --rm <image> <cmd>`` and return (returncode, stdout, stderr).

    Parameters
    ----------
    volumes : {host_path: "container_path[:ro]"}
    """
    args: List[str] = ["docker", "run", "--rm"]

    if workdir:
        args += ["-w", workdir]

    for h, c in (volumes or {}).items():
        args += ["-v", f"{Path(h).resolve()}:{c}"]

    for k, v in (env or {}).items():
        args += ["-e", f"{k}={v}"]

    args += [image] + cmd

    log.debug("docker: %s", " ".join(args))

    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        log.error(f"docker run timed out after {timeout} s: {image}")
        return -1, "", "timeout"
    except FileNotFoundError:
        log.error("docker binary not found")
        return -1, "", "docker not found"


def pull_if_missing(image: str) -> bool:
    """Pull image if not present locally. Returns True on success."""
    check = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
    )
    if check.returncode == 0:
        return True  # already present

    log.info(f"Pulling Docker image: {image}")
    pull = subprocess.run(["docker", "pull", image], capture_output=True)
    if pull.returncode != 0:
        log.error(f"Failed to pull {image}: {pull.stderr.decode()[:300]}")
        return False
    return True
