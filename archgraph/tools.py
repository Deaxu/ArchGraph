"""Managed tool installation for SCIP indexers.

Downloads external tools (coursier, Maven) into ``~/.archgraph/tools/`` so they
are available without polluting the user's global PATH or modifying their system.

Usage::

    from archgraph.tools import ensure_coursier, ensure_maven, tools_env

    cs = ensure_coursier()          # returns Path to cs binary
    mvn = ensure_maven()            # returns Path to mvn binary
    env = tools_env()               # returns os.environ + tools on PATH
"""

from __future__ import annotations

import io
import logging
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.request import urlopen

logger = logging.getLogger(__name__)

TOOLS_DIR = Path.home() / ".archgraph" / "tools"
BIN_DIR = TOOLS_DIR / "bin"

# ── Coursier ────────────────────────────────────────────────────────────────

_CS_URLS: dict[tuple[str, str], str] = {
    ("Windows", "AMD64"): "https://github.com/coursier/launchers/raw/master/cs-x86_64-pc-win32.zip",
    ("Linux", "x86_64"): "https://github.com/coursier/launchers/raw/master/cs-x86_64-pc-linux.gz",
    ("Darwin", "x86_64"): "https://github.com/coursier/launchers/raw/master/cs-x86_64-apple-darwin.gz",
    ("Darwin", "arm64"): "https://github.com/coursier/launchers/raw/master/cs-aarch64-apple-darwin.gz",
    ("Linux", "aarch64"): "https://github.com/coursier/launchers/raw/master/cs-aarch64-pc-linux.gz",
}


def _cs_binary_name() -> str:
    return "cs.exe" if sys.platform == "win32" else "cs"


def ensure_coursier() -> Path | None:
    """Return path to coursier (``cs``) binary, downloading if needed."""
    # Check global PATH first
    existing = shutil.which("cs") or shutil.which("coursier")
    if existing:
        return Path(existing)

    # Check managed install
    managed = BIN_DIR / _cs_binary_name()
    if managed.exists():
        return managed

    # Download
    system = platform.system()
    machine = platform.machine()
    url = _CS_URLS.get((system, machine))
    if url is None:
        logger.warning("No coursier binary available for %s/%s", system, machine)
        return None

    logger.info("Downloading coursier to %s ...", BIN_DIR)
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    try:
        data = urlopen(url, timeout=60).read()
        if url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for member in zf.namelist():
                    if member.endswith(".exe") or "cs-" in member:
                        managed.write_bytes(zf.read(member))
                        break
        elif url.endswith(".gz"):
            import gzip
            managed.write_bytes(gzip.decompress(data))

        if sys.platform != "win32":
            managed.chmod(0o755)
        logger.info("Coursier installed: %s", managed)
        return managed
    except Exception as e:
        logger.warning("Failed to download coursier: %s", e)
        return None


# ── Maven ───────────────────────────────────────────────────────────────────

_MAVEN_VERSION = "3.9.6"
_MAVEN_URL = (
    f"https://archive.apache.org/dist/maven/maven-3/{_MAVEN_VERSION}"
    f"/binaries/apache-maven-{_MAVEN_VERSION}-bin.zip"
)


def _mvn_binary_name() -> str:
    return "mvn.cmd" if sys.platform == "win32" else "mvn"


def ensure_maven() -> Path | None:
    """Return path to ``mvn`` binary, downloading if needed."""
    # Check global PATH first
    existing = shutil.which("mvn")
    if existing:
        return Path(existing)

    # Check managed install
    maven_home = TOOLS_DIR / f"apache-maven-{_MAVEN_VERSION}"
    mvn = maven_home / "bin" / _mvn_binary_name()
    if mvn.exists():
        return mvn

    logger.info("Downloading Maven %s to %s ...", _MAVEN_VERSION, TOOLS_DIR)
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        data = urlopen(_MAVEN_URL, timeout=120).read()
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(TOOLS_DIR)
        if sys.platform != "win32":
            mvn.chmod(0o755)
            # Also make the mvn wrapper executable
            sh_mvn = maven_home / "bin" / "mvn"
            if sh_mvn.exists():
                sh_mvn.chmod(0o755)
        logger.info("Maven installed: %s", mvn)
        return mvn
    except Exception as e:
        logger.warning("Failed to download Maven: %s", e)
        return None


# ── Environment helper ──────────────────────────────────────────────────────


def tools_env() -> dict[str, str]:
    """Return a copy of ``os.environ`` with managed tools directories on PATH.

    This is passed to ``subprocess.run(env=...)`` so child processes can find
    managed tools without modifying the user's shell PATH.
    """
    env = os.environ.copy()
    extra_paths: list[str] = []

    # Managed bin dir (coursier)
    if BIN_DIR.exists():
        extra_paths.append(str(BIN_DIR))

    # Maven bin dir
    maven_home = TOOLS_DIR / f"apache-maven-{_MAVEN_VERSION}"
    maven_bin = maven_home / "bin"
    if maven_bin.exists():
        extra_paths.append(str(maven_bin))

    # Coursier app dir (scip-java installed via cs install)
    cs_apps = _coursier_bin_dir()
    if cs_apps and cs_apps.exists():
        extra_paths.append(str(cs_apps))

    if extra_paths:
        env["PATH"] = os.pathsep.join(extra_paths) + os.pathsep + env.get("PATH", "")

    return env


def _coursier_bin_dir() -> Path | None:
    """Return the coursier managed bin directory."""
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "Coursier" / "data" / "bin"
    return Path.home() / ".local" / "share" / "coursier" / "bin"
