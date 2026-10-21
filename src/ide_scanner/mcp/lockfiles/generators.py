import asyncio
import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from ..sca_support import run_subprocess_exec

logger = logging.getLogger(__name__)


class LockfileGenerator(ABC):
    @abstractmethod
    async def generate(self, manifest_path: Path) -> Path: ...


class JavaScriptLockGenerator(LockfileGenerator):
    @staticmethod
    def _detect_package_manager(manifest_path: Path) -> str:

        manifest_dir = manifest_path.parent
        lockfile_map = {
            "yarn.lock": "yarn",
            "pnpm-lock.yaml": "pnpm",
            "bun.lock": "bun",
            "bun.lockb": "bun",
            "package-lock.json": "npm",
        }

        for lockfile, pm in lockfile_map.items():
            if (manifest_dir / lockfile).exists():
                return pm

        try:
            with open(manifest_path, "r") as f:
                data = json.load(f)
                if pm_field := data.get("packageManager"):
                    for pm in ["yarn", "pnpm", "bun", "npm"]:
                        if pm in pm_field:
                            return pm
        except Exception as e:
            logger.warning(f"Error detecting package manager - {e}")

        return "npm"

    async def generate(self, manifest_path: Path, timeout: int = 60) -> Optional[Path]:

        package_manager = self._detect_package_manager(manifest_path)

        strategies = {
            "npm": (
                [
                    "npm",
                    "install",
                    "--package-lock-only",
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                ],
                "package-lock.json",
            ),
            "yarn": (["yarn", "install", "--ignore-scripts"], "yarn.lock"),
            "pnpm": (
                ["pnpm", "install", "--lockfile-only", "--ignore-scripts"],
                "pnpm-lock.yaml",
            ),
            "bun": (
                ["bun", "install", "--lockfile-only", "--save-text-lockfile"],
                "bun.lock",
            ),
        }

        manifest_dir = manifest_path.parent
        cmd, lockfile_name = strategies.get(package_manager, strategies["npm"])
        lockfile_path = manifest_dir / lockfile_name

        if lockfile_path.exists():
            return lockfile_path

        try:
            _, _, returncode = await run_subprocess_exec(
                args=cmd, cwd=manifest_dir, timeout=timeout
            )

            if returncode == 0 and lockfile_path.exists():
                return lockfile_path

        except asyncio.TimeoutError:
            logger.warning(f"Timeout generating {lockfile_name}.")
        except Exception as e:
            logger.warning(f"Error generating {lockfile_name} - {e}")
        return None


# --- Python Lockfile Generator ---
class UVLockGenerator(LockfileGenerator):
    async def generate(self, manifest_path: Path, timeout: int = 60) -> Optional[Path]:

        manifest_dir = manifest_path.parent
        lockfile_path = manifest_dir / "uv.lock"

        if lockfile_path.exists():
            return lockfile_path

        try:
            _, _, returncode = await run_subprocess_exec(
                args=["uv", "lock"], cwd=manifest_dir, timeout=timeout
            )

            if returncode == 0 and lockfile_path.exists():
                return lockfile_path

        except asyncio.TimeoutError:
            logger.warning("Timeout generating uv.lock.")
        except Exception as e:
            logger.warning(f"Error generating uv.lock - {e}")
        return None


# --- Rust Lockfile Generator ---
class CargoLockGenerator(LockfileGenerator):
    async def generate(self, manifest_path: Path, timeout: int = 60) -> Optional[Path]:

        manifest_dir = manifest_path.parent
        lockfile_path = manifest_dir / "Cargo.lock"

        if lockfile_path.exists():
            return lockfile_path

        try:
            _, _, returncode = await run_subprocess_exec(
                args=["cargo", "generate-lockfile"], cwd=manifest_dir, timeout=timeout
            )

            if returncode == 0 and lockfile_path.exists():
                return lockfile_path

        except asyncio.TimeoutError:
            logger.warning("Timeout generating Cargo.lock.")
        except Exception as e:
            logger.warning(f"Error generating Cargo.lock - {e}")
        return None


LOCKFILE_GENERATORS = {
    # --- JavaScript Manifests ---
    "package.json": JavaScriptLockGenerator(),
    # --- Python Manifests ---
    "pyproject.toml": UVLockGenerator(),
    # --- Rust Manifests ---
    "Cargo.toml": CargoLockGenerator(),
}


async def generate_lockfile(path_str: str) -> Optional[Path]:
    path = Path(path_str)
    generator = LOCKFILE_GENERATORS.get(path.name)
    if not generator or not path.exists():
        return None
    return await generator.generate(path)


__all__ = ["generate_lockfile", "LOCKFILE_GENERATORS"]

