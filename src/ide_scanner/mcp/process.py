from __future__ import annotations

import asyncio
from typing import Sequence


async def run_subprocess_exec(*, args: Sequence[str], timeout: int = 60, **_: object) -> tuple[str, str, int]:
    process = await asyncio.create_subprocess_exec(
        *[str(arg) for arg in args],
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return "", "process timed out", 124
    return stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace"), process.returncode or 0

