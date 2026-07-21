from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ._atomic import write_text


def export_json(report: dict[str, Any], output: str | Path) -> Path:
    path = Path(output)
    write_text(path, json.dumps(report, indent=2, sort_keys=True))
    return path
