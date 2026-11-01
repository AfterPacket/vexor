"""Atomic JSON snapshots for application-owned state; no inference or network I/O."""
import json
import os
from pathlib import Path
import tempfile
from typing import Any


def atomic_write_json(path: Path, data: Any) -> None:
    """Replace a snapshot only after serialization, flush, and fsync succeed.

    A unique temporary file on the same filesystem avoids partial destination
    writes and shared-temp-name collisions. This does not serialize concurrent
    writers or guarantee directory-entry durability after power loss.
    """
    payload = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
