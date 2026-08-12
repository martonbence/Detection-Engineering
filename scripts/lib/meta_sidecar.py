"""Locating and parsing the <name>.meta.json sidecar (register item 3.6).

Three Python callers -- the deploy, the hit check and the indexing wait --
each located the sidecar next to its `.spl` and parsed it themselves, and
each already answers a missing or malformed sidecar differently, on purpose:
the deploy treats it as a setup failure (`die`), the hit check treats it as an
unmeasured rule (an empty dict, feeding a `.get()` chain downstream), and the
indexing wait treats it as one file to skip among possibly many (`continue`).
That is not the kind of duplication item 3.6 already found and removed with
`env_required` -- these three policies are load-bearing, not accidental
copies -- so only the part all three do identically, finding the sidecar path
and parsing its JSON, moves here. Each caller keeps its own except clause.

The PowerShell reader in `run_atomic.ps1` is not consolidated here: sharing
code across languages is not the kind of duplication this module addresses.
"""

import json
from pathlib import Path


def meta_sidecar_path(spl_path: Path) -> Path:
    return spl_path.parent / (spl_path.stem + ".meta.json")


def read_meta_sidecar(spl_path: Path) -> dict:
    """Return the parsed sidecar for `spl_path`.

    Raises `FileNotFoundError` if the sidecar does not exist and
    `json.JSONDecodeError` if it exists but does not parse -- both left to
    propagate so each caller's existing except clause keeps deciding what a
    failure means for it.
    """
    return json.loads(meta_sidecar_path(spl_path).read_text(encoding="utf-8"))
