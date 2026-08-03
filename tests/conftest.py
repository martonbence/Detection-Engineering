"""Makes the pipeline's scripts importable to the tests.

`scripts/` is a set of standalone CLI entry points, not an installable
package -- the workflows invoke them by path. Rather than restructure that
just to be testable, the directories holding the modules under test go on
sys.path here.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

for _sub in ("scripts/verify", "scripts/docs", "scripts/convert"):
    _path = str(REPO_ROOT / _sub)
    if _path not in sys.path:
        sys.path.insert(0, _path)
