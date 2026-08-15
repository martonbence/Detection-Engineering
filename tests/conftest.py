"""Makes the pipeline's scripts importable to the tests.

`scripts/` is a set of standalone CLI entry points, not an installable
package -- the workflows invoke them by path. Rather than restructure that
just to be testable, the directories holding the modules under test go on
sys.path here.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

for _sub in (
    "scripts/verify",
    "scripts/docs",
    "scripts/convert",
    "scripts/state",
    "scripts/deploy",
    "scripts/validate",
    # `scripts` itself, so `from lib.env import ...` resolves in a test that
    # imports nothing else. Every script reaches lib/ by doing this insert at
    # import time, which meant a test could only see the package as a side
    # effect of importing an unrelated module first -- and would break the
    # moment its imports were reordered. Register item 3.6 gave lib/ a second
    # module, so it is now worth stating directly.
    "scripts",
):
    _path = str(REPO_ROOT / _sub)
    if _path not in sys.path:
        sys.path.insert(0, _path)


# The files GitHub Actions hands a step to write back to the runner. They are
# real, live files during the `pytest` step of ci_code_checks.yml, so any test
# that exercises a script's "report to CI" path appends to the *actual* job
# summary or step output -- with whatever fixture data it invented.
#
# That is exactly what happened: three tests here each pushed a made-up
# DETECT-2026-0001/linux-victim finding into the Static-analysis job summary,
# which then reported rules that do not exist as broken.
#
# Unset rather than redirected to a temp file: a script that cannot work
# without these should fail visibly in the test, not write somewhere nobody
# reads. Tests that need one set it themselves.
_GITHUB_WRITABLE_ENV = (
    "GITHUB_STEP_SUMMARY",
    "GITHUB_OUTPUT",
    "GITHUB_ENV",
    "GITHUB_PATH",
)


@pytest.fixture(autouse=True)
def isolate_github_runner_files(monkeypatch):
    for var in _GITHUB_WRITABLE_ENV:
        monkeypatch.delenv(var, raising=False)
