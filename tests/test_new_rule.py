"""Sigma rule scaffolder (register item 4.5, scaffolder half; see
scripts/validate/check_detect_id_uniqueness.py for the collision-protection
half, tested separately).

Nothing in `tests/` exercised `new_rule.py` before this module -- despite the
`sigma-rule-authoring` skill starting every new rule with it, and the
script's own top-of-file comment asserting a specific, checkable claim:

    "The generated file is schema-valid on its own -- every TODO placeholder
    satisfies sigma_schema.json's length/pattern constraints -- so
    validate_sigma.py passes on it unedited."

`test_scaffolded_skeleton_passes_schema_validation_unedited` is that claim,
made into a test: it runs `new_rule.main` and `validate_sigma.main` back to
back, against the repo's real schema, and would fail the moment a SKELETON
edit drifted out of sync with docs/schemas/sigma_schema.json without anyone
touching validate_sigma.py itself.

Every test here points `--rules-dir` at `tmp_path` -- the real `rules/sigma/`
is never read or written by this module.
"""

from __future__ import annotations

import sys
from pathlib import Path

from new_rule import main, next_detect_id

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = REPO_ROOT / "docs" / "schemas" / "sigma_schema.json"


# --- the claim in new_rule.py's own header comment ---------------------------


def test_scaffolded_skeleton_passes_schema_validation_unedited(tmp_path, monkeypatch):
    """scaffold -> validate round trip. Proves the file new_rule.py hands an
    author is schema-valid before they touch a single TODO."""
    assert SCHEMA.exists(), f"expected schema at {SCHEMA}"

    rc = main(["Suspicious LSASS Access From Uncommon Process", "--rules-dir", str(tmp_path)])
    assert rc == 0

    generated = list(tmp_path.glob("*.yml"))
    assert len(generated) == 1

    import validate_sigma

    monkeypatch.setattr(
        sys, "argv", ["validate_sigma.py", "--schema", str(SCHEMA), str(generated[0])]
    )
    assert validate_sigma.main() == 0


def test_scaffolded_rule_carries_a_fresh_detect_id_and_slugged_filename(tmp_path):
    from new_rule import slugify

    title = "My Very First Detection Rule"
    rc = main([title, "--rules-dir", str(tmp_path)])
    assert rc == 0

    generated = list(tmp_path.glob("*.yml"))
    assert len(generated) == 1

    name = generated[0].name
    assert name.startswith("DETECT-")
    assert slugify(title) in name

    text = generated[0].read_text(encoding="utf-8")
    assert "title: My Very First Detection Rule" in text
    assert "custom:" in text
    assert "testing:" in text


def test_second_scaffold_in_the_same_directory_gets_the_next_free_id(tmp_path):
    main(["First Rule Title Here", "--rules-dir", str(tmp_path)])
    main(["Second Rule Title Here", "--rules-dir", str(tmp_path)])

    generated = sorted(p.name for p in tmp_path.glob("*.yml"))
    assert len(generated) == 2
    assert generated[0] != generated[1]

    first_id = generated[0].split("_", 1)[0]
    second_id = generated[1].split("_", 1)[0]
    assert first_id != second_id


# --- error branches -----------------------------------------------------------


def test_title_shorter_than_five_chars_is_rejected(tmp_path, capsys):
    rc = main(["Hi", "--rules-dir", str(tmp_path)])

    assert rc == 2
    assert "too short" in capsys.readouterr().err.lower()
    assert list(tmp_path.glob("*.yml")) == []


def test_existing_filename_collision_returns_2(tmp_path, capsys):
    """`next_detect_id` always increments past ids already in use, so simply
    calling `main()` twice with the same title never collides -- the second
    call lands on the next free id with the same slug, a different filename.
    The actual collision guard (out_path.exists()) needs the exact target
    filename pre-planted, which is what this does directly."""
    from new_rule import slugify

    title = "Exact Duplicate Title"
    expected_id = next_detect_id(tmp_path)
    pre_existing = tmp_path / f"{expected_id}_{slugify(title)}.yml"
    pre_existing.write_text("placeholder -- not a real rule", encoding="utf-8")

    rc = main([title, "--rules-dir", str(tmp_path)])

    assert rc == 2
    assert "already exists" in capsys.readouterr().err
    # The pre-existing file was not overwritten.
    assert pre_existing.read_text(encoding="utf-8") == "placeholder -- not a real rule"
    assert list(tmp_path.glob("*.yml")) == [pre_existing]
