"""The dashboard's deployment panel (register item 4.7).

The panel is rendered in Python rather than by page.js, and these tests guard
the two properties that made that choice worth it: it disappears completely
when there is nothing true to say, and it never merges "what we sent" with
"what is actually there".
"""

import generate_stats as gs


def inventory(**envs):
    return {"schema": 1, "environments": envs}


def dev_section(rules=2, commit="abc1234def", at="2026-08-08T18:00:00+00:00", state=None):
    section = {
        "last_deploy": {
            "at": at,
            "commit": commit,
            "run_id": "42",
            "run_url": "https://github.com/o/r/actions/runs/42",
            "totals": {"updated": rules},
            "rules": {f"DETECT-2026-{i:04d}": {"rule_version": "1.0", "outcome": "updated"} for i in range(rules)},
        }
    }
    if state is not None:
        section["splunk_state"] = state
    return section


def state(has_drift=False, **counts):
    base = {
        "checked_at": "2026-08-08T18:05:00+00:00",
        "in_sync": 27, "missing": 0, "orphan_renamed": 0, "orphan_removed": 0,
        "orphan_removed_unretired": 0, "unmanaged": 0, "duplicate_names": 0,
        "has_drift": has_drift,
    }
    base.update(counts)
    return base


# --- absence ------------------------------------------------------------------


def test_no_inventory_renders_no_panel():
    """An empty panel claiming "0 deployed" is a worse answer than no panel."""
    assert gs.render_deployment_html({}, "o/r") == ""
    assert gs.render_deployment_html({"environments": {}}, "o/r") == ""
    assert gs.render_deployment_html({"schema": 1}, "o/r") == ""


def test_a_corrupt_inventory_renders_no_panel():
    assert gs.render_deployment_html({"environments": "not a dict"}, "o/r") == ""


def test_missing_inventory_file_is_not_an_error(tmp_path):
    assert gs.load_deployment_inventory(tmp_path / "absent.json") == {}


def test_unreadable_inventory_file_is_not_an_error(tmp_path):
    path = tmp_path / "inv.json"
    path.write_text("{not json", encoding="utf-8")
    assert gs.load_deployment_inventory(path) == {}


# --- content ------------------------------------------------------------------


def test_both_halves_are_stated_separately():
    """"We sent 27" and "27 are there" are different claims and stay apart."""
    html = gs.render_deployment_html(inventory(dev=dev_section(state=state())), "o/r")

    assert "Last deployed" in html
    assert "Splunk checked" in html
    assert "matches the repo" in html


def test_drift_is_named_rather_than_just_flagged():
    html = gs.render_deployment_html(
        inventory(prod=dev_section(state=state(has_drift=True, missing=2, in_sync=25))), "o/r"
    )

    assert "drift" in html
    assert "2 missing" in html


def test_an_environment_never_checked_says_so_instead_of_looking_healthy():
    html = gs.render_deployment_html(inventory(prod=dev_section()), "o/r")

    assert "never" in html
    assert "matches the repo" not in html


def test_dev_is_rendered_before_prod():
    """They are read against each other, and the pipeline runs in that order."""
    html = gs.render_deployment_html(
        inventory(prod=dev_section(), dev=dev_section()), "o/r"
    )

    assert html.index(">dev<") < html.index(">prod<")


def test_the_commit_links_to_the_repo():
    html = gs.render_deployment_html(inventory(dev=dev_section(commit="abc1234def")), "o/r")

    assert "https://github.com/o/r/commit/abc1234def" in html
    assert ">abc1234<" in html  # shortened for reading, full sha in the href


def test_nothing_in_the_panel_names_where_splunk_is():
    """The 2.4 report omits URL, app and account because this repo is public.

    The panel is rendered into a published page, so the same rule binds harder
    here: everything shown must be derivable from the repo itself.
    """
    section = dev_section(state=state())
    # Fields an over-eager future change might start carrying through.
    section["app"] = "detection_engineering"
    section["base_url"] = "https://192.168.0.1:8089"

    html = gs.render_deployment_html(inventory(dev=section), "o/r")

    assert "detection_engineering" not in html
    assert "192.168" not in html


def test_ages_are_relative_and_coarse():
    assert gs._relative_age("") == ""
    assert gs._relative_age("not a date") == ""
