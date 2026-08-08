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


# --- the per-rule table -------------------------------------------------------
#
# Four states, and the pairs that must never collapse into each other: "not
# deployed here" versus "deployed and now gone from Splunk" look identical in a
# naive rendering and mean opposite things.


def repo_rules(*pairs):
    return [{"detect_id": did, "rule_version": ver, "title": "T"} for did, ver in pairs]


def env_with(rules, missing_ids=()):
    return {
        "last_deploy": {"at": "2026-08-08T18:00:00+00:00", "rules": rules},
        "splunk_state": {"checked_at": "2026-08-08T18:05:00+00:00", "has_drift": bool(missing_ids),
                         "missing_ids": list(missing_ids)},
    }


def test_a_rule_at_the_repo_version_reads_as_current():
    inv = inventory(dev=env_with({"DETECT-2026-0001": {"rule_version": "1.2"}}))
    html = gs.render_deployment_html(inv, "o/r", repo_rules(("DETECT-2026-0001", "1.2")))

    assert "dep-live" in html
    assert "dep-behind" not in html.split("dep-legend")[0]


def test_an_older_version_reads_as_behind_and_shows_both_numbers():
    """The interesting case, and the one nothing in the pipeline showed before."""
    inv = inventory(prod=env_with({"DETECT-2026-0001": {"rule_version": "1.2"}}))
    html = gs.render_deployment_html(inv, "o/r", repo_rules(("DETECT-2026-0001", "1.4")))

    assert "dep-behind" in html
    assert "1.2 vs 1.4" in html


def test_an_environment_with_no_rule_map_is_unrecorded_not_empty():
    """The panel's worst possible lie: announcing an empty production app.

    Prod's per-rule versions arrive by ingesting a deploy-report artifact. Until
    that has happened there is no rule map, and rendering it as 27 absences
    would report a fully deployed environment as deploying nothing.
    """
    inv = inventory(prod=env_with({}))
    inv["environments"]["prod"]["last_deploy"]["at"] = "2026-08-08T17:56:04Z"
    html = gs.render_deployment_html(inv, "o/r", repo_rules(("DETECT-2026-0001", "1.0")))

    body = html.split("dep-legend")[0]
    assert "dep-unrecorded" in body
    assert "dep-absent" not in body


def test_a_rule_never_deployed_is_absent_not_dead():
    """Register item 1.1 closed "not promoted yet" as normal, so it is not red.

    The environment is known per rule -- other rules are recorded in it -- so
    this rule's absence is a measured fact rather than a gap in our knowledge.
    """
    inv = inventory(prod=env_with({"DETECT-2026-0002": {"rule_version": "1.0"}}))
    rules = repo_rules(("DETECT-2026-0001", "1.0"), ("DETECT-2026-0002", "1.0"))
    html = gs.render_deployment_html(inv, "o/r", rules)

    body = html.split("dep-legend")[0]
    assert "dep-absent" in body
    assert "dep-gone" not in body


def test_a_rule_splunk_no_longer_has_is_the_one_alarm():
    """Deployed, should be running, and the reconcile could not find it."""
    inv = inventory(
        prod=env_with({"DETECT-2026-0001": {"rule_version": "1.0"}}, missing_ids=["DETECT-2026-0001"])
    )
    html = gs.render_deployment_html(inv, "o/r", repo_rules(("DETECT-2026-0001", "1.0")))

    assert "dep-gone" in html


def test_splunks_answer_beats_the_deploy_log():
    """The deploy says what was sent; the reconcile says what is there now."""
    inv = inventory(
        prod=env_with({"DETECT-2026-0001": {"rule_version": "1.4"}}, missing_ids=["DETECT-2026-0001"])
    )
    html = gs.render_deployment_html(inv, "o/r", repo_rules(("DETECT-2026-0001", "1.4")))

    body = html.split("dep-legend")[0]
    assert "dep-gone" in body
    assert "dep-live" not in body


def test_every_repo_rule_gets_a_row_even_if_deployed_nowhere():
    """Inventory-driven rows would omit exactly the rules worth noticing."""
    inv = inventory(dev=env_with({"DETECT-2026-0001": {"rule_version": "1.0"}}))
    rules = repo_rules(("DETECT-2026-0001", "1.0"), ("DETECT-2026-0002", "1.0"))
    html = gs.render_deployment_html(inv, "o/r", rules)

    assert "DETECT-2026-0001" in html
    assert "DETECT-2026-0002" in html


def test_the_state_is_also_readable_without_colour():
    """Nearly the whole table is state, so colour alone would not be enough."""
    inv = inventory(dev=env_with({"DETECT-2026-0001": {"rule_version": "1.0"}}))
    html = gs.render_deployment_html(inv, "o/r", repo_rules(("DETECT-2026-0001", "1.0")))

    assert "visually-hidden" in html
    assert "title=" in html


def test_no_rule_list_means_no_table_but_still_a_panel():
    html = gs.render_deployment_html(inventory(dev=dev_section(state=state())), "o/r", [])

    assert "dep-rules" not in html
    assert "Last deployed" in html
