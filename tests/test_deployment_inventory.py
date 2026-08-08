"""The deployment inventory (register item 4.7).

What is asserted here is mostly about restraint: what the inventory refuses to
do. It must not erase an environment it knows nothing about, must not rewrite
itself when nothing changed, must not invent state when its inputs are missing,
and must not report an analyst's own saved search as drift. Each of those is a
way the file could quietly become untrustworthy, which would make it worse than
the nothing it replaces.
"""

import json

import deployment_inventory as inv
import pytest


def deploy_report(rules=None, totals=None, deployed_at="2026-08-08T18:00:00+00:00"):
    return {
        "deployed_at": deployed_at,
        "totals": totals if totals is not None else {"updated": 2},
        "rules": rules
        if rules is not None
        else [
            {"detect_id": "DETECT-2026-0007", "rule_version": "1.2", "outcome": "updated"},
            {"detect_id": "DETECT-2026-0028", "rule_version": "1.8", "outcome": "updated"},
        ],
    }


def reconcile_report(counts=None, orphan_removed=None):
    base = {
        "desired": 27, "actual": 27, "in_sync": 27, "missing": 0,
        "orphan_renamed": 0, "orphan_removed": 0, "unmanaged": 0, "duplicate_names": 0,
    }
    base.update(counts or {})
    return {"counts": base, "orphan_removed": orphan_removed or []}


def write(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def run(tmp_path, env, deploy=None, reconcile=None, extra=()):
    args = ["--env", env, "--inventory", str(tmp_path / "inv.json")]
    if deploy is not None:
        args += ["--deploy-report", str(write(tmp_path / f"{env}_deploy.json", deploy))]
    if reconcile is not None:
        args += ["--reconcile", str(write(tmp_path / f"{env}_reconcile.json", reconcile))]
    args += list(extra)
    code = inv.main(args)
    path = tmp_path / "inv.json"
    return code, (json.loads(path.read_text(encoding="utf-8")) if path.exists() else None)


# --- what it records ---------------------------------------------------------


def test_a_deploy_is_recorded_per_rule_with_its_version(tmp_path):
    code, data = run(tmp_path, "dev", deploy=deploy_report(), extra=["--commit", "abc1234"])

    assert code == 0
    dev = data["environments"]["dev"]["last_deploy"]
    assert dev["commit"] == "abc1234"
    assert dev["rules"]["DETECT-2026-0007"] == {"rule_version": "1.2", "outcome": "updated"}


def test_splunk_state_is_recorded_separately_from_the_deploy(tmp_path):
    """"We sent 27" and "27 are there" are different claims and stay apart."""
    _, data = run(tmp_path, "dev", deploy=deploy_report(), reconcile=reconcile_report())

    dev = data["environments"]["dev"]
    assert dev["last_deploy"]["totals"] == {"updated": 2}
    assert dev["splunk_state"]["in_sync"] == 27
    assert dev["splunk_state"]["has_drift"] is False
    assert dev["splunk_state"]["checked_at"]


def test_a_file_with_no_detect_id_stays_out_of_the_per_rule_map(tmp_path):
    """It failed before its meta could be read; the totals still count it."""
    report = deploy_report(
        rules=[{"detect_id": "", "outcome": "failed"}, {"detect_id": "DETECT-2026-0007", "outcome": "updated"}],
        totals={"updated": 1, "failed": 1},
    )
    _, data = run(tmp_path, "dev", deploy=report)

    dev = data["environments"]["dev"]["last_deploy"]
    assert list(dev["rules"]) == ["DETECT-2026-0007"]
    assert dev["totals"] == {"updated": 1, "failed": 1}


def test_prod_records_its_deploy_from_metadata_alone(tmp_path):
    """The first prod audit run recorded "no deploy recorded" -- this is why.

    Prod deploys are logged by a workflow that cannot commit, so the audit
    learns which commit production runs from the Actions API rather than from a
    report file. The metadata arrived and was silently dropped, leaving the
    inventory blank for an environment that had been deployed all along -- the
    exact blind spot item 4.7 exists to remove.
    """
    _, data = run(
        tmp_path,
        "prod",
        reconcile=reconcile_report(),
        extra=[
            "--commit", "3354100",
            "--run-id", "31270660683",
            "--run-url", "https://github.com/o/r/actions/runs/31270660683",
            "--deployed-at", "2026-08-08T17:56:04Z",
        ],
    )

    last = data["environments"]["prod"]["last_deploy"]
    assert last["commit"] == "3354100"
    assert last["at"] == "2026-08-08T17:56:04Z"
    assert last["run_id"] == "31270660683"


def test_metadata_does_not_wipe_a_report_derived_entry(tmp_path):
    """Updating a timestamp must not cost the per-rule map a report brought."""
    run(tmp_path, "prod", deploy=deploy_report())
    _, data = run(
        tmp_path, "prod", reconcile=reconcile_report(), extra=["--commit", "newsha1"]
    )

    last = data["environments"]["prod"]["last_deploy"]
    assert last["commit"] == "newsha1"
    assert "DETECT-2026-0007" in last["rules"]


def test_a_reconcile_with_no_deploy_metadata_records_no_deploy(tmp_path):
    """The counterpart: absent metadata must not invent an empty deploy entry."""
    _, data = run(tmp_path, "dev", reconcile=reconcile_report())

    assert "last_deploy" not in data["environments"]["dev"]
    assert data["environments"]["dev"]["splunk_state"]["in_sync"] == 27


# --- what it refuses to do ---------------------------------------------------


def test_a_dev_run_never_erases_what_prod_recorded(tmp_path):
    """Each run only knows its own environment. This is the whole merge story."""
    run(tmp_path, "prod", deploy=deploy_report(deployed_at="2026-08-07T19:16:00+00:00"))
    _, data = run(tmp_path, "dev", deploy=deploy_report())

    assert set(data["environments"]) == {"dev", "prod"}
    assert data["environments"]["prod"]["last_deploy"]["at"] == "2026-08-07T19:16:00+00:00"


def test_an_unchanged_run_leaves_the_file_untouched(tmp_path):
    """The objection to committing this file is a commit per run saying nothing."""
    path = tmp_path / "inv.json"
    run(tmp_path, "dev", deploy=deploy_report())
    first = path.read_text(encoding="utf-8")

    run(tmp_path, "dev", deploy=deploy_report())

    assert path.read_text(encoding="utf-8") == first


def test_a_changed_version_does_show_up(tmp_path):
    """The counterpart to the test above: silence must not mean blindness."""
    run(tmp_path, "dev", deploy=deploy_report())
    changed = deploy_report(
        rules=[{"detect_id": "DETECT-2026-0007", "rule_version": "1.3", "outcome": "updated"}]
    )
    _, data = run(tmp_path, "dev", deploy=changed)

    assert data["environments"]["dev"]["last_deploy"]["rules"]["DETECT-2026-0007"]["rule_version"] == "1.3"


def test_unreadable_inputs_leave_the_inventory_alone(tmp_path):
    """An inventory that invents state is worse than one that is out of date."""
    inventory = tmp_path / "inv.json"
    inventory.write_text('{"schema": 1, "environments": {"dev": {"kept": true}}}', encoding="utf-8")

    code = inv.main([
        "--env", "dev",
        "--inventory", str(inventory),
        "--deploy-report", str(tmp_path / "nope.json"),
    ])

    assert code == 1
    assert json.loads(inventory.read_text(encoding="utf-8"))["environments"]["dev"] == {"kept": True}


def test_naming_no_input_at_all_is_a_usage_error(tmp_path):
    with pytest.raises(SystemExit):
        inv.main(["--env", "dev", "--inventory", str(tmp_path / "inv.json")])


def test_a_corrupt_inventory_is_replaced_rather_than_inherited(tmp_path):
    """Losing history is bad; propagating a broken file into the dashboard is worse."""
    inventory = tmp_path / "inv.json"
    inventory.write_text("{not json", encoding="utf-8")

    code, data = run(tmp_path, "dev", deploy=deploy_report())

    assert code == 0
    assert data["environments"]["dev"]["last_deploy"]["rules"]


# --- drift, defined the same way reconcile defines it ------------------------


def test_an_analyst_s_own_saved_search_is_not_drift(tmp_path):
    """`unmanaged` is deliberately not drift -- red for it teaches people to ignore red."""
    _, data = run(tmp_path, "dev", reconcile=reconcile_report({"unmanaged": 3}))

    state = data["environments"]["dev"]["splunk_state"]
    assert state["unmanaged"] == 3
    assert state["has_drift"] is False


def test_a_retired_removal_orphan_is_the_resolved_state_not_drift(tmp_path):
    report = reconcile_report(
        {"orphan_removed": 1},
        orphan_removed=[{"name": "DETECT-2026-0099_Old", "retired": True}],
    )
    _, data = run(tmp_path, "dev", reconcile=report)

    state = data["environments"]["dev"]["splunk_state"]
    assert state["orphan_removed"] == 1
    assert state["orphan_removed_unretired"] == 0
    assert state["has_drift"] is False


def test_an_unretired_removal_orphan_is_drift(tmp_path):
    report = reconcile_report(
        {"orphan_removed": 1},
        orphan_removed=[{"name": "DETECT-2026-0099_Old", "retired": False}],
    )
    _, data = run(tmp_path, "dev", reconcile=report)

    assert data["environments"]["dev"]["splunk_state"]["has_drift"] is True


def test_a_missing_rule_is_drift(tmp_path):
    """The 2026-08-07 case: deleted from Splunk by hand, nothing said so."""
    _, data = run(tmp_path, "dev", reconcile=reconcile_report({"missing": 1, "in_sync": 26}))

    assert data["environments"]["dev"]["splunk_state"]["has_drift"] is True


def test_a_duplicated_name_is_drift(tmp_path):
    """Two objects under one name is the item 3.9 shadow condition."""
    _, data = run(tmp_path, "dev", reconcile=reconcile_report({"duplicate_names": 1}))

    assert data["environments"]["dev"]["splunk_state"]["has_drift"] is True
