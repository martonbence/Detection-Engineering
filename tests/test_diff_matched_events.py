"""diff_matched_events.py — register item 3.11.

A synthetic fixture built around the register item's own example: 10 events
share host=DC01, 1 has host=victim02. That is the "11 instead of 10" case
history.jsonl showed for DETECT-2026-0019 -- these tests pin down that the
tool actually surfaces the field the count discrepancy hinges on, ranks it
first when more than one field disagrees, and stays quiet on fields that
carry no such signal (constant fields, fields where every event disagrees,
Splunk bookkeeping fields).
"""

import json

import diff_matched_events as dme
import pytest


def make_event(i, *, host="DC01", user="svc_backup", event_code="4688", extra=None):
    event = {
        "_time": f"2026-08-15T10:00:0{i}.000+00:00",
        "_raw": f"raw event body {i}",
        "_cd": f"1:{i}",
        "host": host,
        "user": user,
        "EventCode": event_code,
        "linecount": "1",
        "session_id": f"sess-{i}",  # unique per event on purpose
    }
    if extra:
        event.update(extra)
    return event


def outlier_fixture():
    """10 events on DC01/svc_backup, 1 outlier on victim02/attacker."""
    events = [make_event(i) for i in range(10)]
    events.append(make_event(10, host="victim02", user="attacker"))
    return events


# --- find_splitting_fields ---------------------------------------------------


def test_surfaces_the_minority_host_value():
    splits = dme.find_splitting_fields(outlier_fixture())
    by_field = {s["field"]: s for s in splits}

    assert "host" in by_field
    host_split = by_field["host"]
    assert host_split["majority_value"] == "DC01"
    assert host_split["majority_count"] == 10
    assert host_split["minority_total"] == 1
    assert host_split["minority"][0]["value"] == "victim02"
    assert host_split["minority"][0]["event_indices"] == [10]


def test_multiple_splitting_fields_are_ranked_smallest_minority_first():
    events = [make_event(i) for i in range(10)]
    # host has 1 outlier; EventCode has 3 -- host must rank first.
    events.append(make_event(10, host="victim02"))
    events.append(make_event(11, event_code="4624"))
    events.append(make_event(12, event_code="4624"))
    events.append(make_event(13, event_code="4624"))

    splits = dme.find_splitting_fields(events)
    fields_in_order = [s["field"] for s in splits]

    assert fields_in_order.index("host") < fields_in_order.index("EventCode")


def test_constant_field_is_not_reported():
    splits = dme.find_splitting_fields(outlier_fixture())
    # host and user vary; EventCode is "4688" on every event including the
    # outlier, so it must not show up as a split.
    assert "EventCode" not in {s["field"] for s in splits}


def test_field_where_every_event_disagrees_is_not_reported():
    # session_id is unique per event -- no majority value exists at all, so
    # it carries no split signal and would just be noise if reported.
    splits = dme.find_splitting_fields(outlier_fixture())
    assert "session_id" not in {s["field"] for s in splits}


def test_tied_split_has_no_strict_majority():
    events = [make_event(i, host="A") for i in range(5)] + [
        make_event(i, host="B") for i in range(5, 10)
    ]
    splits = dme.find_splitting_fields(events)
    assert "host" not in {s["field"] for s in splits}


def test_underscore_fields_excluded_by_default():
    splits = dme.find_splitting_fields(outlier_fixture())
    assert not any(s["field"].startswith("_") for s in splits)


def test_underscore_field_can_be_opted_back_in():
    # _time differs between make_event(0) (9x) and make_event(1) (1x) only in
    # the seconds digit, so it splits 9-1 once _time is opted back in.
    events = [make_event(0) for _ in range(9)] + [make_event(1)]
    splits = dme.find_splitting_fields(
        events, exclude_underscore=True, include_fields=frozenset({"_time"})
    )
    assert "_time" in {s["field"] for s in splits}


def test_default_metadata_fields_excluded():
    splits = dme.find_splitting_fields(outlier_fixture())
    assert "linecount" not in {s["field"] for s in splits}


def test_all_fields_flag_equivalent_disables_default_excludes():
    events = [make_event(i, extra={"linecount": "1"}) for i in range(10)]
    events.append(make_event(10, extra={"linecount": "2"}))

    splits_default = dme.find_splitting_fields(events)
    assert "linecount" not in {s["field"] for s in splits_default}

    splits_all = dme.find_splitting_fields(events, exclude_fields=frozenset(), exclude_underscore=False)
    assert "linecount" in {s["field"] for s in splits_all}


def test_missing_field_counts_as_a_value():
    events = [make_event(i) for i in range(10)]
    outlier = make_event(10)
    del outlier["user"]
    events.append(outlier)

    splits = dme.find_splitting_fields(events)
    by_field = {s["field"]: s for s in splits}
    assert by_field["user"]["minority"][0]["value"] == dme.MISSING
    assert by_field["user"]["minority"][0]["event_indices"] == [10]


def test_fewer_than_two_events_returns_nothing():
    assert dme.find_splitting_fields([make_event(0)]) == []
    assert dme.find_splitting_fields([]) == []


def test_multivalue_field_is_hashable():
    events = [make_event(i, extra={"tags": ["a", "b"]}) for i in range(10)]
    events.append(make_event(10, extra={"tags": ["c"]}))
    splits = dme.find_splitting_fields(events)
    by_field = {s["field"]: s for s in splits}
    assert by_field["tags"]["majority_value"] == ("a", "b")
    assert by_field["tags"]["minority"][0]["value"] == ("c",)


# --- load_events --------------------------------------------------------------


def test_load_events_from_hits_json_wrapper(tmp_path):
    path = tmp_path / "hits.json"
    path.write_text(
        json.dumps({"detect_id": "DETECT-2026-0019", "title": "T", "events": outlier_fixture()}),
        encoding="utf-8",
    )
    events, context = dme.load_events(path)
    assert len(events) == 11
    assert context["detect_id"] == "DETECT-2026-0019"


def test_load_events_from_bare_list(tmp_path):
    path = tmp_path / "events.json"
    path.write_text(json.dumps(outlier_fixture()), encoding="utf-8")
    events, context = dme.load_events(path)
    assert len(events) == 11
    assert context == {}


def test_load_events_missing_file_raises(tmp_path):
    with pytest.raises(ValueError, match="could not read"):
        dme.load_events(tmp_path / "nope.json")


def test_load_events_bad_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        dme.load_events(path)


def test_load_events_wrong_shape_raises(tmp_path):
    path = tmp_path / "wrong.json"
    path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    with pytest.raises(ValueError, match="neither a hits"):
        dme.load_events(path)


# --- main() end to end ---------------------------------------------------------


def test_main_reports_the_outlier_field(tmp_path, capsys):
    path = tmp_path / "hits.json"
    path.write_text(
        json.dumps({"detect_id": "DETECT-2026-0019", "events": outlier_fixture()}),
        encoding="utf-8",
    )
    exit_code = dme.main([str(path)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "host" in out
    assert "victim02" in out
    assert "DC01" in out


def test_main_json_output_is_parseable(tmp_path, capsys):
    path = tmp_path / "hits.json"
    path.write_text(json.dumps({"events": outlier_fixture()}), encoding="utf-8")
    exit_code = dme.main([str(path), "--json"])
    out = capsys.readouterr().out

    assert exit_code == 0
    payload = json.loads(out)
    fields = {s["field"] for s in payload["splits"]}
    assert "host" in fields


def test_main_exit_code_2_on_missing_file(tmp_path, capsys):
    exit_code = dme.main([str(tmp_path / "nope.json")])
    err = capsys.readouterr().err
    assert exit_code == 2
    assert "ERROR" in err


def test_main_top_limits_output(tmp_path, capsys):
    events = [make_event(i) for i in range(10)]
    events.append(make_event(10, host="victim02"))
    events.append(make_event(11, event_code="4624"))
    events.append(make_event(12, event_code="4624"))
    events.append(make_event(13, event_code="4624"))
    path = tmp_path / "events.json"
    path.write_text(json.dumps(events), encoding="utf-8")

    exit_code = dme.main([str(path), "--top", "1"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "host" in out
    assert "more splitting field" in out


def test_main_no_splits_message(tmp_path, capsys):
    events = [make_event(i) for i in range(5)]
    path = tmp_path / "events.json"
    path.write_text(json.dumps(events), encoding="utf-8")

    exit_code = dme.main([str(path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "No field has a strict-majority" in out
