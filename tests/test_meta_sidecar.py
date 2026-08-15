"""Locating and parsing the .meta.json sidecar, and the policies that did not merge.

Register item 3.6. Three Python callers each located the sidecar next to its
`.spl` and parsed it themselves, and each answers a missing or malformed
sidecar differently, on purpose: the deploy treats it as a setup failure, the
hit check treats it as an unmeasured rule, the indexing wait treats it as one
file to skip among possibly many. Only the part all three did identically --
finding the path, reading it, parsing it -- moved into lib/meta_sidecar.py.
This file is shaped like test_lib_env.py for the same reason: most of it
exists to prove the three separate policies survived being wired through one
reader.
"""

import json

import check_saved_search_hits
import deploy_spl_to_splunk as deploy
import pytest
import wait_for_indexing
from lib.meta_sidecar import meta_sidecar_path, read_meta_sidecar

RULE_NAME = "DETECT-2026-0001_Alpha"


def _spl(tmp_path):
    return tmp_path / f"{RULE_NAME}.spl"


def _write_sidecar(tmp_path, text):
    (tmp_path / f"{RULE_NAME}.meta.json").write_text(text, encoding="utf-8")


# --- the part that really was duplicated --------------------------------------


def test_every_consumer_now_shares_one_reader():
    shared = read_meta_sidecar
    for module in (deploy, check_saved_search_hits, wait_for_indexing):
        assert module.read_meta_sidecar is shared, (
            f"{module.__name__} reads its own sidecar again -- item 3.6 removed three copies of this"
        )


def test_sidecar_path_sits_next_to_the_spl(tmp_path):
    assert meta_sidecar_path(_spl(tmp_path)) == tmp_path / f"{RULE_NAME}.meta.json"


def test_reads_a_valid_sidecar(tmp_path):
    _write_sidecar(tmp_path, json.dumps({"index": "sysmon"}))
    assert read_meta_sidecar(_spl(tmp_path)) == {"index": "sysmon"}


def test_missing_sidecar_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_meta_sidecar(_spl(tmp_path))


def test_malformed_sidecar_raises_json_decode_error(tmp_path):
    _write_sidecar(tmp_path, "{not json")
    with pytest.raises(json.JSONDecodeError):
        read_meta_sidecar(_spl(tmp_path))


# --- the policies that stayed with the callers --------------------------------


def test_deploy_dies_on_a_missing_sidecar(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        deploy.extract_meta(_spl(tmp_path))
    assert excinfo.value.code == 1


def test_deploy_dies_on_a_malformed_sidecar(tmp_path):
    _write_sidecar(tmp_path, "{not json")
    with pytest.raises(SystemExit) as excinfo:
        deploy.extract_meta(_spl(tmp_path))
    assert excinfo.value.code == 1


def test_hit_check_returns_empty_on_a_missing_sidecar(tmp_path):
    """Unmeasured, not broken -- a missing sidecar should not stop the run."""
    assert check_saved_search_hits.extract_meta(_spl(tmp_path)) == {}


def test_hit_check_returns_empty_on_a_malformed_sidecar(tmp_path):
    _write_sidecar(tmp_path, "{not json")
    assert check_saved_search_hits.extract_meta(_spl(tmp_path)) == {}


def test_indexing_wait_skips_a_missing_sidecar(tmp_path):
    assert wait_for_indexing.indexes_from_meta([str(_spl(tmp_path))]) == []


def test_indexing_wait_skips_a_malformed_sidecar(tmp_path):
    _write_sidecar(tmp_path, "{not json")
    assert wait_for_indexing.indexes_from_meta([str(_spl(tmp_path))]) == []


def test_indexing_wait_picks_up_the_index_field(tmp_path):
    _write_sidecar(tmp_path, json.dumps({"index": "sysmon"}))
    assert wait_for_indexing.indexes_from_meta([str(_spl(tmp_path))]) == ["sysmon"]
