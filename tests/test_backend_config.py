"""Declarative backend selection in the converter (register item 3.7).

Three things are worth holding still here, in descending order of importance:

1. The committed config still says exactly what the code used to hardcode.
   That is the only guard against this refactor -- or a later edit to a YAML
   file that looks harmless -- changing what lands in rules/splunk/.
2. A second backend is reachable without touching sigma_to_spl.py.
3. A missing or malformed config stops the run instead of converting with
   something plausible. The failure mode being bought off is not a crash, it
   is a green run that deployed SPL nobody chose the pipeline for.
"""

import subprocess
import sys
from pathlib import Path

import pytest
import sigma_to_spl
from backend_config import DEFAULT_CONFIG_PATH, BackendConfigError, load_backend

REPO_ROOT = Path(__file__).resolve().parent.parent


def write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "backends.yml"
    path.write_text(body, encoding="utf-8")
    return path


VALID = """
default_backend: splunk
backends:
  splunk:
    target: splunk
    pipeline_override_key: splunk_pipeline
    pipelines:
      by_service:
        sysmon: splunk_sysmon_acceleration
        security: splunk_windows
      default: ""
"""


# --- 1. the committed config is the old hardcoded behaviour -------------------


def test_default_config_path_points_at_the_committed_file():
    assert DEFAULT_CONFIG_PATH == REPO_ROOT / "config" / "backends.yml"
    assert DEFAULT_CONFIG_PATH.is_file()


def test_committed_config_reproduces_the_constants_it_replaced():
    """sigma_to_spl.py:14-15 and 41-47 before item 3.7, character for character."""
    backend = load_backend()

    assert backend.name == "splunk"
    assert backend.target == "splunk"
    assert backend.pipeline_for_service("sysmon") == "splunk_sysmon_acceleration"
    assert backend.pipeline_for_service("security") == "splunk_windows"
    assert backend.default_pipeline == ""
    assert backend.pipeline_override_key == "splunk_pipeline"


@pytest.mark.parametrize(
    ("service", "expected"),
    [
        ("sysmon", "splunk_sysmon_acceleration"),
        ("security", "splunk_windows"),
        ("Sysmon", "splunk_sysmon_acceleration"),
        ("  SECURITY  ", "splunk_windows"),
        ("application", ""),
        ("", ""),
    ],
)
def test_pipeline_routing_matches_the_old_if_chain(service, expected):
    assert load_backend().pipeline_for_service(service) == expected


@pytest.mark.parametrize(
    ("rule", "expected"),
    [
        ({"logsource": {"service": "sysmon"}}, "splunk_sysmon_acceleration"),
        ({"logsource": {"service": "security"}}, "splunk_windows"),
        ({"logsource": {"service": "powershell"}}, ""),
        ({"logsource": {}}, ""),
        ({}, ""),
        ({"logsource": {"service": None}}, ""),
    ],
)
def test_pick_pipeline_on_rule_shapes(rule, expected):
    assert sigma_to_spl.pick_pipeline(rule, load_backend()) == expected


def test_rule_level_override_still_wins_over_the_service_mapping():
    rule = {"logsource": {"service": "sysmon"}, "custom": {"splunk_pipeline": "  custom_pipeline  "}}

    assert sigma_to_spl.pick_pipeline(rule, load_backend()) == "custom_pipeline"


def test_backend_without_an_override_key_ignores_the_rule_field(tmp_path):
    """Omitting the key is a statement that this backend has no per-rule override."""
    config = write_config(
        tmp_path,
        """
default_backend: esql
backends:
  esql:
    target: esql
    pipelines:
      by_service: {}
      default: ecs_windows
""",
    )
    rule = {"logsource": {"service": "sysmon"}, "custom": {"splunk_pipeline": "splunk_windows"}}

    assert sigma_to_spl.pick_pipeline(rule, load_backend(config_path=config)) == "ecs_windows"


# --- 2. a second backend is a config change, not a code change ---------------


TWO_BACKENDS = """
default_backend: splunk
backends:
  splunk:
    target: splunk
    pipeline_override_key: splunk_pipeline
    pipelines:
      by_service:
        sysmon: splunk_sysmon_acceleration
      default: ""
  elastic:
    target: esql
    pipeline_override_key: elastic_pipeline
    pipelines:
      by_service:
        sysmon: ecs_windows_sysmon
      default: ecs_windows
"""


def test_second_backend_is_selectable_by_name(tmp_path):
    config = write_config(tmp_path, TWO_BACKENDS)

    elastic = load_backend("elastic", config_path=config)

    assert elastic.target == "esql"
    assert elastic.pipeline_for_service("sysmon") == "ecs_windows_sysmon"
    assert elastic.pipeline_for_service("application") == "ecs_windows"


def test_default_backend_decides_when_no_name_is_given(tmp_path):
    config = write_config(tmp_path, TWO_BACKENDS)

    assert load_backend(config_path=config).name == "splunk"
    assert load_backend("  ", config_path=config).name == "splunk"


def test_second_backend_reaches_the_sigma_command_line(tmp_path, monkeypatch):
    config = write_config(tmp_path, TWO_BACKENDS)
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: seen.append(cmd))

    sigma_to_spl.run_sigma_convert(
        Path("rules/sigma/r.yml"), Path("out/r.spl"), "ecs_windows", load_backend("elastic", config_path=config)
    )

    assert seen[0][:6] == ["sigma", "convert", "-t", "esql", "-p", "ecs_windows"]


def test_empty_pipeline_still_converts_without_pipeline(tmp_path, monkeypatch):
    """The Splunk default. The flag, not an omitted -p, which would pick a default pipeline."""
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: seen.append(cmd))

    sigma_to_spl.run_sigma_convert(Path("rules/sigma/r.yml"), Path("out/r.spl"), "", load_backend())

    assert seen[0][:5] == ["sigma", "convert", "-t", "splunk", "--without-pipeline"]


# --- 3. broken config fails loudly -------------------------------------------


def test_missing_file_is_reported_as_missing(tmp_path):
    with pytest.raises(BackendConfigError, match="not found"):
        load_backend(config_path=tmp_path / "nope.yml")


def test_unreadable_file_is_not_reported_as_missing(tmp_path):
    """A quarantined or permission-denied file sends you looking for the wrong thing."""
    unreadable = tmp_path / "adirectory.yml"
    unreadable.mkdir()

    with pytest.raises(BackendConfigError, match="could not be read"):
        load_backend(config_path=unreadable)


def test_invalid_yaml_fails(tmp_path):
    with pytest.raises(BackendConfigError, match="not valid YAML"):
        load_backend(config_path=write_config(tmp_path, "default_backend: [unclosed\n"))


def test_empty_file_fails(tmp_path):
    with pytest.raises(BackendConfigError, match="is empty"):
        load_backend(config_path=write_config(tmp_path, "# only a comment\n"))


def test_top_level_scalar_fails(tmp_path):
    with pytest.raises(BackendConfigError, match="expected a mapping"):
        load_backend(config_path=write_config(tmp_path, "splunk\n"))


def test_unknown_top_level_key_fails(tmp_path):
    with pytest.raises(BackendConfigError, match="unknown key"):
        load_backend(config_path=write_config(tmp_path, VALID + "\ndefault_target: splunk\n"))


def test_missing_backends_block_fails(tmp_path):
    with pytest.raises(BackendConfigError, match="expected a mapping"):
        load_backend(config_path=write_config(tmp_path, "default_backend: splunk\n"))


def test_empty_backends_block_fails(tmp_path):
    with pytest.raises(BackendConfigError, match="must not be empty"):
        load_backend(config_path=write_config(tmp_path, "default_backend: splunk\nbackends: {}\n"))


def test_unknown_backend_name_lists_the_configured_ones(tmp_path):
    config = write_config(tmp_path, TWO_BACKENDS)

    with pytest.raises(BackendConfigError, match="unknown backend 'qradar'") as exc:
        load_backend("qradar", config_path=config)

    assert "elastic, splunk" in str(exc.value)
    assert "--backend" in str(exc.value)


def test_default_backend_pointing_at_nothing_fails(tmp_path):
    config = write_config(tmp_path, TWO_BACKENDS.replace("default_backend: splunk", "default_backend: qradar"))

    with pytest.raises(BackendConfigError, match="from default_backend"):
        load_backend(config_path=config)


def test_absent_default_backend_fails_rather_than_picking_the_first(tmp_path):
    config = write_config(tmp_path, TWO_BACKENDS.replace("default_backend: splunk\n", ""))

    with pytest.raises(BackendConfigError, match="no backend requested"):
        load_backend(config_path=config)


def test_backend_entry_must_be_a_mapping(tmp_path):
    with pytest.raises(BackendConfigError, match="expected a mapping"):
        load_backend(config_path=write_config(tmp_path, "default_backend: splunk\nbackends:\n  splunk: splunk\n"))


def test_unknown_key_inside_a_backend_fails(tmp_path):
    """`pipeline:` for `pipelines:` would otherwise read as "no routing at all"."""
    with pytest.raises(BackendConfigError, match="unknown key"):
        load_backend(config_path=write_config(tmp_path, VALID.replace("    pipelines:", "    pipeline:")))


def test_missing_target_fails(tmp_path):
    with pytest.raises(BackendConfigError, match="'target' is required"):
        load_backend(config_path=write_config(tmp_path, VALID.replace("    target: splunk\n", "")))


def test_empty_target_fails(tmp_path):
    with pytest.raises(BackendConfigError, match="'target' is required"):
        load_backend(config_path=write_config(tmp_path, VALID.replace("target: splunk", 'target: "   "')))


def test_non_string_target_fails(tmp_path):
    with pytest.raises(BackendConfigError, match="expected a string"):
        load_backend(config_path=write_config(tmp_path, VALID.replace("target: splunk", "target: [splunk]")))


def test_missing_pipelines_block_fails(tmp_path):
    body = """
default_backend: splunk
backends:
  splunk:
    target: splunk
"""
    with pytest.raises(BackendConfigError, match="missing required key 'pipelines'"):
        load_backend(config_path=write_config(tmp_path, body))


def test_missing_pipeline_default_fails(tmp_path):
    """"No pipeline" has to be written down; an absent key looks like an oversight."""
    with pytest.raises(BackendConfigError, match="missing required key 'default'"):
        load_backend(config_path=write_config(tmp_path, VALID.replace('      default: ""', "")))


def test_misspelled_by_service_is_caught_instead_of_routing_everything_to_default(tmp_path):
    """The silent one: valid YAML, no error, every rule converted without a pipeline."""
    with pytest.raises(BackendConfigError, match="unknown key"):
        load_backend(config_path=write_config(tmp_path, VALID.replace("by_service:", "by_services:")))


def test_by_service_must_be_a_mapping(tmp_path):
    body = VALID.replace(
        "      by_service:\n        sysmon: splunk_sysmon_acceleration\n        security: splunk_windows\n",
        "      by_service: [sysmon, security]\n",
    )

    with pytest.raises(BackendConfigError, match="expected a mapping"):
        load_backend(config_path=write_config(tmp_path, body))


def test_non_string_service_name_fails(tmp_path):
    with pytest.raises(BackendConfigError, match="service names must be non-empty strings"):
        load_backend(config_path=write_config(tmp_path, VALID.replace("        sysmon:", "        1234:")))


def test_case_folded_duplicate_service_fails(tmp_path):
    body = VALID.replace("        security: splunk_windows", "        Sysmon: splunk_windows")

    with pytest.raises(BackendConfigError, match="duplicate service 'sysmon'"):
        load_backend(config_path=write_config(tmp_path, body))


def test_non_string_pipeline_value_fails(tmp_path):
    body = VALID.replace("sysmon: splunk_sysmon_acceleration", "sysmon: 42")

    with pytest.raises(BackendConfigError, match="expected a string"):
        load_backend(config_path=write_config(tmp_path, body))


# --- main(): the config is resolved before anything is written ---------------


def test_main_exits_2_and_converts_nothing_when_the_config_is_broken(tmp_path, monkeypatch, capsys):
    """Exit 2 = the converter could not set itself up, as in validate_sigma.py."""
    broken = write_config(tmp_path, "backends: {}\n")
    outdir = tmp_path / "out"
    rule = tmp_path / "rule.yml"
    rule.write_text("title: t\nlogsource:\n  service: sysmon\n", encoding="utf-8")

    def explode(*args, **kwargs):
        raise AssertionError("sigma convert must not run without a resolved backend")

    monkeypatch.setattr(subprocess, "run", explode)
    monkeypatch.setattr(
        sys, "argv", ["sigma_to_spl.py", "--outdir", str(outdir), "--backends-config", str(broken), str(rule)]
    )

    assert sigma_to_spl.main() == 2
    assert "ERROR" in capsys.readouterr().err
    assert not outdir.exists()


def test_main_exits_2_on_an_unknown_backend_name(tmp_path, monkeypatch, capsys):
    outdir = tmp_path / "out"
    rule = tmp_path / "rule.yml"
    rule.write_text("title: t\n", encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["sigma_to_spl.py", "--outdir", str(outdir), "--backend", "qradar", str(rule)]
    )

    assert sigma_to_spl.main() == 2
    assert "unknown backend 'qradar'" in capsys.readouterr().err
