"""anonymize_matched_events.py — register item 3.10.

The fixture is a realistic `hits.json` rather than a minimal one, because the
failure mode this tool exists to prevent is *partial* anonymization: the
structured fields get pseudonymized, and the same hostname survives in
`_raw`, in a `C:\\Users\\<account>\\` path, or in a UNC argument on a command
line. So the fixture deliberately spells the same three entities six
different ways -- FQDN, short name, lower case, NetBIOS domain, DNS domain,
machine account -- and the tests assert both halves: that no spelling of a
real value survives anywhere in the output, and that every spelling of one
entity lands on the *same* pseudonym, since that cross-event correlation is
the whole reason the artifact stays worth downloading.
"""

import json
import subprocess
import sys
from pathlib import Path

import anonymize_matched_events as ame
import diff_matched_events as dme
import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify" / "anonymize_matched_events.py"

# The lab naming in here is invented for the fixture -- the real lab's names
# are deliberately nowhere in this repository (see the module docstring on why
# the tool discovers identifiers instead of being configured with them).
HOST_FQDN = "WIN-VICTIM01.delab.local"
HOST_SHORT = "WIN-VICTIM01"
DC_FQDN = "DELAB-DC01.delab.local"
DC_SHORT = "DELAB-DC01"
DOMAIN_NETBIOS = "DELAB"
DOMAIN_DNS = "delab.local"
ACCOUNT = "svc_deploy"

REAL_VALUES = (HOST_FQDN, HOST_SHORT, DC_FQDN, DC_SHORT, DOMAIN_NETBIOS, DOMAIN_DNS, ACCOUNT)


def hits_fixture():
    return {
        "detect_id": "DETECT-2026-0019",
        "title": "LSASS Memory Access by Non-Standard Process",
        "event_count": 3,
        "error": None,
        "testing_enabled": True,
        "events": [
            {
                "_time": "2026-08-15T19:02:11.000+02:00",
                "ComputerName": HOST_FQDN,
                "User": f"{DOMAIN_NETBIOS}\\{ACCOUNT}",
                "SourceImage": f"C:\\Users\\{ACCOUNT}\\AppData\\Local\\Temp\\dump.exe",
                "TargetImage": "C:\\Windows\\system32\\lsass.exe",
                "GrantedAccess": "0x1010",
                "SourceProcessId": "6612",
            },
            {
                "_time": "2026-08-15T19:02:12.000+02:00",
                "ComputerName": HOST_SHORT.lower(),
                "User": "NT AUTHORITY\\SYSTEM",
                "SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "TargetImage": "C:\\Windows\\system32\\lsass.exe",
                "GrantedAccess": "0x1410",
                "SourceProcessId": "6613",
            },
            {
                "_time": "2026-08-15T19:02:19.000+02:00",
                "ComputerName": DC_FQDN,
                "User": f"{DOMAIN_NETBIOS}\\Administrator",
                "SourceImage": f"\\\\{HOST_SHORT}\\tools\\procdump64.exe",
                "TargetImage": "C:\\Windows\\system32\\lsass.exe",
                "GrantedAccess": "0x1fffff",
                "SourceProcessId": "9001",
                "SubjectDomainName": DOMAIN_NETBIOS,
                "TargetUserName": f"{DC_SHORT}$",
                "_raw": (
                    f"<Event><Computer>{DC_FQDN}</Computer>"
                    f"<Data Name='CommandLine'>procdump64.exe -ma lsass.exe "
                    f"\\\\{HOST_SHORT}\\share\\lsass.dmp -c {DC_SHORT}</Data></Event>"
                ),
            },
        ],
    }


def anonymized_fixture(salt=ame.DEFAULT_SALT):
    document = hits_fixture()
    pz = ame.Pseudonymizer(salt)
    pz.discover([document])
    return pz.anonymize(document), pz


# --- the core promise: nothing real survives ---------------------------------


def test_no_spelling_of_any_real_identifier_survives_anywhere():
    anonymized, _ = anonymized_fixture()
    rendered = json.dumps(anonymized)
    for value in REAL_VALUES:
        assert value.casefold() not in rendered.casefold(), f"{value!r} survived anonymization"


def test_raw_is_scrubbed_not_just_the_structured_fields():
    """The finding that makes free-text substitution non-optional.

    `_raw` repeats the hostname, a UNC path and a `-c <host>` argument as
    plain text. Field-level replacement alone would leave every one of them.
    """
    anonymized, _ = anonymized_fixture()
    raw = anonymized["events"][2]["_raw"]
    assert DC_FQDN not in raw
    assert HOST_SHORT not in raw
    assert DC_SHORT not in raw
    # ... and the surrounding log structure is still intact.
    assert raw.startswith("<Event><Computer>ANON_HOST_")
    assert "procdump64.exe -ma lsass.exe" in raw


def test_user_profile_path_is_scrubbed():
    """`C:\\Users\\<account>\\` -- 15 of 28 rules put CurrentDirectory in `fields:`."""
    anonymized, _ = anonymized_fixture()
    source_image = anonymized["events"][0]["SourceImage"]
    assert ACCOUNT not in source_image
    assert source_image.startswith("C:\\Users\\ANON_USER_")
    assert source_image.endswith("\\AppData\\Local\\Temp\\dump.exe")


def test_unc_host_is_scrubbed():
    anonymized, _ = anonymized_fixture()
    assert anonymized["events"][2]["SourceImage"].startswith("\\\\ANON_HOST_")


# --- the other core promise: correlation is preserved ------------------------


def test_same_host_spelled_three_ways_gets_one_pseudonym():
    anonymized, _ = anonymized_fixture()
    from_fqdn = anonymized["events"][0]["ComputerName"].split(".")[0]
    from_short_lowercase = anonymized["events"][1]["ComputerName"]
    from_unc = anonymized["events"][2]["SourceImage"].split("\\")[2]
    assert from_fqdn == from_short_lowercase == from_unc


def test_two_different_hosts_get_two_different_pseudonyms():
    anonymized, _ = anonymized_fixture()
    victim = anonymized["events"][0]["ComputerName"]
    dc = anonymized["events"][2]["ComputerName"]
    assert victim != dc


def test_netbios_and_dns_domain_are_one_entity():
    anonymized, _ = anonymized_fixture()
    from_user_field = anonymized["events"][0]["User"].split("\\")[0]
    from_fqdn_suffix = anonymized["events"][0]["ComputerName"].split(".", 1)[1]
    from_domain_field = anonymized["events"][2]["SubjectDomainName"]
    assert from_user_field == from_fqdn_suffix == from_domain_field


def test_dns_suffix_is_dropped_rather_than_kept():
    """`corp.acme-lab.internal` would leak through a preserved suffix."""
    anonymized, _ = anonymized_fixture()
    assert ".local" not in anonymized["events"][0]["ComputerName"]


def test_machine_account_shares_the_host_pseudonym():
    """`DELAB-DC01$` and `ComputerName=DELAB-DC01` are visibly the same box."""
    anonymized, _ = anonymized_fixture()
    machine_account = anonymized["events"][2]["TargetUserName"]
    dc_host = anonymized["events"][2]["ComputerName"].split(".")[0]
    assert machine_account == f"{dc_host}$"


def test_local_account_qualifier_resolves_to_the_host_not_a_new_domain():
    document = {
        "events": [
            {"ComputerName": "WIN10-BOX", "User": "WIN10-BOX\\localadmin"},
        ]
    }
    pz = ame.Pseudonymizer()
    pz.discover([document])
    out = pz.anonymize(document)["events"][0]
    assert out["User"].split("\\")[0] == out["ComputerName"]
    assert "DOMAIN" not in out["User"]


# --- pseudonym properties ----------------------------------------------------


def test_pseudonyms_are_obviously_fake():
    anonymized, _ = anonymized_fixture()
    host = anonymized["events"][1]["ComputerName"]
    assert host.startswith("ANON_HOST_")
    # An underscore is invalid in a DNS label, so this cannot be mistaken for
    # -- or collide with -- a real hostname.
    assert "_" in host


@pytest.mark.parametrize(
    "kind,prefix",
    [("host", "ANON_HOST_"), ("user", "ANON_USER_"), ("domain", "ANON_DOMAIN_")],
)
def test_each_kind_has_its_own_prefix(kind, prefix):
    pz = ame.Pseudonymizer()
    assert getattr(pz, kind)("something").startswith(prefix)


def test_pseudonyms_are_stable_across_independent_runs():
    """Cross-run stability: a recurring issue stays followable across artifacts."""
    first, _ = anonymized_fixture()
    second, _ = anonymized_fixture()
    assert first == second


def test_a_different_salt_renumbers_everything():
    default_run, _ = anonymized_fixture()
    salted_run, _ = anonymized_fixture(salt="a-repository-secret")
    assert default_run["events"][0]["ComputerName"] != salted_run["events"][0]["ComputerName"]


def test_host_and_user_namespaces_do_not_collide():
    pz = ame.Pseudonymizer()
    assert pz.host("ambiguous") != pz.account("ambiguous")


# --- what must NOT be touched ------------------------------------------------


def test_builtin_principals_are_preserved():
    """Running as SYSTEM is the thing you read off a matched event."""
    anonymized, _ = anonymized_fixture()
    assert anonymized["events"][1]["User"] == "NT AUTHORITY\\SYSTEM"
    assert anonymized["events"][2]["User"].endswith("\\Administrator")


@pytest.mark.parametrize("value", ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "Window Manager\\DWM-1"])
def test_builtin_qualified_accounts_pass_through_verbatim(value):
    pz = ame.Pseudonymizer()
    assert pz.user(value) == value


def test_non_identity_content_is_untouched():
    anonymized, _ = anonymized_fixture()
    event = anonymized["events"][0]
    assert event["TargetImage"] == "C:\\Windows\\system32\\lsass.exe"
    assert event["GrantedAccess"] == "0x1010"
    assert event["_time"] == "2026-08-15T19:02:11.000+02:00"


def test_document_structure_and_non_string_values_survive():
    original = hits_fixture()
    anonymized, _ = anonymized_fixture()
    assert list(anonymized.keys()) == list(original.keys())
    assert len(anonymized["events"]) == len(original["events"])
    assert anonymized["event_count"] == 3
    assert anonymized["error"] is None
    assert anonymized["testing_enabled"] is True
    assert anonymized["detect_id"] == "DETECT-2026-0019"


def test_short_or_numeric_identifiers_are_not_substituted_into_free_text():
    """A two-character hostname in prose would corrupt unrelated content."""
    document = {"events": [{"ComputerName": "PC", "CommandLine": "copy PCX.dll C:\\PC\\out"}]}
    pz = ame.Pseudonymizer()
    pz.discover([document])
    out = pz.anonymize(document)["events"][0]
    # Replaced where the field says what it is ...
    assert out["ComputerName"].startswith("ANON_HOST_")
    # ... and left alone where matching it would be guesswork.
    assert out["CommandLine"] == "copy PCX.dll C:\\PC\\out"


def test_substitution_respects_identifier_boundaries():
    """A host called `dcs` must not be replaced inside `dcsrv` or `mydcs`."""
    document = {
        "events": [{"ComputerName": "dcs", "CommandLine": "dcsrv.exe --peer mydcs --self dcs"}]
    }
    pz = ame.Pseudonymizer()
    pz.discover([document])
    command_line = pz.anonymize(document)["events"][0]["CommandLine"]
    assert command_line.startswith("dcsrv.exe --peer mydcs --self ANON_HOST_")


def test_pseudonyms_are_not_re_matched_on_a_second_pass():
    """Idempotence: anonymizing an already-anonymized document is a no-op."""
    once, _ = anonymized_fixture()
    pz = ame.Pseudonymizer()
    pz.discover([once])
    assert pz.anonymize(once) == once


# --- discovery order ---------------------------------------------------------


def test_an_entity_seen_late_is_scrubbed_from_an_earlier_event():
    """Discovery runs over every document before the first rewrite."""
    document = {
        "events": [
            {"CommandLine": "psexec \\\\LATEHOST\\admin$ -u lateuser"},
            {"ComputerName": "LATEHOST", "User": "DOM\\lateuser"},
        ]
    }
    pz = ame.Pseudonymizer()
    pz.discover([document])
    out = pz.anonymize(document)
    assert "LATEHOST" not in out["events"][0]["CommandLine"]
    assert "lateuser" not in out["events"][0]["CommandLine"]


def test_a_host_known_only_from_a_unc_path_still_resolves_a_local_account_qualifier():
    """Pins the discovery sweep order: UNC hosts are registered before user fields.

    `WKS7` appears nowhere as a host *field* -- only inside a command line --
    so if free text were swept after user fields, `WKS7\\bob` would mint a
    DOMAIN pseudonym and the same machine would end up with two identities.
    """
    document = {
        "events": [
            {"CommandLine": "psexec \\\\WKS7\\admin$ -s cmd.exe"},
            {"User": "WKS7\\bob"},
        ]
    }
    pz = ame.Pseudonymizer()
    pz.discover([document])
    out = pz.anonymize(document)
    from_unc = out["events"][0]["CommandLine"].split("\\")[2]
    from_user = out["events"][1]["User"].split("\\")[0]
    assert from_unc.startswith("ANON_HOST_")
    assert from_user == from_unc


def test_entities_are_shared_across_separate_files():
    a = {"events": [{"ComputerName": "SHAREDBOX"}]}
    b = {"events": [{"CommandLine": "ping SHAREDBOX"}]}
    pz = ame.Pseudonymizer()
    pz.discover([a, b])
    host = pz.anonymize(a)["events"][0]["ComputerName"]
    assert pz.anonymize(b)["events"][0]["CommandLine"] == f"ping {host}"


# --- does not break the 3.11 tool -------------------------------------------


def test_diff_matched_events_finds_the_same_splits_after_anonymization():
    """Item 3.11's tool is the main consumer of this artifact; it must still work."""
    original = hits_fixture()
    anonymized, _ = anonymized_fixture()

    before = dme.find_splitting_fields(original["events"])
    after = dme.find_splitting_fields(anonymized["events"])

    assert [s["field"] for s in before] == [s["field"] for s in after]
    assert [s["minority_total"] for s in before] == [s["minority_total"] for s in after]
    assert [m["event_indices"] for s in before for m in s["minority"]] == [
        m["event_indices"] for s in after for m in s["minority"]
    ]


def test_a_host_that_splits_the_event_set_still_splits_it_afterwards():
    events = [{"ComputerName": "DC01"} for _ in range(10)]
    events.append({"ComputerName": "victim02"})
    document = {"events": events}
    pz = ame.Pseudonymizer()
    pz.discover([document])
    split = dme.find_splitting_fields(pz.anonymize(document)["events"])[0]
    assert split["field"] == "ComputerName"
    assert split["majority_count"] == 10
    assert split["minority"][0]["event_indices"] == [10]


# --- self-check --------------------------------------------------------------


def test_residue_reports_a_leaked_identifier():
    _, pz = anonymized_fixture()
    assert pz.residue("nothing to see") == []
    assert pz.residue(f"leaked {HOST_SHORT} here") == [HOST_SHORT]


# --- CLI ---------------------------------------------------------------------


def run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, cwd=cwd,
    )


def write_tree(tmp_path):
    source = tmp_path / "raw"
    (source / "DETECT-2026-0019").mkdir(parents=True)
    (source / "DETECT-2026-0019" / "hits.json").write_text(
        json.dumps(hits_fixture()), encoding="utf-8"
    )
    return source


def test_cli_mirrors_the_input_tree(tmp_path):
    source = write_tree(tmp_path)
    out = tmp_path / "anon"
    result = run_cli("--output-dir", str(out), str(source))
    assert result.returncode == 0, result.stderr
    written = out / "DETECT-2026-0019" / "hits.json"
    assert written.is_file()
    assert HOST_SHORT not in written.read_text(encoding="utf-8")
    # The source is left as it was -- pass_fail_eval.py already read it.
    assert HOST_SHORT in (source / "DETECT-2026-0019" / "hits.json").read_text(encoding="utf-8")


def test_cli_in_place(tmp_path):
    source = write_tree(tmp_path)
    result = run_cli("--in-place", str(source))
    assert result.returncode == 0, result.stderr
    assert HOST_SHORT not in (source / "DETECT-2026-0019" / "hits.json").read_text(encoding="utf-8")


def test_cli_summary_leaks_no_original_value(tmp_path):
    source = write_tree(tmp_path)
    result = run_cli("--output-dir", str(tmp_path / "anon"), str(source))
    combined = result.stdout + result.stderr
    for value in REAL_VALUES:
        assert value not in combined
    assert "1 file(s)" in result.stdout


def test_cli_quiet(tmp_path):
    source = write_tree(tmp_path)
    result = run_cli("--quiet", "--output-dir", str(tmp_path / "anon"), str(source))
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_cli_map_out_refuses_to_write_inside_the_input(tmp_path):
    source = write_tree(tmp_path)
    result = run_cli(
        "--in-place", "--map-out", str(source / "map.json"), str(source)
    )
    assert result.returncode == 2
    assert "de-anonymization key" in result.stderr
    assert not (source / "map.json").exists()


def test_cli_map_out_refuses_to_write_inside_the_output(tmp_path):
    source = write_tree(tmp_path)
    out = tmp_path / "anon"
    result = run_cli(
        "--output-dir", str(out), "--map-out", str(out / "map.json"), str(source)
    )
    assert result.returncode == 2
    assert not (out / "map.json").exists()


def test_cli_map_out_writes_outside(tmp_path):
    source = write_tree(tmp_path)
    map_path = tmp_path / "map.json"
    result = run_cli(
        "--output-dir", str(tmp_path / "anon"), "--map-out", str(map_path), str(source)
    )
    assert result.returncode == 0, result.stderr
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    kinds = {e["kind"] for e in mapping["entities"]}
    assert kinds == {"HOST", "USER", "DOMAIN"}
    assert any(HOST_SHORT in e["seen_as"] for e in mapping["entities"])


def test_cli_fails_closed_on_unparseable_json(tmp_path):
    source = tmp_path / "raw"
    source.mkdir()
    (source / "hits.json").write_text("{not json", encoding="utf-8")
    out = tmp_path / "anon"
    result = run_cli("--output-dir", str(out), str(source))
    assert result.returncode == 2
    assert "not valid JSON" in result.stderr
    # Nothing written means the upload step has nothing to upload.
    assert not out.exists()


def test_cli_fails_on_missing_input(tmp_path):
    result = run_cli("--output-dir", str(tmp_path / "anon"), str(tmp_path / "nope"))
    assert result.returncode == 2
    assert "does not exist" in result.stderr


def test_cli_requires_a_destination(tmp_path):
    source = write_tree(tmp_path)
    result = run_cli(str(source))
    assert result.returncode == 2


def test_cli_salt_comes_from_the_environment(tmp_path, monkeypatch):
    source = write_tree(tmp_path)
    baseline = run_cli("--output-dir", str(tmp_path / "a"), str(source))
    salted = subprocess.run(
        [sys.executable, str(SCRIPT), "--output-dir", str(tmp_path / "b"), str(source)],
        capture_output=True, text=True,
        env={**dict(__import__("os").environ), ame.SALT_ENV_VAR: "secret-salt"},
    )
    assert baseline.returncode == 0 and salted.returncode == 0
    a = (tmp_path / "a" / "DETECT-2026-0019" / "hits.json").read_text(encoding="utf-8")
    b = (tmp_path / "b" / "DETECT-2026-0019" / "hits.json").read_text(encoding="utf-8")
    assert a != b
    assert HOST_SHORT not in a and HOST_SHORT not in b
