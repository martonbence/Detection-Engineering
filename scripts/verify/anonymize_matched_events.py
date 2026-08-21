"""anonymize_matched_events.py — Pseudonymize lab identifiers in matched-event JSON.

Register item 3.10. The old remediation-plan item 2.16 looked at the
`matched-events-sigma-<run_id>` artifact -- publicly downloadable, because
this is a public repository -- and chose shorter retention (90 -> 14 days)
over field stripping. That reasoning holds: the raw event *is* the debugging
value, and a stripped artifact is an artifact nobody opens. But 2.16's own
text names what stayed exposed: the lab's naming -- hostnames, domain,
service accounts -- which has reconnaissance value to the extent the lab
mirrors production. This is the missing piece: run between the verify step
and the upload step, it rewrites those identifiers to stable, per-entity
pseudonyms, so the artifact keeps every property a debugger needs (which
events came from the same box, the same account, the same domain) and loses
the property an outsider wants (what that box is actually called).

Why the identifiers are DISCOVERED rather than configured
---------------------------------------------------------
The obvious design -- a config file listing the lab's real hostnames and
domain, substituted on sight -- is self-defeating here: that file would
commit the lab's naming to the public repository, which is the exact thing
this tool exists to keep out of it. So nothing in this module knows, or ever
learns from the repo, what the lab is called. It reads the values out of the
event fields that carry identity by construction (`ComputerName`, `User`,
`host`, the domain fields, ...), treats each distinct value as an entity,
and mints a pseudonym for it. That is also why it keeps working when the lab
is renamed, or a second victim host appears, with no change here.

Free text is the other half, and it is not optional
---------------------------------------------------
Pseudonymizing the structured fields alone would be theater, and measurably
so on this repo's own data: 15 of 28 rules put `CurrentDirectory` in their
`fields:` list, and on Windows that value is `C:\\Users\\<account>\\...` --
the account name, in free text, in a field no field-level rule would touch.
`CommandLine` / `ParentCommandLine` (26 and 24 rules) are worse, since they
can carry a hostname, a UNC path or a user profile path as an argument.
So every discovered identifier is *also* substituted wherever it appears
inside any other string in the document, and three structural patterns
(`X:\\Users\\<name>\\`, `/home/<name>/`, `\\\\<host>\\share`) mint entities
the identity fields never mentioned.

The substitution is a single pass over one alternation of all known
identifiers, longest first, with a boundary rule (`[A-Za-z0-9_-]` on neither
side) -- not a chain of `str.replace()` calls. That matters: a chain can
rewrite the output of an earlier replacement, and a bare `replace()` turns a
host called `dc` into a pseudonym inside the word "dcom". Values shorter
than MIN_SUBSTITUTABLE_LEN, or with no letter in them, are excluded from the
free-text pass entirely (they are still replaced in their own identity
field, where there is no ambiguity) -- a hostname that is two characters or
all digits cannot be matched in prose without corrupting unrelated content.
Where the two directions conflict this over-redacts rather than under-
redacts: a host genuinely named `server` will also be pseudonymized inside a
path that merely contains the word.

About `_raw`
------------
No rule in this repo currently returns `_raw`. Every generated `.spl` ends
with `| table <fields>` (all 28, checked), and no rule lists `_raw` among
its `fields:`, so the events that reach `hits.json` are already restricted
to the named columns. That is a convention, not an invariant: a
`custom.splunk.raw_query` rule's SPL is emitted verbatim and bypasses the
`fields:` key entirely, so one written without a `| table` returns full
events -- `_raw`, `source`, `splunk_server` and all. `_raw` is therefore
handled like any other free-text field rather than assumed absent, and
`source`/`splunk_server` are in the field tables below for the same reason.

Pseudonym stability
-------------------
Pseudonyms are keyed-hash derived, not counter derived, so they are stable
across runs by default: the same host is the same `ANON_HOST_xxxxxxxx` in
every artifact produced with the same salt. Per-run pseudonyms would satisfy
the letter of "preserve correlation between events" while making the
recurring-issue case -- the one worth debugging -- impossible to follow
across runs. The default salt is a constant in this file, which buys that
cross-run stability but is not a secret: someone who *guesses* a hostname
can confirm the guess by hashing it. Set MATCHED_EVENTS_ANON_SALT (or
--salt) from a repository secret to remove that confirmation oracle while
keeping stability; rotating the salt renumbers every pseudonym, so old and
new artifacts stop correlating with each other.

Not a gate, and not reversible from the artifact: the real -> pseudonym map
is only written when --map-out asks for it, and --map-out refuses to write
inside a directory being anonymized. Nothing this tool prints on stdout
contains an original value either, because the CI log is as public as the
artifact.

Usage:
    python anonymize_matched_events.py --output-dir <dir> <input-dir-or-file>...
    python anonymize_matched_events.py --in-place <input-dir-or-file>...
      [--salt SALT] [--map-out PATH] [--quiet]

Exit codes:
    0  Every input file was rewritten successfully.
    2  Usage error, unreadable/unparseable input, or a post-write self-check
       that still found a known identifier in the output. Fail closed: the CI
       step only exports the artifact path after a 0, so a non-zero here
       means the upload has nothing to upload rather than something raw.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# --- entity kinds ------------------------------------------------------------

KIND_HOST = "HOST"
KIND_USER = "USER"
KIND_DOMAIN = "DOMAIN"

# Deliberately not something that could pass for a real identifier. An
# underscore is invalid in a DNS label, so ANON_HOST_3f21c9ab cannot be
# mistaken for (or collide with) a hostname, and the ANON_ prefix says what
# it is without needing this docstring.
PSEUDONYM_TEMPLATE = "ANON_{kind}_{digest}"
DIGEST_BYTES = 4  # 8 hex characters

# Anything this tool already produced. Recognised so a second run over an
# anonymized file is a no-op rather than a second layer of pseudonyms: an
# operator re-running --in-place, or a CI step retried, would otherwise
# renumber every entity and silently break correlation with the artifact
# from the first run.
PSEUDONYM_RE = re.compile(r"^ANON_(?:HOST|USER|DOMAIN)_[0-9a-f]{8}$")

DEFAULT_SALT = "detection-engineering-matched-events-v1"
SALT_ENV_VAR = "MATCHED_EVENTS_ANON_SALT"

# --- which fields carry which kind of identity -------------------------------
#
# Built from what this repo's rules actually ask Splunk for -- the union of
# the `| table` columns across all 28 generated .spl files is _time,
# ComputerName, User, Image, ParentImage, ProcessId, CommandLine,
# ParentCommandLine, ParentProcessId, CurrentDirectory, IntegrityLevel,
# OriginalFileName, CallTrace, GrantedAccess, SourceImage, SourceProcessId,
# TargetFilename, TargetImage, TargetProcessId -- plus the Splunk defaults and
# the Windows Security-log names a future rule can pull in without any change
# here. Matched case-insensitively: Splunk field names are case-sensitive, but
# the same logical field arrives as `Computer` or `ComputerName` or `host`
# depending on the sourcetype, and guessing wrong fails open.

HOST_FIELDS = frozenset({
    "computername",
    "computer",
    "host",
    "hostname",
    "dvc",
    "dest",
    "dest_host",
    "dest_nt_host",
    "src",
    "src_host",
    "src_nt_host",
    "sourcehostname",
    "destinationhostname",
    "workstation",
    "workstationname",
    "splunk_server",
    "machinename",
})

USER_FIELDS = frozenset({
    "user",
    "username",
    "account_name",
    "accountname",
    "samaccountname",
    "subjectusername",
    "targetusername",
    "caller_user_name",
    "src_user",
    "dest_user",
    "sourceuser",
    "destinationuser",
    "owner",
    "logonuser",
})

DOMAIN_FIELDS = frozenset({
    "domain",
    "dnsdomain",
    "logondomain",
    "subjectdomainname",
    "targetdomainname",
    "dest_nt_domain",
    "src_nt_domain",
    "domainname",
})

FIELD_KIND: dict[str, str] = {}
for _f in HOST_FIELDS:
    FIELD_KIND[_f] = KIND_HOST
for _f in USER_FIELDS:
    FIELD_KIND[_f] = KIND_USER
for _f in DOMAIN_FIELDS:
    FIELD_KIND[_f] = KIND_DOMAIN

# --- values that are not lab naming ------------------------------------------
#
# These are identical on every Windows install on earth, so replacing them
# removes debugging value (running as SYSTEM versus as a user is *the* thing
# you read off a matched event) and hides nothing: none of them says anything
# about this lab. Compared casefolded.

BUILTIN_ACCOUNTS = frozenset({
    "system",
    "localsystem",
    "local system",
    "local service",
    "localservice",
    "network service",
    "networkservice",
    "administrator",
    "administrators",
    "guest",
    "anonymous logon",
    "defaultaccount",
    "wdagutilityaccount",
    "public",
    "default",
    "default user",
    "all users",
    "trustedinstaller",
    "unknown",
    "n/a",
    "-",
    "",
})

BUILTIN_QUALIFIERS = frozenset({
    "nt authority",
    "nt service",
    "nt virtual machine",
    "builtin",
    "workgroup",
    "window manager",
    "font driver host",
    "localhost",
    "iis apppool",
    "unknown",
    "n/a",
    "-",
    ".",
    "",
})

# Per-session pseudo-accounts (Window Manager\DWM-1, Font Driver Host\UMFD-0).
# The trailing number is a session id, not an identity.
SESSION_ACCOUNT_RE = re.compile(r"^(?:dwm|umfd)-\d+$", re.IGNORECASE)

# --- structural patterns in free text ----------------------------------------
#
# Entities the identity fields never mention. A process running as SYSTEM out
# of a user's profile directory names that user nowhere except in the path.

USER_PROFILE_RE = re.compile(r"(?i)[A-Za-z]:\\Users\\([^\\/:*?\"<>|\r\n]+)")
POSIX_HOME_RE = re.compile(r"/home/([A-Za-z0-9._-]+)")
UNC_HOST_RE = re.compile(r"\\\\([A-Za-z0-9][A-Za-z0-9.-]*)\\")

# Below this, or with no letter in it, a value is replaced only in its own
# identity field and never substituted into free text -- see module docstring.
MIN_SUBSTITUTABLE_LEN = 3

# Boundary rule for the free-text pass: an identifier only matches when it is
# not glued to another identifier character on either side. `.` is *not* in
# this class on purpose, so `DC01.lab.local` splits into a host match and a
# domain match rather than matching neither.
_BOUNDARY_CHARS = "A-Za-z0-9_-"


def _walk_strings(node: Any, field: str | None = None):
    """Yield (field_name, string_value) for every string leaf in a JSON document.

    field_name is the dict key the string sat under (None inside a bare list
    at the top level), which is what decides whether a value is treated as an
    identity field or as free text.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk_strings(value, key)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_strings(value, field)
    elif isinstance(node, str):
        yield field, node


class Pseudonymizer:
    """Mints and remembers one pseudonym per real entity, then rewrites documents.

    Two phases, and the order is load-bearing. `discover()` must see every
    document before `anonymize()` rewrites the first one, because a hostname
    that only ever appears in event 12's `ComputerName` still has to be
    substituted out of event 0's command line.
    """

    def __init__(self, salt: str = DEFAULT_SALT):
        self._salt_key = hashlib.sha256((salt or DEFAULT_SALT).encode("utf-8")).digest()
        self.salt_fingerprint = hashlib.sha256((salt or DEFAULT_SALT).encode("utf-8")).hexdigest()[:8]
        # (kind, canonical_key) -> pseudonym
        self._entities: dict[tuple[str, str], str] = {}
        # every literal spelling that should be substituted in free text,
        # casefolded -> pseudonym
        self._candidates: dict[str, str] = {}
        # (kind, canonical_key) -> the literal spellings seen, for --map-out
        self._originals: dict[tuple[str, str], set[str]] = {}
        self._pattern: re.Pattern[str] | None = None
        self.substitutions = 0

    # -- minting --------------------------------------------------------------

    def _mint(self, kind: str, key: str) -> str:
        digest = hashlib.blake2s(
            f"{kind}\x00{key}".encode(),
            key=self._salt_key,
            digest_size=DIGEST_BYTES,
        ).hexdigest()
        return PSEUDONYM_TEMPLATE.format(kind=kind, digest=digest)

    def _entity(self, kind: str, key: str, spelling: str) -> str:
        entry = (kind, key)
        pseudonym = self._entities.get(entry)
        if pseudonym is None:
            pseudonym = self._mint(kind, key)
            self._entities[entry] = pseudonym
        self._originals.setdefault(entry, set()).add(spelling)
        if _is_substitutable(spelling):
            self._candidates[spelling.casefold()] = pseudonym
        return pseudonym

    # -- per-kind registration + replacement ----------------------------------
    #
    # These double as the discovery pass and the rewrite pass: calling one
    # registers the entity if it is new and returns the replacement either
    # way, so discovery is "call it and throw the result away".

    def host(self, value: str) -> str:
        """`DC01` -> pseudonym; `DC01.lab.local` -> host pseudonym + domain pseudonym."""
        text = value.strip()
        if not text or text.casefold() in BUILTIN_QUALIFIERS:
            return value
        label, dot, rest = text.partition(".")
        if label.casefold() in BUILTIN_QUALIFIERS or PSEUDONYM_RE.match(label):
            return value
        # The FQDN as written is also a candidate, so free text containing it
        # verbatim is replaced in one match rather than two adjacent ones.
        host_pseudonym = self._entity(KIND_HOST, label.casefold(), label)
        if not dot:
            return host_pseudonym
        domain_pseudonym = self.domain(rest)
        replacement = f"{host_pseudonym}.{domain_pseudonym}"
        if _is_substitutable(text):
            self._candidates[text.casefold()] = replacement
        return replacement

    def domain(self, value: str) -> str:
        """`LAB` and `lab.local` are the same entity: keyed on the first label."""
        text = value.strip()
        if not text or text.casefold() in BUILTIN_QUALIFIERS:
            return value
        label = text.partition(".")[0]
        if label.casefold() in BUILTIN_QUALIFIERS or PSEUDONYM_RE.match(label):
            return value
        pseudonym = self._entity(KIND_DOMAIN, label.casefold(), label)
        if text.casefold() != label.casefold() and _is_substitutable(text):
            # `lab.local` maps to the same pseudonym as `LAB`, and the DNS
            # suffix is dropped rather than kept: a suffix like
            # `corp.acme-lab.internal` is itself lab naming.
            self._candidates[text.casefold()] = pseudonym
        return pseudonym

    def account(self, value: str) -> str:
        """A bare account name, no domain qualifier."""
        text = value.strip()
        if (
            not text
            or text.casefold() in BUILTIN_ACCOUNTS
            or SESSION_ACCOUNT_RE.match(text)
            or PSEUDONYM_RE.match(text)
        ):
            return value
        if text.endswith("$"):
            # A machine account IS the host, so it shares the host's pseudonym
            # -- `LAB\DC01$` and `ComputerName=DC01` stay visibly the same box.
            return self.host(text[:-1]) + "$"
        return self._entity(KIND_USER, text.casefold(), text)

    def user(self, value: str) -> str:
        """`LAB\\svc_backup`, `svc_backup@lab.local` or a bare `svc_backup`."""
        text = value.strip()
        if not text:
            return value
        if "\\" in text:
            qualifier, _, name = text.rpartition("\\")
            return f"{self._qualifier(qualifier)}\\{self.account(name)}"
        if "@" in text:
            name, _, qualifier = text.partition("@")
            return f"{self.account(name)}@{self.domain(qualifier)}"
        return self.account(text)

    def _qualifier(self, value: str) -> str:
        """The left half of `X\\account` -- a domain, or a host for a local account.

        Resolved as a host when that name was already seen in a host field, so
        `WIN10\\Administrator` and `ComputerName=WIN10` do not become two
        different pseudonyms for one machine. Deterministic because discovery
        registers every host field before it looks at any user field.
        """
        label = value.strip().partition(".")[0]
        if (KIND_HOST, label.casefold()) in self._entities:
            return self.host(value)
        return self.domain(value)

    def identity(self, kind: str, value: str) -> str:
        if kind == KIND_HOST:
            return self.host(value)
        if kind == KIND_USER:
            return self.user(value)
        if kind == KIND_DOMAIN:
            return self.domain(value)
        return value

    # -- free text ------------------------------------------------------------

    def discover_structural(self, text: str) -> None:
        for match in USER_PROFILE_RE.finditer(text):
            self.account(match.group(1))
        for match in POSIX_HOME_RE.finditer(text):
            self.account(match.group(1))
        for match in UNC_HOST_RE.finditer(text):
            self.host(match.group(1))

    def freeze(self) -> None:
        """Compile the one alternation used for the free-text pass."""
        if not self._candidates:
            self._pattern = None
            return
        alternatives = sorted(self._candidates, key=len, reverse=True)
        self._pattern = re.compile(
            f"(?<![{_BOUNDARY_CHARS}])(?:"
            + "|".join(re.escape(a) for a in alternatives)
            + f")(?![{_BOUNDARY_CHARS}])",
            re.IGNORECASE,
        )

    def scrub(self, text: str) -> str:
        if self._pattern is None or not text:
            return text

        def _replace(match: re.Match[str]) -> str:
            # A miss here would mean the alternation matched a spelling whose
            # casefold does not round-trip back to its key. Left unreplaced on
            # purpose rather than guessed at: residue() runs the same pattern
            # over the output, so the run fails closed instead of shipping a
            # value this branch quietly let through.
            replacement = self._candidates.get(match.group(0).casefold())
            if replacement is None:
                return match.group(0)
            self.substitutions += 1
            return replacement

        return self._pattern.sub(_replace, text)

    # -- document rewrite -----------------------------------------------------

    def discover(self, documents: list[Any]) -> None:
        """Register every entity in every document. Call once, before anonymize().

        Three sweeps, in this order for one reason: `_qualifier()` decides
        whether the `X` in `X\\account` is a domain or a local machine by
        asking whether `X` is already a known host, so every host must be
        registered before the first user field is read. Hosts arrive from
        host fields (sweep 1) and from UNC paths in free text (sweep 2), so
        user fields go last (sweep 3). Run in any other order the answer
        would depend on which event happened to come first in the file.
        """
        for document in documents:
            for field, value in _walk_strings(document):
                kind = FIELD_KIND.get((field or "").casefold())
                if kind in (KIND_HOST, KIND_DOMAIN):
                    self.identity(kind, value)

        for document in documents:
            for field, value in _walk_strings(document):
                if FIELD_KIND.get((field or "").casefold()):
                    continue
                self.discover_structural(value)

        for document in documents:
            for field, value in _walk_strings(document):
                if FIELD_KIND.get((field or "").casefold()) == KIND_USER:
                    self.user(value)

        self.freeze()

    def anonymize(self, node: Any, field: str | None = None) -> Any:
        if isinstance(node, dict):
            return {key: self.anonymize(value, key) for key, value in node.items()}
        if isinstance(node, list):
            return [self.anonymize(value, field) for value in node]
        if not isinstance(node, str):
            return node
        kind = FIELD_KIND.get((field or "").casefold())
        if kind:
            # Structured first, then the free-text pass over the result: an
            # identity field can hold a shape this module does not model
            # (`DC01 (lab.local)`), and the pseudonyms it just produced are
            # immune to re-matching -- every candidate is glued to `_` inside
            # them, which the boundary rule excludes.
            return self.scrub(self.identity(kind, node))
        return self.scrub(node)

    # -- reporting ------------------------------------------------------------

    def counts(self) -> dict[str, int]:
        counts = {KIND_HOST: 0, KIND_USER: 0, KIND_DOMAIN: 0}
        for kind, _key in self._entities:
            counts[kind] = counts.get(kind, 0) + 1
        return counts

    def mapping(self) -> dict[str, Any]:
        """The real -> pseudonym map. Never part of the artifact; see --map-out."""
        return {
            "salt_fingerprint": self.salt_fingerprint,
            "entities": sorted(
                (
                    {
                        "kind": kind,
                        "key": key,
                        "pseudonym": self._entities[(kind, key)],
                        "seen_as": sorted(self._originals.get((kind, key), set())),
                    }
                    for kind, key in self._entities
                ),
                key=lambda e: (e["kind"], e["key"]),
            ),
        }

    def residue(self, text: str) -> list[str]:
        """Known identifiers still present in already-anonymized output.

        The self-check behind the exit code 2 path. It cannot see an
        identifier that was never discovered -- nothing can -- but it does
        catch a replacement path that quietly returned its input.
        """
        if self._pattern is None:
            return []
        return sorted({m.group(0) for m in self._pattern.finditer(text)})


def _is_substitutable(value: str) -> bool:
    """May this literal be searched for inside unrelated free text?"""
    text = value.strip()
    return len(text) >= MIN_SUBSTITUTABLE_LEN and any(c.isalpha() for c in text)


# --- file plumbing -----------------------------------------------------------


def collect_inputs(paths: list[Path]) -> list[Path]:
    """Every .json file under the given files/directories, sorted, deduplicated."""
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found.extend(sorted(p for p in path.rglob("*.json") if p.is_file()))
        elif path.is_file():
            found.append(path)
        else:
            raise ValueError(f"input path does not exist: {path}")
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in found:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


def output_path_for(source: Path, roots: list[Path], output_dir: Path | None) -> Path:
    """Mirror the input tree under output_dir, so hits.json keeps its <detect_id>/ parent."""
    if output_dir is None:
        return source
    resolved = source.resolve()
    for root in roots:
        root_resolved = root.resolve()
        if root_resolved.is_dir():
            try:
                return output_dir / resolved.relative_to(root_resolved)
            except ValueError:
                continue
    return output_dir / source.name


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replace lab identifiers in matched-event JSON with stable pseudonyms "
                    "before the files are uploaded as a public CI artifact",
    )
    parser.add_argument("inputs", nargs="+", help="hits.json files, or directories to walk for *.json")
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output-dir", help="Write anonymized copies here, mirroring the input tree")
    destination.add_argument("--in-place", action="store_true", help="Overwrite the input files")
    parser.add_argument(
        "--salt", default=None,
        help=f"Pseudonym salt. Defaults to ${SALT_ENV_VAR}, then to a constant in this file. "
             "Same salt => same pseudonyms across runs; changing it renumbers everything.",
    )
    parser.add_argument(
        "--map-out", default=None, metavar="PATH",
        help="Write the real->pseudonym map here. This is the de-anonymization key: "
             "it must never be written inside a directory that gets uploaded, and this "
             "tool refuses to write it under any input or output directory.",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress the summary line")
    return parser


def main(argv: list[str]) -> int:
    args = build_arg_parser().parse_args(argv)

    inputs = [Path(p) for p in args.inputs]
    output_dir = Path(args.output_dir) if args.output_dir else None

    try:
        files = collect_inputs(inputs)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.map_out:
        map_out = Path(args.map_out).resolve()
        guarded = [p.resolve() for p in inputs if p.is_dir()]
        if output_dir is not None:
            guarded.append(output_dir.resolve())
        for root in guarded:
            if map_out == root or root in map_out.parents:
                print(
                    f"ERROR: --map-out {map_out} is inside {root}, which is being anonymized "
                    "or uploaded. The mapping is the de-anonymization key; write it elsewhere.",
                    file=sys.stderr,
                )
                return 2

    documents: list[Any] = []
    for path in files:
        try:
            documents.append(json.loads(path.read_text(encoding="utf-8")))
        except OSError as exc:
            print(f"ERROR: could not read {path}: {exc}", file=sys.stderr)
            return 2
        except json.JSONDecodeError as exc:
            # Fail closed. An unparseable file cannot be anonymized, and
            # letting it through would upload it verbatim.
            print(f"ERROR: {path} is not valid JSON: {exc}", file=sys.stderr)
            return 2

    salt = args.salt if args.salt is not None else os.environ.get(SALT_ENV_VAR) or DEFAULT_SALT
    pseudonymizer = Pseudonymizer(salt)
    pseudonymizer.discover(documents)

    for path, document in zip(files, documents, strict=True):
        anonymized = pseudonymizer.anonymize(document)
        rendered = json.dumps(anonymized, indent=2, ensure_ascii=False)

        residue = pseudonymizer.residue(rendered)
        if residue:
            print(
                f"ERROR: self-check failed on {path}: {len(residue)} known identifier(s) "
                "survived anonymization. Nothing was written.",
                file=sys.stderr,
            )
            return 2

        destination = output_path_for(path, inputs, output_dir)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered + "\n", encoding="utf-8")

    if args.map_out:
        map_path = Path(args.map_out)
        map_path.parent.mkdir(parents=True, exist_ok=True)
        map_path.write_text(
            json.dumps(pseudonymizer.mapping(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    if not args.quiet:
        counts = pseudonymizer.counts()
        # Counts only, never values: the CI log is as public as the artifact.
        print(
            f"Anonymized {len(files)} file(s): "
            f"{counts[KIND_HOST]} host(s), {counts[KIND_USER]} account(s), "
            f"{counts[KIND_DOMAIN]} domain(s) pseudonymized; "
            f"{pseudonymizer.substitutions} free-text substitution(s). "
            f"Salt fingerprint {pseudonymizer.salt_fingerprint}."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
