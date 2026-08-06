"""Environment-variable reading shared by the Splunk-facing scripts.

Register item 3.6. Four scripts -- the deploy, the reconcile and the two
verify steps -- each carried their own copy of these helpers. `env_bool` was
identical in all four down to the token tables; the TLS announcement added by
item 2.14 was copied verbatim four more times, with a comment admitting as
much. That is the duplication this module removes.

What it deliberately does *not* remove is the part that only looked
duplicated. `env_required` failed differently in each script -- exit 1 in the
deploy and the hit check, exit 2 in the indexing wait, a `ReconcileError` in
the reconcile -- and those codes are load-bearing: item 2.14's own notes cite
them, and the reconcile's exception exists so the step can distinguish a setup
failure from a drift finding. So the *reading* lives here and the *policy*
stays with the caller, wired in one line via `env_reader()`.
"""

import os
from collections.abc import Callable

# Accepted spellings, unchanged from the four copies this replaces. Kept
# deliberately narrow: anything outside both tables falls through to the
# caller's default rather than being guessed at, which is what makes a typo in
# SPLUNK_VERIFY_TLS fail closed instead of quietly disabling verification.
_TRUE = ("true", "1", "yes", "y", "on")
_FALSE = ("false", "0", "no", "n", "off")


class MissingEnvVar(Exception):
    """A required variable was unset, empty, or whitespace only."""


def env_bool(name: str, default: bool = True) -> bool:
    value = (os.getenv(name) or "").strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    return default


def env_required(name: str) -> str:
    """Return the stripped value, or raise `MissingEnvVar`.

    Whitespace-only counts as missing: a variable set to a stray space is a
    mistake, and treating it as a value would send it into a REST path.
    """
    value = (os.getenv(name) or "").strip()
    if not value:
        raise MissingEnvVar(f"Missing required env var: {name}")
    return value


def env_reader(on_missing: Callable[[str], None]) -> Callable[[str], str]:
    """Bind `env_required` to a caller's failure policy.

    Returns a one-argument function so existing call sites -- there are around
    eight per script -- stay exactly as they were, with the exit code or
    exception chosen once at the top of the module.
    """

    def read(name: str) -> str:
        try:
            return env_required(name)
        except MissingEnvVar as exc:
            on_missing(str(exc))
            # Only reached if on_missing returns instead of exiting or raising,
            # which would otherwise hand back None and fail much further along.
            raise

    return read


def announce_tls_mode(verify_tls: bool) -> None:
    """State which mode this run connects in (register item 2.14).

    The defect item 2.14 closed was not that verification can be off -- a
    self-signed lab certificate is a real reason -- but that nothing said so.
    A warning rather than a plain line when off, so it surfaces as a GitHub
    annotation instead of scrolling past in the log.
    """
    if verify_tls:
        print("TLS certificate verification: on.")
    else:
        print(
            "::warning title=TLS verification disabled::SPLUNK_VERIFY_TLS is set to a "
            "false value, so Splunk server certificates are NOT verified for this run."
        )
