# scripts/convert/backend_config.py
"""Loads config/backends.yml -- the converter's backend and pipeline routing.

Register item 3.7. The converter used to carry the Splunk target and the
service -> pipeline mapping as constants; this module turns them into data the
converter reads at startup.

Everything here fails by raising BackendConfigError. Nothing falls back to a
built-in default, and that is the whole design: a converter that shrugs off a
missing or misspelled config and converts with some remembered setting emits
SPL that looks fine, passes the drift gate on the next run because prod
misreads the same file the same way, and deploys to Splunk before anyone finds
out which pipeline actually produced it. A conversion that stops is a bad
minute; a conversion that guesses is a bad quarter.

Unknown keys are rejected for the same reason. `by_services:` instead of
`by_service:` is not a syntax error in YAML -- it is a valid mapping that
routes every rule to the default pipeline. Silently.
"""

from dataclasses import dataclass
from pathlib import Path

import yaml

# The config is resolved relative to this file, not to the working directory.
# The workflows invoke the converter from the repo root, but the tests and any
# local run do not have to, and "which config did it read" should not depend on
# where the shell happened to be.
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "backends.yml"

_TOP_LEVEL_KEYS = {"default_backend", "backends"}
_BACKEND_KEYS = {"target", "pipeline_override_key", "pipelines"}
_PIPELINE_KEYS = {"by_service", "default"}


class BackendConfigError(Exception):
    """The backend config is missing, unreadable, or does not describe a backend."""


@dataclass(frozen=True)
class BackendConfig:
    """One resolved backend: what to hand `sigma convert`, and how to route pipelines."""

    name: str
    target: str
    pipeline_override_key: str
    default_pipeline: str
    pipelines_by_service: dict[str, str]
    source: Path

    def pipeline_for_service(self, service: str) -> str:
        """Pipeline for a Sigma `logsource.service`; the backend default if unmapped.

        An empty return means the rule is converted with --without-pipeline.
        """
        key = (service or "").strip().lower()
        return self.pipelines_by_service.get(key, self.default_pipeline)


def _reject_unknown(where: str, mapping: dict, allowed: set) -> None:
    unknown = sorted(str(k) for k in mapping if k not in allowed)
    if unknown:
        raise BackendConfigError(
            f"{where}: unknown key(s) {', '.join(unknown)} -- allowed: {', '.join(sorted(allowed))}"
        )


def _require_mapping(where: str, value, *, allow_empty: bool = True) -> dict:
    if not isinstance(value, dict):
        raise BackendConfigError(f"{where}: expected a mapping, got {type(value).__name__}")
    if not value and not allow_empty:
        raise BackendConfigError(f"{where}: must not be empty")
    return value


def _as_optional_text(where: str, value) -> str:
    """A string-ish setting where absent, null and "" all mean the same empty value."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise BackendConfigError(f"{where}: expected a string, got {type(value).__name__}")
    return value.strip()


def _load_document(config_path: Path) -> dict:
    try:
        raw = config_path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise BackendConfigError(f"backend config not found: {config_path}") from e
    except OSError as e:
        # Not folded into the not-found case on purpose. A file that exists but
        # cannot be read is a different story -- a permission problem, or the
        # endpoint protection having quarantined it -- and reporting it as
        # "missing" would send whoever reads the log looking for the wrong thing.
        raise BackendConfigError(f"backend config could not be read: {config_path}: {e}") from e

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise BackendConfigError(f"backend config is not valid YAML: {config_path}: {e}") from e

    if document is None:
        raise BackendConfigError(f"backend config is empty: {config_path}")

    return _require_mapping(str(config_path), document)


def _parse_pipelines(where: str, entry: dict) -> tuple[str, dict[str, str]]:
    if "pipelines" not in entry:
        raise BackendConfigError(f"{where}: missing required key 'pipelines'")

    pipelines = _require_mapping(f"{where}.pipelines", entry["pipelines"])
    _reject_unknown(f"{where}.pipelines", pipelines, _PIPELINE_KEYS)

    if "default" not in pipelines:
        raise BackendConfigError(
            f"{where}.pipelines: missing required key 'default' -- write `default: \"\"` "
            f"to state that unmapped log sources convert without a pipeline"
        )

    default_pipeline = _as_optional_text(f"{where}.pipelines.default", pipelines["default"])

    by_service: dict[str, str] = {}
    raw_by_service = _require_mapping(f"{where}.pipelines.by_service", pipelines.get("by_service") or {})
    for raw_key, raw_value in raw_by_service.items():
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise BackendConfigError(f"{where}.pipelines.by_service: service names must be non-empty strings")

        service = raw_key.strip().lower()
        if service in by_service:
            # `Sysmon:` and `sysmon:` are distinct YAML keys but the same log
            # source here, and which one won would come down to file order.
            raise BackendConfigError(
                f"{where}.pipelines.by_service: duplicate service '{service}' after case folding"
            )

        by_service[service] = _as_optional_text(f"{where}.pipelines.by_service.{service}", raw_value)

    return default_pipeline, by_service


def load_backend(name: str = "", config_path: Path | None = None) -> BackendConfig:
    """Resolve one backend from the config.

    `name` empty means "whatever `default_backend` says", which is how both
    workflows call the converter.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    document = _load_document(path)
    _reject_unknown(str(path), document, _TOP_LEVEL_KEYS)

    backends = _require_mapping(f"{path}.backends", document.get("backends"), allow_empty=False)

    requested = (name or "").strip()
    source_of_name = "--backend"
    if not requested:
        requested = _as_optional_text(f"{path}.default_backend", document.get("default_backend"))
        source_of_name = "default_backend"

    if not requested:
        raise BackendConfigError(
            f"{path}: no backend requested and 'default_backend' is not set -- "
            f"configured backends: {', '.join(sorted(str(k) for k in backends))}"
        )

    if requested not in backends:
        raise BackendConfigError(
            f"{path}: unknown backend '{requested}' (from {source_of_name}) -- "
            f"configured backends: {', '.join(sorted(str(k) for k in backends))}"
        )

    where = f"{path}.backends.{requested}"
    entry = _require_mapping(where, backends[requested])
    _reject_unknown(where, entry, _BACKEND_KEYS)

    target = _as_optional_text(f"{where}.target", entry.get("target"))
    if not target:
        raise BackendConfigError(f"{where}: 'target' is required and must be a non-empty string")

    default_pipeline, by_service = _parse_pipelines(where, entry)

    return BackendConfig(
        name=requested,
        target=target,
        pipeline_override_key=_as_optional_text(
            f"{where}.pipeline_override_key", entry.get("pipeline_override_key")
        ),
        default_pipeline=default_pipeline,
        pipelines_by_service=by_service,
        source=path,
    )
