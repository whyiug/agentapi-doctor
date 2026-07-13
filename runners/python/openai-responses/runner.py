#!/usr/bin/env python3
"""Bounded OpenAI Responses SDK observation against a local fixture only."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import platform
import re
import sys
from types import ModuleType
from typing import Any, Sequence
from urllib.parse import urlsplit


PYTHON_VERSION = "3.12.12"
OPENAI_VERSION = "2.38.0"
RUNTIME_IMPLEMENTATION = "CPython"
RUNTIME_SYSTEM = "Linux"
RUNTIME_MACHINE = "x86_64"
SCHEMA_VERSION = "agentapi-doctor.openai-sdk-observation.v1"
SYNTHETIC_API_KEY = "synthetic-test-token"
SYNTHETIC_INPUT = "Return the deterministic synthetic fixture response."
DEFAULT_MODEL = "fixture-model"
MAX_EVENTS = 128
MAX_DISTRIBUTIONS = 128

# This must remain identical to requirements-linux-x86_64-py312.lock. The
# helper is embedded and executed from an isolated temporary directory, so it
# cannot discover the checked-in lock at runtime.
LOCKED_DISTRIBUTIONS = {
    "annotated-types": "0.7.0",
    "anyio": "4.14.2",
    "certifi": "2026.6.17",
    "distro": "1.9.0",
    "h11": "0.16.0",
    "httpcore": "1.0.9",
    "httpx": "0.28.1",
    "idna": "3.18",
    "jiter": "0.16.0",
    "openai": OPENAI_VERSION,
    "pydantic": "2.13.4",
    "pydantic-core": "2.46.4",
    "sniffio": "1.3.1",
    "tqdm": "4.68.4",
    "typing-extensions": "4.16.0",
    "typing-inspection": "0.4.2",
}
# These distributions create and install the environment; they are not part
# of the SDK runtime graph and therefore need not be pinned by the case lock.
ALLOWED_BOOTSTRAP_DISTRIBUTIONS = frozenset({"pip", "setuptools", "wheel"})

_SAFE_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_SAFE_EVENT_TYPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}\Z")
_SAFE_EXCEPTION_CLASS = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,79}\Z")
_SAFE_DISTRIBUTION_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?\Z")
_SAFE_DISTRIBUTION_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,79}\Z")
_SAFE_RUNTIME_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")


class RunnerConfigurationError(ValueError):
    """The runner was invoked outside its deliberately narrow contract."""


class RuntimePinError(RuntimeError):
    """The executing Python or SDK version differs from the fixture pin."""


class ObservationLimitError(RuntimeError):
    """A response exceeded the runner's bounded observation budget."""


def validate_base_url(value: str) -> str:
    """Accept only http://127.0.0.1:<port>/v1 with no URL indirection."""

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise RunnerConfigurationError("base URL is malformed") from exc

    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or parsed.netloc != f"127.0.0.1:{port}"
        or parsed.path.rstrip("/") != "/v1"
        or parsed.query
        or parsed.fragment
    ):
        raise RunnerConfigurationError(
            "base URL must be exactly http://127.0.0.1:<port>/v1"
        )
    return f"http://127.0.0.1:{port}/v1"


def validate_model(value: str) -> str:
    if not _SAFE_MODEL.fullmatch(value):
        raise RunnerConfigurationError("model must be a bounded synthetic identifier")
    return value


def _safe_event_type(value: Any) -> str:
    if isinstance(value, str) and _SAFE_EVENT_TYPE.fullmatch(value):
        return value
    return "invalid-event-type"


def _safe_status(value: Any) -> str | None:
    if isinstance(value, str) and _SAFE_EVENT_TYPE.fullmatch(value):
        return value
    return None


def sanitized_exception_message(exc: BaseException) -> str:
    """Return a useful fixed phrase without copying provider-supplied content."""

    class_name = exc.__class__.__name__
    raw = str(exc).lower()
    if isinstance(exc, RunnerConfigurationError):
        return str(exc)
    if isinstance(exc, RuntimePinError):
        return str(exc)
    if isinstance(exc, ObservationLimitError):
        return "stream exceeded the 128-event observation limit"
    if "response.completed" in raw and (
        "didn't receive" in raw or "did not receive" in raw
    ):
        return "SDK did not receive the required response.completed event"
    if "timeout" in class_name.lower() or "timed out" in raw:
        return "request to the loopback fixture timed out"
    if "connection" in class_name.lower():
        return "SDK could not connect to the loopback fixture"
    if "validation" in class_name.lower():
        return "SDK rejected the streamed response during schema validation"
    return "SDK raised an exception; provider-supplied details were omitted"


def _canonical_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _safe_runtime_value(value: Any, fallback: str) -> str:
    if isinstance(value, str) and _SAFE_RUNTIME_VALUE.fullmatch(value):
        return value
    return fallback


def _installed_distributions() -> list[tuple[str, str]]:
    observed = []
    for distribution in importlib.metadata.distributions():
        observed.append((distribution.metadata.get("Name", ""), distribution.version))
    return observed


def _environment_observation(
    *,
    runtime_version: str | None = None,
    runtime_implementation: str | None = None,
    runtime_system: str | None = None,
    runtime_machine: str | None = None,
    installed_distributions: Sequence[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    implementation = _safe_runtime_value(
        runtime_implementation or platform.python_implementation(), "invalid"
    )
    python_version = _safe_runtime_value(
        runtime_version or platform.python_version(), "invalid"
    )
    system = _safe_runtime_value(runtime_system or platform.system(), "invalid")
    machine = _safe_runtime_value(runtime_machine or platform.machine(), "invalid")
    raw_distributions = list(
        _installed_distributions()
        if installed_distributions is None
        else installed_distributions
    )

    dependencies: list[dict[str, str]] = []
    bootstrap_tools: list[dict[str, str]] = []
    mismatches: list[dict[str, str | None]] = []
    versions_by_name: dict[str, list[str]] = {}
    if len(raw_distributions) > MAX_DISTRIBUTIONS:
        mismatches.append(
            {
                "kind": "distribution_limit_exceeded",
                "name": "installed-distributions",
                "expected": f"at most {MAX_DISTRIBUTIONS}",
                "observed": f"more than {MAX_DISTRIBUTIONS}",
            }
        )

    for index, item in enumerate(raw_distributions[:MAX_DISTRIBUTIONS]):
        try:
            raw_name, raw_version = item
        except (TypeError, ValueError):
            raw_name, raw_version = "", ""
        canonical_name = (
            _canonical_distribution_name(raw_name) if isinstance(raw_name, str) else ""
        )
        if not _SAFE_DISTRIBUTION_NAME.fullmatch(canonical_name):
            mismatches.append(
                {
                    "kind": "invalid_distribution_metadata",
                    "name": f"distribution-{index}",
                    "expected": "a bounded normalized distribution name",
                    "observed": "invalid",
                }
            )
            continue
        if not isinstance(raw_version, str) or not _SAFE_DISTRIBUTION_VERSION.fullmatch(
            raw_version
        ):
            mismatches.append(
                {
                    "kind": "invalid_distribution_metadata",
                    "name": canonical_name,
                    "expected": "a bounded distribution version",
                    "observed": "invalid",
                }
            )
            continue
        record = {"name": canonical_name, "version": raw_version}
        versions_by_name.setdefault(canonical_name, []).append(raw_version)
        if canonical_name in ALLOWED_BOOTSTRAP_DISTRIBUTIONS:
            bootstrap_tools.append(record)
        else:
            dependencies.append(record)

    dependencies.sort(key=lambda item: (item["name"], item["version"]))
    bootstrap_tools.sort(key=lambda item: (item["name"], item["version"]))

    runtime_pins = (
        ("implementation", RUNTIME_IMPLEMENTATION, implementation),
        ("python_version", PYTHON_VERSION, python_version),
        ("system", RUNTIME_SYSTEM, system),
        ("machine", RUNTIME_MACHINE, machine),
    )
    for name, expected, observed in runtime_pins:
        if observed != expected:
            mismatches.append(
                {
                    "kind": "runtime_mismatch",
                    "name": name,
                    "expected": expected,
                    "observed": observed,
                }
            )

    for name, expected_version in sorted(LOCKED_DISTRIBUTIONS.items()):
        observed_versions = versions_by_name.get(name, [])
        if not observed_versions:
            mismatches.append(
                {
                    "kind": "missing_distribution",
                    "name": name,
                    "expected": expected_version,
                    "observed": None,
                }
            )
        elif len(observed_versions) != 1:
            mismatches.append(
                {
                    "kind": "duplicate_distribution",
                    "name": name,
                    "expected": expected_version,
                    "observed": "multiple",
                }
            )
        elif observed_versions[0] != expected_version:
            mismatches.append(
                {
                    "kind": "distribution_version_mismatch",
                    "name": name,
                    "expected": expected_version,
                    "observed": observed_versions[0],
                }
            )

    for name in sorted(versions_by_name):
        if name not in LOCKED_DISTRIBUTIONS and name not in ALLOWED_BOOTSTRAP_DISTRIBUTIONS:
            for observed_version in versions_by_name[name]:
                mismatches.append(
                    {
                        "kind": "unexpected_distribution",
                        "name": name,
                        "expected": None,
                        "observed": observed_version,
                    }
                )
        elif name in ALLOWED_BOOTSTRAP_DISTRIBUTIONS and len(versions_by_name[name]) != 1:
            mismatches.append(
                {
                    "kind": "duplicate_bootstrap_distribution",
                    "name": name,
                    "expected": "at most one",
                    "observed": "multiple",
                }
            )

    mismatches.sort(
        key=lambda item: (
            item["kind"] or "",
            item["name"] or "",
            item["expected"] or "",
            item["observed"] or "",
        )
    )
    return {
        "implementation": implementation,
        "python_version": python_version,
        "system": system,
        "machine": machine,
        "dependencies": dependencies,
        "bootstrap_tools": bootstrap_tools,
        "matches_lock": not mismatches,
        "mismatches": mismatches,
    }


def _attest_environment(**values: Any) -> dict[str, Any]:
    try:
        return _environment_observation(**values)
    except Exception:
        # Metadata is untrusted runtime input. Preserve a parseable, bounded
        # observation without copying exception text or filesystem paths.
        return {
            "implementation": "invalid",
            "python_version": "invalid",
            "system": "invalid",
            "machine": "invalid",
            "dependencies": [],
            "bootstrap_tools": [],
            "matches_lock": False,
            "mismatches": [
                {
                    "kind": "environment_observation_failed",
                    "name": "installed-distributions",
                    "expected": "readable bounded distribution metadata",
                    "observed": "unavailable",
                }
            ],
        }


def _empty_observation(environment: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "version": {"python": environment["python_version"], "openai": None},
        "environment": environment,
        "event_types": [],
        "event_count": 0,
        "final": {"status": None, "output_count": None},
        "exception": None,
    }


def _record_exception(
    observation: dict[str, Any], phase: str, exc: BaseException
) -> dict[str, Any]:
    class_name = exc.__class__.__name__
    if not _SAFE_EXCEPTION_CLASS.fullmatch(class_name):
        class_name = "Exception"
    observation["exception"] = {
        "phase": phase,
        "class": class_name,
        "sanitized_message": sanitized_exception_message(exc),
    }
    return observation


def observe(
    base_url: str,
    model: str = DEFAULT_MODEL,
    *,
    openai_module: ModuleType | Any | None = None,
    httpx_module: ModuleType | Any | None = None,
    runtime_version: str | None = None,
    runtime_implementation: str | None = None,
    runtime_system: str | None = None,
    runtime_machine: str | None = None,
    installed_distributions: Sequence[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Run one bounded high-level Responses stream and return safe metadata."""

    environment = _attest_environment(
        runtime_version=runtime_version,
        runtime_implementation=runtime_implementation,
        runtime_system=runtime_system,
        runtime_machine=runtime_machine,
        installed_distributions=installed_distributions,
    )
    observation = _empty_observation(environment)
    phase = "configuration"
    client = None
    http_client = None
    try:
        safe_base_url = validate_base_url(base_url)
        safe_model = validate_model(model)
        phase = "environment_attestation"
        if not environment["matches_lock"]:
            raise RuntimePinError(
                "runtime environment does not match the frozen dependency lock"
            )

        phase = "sdk_import"
        openai_module = openai_module or importlib.import_module("openai")
        httpx_module = httpx_module or importlib.import_module("httpx")
        actual_openai = getattr(openai_module, "__version__", None)
        observation["version"]["openai"] = actual_openai
        if actual_openai != OPENAI_VERSION:
            raise RuntimePinError(
                f"OpenAI SDK version must be {OPENAI_VERSION}; got {actual_openai}"
            )

        timeout = httpx_module.Timeout(connect=2.0, read=5.0, write=2.0, pool=2.0)
        http_client = httpx_module.Client(
            timeout=timeout,
            trust_env=False,
            follow_redirects=False,
        )
        client = openai_module.OpenAI(
            api_key=SYNTHETIC_API_KEY,
            base_url=safe_base_url,
            http_client=http_client,
            max_retries=0,
            timeout=timeout,
        )

        phase = "stream_open"
        with client.responses.stream(
            model=safe_model,
            input=SYNTHETIC_INPUT,
            max_output_tokens=32,
        ) as stream:
            phase = "event_iteration"
            for event in stream:
                observation["event_count"] += 1
                if observation["event_count"] > MAX_EVENTS:
                    raise ObservationLimitError()
                observation["event_types"].append(
                    _safe_event_type(getattr(event, "type", None))
                )

            phase = "final_response"
            final_response = stream.get_final_response()
            observation["final"]["status"] = _safe_status(
                getattr(final_response, "status", None)
            )
            output = getattr(final_response, "output", None)
            observation["final"]["output_count"] = (
                len(output) if isinstance(output, list) else None
            )
    except Exception as exc:  # The observation is the product of this runner.
        _record_exception(observation, phase, exc)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        elif http_client is not None:
            try:
                http_client.close()
            except Exception:
                pass
    return observation


def _parse_args(argv: Sequence[str]) -> tuple[str, str]:
    if len(argv) == 1 and not argv[0].startswith("--"):
        return argv[0], DEFAULT_MODEL
    values: dict[str, str] = {"--model": DEFAULT_MODEL}
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag not in {"--base-url", "--model"} or flag in values:
            raise RunnerConfigurationError(
                "usage: runner.py --base-url URL [--model MODEL]"
            )
        if index + 1 >= len(argv):
            raise RunnerConfigurationError(f"missing value for {flag}")
        values[flag] = argv[index + 1]
        index += 2
    if "--base-url" not in values:
        raise RunnerConfigurationError("--base-url is required")
    return values["--base-url"], values["--model"]


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        base_url, model = _parse_args(args)
        observation = observe(base_url, model)
    except Exception as exc:
        environment = _attest_environment()
        observation = _empty_observation(environment)
        _record_exception(observation, "configuration", exc)
    sys.stdout.write(json.dumps(observation, sort_keys=True, separators=(",", ":")))
    sys.stdout.write("\n")
    # SDK/configuration failures are observations. Keeping exit zero ensures an
    # orchestrator can parse them and return UNKNOWN rather than discard stdout.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
