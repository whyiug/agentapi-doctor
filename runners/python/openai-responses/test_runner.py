"""Pure-stdlib tests for the bounded OpenAI Responses observation runner."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import re
import types
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("runner.py")
SPEC = importlib.util.spec_from_file_location("openai_responses_runner", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class FakeTimeout:
    def __init__(self, **values):
        self.values = values


class FakeHTTPClient:
    def __init__(self, **values):
        self.values = values
        self.closed = False

    def close(self):
        self.closed = True


class FakeStream:
    def __init__(self, final_error=None):
        self.events = [
            types.SimpleNamespace(type="response.created"),
            types.SimpleNamespace(type="response.completed"),
        ]
        self.final_error = final_error

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def __iter__(self):
        return iter(self.events)

    def get_final_response(self):
        if self.final_error is not None:
            raise self.final_error
        return types.SimpleNamespace(status="completed", output=[object()])


class FakeResponses:
    def __init__(self, stream):
        self.fake_stream = stream
        self.call = None

    def stream(self, **values):
        self.call = values
        return self.fake_stream


class FakeOpenAIClient:
    def __init__(self, owner, stream, **values):
        self.owner = owner
        self.owner.client_values = values
        self.responses = FakeResponses(stream)
        self.closed = False
        self.owner.client = self

    def close(self):
        self.closed = True


def fake_modules(final_error=None):
    stream = FakeStream(final_error)
    httpx = types.SimpleNamespace(Timeout=FakeTimeout, Client=FakeHTTPClient)
    openai = types.SimpleNamespace(__version__="2.38.0", client_values=None, client=None)
    openai.OpenAI = lambda **values: FakeOpenAIClient(openai, stream, **values)
    return openai, httpx


def locked_distributions(*extras):
    return sorted(runner.LOCKED_DISTRIBUTIONS.items()) + list(extras)


def pinned_environment(**overrides):
    values = {
        "runtime_version": "3.12.12",
        "runtime_implementation": "CPython",
        "runtime_system": "Linux",
        "runtime_machine": "x86_64",
        "installed_distributions": locked_distributions(),
    }
    values.update(overrides)
    return values


class URLPolicyTests(unittest.TestCase):
    def test_accepts_only_exact_ipv4_loopback_shape(self):
        self.assertEqual(
            runner.validate_base_url("http://127.0.0.1:18080/v1/"),
            "http://127.0.0.1:18080/v1",
        )

    def test_rejects_indirection_and_credential_forms(self):
        rejected = [
            "http://localhost:18080/v1",
            "http://127.0.0.1.example:18080/v1",
            "http://127.0.0.1:18080@other.example/v1",
            "http://user@127.0.0.1:18080/v1",
            "https://127.0.0.1:18080/v1",
            "http://127.0.0.1/v1",
            "http://127.0.0.1:18080/v1?next=http://example.invalid",
        ]
        for value in rejected:
            with self.subTest(value=value):
                with self.assertRaises(runner.RunnerConfigurationError):
                    runner.validate_base_url(value)


class ObservationTests(unittest.TestCase):
    def test_success_uses_pinned_high_level_sdk_with_network_safety(self):
        openai, httpx = fake_modules()
        result = runner.observe(
            "http://127.0.0.1:18080/v1",
            openai_module=openai,
            httpx_module=httpx,
            **pinned_environment(),
        )

        self.assertIsNone(result["exception"])
        self.assertTrue(result["environment"]["matches_lock"])
        self.assertEqual(
            result["environment"]["dependencies"],
            [
                {"name": name, "version": version}
                for name, version in sorted(runner.LOCKED_DISTRIBUTIONS.items())
            ],
        )
        self.assertEqual(result["environment"]["bootstrap_tools"], [])
        self.assertEqual(result["environment"]["mismatches"], [])
        self.assertEqual(result["event_count"], 2)
        self.assertEqual(
            result["event_types"], ["response.created", "response.completed"]
        )
        self.assertEqual(result["final"], {"status": "completed", "output_count": 1})
        self.assertEqual(openai.client_values["api_key"], runner.SYNTHETIC_API_KEY)
        self.assertEqual(openai.client_values["max_retries"], 0)
        transport = openai.client_values["http_client"]
        self.assertIs(transport.values["trust_env"], False)
        self.assertIs(transport.values["follow_redirects"], False)
        self.assertEqual(
            transport.values["timeout"].values,
            {"connect": 2.0, "read": 5.0, "write": 2.0, "pool": 2.0},
        )
        self.assertEqual(
            openai.client.responses.call,
            {
                "model": "fixture-model",
                "input": runner.SYNTHETIC_INPUT,
                "max_output_tokens": 32,
            },
        )
        self.assertTrue(openai.client.closed)

    def test_missing_terminal_is_bounded_and_does_not_copy_payload(self):
        error = RuntimeError(
            "Didn't receive a `response.completed` event. secret-payload follows"
        )
        openai, httpx = fake_modules(error)
        result = runner.observe(
            "http://127.0.0.1:18080/v1",
            openai_module=openai,
            httpx_module=httpx,
            **pinned_environment(),
        )

        self.assertEqual(result["exception"]["phase"], "final_response")
        self.assertEqual(
            result["exception"]["sanitized_message"],
            "SDK did not receive the required response.completed event",
        )
        self.assertNotIn("secret-payload", json.dumps(result))

    def test_version_mismatch_stops_before_sdk_import(self):
        openai, httpx = fake_modules()
        result = runner.observe(
            "http://127.0.0.1:18080/v1",
            openai_module=openai,
            httpx_module=httpx,
            **pinned_environment(runtime_version="3.12.11"),
        )
        self.assertEqual(result["exception"]["phase"], "environment_attestation")
        self.assertEqual(result["exception"]["class"], "RuntimePinError")
        self.assertEqual(
            result["environment"]["mismatches"],
            [
                {
                    "kind": "runtime_mismatch",
                    "name": "python_version",
                    "expected": "3.12.12",
                    "observed": "3.12.11",
                }
            ],
        )
        self.assertIsNone(openai.client)

    def test_platform_and_implementation_are_part_of_the_attestation(self):
        openai, httpx = fake_modules()
        result = runner.observe(
            "http://127.0.0.1:18080/v1",
            openai_module=openai,
            httpx_module=httpx,
            **pinned_environment(
                runtime_implementation="PyPy",
                runtime_system="Darwin",
                runtime_machine="arm64",
            ),
        )

        self.assertFalse(result["environment"]["matches_lock"])
        self.assertEqual(
            {(item["name"], item["observed"]) for item in result["environment"]["mismatches"]},
            {("implementation", "PyPy"), ("system", "Darwin"), ("machine", "arm64")},
        )
        self.assertEqual(result["exception"]["phase"], "environment_attestation")
        self.assertIsNone(openai.client)

    def test_dependency_mismatches_are_explicit_and_stop_sdk_execution(self):
        openai, httpx = fake_modules()
        distributions = [
            (name, "0.0.0" if name == "httpx" else version)
            for name, version in locked_distributions()
            if name != "openai"
        ]
        distributions.append(("unrelated_plugin", "1.2.3"))
        result = runner.observe(
            "http://127.0.0.1:18080/v1",
            openai_module=openai,
            httpx_module=httpx,
            **pinned_environment(installed_distributions=distributions),
        )

        self.assertEqual(
            result["environment"]["mismatches"],
            [
                {
                    "kind": "distribution_version_mismatch",
                    "name": "httpx",
                    "expected": "0.28.1",
                    "observed": "0.0.0",
                },
                {
                    "kind": "missing_distribution",
                    "name": "openai",
                    "expected": "2.38.0",
                    "observed": None,
                },
                {
                    "kind": "unexpected_distribution",
                    "name": "unrelated-plugin",
                    "expected": None,
                    "observed": "1.2.3",
                },
            ],
        )
        self.assertEqual(result["exception"]["phase"], "environment_attestation")
        self.assertIsNone(openai.client)

    def test_bootstrap_tools_are_observed_but_do_not_change_lock_match(self):
        openai, httpx = fake_modules()
        result = runner.observe(
            "http://127.0.0.1:18080/v1",
            openai_module=openai,
            httpx_module=httpx,
            **pinned_environment(
                installed_distributions=locked_distributions(
                    ("pip", "25.1.1"), ("setuptools", "80.0.0"), ("wheel", "0.46.0")
                )
            ),
        )

        self.assertTrue(result["environment"]["matches_lock"])
        self.assertEqual(
            result["environment"]["bootstrap_tools"],
            [
                {"name": "pip", "version": "25.1.1"},
                {"name": "setuptools", "version": "80.0.0"},
                {"name": "wheel", "version": "0.46.0"},
            ],
        )
        self.assertIsNone(result["exception"])

    def test_metadata_failure_is_a_bounded_redacted_attestation_mismatch(self):
        openai, httpx = fake_modules()
        original = runner._installed_distributions

        def fail_metadata():
            raise RuntimeError("/private/path secret-metadata")

        runner._installed_distributions = fail_metadata
        try:
            result = runner.observe(
                "http://127.0.0.1:18080/v1",
                openai_module=openai,
                httpx_module=httpx,
            )
        finally:
            runner._installed_distributions = original

        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
        self.assertEqual(
            result["environment"]["mismatches"],
            [
                {
                    "kind": "environment_observation_failed",
                    "name": "installed-distributions",
                    "expected": "readable bounded distribution metadata",
                    "observed": "unavailable",
                }
            ],
        )
        self.assertEqual(result["exception"]["phase"], "environment_attestation")
        self.assertNotIn("private", encoded)
        self.assertNotIn("secret", encoded)
        self.assertLess(len(encoded.encode()), 64 << 10)
        self.assertIsNone(openai.client)

    def test_large_unexpected_environment_stays_below_helper_output_limit(self):
        extras = []
        for index in range(runner.MAX_DISTRIBUTIONS + 1):
            suffix = str(index)
            name = "x" * (79 - len(suffix)) + suffix
            extras.append((name, "1+" + "a" * 78))
        environment = runner._attest_environment(
            **pinned_environment(
                installed_distributions=locked_distributions(*extras)
            )
        )
        observation = runner._empty_observation(environment)
        encoded = json.dumps(observation, sort_keys=True, separators=(",", ":"))

        self.assertFalse(environment["matches_lock"])
        self.assertIn(
            "distribution_limit_exceeded",
            {item["kind"] for item in environment["mismatches"]},
        )
        self.assertLess(len(encoded.encode()), 64 << 10)

    def test_cli_error_is_one_json_line_and_never_writes_stderr(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = runner.main(["--base-url", "https://example.invalid/v1"])
        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        lines = stdout.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        result = json.loads(lines[0])
        self.assertEqual(result["exception"]["phase"], "configuration")
        self.assertNotIn("example.invalid", lines[0])

    def test_isolated_c_mode_accepts_one_positional_base_url(self):
        self.assertEqual(
            runner._parse_args(["http://127.0.0.1:18080/v1"]),
            ("http://127.0.0.1:18080/v1", "fixture-model"),
        )


class PinTests(unittest.TestCase):
    def test_fixture_and_lock_match_executed_constants(self):
        fixture = json.loads(MODULE_PATH.with_name("fixture.json").read_text())
        self.assertEqual(fixture["runtime"]["implementation"], runner.RUNTIME_IMPLEMENTATION)
        self.assertEqual(fixture["runtime"]["version"], runner.PYTHON_VERSION)
        self.assertEqual(fixture["runtime"]["platform"], "linux_x86_64")
        self.assertEqual(runner.RUNTIME_SYSTEM, "Linux")
        self.assertEqual(runner.RUNTIME_MACHINE, "x86_64")
        self.assertEqual(fixture["sdk"]["version"], runner.OPENAI_VERSION)
        self.assertEqual(
            [case["id"] for case in fixture["cases"]],
            [
                "reference",
                "missing-terminal-event",
                "duplicate-terminal-event",
                "null-completed-output",
            ],
        )
        self.assertEqual(
            fixture["cases"][1]["expected_observation"]["exception_class"],
            "RuntimeError",
        )
        self.assertEqual(
            fixture["cases"][3]["expected_observation"]["exception_class"],
            "TypeError",
        )
        lock = MODULE_PATH.with_name(
            "requirements-linux-x86_64-py312.lock"
        ).read_text()
        self.assertIn("openai==2.38.0", lock)
        self.assertIn(fixture["sdk"]["wheel"]["sha256"], lock)
        requirements = [
            line
            for line in lock.splitlines()
            if "==" in line and not line.lstrip().startswith("#")
        ]
        hashes = [line for line in lock.splitlines() if "--hash=sha256:" in line]
        self.assertEqual(len(requirements), 16)
        self.assertEqual(len(hashes), 16)
        parsed_lock = {}
        for line in requirements:
            match = re.fullmatch(r"([a-z0-9-]+)==([^ ]+) \\", line)
            self.assertIsNotNone(match, line)
            parsed_lock[match.group(1)] = match.group(2)
        self.assertEqual(parsed_lock, runner.LOCKED_DISTRIBUTIONS)


if __name__ == "__main__":
    unittest.main()
