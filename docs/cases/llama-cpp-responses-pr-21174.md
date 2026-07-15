# Commit-Pinned Responses A/B: llama.cpp PR #21174

[Project home](../../README.md) | [Documentation index](../README.md) |
[Upstream PR](https://github.com/ggml-org/llama.cpp/pull/21174)

On 2026-07-15, AgentAPI Doctor was used alongside the PR's proposed tests to
compare a test-time master commit with the updated head of
[llama.cpp PR #21174](https://github.com/ggml-org/llama.cpp/pull/21174). The
comparison was local, CPU-only, and bound to exact commits.

## Result

| Local target | Existing OpenAI SDK smoke | Selected PR Responses tests | Doctor v0.1.1 |
| --- | ---: | ---: | ---: |
| master `f955e394` | 2/2 passed | 1/9 passed | 3 PASS + 1 FAIL |
| PR head `a28a6d324` | not separately rerun | 9/9 passed | 4 PASS |

The Doctor failure on master was
`openai-responses-http-030-terminal-exactly-once`. The emitted output item had
a nonempty ID and the `message` kind, but no nonnegative output index:

```text
expected: nonempty item ID/kind and nonnegative index
observed: kind="message" index=-1
finding: invalid_output_item / STREAM_STATE_MACHINE
```

That check passed on the PR head. The selected upstream tests also confirmed
that stream events on the PR head carried the sequence and content/output
indexes asserted by the PR's test file.

## Frozen inputs

| Input | Exact value |
| --- | --- |
| llama.cpp master at test time | [`f955e394bf94e01e5e36186d13c985727e5ef5b5`](https://github.com/ggml-org/llama.cpp/commit/f955e394bf94e01e5e36186d13c985727e5ef5b5) |
| PR head | [`a28a6d324e5e36e593c625985025027c7395adc2`](https://github.com/ggml-org/llama.cpp/commit/a28a6d324e5e36e593c625985025027c7395adc2) |
| Master merged by the PR head | `33a75f41c30052fd3d1c38e8ed2f86ee3c3f8fba` |
| PR test file | [`tools/server/tests/unit/test_compat_oai_responses.py`](https://github.com/ggml-org/llama.cpp/blob/a28a6d324e5e36e593c625985025027c7395adc2/tools/server/tests/unit/test_compat_oai_responses.py), Git blob `7a8f414672b1f9d28c98ce54cd5b02348f6b3d8c` |
| Doctor | v0.1.1, commit `151ee2b060ef2513320474bebc4fd04c06115a2d` |
| Doctor Linux amd64 binary | SHA-256 `954edba99ef4b6b6580c4b5293324f21424b1a7fcd819b0128c74e0397581f5c` |
| Python environment | CPython 3.12.7, pytest 8.3.5, OpenAI Python 2.14.0 |
| Model | `ggml-org/test-model-stories260K`, snapshot `479896ec924af6d40fd419ab8f4d1eb2101de00d` |
| Model blob | SHA-256 `270cba1bd5109f42d03350f60406024560464db173c0e387d91f0426d3bd256d` |
| Platform | Linux x86_64, GNU 14.3.0, CPU-only |

The master commit was one unrelated GGML commit after `33a75f41`, the upstream
commit merged into the PR head. The comparison is therefore not a strict
parent/child experiment. This relationship is recorded so the result is not
presented as attribution to a single patch.

Both servers were clean Release builds with CUDA, HIP, Vulkan, tests, and the
web UI disabled. The resulting `llama-server` binaries had these SHA-256
digests:

```text
master f955e394: 829d5d742bb561a2a12c41bb9729f026b5588c05ccb12865897a94483a2f16e0
PR head a28a6d324: efa8d18b8d598b430d51f279e85ff8488c95d36d1afdea72b36616f7afed852b
```

## Method

Each test family used a fresh `llama-server` on a random `127.0.0.1` port. The
server ran with the cached test model, deterministic seed 42, two CPU threads,
and a 120-second process timeout. Proxy variables were removed and no provider
or GPU was used.

The master smoke run used the two OpenAI SDK tests present on the master
commit:

```text
test_responses_with_openai_library
test_responses_stream_with_openai_library
```

The same nine tests from the PR-head test blob were then executed, through the
upstream external-server test path, against each separately built server:

```text
test_responses_schema_fields
test_responses_stream_schema_fields
test_responses_non_function_tool_skipped
test_responses_extra_keys_stripped
test_responses_developer_role_merging
test_responses_input_text_type_multi_turn
test_responses_stream_created_event_has_full_response
test_responses_stream_all_events_have_sequence_number
test_responses_stream_delta_events_have_indices
```

Finally, the official Doctor v0.1.1 binary ran its four bounded OpenAI
Responses checks against a fresh instance of each server:

```sh
doctor test \
  --base-url "http://127.0.0.1:${PORT}/v1" \
  --protocol openai-responses \
  --model tinyllama-2 \
  --allow-plain-http
```

The release archive checksum was verified before the binary was used. Doctor
returned exit 1 for master and exit 0 for the PR head, matching the recorded
case counts. A result summary was also posted back to the
[upstream PR](https://github.com/ggml-org/llama.cpp/pull/21174#issuecomment-4979810149)
so its maintainers can review the evidence in context.

## Scope and limitations

- This is independent local evidence for the exact commits, model, test file,
  runtime, and Doctor checks above.
- It does not establish full OpenAI Responses compatibility, production-model
  behavior, merge readiness, or the correctness of unrelated PR changes.
- The nine selected tests are assertions authored in the upstream PR. Doctor's
  four checks are separate candidate raw-wire interpretations, not vendor
  certification.
- The PR remained open with changes requested when this case was recorded.
- llama.cpp master moved after the run. Claims on this page remain bound to
  `f955e394`, not to later master commits.

This is the intended use of a Doctor result: a small, reviewable observation
that complements a project's own tests without turning it into a broader
compatibility claim.
