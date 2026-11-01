# Model routing and workflow reliability audit

## Scope and evidence limits

This pass fixes application-owned routing, retry classification, response diagnostics,
a rate-limit deadlock path, template-completion bookkeeping, generation provenance,
and bounded probe-task scheduling. It does not disable provider safeguards, improve
jailbreak payloads, or establish that any provider secretly changed models.
No credentials, production scan data, or `.env` contents were inspected. No live
inference requests or paid scans were run. This extracted checkout has no `.git`
metadata, so change-history attribution is unavailable.

## Provider switching versus application routing

The user-supplied Claude support article was retrieved and read:
https://support.claude.com/en/articles/16049681-why-claude-switched-models-in-your-conversation-with-opus-5-or-opus-5-5

It describes safety-triggered fallback to a less capable model in Claude products.
Automatic switching can be disabled with **Settings > Capabilities > Switch models
when a message is flagged**, or **Config > MODEL & OUTPUT** in Claude Code.
Disabling switching pauses flagged requests; it does not disable safety checks.
The article says API switching is not active by default and requires customer
opt-in/configuration. It also describes the Cyber Verification Program for eligible
legitimate defensive-security users; eligibility and model coverage must be checked
with Anthropic.

Vexorr's `AnthropicIntegration` uses the API, not the Claude app. The inspected
adapter sets no provider fallback configuration. The support article alone does
not establish that the reported application symptoms were caused by provider-side
switching. No speculative provider fallback parameters were added.

## Confirmed defects and fixes

| Area | Evidence | Change |
|---|---|---|
| Silent model replacement | `models/integrations.py`, former `AnthropicIntegration._MODEL_MAP` mapped older Claude IDs to different IDs | Removed implicit replacements. Exact requested ID is dispatched by default. |
| Missing provider routed elsewhere | `ModelManager._resolve` skipped unavailable family providers and ultimately tried Ollama | Strict routing is now the default. Missing providers and unknown/ambiguous routes fail before dispatch. |
| Fine-tunes misrouted | Original generic colon-to-Ollama rule preceded `ft:` prefix routing | Strict resolver treats OpenAI fine-tunes separately. |
| Ambiguous dynamic providers | Original loop used first available provider listing the model | Conflicts require an explicit `model_routes` selection. Unavailable explicit providers do not silently fall through. |
| Corrupt config ignored | `_load_config` printed a load error and continued with defaults | Malformed/unreadable configuration fails closed. A missing file retains existing defaults, with strict routing. |
| Unsafe retry categorization | `_retry_sync` / `_retry_async` matched `429` and `503` substrings without permanent/safety exclusions | Safety, context, auth, billing, and exhausted-quota errors are excluded before transient retries. Structured status codes are used when available; legacy message matching remains for exceptions without them. |
| Lost response diagnostics | OpenAI and Anthropic adapters returned text only | String-compatible `ModelResponse` retains reported model and completion reason. OpenAI-compatible adapter also uses the response helper. Output-limit stops receive an explicit incomplete marker; empty refusal replies receive a blocked marker. |
| Rate-limit deadlock | `Scanner._send_probe` could reacquire a provider semaphore while its caller held a slot | New provider-wide cooldown updates the token bucket without acquiring another slot. |
| Invalid RPM | Nonpositive token-bucket RPM could lead to division by zero or indefinite waiting | Reject nonpositive RPM explicitly. |

Audit events `model_dispatch` and `model_result` contain a `model_audit` logging
record attribute with requested model, explicitly configured provider (or null),
dispatched provider/model, reported model, completion reason, and error flag.
They contain no prompt, response text, API key, or endpoint URL. Configure the
`models.integrations` logger at INFO and a handler/formatter that retains the
`model_audit` attribute to collect these events. Null reported metadata means
unavailable, not verified equality. Other adapters still returning plain strings
have null response metadata. Scan results and checkpoints now retain available
metadata in `model_diagnostics`. Provider-reported model labels do not prove the
identity of the underlying model.

## Configuration

In `configs/model_config.json`, merge these fields with existing configuration:

```json
{
  "strict_model": true,
  "model_routes": {
    "gpt-4o": "openai",
    "claude-opus-4-6": "anthropic"
  },
  "model_aliases": {}
}
```

Provider keys must match loaded integrations. Configure valid credentials through
the existing supported mechanism; do not put secrets in committed config. Model
IDs shown here already existed in this repository and are not a claim of current
account entitlement. Verify availability with the provider.

Use `ollama/<model>` for the local Ollama endpoint and
`ollama-cloud/<model>` for the Ollama Cloud integration. Bare `:cloud` names require
an explicit route in strict mode because they can refer to different endpoints.
A local Ollama installation may itself proxy cloud requests: selecting `ollama/`
identifies the endpoint, not a guarantee of local-only execution.

### Optional legacy behavior / explicit aliases

`strict_model: false` explicitly restores legacy heuristic provider selection,
including last-resort Ollama routing. This is less predictable and not recommended.
It does not enable retrying refusals on other providers or error-time model
fallback. No new automatic cross-model fallback mechanism was added.

For a deliberate Anthropic model migration, set `strict_model: false` and supply
an explicit `model_aliases` mapping from an old ID to an authorized replacement
ID. The mapping applies only to the Anthropic adapter. A nonempty alias mapping
with strict mode enabled is rejected. Previous hard-coded aliases are no longer
implicitly restored even in legacy mode. Dispatch audit events expose the mapped
ID. Review and approve every replacement; do not use aliases to evade safeguards.

### Input size

Optionally configure a positive `max_input_chars` under a model's
`model_specific_configurations` entry. The manager counts the full user and system
strings together and rejects oversized requests without truncation or dispatch.
This is an application character cap, **not a token counter or context-window
estimate**. Without this cap, the full assembled input is passed to the adapter,
and provider context-limit errors remain authoritative. Accurate per-model token
budgeting, including message overhead and output reservations, remains unimplemented.

## Follow-up: checkpoint integrity and response previews

The scan checkpoint writer previously overwrote the destination file directly.
It now uses `core/persistence.py::atomic_write_json`: serialize first, write a
unique same-directory temporary file, flush/fsync, close, and atomically replace
the destination. Serialization, fsync, or replacement failures leave the previous
valid checkpoint intact and clean up the temporary file. Failed saves return
`False` and add a deduplicated, sanitized warning to `job.errors`; clients can see
that completed work may not survive a restart. This does not add more checkpoint
scheduling, serialize concurrent writers, or guarantee directory-entry durability
after power loss. The warning remains as historical evidence after later saves.

`ScanJob.to_dict` still returns bounded 4,000-character response previews, but now
includes `response_truncated` and `response_full_length`. The scan result UI labels
shortened previews and directs users to the server JSON export for complete
stored responses. The disk serializer preserves full response text. These flags
describe application previews, not provider-side output truncation. Existing CSV
and browser-local exports have separate truncation behavior and are not changed.

Eight new offline tests cover Unicode snapshots, invalid serialization, failed
replacement/fsync, temporary-file cleanup, full-response round trips, preview
boundaries, visible/deduplicated/sanitized save failures, and interrupted-job
reconciliation without losing previously completed probes.

## Follow-up: HTTP 200 is not generation success

Confirmed code defect: both `/api/models/test` and the connectivity probe previously
returned `success=true` whenever an adapter returned a string, including `Error:`
strings. The model-test UI also hid partial response text on its error path.

`core/model_results.py::response_details` now separates `completed`, `blocked`,
`incomplete`, `empty`, and `error` outcomes. API tests and connectivity probes share
this handling; errors, structured refusals, output limits, and empty output are
not labeled successful completions. Claude `stop_reason=refusal` is recognized even
when partial text exists. OpenAI refusal fields and content-filter completion
reasons are recognized even with partial output. Blocked/incomplete/empty outcomes
cannot become scan findings merely because a heuristic evaluator returns true.
A normal textual refusal with an ordinary completion reason may still be a completed
generation; `completed` does not mean compliance or a confirmed vulnerability.

Model test, provider test, and scan result views display available stop reasons,
requested/dispatched model/provider labels, and provider-reported model labels.
A differing reported label is a diagnostic warning, not proof of downgrade:
snapshot aliases can legitimately differ. No fallback or new retry is triggered
by this warning. Unknown metadata stays unknown. Dispatch metadata is copied per
request to avoid cross-request contamination. Strict routing also now recognizes
Bedrock version suffixes containing colons instead of misrouting them to Ollama.

The user reports Sonnet API failures, but has not supplied the exact model ID or
sanitized response evidence. The Opus support article establishes a possible
provider behavior, not the root cause of that specific Sonnet incident. Provider
safety restrictions remain intact; no paid/live request was used to reproduce it.

## Follow-up: discovery integrity and generator provenance

- Removed all scheduling-time and bulk `mark_template_tested` calls. Only an
  attributable operation settled through `observe_template` records an outcome.
  Errors, cancellations, and incomplete/empty outputs do not mark templates tested.
  Historical tested flags without completion counts are not trusted.
- `tested` means a test completed, not that a vulnerability was confirmed.
  Heuristic-positive counts, completed-evaluation counts, and independently
  validated counts are separate. The legacy `bypass_rate` key is now a fraction,
  not an incrementing integer.
- Placeholder warm-pool strings are not evidence that a complete template was
  evaluated. The legacy AutoPwn sweep ignores template-specific system prompts;
  such templates are not falsely credited as evaluated. This patch does not add
  new system-prompt injection behavior to that path.
- `Scanner(independent_validator=...)` accepts a trusted, server-configured,
  synchronous test-specific verifier. It receives an immutable
  `ValidationObservation` and returns a `ValidationDecision(passed, evaluator)`.
  For example, an isolated application-owned canary test can check its expected
  result. Verifiers must not merely repeat the heuristic classifier. There is no
  HTTP parameter for clients to self-certify a finding. Verifier exceptions,
  invalid decisions, blocked output, and incomplete output are inconclusive.
- Without a verifier, probes remain `unvalidated`. Existing `bypassed` fields
  remain heuristic signals for compatibility; UI labels explain the distinction.
  Method discovery no longer treats those flags alone as confirmed successes.
  Validation status, evaluator identity, and model diagnostics survive checkpoints.
- Rule generation produces unvalidated candidates. LLM generation returns a
  list-compatible `GenerationBatch` with requested model, provider-reported model
  (or null), actual generator, fallback flag, and warning. Missing model labels
  are not replaced with the requested model.
- LLM generation no longer silently falls back. `allow_rule_fallback=true` is an
  explicit API opt-in for transport failures only. HTTP policy errors, quota
  errors, malformed output, and empty output do not trigger rule fallback.
- The async LLM-generation route runs blocking HTTP in a bounded thread pool
  (two generation calls at a time), so it does not freeze the event loop. The
  underlying request still has its existing timeout; cancelling an HTTP handler
  does not forcibly interrupt Python thread execution.
- Exported generated entries are always `unvalidated`, regardless of submitted
  status. Effective-prompt selection excludes explicitly unvalidated candidates.
  They can be submitted for explicit isolated evaluation using the existing
  testing workflow. Legacy entries without a validation status are retained for
  compatibility, not retroactively certified.

## Follow-up: bounded scheduling and offline benchmark

Regular pair scans, injection scans, AutoPwn injection scans, and standalone
AutoPwn scans use `bounded_as_completed`, with at most 16 probe tasks per pair.
Queued work is represented as descriptions, not eagerly started tasks. Stop
prevents new tasks; cancellation/early iterator close cancels and drains owned
tasks and clears active-task tracking. Existing provider concurrency/RPM controls
remain in place. Multi-mode regular scans now count their actual planned work.
This is a per-pair bound, not a global cross-job limit or a provider speedup.

Run the harmless fixture benchmark:

```sh
python tests/benchmark_orchestration.py
```

One local run with 48 logical probes, 2 ms mocked request delay, and provider
concurrency four produced:

| Scenario | Mock requests | Elapsed seconds | Peak probe tasks | Tasks left |
|---|---:|---:|---:|---:|
| Regular pair | 48 | 0.1756 | 16 | 0 |
| Injection | 48 | 0.1870 | 16 | 0 |
| AutoPwn injection | 144 | 0.5564 | 16 | 0 |
| AutoPwn | 144 | 0.5566 | 16 | 0 |

The AutoPwn fixtures use two benign mock modes plus a baseline; no real attack
payload or provider call is used. OS timer resolution affects these timings.
This shows request multiplication and bounded orchestration, not live latency,
provider throughput, security effectiveness, or improvement versus an old build.

## Remaining limitations

| Area | Remaining work |
|---|---|
| Provider attribution | Scanner limiter/timeout selection still independently guesses the provider rather than sharing manager resolution for custom routes. |
| Deadlines | Provider timeout starts after queue/rate-limit acquisition; overall queue-inclusive deadlines remain absent. |
| Run status | Some outer `gather(return_exceptions=True)` results and progress/discovery errors still lack complete failure aggregation. A terminal job status is not proof that every test succeeded. |
| Budgeting | Sequential mode sweeps and optional additional sweeps still multiply requests. Accurate live request/cost budgets and cross-job scheduling need separate work. |
| Chain context | Chain history still cuts each prior message to 800 characters. |
| Exports | CSV/browser-local exports have separate response truncation behavior. |
| Output configuration | Anthropic still caps probe output at 2048 tokens despite some config entries advertising 4096. |
| Validation | A meaningful test-specific verifier and holdout evaluation are deployment responsibilities. No generic verifier can guarantee every vulnerability class. |
| Template support | AutoPwn template-specific system prompts remain unsupported rather than falsely marked evaluated. |

These limitations mean the entire platform is not fully repaired or live-tested.
No autonomous safety-evasion improvements were implemented.

## Reproduction and deployment check

1. Run `python tests/test_model_diagnostics.py -v`. Mocked HTTP-success responses
   with Claude refusal stop reasons, partial refusals, output-limit reasons, and
   ordinary adapter errors must produce explicit non-success outcomes. No harmful
   prompt or live provider is needed.
2. Run the complete offline suite below and the fixture benchmark. Cancellation
   must leave no active probe tasks or held mocked concurrency slots.
3. In the isolated deployment, restart Vexxor to load the changed code and refresh
   the browser to load the updated JavaScript. Select an exact account-authorized
   model ID and send `Reply with exactly: TEST_OK.` through the existing model-test
   UI. This operator-run live check can incur provider charges; it was not run here.
4. Capture only the sanitized outcome, stop reason, requested/dispatched model and
   provider, and reported response model. If the harmless request completes but the
   original test is blocked, that alone still does not distinguish a false positive
   from intended policy enforcement. Provider review may be necessary.
5. Do not enable fallback or retry elsewhere to work around a refusal. Preserve the
   outcome as test evidence, and use the provider's authorized verification process
   if broader testing access is required.

## Rollback

This extracted checkout has no Git metadata or automatic pre-edit source snapshot.
Before deployment, archive the currently deployed source/config and separately back
up scan and discovery data with appropriate access controls. Deploy first to the
isolated environment. To roll back, stop that deployment and restore its prior
source/config and matching pre-change data backup; retain new observations in a
separate archive. Do not delete runtime evidence or run a destructive Git reset.

New result fields are additive and old result records load with unvalidated/unknown
defaults; no destructive schema migration runs. However, older prompt-selection
code does not respect `validation_status`. Do not expose newly exported unvalidated
candidates to that older effective-prompt pool during rollback. There is deliberately
no configuration switch to turn a safety refusal into a successful finding.

## Additional local fallback review

See `FALLBACK_REVIEW.md` for the mocked refusal/timeout/rate-limit/unavailable-model
matrix, structured error classification, bounded retry assertions, same-test
terminal behavior, and explicit `not_evaluated` coverage. Blocked-only summaries
are no longer labeled clean, and unevaluated results do not count as completed
template evaluations or discovery evidence. No hosted-provider safeguard tests
were performed.

## Verification

```sh
python -m unittest discover -s tests -p 'test_*.py' -v
```

91 offline tests pass, covering the new fallback/error classification, coverage
reporting, lifecycle, provenance, validation, startup-adjacent persistence path
validation,
model-outcome, orchestration integration, and scheduling checks, plus
exact prompt forwarding, strict/default routing,
missing/unavailable providers, explicit routes, approved legacy heuristic routing,
explicit aliases, conflicting/malformed configuration, configured oversized input,
rate limits, exhausted quota, service errors, refusals, response metadata,
output-limit markers, cooldown behavior, cancellation, and nonpositive RPM.
All 64 Python source files also compile in memory. The application imports with
version 2.7.2 in the isolated test runtime after its project path is explicitly
added (the embeddable runtime intentionally does not add the current directory). The single inline JavaScript
block in `static/index.html` parses successfully using Node's `vm.Script` without
executing browser code.

The default installed Python 3.13.13 runtime is incomplete (`enum` is missing),
and the registered 3.11/3.14 executables could not be launched. Verification used
an isolated Python 3.13.7 embeddable runtime under
`%LOCALAPPDATA%\Temp\vexorr-python`, with requests and the FastAPI/PyYAML/multipart
dependencies installed there. No system Python repair or installation into a
project environment was performed. Provider SDKs were not installed in that
runtime; adapters were exercised with mocked clients. The scan route module was
imported for checkpoint tests in an empty temporary working directory, without
application startup or live inference. Full FastAPI startup, original example
scripts, live SDK compatibility, rendered browser behavior, end-to-end scans,
costs, and throughput have not been verified.
