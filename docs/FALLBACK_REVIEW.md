# Local fallback-handling review

## Scope

This review uses harmless fixtures and mocked SDK/provider responses only. No
endpoint URL is required, no local server was started, and no live provider calls
or safeguard-bypass testing were performed. It establishes software classification,
routing, retry, and reporting behavior, not model-level behavior or provider
permission/capability. The repository has no Git metadata.

## Confirmed implementation defects and changes

1. **Missing evaluation eligibility.** Blocked generations previously had a blocked
   outcome but no explicit `not_evaluated` status. Probe records, checkpoints, API
   schemas, and diagnostics now retain evaluation status. Generation-only model
   checks return `ready_for_evaluation` for complete responses, not a claim that a
   vulnerability assessment ran. The scanner sets `evaluated` only when a complete
   usable response reaches its heuristic evaluator. Independent validation remains
   a separate status.
2. **Error categories collapsed.** `classify_failure` now distinguishes policy
   refusals, timeouts, rate limits, overload, exhausted quota, authentication,
   permissions, model unavailability, unsupported capabilities, context limits,
   and configuration errors. Structured permanent/policy codes take precedence
   over transient HTTP status. OpenAI and Anthropic adapters preserve the category
   across their string-compatible error responses and dispatch audit copy.
3. **Compatibility retry could repeat a refusal.** OpenAI's parameter retry used
   broad message matching, so an error mentioning `max_tokens` could trigger an
   additional request even when its structured code indicated a policy refusal.
   That retry is now limited to an unsupported-capability/parameter error and
   remains on the exact same model. Refusals, auth, quota, and timeout errors do
   not enter it.
4. **Automatic same-test sequences continued after blocks/errors.** Automatic
   mode sequences now terminate on a blocked or errored result rather than trying
   more modes and a baseline for the same logical test. The optional extra sweep
   excludes previously blocked/errored tests. Explicit separately configured
   multi-mode test cases remain separate test executions; this is not a global
   prohibition on every subsequent authorized test.
5. **Coverage could be reported as clean.** Model/vulnerability summaries now
   distinguish `evaluated`, `partial`, and `not_evaluated`. A blocked-only result
   is not counted in `total_clean`, and executive summaries say `NOT_EVALUATED`
   instead of `clean`. Mixed coverage is partial. Mode summaries expose evaluated
   and not-evaluated counts rather than labeling blocked-only attempts failed.
6. **Unevaluated results could reach discovery bookkeeping.** Template completion,
   method discovery, delta scoring, and independent verification now exclude
   results marked not evaluated. A blocked attempt is inconclusive for template
   completion, not evidence that the intended vulnerability test completed.

## Local test matrix

The routing tests register an explicit primary and an unused secondary/local
integration. Both strict and legacy selection modes are exercised with that
explicit route. Every actual SDK invocation is a mock receiving benign text.

| Fixture | Classification | Attempts | Secondary dispatch | Evaluation |
|---|---|---:|---|---|
| HTTP-success refusal | blocked / policy_refusal | 1 | none | not_evaluated |
| Structured policy code with misleading parameter-error wording | blocked / policy_refusal | 1 | none | not_evaluated |
| Timeout, including text containing 503 | error / timeout | 1 | none | not_evaluated |
| Persistent 429 rate limit | error / rate_limit | 3 | none | not_evaluated |
| Persistent 503 overload | error / service_unavailable | 3 | none | not_evaluated |
| 429 with exhausted-quota code | error / quota_exhausted | 1 | none | not_evaluated |
| Unavailable model | error / model_unavailable | 1 | none | not_evaluated |
| Authentication failure | error / authentication | 1 | none | not_evaluated |
| Genuine parameter compatibility error, then success | completed | 2, same model | none | ready_for_evaluation |

Additional tests cover structured permission/context/unsupported errors, refusal
precedence over an optimistic adapter outcome, checkpoint round trips, exclusion
from discovery/validation, and blocked/partial/completed report coverage. Temporary
SDK error-body data is not included in audit metadata.

## Reproduction

From the repository root:

```sh
python tests/test_fallback_handling.py -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

The complete offline suite passes **91 tests**. All **64 Python files** compile,
and the single inline JavaScript block parses without executing browser code.
The machine's default Python installation is incomplete; verification used the
isolated runtime documented in `RELIABILITY_AUDIT.md`.

## Interpretation and limitations

- Keep `strict_model: true` and explicit provider routes for predictable dispatch.
  No error-time cross-model/provider fallback was added. Legacy routing can still
  select an initially guessed provider; the explicit-route tests do not certify
  every possible legacy configuration.
- `evaluated` means a usable response was assessed, not independent confirmation
  of a vulnerability. `not_evaluated` means no eligible evaluation evidence under
  the current criteria. Old records lacking the field default conservatively to
  not evaluated; they are not retroactively certified.
- Existing attempt-based `bypass_rate` and `total_probes` fields are retained for
  compatibility. They are not completion-coverage metrics. Use evaluation status
  and coverage counts, including planned work, when interpreting them.
- Adapters still returning plain legacy strings provide inferred classifications
  and may lose structured provider details. SDK-specific/live behavior is untested.
- Coarse job-level failure aggregation, global cross-job deadlines, and complete
  Retry-After propagation remain separate limitations. A job's terminal status is
  not proof that every individual test was evaluated.
- No client-side override of provider enforcement exists or is claimed here.

For deployment checks, evidence handling, and rollback instructions, see
`RELIABILITY_AUDIT.md`. No production data migration or provider configuration
change was performed by these tests.
