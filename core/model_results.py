"""Sanitized model-call diagnostics, independent of provider SDKs."""
import re


def classify_failure(error):
    """Classify errors without recording their contents or exposing their body.

    Explicit permanent/policy codes take precedence over an HTTP retry status.
    Message matching supports legacy string adapters; it is not proof of policy.
    """
    status = getattr(error, "status_code", None)
    body = getattr(error, "body", None)
    nested = body.get("error", body) if isinstance(body, dict) else {}
    nested = nested if isinstance(nested, dict) else {}
    codes = {str(v).lower() for v in (
        getattr(error, "code", None), nested.get("code"), nested.get("type"),
    ) if v is not None}
    permanent_codes = (
        ({"content_policy_violation", "policy_violation", "content_filter", "safety_refusal"}, "policy_refusal"),
        ({"insufficient_quota", "quota_exceeded", "billing_hard_limit_reached"}, "quota_exhausted"),
        ({"invalid_api_key", "authentication_error"}, "authentication"),
        ({"permission_denied", "permission_error"}, "permission_denied"),
        ({"context_length_exceeded"}, "context_limit"),
        ({"model_not_found", "model_unavailable"}, "model_unavailable"),
        ({"unsupported_parameter", "unsupported_value"}, "unsupported_capability"),
    )
    for known_codes, category in permanent_codes:
        if codes & known_codes:
            return category
    if status == 401:
        return "authentication"
    message = str(error).lower()
    if any(word in message for word in (
        "refusal", "content_filter", "content filter", "content policy", "safety",
        "prohibited content", "blocked", "flagged by",
    )):
        return "policy_refusal"
    if any(word in message for word in (
        "insufficient_quota", "quota exceeded", "quota exhausted", "billing", "credit", "payment",
    )):
        return "quota_exhausted"
    if (isinstance(error, TimeoutError) or "timeout" in type(error).__name__.lower()
            or "timed out" in message or "timeout" in message or status in (408, 504)):
        return "timeout"
    if any(word in message for word in ("authentication", "invalid api key", "invalid_api_key")):
        return "authentication"
    if status == 403 or any(word in message for word in ("permission", "entitlement")):
        return "permission_denied"
    if any(word in message for word in ("context_length", "context window", "too many tokens")):
        return "context_limit"
    if status == 404 or any(word in message for word in (
        "model not found", "model unavailable", "provider unavailable", "is unavailable",
    )):
        return "model_unavailable"
    if "unsupported" in message or "not supported" in message:
        return "unsupported_capability"
    if any(word in message for word in (
        "strict_model", "model_routes", "model_aliases", "no configured integration",
        "unknown model route", "conflicting model providers",
    )):
        return "configuration_error"
    if status is not None:
        return {429: "rate_limit", 503: "service_unavailable"}.get(status, "provider_error")
    if codes & {"rate_limit_exceeded", "rate_limit_error"} or "rate limit" in message or re.search(r"\b429\b", message):
        return "rate_limit"
    if codes & {"overloaded_error"} or "overloaded" in message or re.search(r"\b503\b", message):
        return "service_unavailable"
    for number, category in ((401, "authentication"), (403, "permission_denied"),
                             (404, "model_unavailable")):
        if re.search(rf"\b{number}\b", message):
            return category
    return "provider_error"


def terminal_execution_result(probe):
    """Do not continue an automatic same-test mode/fallback sequence after a block or error."""
    diagnostics = getattr(probe, "model_diagnostics", {})
    return bool(probe.error) or diagnostics.get("outcome") == "blocked" or (
        diagnostics.get("failure_kind") == "policy_refusal"
    ) or (probe.response or "").startswith("[blocked]")


def response_details(response):
    """Return labels and generation eligibility, not a vulnerability verdict.

    Different response labels can be snapshot aliases, not proof of switching.
    Legacy string adapters provide inferred status and unknown model metadata.
    """
    reason = getattr(response, "finish_reason", None)
    outcome = getattr(response, "outcome", None)
    # Structural refusal/stop signals override optimistic adapter outcomes.
    if reason in ("refusal", "content_filter"):
        outcome = "blocked"
    elif reason in ("length", "max_tokens") and outcome != "blocked":
        outcome = "incomplete"
    if outcome is None:
        if response.startswith("Error:"):
            outcome = "error"
        elif response.startswith("[blocked]"):
            outcome = "blocked"
        elif "[incomplete]" in response:
            outcome = "incomplete"
        elif not response.strip():
            outcome = "empty"
        else:
            outcome = "completed"
    failure_kind = getattr(response, "failure_kind", None)
    if outcome == "blocked":
        failure_kind = "policy_refusal"
    elif failure_kind is None:
        failure_kind = {"incomplete": "output_limit", "empty": "empty_response"}.get(outcome)
        if outcome == "error":
            failure_kind = classify_failure(response)
    dispatch = getattr(response, "request_metadata", {})
    reported = getattr(response, "reported_model", None)
    dispatched = dispatch.get("dispatched_model")
    return {
        "requested_model": dispatch.get("requested_model"),
        "requested_provider": dispatch.get("requested_provider"),
        "dispatched_provider": dispatch.get("dispatched_provider"),
        "dispatched_model": dispatched,
        "reported_model": reported,
        "finish_reason": reason,
        "outcome": outcome,
        "failure_kind": failure_kind,
        "evaluation_status": "ready_for_evaluation" if outcome == "completed" else "not_evaluated",
        "reported_model_differs": (reported != dispatched) if reported and dispatched else None,
    }
