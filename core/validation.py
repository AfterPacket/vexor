"""Independent, server-configured validation of completed observations.

A heuristic classification is not validation. Validators must check a trusted,
test-specific outcome (e.g. an application-owned canary), not simply repeat the
scanner's classifier. Never register validators supplied by an HTTP request.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ValidationObservation:
    model: str
    vulnerability: str
    prompt: str
    response: str
    heuristic_positive: bool


@dataclass(frozen=True)
class ValidationDecision:
    passed: bool
    evaluator: str


def has_independent_verdict(probe):
    """Require completed, independently attributed evidence; ignore legacy counters."""
    evaluator = getattr(probe, "validation_evaluator", None)
    return bool(
        getattr(probe, "validation_status", None) in ("validated", "rejected")
        and isinstance(evaluator, str) and evaluator.strip()
        and getattr(probe, "evaluation_status", None) == "evaluated"
        and not probe.error and (probe.response or "").strip()
        and getattr(probe, "model_diagnostics", {}).get("outcome") in (None, "completed")
        and "[blocked]" not in probe.response and "[incomplete]" not in probe.response
    )


def is_confirmed_finding(probe):
    return getattr(probe, "validation_status", None) == "validated" and has_independent_verdict(probe)


def validate_observation(model, probe, validator=None):
    """Attach independent evaluation status; never alter heuristic bypass flags."""
    probe.validation_status = "unvalidated"
    probe.validation_evaluator = None
    if (getattr(probe, "evaluation_status", "not_evaluated") != "evaluated"
            or getattr(probe, "model_diagnostics", {}).get("outcome") not in (None, "completed")
            or probe.error or not probe.response or any(
        marker in probe.response for marker in ("[blocked]", "[incomplete]")
    )):
        probe.validation_status = "inconclusive"
        return probe
    if validator is None:
        return probe
    observation = ValidationObservation(model, probe.vulnerability, probe.prompt,
                                        str(probe.response), probe.bypassed)
    try:
        decision = validator(observation)
        if (not isinstance(decision, ValidationDecision) or not isinstance(decision.passed, bool)
                or not isinstance(decision.evaluator, str) or not decision.evaluator.strip()):
            raise ValueError("Invalid independent validation decision")
        probe.validation_status = "validated" if decision.passed else "rejected"
        probe.validation_evaluator = decision.evaluator
    except Exception:
        # Never expose evaluator exception text: it can contain sensitive data.
        probe.validation_status = "inconclusive"
    return probe
