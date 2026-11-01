"""Attribute template outcomes only after the corresponding operation settles."""
import asyncio

from core.validation import is_confirmed_finding


async def observe_template(store, template_id, operation):
    if not template_id:
        return await operation()
    try:
        result = await operation()
    except asyncio.CancelledError:
        store.record_template_evaluation(template_id, outcome="cancelled")
        raise
    except Exception:
        store.record_template_evaluation(template_id, outcome="error")
        raise
    response = result.response or ""
    if result.error or response.startswith("Error:"):
        outcome = "error"
    elif (getattr(result, "evaluation_status", "not_evaluated") != "evaluated"
          or not response or "[incomplete]" in response):
        outcome = "inconclusive"
    else:
        outcome = "completed"
    store.record_template_evaluation(
        template_id, outcome=outcome,
        heuristic_positive=bool(result.bypassed) and "[blocked]" not in response,
        independently_validated=is_confirmed_finding(result),
    )
    return result
