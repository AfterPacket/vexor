"""Local fallback-policy review: harmless inputs and mocked SDKs only."""
import asyncio
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import unittest
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from core.model_results import classify_failure, response_details
from models.integrations import ModelManager, ModelResponse, OpenAIIntegration, _retry_async, _retry_sync
from orchestration_fixture import Scenario, module


class SDKError(RuntimeError):
    def __init__(self, status=None, code=None, message="fixture failure"):
        super().__init__(message)
        self.status_code = status
        self.body = {"error": {"code": code, "private_fixture": "DO_NOT_LOG_BODY"}}


def sdk_response(*, refusal=None):
    return NS(model="fixture-model", choices=[NS(
        finish_reason="stop", message=NS(content=None if refusal else "TEST_OK", refusal=refusal))])


def setup_manager(create, async_create, strict=True):
    config = {"strict_model": strict, "model_routes": {"fixture-model": "primary"}}
    adapter = OpenAIIntegration.__new__(OpenAIIntegration)
    adapter.config = config
    adapter.client = NS(chat=NS(completions=NS(create=create)))
    adapter.async_client = NS(chat=NS(completions=NS(create=async_create)))
    unused = NS(send_prompt_with_system=Mock(), send_prompt_async=AsyncMock())
    mm = ModelManager.__new__(ModelManager)
    mm.config = config
    mm.integrations = {"primary": adapter, "secondary": unused, "ollama": unused}
    mm._ollama_models, mm._ollama_cloud_models = set(), set()
    return mm, unused


class ClassificationTests(unittest.TestCase):
    def test_structured_permanent_codes_override_transient_status(self):
        for error, category in (
            (SDKError(429, "content_policy_violation"), "policy_refusal"),
            (SDKError(429, "insufficient_quota"), "quota_exhausted"),
            (SDKError(503, "invalid_api_key"), "authentication"),
            (SDKError(503, "model_not_found"), "model_unavailable"),
            (SDKError(400, "unsupported_parameter"), "unsupported_capability"),
            (SDKError(400, "context_length_exceeded"), "context_limit"),
            (SDKError(429, "permission_denied"), "permission_denied"),
            (SDKError(503, message="request timed out"), "timeout"),
            (SDKError(401, message="fixture mentions rate limit 429"), "authentication"),
        ):
            with self.subTest(category=category):
                self.assertEqual(classify_failure(error), category)

    def test_structural_refusal_overrides_optimistic_adapter_status(self):
        result = ModelResponse("Partial benign fixture", "fixture", "refusal", outcome="completed")
        details = response_details(result)
        self.assertEqual(details["outcome"], "blocked")
        self.assertEqual(details["failure_kind"], "policy_refusal")
        self.assertEqual(details["evaluation_status"], "not_evaluated")

    def test_retry_budgets_are_finite_for_sync_and_async(self):
        for status in (429, 503):
            with self.subTest(status=status):
                sync = Mock(side_effect=SDKError(status))
                with patch("models.integrations.time.sleep") as sleep:
                    with self.assertRaises(SDKError):
                        _retry_sync(sync, retries=3)
                self.assertEqual(sync.call_count, 3)
                self.assertEqual(sleep.call_count, 2)
                async_fn = AsyncMock(side_effect=SDKError(status))
                with patch("models.integrations.asyncio.sleep", new_callable=AsyncMock) as sleep:
                    with self.assertRaises(SDKError):
                        asyncio.run(_retry_async(async_fn, retries=3))
                self.assertEqual(async_fn.await_count, 3)
                self.assertEqual(sleep.await_count, 2)


class RoutingPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_failures_never_dispatch_a_secondary_provider(self):
        cases = (
            (SDKError(429, "content_policy_violation", "unsupported max_tokens"), "policy_refusal", 1),
            (SDKError(503, message="timed out"), "timeout", 1),
            (SDKError(429), "rate_limit", 3),
            (SDKError(503), "service_unavailable", 3),
            (SDKError(404, "model_not_found"), "model_unavailable", 1),
            (SDKError(401), "authentication", 1),
            (SDKError(429, "insufficient_quota"), "quota_exhausted", 1),
        )
        for strict in (True, False):
            for error, category, attempts in cases:
                with self.subTest(strict=strict, category=category):
                    sync, async_create = Mock(side_effect=error), AsyncMock(side_effect=error)
                    mm, secondary = setup_manager(sync, async_create, strict)
                    with patch("models.integrations.time.sleep"), self.assertLogs("models.integrations", level="INFO") as logs:
                        result = mm.send_prompt("Reply TEST_OK", "fixture-model")
                    details = response_details(result)
                    self.assertEqual(details["failure_kind"], category)
                    self.assertEqual(details["evaluation_status"], "not_evaluated")
                    self.assertEqual(sync.call_count, attempts)
                    for call in sync.call_args_list:
                        self.assertEqual(call.kwargs["model"], "fixture-model")
                    with patch("models.integrations.asyncio.sleep", new_callable=AsyncMock):
                        async_result = await mm.send_prompt_async("Reply TEST_OK", "fixture-model")
                    self.assertEqual(response_details(async_result)["failure_kind"], category)
                    self.assertEqual(async_create.await_count, attempts)
                    secondary.send_prompt_with_system.assert_not_called()
                    secondary.send_prompt_async.assert_not_awaited()
                    self.assertNotIn("DO_NOT_LOG_BODY", str([r.model_audit for r in logs.records]))

    async def test_http_success_refusal_is_terminal_without_retry(self):
        create, async_create = Mock(return_value=sdk_response(refusal="Fixture refusal")), AsyncMock(return_value=sdk_response(refusal="Fixture refusal"))
        mm, secondary = setup_manager(create, async_create)
        for result in (mm.send_prompt("Reply TEST_OK", "fixture-model"),
                       await mm.send_prompt_async("Reply TEST_OK", "fixture-model")):
            self.assertEqual(response_details(result)["outcome"], "blocked")
            self.assertEqual(response_details(result)["evaluation_status"], "not_evaluated")
        self.assertEqual(create.call_count, 1)
        self.assertEqual(async_create.await_count, 1)
        secondary.send_prompt_with_system.assert_not_called()
        secondary.send_prompt_async.assert_not_awaited()

    async def test_parameter_compatibility_retry_stays_on_same_model(self):
        error = SDKError(400, "unsupported_parameter", "unsupported max_tokens parameter")
        create = Mock(side_effect=[error, sdk_response()])
        mm, secondary = setup_manager(create, AsyncMock())
        result = mm.send_prompt("Reply TEST_OK", "fixture-model")
        self.assertEqual(result, "TEST_OK")
        self.assertEqual(create.call_count, 2)
        self.assertTrue(all(call.kwargs["model"] == "fixture-model" for call in create.call_args_list))
        self.assertIn("max_completion_tokens", create.call_args.kwargs)
        secondary.send_prompt_with_system.assert_not_called()


class ScanEvaluationTests(unittest.IsolatedAsyncioTestCase):
    async def test_noncompleted_requests_are_recorded_as_not_evaluated(self):
        cases = (
            (ModelResponse("[blocked] fixture", "fixture", "refusal"), None, "policy_refusal"),
            (None, SDKError(429, "content_policy_violation"), "policy_refusal"),
            (None, TimeoutError("fixture timeout"), "timeout"),
            (ModelResponse.from_error(SDKError(429)), None, "rate_limit"),
            (ModelResponse.from_error(SDKError(404, "model_not_found")), None, "model_unavailable"),
        )
        for response, error, category in cases:
            with self.subTest(category=category), Scenario(count=1) as fixture:
                fixture.prepare("regular_pair")
                fixture.scanner.override_engine = Mock()
                fixture.scanner.override_engine.wrap_prompt.side_effect = lambda text, _: text
                fixture.scanner.override_engine.get_system_injection.return_value = None
                mm = NS(send_prompt_async=AsyncMock(return_value=response, side_effect=error))
                probe = await module.Scanner._send_probe(fixture.scanner, mm, "fixture-model", "Reply TEST_OK", "llm01", "none")
                self.assertEqual(probe.evaluation_status, "not_evaluated")
                self.assertEqual(probe.model_diagnostics["failure_kind"], category)
                self.assertFalse(probe.bypassed)
                if category == "policy_refusal":
                    self.assertEqual(probe.model_diagnostics["outcome"], "blocked")
                    self.assertIsNone(probe.error)
                fixture.scanner.prompt_engine.evaluate_response.assert_not_called()
                result = module.ModelVulnResult("fixture-model", "llm01", [probe], 0, 1)
                fixture.job.results = {"fixture-model": [result]}
                serialized = fixture.job.to_dict()["results"]["fixture-model"][0]["probes"][0]
                self.assertEqual(serialized["evaluation_status"], "not_evaluated")
                mode = fixture.job.to_dict()["mode_stats"][0]
                self.assertEqual(mode["evaluation_status"], "not_evaluated")
                self.assertEqual(mode["evaluated"], 0)
                self.assertEqual(mm.send_prompt_async.await_count, 1)

    async def test_refusal_or_error_does_not_continue_automatic_mode_sequence(self):
        for kind in ("autopwn", "autopwn_injection", "regular_pair"):
            for blocked in (True, False):
                with self.subTest(kind=kind, blocked=blocked), Scenario(count=3, delay=0) as fixture:
                    runner = fixture.prepare(kind)
                    fixture.job.include_autopwn = True
                    probe = module.ProbeResult("llm01", "Benign fixture", "[blocked] fixture" if blocked else "",
                        False, "fixture_mode_a", None, 0, error=None if blocked else "fixture transport failure",
                        model_diagnostics={"outcome": "blocked" if blocked else "error"})
                    send = AsyncMock(return_value=probe)
                    fixture.scanner._send_probe = send
                    await runner(fixture.job)
                    self.assertEqual(send.await_count, 3)
                    self.assertFalse(fixture.job.active_tasks)


class CoverageReportingTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("fallback_test_reports", ROOT / "api/routes/reports.py")
        cls.routes = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.routes)

    async def check_report(self, statuses, expected):
        with Scenario(count=1) as fixture:
            fixture.prepare("regular_pair")
            probes = [module.ProbeResult("llm01", "Benign fixture", "TEST_OK" if s == "evaluated" else "[blocked] fixture",
                                         False, "none", None, 0, evaluation_status=s) for s in statuses]
            result = module.ModelVulnResult("fixture-model", "llm01", probes, 0, len(probes))
            fixture.job.results = {"fixture-model": [result]}
            request = NS(app=NS(state=NS(scan_store={fixture.job.scan_id: fixture.job})))
            report = await self.routes.get_report(fixture.job.scan_id, request)
            built = self.routes._build_report(fixture.job)
            summary = (await self.routes.get_summary(fixture.job.scan_id, request))["summary"]
        for value in (report, built):
            self.assertEqual(value.models[0].vulns[0].evaluation_status, expected)
            self.assertEqual(value.models[0].total_clean, int(expected == "evaluated"))
        return report, summary

    async def test_blocked_only_results_are_not_reported_clean(self):
        report, summary = await self.check_report(["not_evaluated"], "not_evaluated")
        self.assertEqual(report.models[0].total_not_evaluated, 1)
        self.assertIn("NOT_EVALUATED", summary)
        self.assertNotIn("clean", summary)

    async def test_mixed_coverage_is_partial_not_clean(self):
        report, summary = await self.check_report(["evaluated", "not_evaluated"], "partial")
        self.assertEqual(report.models[0].total_partial, 1)
        self.assertEqual(report.models[0].vulns[0].evaluated_probes, 1)
        self.assertEqual(report.models[0].vulns[0].not_evaluated_probes, 1)
        self.assertIn("PARTIAL", summary)
        self.assertNotIn("clean", summary)

    async def test_completed_benign_evaluation_retains_evaluated_status(self):
        report, summary = await self.check_report(["evaluated"], "evaluated")
        self.assertEqual(report.models[0].total_not_evaluated, 0)
        self.assertIn("clean", summary)


if __name__ == "__main__":
    unittest.main()
