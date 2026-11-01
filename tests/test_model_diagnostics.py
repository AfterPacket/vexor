"""Regression coverage for HTTP-success/provider-refusal and routing diagnostics."""
import asyncio
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.model_results import response_details
from models.integrations import ModelResponse, _chat_result, _claude_result


def load_route(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DiagnosticTests(unittest.TestCase):
    def test_partial_anthropic_refusal_is_blocked_not_completed(self):
        result = _claude_result(NS(content=[NS(type="text", text="Partial fixture output")],
                                   stop_reason="refusal", model="reported-fixture"))
        details = response_details(result)
        self.assertEqual(details["outcome"], "blocked")
        self.assertEqual(details["finish_reason"], "refusal")
        self.assertIn("Partial fixture output", result)
        self.assertIn("[blocked]", result)

    def test_partial_openai_filter_and_refusal_are_blocked(self):
        for reason, refusal in (("content_filter", None), ("stop", "refused")):
            result = _chat_result(NS(model="fixture", choices=[NS(
                finish_reason=reason, message=NS(content="Partial fixture", refusal=refusal))]))
            self.assertEqual(response_details(result)["outcome"], "blocked")
            self.assertIn("Partial fixture", result)

    def test_unknown_metadata_is_not_invented(self):
        details = response_details("Plain fixture response")
        self.assertEqual(details["outcome"], "completed")
        self.assertIsNone(details["reported_model"])
        self.assertIsNone(details["reported_model_differs"])

    def test_model_label_difference_is_descriptive_not_a_downgrade_claim(self):
        result = ModelResponse("ok", "snapshot", "stop", request_metadata={
            "requested_model": "alias", "dispatched_model": "alias", "dispatched_provider": "fixture"})
        details = response_details(result)
        self.assertTrue(details["reported_model_differs"])
        self.assertEqual(details["outcome"], "completed")
        self.assertNotIn("downgraded", details)


class ModelEndpointTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.routes = load_route("diagnostic_test_models", "api/routes/models.py")

    async def test_errors_refusals_limits_and_empty_are_not_success(self):
        cases = [
            ("Error: Requested provider unavailable", "error"),
            (_claude_result(NS(content=[], stop_reason="refusal", model="fixture")), "blocked"),
            (ModelResponse("partial", "fixture", "max_tokens"), "incomplete"),
            (ModelResponse("", "fixture", "end_turn"), "empty"),
        ]
        for response, outcome in cases:
            with self.subTest(outcome=outcome):
                mm = NS(send_prompt_async=AsyncMock(return_value=response))
                with patch.object(self.routes, "_get_mm", return_value=mm):
                    result = await self.routes.test_model(self.routes.ModelTestRequest(model="fixture"))
                self.assertFalse(result.success)
                self.assertEqual(result.outcome, outcome)
                self.assertTrue(result.error)
                self.assertEqual(mm.send_prompt_async.await_count, 1)

    async def test_normal_result_exposes_sanitized_dispatch_metadata(self):
        response = ModelResponse("TEST_OK", "reported-fixture", "stop", request_metadata={
            "requested_model": "fixture", "dispatched_provider": "openai", "dispatched_model": "fixture"})
        with patch.object(self.routes, "_get_mm", return_value=NS(send_prompt_async=AsyncMock(return_value=response))):
            result = await self.routes.test_model(self.routes.ModelTestRequest(model="fixture"))
        self.assertTrue(result.success)
        self.assertEqual(result.requested_model, "fixture")
        self.assertEqual(result.dispatched_provider, "openai")
        self.assertEqual(result.reported_model, "reported-fixture")
        self.assertTrue(result.reported_model_differs)

    async def test_connectivity_probe_does_not_report_error_strings_as_success(self):
        mm = NS(send_prompt_async=AsyncMock(return_value="Error: provider unavailable"))
        with patch.object(self.routes, "_get_mm", return_value=mm):
            result = await self.routes.probe_model("fixture")
        self.assertFalse(result.success)
        self.assertEqual(result.outcome, "error")

    async def test_exception_detail_is_not_returned(self):
        mm = NS(send_prompt_async=AsyncMock(side_effect=RuntimeError("sensitive fixture detail")))
        with patch.object(self.routes, "_get_mm", return_value=mm):
            result = await self.routes.test_model(self.routes.ModelTestRequest(model="fixture"))
        self.assertEqual(result.outcome, "error")
        self.assertNotIn("sensitive fixture detail", result.error)


class SyntheticEndpointTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                cls.routes = load_route("diagnostic_test_synthetic", "api/routes/synthetic.py")
            finally:
                os.chdir(previous)

    async def test_endpoint_reports_actual_generator_and_fallback(self):
        from core.synthetic_data import GenerationBatch
        batch = GenerationBatch([{"prompt": "Benign fixture"}], requested_model="requested-fixture",
                                generator="rule_based", fallback_used=True, warning="Transport fallback fixture")
        with patch.object(self.routes._gen, "llm_generate", return_value=batch):
            response = await self.routes.generate_with_llm(self.routes.LLMGenerateRequest(
                vulnerability="llm01", base_prompt="Benign fixture", allow_rule_fallback=True))
        self.assertEqual(response["generator"], "rule_based")
        self.assertIsNone(response["model_used"])
        self.assertTrue(response["fallback_used"])
        self.assertEqual(response["validation_status"], "unvalidated")

    async def test_generator_failure_is_explicit_not_fake_success(self):
        from core.synthetic_data import GenerationError
        from fastapi import HTTPException
        with patch.object(self.routes._gen, "llm_generate", side_effect=GenerationError("fixture failure")):
            with self.assertRaises(HTTPException) as raised:
                await self.routes.generate_with_llm(self.routes.LLMGenerateRequest(
                    vulnerability="llm01", base_prompt="Benign fixture"))
        self.assertEqual(raised.exception.status_code, 502)

    async def test_blocking_generation_does_not_block_event_loop(self):
        import threading
        from core.synthetic_data import GenerationBatch
        started, release = threading.Event(), threading.Event()
        loop_thread = threading.get_ident()
        def generator(**kwargs):
            self.assertNotEqual(threading.get_ident(), loop_thread)
            started.set()
            if not release.wait(2):
                raise RuntimeError("fixture deadline")
            return GenerationBatch([], requested_model=kwargs["model"])
        with patch.object(self.routes._gen, "llm_generate", side_effect=generator):
            task = asyncio.create_task(self.routes.generate_with_llm(self.routes.LLMGenerateRequest(
                vulnerability="llm01", base_prompt="Benign fixture")))
            try:
                async def wait_started():
                    while not started.is_set():
                        await asyncio.sleep(0.001)
                await asyncio.wait_for(wait_started(), timeout=1)
                await asyncio.sleep(0.01)
                self.assertFalse(task.done())
            finally:
                release.set()
                await task


if __name__ == "__main__":
    unittest.main()
