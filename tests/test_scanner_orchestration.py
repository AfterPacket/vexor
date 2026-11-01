"""Exercise existing scan runners with benign inputs and mocked provider calls."""
import asyncio
from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, Mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestration_fixture import Scenario, module
from models.integrations import ModelResponse


class OrchestrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_runners_bound_tasks_and_preserve_logical_results(self):
        for kind in ("regular_pair", "injection", "autopwn_injection", "autopwn"):
            with self.subTest(kind=kind), Scenario(count=24, delay=0, concurrency=3) as fixture:
                runner = fixture.prepare(kind)
                with redirect_stdout(io.StringIO()):
                    await runner(fixture.job)
                result = fixture.job.results["fixture-model"][0]
                self.assertEqual(len(result.probes), 24)
                self.assertEqual(result.total_probes, 24)
                self.assertEqual(fixture.calls, 72 if "autopwn" in kind else 24)
                self.assertLessEqual(fixture.peak_tasks, 16)
                self.assertLessEqual(fixture.peak_inflight, 3)
                self.assertFalse(fixture.job.active_tasks)
                self.assertEqual(fixture.inflight, 0)

    async def test_cancellation_stops_queued_work_and_releases_slots(self):
        for kind in ("regular_pair", "injection", "autopwn_injection", "autopwn"):
            with self.subTest(kind=kind), Scenario(count=100, delay=1, concurrency=2) as fixture:
                runner = fixture.prepare(kind)
                with redirect_stdout(io.StringIO()):
                    run = asyncio.create_task(runner(fixture.job))
                    while fixture.calls == 0:
                        await asyncio.sleep(0)
                    fixture.job.cancelled = True
                    for task in list(fixture.job.active_tasks):
                        task.cancel()
                    await asyncio.wait_for(run, timeout=1)
                self.assertFalse(fixture.job.active_tasks)
                self.assertEqual(fixture.inflight, 0)
                self.assertLessEqual(fixture.calls, 2)
                # All cancelled callers released the provider's semaphore slots.
                self.assertEqual(fixture.limiter.semaphore._value, 2)

    async def test_template_outcomes_are_tied_to_completed_regular_probes(self):
        with Scenario(count=2, delay=0) as fixture:
            fixture.store.save_synthesized_templates([{
                "template_id": "fixture-template", "prefix": "Benign prefix {goal}", "confidence": 0.5}])
            runner = fixture.prepare("regular_pair")
            await runner(fixture.job)
            template = fixture.store.get_synthesized_templates()[0]
            self.assertEqual(template["completed_evaluations"], 2)
            self.assertTrue(template["tested"])
            self.assertEqual(template["validation_status"], "unvalidated")

    async def test_sweep_does_not_claim_ignored_system_templates_were_evaluated(self):
        with Scenario(count=2, delay=0) as fixture:
            fixture.store.save_synthesized_templates([{
                "template_id": "fixture-template", "prefix": "Benign prefix {goal}",
                "system_prompt": "Benign test-only instruction", "confidence": 0.5}])
            runner = fixture.prepare("autopwn")
            with redirect_stdout(io.StringIO()):
                await runner(fixture.job)
            template = fixture.store.get_synthesized_templates()[0]
            self.assertFalse(template["tested"])
            self.assertEqual(template["completed_evaluations"], 0)

    async def test_multimode_total_counts_actual_planned_work(self):
        with Scenario(count=3, delay=0) as fixture:
            runner = fixture.prepare("regular_pair")
            fixture.job.override_modes = ["fixture_mode_a", "fixture_mode_b"]
            await runner(fixture.job)
            result = fixture.job.results["fixture-model"][0]
            self.assertEqual(result.total_probes, 6)
            self.assertEqual(len(result.probes), 6)

    async def test_blocked_incomplete_and_empty_do_not_become_findings(self):
        for response in (ModelResponse("[blocked] fixture", "reported-fixture", "refusal"),
                         ModelResponse("partial", "reported-fixture", "max_tokens"),
                         ModelResponse("", "reported-fixture", "end_turn")):
            with self.subTest(response=str(response)), Scenario(count=1) as fixture:
                fixture.prepare("regular_pair")
                fixture.scanner.override_engine = Mock()
                fixture.scanner.override_engine.wrap_prompt.side_effect = lambda text, _: text
                fixture.scanner.override_engine.get_system_injection.return_value = None
                fixture.scanner.prompt_engine.evaluate_response.return_value = True
                fixture.scanner.independent_validator = Mock()
                mm = Mock(send_prompt_async=AsyncMock(return_value=response))
                result = await module.Scanner._send_probe(fixture.scanner, mm, "fixture-model", "Benign fixture", "llm01", "none")
                self.assertFalse(result.bypassed)
                self.assertEqual(result.validation_status, "inconclusive")
                self.assertEqual(result.model_diagnostics["reported_model"], "reported-fixture")
                fixture.scanner.independent_validator.assert_not_called()
                self.assertEqual(mm.send_prompt_async.await_count, 1)


if __name__ == "__main__":
    unittest.main()
