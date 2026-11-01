"""Discovery bookkeeping tests using only benign fixtures and mocked generators."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.failure_store import FailureStore
from core.template_evaluation import observe_template
from core.validation import ValidationDecision, validate_observation

# Empty cwd prevents module-level PromptEngine objects from reading local data.
_previous = Path.cwd()
with tempfile.TemporaryDirectory() as _empty:
    try:
        os.chdir(_empty)
        from core.synthetic_data import GenerationBatch, GenerationError, SyntheticDataGenerator
        from core.prompt_engine import PromptEngine
        from core.scanner import ProbeResult
    finally:
        os.chdir(_previous)


def observation(text="Benign test response", *, error=None, positive=False):
    return ProbeResult("llm01", "Benign fixture", text, positive, "none", None, 1.0,
                       error=error, evaluation_status="evaluated")


class TemplateLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = FailureStore(str(Path(self.directory.name) / "store.json"))
        self.store.save_synthesized_templates([{"template_id": "candidate", "confidence": 0.5,
                                               "tested": True, "validation_status": "validated"}])

    def template(self):
        return self.store.get_synthesized_templates()[0]

    async def test_scheduling_is_not_completion(self):
        started, release = asyncio.Event(), asyncio.Event()
        async def worker():
            started.set()
            await release.wait()
            return observation(positive=True)
        task = asyncio.create_task(observe_template(self.store, "candidate", worker))
        await started.wait()
        self.assertFalse(self.template()["tested"])
        self.assertEqual(self.template()["validation_status"], "unvalidated")
        release.set()
        await task
        self.assertTrue(self.template()["tested"])
        self.assertEqual(self.template()["completed_evaluations"], 1)
        self.assertEqual(self.template()["validation_status"], "unvalidated")

    async def test_error_cancel_and_incomplete_do_not_mark_tested(self):
        async def error():
            raise RuntimeError("fixture failure")
        with self.assertRaises(RuntimeError):
            await observe_template(self.store, "candidate", error)
        async def cancelled():
            raise asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):
            await observe_template(self.store, "candidate", cancelled)
        for result in (observation(error="timeout"), observation(""),
                       observation("partial [incomplete]")):
            async def worker():
                return result
            await observe_template(self.store, "candidate", worker)
        self.assertFalse(self.template()["tested"])
        self.assertEqual(self.template()["error_evaluations"], 2)
        self.assertEqual(self.template()["cancelled_evaluations"], 1)
        self.assertEqual(self.template()["inconclusive_evaluations"], 2)

    async def test_rate_is_fraction_and_independent_validation_is_separate(self):
        for positive in (True, False):
            async def worker():
                return observation(positive=positive)
            await observe_template(self.store, "candidate", worker)
        self.assertEqual(self.template()["bypass_rate"], 0.5)
        self.assertEqual(self.template()["validated_positive_count"], 0)
        async def independently_checked():
            return validate_observation("fixture-model", observation(),
                lambda _: ValidationDecision(True, "fixture-canary-check"))
        await observe_template(self.store, "candidate", independently_checked)
        self.assertEqual(self.template()["validation_status"], "validated")

    async def test_blocked_not_evaluated_result_does_not_mark_template_tested(self):
        async def worker():
            result = observation("[blocked] Fixture refusal")
            result.evaluation_status = "not_evaluated"
            return result
        await observe_template(self.store, "candidate", worker)
        self.assertFalse(self.template()["tested"])
        self.assertEqual(self.template()["inconclusive_evaluations"], 1)
        self.assertEqual(self.template()["completed_evaluations"], 0)

    async def test_legacy_tested_flag_without_evidence_is_not_trusted(self):
        self.store._data["synthesized_templates"]["legacy"] = {
            "template_id": "legacy", "confidence": 0.5, "tested": True}
        candidates = self.store.get_synthesized_templates(untested_only=True)
        self.assertIn("legacy", [t["template_id"] for t in candidates])
        self.assertTrue(all(not t["tested"] for t in candidates))


class IndependentValidationTests(unittest.TestCase):
    def test_heuristic_positive_is_not_validation(self):
        probe = validate_observation("fixture", observation(positive=True))
        self.assertEqual(probe.validation_status, "unvalidated")

    def test_trusted_test_specific_validator_receives_immutable_observation(self):
        def verifier(obs):
            self.assertEqual(obs.model, "fixture")
            with self.assertRaises(AttributeError):
                obs.response = "changed"
            return ValidationDecision(obs.response == "TEST_OK", "exact-fixture-check")
        probe = validate_observation("fixture", observation("TEST_OK"), verifier)
        self.assertEqual(probe.validation_status, "validated")
        self.assertEqual(probe.validation_evaluator, "exact-fixture-check")
        self.assertFalse(probe.bypassed)

    def test_false_exception_and_invalid_decisions_are_not_validation(self):
        self.assertEqual(validate_observation("m", observation(),
            lambda _: ValidationDecision(False, "fixture-check")).validation_status, "rejected")
        def broken(_):
            raise ValueError("sensitive fixture detail")
        for verifier in (broken, lambda _: True, lambda _: ValidationDecision(True, "")):
            result = validate_observation("m", observation(), verifier)
            self.assertEqual(result.validation_status, "inconclusive")
            self.assertIsNone(result.validation_evaluator)

    def test_discovery_does_not_promote_heuristic_positives_to_confirmed_successes(self):
        from core.method_discovery import MethodDiscoveryEngine
        store = Mock()
        store.save_synthesized_templates.return_value = 0
        engine = MethodDiscoveryEngine(store=store)
        engine._extract_and_record_signature = Mock()
        engine._update_refusal_clusters = Mock()
        engine._update_transfer_matrix = Mock()
        engine._compute_scan_deltas = Mock()
        engine.synthesize_novel_methods = Mock(return_value=[])
        heuristic = observation(positive=True)
        confirmed = validate_observation("fixture", observation(),
            lambda _: ValidationDecision(True, "fixture-check"))
        blocked = observation("[blocked] Fixture refusal")
        blocked.evaluation_status = "not_evaluated"
        job = NS(status=NS(value="completed"), results={"fixture": [NS(probes=[heuristic, confirmed, blocked])]})
        engine.analyze_completed_scan(job)
        entries = [call.args[0] for call in engine._extract_and_record_signature.call_args_list]
        self.assertEqual(len(entries), 2)
        self.assertFalse(entries[0]["bypassed"])
        self.assertTrue(entries[1]["bypassed"])
        self.assertTrue(entries[0]["heuristic_positive"])

    def test_errors_blocks_and_incomplete_outputs_do_not_reach_validator(self):
        verifier = Mock(return_value=ValidationDecision(True, "fixture-check"))
        for result in (observation(""), observation(error="timeout"),
                       observation("[blocked] fixture"), observation("[incomplete] fixture")):
            self.assertEqual(validate_observation("m", result, verifier).validation_status, "inconclusive")
        verifier.assert_not_called()


class GenerationProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.gen = SyntheticDataGenerator()
        self.gen._apply_complexity = Mock(side_effect=lambda text, *_: (text, []))
        self.fixture = "A harmless generated fixture long enough to pass the existing length filter."

    def response(self, **extra):
        response = Mock()
        response.json.return_value = {"model": "reported-fixture-model", "message": {"content": self.fixture}, **extra}
        return response

    def test_success_reports_provider_label_and_unvalidated_candidates(self):
        with patch("requests.post", return_value=self.response()):
            result = self.gen.llm_generate("llm01", "Benign fixture", model="requested-fixture", complexity=1)
        self.assertEqual(result.requested_model, "requested-fixture")
        self.assertEqual(result.model_used, "reported-fixture-model")
        self.assertFalse(result.fallback_used)
        self.assertEqual(result[0]["validation_status"], "unvalidated")

    def test_no_reported_model_is_unknown_not_assumed(self):
        with patch("requests.post", return_value=self.response(model=None)):
            result = self.gen.llm_generate("llm01", "Benign fixture", complexity=1)
        self.assertIsNone(result.model_used)

    def test_transport_failure_requires_explicit_fallback_consent(self):
        import requests
        with patch("requests.post", side_effect=requests.ConnectionError("sensitive-detail")):
            with self.assertRaises(GenerationError) as raised:
                self.gen.llm_generate("llm01", "Benign fixture", complexity=1)
            self.assertNotIn("sensitive-detail", str(raised.exception))
            with patch.object(self.gen, "generate", return_value=[{"prompt": "benign", "complexity": 1}]):
                result = self.gen.llm_generate("llm01", "Benign fixture", complexity=1, allow_rule_fallback=True)
        self.assertTrue(result.fallback_used)
        self.assertEqual(result.generator, "rule_based")
        self.assertIsNone(result.model_used)
        self.assertTrue(result.warning)
        self.assertEqual(result[0]["source"], "rule_based")

    def test_http_errors_and_empty_output_never_trigger_fallback(self):
        import requests
        for failure in (requests.HTTPError("403 policy"), requests.HTTPError("429 quota"),
                        requests.HTTPError("503 unavailable")):
            with patch("requests.post", side_effect=failure), patch.object(self.gen, "generate") as fallback:
                with self.assertRaises(GenerationError):
                    self.gen.llm_generate("llm01", "Benign fixture", allow_rule_fallback=True)
                fallback.assert_not_called()
        response = self.response(message={"content": ""})
        with patch("requests.post", return_value=response), patch.object(self.gen, "generate") as fallback:
            with self.assertRaises(GenerationError):
                self.gen.llm_generate("llm01", "Benign fixture", allow_rule_fallback=True)
            fallback.assert_not_called()

    def test_export_cannot_self_certify_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixtures.json"
            count = self.gen.export_to_exploits([
                {"prompt": "Benign generated candidate", "vulnerability": "llm01", "complexity": 1,
                 "validation_status": "validated"}], model_key="fixture", exploits_path=str(path))
            engine = PromptEngine(str(path))
            self.assertEqual(engine._effective_prompts_for("fixture", "llm01"), [])
            record = json.loads(path.read_text(encoding="utf-8"))["effective_prompts"]["fixture"]["llm01"][0]
        self.assertEqual(count, 1)
        self.assertEqual(record["validation_status"], "unvalidated")
        self.assertEqual(record["success_rate"], 0)


if __name__ == "__main__":
    unittest.main()
