"""Offline checkpoint tests using temporary files and benign synthetic records."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.persistence import atomic_write_json


class AtomicWriteTests(unittest.TestCase):
    def test_creates_parent_and_roundtrips_unicode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "scan.json"
            atomic_write_json(path, {"response": "hello \u2603"})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"response": "hello \u2603"})
            self.assertEqual(list(path.parent.glob("*.tmp")), [])

    def test_failed_serialization_keeps_previous_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.json"
            atomic_write_json(path, {"version": 1})
            for invalid in (object(), float("nan")):
                with self.subTest(invalid=type(invalid).__name__):
                    with self.assertRaises((ValueError, TypeError)):
                        atomic_write_json(path, {"bad": invalid})
                    self.assertEqual(json.loads(path.read_text()), {"version": 1})
                    self.assertEqual(list(path.parent.glob("*.tmp")), [])

    def test_failed_replace_keeps_previous_checkpoint_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.json"
            atomic_write_json(path, {"version": 1})
            with patch("core.persistence.os.replace", side_effect=PermissionError("denied")):
                with self.assertRaises(PermissionError):
                    atomic_write_json(path, {"version": 2})
            self.assertEqual(json.loads(path.read_text()), {"version": 1})
            self.assertEqual(list(path.parent.glob("*.tmp")), [])

    def test_fsync_failure_does_not_replace_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.json"
            atomic_write_json(path, {"version": 1})
            with patch("core.persistence.os.fsync", side_effect=OSError("disk failure")):
                with self.assertRaises(OSError):
                    atomic_write_json(path, {"version": 2})
            self.assertEqual(json.loads(path.read_text()), {"version": 1})
            self.assertEqual(list(path.parent.glob("*.tmp")), [])


class ScanCheckpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load the route file without api.routes' eager imports of unrelated routes.
        # Imports run in an empty cwd so no local learning/scan data is read.
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                spec = importlib.util.spec_from_file_location("scan_checkpoint_tests_routes", ROOT / "api/routes/scan.py")
                cls.routes = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(cls.routes)
            finally:
                os.chdir(previous)

    def job(self, response="hello"):
        r = self.routes
        probe = r.ProbeResult("llm01", "Benign example", response, False, "none", None, 1.0)
        result = r.ModelVulnResult("example-model", "llm01", [probe], 0, 1)
        return r.ScanJob("550e8400-e29b-41d4-a716-446655440000", r.ScanStatus.COMPLETED, ["example-model"],
                         ["llm01"], "none", 1, False, results={"example-model": [result]})

    def test_persistence_path_accepts_only_canonical_uuid(self):
        valid = "550e8400-e29b-41d4-a716-446655440000"
        with tempfile.TemporaryDirectory() as tmp, patch.object(self.routes, "SCAN_PERSIST_DIR", Path(tmp)):
            self.assertEqual(self.routes._scan_file_path(valid), Path(tmp) / f"{valid}.json")
            for unsafe in ("../outside", "550e8400-e29b-41d4-a716-446655440000.json", "not-a-uuid", ""):
                with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                    self.routes._scan_file_path(unsafe)

    def test_untrusted_scan_id_never_reads_or_deletes_outside_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside.json"
            outside.write_text("do-not-touch", encoding="utf-8")
            with patch.object(self.routes, "SCAN_PERSIST_DIR", root / "scans"):
                self.assertIsNone(self.routes._get_job("../outside", {}))
                self.assertTrue(outside.exists())

    def test_checkpoint_preserves_full_response_while_preview_is_marked(self):
        job = self.job("x" * 5001)
        with tempfile.TemporaryDirectory() as tmp, patch.object(self.routes, "SCAN_PERSIST_DIR", Path(tmp)):
            self.assertTrue(self.routes.save_scan_to_disk(job))
            data = json.loads((Path(tmp) / "550e8400-e29b-41d4-a716-446655440000.json").read_text(encoding="utf-8"))
            restored = self.routes._json_to_scan(data)
        self.assertEqual(restored.results["example-model"][0].probes[0].response, "x" * 5001)
        preview = restored.to_dict()["results"]["example-model"][0]["probes"][0]
        self.assertEqual(len(preview["response"]), 4000)
        self.assertTrue(preview["response_truncated"])
        self.assertEqual(preview["response_full_length"], 5001)

    def test_validation_and_model_diagnostics_survive_roundtrip(self):
        job = self.job()
        probe = job.results["example-model"][0].probes[0]
        probe.validation_status = "validated"
        probe.validation_evaluator = "fixture-check"
        probe.evaluation_status = "evaluated"
        probe.model_diagnostics = {"outcome": "completed", "reported_model": "fixture"}
        restored = self.routes._json_to_scan(self.routes._scan_to_json(job))
        result = restored.results["example-model"][0].probes[0]
        self.assertEqual(result.validation_status, "validated")
        self.assertEqual(result.validation_evaluator, "fixture-check")
        self.assertEqual(result.evaluation_status, "evaluated")
        self.assertEqual(result.model_diagnostics, probe.model_diagnostics)

    def test_blocked_not_evaluated_status_survives_checkpoint(self):
        job = self.job("[blocked] Benign fixture")
        probe = job.results["example-model"][0].probes[0]
        probe.evaluation_status = "not_evaluated"
        probe.model_diagnostics = {"outcome": "blocked", "failure_kind": "policy_refusal",
                                   "evaluation_status": "not_evaluated"}
        with tempfile.TemporaryDirectory() as tmp, patch.object(self.routes, "SCAN_PERSIST_DIR", Path(tmp)):
            self.assertTrue(self.routes.save_scan_to_disk(job))
            data = json.loads((Path(tmp) / "550e8400-e29b-41d4-a716-446655440000.json").read_text(encoding="utf-8"))
        restored = self.routes._json_to_scan(data).results["example-model"][0].probes[0]
        self.assertEqual(restored.evaluation_status, "not_evaluated")
        self.assertEqual(restored.model_diagnostics["failure_kind"], "policy_refusal")
        self.assertFalse(restored.bypassed)

    def test_legacy_records_default_to_unvalidated_and_unknown_diagnostics(self):
        data = self.routes._scan_to_json(self.job())
        probe = data["results"]["example-model"][0]["probes"][0]
        for key in ("validation_status", "validation_evaluator", "model_diagnostics", "evaluation_status"):
            probe.pop(key)
        restored = self.routes._json_to_scan(data).results["example-model"][0].probes[0]
        self.assertEqual(restored.validation_status, "unvalidated")
        self.assertEqual(restored.model_diagnostics, {})
        self.assertEqual(restored.evaluation_status, "not_evaluated")

    def test_short_and_boundary_responses_not_marked_truncated(self):
        for length in (0, 5, 4000):
            with self.subTest(length=length):
                probe = self.job("x" * length).to_dict()["results"]["example-model"][0]["probes"][0]
                self.assertFalse(probe["response_truncated"])
                self.assertEqual(probe["response_full_length"], length)

    def test_checkpoint_failure_is_visible_deduplicated_and_sanitized(self):
        job = self.job()
        output = io.StringIO()
        with patch.object(self.routes, "atomic_write_json", side_effect=OSError("sensitive-detail")), redirect_stdout(output):
            self.assertFalse(self.routes.save_scan_to_disk(job))
            self.assertFalse(self.routes.save_scan_to_disk(job))
        self.assertEqual(len(job.errors), 1)
        self.assertIn("Checkpoint could not be saved", job.to_dict()["errors"][0])
        self.assertNotIn("sensitive-detail", output.getvalue() + str(job.errors))

    def test_interrupted_checkpoint_reconciles_without_losing_completed_work(self):
        job = self.job()
        job.status = self.routes.ScanStatus.RUNNING
        restored = self.routes._json_to_scan(self.routes._scan_to_json(job))
        self.assertTrue(self.routes._reconcile_zombie(restored))
        self.assertEqual(restored.status, self.routes.ScanStatus.FAILED)
        self.assertEqual(len(restored.results["example-model"][0].probes), 1)
        self.assertFalse(self.routes._reconcile_zombie(restored))
        self.assertEqual(restored.errors.count("Scan interrupted by server restart"), 1)


if __name__ == "__main__":
    unittest.main()
