"""Harmless mocked-provider fixture shared by orchestration tests/benchmarks."""
import asyncio
from contextlib import ExitStack
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_previous = Path.cwd()
with tempfile.TemporaryDirectory() as _empty:
    try:
        os.chdir(_empty)
        import core.scanner as module
    finally:
        os.chdir(_previous)


class FixtureLimiter:
    def __init__(self, concurrency):
        self.semaphore = asyncio.Semaphore(concurrency)

    async def acquire(self, provider, retry_after=None):
        await self.semaphore.acquire()

    def release(self, provider):
        self.semaphore.release()


class Scenario:
    def __init__(self, count=48, delay=0.002, concurrency=4):
        self.count, self.delay = count, delay
        self.calls = self.inflight = self.peak_inflight = self.peak_tasks = 0
        self.limiter = FixtureLimiter(concurrency)
        self.scanner = module.Scanner.__new__(module.Scanner)
        self.scanner.independent_validator = None
        self.scanner._get_mm = lambda: object()
        self.scanner.prompt_engine = Mock()
        self.scanner.prompt_engine.get_prompts.return_value = [f"Benign fixture {i}" for i in range(count)]
        self.scanner.prompt_engine.mutate_prompt.return_value = {}
        self.scanner._autopwn_suite = lambda model: ["fixture_mode_a", "fixture_mode_b"]
        self.scanner._send_probe = self.send
        self.job = None

    def __enter__(self):
        self.stack = ExitStack()
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.store = module.FailureStore(str(Path(directory) / "store.json"))
        for name, value in (("get_registry", lambda: self.limiter), ("_failure_store", self.store),
                            ("_discovery_engine", Mock()), ("_generate_warm_pool_variants", Mock())):
            self.stack.enter_context(patch.object(module, name, value))
        return self

    def __exit__(self, *exc):
        return self.stack.__exit__(*exc)

    async def send(self, mm, model, prompt, vulnerability, mode, system_override=None):
        self.calls += 1
        self.inflight += 1
        self.peak_inflight = max(self.peak_inflight, self.inflight)
        self.peak_tasks = max(self.peak_tasks, len(self.job.active_tasks))
        try:
            await asyncio.sleep(self.delay)
            return module.ProbeResult(vulnerability, prompt, "Benign fixture reply", False, mode, None,
                                      self.delay * 1000, evaluation_status="evaluated")
        finally:
            self.inflight -= 1

    def prepare(self, kind):
        entries = [{"prompt": f"Benign fixture {i}", "vulnerability": "llm01"} for i in range(self.count)]
        if kind == "injection":
            self.job = self.scanner.create_injection_job(["fixture-model"], entries)
            runner = self.scanner.run_injection_scan
        elif kind == "autopwn_injection":
            self.job = self.scanner.create_autopwn_injection_job(["fixture-model"], entries)
            runner = self.scanner.run_autopwn_injection_scan
        elif kind == "autopwn":
            self.job = self.scanner.create_jailbreak_job(["fixture-model"], ["llm01"], prompt_count=self.count,
                                                       use_mutations=False)
            runner = self.scanner.run_jailbreak_scan
        elif kind == "regular_pair":
            self.job = self.scanner.create_scan_job(["fixture-model"], ["llm01"], prompt_count=self.count)
            async def runner(job):
                result = await self.scanner._scan_pair(object(), "fixture-model", "llm01", job)
                job.results = {"fixture-model": [result]}
                return job
        else:
            raise ValueError("Unknown fixture scenario")
        self.job.use_warm_pool = False
        return runner
