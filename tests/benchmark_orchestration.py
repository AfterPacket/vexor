"""Offline orchestration microbenchmark; no live providers or attack generation.

Run: python tests/benchmark_orchestration.py
These figures measure mocked scheduling only, NOT model latency/effectiveness.
"""
import asyncio
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestration_fixture import Scenario


async def main():
    rows = []
    for kind in ("regular_pair", "injection", "autopwn_injection", "autopwn"):
        with Scenario(count=48, delay=0.002, concurrency=4) as fixture:
            runner = fixture.prepare(kind)
            start = time.perf_counter()
            with redirect_stdout(io.StringIO()):
                await runner(fixture.job)
            rows.append({
                "scenario": kind,
                "logical_probes": 48,
                "mock_requests": fixture.calls,
                "mock_delay_seconds": fixture.delay,
                "elapsed_seconds": round(time.perf_counter() - start, 4),
                "peak_provider_calls": fixture.peak_inflight,
                "peak_probe_tasks": fixture.peak_tasks,
                "remaining_tasks": len(fixture.job.active_tasks),
            })
    print(json.dumps({"mode": "offline_mock_only", "results": rows}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
