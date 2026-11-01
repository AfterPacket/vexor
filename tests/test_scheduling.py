"""Bounded-task and cancellation tests; no provider calls or attack payloads."""
import asyncio
from contextlib import aclosing
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.scheduling import bounded_as_completed


class SchedulingTests(unittest.IsolatedAsyncioTestCase):
    async def test_task_count_is_bounded_and_each_item_runs_once(self):
        active, seen, values = set(), [], []
        peak = 0
        async def worker(item):
            nonlocal peak
            peak = max(peak, len(active))
            seen.append(item)
            await asyncio.sleep(0)
            return item
        async for task in bounded_as_completed(range(200), worker, limit=5, active_tasks=active):
            values.append(task.result())
        self.assertEqual(sorted(values), list(range(200)))
        self.assertEqual(len(seen), 200)
        self.assertLessEqual(peak, 5)
        self.assertEqual(active, set())

    async def test_errors_remain_visible_to_consumer(self):
        async def worker(item):
            if item == 2:
                raise RuntimeError("fixture failure")
            return item
        errors, values = [], []
        async for task in bounded_as_completed(range(5), worker, limit=2):
            try:
                values.append(task.result())
            except RuntimeError as e:
                errors.append(str(e))
        self.assertEqual(errors, ["fixture failure"])
        self.assertEqual(sorted(values), [0, 1, 3, 4])

    async def test_parent_cancellation_drains_owned_tasks(self):
        active, started, settled = set(), asyncio.Event(), []
        async def worker(item):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                settled.append(item)
        async def consume():
            async for task in bounded_as_completed(range(100), worker, limit=3, active_tasks=active):
                task.result()
        runner = asyncio.create_task(consume())
        await started.wait()
        runner.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await runner
        self.assertFalse(active)
        self.assertEqual(len(settled), 3)

    async def test_stop_prevents_new_work_and_drains_existing_work(self):
        active, calls, stop = set(), [], asyncio.Event()
        async def worker(item):
            calls.append(item)
            if item == 0:
                stop.set()
                return item
            await asyncio.Event().wait()
        async for task in bounded_as_completed(range(100), worker, limit=3,
                active_tasks=active, should_stop=stop.is_set):
            try:
                task.result()
            except asyncio.CancelledError:
                pass
        self.assertLessEqual(len(calls), 3)
        self.assertFalse(active)

    async def test_early_close_drains_tasks(self):
        active = set()
        async def worker(item):
            if item:
                await asyncio.Event().wait()
            return item
        async with aclosing(bounded_as_completed(range(10), worker, limit=3, active_tasks=active)) as results:
            async for task in results:
                self.assertEqual(task.result(), 0)
                break
        self.assertFalse(active)

    async def test_invalid_limits_fail_before_scheduling(self):
        async def worker(item):
            self.fail("Invalid limit dispatched work")
        for limit in (0, -1, True, 1.5):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                async for task in bounded_as_completed([0], worker, limit=limit):
                    task.result()


if __name__ == "__main__":
    unittest.main()
