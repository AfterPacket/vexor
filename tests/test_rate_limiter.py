"""Offline rate-limit cooldown/cancellation regression tests."""
import asyncio
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.rate_limiter import RateLimiterRegistry, TokenBucket


class RateLimiterTests(unittest.IsolatedAsyncioTestCase):
    async def test_defer_does_not_acquire_a_second_concurrency_slot(self):
        reg = RateLimiterRegistry()
        reg._ensure("custom")
        reg._sems["custom"] = asyncio.Semaphore(1)
        await reg.acquire("custom")
        reg.defer("custom", 0.01)
        self.assertTrue(reg._sems["custom"].locked())
        reg.release("custom")
        await asyncio.wait_for(reg.acquire("custom"), timeout=1)
        reg.release("custom")

    async def test_cooldown_is_shared_and_does_not_consume_token_early(self):
        bucket = TokenBucket(60)
        with patch("core.rate_limiter.time", Mock(monotonic=Mock(return_value=100))):
            bucket._last_refill = 100
            bucket.defer(10)
            bucket.defer(1)
            self.assertEqual(bucket._blocked_until, 110)
            task = asyncio.create_task(bucket.acquire())
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            self.assertEqual(bucket._tokens, 60)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        bucket._blocked_until = 0
        await asyncio.wait_for(bucket.acquire(), timeout=1)

    async def test_invalid_rate_is_rejected_instead_of_hanging(self):
        for rpm in (0, -1):
            with self.assertRaises(ValueError):
                TokenBucket(rpm)


if __name__ == "__main__":
    unittest.main()
