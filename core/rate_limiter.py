#!/usr/bin/env python3
"""
Per-provider rate limiter — token bucket implementation.

Documented free-tier / tier-1 RPM limits per provider.
Override any limit via environment variable:
  RATE_LIMIT_OPENAI=60     (requests per minute)
  RATE_LIMIT_ANTHROPIC=50
  etc.

The limiter is also Retry-After aware: if a 429 carries a header the
integration layer surfaces it as "retry_after:<N>" in the exception
message; the limiter will enforce that delay.
"""

import asyncio
import os
import time
from typing import Dict, Optional


# ── Documented RPM limits (conservative tier-1 / free-tier baselines) ─────────
#
# Sources:
#   OpenAI:      platform.openai.com/docs/guides/rate-limits   (gpt-4o tier-1 = 500 RPM, using 60 as safe default)
#   Anthropic:   docs.anthropic.com/en/api/rate-limits          (claude-3 = 50 RPM tier-1)
#   Google:      ai.google.dev/pricing                          (gemini-flash free = 15 RPM, paid = 1000 RPM; use 60)
#   Groq:        console.groq.com/docs/rate-limits              (llama-3.3-70b = 30 RPM on free, 14400 on dev)
#   Mistral:     docs.mistral.ai/deployment/cloud/rate-limits   (1 RPS = 60 RPM)
#   Together:    docs.together.ai/reference/rate-limits         (60 RPM)
#   Perplexity:  docs.perplexity.ai/reference/post_chat_completions  (50 RPM)
#   DeepSeek:    platform.deepseek.com/docs                     (60 RPM)
#   Cohere:      docs.cohere.com/reference/rate-limits          (100 RPM trial)
#   Bedrock:     docs.aws.amazon.com/bedrock/quotas             (conservative 20 RPM)
#   HuggingFace: huggingface.co/docs/api-inference              (free = ~30 RPM)
#   Ollama:      local — no limit
#   custom:      unknown — conservative 30 RPM

PROVIDER_RPM: Dict[str, int] = {
    "openai":      60,
    "anthropic":   50,
    "google":      60,
    "xai":         60,   # xAI Grok — tier-1 ~60 RPM
    "groq":        30,
    "mistral":     60,
    "together":    60,
    "perplexity":  50,
    "deepseek":    60,
    "cohere":      100,
    "bedrock":     20,
    "huggingface": 30,
    "bigmodel":     60,   # Zhipu BigModel (GLM series)
    "ollama_cloud": 60,   # Ollama Cloud — remote hosted models
    "ollama":      9999,   # local — effectively unlimited
    "custom":      30,
}


def _load_overrides() -> Dict[str, int]:
    """Read RATE_LIMIT_<PROVIDER>=N env vars and return override dict."""
    overrides: Dict[str, int] = {}
    for key, val in os.environ.items():
        if key.upper().startswith("RATE_LIMIT_"):
            prov = key[len("RATE_LIMIT_"):].lower()
            try:
                overrides[prov] = int(val)
            except ValueError:
                pass
    return overrides


# Apply any overrides at import time
_OVERRIDES = _load_overrides()
for _prov, _rpm in _OVERRIDES.items():
    if _prov in PROVIDER_RPM:
        PROVIDER_RPM[_prov] = _rpm


class TokenBucket:
    """
    Async token-bucket rate limiter.

    - Bucket capacity  = rpm  (allows a full-minute burst in theory,
      but we cap the initial fill at capacity to avoid initial burst)
    - Refill rate      = rpm / 60 tokens per second
    - Each acquire()   consumes 1 token; waits if the bucket is empty.
    """

    def __init__(self, rpm: int):
        self.rpm            = rpm
        self._capacity      = float(rpm)
        self._tokens        = float(rpm)          # start full
        self._refill_rate   = rpm / 60.0           # tokens per second
        self._last_refill   = time.monotonic()
        self._lock          = asyncio.Lock()

    def _refill(self):
        now     = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            self._capacity,
            self._tokens + elapsed * self._refill_rate,
        )
        self._last_refill = now

    async def acquire(self, retry_after: Optional[float] = None):
        """
        Block until a token is available (or retry_after seconds have passed).
        Pass retry_after when a 429 response carried a Retry-After header.
        """
        if retry_after and retry_after > 0:
            # Provider told us exactly how long to wait
            await asyncio.sleep(retry_after)

        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Calculate exact wait time to next token
                wait = (1.0 - self._tokens) / self._refill_rate

            await asyncio.sleep(wait)

    @property
    def current_tokens(self) -> float:
        self._refill()
        return self._tokens


class RateLimiterRegistry:
    """
    Process-singleton registry of per-provider TokenBuckets.
    Also enforces a per-provider asyncio.Semaphore for concurrency
    (how many requests can be *in-flight* simultaneously).
    """

    # Concurrent in-flight requests per provider (independent of RPM)
    _CONCURRENCY: Dict[str, int] = {
        "openai":      10,
        "anthropic":    5,
        "google":       8,
        "xai":          8,   # xAI Grok
        "groq":        20,   # Groq is extremely fast
        "mistral":      8,
        "together":     8,
        "perplexity":   5,
        "deepseek":     8,
        "cohere":       5,
        "bedrock":      5,
        "huggingface":  5,
        "bigmodel":     5,   # Zhipu BigModel (GLM series)
        "ollama_cloud": 5,   # Ollama Cloud — remote hosted models
        "ollama":       3,   # local — limited by hardware
        "custom":       5,
    }

    def __init__(self):
        self._buckets: Dict[str, TokenBucket] = {}
        self._sems:    Dict[str, asyncio.Semaphore] = {}

    def _ensure(self, provider: str):
        if provider not in self._buckets:
            rpm = PROVIDER_RPM.get(provider, PROVIDER_RPM["custom"])
            self._buckets[provider] = TokenBucket(rpm)
        if provider not in self._sems:
            limit = self._CONCURRENCY.get(provider, self._CONCURRENCY["custom"])
            self._sems[provider] = asyncio.Semaphore(limit)

    async def acquire(self, provider: str, retry_after: Optional[float] = None):
        """Acquire both the rate-limit token and the concurrency slot."""
        self._ensure(provider)
        await self._buckets[provider].acquire(retry_after=retry_after)
        await self._sems[provider].acquire()

    def release(self, provider: str):
        """Release the concurrency slot (rate-limit token is consumed on acquire)."""
        if provider in self._sems:
            self._sems[provider].release()

    def get_status(self, provider: str) -> Dict:
        self._ensure(provider)
        return {
            "provider":        provider,
            "rpm_limit":       PROVIDER_RPM.get(provider, 30),
            "tokens_available": round(self._buckets[provider].current_tokens, 1),
            "concurrency_limit": self._CONCURRENCY.get(provider, 5),
        }

    def all_status(self) -> list:
        providers = list(PROVIDER_RPM.keys())
        return [self.get_status(p) for p in providers]


# Process-level singleton
_REGISTRY: Optional[RateLimiterRegistry] = None


def get_registry() -> RateLimiterRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = RateLimiterRegistry()
    return _REGISTRY
