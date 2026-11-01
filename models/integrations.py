#!/usr/bin/env python3
"""
Real Model Integrations for Vexor

All providers support:
  send_prompt(prompt, model)
  send_prompt_with_system(prompt, model, system=None)
  send_prompt_async(prompt, model, system=None)   ← async, no blocking sleep

Rate limiting strategy: NO artificial sleep delays.
  • Per-provider asyncio.Semaphore in scanner.py caps concurrency.
  • Exponential-backoff retry is handled here on 429 / transient errors.
  • Each provider SDK's own connection pool manages actual throughput.

Providers:
  OpenAI         — gpt-4o, gpt-4o-mini, gpt-4-turbo
  Anthropic      — claude-opus-4-6, claude-sonnet-4-6, claude-haiku-4-5
  Google         — gemini-2.0-flash, gemini-1.5-pro, gemini-1.5-flash
  xAI Grok       — grok-3, grok-3-fast, grok-3-mini, grok-3-mini-fast, grok-2
  Groq           — llama-3.3-70b-versatile, mixtral-8x7b-32768, etc.
  Mistral        — mistral-large-latest, mistral-medium-latest, etc.
  Together AI    — meta-llama/Llama-3-70b-chat-hf, etc.
  Perplexity     — llama-3.1-sonar-large-128k-online, etc.
  DeepSeek       — deepseek-chat, deepseek-reasoner
  Cohere         — command-r-plus, command-r
  AWS Bedrock    — anthropic.claude-*, amazon.titan-*, etc.
  HuggingFace    — meta-llama/Meta-Llama-3-8B-Instruct, etc.
  Ollama         — local models via http://localhost:11434
  Custom API     — any OpenAI-compatible endpoint
"""

import asyncio
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

import requests

from core.model_results import classify_failure, response_details

# ── Optional SDK availability ─────────────────────────────────────────────────

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import google.generativeai as genai
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

try:
    import cohere as cohere_sdk
    COHERE_AVAILABLE = True
except ImportError:
    COHERE_AVAILABLE = False

try:
    import boto3
    BEDROCK_AVAILABLE = True
except ImportError:
    BEDROCK_AVAILABLE = False

try:
    from huggingface_hub import InferenceClient
    HUGGINGFACE_AVAILABLE = True
except ImportError:
    HUGGINGFACE_AVAILABLE = False


# ── Reasoning models constant ─────────────────────────────────────────────────

REASONING_MODELS = {"deepseek-reasoner", "glm-5", "glm-5.1", "glm-5.2", "o1", "o1-mini", "o1-pro", "o3", "o3-mini", "deepseek-r1", "deepseek-r1:latest"}


# ── Retry helper ──────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)


class ModelResponse(str):
    """String-compatible response with provider-reported, not verified, metadata."""

    def __new__(cls, text, reported_model=None, finish_reason=None, *,
                outcome=None, request_metadata=None, failure_kind=None):
        obj = super().__new__(cls, text)
        obj.reported_model = reported_model
        obj.finish_reason = finish_reason
        obj.outcome = outcome
        obj.failure_kind = failure_kind
        obj.request_metadata = dict(request_metadata or {})
        return obj

    @classmethod
    def from_error(cls, error):
        category = classify_failure(error)
        if category == "policy_refusal":
            return cls("[blocked] Provider rejected the request.", outcome="blocked", failure_kind=category)
        return cls(f"Error: {error}", outcome="error", failure_kind=category)


def _chat_result(resp):
    choice = resp.choices[0]
    message = choice.message
    text = message.content or ""
    reason = getattr(choice, "finish_reason", None)
    blocked = bool(getattr(message, "refusal", None)) or reason == "content_filter"
    if blocked:
        text = ("[blocked] Provider refused or filtered the request.\n" + text).strip()
    elif reason == "length":
        text += "\n[incomplete] Provider reached the output token limit."
    outcome = "blocked" if blocked else "incomplete" if reason == "length" else None
    return ModelResponse(text.strip(), getattr(resp, "model", None), reason, outcome=outcome)


def _is_transient_error(exc):
    """Never retry safety, auth, context, billing, or exhausted-quota failures."""
    return classify_failure(exc) in {"rate_limit", "service_unavailable"}

async def _retry_async(coro_fn, retries: int = 3, base_delay: float = 1.0):
    """
    Retry an async callable on transient rate-limit/overload errors (429, 503).
    Uses exponential backoff.  Does NOT sleep on first attempt.
    """
    last_err: Exception = RuntimeError("unknown")
    for attempt in range(retries):
        try:
            return await coro_fn()
        except Exception as e:
            last_err = e
            # Retries are limited to rate-limit / temporary service overload.
            # Do NOT retry a timeout: a timed-out generation may already have
            # consumed tokens and retrying blindly multiplies scan cost.
            if _is_transient_error(e):
                if attempt < retries - 1:
                    await asyncio.sleep(base_delay * (2 ** attempt))
                continue
            raise  # Non-retriable — propagate immediately
    raise last_err


def _retry_sync(fn, retries: int = 3, base_delay: float = 1.0):
    """Sync version of retry for thread-pool workers."""
    last_err: Exception = RuntimeError("unknown")
    for attempt in range(retries):
        try:
            return fn()
        except Exception as e:
            last_err = e
            # Do not retry a timeout: it can already have consumed a full
            # generation and retrying would multiply paid scan attempts.
            if _is_transient_error(e):
                if attempt < retries - 1:
                    time.sleep(base_delay * (2 ** attempt))
                continue
            raise
    raise last_err


def is_reasoning_model(model_name: str) -> bool:
    """Check if a model is a reasoning/thinking model that needs extra token budget."""
    low = model_name.lower()
    # Strip common prefixes/suffixes so 'ollama-cloud/glm-5.2:cloud' → 'glm-5.2'
    for p in ("ollama/", "ollama:", "ollama-cloud/", "ollama-cloud:"):
        if low.startswith(p):
            low = low[len(p):]
    for rm in REASONING_MODELS:
        if rm in low:
            return True
    return False

def auto_max_tokens(model_name: str, base: int = 4096) -> int:
    """Return appropriate max_tokens for a model. Reasoning models need extra token budget."""
    return base * 2 if is_reasoning_model(model_name) else base


def openai_uses_restricted_params(model_name: str) -> bool:
    """
    True for OpenAI model families that reject `temperature` (only the default
    is allowed) and `max_tokens` (they require `max_completion_tokens`):
    the o-series reasoning models (o1/o3/o4/o5) and the gpt-5+ generation.

    Detection is family-based (not an exact-ID list) so newly released models
    are handled automatically; the call sites also fall back to these params
    on a parameter-compatibility error for any model not caught here.
    """
    low = model_name.lower()
    # Strip an OpenAI fine-tune prefix like 'ft:gpt-4o:org::id'
    if low.startswith("ft:"):
        low = low[3:]
    if low.startswith(("o1", "o3", "o4", "o5")):
        return True
    m = re.match(r"(?:chat)?gpt-(\d+)", low)
    if m and int(m.group(1)) >= 5:
        return True
    return False


def _openai_param_error(err_msg: str) -> bool:
    """True when an OpenAI error indicates temperature/max_tokens incompatibility."""
    low = err_msg.lower()
    return (
        ("temperature" in low and "unsupported" in low)
        or "max_tokens" in low
        or "max_completion_tokens" in low
        or ("unsupported parameter" in low)
        or ("unsupported value" in low and "temperature" in low)
    )


# ── Base class ────────────────────────────────────────────────────────────────

class ModelIntegrator:
    """Base class for all model integrations."""

    def __init__(self, config: Dict):
        self.config = config
        # No artificial delay — rate limiting is handled by semaphores in scanner

    def send_prompt(self, prompt: str, model_name: str) -> str:
        raise NotImplementedError

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        return self.send_prompt(prompt, model_name)

    async def send_prompt_async(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        """Async wrapper — override in subclasses that have a native async client."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self.send_prompt_with_system, prompt, model_name, system
        )


# ── OpenAI ────────────────────────────────────────────────────────────────────

class OpenAIIntegration(ModelIntegrator):
    def __init__(self, config: Dict):
        super().__init__(config)
        if not OPENAI_AVAILABLE:
            raise ImportError("pip install openai")
        api_key = config.get("openai_api_key") or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not configured")
        self.client       = openai.OpenAI(api_key=api_key, max_retries=0, timeout=60)
        self.async_client = openai.AsyncOpenAI(api_key=api_key, max_retries=0, timeout=60)

    def _build_messages(self, prompt: str, system: Optional[str]) -> list:
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        return msgs

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def _kwargs(self, prompt: str, system: Optional[str], model_name: str, restricted: bool) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "model":    model_name,
            "messages": self._build_messages(prompt, system),
        }
        if restricted:
            # o-series / gpt-5+ : only max_completion_tokens, default temperature
            kwargs["max_completion_tokens"] = auto_max_tokens(model_name)
        else:
            kwargs["max_tokens"]  = auto_max_tokens(model_name)
            kwargs["temperature"] = 0.7
        return kwargs

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        restricted = openai_uses_restricted_params(model_name)
        def _call():
            try:
                resp = self.client.chat.completions.create(
                    **self._kwargs(prompt, system, model_name, restricted)
                )
            except Exception as e:
                # Unknown newer model that rejects temperature/max_tokens —
                # retry once with the restricted param set.
                if (not restricted and classify_failure(e) == "unsupported_capability"
                        and _openai_param_error(str(e))):
                    resp = self.client.chat.completions.create(
                        **self._kwargs(prompt, system, model_name, True)
                    )
                else:
                    raise
            return _chat_result(resp)
        try:
            return _retry_sync(_call)
        except Exception as e:
            return ModelResponse.from_error(e)

    async def send_prompt_async(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        restricted = openai_uses_restricted_params(model_name)
        async def _call():
            try:
                resp = await self.async_client.chat.completions.create(
                    **self._kwargs(prompt, system, model_name, restricted)
                )
            except Exception as e:
                if (not restricted and classify_failure(e) == "unsupported_capability"
                        and _openai_param_error(str(e))):
                    resp = await self.async_client.chat.completions.create(
                        **self._kwargs(prompt, system, model_name, True)
                    )
                else:
                    raise
            return _chat_result(resp)
        try:
            return await _retry_async(_call)
        except Exception as e:
            return ModelResponse.from_error(e)

    def discover_models(self) -> List[str]:
        """List models available to this OpenAI account via /v1/models.
        New models released after the static catalogue was written appear here
        automatically — this is what keeps Vexor current without code changes."""
        try:
            resp = self.client.models.list()
            ids = [m.id for m in resp.data if getattr(m, "id", None)]
            # Filter out embeddings / TTS / image / moderation non-chat models
            chat = [i for i in ids if not any(
                i.lower().endswith(s) or s in i.lower()
                for s in ("embed", "whisper", "tts", "dall-e", "davinci",
                          "babbage", "ada", "moderation", "search",
                          "image", "audio", "realtime")
            )]
            return sorted(chat)
        except Exception:
            return []


# ── Anthropic ─────────────────────────────────────────────────────────────────

# A probe only needs enough output to judge whether the model complied, not the
# whole essay.  A full 4096-token generation on a thinking model measured ~52s
# alone and 150s+ under scan concurrency, which is what was blowing the probe
# budget.  Reports truncate to 500 chars anyway (configs/model_config.json).
PROBE_MAX_TOKENS = 2048


# The guard classifier can reject an injection attempt up front: the API returns
# stop_reason="refusal" with no content blocks at all.  Returning "" for that
# throws the signal away — the guard phrases in prompt_engine's
# _GLOBAL_REFUSAL_SIGNALS have nothing to match against, so a blocked probe is
# indistinguishable from an empty reply.  This marker contains "[blocked]",
# which those signals and failure_classifier's _GUARD_SIGNALS already
# recognise, so it scores as a non-bypass and classifies as a GUARD_BLOCK.
CLAUDE_GUARD_BLOCK = (
    "[blocked] Guard classifier rejected the request (stop_reason=refusal) — "
    "generation was halted before any output was produced."
)


def _is_claude_guard_error(err_msg: str) -> bool:
    """
    True when an Anthropic API error is actually the safety classifier blocking
    the request (Fable/Opus constitutional classifiers), rather than a real
    transport/billing/auth failure.  These must be recorded as a GUARD_BLOCK
    non-bypass, NOT as an error or timeout.
    """
    low = err_msg.lower()
    return any(k in low for k in (
        "output blocked", "blocked by content", "content filtering",
        "content_filter", "content policy", "blocked by safety",
        "safety classifier", "prohibited content", "blocked by our",
        "flagged by", "safety_filter", "was blocked",
    ))


def _claude_result(msg) -> str:
    """Response text, or an explicit marker when the guard blocked generation."""
    text = _claude_text(msg.content)
    reason = getattr(msg, "stop_reason", None)
    if reason == "refusal":
        text = ("[blocked] Provider ended generation with stop_reason=refusal.\n" + text).strip() if text else CLAUDE_GUARD_BLOCK
    elif reason == "max_tokens":
        text += "\n[incomplete] Provider reached the output token limit."
    return ModelResponse(text, getattr(msg, "model", None), reason)


def _claude_text(content) -> str:
    """Join the text blocks of a Claude response.

    Thinking models (fable-5, opus-5, …) return a 'thinking' block first, so
    content[0] is not the answer.  A guard-blocked reply may carry no text
    block at all — that yields "" rather than raising.
    """
    if not content:
        return ""
    return "".join(
        b.text for b in content if getattr(b, "type", None) == "text"
    ).strip()


class AnthropicIntegration(ModelIntegrator):
    def __init__(self, config: Dict):
        super().__init__(config)
        if not ANTHROPIC_AVAILABLE:
            raise ImportError("pip install anthropic")
        api_key = config.get("anthropic_api_key") or os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not configured")
        self.client       = anthropic.Anthropic(api_key=api_key, max_retries=0, timeout=180)
        self.async_client = anthropic.AsyncAnthropic(api_key=api_key, max_retries=0, timeout=180)

    def _resolved(self, model: str) -> str:
        if self.config.get("strict_model", True):
            return model
        return self.config.get("model_aliases", {}).get(model, model)

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        kwargs: Dict[str, Any] = {
            "model":    self._resolved(model_name),
            "max_tokens": min(auto_max_tokens(model_name), PROBE_MAX_TOKENS),
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        def _call():
            # Stream: a long non-streaming generation gets dropped in flight
            # ("Request timed out or interrupted").  Streaming keeps the
            # connection fed, so only the total generation time matters.
            with self.client.messages.stream(**kwargs) as s:
                return _claude_result(s.get_final_message())
        try:
            return _retry_sync(_call)
        except Exception as e:
            if classify_failure(e) == "policy_refusal":
                return ModelResponse(CLAUDE_GUARD_BLOCK, outcome="blocked", failure_kind="policy_refusal")
            return ModelResponse.from_error(e)

    async def send_prompt_async(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        kwargs: Dict[str, Any] = {
            "model":    self._resolved(model_name),
            "max_tokens": min(auto_max_tokens(model_name), PROBE_MAX_TOKENS),
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        async def _call():
            # See send_prompt_with_system — streaming avoids the dropped-
            # connection failure mode on long generations.
            async with self.async_client.messages.stream(**kwargs) as s:
                return _claude_result(await s.get_final_message())
        try:
            return await _retry_async(_call)
        except Exception as e:
            if classify_failure(e) == "policy_refusal":
                return ModelResponse(CLAUDE_GUARD_BLOCK, outcome="blocked", failure_kind="policy_refusal")
            return ModelResponse.from_error(e)

    def discover_models(self) -> List[str]:
        """List Claude models via the Anthropic Models API (client.models.list).
        New Claude releases appear here automatically."""
        try:
            resp = self.client.models.list()
            ids = [m.id for m in getattr(resp, "data", []) if getattr(m, "id", None)]
            return sorted(ids)
        except Exception:
            return []


# ── Google ────────────────────────────────────────────────────────────────────

class GoogleIntegration(ModelIntegrator):
    def __init__(self, config: Dict):
        super().__init__(config)
        if not GOOGLE_AVAILABLE:
            raise ImportError("pip install google-generativeai")
        api_key = config.get("google_api_key") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not configured")
        genai.configure(api_key=api_key)

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        def _call():
            kwargs: Dict[str, Any] = {}
            if system:
                kwargs["system_instruction"] = system
            model = genai.GenerativeModel(model_name, **kwargs)
            resp = model.generate_content(prompt)
            return (resp.text or "").strip()
        try:
            return _retry_sync(_call)
        except Exception as e:
            return f"Error: {e}"

    def discover_models(self) -> List[str]:
        """List Gemini models via google.generativeai.list_models()."""
        try:
            models = []
            for m in genai.list_models():
                name = getattr(m, "name", "") or ""
                short = name.split("/")[-1] if name else ""
                methods = getattr(m, "supported_generation_methods", [])
                if short and "generateContent" in methods:
                    models.append(short)
            return sorted(models)
        except Exception:
            return []


# ── OpenAI-compatible base (Groq / Together / Perplexity / DeepSeek / Mistral) ──

class OpenAICompatIntegration(ModelIntegrator):
    """Re-uses the OpenAI SDK with a custom base_url."""

    def __init__(self, config: Dict, base_url: str, api_key: str, label: str):
        super().__init__(config)
        if not OPENAI_AVAILABLE:
            raise ImportError("pip install openai")
        if not api_key:
            raise ValueError(f"{label} API key not configured")
        self.client       = openai.OpenAI(api_key=api_key, base_url=base_url,
                                       max_retries=0, timeout=60)
        self.async_client = openai.AsyncOpenAI(api_key=api_key, base_url=base_url,
                                              max_retries=0, timeout=60)

    def _msgs(self, prompt: str, system: Optional[str]) -> list:
        out = []
        if system:
            out.append({"role": "system", "content": system})
        out.append({"role": "user", "content": prompt})
        return out

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        def _call():
            resp = self.client.chat.completions.create(
                model=model_name,
                messages=self._msgs(prompt, system),
                max_tokens=auto_max_tokens(model_name),
                temperature=0.7,
            )
            return _chat_result(resp)
        try:
            return _retry_sync(_call)
        except Exception as e:
            return f"Error: {e}"

    async def send_prompt_async(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        async def _call():
            resp = await self.async_client.chat.completions.create(
                model=model_name,
                messages=self._msgs(prompt, system),
                max_tokens=auto_max_tokens(model_name),
                temperature=0.7,
            )
            return _chat_result(resp)
        try:
            return await _retry_async(_call)
        except Exception as e:
            return f"Error: {e}"

    def discover_models(self) -> List[str]:
        """List models from this OpenAI-compatible endpoint via GET /models.
        Works for Groq, Together, DeepSeek, Mistral, Perplexity, xAI, BigModel,
        and any user-added dynamic provider."""
        try:
            resp = self.client.models.list()
            ids = [m.id for m in resp.data if getattr(m, "id", None)]
            chat = [i for i in ids if not any(
                i.lower().endswith(s) or s in i.lower()
                for s in ("embed", "whisper", "tts", "rerank", "guard",
                          "moderation", "babbage", "davinci", "ada",
                          "guardian", "safety")
            )]
            return sorted(chat)
        except Exception:
            return []


class GrokIntegration(OpenAICompatIntegration):
    """xAI Grok — OpenAI-compatible API at api.x.ai"""
    def __init__(self, config: Dict):
        super().__init__(config,
            base_url="https://api.x.ai/v1",
            api_key=config.get("xai_api_key") or os.getenv("XAI_API_KEY") or "",
            label="xAI Grok")


class BigModelIntegration(OpenAICompatIntegration):
    """Zhipu AI BigModel (GLM series) — OpenAI-compatible API at open.bigmodel.cn"""
    def __init__(self, config: Dict):
        super().__init__(config,
            base_url="https://open.bigmodel.cn/api/paas/v4",
            api_key=config.get("bigmodel_api_key") or os.getenv("BIGMODEL_API_KEY") or "",
            label="BigModels")


class GroqIntegration(OpenAICompatIntegration):
    def __init__(self, config: Dict):
        super().__init__(config,
            base_url="https://api.groq.com/openai/v1",
            api_key=config.get("groq_api_key") or os.getenv("GROQ_API_KEY") or "",
            label="Groq")


class TogetherIntegration(OpenAICompatIntegration):
    def __init__(self, config: Dict):
        super().__init__(config,
            base_url="https://api.together.xyz/v1",
            api_key=config.get("together_api_key") or os.getenv("TOGETHER_API_KEY") or "",
            label="Together")


class PerplexityIntegration(OpenAICompatIntegration):
    def __init__(self, config: Dict):
        super().__init__(config,
            base_url="https://api.perplexity.ai",
            api_key=config.get("perplexity_api_key") or os.getenv("PERPLEXITY_API_KEY") or "",
            label="Perplexity")


class DeepSeekIntegration(OpenAICompatIntegration):
    def __init__(self, config: Dict):
        super().__init__(config,
            base_url="https://api.deepseek.com/v1",
            api_key=config.get("deepseek_api_key") or os.getenv("DEEPSEEK_API_KEY") or "",
            label="DeepSeek")


class MistralIntegration(OpenAICompatIntegration):
    def __init__(self, config: Dict):
        super().__init__(config,
            base_url="https://api.mistral.ai/v1",
            api_key=config.get("mistral_api_key") or os.getenv("MISTRAL_API_KEY") or "",
            label="Mistral")


# ── Cohere ────────────────────────────────────────────────────────────────────

class CohereIntegration(ModelIntegrator):
    def __init__(self, config: Dict):
        super().__init__(config)
        if not COHERE_AVAILABLE:
            raise ImportError("pip install cohere")
        api_key = config.get("cohere_api_key") or os.getenv("COHERE_API_KEY")
        if not api_key:
            raise ValueError("COHERE_API_KEY not configured")
        self.client = cohere_sdk.ClientV2(api_key=api_key)

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        def _call():
            resp = self.client.chat(model=model_name, messages=msgs)
            return (resp.message.content[0].text or "").strip() if resp.message.content else ""
        try:
            return _retry_sync(_call)
        except Exception as e:
            return f"Error: {e}"


# ── AWS Bedrock ───────────────────────────────────────────────────────────────

class BedrockIntegration(ModelIntegrator):
    def __init__(self, config: Dict):
        super().__init__(config)
        if not BEDROCK_AVAILABLE:
            raise ImportError("pip install boto3")
        region = config.get("aws_region") or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self.client = boto3.client("bedrock-runtime", region_name=region)

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        def _call():
            kwargs: Dict[str, Any] = {
                "modelId":  model_name,
                "messages": [{"role": "user", "content": [{"text": prompt}]}],
            }
            if system:
                kwargs["system"] = [{"text": system}]
            resp = self.client.converse(**kwargs)
            _content = resp.get("output", {}).get("message", {}).get("content", [{}])
            return (_content[0].get("text") or "").strip() if _content else ""
        try:
            return _retry_sync(_call)
        except Exception as e:
            return f"Error: {e}"


# ── HuggingFace Inference ─────────────────────────────────────────────────────

class HuggingFaceIntegration(ModelIntegrator):
    def __init__(self, config: Dict):
        super().__init__(config)
        if not HUGGINGFACE_AVAILABLE:
            raise ImportError("pip install huggingface-hub")
        api_key = config.get("huggingface_api_key") or os.getenv("HUGGINGFACE_API_KEY")
        if not api_key:
            raise ValueError("HUGGINGFACE_API_KEY not configured")
        self.client = InferenceClient(token=api_key)

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        def _call():
            resp = self.client.chat_completion(
                model=model_name, messages=msgs, max_tokens=auto_max_tokens(model_name, base=2048)
            )
            return (resp.choices[0].message.content or "").strip()
        try:
            return _retry_sync(_call)
        except Exception as e:
            return f"Error: {e}"


# ── Ollama ────────────────────────────────────────────────────────────────────

class OllamaIntegration(ModelIntegrator):
    def __init__(self, config: Dict):
        super().__init__(config)
        # Honor OLLAMA_BASE_URL env var (documented in .env.example) over the
        # config-file value so a remote Ollama instance is picked up without
        # editing configs/model_config.json.  Config file > hardcoded default.
        raw = (
            os.getenv("OLLAMA_BASE_URL")
            or config.get("ollama_base_url")
            or "http://localhost:11434"
        )
        # Normalize: strip trailing slash and /v1 suffix.  /v1 is the
        # OpenAI-compatible path; OllamaIntegration uses the native /api/chat
        # endpoint, so /v1 would produce a wrong URL (/v1/api/chat -> 404).
        self.base_url = raw.rstrip("/")
        if self.base_url.endswith("/v1"):
            self.base_url = self.base_url[:-3].rstrip("/") or "http://localhost:11434"
        self._session = requests.Session()

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        clean = model_name.replace("ollama/", "").replace("ollama:", "")
        clean = clean.replace("ollama-cloud/", "").replace("ollama-cloud:", "")
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        def _call():
            resp = self._session.post(
                f"{self.base_url}/api/chat",
                json={"model": clean, "messages": msgs, "stream": False},
                timeout=240,
            )
            resp.raise_for_status()
            return (resp.json()["message"]["content"] or "").strip()
        try:
            return _retry_sync(_call)
        except Exception as e:
            return f"Error: {e}"

    async def send_prompt_async(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        try:
            import aiohttp
        except ImportError:
            # Fall back to thread pool
            return await super().send_prompt_async(prompt, model_name, system)

        clean = model_name.replace("ollama/", "").replace("ollama:", "")
        clean = clean.replace("ollama-cloud/", "").replace("ollama-cloud:", "")
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})

        async def _call():
            async with aiohttp.ClientSession() as s:
                async with s.post(
                    f"{self.base_url}/api/chat",
                    json={"model": clean, "messages": msgs, "stream": False},
                    timeout=aiohttp.ClientTimeout(total=240),
                ) as r:
                    r.raise_for_status()
                    data = await r.json()
                    return (data["message"]["content"] or "").strip()
        try:
            return await _retry_async(_call)
        except Exception as e:
            return f"Error: {e}"

    def get_available_models(self) -> List[str]:
        try:
            resp = self._session.get(f"{self.base_url}/api/tags", timeout=5)
            resp.raise_for_status()
            return [m["name"] for m in resp.json().get("models", [])]
        except Exception:
            return []

    # Alias so ModelManager.discover_all_models() can call a uniform method.
    discover_models = get_available_models


class OllamaCloudIntegration(OpenAICompatIntegration):
    """Ollama Cloud — remote models via ollama.com/v1 with reasoning model support."""
    def __init__(self, config: Dict):
        super().__init__(config,
            base_url=config.get("ollama_cloud_base_url", "https://ollama.com/v1"),
            api_key=config.get("ollama_cloud_api_key") or os.getenv("OLLAMA_API_KEY") or "",
            label="Ollama Cloud")
    
    def _clean_name(self, model_name: str) -> str:
        """Strip the ollama-cloud/ prefix so the API receives the bare model ID."""
        return model_name.replace("ollama-cloud/", "").replace("ollama-cloud:", "")

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        clean = self._clean_name(model_name)
        def _call():
            resp = self.client.chat.completions.create(
                model=clean,
                messages=self._msgs(prompt, system),
                max_tokens=auto_max_tokens(model_name),
                temperature=0.7,
            )
            return (resp.choices[0].message.content or "").strip()
        try:
            return _retry_sync(_call)
        except Exception as e:
            return f"Error: {e}"

    async def send_prompt_async(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        clean = self._clean_name(model_name)
        async def _call():
            resp = await self.async_client.chat.completions.create(
                model=clean,
                messages=self._msgs(prompt, system),
                max_tokens=auto_max_tokens(model_name),
                temperature=0.7,
            )
            return (resp.choices[0].message.content or "").strip()
        try:
            return await _retry_async(_call)
        except Exception as e:
            return f"Error: {e}"

    def discover_models(self) -> List[str]:
        """List models from Ollama Cloud via GET /v1/models, prefixed with
        'ollama-cloud/' so routing works correctly."""
        try:
            ids = super().discover_models()
            return [f"ollama-cloud/{i}" for i in ids]
        except Exception:
            return []

    def send_prompt_raw(self, prompt: str, model_name: str, system: Optional[str] = None) -> Dict[str, Any]:
        """Send prompt via raw HTTP to capture reasoning field (OpenAI SDK drops it)."""
        clean = self._clean_name(model_name)
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        data = {
            "model": clean,
            "messages": msgs,
            "max_tokens": auto_max_tokens(model_name),
            "temperature": 0.7,
            "stream": False,
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key if hasattr(self, 'api_key') else (self.config.get('ollama_cloud_api_key') or os.getenv('OLLAMA_API_KEY') or '')}",
        }
        base_url = self.config.get("ollama_cloud_base_url", "https://ollama.com/v1")

        def _call():
            resp = requests.post(
                f"{base_url}/chat/completions",
                json=data, headers=headers, timeout=120,
            )
            resp.raise_for_status()
            rj = resp.json()
            choice = rj.get("choices", [{}])[0]
            msg = choice.get("message", {})
            return {
                "content": (msg.get("content") or "").strip(),
                "reasoning": (msg.get("reasoning") or "").strip(),
                "model": rj.get("model", model_name),
                "usage": rj.get("usage", {}),
            }
        try:
            return _retry_sync(_call)
        except Exception as e:
            return {"content": f"Error: {e}", "reasoning": "", "model": model_name, "usage": {}}


# ── Custom API (GLM etc.) ─────────────────────────────────────────────────────

class CustomAPIIntegration(ModelIntegrator):
    def __init__(self, config: Dict):
        super().__init__(config)
        self.api_endpoints = config.get("api_endpoints", {})
        self.api_keys      = config.get("api_keys", {})
        self.headers       = config.get("default_headers", {
            "Content-Type": "application/json",
            "User-Agent":   "GenAI-Security-Toolkit/2.0",
        })
        self._session = requests.Session()

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        ep = self.api_endpoints.get(model_name)
        if not ep:
            return f"Error: No endpoint configured for {model_name}"
        url     = ep["url"]
        api_key = self.api_keys.get(model_name) or os.getenv(f"{model_name.upper()}_API_KEY")
        headers = {**self.headers, **ep.get("headers", {})}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        fmt = ep.get("payload_format", "openai")
        if fmt == "openai":
            msgs: list = []
            if system:
                msgs.append({"role": "system", "content": system})
            msgs.append({"role": "user", "content": prompt})
            data: Dict[str, Any] = {
                "model": model_name, "messages": msgs,
                "max_tokens": ep.get("max_tokens", 4000),
                "temperature": ep.get("temperature", 0.7),
            }
        elif fmt == "simple":
            data = {"prompt": prompt,
                    "max_tokens": ep.get("max_tokens", 4000),
                    "temperature": ep.get("temperature", 0.7)}
        else:
            data = ep.get("custom_payload", {}).copy()
            data["prompt"] = prompt

        def _call():
            resp = self._session.post(url, json=data, headers=headers, timeout=30)
            resp.raise_for_status()
            rj = resp.json()
            if "choices" in rj:
                return rj["choices"][0]["message"]["content"]
            for key in ("response", "text", "output", "content"):
                if key in rj:
                    return rj[key]
            return str(rj)
        try:
            return _retry_sync(_call)
        except Exception as e:
            return f"Error: {e}"


# ── Route prefix → integration key ───────────────────────────────────────────

_PREFIX_MAP = [
    # OpenAI — chat & reasoning lines (gpt-*, o1/o3/o4/o5, chatgpt-*)
    ("chatgpt",               "openai"),
    ("o1",                    "openai"),
    ("o3",                    "openai"),
    ("o4",                    "openai"),
    ("o5",                    "openai"),
    ("gpt",                   "openai"),
    ("ft:",                   "openai"),   # fine-tuned OpenAI models
    # Anthropic
    ("claude",                "anthropic"),
    # Google
    ("gemini",               "google"),
    # xAI Grok
    ("grok",                 "xai"),
    # Perplexity (sonar models)
    ("llama-3.1-sonar",      "perplexity"),
    ("sonar",                "perplexity"),
    ("sonar-pro",            "perplexity"),
    ("sonar-reasoning",      "perplexity"),
    ("r1-sonar",             "perplexity"),
    # Groq
    ("llama-3.3",            "groq"),
    ("llama-3.1-8b",         "groq"),
    ("mixtral-8x7b-32768",   "groq"),
    ("whisper",              "groq"),
    ("kimi",                 "groq"),
    # Mistral / Le Chat
    ("mistral",              "mistral"),
    ("codestral",            "mistral"),
    ("magistral",            "mistral"),
    # Cohere
    ("command",              "cohere"),
    ("ayra",                 "cohere"),
    # DeepSeek
    ("deepseek",             "deepseek"),
    # AWS Bedrock — model IDs contain dots (anthropic. / amazon. / us.anthropic.)
    ("anthropic.",           "bedrock"),
    ("amazon.",              "bedrock"),
    ("us.anthropic.",        "bedrock"),
    # Together AI — org/model patterns
    ("meta-llama/llama-3",   "together"),
    ("meta-llama/llama-4",   "together"),
    ("mistralai/",           "together"),
    ("qwen/",                "together"),
    ("deepseek-ai/",         "together"),
    ("nvidia/",              "together"),
    # HuggingFace — org/model patterns
    ("meta-llama/meta-llama","huggingface"),
    # BigModel / Zhipu AI GLM
    ("glm",                  "bigmodel"),
    # Ollama Cloud (remote)
    ("ollama-cloud",         "ollama_cloud"),
    # Ollama (local) — keep last; the live-model check in _resolve handles tags
    ("ollama",               "ollama"),
]


# ── Model Manager ─────────────────────────────────────────────────────────────

class ModelManager:
    """Manages all model integrations and routes prompts to the right provider."""

    def __init__(self, config_file: str = "configs/model_config.json"):
        self._config_file = config_file
        self.config       = self._load_config(config_file)
        self._validate_routing_config()
        self.integrations: Dict[str, ModelIntegrator] = {}
        self._initialize_integrations()

    def _load_config(self, config_file: str) -> Dict[str, Any]:
        defaults: Dict[str, Any] = {
            "supported_models": [
                "gpt-4o", "gpt-4o-mini", "gpt-4-turbo",
                "o1", "o1-mini", "o3", "o3-mini", "o4-mini",
                "claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5",
                "gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash",
                "grok-3", "grok-3-fast", "grok-2",
            ],
            "ollama_base_url": "http://localhost:11434",
            "api_endpoints": {},
            "api_keys": {},
            "default_headers": {
                "Content-Type": "application/json",
                "User-Agent":   "GenAI-Security-Toolkit/2.0",
            },
        }
        if os.path.exists(config_file):
            try:
                with open(config_file) as f:
                    defaults.update(json.load(f))
            except (OSError, ValueError, TypeError) as e:
                raise ValueError("Cannot load model configuration; refusing default routing") from e
        return defaults

    def _try_init(self, key: str, cls, *args):
        try:
            self.integrations[key] = cls(*args)
            print(f"[+] {key}")
        except Exception as e:
            print(f"[-] {key}: {e}")

    def _initialize_integrations(self):
        cfg = self.config
        if cfg.get("openai_api_key")       or os.getenv("OPENAI_API_KEY"):
            self._try_init("openai",      OpenAIIntegration,      cfg)
        if cfg.get("anthropic_api_key")    or os.getenv("ANTHROPIC_API_KEY"):
            self._try_init("anthropic",   AnthropicIntegration,   cfg)
        if cfg.get("google_api_key")       or os.getenv("GOOGLE_API_KEY"):
            self._try_init("google",      GoogleIntegration,      cfg)
        if cfg.get("xai_api_key")           or os.getenv("XAI_API_KEY"):
            self._try_init("xai",         GrokIntegration,        cfg)
        if cfg.get("groq_api_key")         or os.getenv("GROQ_API_KEY"):
            self._try_init("groq",        GroqIntegration,        cfg)
        if cfg.get("mistral_api_key")      or os.getenv("MISTRAL_API_KEY"):
            self._try_init("mistral",     MistralIntegration,     cfg)
        if cfg.get("together_api_key")     or os.getenv("TOGETHER_API_KEY"):
            self._try_init("together",    TogetherIntegration,    cfg)
        if cfg.get("perplexity_api_key")   or os.getenv("PERPLEXITY_API_KEY"):
            self._try_init("perplexity",  PerplexityIntegration,  cfg)
        if cfg.get("deepseek_api_key")     or os.getenv("DEEPSEEK_API_KEY"):
            self._try_init("deepseek",    DeepSeekIntegration,    cfg)
        if cfg.get("cohere_api_key")       or os.getenv("COHERE_API_KEY"):
            self._try_init("cohere",      CohereIntegration,      cfg)
        if cfg.get("aws_access_key_id")    or os.getenv("AWS_ACCESS_KEY_ID"):
            self._try_init("bedrock",     BedrockIntegration,     cfg)
        if cfg.get("huggingface_api_key")  or os.getenv("HUGGINGFACE_API_KEY"):
            self._try_init("huggingface", HuggingFaceIntegration, cfg)
        if cfg.get("bigmodel_api_key")     or os.getenv("BIGMODEL_API_KEY"):
            self._try_init("bigmodel",    BigModelIntegration,    cfg)
        if cfg.get("ollama_cloud_api_key") or os.getenv("OLLAMA_API_KEY"):
            self._try_init("ollama_cloud", OllamaCloudIntegration, cfg)
        # Ollama — no key required
        self._try_init("ollama",  OllamaIntegration,  cfg)
        # Cache live Ollama model names for routing (avoids misrouting to OpenAI etc.)
        # Refreshed lazily in _resolve / refresh_ollama_models() so newly-pulled
        # models are picked up without a restart.
        self._ollama_models: set = set()
        # Cache live Ollama Cloud model names for routing.  Models like
        # 'glm-5.2:cloud' contain a colon which would misroute to local Ollama
        # without this check.  Refreshed lazily in _resolve.
        self._ollama_cloud_models: set = set()
        self.refresh_ollama_models()
        if cfg.get("api_endpoints"):
            self._try_init("custom", CustomAPIIntegration, cfg)
        # Dynamic providers added via UI (stored in model_config.json dynamic_providers)
        for pname, pcfg in cfg.get("dynamic_providers", {}).items():
            env_key = f"{pname.upper()}_API_KEY"
            api_key = pcfg.get("api_key") or os.getenv(env_key) or ""
            if api_key or pcfg.get("no_key_required"):
                try:
                    self.integrations[pname] = OpenAICompatIntegration(
                        cfg,
                        base_url=pcfg["base_url"],
                        api_key=api_key,
                        label=pcfg.get("label", pname),
                    )
                    print(f"[+] {pname} (dynamic)")
                except Exception as e:
                    print(f"[-] {pname}: {e}")

    def _validate_routing_config(self):
        strict = self.config.get("strict_model", True)
        if not isinstance(strict, bool):
            raise ValueError("strict_model must be a boolean")
        for key in ("model_routes", "model_aliases"):
            value = self.config.get(key, {})
            if not isinstance(value, dict) or any(
                not isinstance(k, str) or not k or not isinstance(v, str) or not v
                for k, v in value.items()
            ):
                raise ValueError(f"{key} must map nonempty model IDs to nonempty strings")
        if strict and self.config.get("model_aliases"):
            raise ValueError("model_aliases requires explicit consent via strict_model=false")

    def _required_provider(self, key):
        intg = self.integrations.get(key)
        if intg is None:
            raise ValueError(f"Requested provider '{key}' is unavailable; configure its credentials/SDK. No fallback dispatched.")
        return intg

    def _resolve_strict(self, model_name):
        low = model_name.lower()
        for prefix, provider in (("ollama-cloud/", "ollama_cloud"), ("ollama/", "ollama"), ("ollama:", "ollama")):
            if low.startswith(prefix):
                return self._required_provider(provider)
        if low.endswith((":cloud", ":cloud-latest")):
            raise ValueError("Ambiguous cloud model: use ollama/ or ollama-cloud/ explicitly, or configure model_routes")
        # Bedrock version suffixes also contain colons; they are not local tags.
        for prefix, provider in _PREFIX_MAP:
            if provider == "bedrock" and low.startswith(prefix):
                return self._required_provider(provider)
        if ":" in model_name and not low.startswith("ft:"):
            return self._required_provider("ollama")
        for prefix, provider in _PREFIX_MAP:
            if low.startswith(prefix):
                return self._required_provider(provider)
        if model_name in self._ollama_models:
            return self._required_provider("ollama")
        raise ValueError("Unknown model route; configure model_routes or use an explicit ollama/ prefix. No fallback dispatched.")

    def _resolve(self, model_name: str) -> Optional[ModelIntegrator]:
        self._validate_routing_config()
        route = self.config.get("model_routes", {}).get(model_name)
        if route:
            return self._required_provider(route)
        candidates = []
        if model_name in self.config.get("api_endpoints", {}):
            candidates.append("custom")
        for key, cfg in self.config.get("dynamic_providers", {}).items():
            if model_name in cfg.get("models", []):
                candidates.append(key)
        if len(candidates) > 1:
            raise ValueError("Conflicting model providers; select one with model_routes")
        if candidates:
            return self._required_provider(candidates[0])
        if self.config.get("strict_model", True):
            return self._resolve_strict(model_name)
        # Explicit custom endpoint wins before any heuristic (handles names like "glm-5:cloud")
        if model_name in self.config.get("api_endpoints", {}):
            return self.integrations.get("custom")
        # Dynamic providers (added via UI): check by explicit model list
        for pname, pcfg in self.config.get("dynamic_providers", {}).items():
            if model_name in pcfg.get("models", []):
                intg = self.integrations.get(pname)
                if intg:
                    return intg
        # ── Local Ollama vs Ollama Cloud routing ──
        # A ':cloud'-tagged model (e.g. 'glm-5.2:cloud') could be either:
        #   (a) pulled in the LOCAL Ollama instance, or
        #   (b) served by Ollama Cloud (remote, needs OLLAMA_API_KEY).
        # Check the local cache FIRST so locally-pulled :cloud models are not
        # misrouted to the remote cloud service.
        ollama = self.integrations.get("ollama")
        if ollama and model_name in self._ollama_models:
            return ollama
        # For ':cloud' models not in the local cache, rely on the background-warmup
        # cache.  Do NOT call refresh_ollama_models() here — that makes a sync HTTP
        # request that would block the async event loop during scans.
        # Ollama Cloud routing below handles uncached ':cloud' models.
        # Ollama Cloud (remote): check by prefix, ':cloud' suffix, or cache.
        ollama_cloud = self.integrations.get("ollama_cloud")
        if ollama_cloud:
            low = model_name.lower()
            if low.startswith("ollama-cloud/"):
                return ollama_cloud
            if low.endswith(":cloud") or low.endswith(":cloud-latest"):
                return ollama_cloud
            if model_name in self._ollama_cloud_models:
                return ollama_cloud
            # Cache miss — do NOT refresh here.  The sync HTTP call would block
            # the async event loop.  Background warmup / discover_all_models()
            # populates the cache; routing falls through to the heuristics below.
        # If the model has an 'ollama-cloud/' prefix but Ollama Cloud isn't
        # loaded (no OLLAMA_API_KEY) and it's NOT in the local Ollama cache,
        # return None now — don't let the last-resort Ollama fallback catch it
        # and send a cloud-only model name to local Ollama (-> 404 model not
        # found).  The caller gets a clear "No integration" error instead.
        if model_name.lower().startswith("ollama-cloud/"):
            return None
        # Local Ollama: colon→ollama rule for "name:tag" models not in cache.
        # This prevents models like "gpt-oss:20b" being misrouted to OpenAI.
        if ollama and ":" in model_name:
            return ollama
        # Cache miss — do NOT refresh here.  The sync HTTP call (GET /api/tags)
        # would block the async event loop.  Background warmup populates the
        # cache; routing falls through to the prefix/org heuristics below.
        low = model_name.lower()
        for prefix, key in _PREFIX_MAP:
            if low.startswith(prefix):
                intg = self.integrations.get(key)
                if intg:
                    return intg
        # Org/model pattern → HuggingFace (if loaded), else try Ollama
        if "/" in model_name:
            hf = self.integrations.get("huggingface")
            if hf:
                return hf
            # chevalblanc/*, catsarethebest/* etc. may be Ollama models
            ollama = self.integrations.get("ollama")
            if ollama:
                return ollama
        # Last resort: if Ollama is loaded, try it — catches mistral:latest,
        # llama3, deepseek-coder:latest and any other locally-pulled model.
        ollama = self.integrations.get("ollama")
        if ollama:
            return ollama
        return None

    # ── Public API ────────────────────────────────────────────────────────────

    def _prepare_dispatch(self, prompt, model_name, system):
        intg = self._resolve(model_name)
        if intg is None:
            raise ValueError("No configured integration; select a provider with model_routes")
        limit = self.config.get("model_specific_configurations", {}).get(model_name, {}).get("max_input_chars")
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
                raise ValueError("max_input_chars must be a positive integer")
            if len(prompt) + len(system or "") > limit:
                raise ValueError("Input exceeds configured max_input_chars; shorten it explicitly. Nothing was truncated or dispatched.")
        provider = next(k for k, v in self.integrations.items() if v is intg)
        dispatched = model_name
        if isinstance(intg, AnthropicIntegration):
            dispatched = intg._resolved(model_name)
        elif isinstance(intg, OllamaCloudIntegration):
            dispatched = intg._clean_name(model_name)
        elif isinstance(intg, OllamaIntegration):
            dispatched = model_name.replace("ollama/", "").replace("ollama:", "")
        audit = {"requested_model": model_name, "requested_provider": self.config.get("model_routes", {}).get(model_name),
                 "dispatched_provider": provider, "dispatched_model": dispatched}
        logger.info("model_dispatch", extra={"model_audit": audit})
        return intg, audit

    def _audit_result(self, response, audit):
        # Make a per-request copy: shared/fake responses must not leak metadata
        # between simultaneous calls.
        result = ModelResponse(
            str(response), getattr(response, "reported_model", None),
            getattr(response, "finish_reason", None),
            outcome=getattr(response, "outcome", None), request_metadata=audit,
            failure_kind=getattr(response, "failure_kind", None),
        )
        logger.info("model_result", extra={"model_audit": {
            **audit, **response_details(result),
            "is_error": result.startswith("Error:"),
        }})
        return result

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        try:
            intg, audit = self._prepare_dispatch(prompt, model_name, system)
        except ValueError as e:
            return f"Error: {e}"
        return self._audit_result(intg.send_prompt_with_system(prompt, model_name, system), audit)

    async def send_prompt_async(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        try:
            intg, audit = self._prepare_dispatch(prompt, model_name, system)
        except ValueError as e:
            return f"Error: {e}"
        return self._audit_result(await intg.send_prompt_async(prompt, model_name, system), audit)

    def get_available_models(self) -> List[str]:
        """Static catalogue + live Ollama models.
        Use discover_all_models() to also pull live model lists from cloud providers."""
        models = list(self.config.get("supported_models", []))
        ollama = self.integrations.get("ollama")
        if ollama:
            models += [f"ollama/{m}" for m in ollama.get_available_models()]
        return models

    def refresh_ollama_models(self) -> set:
        """Re-query the local Ollama instance for installed models and update the
        routing cache.  Safe to call repeatedly; cheap (one GET /api/tags)."""
        ollama = self.integrations.get("ollama")
        if not ollama:
            self._ollama_models = set()
            return self._ollama_models
        try:
            self._ollama_models = set(ollama.get_available_models())
        except Exception:
            pass
        return self._ollama_models

    def _refresh_ollama_cloud_models(self) -> set:
        """Re-query Ollama Cloud for available models and update the routing
        cache.  Models are stored WITH the 'ollama-cloud/' prefix so they
        match what discover_models() returns."""
        ollama_cloud = self.integrations.get("ollama_cloud")
        if not ollama_cloud:
            self._ollama_cloud_models = set()
            return self._ollama_cloud_models
        try:
            ids = ollama_cloud.discover_models() or []
            self._ollama_cloud_models = set(ids)
        except Exception:
            pass
        return self._ollama_cloud_models

    # Integrations without a discover_models() method are skipped.
    _DISCOVERY_ORDER = [
        "openai", "anthropic", "google", "xai", "groq", "mistral",
        "together", "perplexity", "deepseek", "cohere", "huggingface",
        "bigmodel", "ollama_cloud", "ollama",
    ]

    def discover_all_models(self) -> Dict[str, List[str]]:
        """Query every loaded integration that supports model discovery and
        return {provider_key: [model_id, ...]}.  Newly released models from any
        provider appear here automatically - no code change required when a new
        Claude / GPT / Grok / Gemini ships."""
        discovered: Dict[str, List[str]] = {}
        for key in self._DISCOVERY_ORDER:
            intg = self.integrations.get(key)
            if not intg:
                continue
            fn = getattr(intg, "discover_models", None)
            if fn is None:
                fn = getattr(intg, "get_available_models", None)
            if fn is None:
                continue
            try:
                ids = fn() or []
            except Exception as e:
                print(f"[-] discover {key}: {e}")
                ids = []
            if ids:
                discovered[key] = sorted(set(ids))
        # Dynamic (user-added) providers
        for pname, intg in self.integrations.items():
            if pname in self._DISCOVERY_ORDER or pname == "custom":
                continue
            fn = getattr(intg, "discover_models", None)
            if fn is None:
                continue
            try:
                ids = fn() or []
            except Exception:
                ids = []
            if ids:
                discovered[pname] = sorted(set(ids))
        return discovered

    def refresh_models(self) -> Dict[str, List[str]]:
        """Discover live models from all providers, merge new ones into
        configs/model_config.json supported_models, and refresh the Ollama
        routing cache.  Returns the discovered map."""
        self.refresh_ollama_models()
        self._refresh_ollama_cloud_models()
        discovered = self.discover_all_models()
        try:
            cfg_path = self._config_file
            cfg = self._load_config(cfg_path)
            supported = list(cfg.get("supported_models", []))
            seen = set(supported)
            changed = False
            for ids in discovered.values():
                for mid in ids:
                    if mid and mid not in seen:
                        supported.append(mid)
                        seen.add(mid)
                        changed = True
            if changed:
                cfg["supported_models"] = supported
                with open(cfg_path, "w") as f:
                    json.dump(cfg, f, indent=2)
                self.config["supported_models"] = supported
        except Exception as e:
            print(f"[-] refresh_models persist: {e}")
        return discovered

    def list_integrations(self) -> List[str]:
        return list(self.integrations.keys())

    def test_all_models(self) -> Dict[str, str]:
        results: Dict[str, str] = {}
        for model in self.config.get("supported_models", []):
            try:
                resp = self.send_prompt("Respond with: ok", model)
                results[model] = "ok" if not resp.startswith("Error:") else resp
            except Exception as e:
                results[model] = f"failed: {e}"
        return results


# ── Example config reference ──────────────────────────────────────────────────

EXAMPLE_CONFIG = {
    "supported_models": [
        "gpt-4o", "gpt-4o-mini",
        "claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5",
        "gemini-2.0-flash", "gemini-1.5-pro",
        "llama-3.3-70b-versatile",
        "mistral-large-latest",
        "command-r-plus",
        "deepseek-chat",
        "ollama/llama3.1", "ollama/deepseek-r1",
    ],
    "openai_api_key":      "",
    "anthropic_api_key":   "",
    "google_api_key":      "",
    "xai_api_key":         "",
    "groq_api_key":        "",
    "mistral_api_key":     "",
    "together_api_key":    "",
    "perplexity_api_key":  "",
    "deepseek_api_key":    "",
    "cohere_api_key":      "",
    "huggingface_api_key": "",
    "aws_region":          "us-east-1",
    "ollama_base_url":     "http://localhost:11434",
    "api_endpoints": {
        "glm-4": {
            "url": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
            "payload_format": "openai",
            "max_tokens": 4000,
        },
    },
    "api_keys":        {"glm-4": ""},
    "default_headers": {
        "Content-Type": "application/json",
        "User-Agent":   "GenAI-Security-Toolkit/2.0",
    },
}
