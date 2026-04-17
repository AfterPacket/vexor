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
import os
import time
from typing import Any, Dict, List, Optional

import requests

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


# ── Retry helper ──────────────────────────────────────────────────────────────

async def _retry_async(coro_fn, retries: int = 3, base_delay: float = 1.0):
    """
    Retry an async callable on transient errors (429, 503, timeout).
    Uses exponential backoff.  Does NOT sleep on first attempt.
    """
    last_err: Exception = RuntimeError("unknown")
    for attempt in range(retries):
        try:
            return await coro_fn()
        except Exception as e:
            last_err = e
            msg = str(e).lower()
            # Only retry on rate-limit / server errors
            if any(k in msg for k in ("429", "rate limit", "503", "timeout", "overloaded")):
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
            msg = str(e).lower()
            if any(k in msg for k in ("429", "rate limit", "503", "timeout", "overloaded")):
                if attempt < retries - 1:
                    time.sleep(base_delay * (2 ** attempt))
                continue
            raise
    raise last_err


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
        self.client       = openai.OpenAI(api_key=api_key)
        self.async_client = openai.AsyncOpenAI(api_key=api_key)

    def _build_messages(self, prompt: str, system: Optional[str]) -> list:
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        return msgs

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        def _call():
            resp = self.client.chat.completions.create(
                model=model_name,
                messages=self._build_messages(prompt, system),
                max_tokens=4096,
                temperature=0.7,
            )
            return resp.choices[0].message.content.strip()
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
                messages=self._build_messages(prompt, system),
                max_tokens=4096,
                temperature=0.7,
            )
            return resp.choices[0].message.content.strip()
        try:
            return await _retry_async(_call)
        except Exception as e:
            return f"Error: {e}"


# ── Anthropic ─────────────────────────────────────────────────────────────────

class AnthropicIntegration(ModelIntegrator):
    _MODEL_MAP = {
        "claude-opus-4-6":   "claude-opus-4-6",
        "claude-sonnet-4-6": "claude-sonnet-4-6",
        "claude-haiku-4-5":  "claude-haiku-4-5",
        "claude-3-opus":     "claude-opus-4-6",
        "claude-3-sonnet":   "claude-sonnet-4-6",
        "claude-3-haiku":    "claude-haiku-4-5",
        "claude-3-5-sonnet": "claude-sonnet-4-6",
    }

    def __init__(self, config: Dict):
        super().__init__(config)
        if not ANTHROPIC_AVAILABLE:
            raise ImportError("pip install anthropic")
        api_key = config.get("anthropic_api_key") or os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not configured")
        self.client       = anthropic.Anthropic(api_key=api_key)
        self.async_client = anthropic.AsyncAnthropic(api_key=api_key)

    def _resolved(self, model: str) -> str:
        return self._MODEL_MAP.get(model, model)

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        kwargs: Dict[str, Any] = {
            "model":    self._resolved(model_name),
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        def _call():
            resp = self.client.messages.create(**kwargs)
            return resp.content[0].text.strip()
        try:
            return _retry_sync(_call)
        except Exception as e:
            return f"Error: {e}"

    async def send_prompt_async(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        kwargs: Dict[str, Any] = {
            "model":    self._resolved(model_name),
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        async def _call():
            resp = await self.async_client.messages.create(**kwargs)
            return resp.content[0].text.strip()
        try:
            return await _retry_async(_call)
        except Exception as e:
            return f"Error: {e}"


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
            return resp.text.strip()
        try:
            return _retry_sync(_call)
        except Exception as e:
            return f"Error: {e}"


# ── OpenAI-compatible base (Groq / Together / Perplexity / DeepSeek / Mistral) ─

class OpenAICompatIntegration(ModelIntegrator):
    """Re-uses the OpenAI SDK with a custom base_url."""

    def __init__(self, config: Dict, base_url: str, api_key: str, label: str):
        super().__init__(config)
        if not OPENAI_AVAILABLE:
            raise ImportError("pip install openai")
        if not api_key:
            raise ValueError(f"{label} API key not configured")
        self.client       = openai.OpenAI(api_key=api_key, base_url=base_url)
        self.async_client = openai.AsyncOpenAI(api_key=api_key, base_url=base_url)

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
                max_tokens=4096,
                temperature=0.7,
            )
            return resp.choices[0].message.content.strip()
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
                max_tokens=4096,
                temperature=0.7,
            )
            return resp.choices[0].message.content.strip()
        try:
            return await _retry_async(_call)
        except Exception as e:
            return f"Error: {e}"


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
            return resp.message.content[0].text.strip()
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
            return resp["output"]["message"]["content"][0]["text"].strip()
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
                model=model_name, messages=msgs, max_tokens=2048
            )
            return resp.choices[0].message.content.strip()
        try:
            return _retry_sync(_call)
        except Exception as e:
            return f"Error: {e}"


# ── Ollama ────────────────────────────────────────────────────────────────────

class OllamaIntegration(ModelIntegrator):
    def __init__(self, config: Dict):
        super().__init__(config)
        self.base_url = config.get("ollama_base_url", "http://localhost:11434")
        self._session = requests.Session()

    def send_prompt(self, prompt: str, model_name: str) -> str:
        return self.send_prompt_with_system(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        clean = model_name.replace("ollama/", "").replace("ollama:", "")
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        def _call():
            resp = self._session.post(
                f"{self.base_url}/api/chat",
                json={"model": clean, "messages": msgs, "stream": False},
                timeout=120,
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"].strip()
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
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})

        async def _call():
            async with aiohttp.ClientSession() as s:
                async with s.post(
                    f"{self.base_url}/api/chat",
                    json={"model": clean, "messages": msgs, "stream": False},
                    timeout=aiohttp.ClientTimeout(total=120),
                ) as r:
                    r.raise_for_status()
                    data = await r.json()
                    return data["message"]["content"].strip()
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
    ("gpt",                  "openai"),
    ("claude",               "anthropic"),
    ("gemini",               "google"),
    ("llama-3.1-sonar",      "perplexity"),
    ("llama-3.3",            "groq"),
    ("llama-3.1-8b",         "groq"),
    ("mixtral-8x7b-32768",   "groq"),
    ("whisper",              "groq"),
    ("mistral",              "mistral"),
    ("command",              "cohere"),
    ("deepseek",             "deepseek"),
    ("anthropic.",           "bedrock"),
    ("amazon.",              "bedrock"),
    ("us.anthropic.",        "bedrock"),
    ("meta-llama/llama-3",   "together"),
    ("mistralai/",           "together"),
    ("meta-llama/meta-llama","huggingface"),
    ("ollama",               "ollama"),
]


# ── Model Manager ─────────────────────────────────────────────────────────────

class ModelManager:
    """Manages all model integrations and routes prompts to the right provider."""

    def __init__(self, config_file: str = "configs/model_config.json"):
        self.config       = self._load_config(config_file)
        self.integrations: Dict[str, ModelIntegrator] = {}
        self._initialize_integrations()

    def _load_config(self, config_file: str) -> Dict:
        defaults: Dict[str, Any] = {
            "supported_models": [
                "gpt-4o", "gpt-4o-mini",
                "claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5",
                "gemini-2.0-flash", "gemini-1.5-pro",
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
            except Exception as e:
                print(f"[!] Config load error ({config_file}): {e}")
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
        # Ollama — no key required
        self._try_init("ollama",  OllamaIntegration,  cfg)
        # Cache live Ollama model names for routing (avoids misrouting to OpenAI etc.)
        self._ollama_models: set = set()
        ollama = self.integrations.get("ollama")
        if ollama:
            try:
                self._ollama_models = set(ollama.get_available_models())
            except Exception:
                pass
        if cfg.get("api_endpoints"):
            self._try_init("custom", CustomAPIIntegration, cfg)

    def _resolve(self, model_name: str) -> Optional[ModelIntegrator]:
        # Check Ollama first: cached model list or "name:tag" colon format
        # This prevents models like "gpt-oss:20b" being misrouted to OpenAI
        ollama = self.integrations.get("ollama")
        if ollama and (model_name in self._ollama_models or ":" in model_name):
            return ollama
        low = model_name.lower()
        for prefix, key in _PREFIX_MAP:
            if low.startswith(prefix):
                intg = self.integrations.get(key)
                if intg:
                    return intg
        # Explicit API endpoint configured
        if model_name in self.config.get("api_endpoints", {}):
            return self.integrations.get("custom")
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

    def send_prompt(self, prompt: str, model_name: str) -> str:
        intg = self._resolve(model_name)
        if not intg:
            return f"Error: No integration for '{model_name}'"
        return intg.send_prompt(prompt, model_name)

    def send_prompt_with_system(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        intg = self._resolve(model_name)
        if not intg:
            return f"Error: No integration for '{model_name}'"
        return intg.send_prompt_with_system(prompt, model_name, system)

    async def send_prompt_async(
        self, prompt: str, model_name: str, system: Optional[str] = None
    ) -> str:
        intg = self._resolve(model_name)
        if not intg:
            return f"Error: No integration for '{model_name}'"
        return await intg.send_prompt_async(prompt, model_name, system)

    def get_available_models(self) -> List[str]:
        models = list(self.config.get("supported_models", []))
        ollama = self.integrations.get("ollama")
        if ollama:
            models += [f"ollama/{m}" for m in ollama.get_available_models()]
        return models

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
