#!/usr/bin/env python3
"""
Model routes
GET  /api/models           — list available models
GET  /api/models/providers — provider initialisation status
POST /api/models/test      — send a test prompt to a model
GET  /api/models/{model}   — probe connectivity for one model
"""

import asyncio
import time

from fastapi import APIRouter, HTTPException

from api.schemas.models import (
    ModelInfo, ModelsListResponse,
    ModelTestRequest, ModelTestResponse,
)

router = APIRouter()

# Lazy singleton
_mm = None


def _get_mm():
    global _mm
    if _mm is None:
        try:
            from models.integrations import ModelManager
            _mm = ModelManager()
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"ModelManager unavailable: {e}")
    return _mm


# ── Known model catalogue (provider-tagged) ───────────────────────────────────

_CATALOGUE = [
    # OpenAI
    ("gpt-4o",                        "openai"),
    ("gpt-4o-mini",                   "openai"),
    ("gpt-4-turbo",                   "openai"),
    # Anthropic
    ("claude-opus-4-6",               "anthropic"),
    ("claude-sonnet-4-6",             "anthropic"),
    ("claude-haiku-4-5",              "anthropic"),
    # Google
    ("gemini-2.0-flash",              "google"),
    ("gemini-1.5-pro",                "google"),
    ("gemini-1.5-flash",              "google"),
    # Groq
    ("llama-3.3-70b-versatile",       "groq"),
    ("llama-3.1-8b-instant",          "groq"),
    ("mixtral-8x7b-32768",            "groq"),
    # Mistral
    ("mistral-large-latest",          "mistral"),
    ("mistral-medium-latest",         "mistral"),
    ("mistral-small-latest",          "mistral"),
    # Cohere
    ("command-r-plus",                "cohere"),
    ("command-r",                     "cohere"),
    # Together AI
    ("meta-llama/Llama-3-70b-chat-hf","together"),
    ("mistralai/Mixtral-8x7B-Instruct-v0.1", "together"),
    # Perplexity
    ("llama-3.1-sonar-large-128k-online", "perplexity"),
    ("llama-3.1-sonar-small-128k-online", "perplexity"),
    # DeepSeek
    ("deepseek-chat",                 "deepseek"),
    ("deepseek-reasoner",             "deepseek"),
    # AWS Bedrock
    ("anthropic.claude-opus-4-6-20250514-v1:0",  "bedrock"),
    ("amazon.titan-text-express-v1",  "bedrock"),
    # HuggingFace
    ("meta-llama/Meta-Llama-3-8B-Instruct", "huggingface"),
    # GLM
    ("glm-4",                         "custom"),
    # Ollama — models added dynamically from live /api/tags query
]


_PROVIDER_ENV_KEYS = {
    "openai":      "OPENAI_API_KEY",
    "anthropic":   "ANTHROPIC_API_KEY",
    "google":      "GOOGLE_API_KEY",
    "groq":        "GROQ_API_KEY",
    "mistral":     "MISTRAL_API_KEY",
    "together":    "TOGETHER_API_KEY",
    "perplexity":  "PERPLEXITY_API_KEY",
    "deepseek":    "DEEPSEEK_API_KEY",
    "cohere":      "COHERE_API_KEY",
    "bedrock":     "AWS_ACCESS_KEY_ID",
    "huggingface": "HUGGINGFACE_API_KEY",
    "ollama":      None,  # no key required
    "custom":      None,  # key configured per-model in model_config.json
}


@router.get("/rate-limits")
async def get_rate_limits():
    """Return current RPM limits and token bucket status for all providers."""
    from core.rate_limiter import get_registry, PROVIDER_RPM
    reg = get_registry()
    return {"rate_limits": reg.all_status(), "configured_rpm": PROVIDER_RPM}


@router.get("/providers")
async def list_providers():
    """Return initialisation status for every provider."""
    import os
    mm = _get_mm()
    loaded = set(getattr(mm, "integrations", {}).keys())
    result = []
    for provider, env_key in _PROVIDER_ENV_KEYS.items():
        key_set = (env_key is None) or bool(os.getenv(env_key))
        result.append({
            "provider":   provider,
            "loaded":     provider in loaded,
            "env_key":    env_key,
            "key_set":    key_set,
            "models":     [m for m, p in _CATALOGUE if p == provider],
        })
    return {"providers": result}


@router.get("", response_model=ModelsListResponse)
async def list_models():
    """Return all known models. 'available' reflects whether the provider's API key is loaded.
    Ollama models are queried live from the local Ollama instance."""
    mm = _get_mm()
    loaded_providers: set = set(getattr(mm, "integrations", {}).keys())

    # Static catalogue
    seen: set = set()
    items = []
    for model_id, provider in _CATALOGUE:
        seen.add(model_id)
        items.append(ModelInfo(
            model_id  = model_id,
            provider  = provider,
            available = provider in loaded_providers,
            aliases   = [],
        ))

    # Append live Ollama models not already in catalogue
    ollama_intg = getattr(mm, "integrations", {}).get("ollama")
    if ollama_intg and hasattr(ollama_intg, "get_available_models"):
        try:
            for model_id in ollama_intg.get_available_models():
                if model_id not in seen:
                    seen.add(model_id)
                    items.append(ModelInfo(
                        model_id  = model_id,
                        provider  = "ollama",
                        available = True,
                        aliases   = [],
                    ))
        except Exception:
            pass

    return ModelsListResponse(models=items, total=len(items))


@router.post("/test", response_model=ModelTestResponse)
async def test_model(req: ModelTestRequest):
    """Send a test prompt and return the response + latency."""
    mm    = _get_mm()
    start = time.time()
    try:
        response = await mm.send_prompt_async(req.prompt, req.model, req.system or None)
        return ModelTestResponse(
            model      = req.model,
            response   = response,
            latency_ms = round((time.time() - start) * 1000, 1),
            success    = True,
        )
    except Exception as e:
        return ModelTestResponse(
            model      = req.model,
            response   = "",
            latency_ms = round((time.time() - start) * 1000, 1),
            success    = False,
            error      = str(e),
        )


@router.get("/{model_id:path}", response_model=ModelTestResponse)
async def probe_model(model_id: str):
    """Quick connectivity check — sends 'ping' and returns result."""
    mm    = _get_mm()
    start = time.time()
    try:
        response = await mm.send_prompt_async(
            "Respond with the single word: pong", model_id
        )
        return ModelTestResponse(
            model      = model_id,
            response   = response,
            latency_ms = round((time.time() - start) * 1000, 1),
            success    = True,
        )
    except Exception as e:
        return ModelTestResponse(
            model      = model_id,
            response   = "",
            latency_ms = round((time.time() - start) * 1000, 1),
            success    = False,
            error      = str(e),
        )
