#!/usr/bin/env python3
"""
Model routes
GET  /api/models           — list available models
GET  /api/models/providers — provider initialisation status
POST /api/models/test      — send a test prompt to a model
GET  /api/models/{model}   — probe connectivity for one model
"""

import asyncio
import json
import os
import time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

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
    # xAI Grok
    ("grok-3",                        "xai"),
    ("grok-3-fast",                   "xai"),
    ("grok-3-mini",                   "xai"),
    ("grok-3-mini-fast",              "xai"),
    ("grok-2",                        "xai"),
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
    # BigModels (Zhipu AI GLM series)
    ("glm-4",                         "bigmodel"),
    ("glm-4-flash",                   "bigmodel"),
    ("glm-4-plus",                    "bigmodel"),
    ("glm-z1-flash",                  "bigmodel"),
    # Ollama — models added dynamically from live /api/tags query
]


_PROVIDER_ENV_KEYS = {
    "openai":      "OPENAI_API_KEY",
    "anthropic":   "ANTHROPIC_API_KEY",
    "google":      "GOOGLE_API_KEY",
    "xai":         "XAI_API_KEY",
    "groq":        "GROQ_API_KEY",
    "mistral":     "MISTRAL_API_KEY",
    "together":    "TOGETHER_API_KEY",
    "perplexity":  "PERPLEXITY_API_KEY",
    "deepseek":    "DEEPSEEK_API_KEY",
    "cohere":      "COHERE_API_KEY",
    "bedrock":     "AWS_ACCESS_KEY_ID",
    "huggingface": "HUGGINGFACE_API_KEY",
    "bigmodel":    "BIGMODEL_API_KEY",
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
    """Return initialisation status for every provider, including dynamic ones."""
    mm = _get_mm()
    loaded = set(getattr(mm, "integrations", {}).keys())
    result = []
    for provider, env_key in _PROVIDER_ENV_KEYS.items():
        key_set = (env_key is None) or bool(os.getenv(env_key))
        result.append({
            "provider": provider,
            "loaded":   provider in loaded,
            "env_key":  env_key,
            "key_set":  key_set,
            "models":   [m for m, p in _CATALOGUE if p == provider],
            "dynamic":  False,
        })
    cfg = _load_config_file()
    for pname, pcfg in cfg.get("dynamic_providers", {}).items():
        env_key = f"{pname.upper()}_API_KEY"
        key_set = bool(os.getenv(env_key)) or pcfg.get("no_key_required", False)
        result.append({
            "provider": pname,
            "loaded":   pname in loaded,
            "env_key":  env_key,
            "key_set":  key_set,
            "models":   pcfg.get("models", []),
            "label":    pcfg.get("label", pname),
            "dynamic":  True,
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

    # Dynamic provider models
    for pname, pcfg in _load_config_file().get("dynamic_providers", {}).items():
        for model_id in pcfg.get("models", []):
            if model_id not in seen:
                seen.add(model_id)
                items.append(ModelInfo(
                    model_id  = model_id,
                    provider  = pname,
                    available = pname in loaded_providers,
                    aliases   = [],
                ))

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


# ── Custom provider management ────────────────────────────────────────────────

_CONFIG_FILE = "configs/model_config.json"
_ENV_FILE    = ".env"


def _load_config_file() -> dict:
    if os.path.exists(_CONFIG_FILE):
        with open(_CONFIG_FILE) as f:
            return json.load(f)
    return {}


def _save_config_file(cfg: dict):
    with open(_CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def _reload_mm():
    global _mm
    _mm = None


def _write_env_key(key: str, value: str):
    """Upsert KEY=value in .env, then set it in the current process environment."""
    lines: list = []
    updated = False
    if os.path.exists(_ENV_FILE):
        with open(_ENV_FILE) as f:
            for line in f:
                if line.startswith(f"{key}="):
                    lines.append(f"{key}={value}\n")
                    updated = True
                else:
                    lines.append(line)
    if not updated:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append(f"{key}={value}\n")
    with open(_ENV_FILE, "w") as f:
        f.writelines(lines)
    os.environ[key] = value  # available immediately without restart


def _remove_env_key(key: str):
    """Comment out KEY from .env (preserves history, stops it being picked up)."""
    if not os.path.exists(_ENV_FILE):
        return
    with open(_ENV_FILE) as f:
        lines = f.readlines()
    with open(_ENV_FILE, "w") as f:
        for line in lines:
            if line.startswith(f"{key}="):
                f.write(f"# {line}")
            else:
                f.write(line)
    os.environ.pop(key, None)


async def _discover_models(base_url: str, api_key: str) -> list:
    """Try GET {base_url}/models and return a sorted list of model IDs."""
    import asyncio
    import requests as _req

    def _fetch():
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        url = base_url.rstrip("/") + "/models"
        r = _req.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json()

    try:
        data = await asyncio.to_thread(_fetch)
        if isinstance(data, dict) and "data" in data:
            return sorted(m["id"] for m in data["data"] if isinstance(m, dict) and "id" in m)
        if isinstance(data, list):
            return sorted(m.get("id", str(m)) if isinstance(m, dict) else str(m) for m in data)
    except Exception:
        pass
    return []


class ProviderAddRequest(BaseModel):
    name:            str
    label:           str  = ""
    base_url:        str
    api_key:         str  = ""
    no_key_required: bool = False


@router.post("/providers")
async def add_provider(req: ProviderAddRequest):
    """Discover models, write API key to .env, save to model_config.json, reload MM."""
    import re
    if not re.match(r"^[a-zA-Z0-9_-]+$", req.name):
        raise HTTPException(status_code=400, detail="name must be alphanumeric/underscore/hyphen")
    if not req.base_url:
        raise HTTPException(status_code=400, detail="base_url is required")

    env_key = f"{req.name.upper()}_API_KEY"
    models  = await _discover_models(req.base_url, req.api_key)

    if req.api_key:
        _write_env_key(env_key, req.api_key)

    cfg = _load_config_file()
    cfg.setdefault("dynamic_providers", {})[req.name] = {
        "base_url":        req.base_url,
        "label":           req.label or req.name,
        "models":          models,
        "no_key_required": req.no_key_required,
    }
    for m in models:
        if m not in cfg.get("supported_models", []):
            cfg.setdefault("supported_models", []).append(m)
    _save_config_file(cfg)
    _reload_mm()

    return {"status": "added", "name": req.name, "env_key": env_key, "models": models}


@router.delete("/providers/{name}")
async def remove_provider(name: str):
    """Remove a dynamic provider from model_config.json (comments out its .env key)."""
    cfg = _load_config_file()
    dynp = cfg.get("dynamic_providers", {})
    if name not in dynp:
        raise HTTPException(status_code=404, detail=f"Dynamic provider '{name}' not found")
    removed_models = dynp.pop(name).get("models", [])
    supported = cfg.get("supported_models", [])
    for m in removed_models:
        if m in supported:
            supported.remove(m)
    _save_config_file(cfg)
    _remove_env_key(f"{name.upper()}_API_KEY")
    _reload_mm()
    return {"status": "removed", "name": name}


class CustomProviderRequest(BaseModel):
    model_id:       str
    url:            str
    api_key:        str = ""
    payload_format: str = "openai"
    max_tokens:     int = 4000
    temperature:    float = 0.7


@router.get("/providers/custom")
async def list_custom_providers():
    """Return all custom API endpoints from model_config.json."""
    cfg = _load_config_file()
    return {"endpoints": cfg.get("api_endpoints", {})}


@router.post("/providers/custom")
async def add_custom_provider(req: CustomProviderRequest):
    """Add a custom API endpoint to model_config.json and reload the model manager."""
    if not req.model_id or not req.url:
        raise HTTPException(status_code=400, detail="model_id and url are required")
    cfg = _load_config_file()
    cfg.setdefault("api_endpoints", {})[req.model_id] = {
        "url":            req.url,
        "payload_format": req.payload_format,
        "max_tokens":     req.max_tokens,
        "temperature":    req.temperature,
    }
    if req.api_key:
        cfg.setdefault("api_keys", {})[req.model_id] = req.api_key
    if req.model_id not in cfg.get("supported_models", []):
        cfg.setdefault("supported_models", []).append(req.model_id)
    _save_config_file(cfg)
    _reload_mm()
    return {"status": "added", "model_id": req.model_id}


@router.delete("/providers/custom/{model_id:path}")
async def remove_custom_provider(model_id: str):
    """Remove a custom API endpoint from model_config.json and reload the model manager."""
    cfg = _load_config_file()
    endpoints = cfg.get("api_endpoints", {})
    if model_id not in endpoints:
        raise HTTPException(status_code=404, detail=f"No custom endpoint for '{model_id}'")
    del endpoints[model_id]
    cfg.get("api_keys", {}).pop(model_id, None)
    supported = cfg.get("supported_models", [])
    if model_id in supported:
        supported.remove(model_id)
    _save_config_file(cfg)
    _reload_mm()
    return {"status": "removed", "model_id": model_id}


# ── Ollama configuration ────────────────────────────────────────────────────────

class OllamaConfigRequest(BaseModel):
    ollama_base_url: str


@router.get("/config/ollama")
async def get_ollama_config():
    """Return the current Ollama base URL from model_config.json."""
    cfg = _load_config_file()
    return {"ollama_base_url": cfg.get("ollama_base_url", "http://127.0.0.1:11434/v1")}


@router.patch("/config/ollama")
async def update_ollama_config(req: OllamaConfigRequest):
    """Update Ollama base URL in model_config.json and reload the ModelManager."""
    if not req.ollama_base_url:
        raise HTTPException(status_code=400, detail="ollama_base_url is required")
    cfg = _load_config_file()
    cfg["ollama_base_url"] = req.ollama_base_url
    _save_config_file(cfg)
    _reload_mm()
    # Return the live model list for the UI to refresh
    mm = _get_mm()
    ollama_intg = getattr(mm, "integrations", {}).get("ollama")
    models = []
    if ollama_intg and hasattr(ollama_intg, "get_available_models"):
        try:
            models = ollama_intg.get_available_models()
        except Exception:
            pass
    return {"status": "updated", "ollama_base_url": req.ollama_base_url, "models": models}


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
