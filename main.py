#!/usr/bin/env python3
"""
Vexor — FastAPI Application
Offensive LLM security testing platform (OWASP GenAI Top 10)

Usage:
    uvicorn main:app --reload --host 127.0.0.1 --port 8080

URLs:
    http://localhost:8080/       Web UI (dashboard)
    http://localhost:8080/docs   Swagger UI
    http://localhost:8080/redoc  ReDoc
    http://localhost:8080/api    API info (JSON)
"""

import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict

# Load .env from project root before anything else reads os.getenv()
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env", override=True)
except ImportError:
    pass

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.routes import scan, models, prompts, overrides, import_routes, reports, synthetic, discovery, chain


# ── Shared in-memory store for async scan jobs ────────────────────────────────
# key: scan_id / batch_id → status dict
# In production replace with Redis + Celery
scan_store: Dict[str, Any] = {}
batch_store: Dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio

    app.state.scan_store  = scan_store
    app.state.batch_store = batch_store
    from api.routes.scan import load_all_scans_from_disk
    n = load_all_scans_from_disk(scan_store)
    print(f"[*] Vexor API — starting up (loaded {n} persisted scan(s))")

    # Lazy model warming: defer discovery and module loading to background
    # This keeps startup fast and responsive
    async def _background_warmup():
        """Non-blocking warmup of ModelManager and vulnerability modules."""
        try:
            from api.routes.scan import _scanner
            from core.prompt_engine import ALL_VULNS

            print("[*] Background warmup: initializing ModelManager...")
            mm = _scanner._get_mm()
            print("[*] Background warmup: ModelManager initialized")

            # Load vuln modules with timeout to prevent hanging
            print(f"[*] Background warmup: loading {len(ALL_VULNS)} vuln module(s)...")
            timeout_per_module = 5  # seconds
            for v in ALL_VULNS:
                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(_scanner.prompt_engine.load_module, v),
                        timeout=timeout_per_module
                    )
                except asyncio.TimeoutError:
                    print(f"[!] Background warmup: vuln module {v} timed out (skipped)")
                except Exception as e:
                    print(f"[!] Background warmup: vuln module {v} failed: {e}")
            print("[*] Background warmup: vuln modules loaded")

            # Auto-discover newly released models (with timeout)
            print("[*] Background warmup: discovering models...")
            try:
                discovered = await asyncio.wait_for(
                    asyncio.to_thread(mm.refresh_models),
                    timeout=30  # 30s timeout for model discovery
                )
                total = sum(len(v) for v in discovered.values())
                if total:
                    print(f"[*] Background warmup: discovered {total} model(s)")
                else:
                    print("[*] Background warmup: no new models discovered (check API keys)")
            except asyncio.TimeoutError:
                print("[!] Background warmup: model discovery timed out (proceeding without refresh)")
            except Exception as e:
                print(f"[!] Background warmup: model discovery failed: {e}")

        except Exception as e:
            print(f"[!] Background warmup failed: {e}")

    # Schedule the warmup to run in background without blocking startup
    asyncio.create_task(_background_warmup())
    print("[*] Vexor API ready (background warmup in progress)")

    yield
    print("[*] Vexor API — shutting down")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Vexor",
    description=(
        "**Offensive LLM security testing API** — OWASP GenAI Top 10\n\n"
        "Test models for prompt injection, data exfiltration, system-prompt leakage, "
        "excessive agency, and more across **15+ providers**.\n\n"
        "### Features\n"
        "- One-shot and batch vulnerability scans\n"
        "- Override modes: **DAN**, **GodMode**, **AIM**, **STAN**, **DUDE**, "
        "**Evil Confidant**, **Developer**, **Opposite**, and provider-specific bypasses\n"
        "- Prompt mutation engine (base64, leet, Unicode homoglyphs, zero-width, ROT13)\n"
        "- Import **PromptFoo** results to auto-tune attack prompts\n"
        "- HTML / JSON report generation\n\n"
        "⚠️ *For authorized security testing only.*"
    ),
    version="2.7.1",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "Scanning",  "description": "Run vulnerability scans against LLMs"},
        {"name": "Models",    "description": "List and test available model providers"},
        {"name": "Prompts",   "description": "Browse, generate, and mutate attack prompts"},
        {"name": "Overrides", "description": "Jailbreak/override persona management"},
        {"name": "Import",    "description": "Import PromptFoo results to improve prompts"},
        {"name": "Reports",   "description": "Generate scan reports"},
        {"name": "Synthetic",   "description": "Generate synthetic attack data at configurable complexity levels"},
        {"name": "Discovery",   "description": "Self-learning engine — failure analysis, method signatures, warm pool, synthesis"},
        {"name": "Health",      "description": "API health checks"},
    ],
)

# ── CORS ─────────────────────────────────────────────────────────────────────
# Restricted to localhost origins only.  The UI is served from the same
# FastAPI process so same-origin requests are never subject to CORS; this
# list controls what *other* origins (e.g. a separate dev server on :3000)
# may call the API.  Do NOT add "*" here — that would allow any page the
# analyst visits to silently exfiltrate scan results.
_ALLOWED_ORIGINS = [
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:3000",   # optional: local dev front-end
    "http://127.0.0.1:3000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=False,                          # no cookies / auth headers
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Request-ID"],
)


# ── Request timing middleware ─────────────────────────────────────────────────
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    t0 = time.time()
    response = await call_next(request)
    response.headers["X-Process-Time-Ms"] = str(round((time.time() - t0) * 1000, 1))
    return response


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(scan.router,         prefix="/api/scan",      tags=["Scanning"])
app.include_router(models.router,       prefix="/api/models",    tags=["Models"])
app.include_router(prompts.router,      prefix="/api/prompts",   tags=["Prompts"])
app.include_router(overrides.router,    prefix="/api/overrides", tags=["Overrides"])
app.include_router(import_routes.router,prefix="/api/import",    tags=["Import"])
app.include_router(reports.router,      prefix="/api/reports",   tags=["Reports"])
app.include_router(synthetic.router,   prefix="/api/synthetic",  tags=["Synthetic"])
app.include_router(discovery.router,   prefix="/api/discovery",  tags=["Discovery"])
app.include_router(chain.router,       prefix="/api/chain",      tags=["Chain"])

# ── Static / Frontend ─────────────────────────────────────────────────────────
_STATIC = Path(__file__).parent / "static"
if _STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


# Root serves the Web UI directly — no sub-route needed
@app.get("/", include_in_schema=False)
async def serve_ui():
    return FileResponse(str(_STATIC / "index.html"))


# ── API info / health ─────────────────────────────────────────────────────────
@app.get("/api", tags=["Health"], summary="API info")
async def api_info():
    """JSON summary of all available API endpoints."""
    return {
        "name":    "Vexor API",
        "version": "2.7.1",
        "ui":      "http://localhost:8080/",
        "docs":    "/docs",
        "endpoints": {
            "scan":      "/api/scan",
            "models":    "/api/models",
            "prompts":   "/api/prompts",
            "overrides": "/api/overrides",
            "import":    "/api/import",
            "reports":   "/api/reports",
            "synthetic": "/api/synthetic",
            "discovery": "/api/discovery",
        },
        "status": "operational",
    }


@app.get("/health", tags=["Health"], summary="Health check")
async def health():
    return {"status": "ok", "timestamp": time.time()}


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import uvicorn
    no_reload = "--no-reload" in sys.argv
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=not no_reload)
