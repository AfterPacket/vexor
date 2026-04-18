#!/usr/bin/env python3
"""
Scan Orchestration Engine — concurrent bulk testing

Design:
  • Each (model, vulnerability) pair runs concurrently via asyncio.gather().
  • Probes within a pair also run concurrently, gated by the RateLimiterRegistry
    which enforces both a per-provider RPM token bucket AND a concurrency cap.
  • No artificial sleep delays — rate limiting is request-driven, not time-based.
  • 429 responses carrying Retry-After headers are parsed and fed back to the
    rate limiter so the next request waits the correct amount.
  • run_scan()             — standard scan using the PromptEngine library
  • run_injection_scan()   — custom prompts from PromptFoo import or user input
"""

import asyncio
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from core.failure_classifier import FailureClassifier
from core.failure_store import FailureStore
from core.method_discovery import MethodDiscoveryEngine
from core.override_engine import OverrideEngine, get_recommended_overrides
from core.probe_adaptor import ProbeAdaptor
from core.prompt_engine import ALL_VULNS, PromptEngine
from core.rate_limiter import get_registry

# Module-level singletons — shared with discovery routes
_failure_store    = FailureStore()
_discovery_engine = MethodDiscoveryEngine(store=_failure_store)


def _generate_warm_pool_variants(job: "ScanJob") -> None:
    """
    After a scan wave, run ProbeAdaptor on warm pool entries that did NOT
    get bypassed during this wave.  Generated variants are stored back into
    the warm pool entry so the next wave re-tests them.
    """
    # Collect all prompt texts that were bypassed in this job
    bypassed_prompts: set = set()
    for vr_list in job.results.values():
        for vr in vr_list:
            for pr in vr.probes:
                if pr.bypassed:
                    bypassed_prompts.add(pr.prompt)

    # For each warm pool entry that was NOT bypassed, generate variants
    adaptor = ProbeAdaptor()
    for key, entries in list(_failure_store._data["warm_pool"].items()):
        for entry in entries:
            prompt = entry.get("prompt", "")
            if not prompt or prompt in bypassed_prompts:
                continue
            try:
                from core.failure_classifier import FailureClass, DefenseType
                fc = FailureClass(entry.get("best_failure_class", "hard_block"))
                dt = DefenseType(entry.get("defense_type", entry.get("best_failure_class", "unknown")))
            except ValueError:
                fc = FailureClass.HARD_BLOCK
                dt = DefenseType.UNKNOWN
            existing = set(entry.get("adapted_variants", []))
            mutations_tried = entry.get("mutations_tried", [])
            variants = adaptor.adapt(
                prompt          = prompt,
                failure_class   = fc,
                defense_type    = dt,
                compliance_snippet = entry.get("compliance_snippet", ""),
                mutations_already_tried = mutations_tried,
                max_variants    = 3,
            )
            for variant_text, _strategy in variants:
                if variant_text and variant_text not in existing:
                    _failure_store.add_adapted_variant(entry["probe_id"], variant_text)
                    existing.add(variant_text)


def _clean_api_error(raw: str) -> str:
    """Extract a human-readable message from a provider SDK error string."""
    import re
    # Try to pull 'message': '...' out of the JSON-like error body
    m = re.search(r"'message':\s*'([^']+)'", raw)
    if m:
        return m.group(1)
    m = re.search(r'"message":\s*"([^"]+)"', raw)
    if m:
        return m.group(1)
    # Fall back to just the status code + first 120 chars
    return raw[:120]


def _provider_for_model(model: str) -> str:
    """Map model name to provider key without importing ModelManager."""
    low = model.lower()
    # Ollama-first: name:tag format always means local Ollama regardless of prefix
    if low.startswith("ollama") or ":" in low:         return "ollama"
    # Cloud providers
    if low.startswith("gpt"):                           return "openai"
    if low.startswith("claude"):                        return "anthropic"
    if low.startswith("gemini"):                        return "google"
    if low.startswith("llama-3.1-sonar"):               return "perplexity"
    if low.startswith(("llama-3", "mixtral-8x7b-32768")):
                                                        return "groq"
    if low.startswith("mistral"):                       return "mistral"
    if low.startswith("command"):                       return "cohere"
    if low.startswith("deepseek"):                      return "deepseek"
    if low.startswith(("anthropic.", "amazon.", "us.anthropic.")):
                                                        return "bedrock"
    if low.startswith(("meta-llama/llama-3", "mistralai/")):
                                                        return "together"
    if "/" in low:                                      return "huggingface"
    return "ollama"   # fallback: try local Ollama for short bare names


_PROBE_TIMEOUT: dict = {
    "ollama":      300.0,  # local models can be slow on CPU
    "bedrock":     120.0,
    "huggingface": 120.0,
    "openai":       30.0,
    "anthropic":    30.0,
    "groq":         20.0,  # Groq is very fast — fail quickly if stalled
    "xai":          30.0,
    "google":       30.0,
    "mistral":      30.0,
    "together":     30.0,
    "deepseek":     30.0,
    "cohere":       30.0,
    "perplexity":   30.0,
}


# ── Status / dataclasses ──────────────────────────────────────────────────────

class ScanStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


@dataclass
class ProbeResult:
    vulnerability:  str
    prompt:         str
    response:       str
    bypassed:       bool
    override_mode:  str
    mutation:       Optional[str]
    latency_ms:     float
    error:          Optional[str] = None
    wrapped_prompt: Optional[str] = None  # full prompt as sent to model (after override wrapping)


@dataclass
class ModelVulnResult:
    model:         str
    vulnerability: str
    probes:        List[ProbeResult] = field(default_factory=list)
    bypass_count:  int = 0
    total_probes:  int = 0

    @property
    def bypass_rate(self) -> float:
        return self.bypass_count / self.total_probes if self.total_probes else 0.0

    @property
    def vulnerable(self) -> bool:
        return self.bypass_count > 0


@dataclass
class ScanJob:
    scan_id:         str
    status:          ScanStatus
    models:          List[str]
    vulnerabilities: List[str]
    override_mode:   str
    prompt_count:    int
    use_mutations:   bool
    results:              Dict[str, List[ModelVulnResult]] = field(default_factory=dict)
    errors:               List[str] = field(default_factory=list)
    started_at:           Optional[float] = None
    finished_at:          Optional[float] = None
    progress:             int = 0   # 0-100
    use_warm_pool:        bool = True
    cancelled:            bool = False
    probes_completed:     int = 0   # incremented per probe for live progress
    probes_total_hint:    int = 0   # estimated total set before scan starts
    active_tasks:         set = field(default_factory=set)  # in-flight asyncio tasks
    # Per-vulnerability extra prompts from chain templates — keyed by vuln id
    extra_prompts:        Dict[str, List[str]] = field(default_factory=dict)

    @property
    def elapsed_seconds(self) -> Optional[float]:
        if self.started_at is None:
            return None
        return round((self.finished_at or time.time()) - self.started_at, 2)

    def to_dict(self) -> Dict:
        out: Dict[str, Any] = {}
        for model, vr_list in self.results.items():
            out[model] = [
                {
                    "vulnerability": vr.vulnerability,
                    "bypass_rate":   round(vr.bypass_rate, 3),
                    "bypass_count":  vr.bypass_count,
                    "total_probes":  vr.total_probes,
                    "vulnerable":    vr.vulnerable,
                    "probes": [
                        {
                            "prompt":         p.prompt,
                            "wrapped_prompt": p.wrapped_prompt,
                            "response":       p.response[:1000],
                            "bypassed":       p.bypassed,
                            "override_mode":  p.override_mode,
                            "mutation":       p.mutation,
                            "latency_ms":     p.latency_ms,
                            "error":          p.error,
                        }
                        for p in vr.probes
                    ],
                }
                for vr in vr_list
            ]
        finished_probes = sum(
            len(vr.probes)
            for vr_list in self.results.values()
            for vr in vr_list
        )
        # While running, probes_completed tracks all in-flight completions; after
        # completion, use the authoritative count from results.
        total_probes = finished_probes if self.status != ScanStatus.RUNNING else max(finished_probes, self.probes_completed)
        total_bypasses = sum(
            vr.bypass_count
            for vr_list in self.results.values()
            for vr in vr_list
        )
        return {
            "scan_id":          self.scan_id,
            "status":           self.status.value,
            "models":           self.models,
            "vulnerabilities":  self.vulnerabilities,
            "override_mode":    self.override_mode,
            "progress":         self.progress,
            "elapsed_seconds":  self.elapsed_seconds,
            "errors":           self.errors,
            "total_probes":     total_probes,
            "bypasses":         total_bypasses,
            "results":          out,
        }


# ── Scanner ───────────────────────────────────────────────────────────────────

class Scanner:
    """
    Async scanner — runs all (model × vulnerability) pairs concurrently.
    Within each pair all probes are sent concurrently, throttled by a
    per-provider semaphore.
    """

    def __init__(self):
        self.prompt_engine   = PromptEngine()
        self.override_engine = OverrideEngine()
        self._mm             = None   # Lazy-loaded

    # ── ModelManager lazy load ────────────────────────────────────────────────

    def _get_mm(self):
        if self._mm is None:
            from models.integrations import ModelManager
            self._mm = ModelManager()
        return self._mm

    # ── Public API ────────────────────────────────────────────────────────────

    def create_scan_job(
        self,
        models:          List[str],
        vulnerabilities: Optional[List[str]] = None,
        override_mode:   str = "none",
        prompt_count:    int = 10,
        use_mutations:   bool = False,
        extra_prompts:   Optional[Dict[str, List[str]]] = None,
    ) -> ScanJob:
        return ScanJob(
            scan_id         = str(uuid.uuid4()),
            status          = ScanStatus.PENDING,
            models          = models,
            vulnerabilities = vulnerabilities or ALL_VULNS,
            override_mode   = override_mode,
            prompt_count    = prompt_count,
            use_mutations   = use_mutations,
            extra_prompts   = extra_prompts or {},
        )

    async def run_scan(
        self,
        job: ScanJob,
        on_progress: Optional[Callable] = None,
    ) -> ScanJob:
        """
        Run a scan job.  All model/vuln pairs execute concurrently.
        Progress callback receives the job object after each pair completes.
        """
        job.status     = ScanStatus.RUNNING
        job.started_at = time.time()

        try:
            mm = self._get_mm()
        except Exception as e:
            job.status      = ScanStatus.FAILED
            job.finished_at = time.time()
            job.errors.append(f"ModelManager init: {e}")
            return job

        # Build all (model, vuln) tasks
        pairs = [(m, v) for m in job.models for v in job.vulnerabilities]
        total = len(pairs)
        done  = 0
        lock  = asyncio.Lock()
        job_abort = asyncio.Event()

        # Estimate total probes for live progress.
        # Base = prompt_count + chain extras per vuln; mutations add ~12 more per vuln (3 base × 4 variants).
        def _estimate_per_pair(vuln: str) -> int:
            base = job.prompt_count + len(job.extra_prompts.get(vuln, []))
            if job.use_mutations:
                base += min(3, base) * 4
            return base
        job.probes_total_hint = sum(_estimate_per_pair(v) for _ in job.models for v in job.vulnerabilities)

        # Lazy import to avoid circular dependency at module load time
        def _checkpoint():
            try:
                from api.routes.scan import save_scan_to_disk
                save_scan_to_disk(job)
            except Exception:
                pass

        _checkpoint_every = 10   # write partial results every N probes

        def _on_probe_done():
            job.probes_completed += 1
            if job.probes_total_hint > 0:
                job.progress = min(99, int(job.probes_completed / job.probes_total_hint * 100))
            if job.probes_completed % _checkpoint_every == 0:
                _checkpoint()

        async def _run_pair(model: str, vuln: str):
            nonlocal done
            # Pre-register so probes stream into job.results in real time
            live_result = ModelVulnResult(model=model, vulnerability=vuln)
            async with lock:
                job.results.setdefault(model, []).append(live_result)
            try:
                if job.cancelled or job_abort.is_set():
                    return
                await self._scan_pair(mm, model, vuln, job, job_abort, _on_probe_done, live_result)
            except Exception as e:
                async with lock:
                    job.errors.append(f"{model}/{vuln}: {e}")
            finally:
                async with lock:
                    done += 1
                if on_progress:
                    try:
                        on_progress(job)
                    except Exception:
                        pass

        await asyncio.gather(*[_run_pair(m, v) for m, v in pairs])

        job.finished_at = time.time()
        if job.cancelled:
            job.status   = ScanStatus.CANCELLED
        else:
            job.status   = ScanStatus.COMPLETED
            job.progress = 100

        # Post-scan: discovery analysis + warm pool maintenance
        try:
            _discovery_engine.analyze_completed_scan(job)
        except Exception:
            pass
        try:
            _failure_store.tick_warm_pool()
            _failure_store.save()
        except Exception:
            pass
        # Generate ProbeAdaptor variants for top warm pool misses
        try:
            _generate_warm_pool_variants(job)
        except Exception:
            pass

        return job

    # ── Per-(model, vuln) concurrent scan ────────────────────────────────────

    async def _scan_pair(
        self,
        mm:             Any,
        model:          str,
        vuln:           str,
        job:            ScanJob,
        job_abort:      Optional[asyncio.Event] = None,
        on_probe_done:  Optional[Callable] = None,
        result:         Optional["ModelVulnResult"] = None,
    ) -> ModelVulnResult:
        if result is None:
            result = ModelVulnResult(model=model, vulnerability=vuln)

        # ── Warm pool injection ───────────────────────────────────────────────
        # Prepend any warm pool entries (and their adapted variants) for this
        # (model, vuln) pair so re-promising failed probes are tested first.
        warm_prompts: List[str] = []
        if job.use_warm_pool:
            try:
                warm_entries = _failure_store.get_warm_pool(
                    model=model, vuln=vuln, min_score=1
                )
                for we in warm_entries[:10]:   # cap at 10 warm probes per pair
                    warm_prompts.append(we["prompt"])
                    for v in we.get("adapted_variants", [])[:3]:
                        if v and v not in warm_prompts:
                            warm_prompts.append(v)
            except Exception:
                pass

            # Transfer matrix: pull high-transfer prompts from other models that
            # successfully bypassed the same vuln — they're likely to work here too.
            try:
                matrix = _failure_store.transfer_matrix
                for key, val in matrix.items():
                    avg = val["sum"] / val["count"] if val["count"] > 0 else 0
                    if avg < 0.5:
                        continue
                    # key format: "model_a→model_b:vuln"
                    if f"\u2192{model}:{vuln}" not in key:
                        continue
                    model_a = key.split("\u2192")[0]
                    for we in _failure_store.get_warm_pool(model=model_a, vuln=vuln, min_score=1)[:3]:
                        p = we["prompt"]
                        if p and p not in warm_prompts:
                            warm_prompts.append(p)
            except Exception:
                pass

        # Build standard prompt list
        prompts: List[str] = list(
            self.prompt_engine.get_prompts(
                vuln, model=model, count=job.prompt_count, shuffle=True
            )
        )

        # Inject chain-derived step prompts for this vulnerability
        chain_extras = job.extra_prompts.get(vuln, [])
        prompts.extend(chain_extras)

        # Apply mutations to first 3 base prompts (not just the first)
        if job.use_mutations and prompts:
            mutation_sources = prompts[:3]
            for base_p in mutation_sources:
                variants = self.prompt_engine.generate_variants(base_p)
                prompts += variants[:4]

        # Warm pool prompts come first (deduplicated)
        seen_p: set = set()
        final_prompts: List[str] = []
        for p in warm_prompts + prompts:
            if p and p not in seen_p:
                seen_p.add(p)
                final_prompts.append(p)
        prompts = final_prompts

        result.total_probes = len(prompts)
        provider = _provider_for_model(model)
        rl = get_registry()
        pair_abort = asyncio.Event()   # pair-level abort (set on first fatal error)

        # Build per-prompt override mode list.
        # "variety" cycles through model-recommended + general effective modes so each
        # probe gets a different override — maximises coverage without full AutoPwn cost.
        _VARIETY_BASE = [
            "none", "sophistication", "godmode", "developer",
            "cognitive_research", "calibration_v2", "capability_test", "data_labeller_v2",
        ]
        if job.override_mode == "variety":
            _rec = get_recommended_overrides(model)
            # Use learned delta scores to rank modes — modes that historically improve
            # outcomes for this model come first; fall back to static list for unknowns.
            _delta = _failure_store.get_delta_scores(model)
            if _delta:
                _delta_ranked = sorted(_delta.keys(), key=lambda m: _delta[m], reverse=True)
                _all_base = _delta_ranked + [m for m in list(_rec) + _VARIETY_BASE if m not in set(_delta_ranked)]
            else:
                _all_base = list(_rec) + _VARIETY_BASE
            _seen_v: set = set()
            _variety_modes = [m for m in _all_base if not (_seen_v.add(m) or m in _seen_v - {m})]
            # de-dup preserving order
            _seen_v2: set = set()
            _variety_modes = [m for m in _all_base if not (m in _seen_v2 or _seen_v2.add(m))]
        else:
            _variety_modes = []  # unused

        def _mode_for_prompt(idx: int) -> str:
            if job.override_mode == "variety":
                return _variety_modes[idx % len(_variety_modes)]
            return job.override_mode

        def _should_abort() -> bool:
            return job.cancelled or pair_abort.is_set() or (job_abort is not None and job_abort.is_set())

        async def _probe(
            raw_prompt:      str,
            override_mode:   str,
            system_override: Optional[str] = None,
        ) -> ProbeResult:
            if _should_abort():
                raise asyncio.CancelledError("scan aborted")
            await rl.acquire(provider)
            try:
                if _should_abort():
                    raise asyncio.CancelledError("scan aborted")
                return await self._send_probe(
                    mm, model, raw_prompt, vuln, override_mode,
                    system_override=system_override,
                )
            except RuntimeError as e:
                if "Fatal provider error" in str(e):
                    pair_abort.set()
                    if job_abort is not None:
                        job_abort.set()
                    job.cancelled = True
                raise
            finally:
                rl.release(provider)

        # Use as_completed so progress updates as each probe finishes,
        # not all at once after the last one in the batch lands.
        tasks = [
            asyncio.ensure_future(_probe(p, _mode_for_prompt(i)))
            for i, p in enumerate(prompts)
        ]

        # Synthesized template probes — apply learned attack templates to the
        # first 2 base prompts. Cap at 3 templates per pair to avoid runaway growth.
        try:
            synth_templates = _failure_store.get_synthesized_templates(
                model=model, vuln=vuln, min_confidence=0.45, untested_only=False
            )[:3]
            for tmpl in synth_templates:
                prefix   = tmpl.get("prefix", "")
                sys_p    = tmpl.get("system_prompt") or None
                tmpl_id  = tmpl.get("template_id")
                for base_p in prompts[:2]:
                    if not base_p:
                        continue
                    if "{goal}" in prefix:
                        synth_p = prefix.replace("{goal}", base_p)
                    else:
                        synth_p = (prefix + " " + base_p).strip() if prefix else base_p
                    t = asyncio.ensure_future(_probe(synth_p, "none", system_override=sys_p))
                    tasks.append(t)
                    result.total_probes += 1
                if tmpl_id:
                    _failure_store.mark_template_tested(tmpl_id)
        except Exception:
            pass
        job.active_tasks.update(tasks)
        fatal_err: Optional[str] = None
        for fut in asyncio.as_completed(tasks):
            try:
                pr: Any = await fut
            except asyncio.CancelledError:
                if on_probe_done:
                    on_probe_done()
                continue   # probe was cancelled (abort/stop) — skip silently
            except Exception as e:
                pr = e
            if on_probe_done:
                on_probe_done()
            if isinstance(pr, Exception):
                err_str = str(pr)
                result.probes.append(ProbeResult(
                    vulnerability = vuln,
                    prompt        = "",
                    response      = "",
                    bypassed      = False,
                    override_mode = _mode_for_prompt(0),
                    mutation      = None,
                    latency_ms    = 0,
                    error         = err_str,
                ))
                if "Fatal provider error" in err_str and not fatal_err:
                    fatal_err = err_str
                    for t in tasks:
                        t.cancel()
            else:
                result.probes.append(pr)
                if pr.bypassed:
                    result.bypass_count += 1

        if fatal_err:
            raise RuntimeError(fatal_err)

        return result

    # ── Single probe ─────────────────────────────────────────────────────────

    @staticmethod
    def _parse_retry_after(error_msg: str) -> Optional[float]:
        """Extract seconds from 'retry_after:<N>' or 'Retry-After: <N>' in error text."""
        m = re.search(r"retry[_-]after[:\s]+([0-9.]+)", error_msg, re.I)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass
        return None

    async def _send_probe(
        self,
        mm:              Any,
        model:           str,
        raw_prompt:      str,
        vulnerability:   str,
        override_mode:   str,
        system_override: Optional[str] = None,
    ) -> ProbeResult:
        final_prompt = self.override_engine.wrap_prompt(raw_prompt, override_mode)
        system_inj   = system_override if system_override is not None else (
            self.override_engine.get_system_injection(override_mode) or None
        )
        provider     = _provider_for_model(model)
        rl           = get_registry()

        start = time.time()
        error: Optional[str] = None
        response = ""
        timeout_s = _PROBE_TIMEOUT.get(provider, 60.0)
        try:
            response = await asyncio.wait_for(
                mm.send_prompt_async(final_prompt, model, system_inj),
                timeout=timeout_s,
            )
            # Surface provider error strings returned by integrations
            if response and response.startswith("Error:"):
                error    = response
                response = ""
            elif response:
                rl_check = response.lower()
                if any(k in rl_check for k in (
                    "500 internal server error", "502 bad gateway",
                    "503 service unavailable", "504 gateway timeout",
                )):
                    error    = f"Error: provider HTTP error — {response[:120]}"
                    response = ""
        except asyncio.TimeoutError:
            error    = f"Error: request to {model} timed out after {int(timeout_s)}s"
            response = ""
        except Exception as e:
            error    = _clean_api_error(str(e))
            response = ""
            # If rate-limited, re-acquire with the retry-after hint so next
            # request to this provider waits the correct amount
            if "429" in error or "rate limit" in error.lower():
                retry_after = self._parse_retry_after(error)
                if retry_after:
                    await rl.acquire(provider, retry_after=retry_after)
                    rl.release(provider)

        # Detect fatal provider errors (billing, auth, quota) and raise so the
        # pair-level handler can abort rather than fire 25 more doomed probes.
        if error:
            el = error.lower()
            if any(k in el for k in (
                "credit", "billing", "insufficient_quota", "quota exceeded",
                "402", "401", "invalid api key", "authentication",
                "your account", "out of credits", "payment",
            )):
                raise RuntimeError(f"Fatal provider error — {error}")

        latency_ms = (time.time() - start) * 1000
        bypassed   = self.prompt_engine.evaluate_response(
            vulnerability, raw_prompt, response
        )

        # Record failures to the warm pool / discovery engine
        if not bypassed and raw_prompt and response and not error:
            try:
                classification = FailureClassifier.classify(response, vulnerability)
                _failure_store.record(
                    prompt        = raw_prompt,
                    response      = response,
                    model         = model,
                    vulnerability = vulnerability,
                    override_mode = override_mode,
                    classification= classification,
                    source        = "scan",
                )
            except Exception:
                pass  # never let discovery errors block probe results

        return ProbeResult(
            vulnerability  = vulnerability,
            prompt         = raw_prompt,
            response       = response,
            bypassed       = bypassed,
            override_mode  = override_mode,
            mutation       = None,
            latency_ms     = round(latency_ms, 1),
            error          = error,
            wrapped_prompt = final_prompt if override_mode != "none" else None,
        )

    # ── Injection scan (custom prompts from PromptFoo / user) ────────────────

    def create_injection_job(
        self,
        models:         List[str],
        custom_prompts: List[Dict],   # [{prompt, vulnerability, source, ...}]
        override_mode:  str = "none",
        label:          str = "injection",
    ) -> ScanJob:
        """
        Create a ScanJob pre-populated with caller-supplied prompts.
        custom_prompts: list of dicts with at minimum {"prompt": str, "vulnerability": str}
        """
        vulns = list({p.get("vulnerability", "llm01") for p in custom_prompts})
        job = ScanJob(
            scan_id         = str(uuid.uuid4()),
            status          = ScanStatus.PENDING,
            models          = models,
            vulnerabilities = vulns,
            override_mode   = override_mode,
            prompt_count    = len(custom_prompts),
            use_mutations   = False,
        )
        # Attach custom prompts as metadata so run_injection_scan() can find them
        job._custom_prompts = custom_prompts  # type: ignore[attr-defined]
        return job

    async def run_injection_scan(
        self,
        job: ScanJob,
        on_progress: Optional[Callable] = None,
    ) -> ScanJob:
        """
        Like run_scan() but uses job._custom_prompts instead of PromptEngine.
        Groups prompts by vulnerability so each (model, vuln) pair uses only
        the prompts that were imported for that vulnerability.
        """
        job.status     = ScanStatus.RUNNING
        job.started_at = time.time()
        custom: List[Dict] = getattr(job, "_custom_prompts", [])

        try:
            mm = self._get_mm()
        except Exception as e:
            job.status      = ScanStatus.FAILED
            job.finished_at = time.time()
            job.errors.append(f"ModelManager init: {e}")
            return job

        # Group by vulnerability
        by_vuln: Dict[str, List[str]] = {}
        for entry in custom:
            v = entry.get("vulnerability", "llm01")
            by_vuln.setdefault(v, []).append(entry.get("prompt", ""))

        pairs = [(m, v) for m in job.models for v in by_vuln]
        total = len(pairs)
        done  = 0
        lock  = asyncio.Lock()

        async def _run_pair(model: str, vuln: str):
            nonlocal done
            prompts = by_vuln.get(vuln, [])
            result  = ModelVulnResult(model=model, vulnerability=vuln)
            result.total_probes = len(prompts)
            provider = _provider_for_model(model)
            rl = get_registry()

            async def _probe(raw_prompt: str) -> ProbeResult:
                if job.cancelled:
                    raise asyncio.CancelledError("scan aborted")
                await rl.acquire(provider)
                try:
                    if job.cancelled:
                        raise asyncio.CancelledError("scan aborted")
                    return await self._send_probe(
                        mm, model, raw_prompt, vuln, job.override_mode
                    )
                finally:
                    rl.release(provider)

            tasks = [asyncio.ensure_future(_probe(p)) for p in prompts]
            job.active_tasks.update(tasks)
            probe_results = await asyncio.gather(*tasks, return_exceptions=True)
            job.active_tasks.difference_update(tasks)
            for pr in probe_results:
                if isinstance(pr, Exception):
                    result.probes.append(ProbeResult(
                        vulnerability=vuln, prompt="", response="",
                        bypassed=False, override_mode=job.override_mode,
                        mutation=None, latency_ms=0, error=str(pr),
                    ))
                else:
                    result.probes.append(pr)
                    if pr.bypassed:
                        result.bypass_count += 1

            async with lock:
                job.results.setdefault(model, []).append(result)
                done += 1
                job.progress = int(done / total * 100)
            if on_progress:
                try:
                    on_progress(job)
                except Exception:
                    pass

        await asyncio.gather(*[_run_pair(m, v) for m, v in pairs])
        job.finished_at = time.time()
        if job.cancelled:
            job.status = ScanStatus.CANCELLED
        else:
            job.status   = ScanStatus.COMPLETED
            job.progress = 100
        try:
            _discovery_engine.analyze_completed_scan(job)
        except Exception:
            pass
        try:
            _failure_store.tick_warm_pool()
            _failure_store.save()
        except Exception:
            pass
        try:
            _generate_warm_pool_variants(job)
        except Exception:
            pass
        return job

    # ── AutoPwn injection — imported prompts + model-aware mode ordering ─────

    def create_autopwn_injection_job(
        self,
        models:         List[str],
        custom_prompts: List[Dict],   # [{prompt, vulnerability, winning_mode, ...}]
        label:          str = "autopwn_injection",
    ) -> ScanJob:
        """
        Like create_injection_job but tagged for AutoPwn mode selection.
        Each prompt carries an optional winning_mode from the import DB
        which will be tried first before the full model suite.
        """
        vulns = list({p.get("vulnerability", "llm01") for p in custom_prompts})
        job = ScanJob(
            scan_id         = str(uuid.uuid4()),
            status          = ScanStatus.PENDING,
            models          = models,
            vulnerabilities = vulns,
            override_mode   = "autopwn_injection",
            prompt_count    = len(custom_prompts),
            use_mutations   = False,
        )
        job._custom_prompts = custom_prompts  # type: ignore[attr-defined]
        return job

    async def run_autopwn_injection_scan(
        self,
        job: ScanJob,
        on_progress: Optional[Callable] = None,
        extra_winning_modes: Optional[Dict[str, List[str]]] = None,
    ) -> ScanJob:
        """
        AutoPwn injection scan:
          - Uses imported/generated prompts (job._custom_prompts)
          - Per probe: if the prompt has a stored winning_mode, try that FIRST,
            then fall through to the model-specific AutoPwn suite
          - Per model: also prepend any winning modes recorded in the import DB
            (passed in via extra_winning_modes: {model_key: [mode, ...]})
          - Records which mode achieved bypass
        """
        job.status     = ScanStatus.RUNNING
        job.started_at = time.time()
        custom: List[Dict] = getattr(job, "_custom_prompts", [])
        extra_winning_modes = extra_winning_modes or {}

        try:
            mm = self._get_mm()
        except Exception as e:
            job.status      = ScanStatus.FAILED
            job.finished_at = time.time()
            job.errors.append(f"ModelManager init: {e}")
            return job

        # Group prompts by vuln, preserving winning_mode per prompt
        by_vuln: Dict[str, List[Dict]] = {}
        for entry in custom:
            v = entry.get("vulnerability", "llm01")
            by_vuln.setdefault(v, []).append(entry)

        # Pre-build per-model suites (winning modes from imports go FIRST)
        model_suites: Dict[str, List[str]] = {}
        for m in job.models:
            from core.override_engine import get_recommended_overrides
            base_suite = self._autopwn_suite(m)
            # Prepend any extra winning modes from the import DB
            imported_wins = extra_winning_modes.get(m, [])
            # Deduplicate: imported wins first, then base suite
            seen: set = set()
            merged: List[str] = []
            for mode in imported_wins + base_suite:
                if mode not in seen and mode != "none":
                    seen.add(mode)
                    merged.append(mode)
            model_suites[m] = merged

        pairs = [(m, v) for m in job.models for v in by_vuln]
        total = len(pairs)
        done  = 0
        lock  = asyncio.Lock()

        async def _autopwn_probe(model: str, entry: Dict, vuln: str) -> ProbeResult:
            raw_prompt   = entry.get("prompt", "")
            prompt_mode  = entry.get("winning_mode", "none")
            provider     = _provider_for_model(model)
            rl           = get_registry()

            # Build ordered mode list: stored winning mode → model suite
            suite = list(model_suites[model])
            if prompt_mode and prompt_mode != "none" and prompt_mode not in suite:
                suite.insert(0, prompt_mode)
            elif prompt_mode and prompt_mode != "none":
                # Move it to front
                suite = [prompt_mode] + [m for m in suite if m != prompt_mode]

            for mode in suite:
                if job.cancelled:
                    raise asyncio.CancelledError("scan aborted")
                await rl.acquire(provider)
                try:
                    if job.cancelled:
                        raise asyncio.CancelledError("scan aborted")
                    result = await self._send_probe(mm, model, raw_prompt, vuln, mode)
                finally:
                    rl.release(provider)
                if result.bypassed:
                    return result

            # Fallback — bare probe
            if job.cancelled:
                raise asyncio.CancelledError("scan aborted")
            await rl.acquire(provider)
            try:
                baseline = await self._send_probe(mm, model, raw_prompt, vuln, "none")
            finally:
                rl.release(provider)
            return baseline

        async def _run_pair(model: str, vuln: str):
            nonlocal done
            entries  = by_vuln.get(vuln, [])
            result   = ModelVulnResult(model=model, vulnerability=vuln)
            result.total_probes = len(entries)

            tasks = [asyncio.ensure_future(_autopwn_probe(model, e, vuln)) for e in entries]
            job.active_tasks.update(tasks)
            probe_results = await asyncio.gather(*tasks, return_exceptions=True)
            job.active_tasks.difference_update(tasks)
            for pr in probe_results:
                if isinstance(pr, Exception):
                    result.probes.append(ProbeResult(
                        vulnerability=vuln, prompt="", response="",
                        bypassed=False, override_mode="error",
                        mutation=None, latency_ms=0, error=str(pr),
                    ))
                else:
                    result.probes.append(pr)
                    if pr.bypassed:
                        result.bypass_count += 1

            async with lock:
                job.results.setdefault(model, []).append(result)
                done += 1
                job.progress = int(done / total * 100)
            if on_progress:
                try:
                    on_progress(job)
                except Exception:
                    pass

        await asyncio.gather(*[_run_pair(m, v) for m, v in pairs])
        job.finished_at = time.time()
        if job.cancelled:
            job.status = ScanStatus.CANCELLED
        else:
            job.status   = ScanStatus.COMPLETED
            job.progress = 100
        try:
            _discovery_engine.analyze_completed_scan(job)
        except Exception:
            pass
        try:
            _failure_store.tick_warm_pool()
            _failure_store.save()
        except Exception:
            pass
        try:
            _generate_warm_pool_variants(job)
        except Exception:
            pass
        return job

    # ── Jailbreak sweep — cycles every override mode automatically ────────────

    # All override modes to sweep (ordered by aggression ascending)
    # Fallback full suite (used when a model doesn't match any known provider)
    JAILBREAK_MODES: List[str] = [
        "dan", "godmode", "aim", "stan", "dude", "evil_confidant",
        "developer", "opposite", "jailbreak", "claude_bypass",
        "gemini_bypass", "gpt_bypass", "chatgpt_dan", "aim_v2",
        "sudo", "translator",
    ]

    @staticmethod
    def _autopwn_suite(model: str) -> List[str]:
        """
        Return an ordered list of override modes for this specific model.
        Model-specific modes come first (highest probability of bypass),
        followed by any remaining universal modes.
        """
        recommended = get_recommended_overrides(model)  # already deduped + ordered
        # Append any modes not already in the recommended list so we always
        # have a complete fallback sweep behind the targeted ones.
        all_modes = [
            "dan", "godmode", "aim", "aim_v2", "stan", "dude", "evil_confidant",
            "developer", "opposite", "jailbreak", "sudo", "translator",
            "claude_bypass", "gemini_bypass", "gpt_bypass", "chatgpt_dan",
        ]
        seen = set(recommended)
        for m in all_modes:
            if m not in seen:
                recommended.append(m)
                seen.add(m)
        return recommended

    def create_jailbreak_job(
        self,
        models:          List[str],
        vulnerabilities: Optional[List[str]] = None,
        prompt_count:    int = 3,
        use_mutations:   bool = False,
    ) -> ScanJob:
        """
        Create a ScanJob configured for AutoPwn sweep mode.
        Each model gets its own prioritised override suite at scan time.
        """
        job = ScanJob(
            scan_id         = str(uuid.uuid4()),
            status          = ScanStatus.PENDING,
            models          = models,
            vulnerabilities = vulnerabilities or ALL_VULNS,
            override_mode   = "autopwn",
            prompt_count    = prompt_count,
            use_mutations   = use_mutations,
        )
        return job

    async def run_jailbreak_scan(
        self,
        job: ScanJob,
        on_progress: Optional[Callable] = None,
    ) -> ScanJob:
        """
        AutoPwn suite: for each model, build a model-specific ordered override
        suite (model-targeted modes first, then universal fallbacks).  Try each
        mode per prompt in order, stop as soon as a bypass is found.
        Records the winning mode in probe.override_mode.
        Falls back to 'none' baseline if every mode fails.
        """
        job.status     = ScanStatus.RUNNING
        job.started_at = time.time()

        try:
            mm = self._get_mm()
        except Exception as e:
            job.status      = ScanStatus.FAILED
            job.finished_at = time.time()
            job.errors.append(f"ModelManager init: {e}")
            return job

        # Pre-build per-model suites so we don't recompute inside the hot loop
        model_suites: Dict[str, List[str]] = {
            m: self._autopwn_suite(m) for m in job.models
        }

        pairs = [(m, v) for m in job.models for v in job.vulnerabilities]
        total = len(pairs)
        done  = 0
        lock  = asyncio.Lock()
        job_abort = asyncio.Event()

        job.probes_total_hint = job.prompt_count * len(pairs)

        def _on_probe_done():
            job.probes_completed += 1
            if job.probes_total_hint > 0:
                job.progress = min(99, int(job.probes_completed / job.probes_total_hint * 100))

        async def _sweep_probe(model: str, raw_prompt: str, vuln: str) -> ProbeResult:
            """
            Try override modes in model-prioritised order.
            Return on first bypass; return baseline probe if all fail.
            """
            provider = _provider_for_model(model)
            rl = get_registry()
            suite = model_suites[model]

            last_result: Optional[ProbeResult] = None
            for mode in suite:
                if job.cancelled or job_abort.is_set():
                    raise asyncio.CancelledError("scan aborted")
                await rl.acquire(provider)
                try:
                    if job.cancelled or job_abort.is_set():
                        raise asyncio.CancelledError("scan aborted")
                    result = await self._send_probe(mm, model, raw_prompt, vuln, mode)
                except RuntimeError as e:
                    if "Fatal provider error" in str(e):
                        job_abort.set()
                        job.cancelled = True
                    raise
                finally:
                    rl.release(provider)

                last_result = result
                if result.bypassed:
                    return result  # early exit — winning mode found

            # All modes failed — run bare baseline so we have a response on record
            if job.cancelled or job_abort.is_set():
                raise asyncio.CancelledError("scan aborted")
            await rl.acquire(provider)
            try:
                baseline = await self._send_probe(mm, model, raw_prompt, vuln, "none")
            except RuntimeError as e:
                if "Fatal provider error" in str(e):
                    job_abort.set()
                    job.cancelled = True
                raise
            finally:
                rl.release(provider)
            return baseline

        async def _run_pair(model: str, vuln: str):
            nonlocal done
            # Pre-register so probes stream into job.results in real time
            live_result = ModelVulnResult(model=model, vulnerability=vuln)
            async with lock:
                job.results.setdefault(model, []).append(live_result)
            try:
                if job.cancelled or job_abort.is_set():
                    return
                prompts: List[str] = list(
                    self.prompt_engine.get_prompts(
                        vuln, model=model, count=job.prompt_count, shuffle=True
                    )
                )
                if job.use_mutations and prompts:
                    prompts += self.prompt_engine.generate_variants(prompts[0])[: job.prompt_count]

                # Warm pool injection — prepend re-promising failed probes
                if job.use_warm_pool:
                    try:
                        warm_entries = _failure_store.get_warm_pool(
                            model=model, vuln=vuln, min_score=1
                        )
                        warm_prompts: List[str] = []
                        for we in warm_entries[:10]:
                            warm_prompts.append(we["prompt"])
                            for v in we.get("adapted_variants", [])[:3]:
                                if v and v not in warm_prompts:
                                    warm_prompts.append(v)
                        seen_p: set = set(prompts)
                        for wp in warm_prompts:
                            if wp and wp not in seen_p:
                                prompts.insert(0, wp)
                                seen_p.add(wp)
                    except Exception:
                        pass

                live_result.total_probes = len(prompts)

                tasks = [asyncio.ensure_future(_sweep_probe(model, p, vuln)) for p in prompts]
                job.active_tasks.update(tasks)
                for fut in asyncio.as_completed(tasks):
                    try:
                        pr = await fut
                    except Exception as e:
                        pr = e
                    _on_probe_done()
                    if isinstance(pr, Exception):
                        live_result.probes.append(ProbeResult(
                            vulnerability=vuln, prompt="", response="",
                            bypassed=False, override_mode="error",
                            mutation=None, latency_ms=0, error=str(pr),
                        ))
                    else:
                        live_result.probes.append(pr)
                        if pr.bypassed:
                            live_result.bypass_count += 1

            except Exception as e:
                async with lock:
                    job.errors.append(f"{model}/{vuln}: {e}")
            finally:
                async with lock:
                    done += 1
                if on_progress:
                    try:
                        on_progress(job)
                    except Exception:
                        pass

        await asyncio.gather(*[_run_pair(m, v) for m, v in pairs])
        job.finished_at = time.time()
        if job.cancelled:
            job.status = ScanStatus.CANCELLED
        else:
            job.status   = ScanStatus.COMPLETED
            job.progress = 100
        try:
            _discovery_engine.analyze_completed_scan(job)
        except Exception:
            pass
        try:
            _failure_store.tick_warm_pool()
            _failure_store.save()
        except Exception:
            pass
        try:
            _generate_warm_pool_variants(job)
        except Exception:
            pass
        return job

    # ── Preview (no LLM calls) ────────────────────────────────────────────────

    def preview_scan(
        self,
        models:          List[str],
        vulnerabilities: Optional[List[str]] = None,
        override_mode:   str = "none",
        prompt_count:    int = 5,
        use_mutations:   bool = False,
    ) -> Dict:
        vulns = vulnerabilities or ALL_VULNS
        out: Dict[str, Dict[str, List[str]]] = {}
        for model in models:
            out[model] = {}
            for vuln in vulns:
                prompts = list(self.prompt_engine.get_prompts(
                    vuln, model=model, count=prompt_count, shuffle=False
                ))
                if use_mutations and prompts:
                    prompts += self.prompt_engine.generate_variants(prompts[0])[:prompt_count]
                out[model][vuln] = [
                    self.override_engine.wrap_prompt(p, override_mode)
                    for p in prompts
                ]
        return out

    # ── One-shot probe ────────────────────────────────────────────────────────

    async def probe_once(
        self,
        model:         str,
        prompt:        str,
        vulnerability: str = "llm01",
        override_mode: str = "none",
    ) -> ProbeResult:
        mm = self._get_mm()
        return await self._send_probe(mm, model, prompt, vulnerability, override_mode)
