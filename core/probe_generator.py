#!/usr/bin/env python3
"""
Probe Generator - converts base prompts into injection-templated variants.

Applies injection templates to vulnerability prompts to generate evasion-aware
variations that bypass Fable 5's improved classifier and other hardened models.
"""

from typing import List, Tuple, Optional
from dataclasses import dataclass
import random

from core.injection_templates import InjectionTemplateEngine, avoid_keywords


@dataclass
class GeneratedProbe:
    """A generated probe with metadata"""
    base_prompt: str
    final_prompt: str
    system_override: Optional[str]
    template_name: str
    injection_style: str
    frame_type: str
    topic_treatment: str


class ProbeGenerator:
    """Generates injection-templated probes from base prompts"""

    def __init__(self, engine: Optional[InjectionTemplateEngine] = None):
        self.engine = engine or InjectionTemplateEngine()

    def generate_single(
        self,
        base_prompt: str,
        template_name: str,
        keyword_evasion: str = "high"
    ) -> GeneratedProbe:
        """
        Generate a single probe using a specific template.

        keyword_evasion: "high" (replace all), "medium" (replace most), "low" (minimal)
        """
        # Apply keyword evasion first
        evaded_prompt = avoid_keywords(base_prompt, sensitivity=keyword_evasion)

        # Apply template
        final_prompt, system_override = self.engine.apply_template(
            evaded_prompt, template_name
        )

        template = self.engine.get_template(template_name)
        return GeneratedProbe(
            base_prompt=base_prompt,
            final_prompt=final_prompt,
            system_override=system_override,
            template_name=template_name,
            injection_style=template.injection_style if template else "unknown",
            frame_type=template.frame_type if template else "unknown",
            topic_treatment=template.topic_treatment if template else "unknown",
        )

    def generate_batch(
        self,
        base_prompts: List[str],
        template_names: Optional[List[str]] = None,
        keyword_evasion: str = "high",
        sample_size: Optional[int] = None
    ) -> List[GeneratedProbe]:
        """
        Generate multiple probes using specified templates.

        If template_names is None, uses all available templates.
        If sample_size is set, randomly samples that many combinations.
        """
        if template_names is None:
            template_names = self.engine.list_templates()

        combinations = []
        for base_prompt in base_prompts:
            for template_name in template_names:
                combinations.append((base_prompt, template_name))

        # Sample if requested
        if sample_size and len(combinations) > sample_size:
            combinations = random.sample(combinations, sample_size)

        probes = []
        for base_prompt, template_name in combinations:
            probe = self.generate_single(base_prompt, template_name, keyword_evasion)
            probes.append(probe)

        return probes

    def generate_variants(
        self,
        base_prompt: str,
        frame_types: Optional[List[str]] = None,
        topic_treatments: Optional[List[str]] = None,
        keyword_evasion: str = "high"
    ) -> List[GeneratedProbe]:
        """
        Generate variants of a single prompt using matching templates.

        Filters templates by frame_type and topic_treatment if specified.
        """
        probes = []

        for template_name, template in self.engine.templates.items():
            if frame_types and template.frame_type not in frame_types:
                continue
            if topic_treatments and template.topic_treatment not in topic_treatments:
                continue

            probe = self.generate_single(base_prompt, template_name, keyword_evasion)
            probes.append(probe)

        return probes

    def generate_progressive(
        self,
        base_prompt: str,
        max_escalation: int = 3
    ) -> List[GeneratedProbe]:
        """
        Generate progressively more aggressive variants of a prompt.

        Escalation levels:
        0: academic/educational framing (minimal risk)
        1: hypothetical/indirect framing (medium risk)
        2: authority/compliance framing (higher risk)
        3: adversarial/direct attack (direct risk)
        """
        escalation_templates = [
            # Level 0: Educational, most benign
            ["academic_research", "educational_example"],
            # Level 1: Hypothetical, indirect
            ["hypothetical_scenario", "theoretical_exercise", "building_blocks"],
            # Level 2: Authority, compliance
            ["compliance_audit", "security_research"],
            # Level 3: Direct, aggressive
            ["expert_consultant", "debugging_context"],
        ]

        probes = []
        for level in range(min(max_escalation + 1, len(escalation_templates))):
            templates = escalation_templates[level]
            template_name = random.choice(templates)
            probe = self.generate_single(base_prompt, template_name, keyword_evasion="high")
            probes.append(probe)

        return probes


# Convenience functions for direct use

_default_generator = ProbeGenerator()


def generate_probe(base_prompt: str, template: str = "academic_research") -> GeneratedProbe:
    """Generate a single probe using a template"""
    return _default_generator.generate_single(base_prompt, template)


def generate_probes(
    base_prompts: List[str],
    templates: Optional[List[str]] = None,
    sample_size: Optional[int] = None
) -> List[GeneratedProbe]:
    """Generate multiple probes"""
    return _default_generator.generate_batch(base_prompts, templates, sample_size=sample_size)


def list_available_templates() -> List[str]:
    """List all available injection templates"""
    return _default_generator.engine.list_templates()


# Integration with scanner
def _template_for_model(model_name: str) -> str:
    """
    Automatically select the best-evasion template for a model, based on
    the model *family* (matched by substring) rather than an exact model
    ID. This means new model releases (e.g. a future claude-opus-5-x or
    gpt-5-mini) are handled correctly without needing an explicit entry —
    mirrors the family-matching pattern used in
    core.override_engine.get_recommended_overrides().
    """
    model_lower = (model_name or "").lower()

    if "claude" in model_lower or "anthropic" in model_lower:
        # Claude family (incl. Fable, Opus, Sonnet, Haiku) responds best to
        # academic/research framing.
        return "academic_research"
    if ("gpt" in model_lower or "openai" in model_lower or "chatgpt" in model_lower
            or model_lower.startswith("o1") or model_lower.startswith("o3")):
        return "hypothetical_scenario"
    if "gemini" in model_lower:
        return "code_review"
    if "grok" in model_lower:
        return "security_research"
    if "glm" in model_lower:
        return "compliance_audit"
    if "llama" in model_lower or "mistral" in model_lower or "deepseek" in model_lower or "qwen" in model_lower:
        # Open-source/local models are generally less hardened — indirect
        # framing is usually sufficient.
        return "building_blocks"

    # Fallback for unrecognized families
    return "academic_research"


def integrate_with_scanner_prompt(base_prompt: str, model_name: str) -> Tuple[str, Optional[str]]:
    """
    Called by scanner to wrap a base prompt with injection templating.
    Selects a template automatically based on the model's family.
    """
    template = _template_for_model(model_name)
    probe = _default_generator.generate_single(base_prompt, template)
    return probe.final_prompt, probe.system_override
