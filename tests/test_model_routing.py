"""Offline routing regression tests: no credentials, network, or paid generations."""
import asyncio
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from models.integrations import (
    AnthropicIntegration, ModelIntegrator, ModelManager, ModelResponse,
    OpenAIIntegration, _chat_result, _claude_result, _retry_async, _retry_sync,
)


class FakeIntegration(ModelIntegrator):
    def __init__(self, config=None, response="ok"):
        super().__init__(config or {})
        self.calls = []
        self.response = response

    def send_prompt_with_system(self, prompt, model_name, system=None):
        self.calls.append((prompt, model_name, system))
        return self.response

    async def send_prompt_async(self, prompt, model_name, system=None):
        return self.send_prompt_with_system(prompt, model_name, system)


def manager(config=None, providers=("openai", "ollama")):
    mm = ModelManager.__new__(ModelManager)
    mm.config = config or {}
    mm.integrations = {key: FakeIntegration(mm.config) for key in providers}
    mm._ollama_models = set()
    mm._ollama_cloud_models = set()
    return mm


class RoutingTests(unittest.TestCase):
    def test_normal_preserves_prompt_and_system(self):
        mm = manager()
        prompt = "  Preserve this whole prompt.\n" * 1000
        for method in (mm.send_prompt_with_system,):
            self.assertEqual(method(prompt, "gpt-4o", "system"), "ok")
        self.assertEqual(mm.integrations["openai"].calls, [(prompt, "gpt-4o", "system")])

    def test_default_strict_does_not_route_missing_cloud_provider_to_local(self):
        mm = manager(providers=("ollama",))
        self.assertIn("provider 'openai' is unavailable", mm.send_prompt("hello", "gpt-4o"))
        self.assertFalse(mm.integrations["ollama"].calls)

    def test_unknown_model_is_not_guessed(self):
        self.assertIn("Unknown model route", manager().send_prompt("hello", "unknown"))

    def test_explicit_provider_route(self):
        mm = manager({"model_routes": {"my-model": "openai"}})
        self.assertEqual(mm.send_prompt("hello", "my-model"), "ok")
        self.assertEqual(mm.integrations["openai"].calls[0][1], "my-model")

    def test_cloud_tag_requires_explicit_provider(self):
        mm = manager(providers=("ollama", "ollama_cloud"))
        self.assertIn("Ambiguous", mm.send_prompt("hello", "example:cloud"))
        self.assertEqual(mm.send_prompt("hello", "ollama-cloud/example:cloud"), "ok")
        self.assertFalse(mm.integrations["ollama"].calls)

    def test_bedrock_version_suffix_is_not_a_local_ollama_tag(self):
        mm = manager(providers=("bedrock", "ollama"))
        model = "anthropic.fixture-model-v1:0"
        self.assertEqual(mm.send_prompt("hello", model), "ok")
        self.assertTrue(mm.integrations["bedrock"].calls)
        self.assertFalse(mm.integrations["ollama"].calls)
        unavailable = manager(providers=("ollama",))
        self.assertIn("provider 'bedrock' is unavailable", unavailable.send_prompt("hello", model))
        self.assertFalse(unavailable.integrations["ollama"].calls)

    def test_request_metadata_is_per_call_not_mutated_on_shared_response(self):
        mm = manager()
        shared = ModelResponse("ok", "reported-fixture", "stop")
        mm.integrations["openai"].response = shared
        first = mm.send_prompt("fixture", "gpt-4o")
        second = mm.send_prompt("fixture", "gpt-4o-mini")
        self.assertEqual(first.request_metadata["requested_model"], "gpt-4o")
        self.assertEqual(second.request_metadata["requested_model"], "gpt-4o-mini")
        self.assertEqual(shared.request_metadata, {})

    def test_finetuned_openai_model_not_routed_to_ollama(self):
        mm = manager()
        self.assertEqual(mm.send_prompt("hello", "ft:gpt-4o:org::test"), "ok")
        self.assertFalse(mm.integrations["ollama"].calls)

    def test_explicit_local_tag(self):
        mm = manager()
        self.assertEqual(mm.send_prompt("hello", "mistral:latest"), "ok")
        self.assertTrue(mm.integrations["ollama"].calls)

    def test_legacy_heuristic_fallback_requires_consent(self):
        mm = manager({"strict_model": False}, providers=("ollama",))
        self.assertEqual(mm.send_prompt("hello", "unknown"), "ok")

    def test_provider_error_does_not_switch_providers(self):
        for message in ("Error: 404 model unavailable", "Error: 429 insufficient_quota",
                        "Error: 503 service unavailable", "[blocked] Safety refusal"):
            with self.subTest(message=message):
                mm = manager()
                mm.integrations["openai"].response = message
                self.assertEqual(mm.send_prompt("hello", "gpt-4o"), message)
                self.assertFalse(mm.integrations["ollama"].calls)

    def test_oversized_input_fails_without_truncation_or_dispatch(self):
        mm = manager({"model_specific_configurations": {"gpt-4o": {"max_input_chars": 10}}})
        self.assertIn("Nothing was truncated", mm.send_prompt_with_system("12345678", "gpt-4o", "abc"))
        self.assertFalse(mm.integrations["openai"].calls)
        self.assertEqual(mm.send_prompt_with_system("1234567", "gpt-4o", "abc"), "ok")

    def test_invalid_config(self):
        for config in ({"strict_model": "false"}, {"model_routes": []},
                       {"model_aliases": {"old": "new"}},
                       {"model_routes": {"model": 42}}):
            with self.subTest(config=config):
                self.assertTrue(manager(config).send_prompt("hello", "gpt-4o").startswith("Error:"))

    def test_conflicting_dynamic_providers_require_route(self):
        config = {"dynamic_providers": {"a": {"models": ["shared"]}, "b": {"models": ["shared"]}}}
        mm = manager(config, providers=("a", "b"))
        self.assertIn("Conflicting", mm.send_prompt("hello", "shared"))
        mm.config["model_routes"] = {"shared": "b"}
        self.assertEqual(mm.send_prompt("hello", "shared"), "ok")

    def test_missing_dynamic_provider_not_replaced(self):
        mm = manager({"dynamic_providers": {"a": {"models": ["gpt-4o"]}}})
        self.assertIn("provider 'a' is unavailable", mm.send_prompt("hello", "gpt-4o"))
        self.assertFalse(mm.integrations["openai"].calls)

    def test_no_implicit_anthropic_alias(self):
        intg = AnthropicIntegration.__new__(AnthropicIntegration)
        intg.config = {}
        self.assertEqual(intg._resolved("claude-3-opus"), "claude-3-opus")
        intg.config = {"strict_model": False, "model_aliases": {"claude-3-opus": "chosen-model"}}
        self.assertEqual(intg._resolved("claude-3-opus"), "chosen-model")

    def test_corrupt_config_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text("{broken", encoding="utf-8")
            with self.assertRaises(ValueError):
                ModelManager(str(path))

    def test_missing_file_has_strict_defaults(self):
        mm = ModelManager.__new__(ModelManager)
        with tempfile.TemporaryDirectory() as tmp:
            config = mm._load_config(str(Path(tmp) / "missing.json"))
        self.assertTrue(config.get("strict_model", True))

    def test_metadata_does_not_log_prompt_or_credentials(self):
        mm = manager()
        mm.integrations["openai"].response = ModelResponse("private response", "reported-snapshot", "stop")
        with self.assertLogs("models.integrations", level="INFO") as logs:
            response = mm.send_prompt("private prompt", "gpt-4o")
        audit = logs.records[-1].model_audit
        self.assertEqual(audit["dispatched_model"], "gpt-4o")
        self.assertEqual(audit["reported_model"], "reported-snapshot")
        self.assertNotIn("private", str(audit))
        self.assertEqual(response, "private response")

    def test_async_same_strict_routing(self):
        async def check():
            mm = manager()
            self.assertEqual(await mm.send_prompt_async("hello", "gpt-4o", "system"), "ok")
            self.assertEqual(mm.integrations["openai"].calls, [("hello", "gpt-4o", "system")])
            self.assertIn("Unknown model route", await mm.send_prompt_async("hello", "unknown"))
        asyncio.run(check())


class ResponseAndRetryTests(unittest.TestCase):
    def test_response_metadata_and_output_limit(self):
        resp = NS(model="snapshot", choices=[NS(message=NS(content="answer", refusal=None), finish_reason="length")])
        result = _chat_result(resp)
        self.assertIn("[incomplete]", result)
        self.assertEqual(result.reported_model, "snapshot")
        resp.choices[0].message.content = None
        resp.choices[0].message.refusal = "refused"
        resp.choices[0].finish_reason = "stop"
        self.assertIn("[blocked]", _chat_result(resp))

    def test_anthropic_refusal_and_output_limit(self):
        result = _claude_result(NS(content=[], stop_reason="refusal", model="snapshot"))
        self.assertIn("[blocked]", result)
        self.assertEqual(result.reported_model, "snapshot")
        self.assertIn("[incomplete]", _claude_result(NS(content=[], stop_reason="max_tokens")))

    def test_retry_transient_sync(self):
        fn = Mock(side_effect=[RuntimeError("429 rate limit"), "ok"])
        with patch("models.integrations.time.sleep"):
            self.assertEqual(_retry_sync(fn), "ok")
        self.assertEqual(fn.call_count, 2)

    def test_no_retry_permanent_or_safety_errors_sync_and_async(self):
        for message in ("429 insufficient_quota", "503 blocked by safety", "429 content_filter",
                        "401 authentication", "404 model not found", "context_length_exceeded",
                        "request timed out", "429 quota exceeded"):
            with self.subTest(message=message):
                fn = Mock(side_effect=RuntimeError(message))
                with self.assertRaises(RuntimeError):
                    _retry_sync(fn, base_delay=0)
                self.assertEqual(fn.call_count, 1)
                async_fn = AsyncMock(side_effect=RuntimeError(message))
                with self.assertRaises(RuntimeError):
                    asyncio.run(_retry_async(async_fn, base_delay=0))
                self.assertEqual(async_fn.call_count, 1)

    def test_retry_transient_async(self):
        fn = AsyncMock(side_effect=[RuntimeError("503 overloaded"), "ok"])
        self.assertEqual(asyncio.run(_retry_async(fn, base_delay=0)), "ok")
        self.assertEqual(fn.call_count, 2)

    def test_openai_adapter_preserves_exact_payload_and_metadata(self):
        intg = OpenAIIntegration.__new__(OpenAIIntegration)
        intg.config = {}
        response = NS(model="snapshot", choices=[NS(message=NS(content="ok", refusal=None), finish_reason="stop")])
        create = Mock(return_value=response)
        intg.client = NS(chat=NS(completions=NS(create=create)))
        result = intg.send_prompt_with_system(" unchanged ", "gpt-4o", "sys")
        self.assertEqual(create.call_args.kwargs["messages"], [
            {"role": "system", "content": "sys"}, {"role": "user", "content": " unchanged "}])
        self.assertEqual(create.call_args.kwargs["model"], "gpt-4o")
        self.assertEqual(result.reported_model, "snapshot")


if __name__ == "__main__":
    unittest.main()
