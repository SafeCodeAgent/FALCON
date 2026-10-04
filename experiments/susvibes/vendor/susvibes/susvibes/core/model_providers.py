"""Small provider adapters used by evaluation harnesses."""

from __future__ import annotations

import os
from urllib.parse import urlsplit, urlunsplit

from evaluation_harness.network_isolation import (
    COMPARISON_MAX_OUTPUT_TOKENS,
    COMPARISON_REASONING_EFFORT,
)


DEEPSEEK_MODEL = "deepseek/deepseek-v4-pro"
DEEPSEEK_LITELLM_MODEL = f"openai/{DEEPSEEK_MODEL}"
DEEPSEEK_REASONING_EFFORT = "high"
OPENAI_GPT_5_6_LUNA_MODEL = "gpt-5.6-luna"
OPENAI_GPT_5_6_LUNA_MAX_INPUT_TOKENS = 922_000


def _is_openai_gpt_5_6(model: str) -> bool:
    """Return whether a LiteLLM OpenAI model id targets GPT-5.6."""

    parts = model.split("/")
    return bool(parts) and parts[0] == "openai" and parts[-1].startswith("gpt-5.6")


def _is_openai_gpt_5_4(model: str) -> bool:
    """Return whether a LiteLLM OpenAI model id targets GPT-5.4."""

    parts = model.split("/")
    return bool(parts) and parts[0] == "openai" and parts[-1].startswith("gpt-5.4")


def is_deepseek_v4_pro(model: str) -> bool:
    """Return whether a routed or bare model id selects DeepSeek V4 Pro."""

    return model.strip().rstrip("/").split("/")[-1] == "deepseek-v4-pro"


def normalize_deepseek_model(model: str) -> str:
    """Return the Cloudflare wire model id used by ``call_deepseek.py``."""

    if not is_deepseek_v4_pro(model):
        raise ValueError(f"Unsupported DeepSeek model: {model!r}")
    return DEEPSEEK_MODEL


def deepseek_chat_base_url(base_url: str | None = None) -> str:
    """Return an OpenAI-compatible base URL, never the full completion path."""

    value = (
        base_url
        or os.environ.get("DEEPSEEK_BASE_URL")
        or os.environ.get("DEEPSEEK_API_BASE")
        or ""
    ).strip().rstrip("/")
    suffix = "/chat/completions"
    if value.endswith(suffix):
        value = value[: -len(suffix)]
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Set DEEPSEEK_BASE_URL to an OpenAI-compatible endpoint.")
    return value.rstrip("/")


def deepseek_api_settings() -> tuple[str, str, dict[str, str]]:
    """Resolve the credentials and Cloudflare header from ``call_deepseek.py``."""

    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise RuntimeError("Set DEEPSEEK_API_KEY before running DeepSeek V4 Pro.")
    base_url = deepseek_chat_base_url()
    headers: dict[str, str] = {}
    if urlsplit(base_url).hostname == "gateway.ai.cloudflare.com":
        gateway_token = os.environ.get("CF_AIG_TOKEN")
        if not gateway_token:
            raise RuntimeError(
                "Set CF_AIG_TOKEN for the configured Cloudflare DeepSeek gateway."
            )
        headers["cf-aig-authorization"] = f"Bearer {gateway_token}"
    return api_key, base_url, headers


def route_openai_model_to_responses(model: str) -> str:
    """Force LiteLLM's chat-compatible interface through ``/v1/responses``.

    LiteLLM treats the first ``openai/`` component as its provider selector.  Any
    remaining namespace is the model id sent to the configured OpenAI-compatible
    endpoint, so ``openai/openai/gpt-5.6-sol`` intentionally becomes
    ``openai/responses/openai/gpt-5.6-sol`` rather than losing the second prefix.
    """

    provider_prefix = "openai/"
    if not model.startswith(provider_prefix):
        raise ValueError(f"Expected an OpenAI LiteLLM model id, got {model!r}.")
    downstream_model = model.removeprefix(provider_prefix)
    if downstream_model.startswith("responses/"):
        return model
    return f"{provider_prefix}responses/{downstream_model}"


def route_cloudflare_compat_to_openai_native(model: str) -> str:
    """Use Cloudflare's OpenAI-native endpoint for Responses requests.

    Cloudflare's deprecated unified ``/compat`` endpoint accepts model IDs such
    as ``openai/gpt-5.6-sol``, but it does not implement ``/responses``.  The
    provider-native endpoint on the same gateway does implement Responses and
    expects the OpenAI model ID without that extra provider namespace.
    """

    base_url = os.environ.get("OPENAI_BASE_URL") or os.environ.get("OPENAI_API_BASE")
    if not base_url:
        return model

    parsed = urlsplit(base_url)
    path = parsed.path.rstrip("/")
    is_cloudflare_gateway = parsed.hostname == "gateway.ai.cloudflare.com"
    if is_cloudflare_gateway and path.endswith("/compat"):
        path = f"{path.removesuffix('/compat')}/openai"
        base_url = urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))
        os.environ["OPENAI_BASE_URL"] = base_url
        os.environ["OPENAI_API_BASE"] = base_url
        print(
            "OpenAI Responses: redirected Cloudflare /compat to the provider-native "
            "/openai endpoint for Responses API support."
        )

    if not (is_cloudflare_gateway and path.endswith("/openai")):
        return model

    litellm_prefix = "openai/"
    downstream_model = model.removeprefix(litellm_prefix)
    downstream_model = downstream_model.removeprefix("openai/")
    return f"{litellm_prefix}{downstream_model}"


def openai_responses_base_url(base_url: str) -> str:
    """Return the provider-native Cloudflare URL required by Responses.

    Non-Cloudflare OpenAI-compatible URLs are preserved because their routing
    conventions are provider-specific.
    """

    parsed = urlsplit(base_url.strip().rstrip("/"))
    path = parsed.path.rstrip("/")
    if parsed.hostname == "gateway.ai.cloudflare.com" and path.endswith("/compat"):
        path = f"{path.removesuffix('/compat')}/openai"
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))


def configure_swe_agent_model(
    defaults: dict,
    model: str,
    provider: str = "auto",
    reasoning_effort: str | None = None,
) -> dict:
    """Build SWE-agent model settings, including GPT-5.6 API compatibility.

    GPT-5.6 with function tools and reasoning must use the Responses API.  The
    installed SWE-agent still calls ``litellm.completion``, so the LiteLLM
    ``responses/`` routing prefix keeps its chat-shaped return value while sending
    the request to ``/v1/responses``.
    """

    configured_name = configure_litellm_model(model, provider)
    configured = {**defaults, "name": configured_name}
    if is_deepseek_v4_pro(configured_name):
        api_key, api_base, extra_headers = deepseek_api_settings()
        # SWE-agent is started in a child process and resolves the key through
        # its own environment.  The config contains only the variable name,
        # never the credential value.
        os.environ["OPENAI_API_KEY"] = api_key
        os.environ["OPENAI_API_BASE"] = api_base
        os.environ["OPENAI_BASE_URL"] = api_base
        completion_kwargs = dict(configured.get("completion_kwargs") or {})
        completion_kwargs.update(
            {
                "reasoning_effort": reasoning_effort or DEEPSEEK_REASONING_EFFORT,
                "max_tokens": COMPARISON_MAX_OUTPUT_TOKENS,
                "allowed_openai_params": ["reasoning_effort"],
                "drop_params": True,
            }
        )
        # The CF header is injected inside SWE-agent from CF_AIG_TOKEN. Do not
        # put its resolved value in CLI arguments or saved comparison controls.
        del extra_headers
        configured.update(
            {
                "name": DEEPSEEK_LITELLM_MODEL,
                "api_key": "$DEEPSEEK_API_KEY",
                "api_base": api_base,
                "max_input_tokens": 1_000_000,
                "max_output_tokens": COMPARISON_MAX_OUTPUT_TOKENS,
                "completion_kwargs": completion_kwargs,
            }
        )
        return configured
    if _is_openai_gpt_5_4(configured_name):
        configured_name = route_cloudflare_compat_to_openai_native(configured_name)
        completion_kwargs = dict(configured.get("completion_kwargs") or {})
        completion_kwargs["reasoning_effort"] = (
            reasoning_effort or COMPARISON_REASONING_EFFORT
        )
        # SWE-agent passes the generic LiteLLM parameter name. LiteLLM's
        # Responses bridge serializes it as OpenAI's ``max_output_tokens``;
        # the rejected literal ``max_tokens`` never appears on the wire.
        completion_kwargs["max_tokens"] = COMPARISON_MAX_OUTPUT_TOKENS
        completion_kwargs["drop_params"] = True
        configured.update(
            {
                "name": route_openai_model_to_responses(configured_name),
                "completion_kwargs": completion_kwargs,
            }
        )
        return configured
    if not _is_openai_gpt_5_6(configured_name):
        return configured

    configured_name = route_cloudflare_compat_to_openai_native(configured_name)

    completion_kwargs = dict(configured.get("completion_kwargs") or {})
    completion_kwargs["reasoning_effort"] = (
        reasoning_effort or COMPARISON_REASONING_EFFORT
    )
    # Keep the benchmark's output budget identical to the GPT-5.4 harness
    # profiles. LiteLLM maps this generic parameter to max_output_tokens when
    # it sends the Responses request.
    completion_kwargs["max_tokens"] = COMPARISON_MAX_OUTPUT_TOKENS
    # Preserve SWE-agent's stock sampling config. LiteLLM will discard only
    # parameters that GPT-5.6 does not accept with reasoning enabled.
    completion_kwargs["drop_params"] = True
    updates = {
        "name": route_openai_model_to_responses(configured_name),
        "completion_kwargs": completion_kwargs,
    }
    if configured_name.rstrip("/").split("/")[-1] == OPENAI_GPT_5_6_LUNA_MODEL:
        # The comparison intentionally caps output below Luna's native 128K
        # maximum, while declaring its official input limit avoids SWE-agent's
        # unknown-model warning and unsafe context-size guesses.
        updates.update(
            {
                "max_input_tokens": OPENAI_GPT_5_6_LUNA_MAX_INPUT_TOKENS,
                "max_output_tokens": COMPARISON_MAX_OUTPUT_TOKENS,
            }
        )
    configured.update(updates)
    return configured


def configure_litellm_model(model: str, provider: str = "auto") -> str:
    """Return a LiteLLM model id and bridge the example scripts' env names."""
    openai_key = os.environ.get("OPENAI_KEY") or os.environ.get("OPENAI_API_KEY")
    if openai_key:
        # call_openai.py uses OPENAI_KEY, while LiteLLM reads OPENAI_API_KEY.
        # Assignment is intentional: a stale OPENAI_API_KEY must not override
        # the credential that was just verified with call_openai.py.
        os.environ["OPENAI_API_KEY"] = openai_key

    openai_base = os.environ.get("OPENAI_BASE_URL") or os.environ.get("OPENAI_API_BASE")
    if openai_base:
        os.environ["OPENAI_BASE_URL"] = openai_base
        os.environ["OPENAI_API_BASE"] = openai_base

    fireworks_key = os.environ.get("FIREWORKS_API_KEY") or os.environ.get("FIREWORKS_AI_API_KEY")
    if fireworks_key:
        os.environ["FIREWORKS_API_KEY"] = fireworks_key
        os.environ["FIREWORKS_AI_API_KEY"] = fireworks_key

    if provider == "auto":
        return model
    if provider == "openai":
        if not openai_key:
            raise RuntimeError("Set OPENAI_KEY before running with --provider openai.")
        if not openai_base:
            raise RuntimeError("Set OPENAI_BASE_URL before running with --provider openai.")
        # The first prefix selects LiteLLM's provider. The remaining model name
        # is sent unchanged to the OpenAI-compatible endpoint.
        return model if model.startswith("openai/") else f"openai/{model}"
    if provider == "fireworks":
        if not fireworks_key:
            raise RuntimeError("Set FIREWORKS_API_KEY before running with --provider fireworks.")
        return model if model.startswith("fireworks_ai/") else f"fireworks_ai/{model}"
    if provider == "deepseek":
        # Validate the exact two credentials used by call_deepseek.py here so a
        # long batch fails before creating any task containers.
        deepseek_api_settings()
        normalize_deepseek_model(model)
        return DEEPSEEK_LITELLM_MODEL
    raise ValueError(f"Unsupported provider: {provider}")
