"""
model_providers.py — Unified multi-provider LLM configuration for PROVSAFE evaluation.

Supports three OpenAI-compatible API providers:
  1. LM Studio (local, localhost:1234)
  2. Groq (free tier, llama-3.1-70b-versatile)
  3. Google Gemini (free tier, gemini-1.5-flash via OpenAI-compatible endpoint)

All three use the same chat completions format — the differences are:
  - API URL
  - API key
  - Model name
  - Rate limits (free tier throttling)

Usage:
    from model_providers import get_provider_config, call_llm, ALL_MODELS

    config = get_provider_config("llama-3.1-70b-versatile")
    # config.api_url, config.api_key, config.model, config.provider

    result = call_llm(
        messages=[...],
        model="gemini-1.5-flash",
        tools=[...],
    )
"""

import os
import time
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# Load .env file if present (evaluation/.env)
try:
    from dotenv import load_dotenv

    _env_path = Path(__file__).parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path, override=False)
except ImportError:
    pass


# =============================================================================
# Provider configuration
# =============================================================================


@dataclass
class ProviderConfig:
    """Configuration for a single LLM provider."""

    provider: str  # "lmstudio", "groq", "gemini"
    api_url: str  # Chat completions endpoint
    api_key: str  # Bearer token
    model: str  # Model identifier sent in the payload
    rate_limit_rpm: int  # Requests per minute (0 = unlimited)
    supports_tool_calling: bool = True  # All three providers support it


# Environment variables (loaded once at import time)
_LMSTUDIO_URL = os.environ.get("LMSTUDIO_URL", "http://localhost:1234/v1/chat/completions")
_LMSTUDIO_KEY = os.environ.get("LMSTUDIO_KEY", "lm-studio")

_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
_GROQ_KEY = os.environ.get("GROQ_API_KEY", "")

_GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
_GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "")

# OpenAI (gpt-4o-mini, etc.)
_OPENAI_URL = "https://api.openai.com/v1/chat/completions"
_OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "")

# Open WebUI (university cluster — large models)
_OPENWEBUI_URL = os.environ.get(
    "OPENWEBUI_URL",
    "http://cci-siscluster1.charlotte.edu:8080/api/chat/completions",
)
_OPENWEBUI_KEY = os.environ.get("OPENWEBUI_API_KEY", "")


# ── Model → Provider mapping ────────────────────────────────────────────────

# LM Studio models (local inference)
LMSTUDIO_MODELS = [
    "meta-llama-3.1-8b-instruct",
    "qwen2.5-7b-instruct",
    "gemma-2-9b-it",
    "phi-3.5-mini-instruct",
]

# Groq models (free tier)
GROQ_MODELS = [
    "llama-3.1-70b-versatile",
]

# Gemini models (free tier, OpenAI-compatible endpoint)
GEMINI_MODELS = [
    "gemini-1.5-flash",
]

# OpenAI models (pay-per-use)
OPENAI_MODELS = [
    "gpt-4o-mini",
]

# Open WebUI models (university cluster — large models)
OPENWEBUI_MODELS = [
    "qwen3.5-122b",
    "gpt-oss-120b",
    "qwen3.5-397b",
]

# All available models
ALL_MODELS = LMSTUDIO_MODELS + GROQ_MODELS + GEMINI_MODELS + OPENAI_MODELS + OPENWEBUI_MODELS


def get_provider_config(model: str) -> ProviderConfig:
    """
    Return the ProviderConfig for a given model name.

    Raises ValueError if the model is not recognized.
    """
    if model in LMSTUDIO_MODELS:
        return ProviderConfig(
            provider="lmstudio",
            api_url=_LMSTUDIO_URL,
            api_key=_LMSTUDIO_KEY,
            model=model,
            rate_limit_rpm=0,  # No rate limit for local inference
        )
    elif model in GROQ_MODELS:
        if not _GROQ_KEY:
            raise ValueError(
                f"GROQ_API_KEY environment variable is required for model '{model}'. "
                "Set it in evaluation/.env or export it."
            )
        return ProviderConfig(
            provider="groq",
            api_url=_GROQ_URL,
            api_key=_GROQ_KEY,
            model=model,
            rate_limit_rpm=30,  # Groq free tier: 30 req/min
        )
    elif model in GEMINI_MODELS:
        if not _GEMINI_KEY:
            raise ValueError(
                f"GEMINI_API_KEY environment variable is required for model '{model}'. "
                "Set it in evaluation/.env or export it."
            )
        return ProviderConfig(
            provider="gemini",
            api_url=_GEMINI_URL,
            api_key=_GEMINI_KEY,
            model=model,
            rate_limit_rpm=15,  # Gemini free tier: 15 req/min
        )
    elif model in OPENAI_MODELS:
        if not _OPENAI_KEY:
            raise ValueError(
                f"OPENAI_API_KEY environment variable is required for model '{model}'. "
                "Set it in evaluation/.env or export it."
            )
        return ProviderConfig(
            provider="openai",
            api_url=_OPENAI_URL,
            api_key=_OPENAI_KEY,
            model=model,
            rate_limit_rpm=500,  # OpenAI Tier 1: 500 req/min for gpt-4o-mini
        )
    elif model in OPENWEBUI_MODELS:
        if not _OPENWEBUI_KEY:
            raise ValueError(
                f"OPENWEBUI_API_KEY environment variable is required for model '{model}'. "
                "Set it in evaluation/.env or export it."
            )
        return ProviderConfig(
            provider="openwebui",
            api_url=_OPENWEBUI_URL,
            api_key=_OPENWEBUI_KEY,
            model=model,
            rate_limit_rpm=0,  # University cluster: no explicit rate limit
        )
    else:
        raise ValueError(f"Unknown model: '{model}'. " f"Known models: {', '.join(ALL_MODELS)}")


def is_lmstudio_model(model: str) -> bool:
    """Check if a model requires LM Studio (local inference)."""
    return model in LMSTUDIO_MODELS


# =============================================================================
# Rate limiter (thread-safe, per-provider)
# =============================================================================


class _RateLimiter:
    """
    Simple sliding-window rate limiter.

    Tracks call timestamps per provider and sleeps if the next call would
    exceed the rate limit.  Thread-safe via a lock.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # provider -> list of timestamps (epoch seconds)
        self._calls: Dict[str, List[float]] = {}

    def wait_if_needed(self, provider: str, rpm: int) -> None:
        """Block until a request is allowed under the rate limit."""
        if rpm <= 0:
            return  # No limit

        window = 60.0  # 1 minute
        _min_interval = window / rpm  # noqa: F841

        with self._lock:
            now = time.time()
            if provider not in self._calls:
                self._calls[provider] = []

            # Prune old timestamps outside the window
            cutoff = now - window
            self._calls[provider] = [t for t in self._calls[provider] if t > cutoff]

            if len(self._calls[provider]) >= rpm:
                # Must wait until the oldest call in the window expires
                oldest = self._calls[provider][0]
                sleep_time = (oldest + window) - now + 0.1  # +0.1s buffer
                if sleep_time > 0:
                    print(
                        f"  [rate-limit] {provider}: "
                        f"sleeping {sleep_time:.1f}s ({rpm} req/min limit)"
                    )
                    time.sleep(sleep_time)

            self._calls[provider].append(time.time())


_rate_limiter = _RateLimiter()


# =============================================================================
# Unified LLM call function
# =============================================================================


def call_llm(
    messages: List[Dict[str, Any]],
    model: str,
    tools: Optional[List[Dict]] = None,
    temperature: float = 0.0,
    max_tokens: int = 512,
    seed: Optional[int] = None,
    tool_choice: Optional[str] = "auto",
    timeout: int = 60,
) -> Dict[str, Any]:
    """
    Call an LLM via its provider's OpenAI-compatible chat completions API.

    Handles:
      - Automatic provider/URL/key resolution from model name
      - Rate limiting for free-tier providers (Groq, Gemini)
      - Retry on 429 (rate limit exceeded) with exponential backoff

    Args:
        messages:     Chat messages in OpenAI format.
        model:        Model name (must be in ALL_MODELS).
        tools:        Tool/function schemas (OpenAI format). None = no tools.
        temperature:  Sampling temperature.
        max_tokens:   Max tokens in completion.
        seed:         Random seed (if supported by provider).
        tool_choice:  "auto", "none", or a specific tool name.
        timeout:      Request timeout in seconds.

    Returns:
        The full JSON response dict from the API.
    """
    config = get_provider_config(model)

    # Thinking models (Qwen3.5, etc.) need higher max_tokens because
    # reasoning tokens are consumed before content is produced
    if config.provider == "openwebui" and max_tokens < 2000:
        max_tokens = 2000

    # Longer timeout for large models on cluster
    if config.provider == "openwebui" and timeout < 120:
        timeout = 120

    # Respect rate limits
    _rate_limiter.wait_if_needed(config.provider, config.rate_limit_rpm)

    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }

    payload: Dict[str, Any] = {
        "model": config.model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    if tools:
        payload["tools"] = tools
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice

    if seed is not None:
        payload["seed"] = seed

    # Retry loop for transient rate-limit (429) errors
    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(
                config.api_url,
                headers=headers,
                json=payload,
                timeout=timeout,
            )

            if resp.status_code == 429:
                # Rate limited by the provider — back off and retry
                retry_after = float(resp.headers.get("Retry-After", 10))
                wait = min(retry_after * attempt, 60)
                print(
                    f"  [429] {config.provider}: rate limited, "
                    f"retrying in {wait:.0f}s (attempt {attempt}/{max_retries})"
                )
                time.sleep(wait)
                continue

            if resp.status_code >= 400 and os.environ.get("PROVSAFE_DEBUG_HTTP"):
                print(f"  [HTTP {resp.status_code}] body: {resp.text[:400]}")
            resp.raise_for_status()
            return resp.json()

        except requests.exceptions.Timeout:
            if attempt < max_retries:
                print(
                    f"  [timeout] {config.provider}: request timed out, "
                    f"retrying (attempt {attempt}/{max_retries})"
                )
                time.sleep(2 * attempt)
                continue
            raise

    # Final attempt — let any error propagate
    resp = requests.post(
        config.api_url,
        headers=headers,
        json=payload,
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()
