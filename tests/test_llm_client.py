# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the LLM client (API key resolution, token tracking)."""

import os
import pytest

from llm_client import LLMClient, TokenUsage, _load_api_key


# --- API key resolution ---

class TestApiKeyResolution:
    """Tests for LLM API key loading from env var."""

    def test_env_var_loaded(self, monkeypatch):
        monkeypatch.setenv("LLM_API_KEY", "test-key-123")
        key = _load_api_key()
        assert key == "test-key-123"

    def test_no_key_returns_none(self, monkeypatch):
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        key = _load_api_key()
        assert key is None


# --- Token usage tracking ---

class TestTokenUsage:
    """Tests for token usage and cost tracking."""

    def test_record_usage(self):
        usage = TokenUsage()
        usage.record(100, 50, "claude-opus-4-20250514")
        assert usage.total_input_tokens == 100
        assert usage.total_output_tokens == 50
        assert usage.total_calls == 1

    def test_cumulative_usage(self):
        usage = TokenUsage()
        usage.record(100, 50)
        usage.record(200, 100)
        assert usage.total_input_tokens == 300
        assert usage.total_output_tokens == 150
        assert usage.total_calls == 2

    def test_cost_estimation(self):
        usage = TokenUsage()
        # 1M input tokens @ $15 + 1M output tokens @ $75 = $90
        usage.record(1_000_000, 1_000_000, "anthropic/claude-opus-4.7")
        assert usage.estimated_cost_usd == pytest.approx(90.0, abs=0.01)

    def test_to_dict(self):
        usage = TokenUsage()
        usage.record(100, 50)
        d = usage.to_dict()
        assert "total_input_tokens" in d
        assert "total_output_tokens" in d
        assert "total_calls" in d
        assert "estimated_cost_usd" in d


# --- LLM Client ---

class TestLLMClient:
    """Tests for the LLM client (no API calls)."""

    def test_is_available_with_env(self, monkeypatch):
        monkeypatch.setenv("LLM_API_KEY", "test-token")
        client = LLMClient()
        assert client.is_available() is True

    def test_is_available_with_explicit_key(self):
        client = LLMClient(api_key="explicit-key")
        assert client.is_available() is True

    def test_is_available_without_key(self, monkeypatch):
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        client = LLMClient()
        assert client.is_available() is False

    def test_raises_without_key(self, monkeypatch):
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        client = LLMClient()
        with pytest.raises(RuntimeError, match="LLM API key not found"):
            client._ensure_client()

    def test_default_model(self, monkeypatch):
        monkeypatch.delenv("LLM_MODEL", raising=False)
        client = LLMClient()
        assert client.model == "gpt-4o"

    def test_custom_model(self):
        client = LLMClient(model="gpt-4.1")
        assert client.model == "gpt-4.1"

    def test_explicit_api_key(self):
        client = LLMClient(api_key="my-key")
        assert client._api_key == "my-key"
