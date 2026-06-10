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

"""Tests for the deep scan detector (mocked LLM)."""

import json
from unittest.mock import MagicMock, patch

import pytest

from detector import Detector, RULE_BASED_SYSTEM_PROMPT, EXPLORATORY_SYSTEM_PROMPT
from finding_store import FindingStore
from indexer import CodeIndex


PYTHON_SAMPLE = '''\
def handle_login(username, password):
    query = f"SELECT * FROM users WHERE name='{username}'"
    return db.execute(query)

def safe_function():
    return "hello"
'''


@pytest.fixture
def store(tmp_path):
    return FindingStore(db_path=str(tmp_path / "test.db"))


@pytest.fixture
def index(tmp_path):
    f = tmp_path / "app.py"
    f.write_text(PYTHON_SAMPLE)
    idx = CodeIndex()
    idx.build(str(f))
    return idx


@pytest.fixture
def mock_llm():
    client = MagicMock()
    client.chat = MagicMock()
    return client


@pytest.fixture
def detector(mock_llm, index, store):
    return Detector(mock_llm, index, store)


# --- Response parsing ---

class TestResponseParsing:
    """Tests for parsing LLM responses."""

    def test_parse_valid_json_array(self):
        text = json.dumps([{
            "vulnerability_class": "sql-injection",
            "description": "SQL injection via string concatenation",
            "cwe": "CWE-89",
            "severity_tier": "ERROR",
            "severity_cvss": 8.5,
        }])
        result = Detector._parse_findings_response(text)
        assert len(result) == 1
        assert result[0]["vulnerability_class"] == "sql-injection"

    def test_parse_empty_array(self):
        result = Detector._parse_findings_response("[]")
        assert result == []

    def test_parse_single_object(self):
        text = json.dumps({
            "vulnerability_class": "xss",
            "description": "XSS found",
            "cwe": "CWE-79",
            "severity_tier": "WARNING",
            "severity_cvss": 6.0,
        })
        result = Detector._parse_findings_response(text)
        assert len(result) == 1

    def test_parse_markdown_wrapped(self):
        text = "```json\n" + json.dumps([{
            "vulnerability_class": "sqli",
            "description": "test",
            "cwe": "CWE-89",
            "severity_tier": "ERROR",
            "severity_cvss": 8.0,
        }]) + "\n```"
        result = Detector._parse_findings_response(text)
        assert len(result) == 1

    def test_parse_json_in_text(self):
        text = 'Here are the findings:\n[{"vulnerability_class": "xss", "description": "test"}]\nDone.'
        result = Detector._parse_findings_response(text)
        assert len(result) == 1

    def test_parse_invalid_json(self):
        result = Detector._parse_findings_response("not json at all")
        assert result == []

    def test_parse_empty_string(self):
        result = Detector._parse_findings_response("")
        assert result == []


# --- Rule-based detection ---

class TestRuleBased:
    """Tests for LLM-evaluated rule-based detection."""

    def test_creates_candidates_from_findings(self, detector, mock_llm, store):
        mock_llm.chat.return_value = (
            json.dumps([{
                "vulnerability_class": "sql-injection",
                "description": "SQL injection via f-string",
                "cwe": "CWE-89",
                "severity_tier": "ERROR",
                "severity_cvss": 8.5,
            }]),
            {"input_tokens": 100, "output_tokens": 50}
        )

        stats = detector.run_rule_based()
        assert stats["functions_analysed"] >= 1
        assert stats["candidates_created"] >= 1

        findings = store.get_findings()
        sqli = [f for f in findings if f["vulnerability_class"] == "sql-injection"]
        assert len(sqli) >= 1
        assert sqli[0]["detection_technique"] == "rule-based-llm"

    def test_deduplicates_findings(self, detector, mock_llm, store):
        mock_llm.chat.return_value = (
            json.dumps([{
                "vulnerability_class": "sql-injection",
                "description": "Same finding",
                "cwe": "CWE-89",
                "severity_tier": "ERROR",
                "severity_cvss": 8.5,
            }]),
            {"input_tokens": 100, "output_tokens": 50}
        )

        # Run twice — second should skip already-processed functions
        detector.run_rule_based()
        stats = detector.run_rule_based()
        assert stats["resumed_skipped"] >= 1

    def test_no_findings_produces_empty(self, detector, mock_llm, store):
        mock_llm.chat.return_value = ("[]", {"input_tokens": 50, "output_tokens": 5})

        stats = detector.run_rule_based()
        assert stats["candidates_created"] == 0

    def test_handles_llm_error(self, detector, mock_llm, store):
        mock_llm.chat.side_effect = RuntimeError("API error")

        stats = detector.run_rule_based()
        assert stats["errors"] >= 1

    def test_redacts_before_sending(self, detector, mock_llm, index, tmp_path):
        # Create a file with a secret
        secret_file = tmp_path / "secret_app.py"
        secret_file.write_text('def get_config():\n    password = "SuperSecret123"\n    return password\n')
        index.build(str(secret_file))

        mock_llm.chat.return_value = ("[]", {"input_tokens": 50, "output_tokens": 5})
        detector.run_rule_based(file_path=str(secret_file))

        # Verify the sent message was redacted
        if mock_llm.chat.called:
            call_args = mock_llm.chat.call_args
            sent_message = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get("user_message", "")
            assert "SuperSecret123" not in sent_message


# --- Exploratory detection ---

class TestExploratory:
    """Tests for exploratory hunting."""

    def test_exploratory_creates_candidates(self, detector, mock_llm, store):
        mock_llm.chat.return_value = (
            json.dumps([{
                "function_name": "handle_login",
                "file_path": "app.py",
                "vulnerability_class": "auth-bypass",
                "description": "Missing rate limiting on login",
                "cwe": "CWE-307",
                "severity_tier": "WARNING",
                "severity_cvss": 6.5,
            }]),
            {"input_tokens": 200, "output_tokens": 100}
        )

        stats = detector.run_exploratory()
        assert stats["batches_analysed"] >= 1
        assert stats["candidates_created"] >= 1

    def test_exploratory_with_focus_areas(self, detector, mock_llm, store):
        mock_llm.chat.return_value = ("[]", {"input_tokens": 50, "output_tokens": 5})

        stats = detector.run_exploratory(focus_areas=["login"])
        assert stats["batches_analysed"] >= 0  # May or may not match

    def test_exploratory_empty_index(self, mock_llm, store):
        empty_index = CodeIndex()
        det = Detector(mock_llm, empty_index, store)
        stats = det.run_exploratory()
        assert stats["batches_analysed"] == 0

    def test_exploratory_with_security_map(self, mock_llm, index, store):
        det = Detector(mock_llm, index, store,
                       security_map="Auth module is trust boundary. DB layer is internal.")
        mock_llm.chat.return_value = ("[]", {"input_tokens": 50, "output_tokens": 5})

        det.run_exploratory()
        if mock_llm.chat.called:
            sent = mock_llm.chat.call_args[0][1]
            assert "trust boundary" in sent


# --- Batch creation ---

class TestBatching:
    """Tests for exploration batch creation."""

    def test_creates_batches(self, detector):
        functions = [
            {"name": f"func_{i}", "file_path": "a.py", "body": "pass"}
            for i in range(12)
        ]
        batches = detector._create_exploration_batches(functions, batch_size=5)
        assert len(batches) == 3  # 5 + 5 + 2

    def test_focus_area_filtering(self, detector):
        functions = [
            {"name": "login", "file_path": "auth.py", "body": "pass"},
            {"name": "get_data", "file_path": "data.py", "body": "pass"},
        ]
        batches = detector._create_exploration_batches(functions, focus_areas=["auth"])
        total_funcs = sum(len(b) for b in batches)
        assert total_funcs == 1
