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

"""Tests for the deep scan triager (mocked LLM)."""

import json
from unittest.mock import MagicMock

import pytest

from finding_store import FindingStore, FindingState, Verdict
from indexer import CodeIndex
from triager import Triager


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
def triager(mock_llm, index, store):
    return Triager(mock_llm, index, store)


def _add_candidate(store, file_path="app.py", func_name="handle_login",
                   vuln_class="sql-injection"):
    """Helper to add a candidate finding."""
    return store.add_finding(
        file_path=file_path,
        vulnerability_class=vuln_class,
        description="Test finding",
        function_name=func_name,
        detection_technique="rule-based-llm",
        cwe="CWE-89",
        severity_tier="ERROR",
        severity_cvss=8.5,
    )


# --- Response parsing ---

class TestTriageResponseParsing:
    """Tests for parsing triage LLM responses."""

    def test_parse_true_positive(self):
        text = json.dumps({
            "verdict": "true-positive",
            "confidence": 0.95,
            "evidence_report": "SQL injection via unsanitised f-string. User input flows directly into query.",
            "severity_adjustment": {
                "severity_tier": "ERROR",
                "severity_cvss": 9.0,
                "reason": "Network accessible endpoint"
            }
        })
        verdict, evidence, severity, confidence = Triager._parse_triage_response(text)
        assert verdict == Verdict.TRUE_POSITIVE
        assert confidence == 0.95
        assert "unsanitised" in evidence

    def test_parse_false_positive(self):
        text = json.dumps({
            "verdict": "false-positive",
            "confidence": 0.90,
            "evidence_report": "Input is sanitised by middleware before reaching this function.",
        })
        verdict, evidence, _, confidence = Triager._parse_triage_response(text)
        assert verdict == Verdict.FALSE_POSITIVE

    def test_parse_needs_review(self):
        text = json.dumps({
            "verdict": "needs-review",
            "confidence": 0.40,
            "evidence_report": "Cannot determine if middleware sanitises input.",
        })
        verdict, _, _, confidence = Triager._parse_triage_response(text)
        assert verdict == Verdict.NEEDS_REVIEW
        assert confidence == 0.40

    def test_parse_markdown_wrapped(self):
        inner = json.dumps({"verdict": "false-positive", "confidence": 0.8, "evidence_report": "test"})
        text = f"```json\n{inner}\n```"
        verdict, _, _, _ = Triager._parse_triage_response(text)
        assert verdict == Verdict.FALSE_POSITIVE

    def test_parse_json_in_text(self):
        text = 'Analysis:\n{"verdict": "code-quality", "confidence": 0.7, "evidence_report": "Poor practice"}\nDone.'
        verdict, _, _, _ = Triager._parse_triage_response(text)
        assert verdict == Verdict.CODE_QUALITY

    def test_parse_invalid_json(self):
        verdict, evidence, _, _ = Triager._parse_triage_response("not json")
        assert verdict == Verdict.NEEDS_REVIEW
        assert "Parse error" in evidence

    def test_parse_unknown_verdict(self):
        text = json.dumps({"verdict": "unknown-value", "confidence": 0.5, "evidence_report": "test"})
        verdict, _, _, _ = Triager._parse_triage_response(text)
        assert verdict == Verdict.NEEDS_REVIEW


# --- Triage lifecycle ---

class TestTriageLifecycle:
    """Tests for the full triage workflow."""

    def test_true_positive_gets_confirmed_and_published(self, triager, mock_llm, store):
        fid = _add_candidate(store)
        mock_llm.chat.return_value = (
            json.dumps({
                "verdict": "true-positive",
                "confidence": 0.95,
                "evidence_report": "SQL injection confirmed. Unsanitised user input in f-string query.",
            }),
            {"input_tokens": 200, "output_tokens": 100}
        )

        stats = triager.triage_all_candidates()
        assert stats["true_positive"] == 1

        finding = store.get_finding(fid)
        assert finding["verdict"] == Verdict.TRUE_POSITIVE.value
        assert finding["state"] == FindingState.PUBLISHED.value

    def test_false_positive_stays_candidate(self, triager, mock_llm, store):
        fid = _add_candidate(store)
        mock_llm.chat.return_value = (
            json.dumps({
                "verdict": "false-positive",
                "confidence": 0.90,
                "evidence_report": "Sanitised by middleware.",
            }),
            {"input_tokens": 200, "output_tokens": 100}
        )

        triager.triage_all_candidates()
        finding = store.get_finding(fid)
        assert finding["verdict"] == Verdict.FALSE_POSITIVE.value
        assert finding["state"] == FindingState.CANDIDATE.value

    def test_needs_review_escalates_on_low_confidence(self, triager, mock_llm, store):
        _add_candidate(store)

        # First call returns low-confidence needs-review, second returns a verdict
        mock_llm.chat.side_effect = [
            (json.dumps({
                "verdict": "needs-review",
                "confidence": 0.30,
                "evidence_report": "Inconclusive.",
            }), {"input_tokens": 200, "output_tokens": 100}),
            (json.dumps({
                "verdict": "false-positive",
                "confidence": 0.85,
                "evidence_report": "After deeper investigation: sanitised by ORM.",
            }), {"input_tokens": 300, "output_tokens": 150}),
        ]

        stats = triager.triage_all_candidates()
        assert stats["false_positive"] == 1

    def test_needs_review_no_escalation_high_confidence(self, triager, mock_llm, store):
        _add_candidate(store)
        mock_llm.chat.return_value = (
            json.dumps({
                "verdict": "needs-review",
                "confidence": 0.70,
                "evidence_report": "Cannot fully confirm but likely real.",
            }),
            {"input_tokens": 200, "output_tokens": 100}
        )

        stats = triager.triage_all_candidates()
        assert stats["needs_review"] == 1
        assert mock_llm.chat.call_count == 1  # No escalation

    def test_skips_already_verdicted(self, triager, mock_llm, store):
        fid = _add_candidate(store)
        store.set_verdict(fid, Verdict.FALSE_POSITIVE)

        mock_llm.chat.return_value = ("[]", {"input_tokens": 10, "output_tokens": 5})
        stats = triager.triage_all_candidates()
        assert stats["triaged"] == 0
        assert mock_llm.chat.call_count == 0

    def test_multiple_candidates(self, triager, mock_llm, store):
        _add_candidate(store, func_name="handle_login", vuln_class="sql-injection")
        _add_candidate(store, func_name="safe_function", vuln_class="xss")

        mock_llm.chat.return_value = (
            json.dumps({
                "verdict": "false-positive",
                "confidence": 0.90,
                "evidence_report": "Not exploitable.",
            }),
            {"input_tokens": 100, "output_tokens": 50}
        )

        stats = triager.triage_all_candidates()
        assert stats["triaged"] == 2

    def test_handles_llm_error(self, triager, mock_llm, store):
        _add_candidate(store)
        mock_llm.chat.side_effect = RuntimeError("API error")

        stats = triager.triage_all_candidates()
        assert stats["errors"] == 1
        assert stats["triaged"] == 0


# --- Single finding triage ---

class TestSingleFindingTriage:
    """Tests for triaging individual findings."""

    def test_triage_by_id(self, triager, mock_llm, store):
        fid = _add_candidate(store)
        mock_llm.chat.return_value = (
            json.dumps({
                "verdict": "true-positive",
                "confidence": 0.90,
                "evidence_report": "Confirmed SQL injection.",
            }),
            {"input_tokens": 200, "output_tokens": 100}
        )

        result = triager.triage_finding_by_id(fid)
        assert result is not None
        assert result["verdict"] == "true-positive"

    def test_triage_nonexistent_finding(self, triager, mock_llm):
        result = triager.triage_finding_by_id("nonexistent")
        assert result is None


# --- Context building ---

class TestContextBuilding:
    """Tests for investigation context construction."""

    def test_context_includes_function_body(self, triager, index, tmp_path):
        # The index was built with app.py which has handle_login
        file_path = str(tmp_path / "app.py")
        finding = {
            "file_path": file_path,
            "function_name": "handle_login",
            "vulnerability_class": "sql-injection",
            "cwe": "CWE-89",
            "description": "SQL injection",
            "detection_technique": "rule-based-llm",
        }
        context = triager._build_investigation_context(finding)
        assert "handle_login" in context
        assert "sql-injection" in context

    def test_context_with_security_map(self, mock_llm, index, store):
        t = Triager(mock_llm, index, store,
                    security_map="Login endpoint is the trust boundary.")
        finding = {
            "file_path": "app.py",
            "function_name": "handle_login",
            "vulnerability_class": "sql-injection",
            "cwe": "CWE-89",
            "description": "test",
            "detection_technique": "rule-based-llm",
        }
        context = t._build_investigation_context(finding)
        assert "trust boundary" in context


# --- Duplicate function names (whole-branch review, Finding 2) ---

DUPLICATE_NAME_SAMPLE = '''\
def fetch(url):
    result = first_helper(url)
    log(result)
    return result


def fetch(url):
    result = second_helper(url)
    log(result)
    return result
'''


class TestDuplicateFunctionNames:
    """
    A finding reported against the second of two same-named functions must be
    investigated against that function's body. Resolving by plain name
    returned the first match, so the triager issued a verdict on code the
    detector never flagged.
    """

    @pytest.fixture
    def dup(self, tmp_path, mock_llm, store):
        f = tmp_path / "dup.py"
        f.write_text(DUPLICATE_NAME_SAMPLE)
        idx = CodeIndex(min_function_lines=1)
        idx.build(str(f))
        return Triager(mock_llm, idx, store), str(f)

    def test_context_uses_the_reported_duplicate_body(self, dup, store):
        triager, path = dup
        fid = _add_candidate(store, file_path=path, func_name="fetch#1")

        context = triager._build_investigation_context(store.get_finding(fid))
        assert "second_helper" in context
        assert "first_helper" not in context

    def test_plain_name_still_resolves_to_the_first(self, dup, store):
        triager, path = dup
        fid = _add_candidate(store, file_path=path, func_name="fetch")

        context = triager._build_investigation_context(store.get_finding(fid))
        assert "first_helper" in context
        assert "second_helper" not in context
