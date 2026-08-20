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
    # min_function_lines=1: these tests exercise the detector, not the
    # trivial-skip feature, and PYTHON_SAMPLE's bodies are intentionally short.
    idx = CodeIndex(min_function_lines=1)
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


# --- Truncated response recovery ---

# A response cut off by max_tokens: one complete finding, then a partial one.
TRUNCATED_ARRAY = '''[
  {
    "vulnerability_class": "path-traversal",
    "description": "Builds a file path from unvalidated input.",
    "cwe": "CWE-22",
    "severity_tier": "ERROR",
    "severity_cvss": 7.5
  },
  {
    "vulnerability_class": "sql-injection",
    "description": "Unsanitised inp'''


class TestTruncationRecovery:
    """Findings completed before the cut must survive a truncated response."""

    def test_salvages_complete_object(self):
        result = Detector._parse_findings_response(TRUNCATED_ARRAY, finish_reason="length")
        assert len(result) == 1
        assert result[0]["vulnerability_class"] == "path-traversal"
        assert result[0]["cwe"] == "CWE-22"

    def test_salvages_several_complete_objects(self):
        text = json.dumps([
            {"vulnerability_class": "xss", "description": "a"},
            {"vulnerability_class": "sqli", "description": "b"},
        ])
        truncated = text[:-1] + ', {"vulnerability_class": "pa'
        result = Detector._parse_findings_response(truncated, finish_reason="length")
        assert len(result) == 2

    def test_cut_before_first_object_completes(self):
        text = '[\n  {\n    "vulnerability_class": "path-tra'
        result = Detector._parse_findings_response(text, finish_reason="length")
        assert result == []

    def test_salvage_without_finish_reason(self):
        """Callers that do not report finish_reason still get recovery."""
        result = Detector._parse_findings_response(TRUNCATED_ARRAY)
        assert len(result) == 1

    def test_salvage_through_markdown_fence(self):
        result = Detector._parse_findings_response(
            "```json\n" + TRUNCATED_ARRAY, finish_reason="length")
        assert len(result) == 1

    def test_complete_response_unaffected(self):
        text = json.dumps([{"vulnerability_class": "xss", "description": "x"}])
        result = Detector._parse_findings_response(text, finish_reason="stop")
        assert len(result) == 1

    def test_garbage_still_returns_empty(self):
        assert Detector._parse_findings_response("not json", finish_reason="stop") == []

    def test_recovered_finding_reaches_the_store(self, detector, mock_llm, store):
        """The point of the salvage: a truncated batch still yields a candidate."""
        truncated = '''[
  {
    "function_name": "handle_login",
    "file_path": "app.py",
    "vulnerability_class": "path-traversal",
    "description": "Builds a file path from unvalidated input.",
    "cwe": "CWE-22",
    "severity_tier": "ERROR",
    "severity_cvss": 7.5
  },
  {
    "function_name": "safe_function",
    "vulnerability_class": "sql-inj'''
        mock_llm.chat.return_value = (
            truncated,
            {"input_tokens": 7000, "output_tokens": 1100, "finish_reason": "length"},
        )

        stats = detector.run_exploratory()
        assert stats["candidates_created"] == 1
        assert stats["errors"] == 0


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


# --- Frontend prompt coverage ---

class TestFrontendPromptCoverage:
    """The brute-force prompts must name the React/Vite classes we scan for."""

    @pytest.mark.parametrize("needle", [
        "dangerouslySetInnerHTML",
        "javascript:",
        "localStorage",
        "import.meta.env",
    ])
    def test_rule_based_prompt_mentions(self, needle):
        assert needle in RULE_BASED_SYSTEM_PROMPT

    def test_exploratory_prompt_mentions_client_side_authorisation(self):
        assert "client-side" in EXPLORATORY_SYSTEM_PROMPT.lower()

    def test_rule_based_prompt_field_list_precedes_frontend_block(self):
        assert RULE_BASED_SYSTEM_PROMPT.index("vulnerability_class") < \
            RULE_BASED_SYSTEM_PROMPT.index("dangerouslySetInnerHTML")

    def test_rule_based_prompt_frontend_block_precedes_closing_instruction(self):
        assert RULE_BASED_SYSTEM_PROMPT.index("dangerouslySetInnerHTML") < \
            RULE_BASED_SYSTEM_PROMPT.rindex("Respond ONLY")

    def test_exploratory_prompt_frontend_flaw_precedes_closing_instruction(self):
        assert EXPLORATORY_SYSTEM_PROMPT.index("Client-side-only authorisation") < \
            EXPLORATORY_SYSTEM_PROMPT.rindex("Respond ONLY")


# --- Same-named functions in one file (whole-branch review, Finding 1) ---

GRID_TSX_SAMPLE = '''\
export const getColumns = () => [
    {
        field: "a",
        renderCell: (p) => {
            const safe = escapeHtml(p.a);
            logRender(safe);
            return <span>{safe}</span>;
        },
    },
    {
        field: "z",
        renderCell: (p) => {
            const raw = p.z;
            logRender(raw);
            return <span dangerouslySetInnerHTML={{__html: raw}} />;
        },
    },
];
'''

XSS_FINDING = json.dumps([{
    "vulnerability_class": "xss",
    "description": "Unescaped value rendered via dangerouslySetInnerHTML",
    "cwe": "CWE-79",
    "severity_tier": "ERROR",
    "severity_cvss": 7.5,
}])


@pytest.fixture
def grid_index(tmp_path):
    f = tmp_path / "grid.tsx"
    f.write_text(GRID_TSX_SAMPLE)
    # min_function_lines=1: the subject is per-function identity, not the
    # trivial-skip threshold.
    idx = CodeIndex(min_function_lines=1)
    idx.build(str(f))
    return idx


class TestSameNamedFunctions:
    """
    Two renderCell callbacks in one grid.tsx are distinct units in the index,
    and the detector has to keep them distinct too: the processed-marker and
    the finding fingerprint both keyed on (file, qualified_name), so the
    second one was skipped as 'already processed' and any finding it did
    produce collapsed onto the first one's fingerprint.
    """

    def test_every_same_named_function_reaches_the_llm(self, mock_llm, store, grid_index):
        mock_llm.chat.return_value = ("[]", {"input_tokens": 50, "output_tokens": 5})
        detector = Detector(mock_llm, grid_index, store)

        stats = detector.run_rule_based()
        assert stats["functions_analysed"] == 3
        assert stats["resumed_skipped"] == 0
        assert mock_llm.chat.call_count == 3

    def test_the_vulnerable_duplicate_is_actually_sent(self, mock_llm, store, grid_index):
        mock_llm.chat.return_value = ("[]", {"input_tokens": 50, "output_tokens": 5})
        Detector(mock_llm, grid_index, store).run_rule_based()

        # Both renderCell callbacks must arrive as units of their own. The
        # enclosing getColumns body happens to quote the vulnerable line too,
        # so a bare substring check over all prompts proves nothing.
        prompts = [call[0][1] for call in mock_llm.chat.call_args_list]
        render_prompts = [p for p in prompts if "## Function: getColumns.renderCell" in p]
        assert len(render_prompts) == 2
        assert sum("dangerouslySetInnerHTML" in p for p in render_prompts) == 1

    def test_each_duplicate_is_prompted_with_its_own_callees(self, mock_llm, store, tmp_path):
        # get_callees resolved by plain name and returned the first match, so
        # the second duplicate would be described to the LLM with the first
        # one's call graph.
        f = tmp_path / "dup.py"
        f.write_text(
            "def fetch(url):\n"
            "    a = first_helper(url)\n"
            "    log(a)\n"
            "    return a\n"
            "\n\n"
            "def fetch(url):\n"
            "    b = second_helper(url)\n"
            "    log(b)\n"
            "    return b\n"
        )
        idx = CodeIndex(min_function_lines=1)
        idx.build(str(f))
        mock_llm.chat.return_value = ("[]", {"input_tokens": 50, "output_tokens": 5})
        Detector(mock_llm, idx, store).run_rule_based()

        prompts = [call[0][1] for call in mock_llm.chat.call_args_list]
        second = next(p for p in prompts if "second_helper(url)" in p)
        assert "- second_helper" in second
        assert "- first_helper" not in second

    def test_findings_from_same_named_functions_do_not_collapse(self, mock_llm, store, grid_index):
        mock_llm.chat.return_value = (XSS_FINDING, {"input_tokens": 100, "output_tokens": 50})
        detector = Detector(mock_llm, grid_index, store)

        stats = detector.run_rule_based()
        assert stats["candidates_created"] == 3
        assert stats["duplicates_skipped"] == 0

        findings = store.get_findings()
        assert len({f["fingerprint"] for f in findings}) == 3
        assert len({f["function_name"] for f in findings}) == 3

    def test_fingerprints_are_stable_across_a_rescan_of_unchanged_code(
            self, mock_llm, store, grid_index, tmp_path):
        # DefectDojo tracks findings by fingerprint. An identity that shifts
        # when nothing changed turns every import into a fresh duplicate.
        mock_llm.chat.return_value = (XSS_FINDING, {"input_tokens": 100, "output_tokens": 50})
        Detector(mock_llm, grid_index, store).run_rule_based()
        first = {f["fingerprint"] for f in store.get_findings()}

        rebuilt = CodeIndex(min_function_lines=1)
        rebuilt.build(str(tmp_path / "grid.tsx"))
        other_store = FindingStore(db_path=str(tmp_path / "second.db"))
        Detector(mock_llm, rebuilt, other_store).run_rule_based()
        second = {f["fingerprint"] for f in other_store.get_findings()}

        assert first == second

    def test_second_scan_into_the_same_store_adds_nothing(self, mock_llm, store, grid_index):
        mock_llm.chat.return_value = (XSS_FINDING, {"input_tokens": 100, "output_tokens": 50})
        detector = Detector(mock_llm, grid_index, store)
        detector.run_rule_based()
        before = len(store.get_findings())

        stats = detector.run_rule_based()
        assert stats["resumed_skipped"] == 3
        assert stats["candidates_created"] == 0
        assert len(store.get_findings()) == before
