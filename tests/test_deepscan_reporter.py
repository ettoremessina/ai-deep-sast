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

"""Tests for the deep scan report generator."""

import json
import os

import pytest

from finding_store import FindingStore, Verdict
from deepscan_reporter import DeepScanReporter


@pytest.fixture
def store(tmp_path):
    return FindingStore(db_path=str(tmp_path / "test.db"))


@pytest.fixture
def reporter(store, tmp_path):
    output_dir = str(tmp_path / "reports")
    return DeepScanReporter(
        store, output_dir=output_dir,
        repo_url="https://github.com/cisco-open/ai-deep-sast",
        commit_sha="abc123def456",
    )


def _add_published_finding(store, vuln_class="sql-injection", severity="ERROR",
                           cvss=8.5, cwe="CWE-89"):
    """Add a finding and push it through to published state."""
    fid = store.add_finding(
        file_path="src/app.py",
        vulnerability_class=vuln_class,
        description=f"Test {vuln_class} finding",
        function_name="handle_request",
        severity_tier=severity,
        severity_cvss=cvss,
        cwe=cwe,
        detection_technique="exploratory",
    )
    store.set_verdict(
        fid, Verdict.TRUE_POSITIVE,
        evidence_report=f"Confirmed {vuln_class}. Unsanitised input reaches dangerous sink."
    )
    store.publish_finding(fid)
    return fid


class TestMarkdownReport:
    """Tests for Markdown report generation."""

    def test_generates_report_file(self, reporter, store):
        _add_published_finding(store)
        path = reporter.generate_report()
        assert os.path.exists(path)
        assert path.endswith(".md")

    def test_report_contains_findings(self, reporter, store):
        _add_published_finding(store, "sql-injection")
        path = reporter.generate_report()
        with open(path) as f:
            content = f.read()
        assert "sql-injection" in content
        assert "CWE-89" in content
        assert "ERROR" in content

    def test_report_header(self, reporter, store):
        _add_published_finding(store)
        path = reporter.generate_report()
        with open(path) as f:
            content = f.read()
        assert "AI Deep SAST" in content
        assert "abc123def456" in content
        assert "Opus 4" in content

    def test_report_summary_table(self, reporter, store):
        _add_published_finding(store, "sqli")
        _add_published_finding(store, "xss", "WARNING", 6.0, "CWE-79")
        path = reporter.generate_report()
        with open(path) as f:
            content = f.read()
        assert "True positives (published)" in content
        assert "2" in content

    def test_empty_report(self, reporter, store):
        path = reporter.generate_report()
        with open(path) as f:
            content = f.read()
        assert "No confirmed vulnerabilities" in content

    def test_needs_review_hidden_by_default(self, reporter, store):
        fid = store.add_finding("a.py", "maybe-vuln", "test")
        store.set_verdict(fid, Verdict.NEEDS_REVIEW)

        path = reporter.generate_report(show_needs_review=False)
        with open(path) as f:
            content = f.read()
        assert "Needs Review" not in content

    def test_needs_review_shown_when_enabled(self, reporter, store):
        fid = store.add_finding("a.py", "maybe-vuln", "test")
        store.set_verdict(fid, Verdict.NEEDS_REVIEW)

        path = reporter.generate_report(show_needs_review=True)
        with open(path) as f:
            content = f.read()
        assert "Needs Review" in content
        assert "maybe-vuln" in content

    def test_permalink_in_report(self, reporter, store):
        _add_published_finding(store)
        path = reporter.generate_report()
        with open(path) as f:
            content = f.read()
        assert "github.com/cisco-open/ai-deep-sast" in content
        assert "abc123def456" in content

    def test_severity_breakdown(self, reporter, store):
        _add_published_finding(store, "sqli", "ERROR", 9.0)
        _add_published_finding(store, "xss", "WARNING", 5.0, "CWE-79")
        path = reporter.generate_report()
        with open(path) as f:
            content = f.read()
        assert "Severity Breakdown" in content


class TestJsonReport:
    """Tests for JSON report generation."""

    def test_generates_json_file(self, reporter, store):
        _add_published_finding(store)
        path = reporter.generate_json_report()
        assert os.path.exists(path)
        assert path.endswith(".json")

    def test_json_structure(self, reporter, store):
        _add_published_finding(store, "sqli")
        path = reporter.generate_json_report()
        with open(path) as f:
            data = json.load(f)
        assert "generated_at" in data
        assert "summary" in data
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_json_empty_report(self, reporter, store):
        path = reporter.generate_json_report()
        with open(path) as f:
            data = json.load(f)
        assert data["findings"] == []


class TestPermalinks:
    """Tests for commit-pinned permalink construction."""

    def test_permalink_format(self, reporter):
        finding = {"file_path": "src/app.py"}
        link = reporter._build_permalink(finding)
        assert link == "https://github.com/cisco-open/ai-deep-sast/blob/abc123def456/src/app.py"

    def test_permalink_no_repo_url(self, store, tmp_path):
        r = DeepScanReporter(store, str(tmp_path / "r"))
        link = r._build_permalink({"file_path": "app.py"})
        assert link is None

    def test_permalink_no_commit(self, store, tmp_path):
        r = DeepScanReporter(store, str(tmp_path / "r"),
                            repo_url="https://github.com/test")
        link = r._build_permalink({"file_path": "app.py"})
        assert link is None
