#!/usr/bin/env python3
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
"""
Semgrep Rule Tests for Custom Secret Detection
================================================
Runs Semgrep with custom-secrets.yaml against test fixtures and
verifies expected detection counts and false-positive exclusions.

Run with: python -m pytest tests/test_rules.py -v
"""

import json
import os
import subprocess
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_FILE = os.path.join(REPO_ROOT, "config", "custom-secrets.yaml")
ZIPSLIP_RULES_FILE = os.path.join(REPO_ROOT, "config", "custom-zipslip.yaml")
FIXTURES_DIR = os.path.join(REPO_ROOT, "tests", "fixtures")


def run_semgrep(target_file):
    """Run Semgrep against a single fixture file and return findings."""
    result = subprocess.run(
        [
            "semgrep",
            "--config", RULES_FILE,
            "--json",
            "--no-git-ignore",
            target_file,
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    data = json.loads(result.stdout)
    return data.get("results", [])


def findings_by_rule(results):
    """Group findings by rule_id."""
    grouped = {}
    for r in results:
        rule = r["check_id"]
        grouped.setdefault(rule, []).append(r)
    return grouped


# ============================================================
# .properties file tests
# ============================================================
class TestPropertiesRules:
    """Tests for config file rules against .properties fixtures."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.results = run_semgrep(
            os.path.join(FIXTURES_DIR, "test-secrets.properties")
        )
        self.by_rule = findings_by_rule(self.results)

    def test_detects_hardcoded_passwords(self):
        """Should detect hardcoded password values."""
        rule = "config.hardcoded-password-properties"
        assert rule in self.by_rule
        # db.password, spring.datasource.password, ci.serviceAccountAdminPassword, pinot.password
        assert len(self.by_rule[rule]) >= 4

    def test_detects_redis_password(self):
        """Should detect hardcoded Redis password."""
        rule = "config.hardcoded-redis-password"
        assert rule in self.by_rule
        assert len(self.by_rule[rule]) >= 1

    def test_detects_api_keys(self):
        """Should detect hardcoded API keys/tokens."""
        rule = "config.hardcoded-api-key-properties"
        assert rule in self.by_rule
        assert len(self.by_rule[rule]) >= 1

    def test_skips_spring_boot_placeholders(self):
        """Should NOT flag ${VAR} placeholders."""
        for r in self.results:
            line = r.get("extra", {}).get("lines", "")
            assert "${DB_PASSWORD}" not in line or r["check_id"] != "config.hardcoded-password-properties"
            assert "${REDIS_PASSWORD}" not in line or r["check_id"] != "config.hardcoded-password-properties"

    def test_skips_helm_templates(self):
        """Should NOT flag {{ }} templates."""
        for r in self.results:
            line = r.get("extra", {}).get("lines", "")
            assert "{{vault" not in line
            assert "{{ .Values" not in line

    def test_skips_comments(self):
        """Should NOT flag commented-out lines."""
        for r in self.results:
            line = r.get("extra", {}).get("lines", "").strip()
            assert not line.startswith("#")


# ============================================================
# .yaml file tests
# ============================================================
class TestYamlRules:
    """Tests for config file rules against .yaml fixtures."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.results = run_semgrep(
            os.path.join(FIXTURES_DIR, "test-secrets.yaml")
        )
        self.by_rule = findings_by_rule(self.results)

    def test_detects_hardcoded_passwords_in_yaml(self):
        """Should detect hardcoded password values in YAML."""
        rule = "config.hardcoded-password-properties"
        assert rule in self.by_rule
        assert len(self.by_rule[rule]) >= 2

    def test_detects_api_keys_in_yaml(self):
        """Should detect hardcoded API keys in YAML."""
        rule = "config.hardcoded-api-key-properties"
        assert rule in self.by_rule
        assert len(self.by_rule[rule]) >= 1

    def test_skips_placeholders_in_yaml(self):
        """Should NOT flag ${VAR} placeholders in YAML."""
        for r in self.results:
            line = r.get("extra", {}).get("lines", "")
            assert "${DB_PASSWORD}" not in line
            assert "${REDIS_PASSWORD}" not in line

    def test_skips_helm_templates_in_yaml(self):
        """Should NOT flag {{ }} templates in YAML."""
        for r in self.results:
            line = r.get("extra", {}).get("lines", "")
            assert "{{ .Values" not in line
            assert "{{vault" not in line

    def test_skips_comments_in_yaml(self):
        """Should NOT flag commented-out lines in YAML."""
        for r in self.results:
            line = r.get("extra", {}).get("lines", "").strip()
            assert not line.startswith("#")


# ============================================================
# .env file tests
# ============================================================
class TestEnvRules:
    """Tests for config file rules against .env fixtures."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.results = run_semgrep(
            os.path.join(FIXTURES_DIR, "test-secrets.env")
        )
        self.by_rule = findings_by_rule(self.results)

    def test_detects_hardcoded_passwords_in_env(self):
        """Should detect hardcoded passwords in .env files."""
        rule = "config.hardcoded-password-properties"
        assert rule in self.by_rule
        assert len(self.by_rule[rule]) >= 2

    def test_skips_variable_references_in_env(self):
        """Should NOT flag ${VAR} references in .env files."""
        for r in self.results:
            line = r.get("extra", {}).get("lines", "")
            assert "${DB_PASSWORD}" not in line
            assert "${REDIS_PASSWORD}" not in line

    def test_skips_comments_in_env(self):
        """Should NOT flag commented-out lines in .env files."""
        for r in self.results:
            line = r.get("extra", {}).get("lines", "").strip()
            assert not line.startswith("#")


# ============================================================
# Java source code tests
# ============================================================
class TestJavaRules:
    """Tests for source code rules against Java fixtures."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.results = run_semgrep(
            os.path.join(FIXTURES_DIR, "TestSecrets.java")
        )
        self.by_rule = findings_by_rule(self.results)

    def test_detects_hardcoded_java_secrets(self):
        """Should detect hardcoded credential assignments in Java."""
        rule = "config.hardcoded-secret-java"
        assert rule in self.by_rule
        assert len(self.by_rule[rule]) >= 3

    def test_skips_short_values(self):
        """Should NOT flag values shorter than 4 characters."""
        rule = "config.hardcoded-secret-java"
        for r in self.by_rule.get(rule, []):
            matched = r.get("extra", {}).get("metavars", {}).get("$VALUE", {}).get("abstract_content", "")
            if matched:
                assert len(matched) >= 4

    def test_skips_file_paths(self):
        """Should NOT flag values that are file paths."""
        rule = "config.hardcoded-secret-java"
        for r in self.by_rule.get(rule, []):
            line = r.get("extra", {}).get("lines", "")
            assert ".txt" not in line or "PASSWORD_FILE" not in line
            assert ".yaml" not in line or "SECRET_CONFIG" not in line


# ============================================================
# Python source code tests
# ============================================================
class TestPythonRules:
    """Tests for source code rules against Python fixtures."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.results = run_semgrep(
            os.path.join(FIXTURES_DIR, "test_secrets.py")
        )
        self.by_rule = findings_by_rule(self.results)

    def test_detects_hardcoded_python_secrets(self):
        """Should detect hardcoded credential assignments in Python."""
        rule = "config.hardcoded-secret-python"
        assert rule in self.by_rule
        assert len(self.by_rule[rule]) >= 3

    def test_skips_short_values(self):
        """Should NOT flag values shorter than 4 characters."""
        rule = "config.hardcoded-secret-python"
        for r in self.by_rule.get(rule, []):
            matched = r.get("extra", {}).get("metavars", {}).get("$VALUE", {}).get("abstract_content", "")
            if matched:
                assert len(matched) >= 4

    def test_skips_file_paths(self):
        """Should NOT flag values that are file paths."""
        rule = "config.hardcoded-secret-python"
        for r in self.by_rule.get(rule, []):
            line = r.get("extra", {}).get("lines", "")
            assert ".txt" not in line or "PASSWORD_FILE" not in line
            assert ".yaml" not in line or "SECRET_CONFIG" not in line


def run_semgrep_zipslip(target_file):
    """Run Semgrep with Zip Slip rules against a single fixture file."""
    result = subprocess.run(
        [
            "semgrep",
            "--config", ZIPSLIP_RULES_FILE,
            "--json",
            "--no-git-ignore",
            target_file,
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    data = json.loads(result.stdout)
    return data.get("results", [])


# ============================================================
# Java Zip Slip tests
# ============================================================
class TestJavaZipSlip:
    """Tests for Zip Slip taint rules against Java fixtures."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.results = run_semgrep_zipslip(
            os.path.join(FIXTURES_DIR, "TestZipSlip.java")
        )
        self.by_rule = findings_by_rule(self.results)

    def test_detects_vulnerable_file_output(self):
        """Should detect ZipEntry.getName() flowing into FileOutputStream."""
        rule = "config.zipslip-java"
        assert rule in self.by_rule
        lines = [r["start"]["line"] for r in self.by_rule[rule]]
        assert 41 in lines

    def test_detects_vulnerable_paths_get(self):
        """Should detect ZipEntry.getName() flowing into Paths.get()."""
        rule = "config.zipslip-java"
        lines = [r["start"]["line"] for r in self.by_rule[rule]]
        assert 58 in lines

    def test_no_false_positive_on_sanitized(self):
        """Should NOT flag extractSafe() which uses getCanonicalPath()."""
        rule = "config.zipslip-java"
        lines = [r["start"]["line"] for r in self.by_rule.get(rule, [])]
        # Lines 64-78 are the safe function — no findings there
        safe_lines = set(range(64, 79))
        assert not safe_lines.intersection(lines)

    def test_finding_count(self):
        """Should find exactly 2 vulnerable patterns."""
        rule = "config.zipslip-java"
        assert len(self.by_rule.get(rule, [])) == 2


# ============================================================
# Python Zip Slip tests
# ============================================================
class TestPythonZipSlip:
    """Tests for Zip Slip taint rules against Python fixtures."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.results = run_semgrep_zipslip(
            os.path.join(FIXTURES_DIR, "test_zipslip.py")
        )
        self.by_rule = findings_by_rule(self.results)

    def test_detects_vulnerable_zip_extract(self):
        """Should detect zipinfo.filename flowing into open()."""
        rule = "config.zipslip-python"
        assert rule in self.by_rule
        lines = [r["start"]["line"] for r in self.by_rule[rule]]
        assert 30 in lines

    def test_detects_vulnerable_tar_extract(self):
        """Should detect tarinfo.name flowing into open()."""
        rule = "config.zipslip-python"
        lines = [r["start"]["line"] for r in self.by_rule[rule]]
        assert 39 in lines

    def test_no_false_positive_on_sanitized(self):
        """Should NOT flag extract_zip_safe() which uses os.path.realpath()."""
        rule = "config.zipslip-python"
        lines = [r["start"]["line"] for r in self.by_rule.get(rule, [])]
        # Lines 46-53 are the safe function — no findings there
        safe_lines = set(range(46, 54))
        assert not safe_lines.intersection(lines)

    def test_finding_count(self):
        """Should find exactly 2 vulnerable patterns."""
        rule = "config.zipslip-python"
        assert len(self.by_rule.get(rule, [])) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
