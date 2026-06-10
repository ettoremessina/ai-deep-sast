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

"""Tests for the redaction layer."""

import os
import tempfile

import pytest

from redactor import (
    REDACTED_PLACEHOLDER,
    RedactionResult,
    redact_file,
    redact_secrets_in_text,
    verify_no_secrets,
)


# --- Pattern-based redaction ---

class TestPatternRedaction:
    """Tests for regex-based secret redaction."""

    def test_redact_password_double_quotes(self):
        text = 'password = "SuperSecret123"'
        result = redact_secrets_in_text(text)
        assert REDACTED_PLACEHOLDER in result.redacted
        assert "SuperSecret123" not in result.redacted
        assert result.redaction_count == 1

    def test_redact_password_single_quotes(self):
        text = "password = 'SuperSecret123'"
        result = redact_secrets_in_text(text)
        assert REDACTED_PLACEHOLDER in result.redacted
        assert "SuperSecret123" not in result.redacted

    def test_redact_api_key(self):
        text = 'api_key = "sk-1234567890abcdef"'
        result = redact_secrets_in_text(text)
        assert REDACTED_PLACEHOLDER in result.redacted
        assert "sk-1234567890abcdef" not in result.redacted

    def test_redact_token(self):
        text = 'token = "ghp_xxxxxxxxxxxxxxxxxxxx"'
        result = redact_secrets_in_text(text)
        assert REDACTED_PLACEHOLDER in result.redacted

    def test_redact_secret_assignment(self):
        text = 'SECRET = "my_secret_value_here"'
        result = redact_secrets_in_text(text)
        assert REDACTED_PLACEHOLDER in result.redacted
        assert "my_secret_value_here" not in result.redacted

    def test_redact_credential(self):
        text = 'credential = "admin:p@ssw0rd"'
        result = redact_secrets_in_text(text)
        assert REDACTED_PLACEHOLDER in result.redacted

    def test_redact_properties_format(self):
        text = "password=MyP@ssword123"
        result = redact_secrets_in_text(text)
        assert REDACTED_PLACEHOLDER in result.redacted
        assert "MyP@ssword123" not in result.redacted

    def test_redact_colon_format(self):
        text = 'password: "secret_value"'
        result = redact_secrets_in_text(text)
        assert REDACTED_PLACEHOLDER in result.redacted

    def test_redact_jdbc_password(self):
        text = 'jdbc:mysql://host:3306/db?password=s3cret&user=admin'
        result = redact_secrets_in_text(text)
        assert REDACTED_PLACEHOLDER in result.redacted
        assert "s3cret" not in result.redacted

    def test_redact_private_key(self):
        text = 'private_key = "-----BEGIN RSA PRIVATE KEY-----"'
        result = redact_secrets_in_text(text)
        assert REDACTED_PLACEHOLDER in result.redacted

    def test_case_insensitive(self):
        text = 'PASSWORD = "CaseSensitiveSecret"'
        result = redact_secrets_in_text(text)
        assert REDACTED_PLACEHOLDER in result.redacted
        assert "CaseSensitiveSecret" not in result.redacted


# --- Skip patterns (false positives) ---

class TestSkipPatterns:
    """Tests for patterns that should NOT be redacted."""

    def test_skip_commented_line(self):
        text = '# password = "not_a_real_secret"'
        result = redact_secrets_in_text(text)
        assert result.redaction_count == 0

    def test_skip_spring_placeholder(self):
        text = 'password = "${DB_PASSWORD}"'
        result = redact_secrets_in_text(text)
        assert result.redaction_count == 0

    def test_skip_helm_template(self):
        text = 'password = "{{ .Values.dbPassword }}"'
        result = redact_secrets_in_text(text)
        assert result.redaction_count == 0

    def test_skip_already_redacted(self):
        text = f'password = "{REDACTED_PLACEHOLDER}"'
        result = redact_secrets_in_text(text)
        assert result.redaction_count == 0

    def test_skip_placeholder_values(self):
        text = 'password = "changeme"'
        result = redact_secrets_in_text(text)
        assert result.redaction_count == 0

    def test_skip_todo_placeholder(self):
        text = 'password = "TODO"'
        result = redact_secrets_in_text(text)
        assert result.redaction_count == 0


# --- Preserve non-secret code ---

class TestPreserveCode:
    """Tests that non-secret code is preserved."""

    def test_preserve_normal_code(self):
        text = 'def handle_login(username, password):\n    return authenticate(username, password)'
        result = redact_secrets_in_text(text)
        assert result.redacted == text
        assert result.redaction_count == 0

    def test_preserve_variable_names(self):
        text = 'password_field = form.get("password")\nvalidate_password(password_field)'
        result = redact_secrets_in_text(text)
        assert result.redaction_count == 0

    def test_preserve_imports(self):
        text = 'from django.contrib.auth import authenticate'
        result = redact_secrets_in_text(text)
        assert result.redacted == text

    def test_preserve_empty_text(self):
        result = redact_secrets_in_text("")
        assert result.redacted == ""
        assert result.redaction_count == 0

    def test_preserve_whitespace_only(self):
        result = redact_secrets_in_text("   \n\n   ")
        assert result.redaction_count == 0


# --- Multi-line redaction ---

class TestMultiLine:
    """Tests for multi-line content redaction."""

    def test_redact_multiple_secrets(self):
        text = (
            'db_password = "secret1"\n'
            'api_key = "key123"\n'
            'normal_var = 42\n'
            'token = "tok_abc"\n'
        )
        result = redact_secrets_in_text(text)
        assert result.redaction_count == 3
        assert "secret1" not in result.redacted
        assert "key123" not in result.redacted
        assert "tok_abc" not in result.redacted
        assert "normal_var = 42" in result.redacted

    def test_mixed_secrets_and_code(self):
        text = (
            'import os\n'
            '\n'
            'class Config:\n'
            '    password = "hardcoded_pass"\n'
            '    host = "localhost"\n'
            '    port = 5432\n'
        )
        result = redact_secrets_in_text(text)
        assert "hardcoded_pass" not in result.redacted
        assert "localhost" in result.redacted
        assert "5432" in result.redacted
        assert "import os" in result.redacted


# --- Semgrep finding-based redaction ---

class TestFindingRedaction:
    """Tests for Semgrep finding-based redaction."""

    def test_redact_from_finding(self):
        text = 'line1\npassword = "secret_from_finding"\nline3'
        findings = [{
            "check_id": "custom.hardcoded-password",
            "path": "test.py",
            "start": {"line": 2, "col": 1},
            "end": {"line": 2, "col": 35},
        }]
        result = redact_secrets_in_text(text, findings)
        assert "secret_from_finding" not in result.redacted
        assert result.redaction_count >= 1

    def test_finding_out_of_range(self):
        text = 'only one line'
        findings = [{
            "check_id": "test",
            "path": "test.py",
            "start": {"line": 99, "col": 1},
            "end": {"line": 99, "col": 10},
        }]
        result = redact_secrets_in_text(text, findings)
        assert result.redacted == text


# --- File redaction ---

class TestFileRedaction:
    """Tests for file-based redaction."""

    def test_redact_file(self, tmp_path):
        file_path = str(tmp_path / "config.py")
        with open(file_path, "w") as f:
            f.write('password = "file_secret"\nhost = "localhost"\n')

        result = redact_file(file_path)
        assert "file_secret" not in result.redacted
        assert "localhost" in result.redacted
        assert result.redaction_count >= 1

    def test_redact_file_not_found(self):
        result = redact_file("/nonexistent/path.py")
        assert result.redacted == ""
        assert result.redaction_count == 0

    def test_file_not_modified(self, tmp_path):
        file_path = str(tmp_path / "config.py")
        original = 'password = "dont_touch_original"\n'
        with open(file_path, "w") as f:
            f.write(original)

        redact_file(file_path)

        with open(file_path, "r") as f:
            assert f.read() == original


# --- Pre-send verification ---

class TestVerification:
    """Tests for pre-send secret verification."""

    def test_verify_clean_text(self):
        text = f'password = "{REDACTED_PLACEHOLDER}"\nhost = "localhost"'
        assert verify_no_secrets(text) is True

    def test_verify_detects_known_secret(self):
        text = 'password = "MyActualSecret"'
        assert verify_no_secrets(text, known_secrets={"MyActualSecret"}) is False

    def test_verify_detects_pattern_secret(self):
        text = 'password = "unredacted_secret_value"'
        assert verify_no_secrets(text) is False

    def test_verify_empty_text(self):
        assert verify_no_secrets("") is True

    def test_verify_no_secrets_in_normal_code(self):
        text = 'def authenticate(user, password):\n    return check(user, password)'
        assert verify_no_secrets(text) is True


# --- RedactionResult ---

class TestRedactionResult:
    """Tests for RedactionResult dataclass."""

    def test_was_redacted_true(self):
        result = RedactionResult("orig", "redacted", 1, [{"line": 1}])
        assert result.was_redacted is True

    def test_was_redacted_false(self):
        result = RedactionResult("orig", "orig", 0, [])
        assert result.was_redacted is False

    def test_to_dict(self):
        result = RedactionResult("orig", "redacted", 2, [{"line": 1}, {"line": 3}])
        d = result.to_dict()
        assert d["redaction_count"] == 2
        assert d["was_redacted"] is True
        assert len(d["redacted_locations"]) == 2
