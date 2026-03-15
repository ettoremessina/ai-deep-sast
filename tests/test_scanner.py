#!/usr/bin/env python3
"""
Unit Tests for AI-Powered OWASP Scanner
========================================
Run with: python -m pytest tests/test_scanner.py -v
"""

import os
import sys
import json
import pytest
import tempfile

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiowaspscan import (
    merge_configuration,
    extract_code_snippet,
    build_prompt,
    generate_summary,
    evaluate_quality_gate,
    load_config,
    setup_logging
)


# ============================================================
# Test Configuration
# ============================================================
class TestConfiguration:
    """Tests for configuration management."""

    def test_load_config_valid(self, tmp_path):
        """Test loading a valid YAML config."""
        config_content = """
target: "./src"
model: "llama-3"
severity_threshold: "ERROR"
"""
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text(config_content)

        config = load_config(str(config_file))
        assert config['target'] == './src'
        assert config['model'] == 'llama-3'
        assert config['severity_threshold'] == 'ERROR'

    def test_load_config_missing_file(self):
        """Test loading a non-existent config file."""
        config = load_config('/nonexistent/path/config.yaml')
        assert config == {}

    def test_load_config_invalid_yaml(self, tmp_path):
        """Test loading an invalid YAML file."""
        config_file = tmp_path / "bad_config.yaml"
        config_file.write_text("invalid: yaml: content: [")

        config = load_config(str(config_file))
        # Should return empty dict on parse error
        assert isinstance(config, dict)


# ============================================================
# Test Code Snippet Extraction
# ============================================================
class TestCodeSnippetExtraction:
    """Tests for code snippet extraction."""

    def test_extract_snippet_basic(self, tmp_path):
        """Test basic snippet extraction."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n"
        )
        logger = setup_logging()
        snippet = extract_code_snippet(
            str(test_file), 4, 6, context_lines=1, logger=logger
        )
        assert "line4" in snippet
        assert "line5" in snippet
        assert "line6" in snippet

    def test_extract_snippet_file_not_found(self):
        """Test snippet extraction with non-existent file."""
        logger = setup_logging()
        snippet = extract_code_snippet(
            "/nonexistent/file.py", 1, 3, context_lines=1, logger=logger
        )
        assert "unavailable" in snippet.lower()

    def test_extract_snippet_markers(self, tmp_path):
        """Test that vulnerability markers are applied correctly."""
        test_file = tmp_path / "test.py"
        test_file.write_text("line1\nline2\nline3\nline4\nline5\n")
        logger = setup_logging()
        snippet = extract_code_snippet(
            str(test_file), 3, 3, context_lines=1, logger=logger
        )
        assert ">>>" in snippet  # Marker for vulnerable line


# ============================================================
# Test Prompt Building
# ============================================================
class TestPromptBuilding:
    """Tests for LLM prompt construction."""

    def test_build_prompt_contains_all_sections(self):
        """Test that the prompt includes all required sections."""
        prompt = build_prompt(
            "eval(user_input)",
            "Dangerous use of eval()",
            "python.lang.security.eval-injection"
        )
        assert "OWASP Category" in prompt
        assert "Severity" in prompt
        assert "Explanation" in prompt
        assert "Remediation" in prompt
        assert "eval(user_input)" in prompt
        assert "python.lang.security.eval-injection" in prompt

    def test_build_prompt_handles_special_characters(self):
        """Test prompt handles special characters in code."""
        prompt = build_prompt(
            'query = f"SELECT * FROM users WHERE id={user_id}"',
            "SQL injection risk",
            "sql-injection"
        )
        assert "SELECT * FROM users" in prompt


# ============================================================
# Test Summary Generation
# ============================================================
class TestSummaryGeneration:
    """Tests for report summary generation."""

    def test_generate_summary_mixed(self):
        """Test summary with mixed severities."""
        report = [
            {"severity": "ERROR"},
            {"severity": "ERROR"},
            {"severity": "WARNING"},
            {"severity": "INFO"},
        ]
        summary = generate_summary(report)
        assert summary['ERROR'] == 2
        assert summary['WARNING'] == 1
        assert summary['INFO'] == 1

    def test_generate_summary_empty(self):
        """Test summary with no findings."""
        summary = generate_summary([])
        assert summary['ERROR'] == 0
        assert summary['WARNING'] == 0
        assert summary['INFO'] == 0


# ============================================================
# Test Quality Gate
# ============================================================
class TestQualityGate:
    """Tests for quality gate evaluation."""

    def test_quality_gate_pass(self):
        """Test quality gate passes when no violations."""
        logger = setup_logging()
        report = [
            {"severity": "INFO", "rule_id": "test", "file": "a.py", "lines": "1-2"}
        ]
        exit_code = evaluate_quality_gate(report, "WARNING", logger)
        assert exit_code == 0

    def test_quality_gate_fail_on_warning(self):
        """Test quality gate fails on WARNING threshold."""
        logger = setup_logging()
        report = [
            {"severity": "WARNING", "rule_id": "test", "file": "a.py", "lines": "1-2"}
        ]
        exit_code = evaluate_quality_gate(report, "WARNING", logger)
        assert exit_code == 1

    def test_quality_gate_fail_on_error(self):
        """Test quality gate fails on ERROR threshold."""
        logger = setup_logging()
        report = [
            {"severity": "ERROR", "rule_id": "test", "file": "a.py", "lines": "1-2"},
            {"severity": "WARNING", "rule_id": "test2", "file": "b.py", "lines": "3-4"},
        ]
        exit_code = evaluate_quality_gate(report, "ERROR", logger)
        assert exit_code == 1

    def test_quality_gate_pass_on_error_threshold_with_warnings(self):
        """Test quality gate passes warnings when threshold is ERROR."""
        logger = setup_logging()
        report = [
            {"severity": "WARNING", "rule_id": "test", "file": "a.py", "lines": "1-2"},
            {"severity": "INFO", "rule_id": "test2", "file": "b.py", "lines": "3-4"},
        ]
        exit_code = evaluate_quality_gate(report, "ERROR", logger)
        assert exit_code == 0

    def test_quality_gate_empty_report(self):
        """Test quality gate with no findings."""
        logger = setup_logging()
        exit_code = evaluate_quality_gate([], "WARNING", logger)
        assert exit_code == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
