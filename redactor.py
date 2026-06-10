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
Redaction layer for deep scan.

Strips secret VALUES from source code before sending to external LLM APIs.
Uses Semgrep findings to identify secret locations, then replaces the
matched values with <REDACTED> placeholders.

This is a security constraint:
source code CAN be sent to the API, but secret values MUST be redacted.

The frontier model does not need actual secret values to:
- Determine that hardcoding a password is a vulnerability
- Trace data flows through the code
- Assess trust boundary crossings
- Produce remediation guidance
"""

import json
import logging
import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Placeholder used to replace secret values
REDACTED_PLACEHOLDER = "<REDACTED>"

# Patterns that match common secret assignment formats
# Used as a fallback when Semgrep results don't include exact match ranges
_SECRET_VALUE_PATTERNS = [
    # key = "value" or key = 'value'
    re.compile(
        r'((?:password|passwd|secret|credential|api_key|api_secret|token|auth_token'
        r'|access_key|private_key)\s*[=:]\s*)["\']([^"\']+)["\']',
        re.IGNORECASE
    ),
    # key=value (no quotes, .properties/.env style)
    re.compile(
        r'((?:password|passwd|secret|credential|api_key|api_secret|token|auth_token'
        r'|access_key|private_key)\s*[=:]\s*)(\S+)',
        re.IGNORECASE
    ),
    # JDBC connection strings with passwords
    re.compile(
        r'(jdbc:[^"\'\s]*password=)([^&"\';\s]+)',
        re.IGNORECASE
    ),
]

# Patterns that should NOT be redacted (false positives)
_SKIP_PATTERNS = [
    re.compile(r'^\s*#'),           # commented-out lines
    re.compile(r'\$\{'),            # Spring Boot ${VAR} placeholders
    re.compile(r'\{\{'),            # Helm/Vault {{ }} templates
    re.compile(r'<REDACTED>'),      # already redacted
]


class RedactionResult:
    """Result of redacting a piece of content."""

    def __init__(self, original: str, redacted: str, redaction_count: int,
                 redacted_locations: List[Dict[str, Any]]):
        self.original = original
        self.redacted = redacted
        self.redaction_count = redaction_count
        self.redacted_locations = redacted_locations

    @property
    def was_redacted(self) -> bool:
        return self.redaction_count > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "redaction_count": self.redaction_count,
            "was_redacted": self.was_redacted,
            "redacted_locations": self.redacted_locations,
        }


def redact_secrets_in_text(text: str, secret_findings: Optional[List[Dict[str, Any]]] = None) -> RedactionResult:
    """
    Redact secret values in a text string.

    If secret_findings (from Semgrep) are provided, uses them to identify
    exact locations. Otherwise falls back to regex pattern matching.

    Args:
        text: Source code text to redact
        secret_findings: Optional list of Semgrep findings with 'start'/'end' line info

    Returns:
        RedactionResult with redacted text and metadata
    """
    if not text or not text.strip():
        return RedactionResult(text, text, 0, [])

    lines = text.split("\n")
    redacted_lines = list(lines)
    locations: List[Dict[str, Any]] = []
    count = 0

    if secret_findings:
        count, locations = _redact_from_findings(redacted_lines, secret_findings)

    # Always run pattern-based redaction as a safety net
    pattern_count, pattern_locations = _redact_from_patterns(redacted_lines)
    count += pattern_count
    locations.extend(pattern_locations)

    redacted_text = "\n".join(redacted_lines)
    return RedactionResult(text, redacted_text, count, locations)


def _redact_from_findings(lines: List[str], findings: List[Dict[str, Any]]) -> Tuple[int, List[Dict[str, Any]]]:
    """Redact based on Semgrep finding locations."""
    count = 0
    locations: List[Dict[str, Any]] = []

    for finding in findings:
        start_line = finding.get("start", {}).get("line", 0)
        if start_line < 1 or start_line > len(lines):
            continue

        line_idx = start_line - 1
        line = lines[line_idx]

        if _should_skip(line):
            continue

        new_line, redacted = _redact_line(line)
        if redacted:
            lines[line_idx] = new_line
            count += 1
            locations.append({
                "line": start_line,
                "rule_id": finding.get("check_id", "unknown"),
                "source": "semgrep",
            })

    return count, locations


def _redact_from_patterns(lines: List[str]) -> Tuple[int, List[Dict[str, Any]]]:
    """Redact based on regex pattern matching (fallback/safety net)."""
    count = 0
    locations: List[Dict[str, Any]] = []

    for i, line in enumerate(lines):
        if _should_skip(line):
            continue
        if REDACTED_PLACEHOLDER in line:
            continue

        new_line, redacted = _redact_line(line)
        if redacted:
            lines[i] = new_line
            count += 1
            locations.append({
                "line": i + 1,
                "source": "pattern",
            })

    return count, locations


def _redact_line(line: str) -> Tuple[str, bool]:
    """
    Attempt to redact secret values in a single line.

    Returns (new_line, was_redacted).
    """
    original = line
    for pattern in _SECRET_VALUE_PATTERNS:
        match = pattern.search(line)
        if match:
            prefix = match.group(1)
            value = match.group(2)
            if value and len(value) > 0 and not _is_placeholder(value):
                # Check if the value was quoted in the original
                val_start = match.start(2)
                val_end = match.end(2)
                has_open_quote = val_start > 0 and line[val_start - 1] in "\"'"
                has_close_quote = val_end < len(line) and line[val_end] in "\"'"
                if has_open_quote and has_close_quote:
                    quote = line[val_start - 1]
                    line = line[:val_start] + REDACTED_PLACEHOLDER + line[val_end:]
                else:
                    line = line[:val_start] + REDACTED_PLACEHOLDER + line[val_end:]
                return line, True

    return original, False


def _should_skip(line: str) -> bool:
    """Check if a line should be skipped for redaction."""
    for pattern in _SKIP_PATTERNS:
        if pattern.search(line):
            return True
    return False


def _is_placeholder(value: str) -> bool:
    """Check if a value is already a placeholder (not a real secret)."""
    placeholders = {
        REDACTED_PLACEHOLDER, "changeme", "placeholder", "example",
        "your_password_here", "your_api_key", "xxx", "TODO",
        "CHANGE_ME", "INSERT_HERE",
    }
    return value.strip().strip("\"'") in placeholders or value.startswith("${") or value.startswith("{{")


def redact_file(file_path: str,
                secret_findings: Optional[List[Dict[str, Any]]] = None) -> RedactionResult:
    """
    Read a file, redact secrets, return the result.

    Does NOT modify the original file.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (OSError, IOError) as e:
        logger.error("Cannot read file for redaction: %s — %s", file_path, e)
        return RedactionResult("", "", 0, [])

    file_findings = [f for f in (secret_findings or [])
                     if f.get("path", "") == file_path or
                     os.path.basename(f.get("path", "")) == os.path.basename(file_path)]

    result = redact_secrets_in_text(content, file_findings)
    if result.was_redacted:
        logger.info("Redacted %d secret(s) in %s", result.redaction_count, file_path)

    return result


def run_semgrep_for_secrets(target: str,
                            semgrep_config: str = "p/secrets,config/custom-secrets.yaml",
                            timeout: int = 120) -> List[Dict[str, Any]]:
    """
    Run Semgrep with secret-detection rules and return findings.

    Used to identify secret locations for the redaction layer.
    """
    cmd = [
        "semgrep", "scan",
        "--config", semgrep_config,
        "--json",
        "--metrics=off",
        "--quiet",
        target,
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode not in (0, 1):
            logger.warning("Semgrep secret scan returned code %d", result.returncode)
            return []

        data = json.loads(result.stdout)
        findings = []
        for r in data.get("results", []):
            findings.append({
                "check_id": r.get("check_id", ""),
                "path": r.get("path", ""),
                "start": r.get("start", {}),
                "end": r.get("end", {}),
                "extra": {
                    "message": r.get("extra", {}).get("message", ""),
                    "lines": r.get("extra", {}).get("lines", ""),
                },
            })
        logger.info("Semgrep found %d secret(s) in %s", len(findings), target)
        return findings

    except subprocess.TimeoutExpired:
        logger.error("Semgrep secret scan timed out after %ds", timeout)
        return []
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Semgrep secret scan failed: %s", e)
        return []


def verify_no_secrets(text: str, known_secrets: Optional[Set[str]] = None) -> bool:
    """
    Pre-send assertion: verify no known secret values remain in text.

    Returns True if text is safe to send, False if secrets detected.
    """
    if known_secrets:
        for secret in known_secrets:
            if secret in text and secret != REDACTED_PLACEHOLDER:
                logger.error("Pre-send check FAILED: known secret value found in text")
                return False

    # Check for common high-entropy patterns that look like API keys
    # This is a lightweight heuristic, not a replacement for Semgrep
    for pattern in _SECRET_VALUE_PATTERNS:
        match = pattern.search(text)
        if match:
            value = match.group(2)
            if value and not _is_placeholder(value) and value != REDACTED_PLACEHOLDER:
                logger.warning("Pre-send check: possible unredacted secret at pattern match")
                return False

    return True
