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

"""Tests for the Vite environment-variable analyser."""

import logging

import pytest

from vite_env import scan_vite_env, parse_env_file


def test_parses_keys_without_exposing_values(tmp_path):
    env = tmp_path / ".env"
    env.write_text("VITE_API_KEY=sk-live-secret123\nDB_PASSWORD=hunter2\n")
    pairs = parse_env_file(str(env))
    assert pairs == ["VITE_API_KEY", "DB_PASSWORD"]


def test_only_vite_keys_are_reported(tmp_path):
    (tmp_path / ".env").write_text("VITE_API_KEY=abc\nDB_PASSWORD=hunter2\n")
    findings = scan_vite_env(str(tmp_path), {})
    keys = [f["key"] for f in findings]
    assert keys == ["VITE_API_KEY"]


def test_no_finding_contains_a_value(tmp_path):
    (tmp_path / ".env").write_text("VITE_API_KEY=sk-live-secret123\n")
    findings = scan_vite_env(str(tmp_path), {})
    blob = repr(findings)
    assert "sk-live-secret123" not in blob


def test_use_sites_are_reported(tmp_path):
    (tmp_path / ".env").write_text("VITE_API_KEY=abc\n")
    findings = scan_vite_env(str(tmp_path), {"VITE_API_KEY": ["src/config.ts"]})
    assert findings[0]["use_sites"] == ["src/config.ts"]


def test_key_defined_in_several_files_is_one_finding(tmp_path):
    (tmp_path / ".env").write_text("VITE_API_KEY=abc\n")
    (tmp_path / ".env.prod").write_text("VITE_API_KEY=xyz\n")
    findings = scan_vite_env(str(tmp_path), {})
    assert len(findings) == 1
    assert sorted(findings[0]["files"]) == [".env", ".env.prod"]


def test_secret_looking_key_ranks_above_a_url(tmp_path):
    (tmp_path / ".env").write_text("VITE_API_URL=https://x\nVITE_CLIENT_SECRET=s\n")
    by_key = {f["key"]: f["severity_tier"] for f in scan_vite_env(str(tmp_path), {})}
    assert by_key["VITE_CLIENT_SECRET"] == "ERROR"
    assert by_key["VITE_API_URL"] == "INFO"


def test_unreadable_env_file_does_not_raise(tmp_path):
    bad = tmp_path / ".env"
    bad.write_bytes(b"\xff\xfe VITE_A=1\n")
    assert scan_vite_env(str(tmp_path), {}) is not None


def test_no_env_files_is_silent(tmp_path):
    assert scan_vite_env(str(tmp_path), {}) == []


def test_malformed_env_file_logs_warning_without_leaking_content(tmp_path, caplog):
    bad = tmp_path / ".env"
    sentinel = "SENTINEL_VALUE_9f8e7d6c5b4a"
    # A file that starts out as plausible, valid text (with a real-looking
    # value) and then degrades into binary garbage mid-file, as a corrupted
    # or partially-written .env would in practice.
    bad.write_bytes(("VITE_A=" + sentinel + "\n").encode("utf-8") + b"\xff\xfe\x00\x01")

    with caplog.at_level(logging.WARNING):
        findings = scan_vite_env(str(tmp_path), {})

    assert findings == []

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "expected a warning to be logged for a malformed .env file"
    assert any(".env" in w.getMessage() for w in warnings)

    log_text = caplog.text
    assert sentinel not in log_text
    assert "VITE_A" not in log_text
