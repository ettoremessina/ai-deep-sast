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
Deep scan detector.

Two detection techniques (§5.4):
1. LLM-evaluated rule-based (FR-037): Opus 4 evaluates each function against
   detection rules with full call-graph context from the index.
2. Exploratory hunting (FR-040): Opus 4 free-form exploration guided by the
   security map and call graph.

Candidates are written to the finding store (FR-044) and NEVER surfaced
directly to humans. The Triager promotes them.

Constitution alignment:
  I.   Evidence Over Assertion — each candidate includes why it's suspicious
  VIII. Fingerprints Stable Under Edit — dedup by fingerprint before writing
"""

import json
import logging
from typing import Any, Dict, List, Optional

from finding_store import FindingStore
from indexer import CodeIndex
from llm_client import LLMClient
from redactor import redact_secrets_in_text, verify_no_secrets
from rule_matcher import RuleMatcher, MatchResult

logger = logging.getLogger(__name__)


def _identity(func: Dict[str, Any]) -> str:
    """The name that identifies one indexed unit inside its file.

    Both the processed marker and the finding fingerprint are keyed on this,
    so it has to be unique per unit within a file — see
    FunctionInfo.unique_name. The fallbacks cover function dicts that did not
    come from the index (Semgrep groups, exploratory candidates).
    """
    return func.get("unique_name") or func.get("qualified_name") or func.get("name", "")


# --- Prompts ---

RULE_BASED_SYSTEM_PROMPT = """\
You are a security vulnerability detector. You are given a function from a codebase \
along with its callers and callees for context.

Analyse the function for security vulnerabilities. For each vulnerability found, respond \
with a JSON array of findings. Each finding must have:
- "vulnerability_class": short identifier (e.g. "sql-injection", "xss", "path-traversal", "hardcoded-secret", "ssrf")
- "description": one paragraph explaining WHY this is a vulnerability, with specific reference to the code
- "cwe": the most specific CWE ID (e.g. "CWE-89")
- "severity_tier": one of "INFO", "WARNING", "ERROR"
- "severity_cvss": estimated CVSS v3.1 score (0.0-10.0)

When the code is a browser front end, also consider:
- dangerouslySetInnerHTML, innerHTML or document.write reached by non-constant input
- javascript: or data: URLs flowing into href, src or window.open
- tokens, credentials or personal data written to localStorage or sessionStorage
- secrets read from import.meta.env: every VITE_-prefixed variable is inlined into \
the client bundle and is readable by any visitor
- authorisation decided only in the browser, with no server-side check
- postMessage handlers that do not verify event.origin

If no vulnerabilities are found, respond with an empty JSON array: []

Respond ONLY with the JSON array, no other text.
"""

GUIDED_SYSTEM_PROMPT = """\
You are a security vulnerability detector. You are given a function from a codebase \
along with its callers and callees for context, AND a set of specific security \
requirements to check against.

Analyse the function ONLY against the provided security requirements. For each \
violation found, respond with a JSON array of findings. Each finding must have:
- "vulnerability_class": short identifier (e.g. "sql-injection", "xss", "path-traversal")
- "description": one paragraph explaining WHY this is a vulnerability, referencing the specific requirement violated
- "cwe": the most specific CWE ID (e.g. "CWE-89")
- "severity_tier": one of "INFO", "WARNING", "ERROR"
- "severity_cvss": estimated CVSS v3.1 score (0.0-10.0)
- "asvs_id": the ASVS requirement ID violated (if applicable, e.g. "1.2.4")
- "codeguard_rule": the CodeGuard rule ID violated (if applicable)

If no violations are found against the provided requirements, respond with an empty JSON array: []

Respond ONLY with the JSON array, no other text.
"""

SEMGREP_GUIDED_SYSTEM_PROMPT = """\
You are a security vulnerability validator. A static analysis tool (Semgrep) has flagged \
a potential vulnerability in the code below. Your job is to validate whether this finding \
is a TRUE POSITIVE (actually exploitable) or a FALSE POSITIVE (not exploitable).

For each Semgrep finding, analyse the code and respond with a JSON array. Each element must have:
- "vulnerability_class": short identifier (e.g. "sql-injection", "xss", "path-traversal")
- "description": explain WHY this is or is not exploitable, referencing the specific code
- "cwe": the most specific CWE ID (e.g. "CWE-89")
- "severity_tier": one of "INFO", "WARNING", "ERROR"
- "severity_cvss": estimated CVSS v3.1 score (0.0-10.0)
- "semgrep_rule": the Semgrep rule ID that triggered this finding
- "exploitable": true or false — can an attacker actually reach and trigger this?
- "evidence": the specific attack input that would exploit this (if exploitable)
- "mitigations_present": list any existing sanitization/validation you see upstream

If the finding is a FALSE POSITIVE, still include it but set exploitable to false and \
explain why in the description.

Respond ONLY with the JSON array, no other text.
"""

EXPLORATORY_SYSTEM_PROMPT = """\
You are a security researcher performing exploratory vulnerability hunting on a codebase. \
You are given a security map (architecture, attack surface, trust boundaries) and a set of \
functions to investigate.

Look for design-level security flaws that pattern-matching rules would miss:
- Authentication/authorisation bypasses
- Business logic flaws
- Race conditions
- Insecure data flows across trust boundaries
- Missing input validation at trust boundary crossings
- Privilege escalation paths
- Client-side-only authorisation: route guards or UI gating with no server check
- Trust placed in build-time configuration that ships to the browser

For each vulnerability found, respond with a JSON array of findings. Each finding must have:
- "function_name": the function where the vulnerability manifests
- "file_path": the file containing that function
- "vulnerability_class": short identifier
- "description": detailed explanation with code references
- "cwe": most specific CWE ID
- "severity_tier": one of "INFO", "WARNING", "ERROR"
- "severity_cvss": estimated CVSS v3.1 score (0.0-10.0)

If no vulnerabilities are found, respond with an empty JSON array: []

Respond ONLY with the JSON array, no other text.
"""


class Detector:
    """
    Deep scan detector.

    Writes candidate findings to the finding store.
    Does NOT surface findings to humans (FR-044).
    """

    def __init__(self, llm_client: LLMClient, index: CodeIndex,
                 finding_store: FindingStore,
                 security_map: Optional[str] = None,
                 rule_matcher: Optional[RuleMatcher] = None):
        self.llm = llm_client
        self.index = index
        self.store = finding_store
        self.security_map = security_map or ""
        self.rule_matcher = rule_matcher

    def run_rule_based(self, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Run LLM-evaluated rule-based detection (FR-037).

        Evaluates each function with its call-graph context.
        Front-loads context per FR-049.
        """
        stats = {"functions_analysed": 0, "candidates_created": 0,
                 "duplicates_skipped": 0, "errors": 0,
                 "resumed_skipped": 0}

        if file_path:
            functions = self.index.list_functions_in_file(file_path)
        else:
            functions = self.index.get_all_functions()

        total = len(functions) if isinstance(functions, list) else None
        already_done = self.store.get_processed_count()
        if already_done > 0:
            logger.info("Resume: %d functions already processed, skipping them", already_done)

        consecutive_auth_errors = 0
        max_consecutive_auth_errors = 3

        for func in functions:
            # unique_name, not qualified_name: the index keeps two renderCell
            # callbacks in one grid.tsx apart, but a marker keyed on the name
            # they share makes the second one look already-processed and drops
            # it, and any finding it produced would collapse onto the first
            # one's fingerprint.
            func_name = _identity(func)
            if self.store.is_function_processed(func["file_path"], func_name):
                stats["resumed_skipped"] += 1
                continue

            try:
                candidates = self._analyse_function(func)
                consecutive_auth_errors = 0
                self.store.mark_function_processed(func["file_path"], func_name)
                for candidate in candidates:
                    fid = self.store.add_finding(
                        file_path=func["file_path"],
                        vulnerability_class=candidate.get("vulnerability_class", "unknown"),
                        description=candidate.get("description", ""),
                        detection_technique="rule-based-llm",
                        function_name=func_name,
                        severity_cvss=candidate.get("severity_cvss"),
                        severity_tier=candidate.get("severity_tier"),
                        cwe=candidate.get("cwe"),
                    )
                    if fid:
                        stats["candidates_created"] += 1
                    else:
                        stats["duplicates_skipped"] += 1
                stats["functions_analysed"] += 1

            except Exception as e:
                error_str = str(e)
                if "401" in error_str or "403" in error_str:
                    consecutive_auth_errors += 1
                    if consecutive_auth_errors >= max_consecutive_auth_errors:
                        logger.error("Circuit breaker: %d consecutive auth errors — stopping rule-based",
                                     consecutive_auth_errors)
                        stats["circuit_breaker"] = True
                        break
                else:
                    consecutive_auth_errors = 0
                logger.error("Error analysing function %s: %s", func.get("name"), e)
                stats["errors"] += 1

        logger.info("Rule-based detection: %d functions, %d candidates, %d dedup, %d resumed",
                     stats["functions_analysed"], stats["candidates_created"],
                     stats["duplicates_skipped"], stats["resumed_skipped"])
        return stats

    def run_guided(self, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Run rule-guided detection — only analyse functions matching ASVS/CodeGuard rules.

        Functions with no rule matches are skipped entirely (no LLM call).
        Matched functions get a focused prompt with specific rules to check.
        """
        if not self.rule_matcher:
            logger.error("No rule matcher configured — cannot run guided mode")
            return {}

        stats = {"functions_analysed": 0, "candidates_created": 0,
                 "duplicates_skipped": 0, "errors": 0,
                 "resumed_skipped": 0, "rule_skipped": 0,
                 "total_functions": 0}

        if file_path:
            functions = self.index.list_functions_in_file(file_path)
        else:
            functions = self.index.get_all_functions()

        stats["total_functions"] = len(functions)
        already_done = self.store.get_processed_count()
        if already_done > 0:
            logger.info("Resume: %d functions already processed, skipping them", already_done)

        for func in functions:
            func_name = _identity(func)
            if self.store.is_function_processed(func["file_path"], func_name):
                stats["resumed_skipped"] += 1
                continue

            # Rule matching — skip if no rules match
            match_result = self.rule_matcher.match_function(func)
            if not match_result.has_matches:
                self.store.mark_function_processed(func["file_path"], func_name)
                stats["rule_skipped"] += 1
                continue

            try:
                candidates = self._analyse_function_guided(func, match_result)
                self.store.mark_function_processed(func["file_path"], func_name)
                for candidate in candidates:
                    fid = self.store.add_finding(
                        file_path=func["file_path"],
                        vulnerability_class=candidate.get("vulnerability_class", "unknown"),
                        description=candidate.get("description", ""),
                        detection_technique="guided-llm",
                        function_name=func_name,
                        severity_cvss=candidate.get("severity_cvss"),
                        severity_tier=candidate.get("severity_tier"),
                        cwe=candidate.get("cwe"),
                        rule_id=candidate.get("asvs_id") or candidate.get("codeguard_rule"),
                    )
                    if fid:
                        stats["candidates_created"] += 1
                    else:
                        stats["duplicates_skipped"] += 1
                stats["functions_analysed"] += 1

            except Exception as e:
                logger.error("Error analysing function %s: %s", func.get("name"), e)
                stats["errors"] += 1

        matcher_stats = self.rule_matcher.get_stats()
        filter_rate = (stats["rule_skipped"] / stats["total_functions"] * 100
                       if stats["total_functions"] > 0 else 0)
        logger.info(
            "Guided detection: %d total, %d matched (%d to LLM), %d rule-skipped (%.1f%% filtered), "
            "%d candidates, %d resumed",
            stats["total_functions"], stats["functions_analysed"],
            stats["functions_analysed"], stats["rule_skipped"],
            filter_rate, stats["candidates_created"], stats["resumed_skipped"]
        )
        return stats

    def _analyse_function_guided(self, func: Dict[str, Any],
                                  match_result: MatchResult) -> List[Dict[str, Any]]:
        """Analyse a function with rule-guided prompt."""
        func_name = func.get("name", "")
        file_path = func.get("file_path", "")
        body = func.get("body", "")

        callers = self.index.get_callers(func_name)
        callees = self.index.get_callees(file_path, _identity(func))

        # Build guided prompt with matched rules
        guided_rules = self.rule_matcher.build_guided_prompt(match_result)

        context_parts = [
            f"## Function: {func.get('qualified_name', func_name)}",
            f"File: {file_path}",
            f"Lines: {func.get('start_line')}-{func.get('end_line')}",
            f"\n### Security Requirements to Check:\n{guided_rules}",
            f"\n### Function Body:\n```\n{body}\n```",
        ]

        if callers:
            caller_info = "\n".join(
                f"- {c.get('qualified_name', c.get('name', '?'))} in {c.get('file_path', '?')}"
                for c in callers[:5]
            )
            context_parts.append(f"\n### Callers (who calls this):\n{caller_info}")

        if callees:
            context_parts.append(f"\n### Callees (what this calls):\n- " + "\n- ".join(callees[:10]))

        user_message = "\n".join(context_parts)

        # Redact secrets before sending
        redaction = redact_secrets_in_text(user_message)
        safe_message = redaction.redacted

        if not verify_no_secrets(safe_message):
            logger.error("Pre-send verification failed for %s — skipping", func_name)
            return []

        response_text, call_info = self.llm.chat(GUIDED_SYSTEM_PROMPT, safe_message)
        return self._parse_findings_response(
            response_text, call_info.get("finish_reason", ""))

    def run_semgrep_guided(self, semgrep_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Run Semgrep-guided detection — Opus validates each Semgrep finding.

        For each Semgrep finding, send the flagged function + Semgrep context
        to Opus for exploitability validation. This is the fastest guided mode
        since only Semgrep-flagged locations are sent to the LLM.
        """
        stats = {"findings_validated": 0, "confirmed_tp": 0,
                 "confirmed_fp": 0, "candidates_created": 0,
                 "duplicates_skipped": 0, "errors": 0,
                 "total_semgrep_findings": len(semgrep_results)}

        if not semgrep_results:
            logger.warning("No Semgrep findings to validate")
            return stats

        # Group Semgrep findings by file+function for efficient processing
        grouped = self._group_semgrep_findings(semgrep_results)
        logger.info("Semgrep → Opus: %d findings in %d groups",
                     len(semgrep_results), len(grouped))

        for key, findings_group in grouped.items():
            file_path = findings_group[0]["path"]
            func_name = findings_group[0].get("function_name")

            # Skip already processed
            if func_name and self.store.is_function_processed(file_path, func_name):
                stats["findings_validated"] += len(findings_group)
                continue

            try:
                candidates = self._analyse_semgrep_finding(findings_group)
                if func_name:
                    self.store.mark_function_processed(file_path, func_name)

                for candidate in candidates:
                    is_exploitable = candidate.get("exploitable", True)
                    if not is_exploitable:
                        stats["confirmed_fp"] += 1
                        continue

                    stats["confirmed_tp"] += 1
                    fid = self.store.add_finding(
                        file_path=file_path,
                        vulnerability_class=candidate.get("vulnerability_class", "unknown"),
                        description=candidate.get("description", ""),
                        detection_technique="semgrep-guided-llm",
                        function_name=func_name,
                        severity_cvss=candidate.get("severity_cvss"),
                        severity_tier=candidate.get("severity_tier"),
                        cwe=candidate.get("cwe"),
                        rule_id=candidate.get("semgrep_rule"),
                    )
                    if fid:
                        stats["candidates_created"] += 1
                    else:
                        stats["duplicates_skipped"] += 1

                stats["findings_validated"] += len(findings_group)

            except Exception as e:
                logger.error("Error validating Semgrep finding in %s: %s", file_path, e)
                stats["errors"] += 1

        tp_rate = (stats["confirmed_tp"] /
                   max(stats["confirmed_tp"] + stats["confirmed_fp"], 1) * 100)
        logger.info(
            "Semgrep-guided: %d findings validated, %d TP (%.1f%%), %d FP, %d candidates stored",
            stats["findings_validated"], stats["confirmed_tp"], tp_rate,
            stats["confirmed_fp"], stats["candidates_created"]
        )
        return stats

    def _analyse_semgrep_finding(self, findings_group: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate a group of Semgrep findings in the same function with Opus."""
        first = findings_group[0]
        file_path = first["path"]
        start_line = first.get("start", {}).get("line", 0)

        # Try to get the function from the index
        func = None
        func_name = first.get("function_name")
        if func_name:
            funcs = self.index.list_functions_in_file(file_path)
            for f in funcs:
                # unique_name too: _find_function_at_line reports a discriminated
                # name ("fetch#1") for a second same-named function, which matches
                # neither of the other two.
                if func_name in (f.get("name"), f.get("qualified_name"),
                                 f.get("unique_name")):
                    func = f
                    break

        # Build context
        context_parts = [f"## File: {file_path}"]

        # Add Semgrep findings context
        context_parts.append("\n### Semgrep Findings to Validate:")
        for sg in findings_group:
            rule_id = sg.get("check_id", "unknown")
            severity = sg.get("extra", {}).get("severity", "UNKNOWN")
            message = sg.get("extra", {}).get("message", "")
            line = sg.get("start", {}).get("line", "?")
            end_line = sg.get("end", {}).get("line", "?")
            snippet = sg.get("extra", {}).get("lines", "")

            context_parts.append(
                f"- **Rule**: {rule_id}\n"
                f"  **Severity**: {severity}\n"
                f"  **Line**: {line}-{end_line}\n"
                f"  **Message**: {message}\n"
                f"  **Code**: `{snippet.strip()}`"
            )

        # Add function body if available
        if func:
            body = func.get("body", "")
            context_parts.append(
                f"\n### Function: {func.get('qualified_name', func_name)}\n"
                f"Lines: {func.get('start_line')}-{func.get('end_line')}\n"
                f"```\n{body}\n```"
            )

            callers = self.index.get_callers(func.get("name", ""))
            callees = self.index.get_callees(file_path, func.get("name", ""))

            if callers:
                caller_info = "\n".join(
                    f"- {c.get('qualified_name', c.get('name', '?'))} in {c.get('file_path', '?')}"
                    for c in callers[:5]
                )
                context_parts.append(f"\n### Callers:\n{caller_info}")

            if callees:
                context_parts.append(f"\n### Callees:\n- " + "\n- ".join(callees[:10]))
        else:
            # No function found — send surrounding code lines
            context_parts.append(
                f"\n### Code at flagged location (line {start_line}):\n"
                f"(Function body not available — file-level finding)"
            )

        user_message = "\n".join(context_parts)

        # Redact secrets before sending
        redaction = redact_secrets_in_text(user_message)
        safe_message = redaction.redacted

        if not verify_no_secrets(safe_message):
            logger.error("Pre-send verification failed for %s — skipping", file_path)
            return []

        response_text, call_info = self.llm.chat(SEMGREP_GUIDED_SYSTEM_PROMPT, safe_message)
        return self._parse_findings_response(
            response_text, call_info.get("finish_reason", ""))

    def _group_semgrep_findings(self, results: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group Semgrep findings by file + function for batched validation."""
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for finding in results:
            file_path = finding.get("path", "")
            # Try to determine function name from the index
            line = finding.get("start", {}).get("line", 0)
            func_name = self._find_function_at_line(file_path, line)
            finding["function_name"] = func_name
            key = f"{file_path}::{func_name or 'file-level'}"
            grouped.setdefault(key, []).append(finding)
        return grouped

    def _find_function_at_line(self, file_path: str, line: int) -> Optional[str]:
        """Find which function contains a given line number."""
        funcs = self.index.list_functions_in_file(file_path)
        for func in funcs:
            start = func.get("start_line", 0)
            end = func.get("end_line", 0)
            if start <= line <= end:
                return _identity(func)
        return None

    def run_exploratory(self, focus_areas: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run exploratory hunting (FR-040).

        Free-form LLM exploration guided by the security map and index.
        """
        stats = {"batches_analysed": 0, "candidates_created": 0,
                 "duplicates_skipped": 0, "errors": 0,
                 "resumed_skipped": 0}

        all_functions = self.index.get_all_functions()
        if not all_functions:
            logger.warning("No functions in index for exploratory hunting")
            return stats

        # Group functions into batches for exploration
        batches = self._create_exploration_batches(all_functions, focus_areas)
        total_batches = len(batches)
        consecutive_auth_errors = 0
        max_consecutive_auth_errors = 3

        logger.info("Exploratory: %d batches to process", total_batches)

        for idx, batch in enumerate(batches):
            # Generate a stable key for this batch (file_path + function names)
            batch_key = "|".join(
                f"{f.get('file_path', '')}:{f.get('name', '')}" for f in batch
            )
            if self.store.is_batch_processed(batch_key):
                stats["resumed_skipped"] += 1
                continue

            try:
                candidates = self._explore_batch(batch)
                consecutive_auth_errors = 0
                self.store.mark_batch_processed(batch_key)
                for candidate in candidates:
                    fid = self.store.add_finding(
                        file_path=candidate.get("file_path", batch[0]["file_path"]),
                        vulnerability_class=candidate.get("vulnerability_class", "unknown"),
                        description=candidate.get("description", ""),
                        detection_technique="exploratory",
                        function_name=candidate.get("function_name"),
                        severity_cvss=candidate.get("severity_cvss"),
                        severity_tier=candidate.get("severity_tier"),
                        cwe=candidate.get("cwe"),
                    )
                    if fid:
                        stats["candidates_created"] += 1
                    else:
                        stats["duplicates_skipped"] += 1
                stats["batches_analysed"] += 1

                if (idx + 1) % 500 == 0 or (idx + 1) == total_batches:
                    logger.info("Exploratory progress: %d/%d batches (%.0f%%), %d candidates",
                                idx + 1, total_batches,
                                (idx + 1) / total_batches * 100,
                                stats["candidates_created"])

            except Exception as e:
                error_str = str(e)
                if "401" in error_str or "403" in error_str:
                    consecutive_auth_errors += 1
                    if consecutive_auth_errors >= max_consecutive_auth_errors:
                        logger.error("Circuit breaker: %d consecutive auth errors — stopping exploratory",
                                     consecutive_auth_errors)
                        stats["circuit_breaker"] = True
                        break
                else:
                    consecutive_auth_errors = 0
                logger.error("Error in exploratory batch: %s", e)
                stats["errors"] += 1

        logger.info("Exploratory detection: %d batches, %d candidates, %d resumed",
                     stats["batches_analysed"], stats["candidates_created"],
                     stats["resumed_skipped"])
        return stats

    def _analyse_function(self, func: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyse a single function with call-graph context (FR-049)."""
        # Front-load context: function body + callers + callees
        func_name = func.get("name", "")
        file_path = func.get("file_path", "")
        body = func.get("body", "")

        # Callers are keyed by the plain callee name; callees have to be looked
        # up by the unique name or the second of two same-named functions is
        # described to the LLM with the first one's call graph.
        callers = self.index.get_callers(func_name)
        callees = self.index.get_callees(file_path, _identity(func))

        context_parts = [
            f"## Function: {_identity(func) or func_name}",
            f"File: {file_path}",
            f"Lines: {func.get('start_line')}-{func.get('end_line')}",
            f"\n### Function Body:\n```\n{body}\n```",
        ]

        if callers:
            caller_info = "\n".join(
                f"- {c.get('qualified_name', c.get('name', '?'))} in {c.get('file_path', '?')}"
                for c in callers[:5]  # Limit to 5 callers
            )
            context_parts.append(f"\n### Callers (who calls this):\n{caller_info}")

        if callees:
            context_parts.append(f"\n### Callees (what this calls):\n- " + "\n- ".join(callees[:10]))

        user_message = "\n".join(context_parts)

        # Redact secrets before sending
        redaction = redact_secrets_in_text(user_message)
        safe_message = redaction.redacted

        if not verify_no_secrets(safe_message):
            logger.error("Pre-send verification failed for %s — skipping", func_name)
            return []

        response_text, call_info = self.llm.chat(RULE_BASED_SYSTEM_PROMPT, safe_message)
        return self._parse_findings_response(
            response_text, call_info.get("finish_reason", ""))

    def _explore_batch(self, batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Explore a batch of related functions for design-level flaws."""
        batch_context = []
        for func in batch:
            batch_context.append(
                f"### {func.get('qualified_name', func.get('name', '?'))} "
                f"({func.get('file_path', '?')}:{func.get('start_line', '?')})\n"
                f"```\n{func.get('body', '')}\n```"
            )

        user_message_parts = []
        if self.security_map:
            user_message_parts.append(f"## Security Map\n{self.security_map}\n")
        user_message_parts.append("## Functions to Investigate\n")
        user_message_parts.append("\n\n".join(batch_context))

        user_message = "\n".join(user_message_parts)

        # Redact secrets before sending
        redaction = redact_secrets_in_text(user_message)
        safe_message = redaction.redacted

        if not verify_no_secrets(safe_message):
            logger.error("Pre-send verification failed for batch — skipping")
            return []

        response_text, call_info = self.llm.chat(EXPLORATORY_SYSTEM_PROMPT, safe_message)
        return self._parse_findings_response(
            response_text, call_info.get("finish_reason", ""))

    def _create_exploration_batches(self, functions: List[Dict[str, Any]],
                                    focus_areas: Optional[List[str]] = None,
                                    batch_size: int = 5) -> List[List[Dict[str, Any]]]:
        """Group functions into batches for exploration."""
        if focus_areas:
            # Filter to focus areas
            filtered = [f for f in functions
                        if any(area.lower() in f.get("file_path", "").lower() or
                               area.lower() in f.get("name", "").lower()
                               for area in focus_areas)]
            functions = filtered if filtered else functions

        # Group by file, then chunk
        by_file: Dict[str, List[Dict]] = {}
        for func in functions:
            fp = func.get("file_path", "")
            by_file.setdefault(fp, []).append(func)

        batches = []
        for file_funcs in by_file.values():
            for i in range(0, len(file_funcs), batch_size):
                batches.append(file_funcs[i:i + batch_size])

        return batches

    @staticmethod
    def _salvage_truncated_findings(text: str) -> List[Dict[str, Any]]:
        """
        Recover the findings that were completed before the response was cut off.

        A response truncated at the token cap ends mid-object, which makes the whole
        array unparseable — but the objects emitted before the cut are intact, and
        they are real findings that would otherwise be dropped silently.
        """
        start = text.find("[")
        if start < 0:
            return []

        decoder = json.JSONDecoder()
        recovered: List[Dict[str, Any]] = []
        pos = start + 1

        while pos < len(text):
            while pos < len(text) and text[pos] in " \t\r\n,":
                pos += 1
            if pos >= len(text) or text[pos] != "{":
                break
            try:
                obj, pos = decoder.raw_decode(text, pos)
            except ValueError:
                break  # first incomplete object — everything after it is cut too
            if isinstance(obj, dict):
                recovered.append(obj)

        return recovered

    @staticmethod
    def _parse_findings_response(response_text: str,
                                 finish_reason: str = "") -> List[Dict[str, Any]]:
        """Parse LLM response into a list of finding dicts."""
        text = response_text.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        if not text or text == "[]":
            return []

        try:
            result = json.loads(text)
            if isinstance(result, list):
                return [r for r in result if isinstance(r, dict)]
            if isinstance(result, dict):
                return [result]
        except json.JSONDecodeError:
            # Try to extract JSON array from the response
            start = text.find("[")
            end = text.rfind("]")
            if start >= 0 and end > start:
                try:
                    result = json.loads(text[start:end + 1])
                    if isinstance(result, list):
                        return [r for r in result if isinstance(r, dict)]
                except json.JSONDecodeError:
                    pass

            # Last resort: keep whatever the model completed before the cut.
            recovered = Detector._salvage_truncated_findings(text)
            if recovered:
                logger.warning(
                    "Unparseable LLM response (finish_reason=%s, %d chars) — "
                    "recovered %d complete finding(s) written before the cut",
                    finish_reason or "unknown", len(text), len(recovered),
                )
            else:
                logger.warning(
                    "Unparseable LLM response (finish_reason=%s, %d chars) — "
                    "no complete finding to recover, this batch is lost",
                    finish_reason or "unknown", len(text),
                )
            # Full text only at DEBUG: it quotes scanned source into the log.
            logger.debug("Unparsed LLM response in full:\n%s", text)
            return recovered

        return []
