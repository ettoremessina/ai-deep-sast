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
Deep scan triager.

Investigates candidate findings using a checklist-first approach
with tool-use fallback (§5.5):

1. Checklist investigation:
   - Read the code at the finding location
   - Trace the data flow (callers → function → callees)
   - Check for sanitization/validation
   - Identify trust boundary crossings
   - Assess exploitability and impact

2. If the evidence gate (FR-054) is not satisfied, escalate to
   open tool-use loop for deeper investigation.

Verdicts: true-positive, false-positive, needs-review, not-applicable, code-quality

Constitution alignment:
  I.   Evidence Over Assertion — verdict requires structural evidence
  II.  Surface Only What Survives — only true-positive reaches reports
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from finding_store import FindingStore, FindingState, Verdict
from indexer import CodeIndex
from llm_client import LLMClient
from redactor import redact_secrets_in_text, verify_no_secrets

logger = logging.getLogger(__name__)

# --- Prompts ---

TRIAGE_SYSTEM_PROMPT = """\
You are a security vulnerability triager. You are given a candidate finding \
(a potential vulnerability) along with the function code, its callers, callees, \
and surrounding context.

Your job is to determine if this is a real, exploitable vulnerability by following \
this investigation checklist:

1. **Read the code**: Understand what the function does.
2. **Trace data flow**: Follow user input from callers through this function to callees.
3. **Check sanitisation**: Is the input validated or sanitised before the dangerous operation?
4. **Trust boundary**: Does the data cross a trust boundary (e.g., user input → database)?
5. **Exploitability**: Can an attacker actually trigger this? What's the attack vector?
6. **Impact**: What damage can result? Data leak? Code execution? DoS?

Based on your analysis, assign a verdict:
- "true-positive": Real vulnerability with exploitable path. MUST include evidence.
- "false-positive": Not exploitable (sanitised, unreachable, test code, etc.)
- "needs-review": Likely real but you cannot fully confirm from the code alone.
- "not-applicable": The code pattern is intentional/safe in this context.
- "code-quality": Not a security issue but poor practice worth noting.

Respond with a JSON object:
{
    "verdict": "true-positive|false-positive|needs-review|not-applicable|code-quality",
    "confidence": 0.0-1.0,
    "evidence_report": "Detailed explanation of your analysis following the checklist. \
For true-positive: describe the attack vector, data flow, trust boundary, and impact. \
For false-positive: explain why it's not exploitable.",
    "severity_adjustment": {
        "severity_tier": "INFO|WARNING|ERROR",
        "severity_cvss": 0.0-10.0,
        "reason": "Why the severity was adjusted from the detector's estimate"
    }
}

Respond ONLY with the JSON object, no other text.
"""

DEEP_INVESTIGATION_PROMPT = """\
The initial checklist investigation was inconclusive for this finding. \
Perform a deeper investigation:

1. Trace the COMPLETE data flow across all available functions.
2. Look for indirect sanitisation (e.g., framework-level middleware).
3. Check if the function is only called from test code.
4. Assess if the vulnerability class applies to this language/framework.
5. Consider the security map context for trust boundaries.

Previous checklist result:
{previous_analysis}

Additional context:
{additional_context}

Provide your final verdict as the same JSON format.
"""


class Triager:
    """
    Deep scan triager.

    Investigates candidate findings and assigns verdicts.
    Checklist-first, tool-use fallback.
    """

    def __init__(self, llm_client: LLMClient, index: CodeIndex,
                 finding_store: FindingStore,
                 security_map: Optional[str] = None):
        self.llm = llm_client
        self.index = index
        self.store = finding_store
        self.security_map = security_map or ""

    def triage_all_candidates(self) -> Dict[str, Any]:
        """
        Triage all candidate findings that don't have a verdict yet.

        Returns stats on verdicts assigned.
        """
        stats = {"triaged": 0, "true_positive": 0, "false_positive": 0,
                 "needs_review": 0, "not_applicable": 0, "code_quality": 0,
                 "errors": 0}

        candidates = self.store.get_findings(state=FindingState.CANDIDATE)
        unverdict = [f for f in candidates if f.get("verdict") is None]

        logger.info("Triaging %d candidate findings", len(unverdict))

        for finding in unverdict:
            try:
                verdict, evidence, severity = self._triage_finding(finding)
                self._apply_verdict(finding, verdict, evidence, severity)
                stats["triaged"] += 1
                verdict_key = verdict.value.replace("-", "_")
                if verdict_key in stats:
                    stats[verdict_key] += 1
            except Exception as e:
                logger.error("Error triaging finding %s: %s", finding.get("id"), e)
                stats["errors"] += 1

        logger.info("Triage complete: %d triaged — TP:%d FP:%d NR:%d NA:%d CQ:%d",
                     stats["triaged"], stats["true_positive"], stats["false_positive"],
                     stats["needs_review"], stats["not_applicable"], stats["code_quality"])
        return stats

    def triage_finding_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Triage a single finding by ID."""
        finding = self.store.get_finding(finding_id)
        if not finding:
            logger.error("Finding not found: %s", finding_id)
            return None

        try:
            verdict, evidence, severity = self._triage_finding(finding)
            self._apply_verdict(finding, verdict, evidence, severity)
            return {
                "finding_id": finding_id,
                "verdict": verdict.value,
                "evidence": evidence,
                "severity": severity,
            }
        except Exception as e:
            logger.error("Error triaging finding %s: %s", finding_id, e)
            return None

    def _triage_finding(self, finding: Dict[str, Any]) -> Tuple[Verdict, str, Optional[Dict]]:
        """
        Run the triage checklist on a finding.

        Returns (verdict, evidence_report, severity_adjustment).
        """
        # Step 1: Build investigation context
        context = self._build_investigation_context(finding)

        # Step 2: Checklist investigation (primary)
        verdict, evidence, severity, confidence = self._checklist_investigation(finding, context)

        # Step 3: If inconclusive (needs-review with low confidence), escalate
        if verdict == Verdict.NEEDS_REVIEW and confidence < 0.6:
            logger.info("Finding %s inconclusive (%.2f), escalating to deep investigation",
                        finding.get("id"), confidence)
            verdict, evidence, severity, _ = self._deep_investigation(
                finding, context, evidence
            )

        return verdict, evidence, severity

    def _build_investigation_context(self, finding: Dict[str, Any]) -> str:
        """Build the context for investigating a finding."""
        file_path = finding.get("file_path", "")
        func_name = finding.get("function_name", "")

        parts = [
            f"## Candidate Finding",
            f"- **File**: {file_path}",
            f"- **Function**: {func_name}",
            f"- **Vulnerability Class**: {finding.get('vulnerability_class', '?')}",
            f"- **CWE**: {finding.get('cwe', '?')}",
            f"- **Description**: {finding.get('description', '?')}",
            f"- **Detection**: {finding.get('detection_technique', '?')}",
        ]

        # Get function body
        if func_name and file_path:
            # Try with just the function name (without class prefix)
            simple_name = func_name.split(".")[-1] if "." in func_name else func_name
            body = self.index.get_function_body(file_path, func_name)
            if not body:
                body = self.index.get_function_body(file_path, simple_name)
            if body:
                parts.append(f"\n### Function Body:\n```\n{body}\n```")

            # Get callers
            callers = self.index.get_callers(simple_name)
            if callers:
                caller_bodies = []
                for c in callers[:3]:  # Top 3 callers
                    cb = self.index.get_function_body(
                        c.get("file_path", ""), c.get("name", "")
                    )
                    if cb:
                        caller_bodies.append(
                            f"#### {c.get('qualified_name', c.get('name', '?'))} "
                            f"({c.get('file_path', '?')})\n```\n{cb}\n```"
                        )
                if caller_bodies:
                    parts.append(f"\n### Callers:\n" + "\n".join(caller_bodies))

            # Get callees
            callees = self.index.get_callees(file_path, simple_name)
            if callees:
                callee_bodies = []
                for callee_name in callees[:5]:
                    symbols = self.index.find_symbol(callee_name)
                    for s in symbols[:1]:
                        callee_bodies.append(
                            f"#### {s.get('qualified_name', callee_name)} "
                            f"({s.get('file_path', '?')})\n```\n{s.get('body', '?')}\n```"
                        )
                if callee_bodies:
                    parts.append(f"\n### Callees:\n" + "\n".join(callee_bodies))

        # Security map context
        if self.security_map:
            parts.append(f"\n### Security Map:\n{self.security_map}")

        return "\n".join(parts)

    def _checklist_investigation(self, finding: Dict[str, Any],
                                 context: str) -> Tuple[Verdict, str, Optional[Dict], float]:
        """Run the checklist investigation."""
        # Redact before sending
        redaction = redact_secrets_in_text(context)
        safe_context = redaction.redacted

        if not verify_no_secrets(safe_context):
            logger.error("Pre-send verification failed for finding %s", finding.get("id"))
            return Verdict.NEEDS_REVIEW, "Skipped: redaction verification failed", None, 0.0

        response_text, _ = self.llm.chat(TRIAGE_SYSTEM_PROMPT, safe_context)
        return self._parse_triage_response(response_text)

    def _deep_investigation(self, finding: Dict[str, Any], context: str,
                            previous_analysis: str) -> Tuple[Verdict, str, Optional[Dict], float]:
        """Escalate to deeper investigation when checklist is inconclusive."""
        # Gather additional context
        func_name = finding.get("function_name", "")
        simple_name = func_name.split(".")[-1] if "." in func_name else func_name

        additional = []
        # Search for related patterns
        related = self.index.full_text_search(finding.get("vulnerability_class", ""))
        if related:
            additional.append("### Related code mentioning this vulnerability class:")
            for r in related[:3]:
                additional.append(f"- {r.get('qualified_name', '?')} in {r.get('file_path', '?')}")

        additional_text = "\n".join(additional) if additional else "No additional context found."

        prompt = DEEP_INVESTIGATION_PROMPT.format(
            previous_analysis=previous_analysis,
            additional_context=additional_text,
        )

        # Redact
        redaction = redact_secrets_in_text(f"{context}\n\n{prompt}")
        safe_message = redaction.redacted

        if not verify_no_secrets(safe_message):
            return Verdict.NEEDS_REVIEW, previous_analysis, None, 0.5

        response_text, _ = self.llm.chat(TRIAGE_SYSTEM_PROMPT, safe_message)
        return self._parse_triage_response(response_text)

    def _apply_verdict(self, finding: Dict[str, Any], verdict: Verdict,
                       evidence: str, severity: Optional[Dict]):
        """Apply the verdict to the finding store."""
        finding_id = finding.get("id", "")

        success = self.store.set_verdict(finding_id, verdict, evidence_report=evidence)
        if not success and verdict == Verdict.TRUE_POSITIVE:
            logger.error("Failed to set true-positive verdict for %s (evidence gate?)", finding_id)

        # Auto-publish true-positives
        if verdict == Verdict.TRUE_POSITIVE and success:
            self.store.publish_finding(finding_id)

    @staticmethod
    def _parse_triage_response(response_text: str) -> Tuple[Verdict, str, Optional[Dict], float]:
        """Parse LLM triage response into verdict components."""
        text = response_text.strip()

        # Strip markdown code fences
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON from response
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                try:
                    result = json.loads(text[start:end + 1])
                except json.JSONDecodeError:
                    logger.warning("Failed to parse triage response: %s...", text[:200])
                    return Verdict.NEEDS_REVIEW, f"Parse error: {text[:500]}", None, 0.0
            else:
                return Verdict.NEEDS_REVIEW, f"Parse error: {text[:500]}", None, 0.0

        # Extract verdict
        verdict_str = result.get("verdict", "needs-review")
        try:
            verdict = Verdict(verdict_str)
        except ValueError:
            logger.warning("Unknown verdict: %s, defaulting to needs-review", verdict_str)
            verdict = Verdict.NEEDS_REVIEW

        evidence = result.get("evidence_report", "")
        confidence = result.get("confidence", 0.5)
        severity = result.get("severity_adjustment")

        return verdict, evidence, severity, confidence
