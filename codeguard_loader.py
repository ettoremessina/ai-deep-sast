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
CodeGuard Loader — parse CodeGuard markdown rules into matchable security guidelines.

Loads CodeGuard rules from markdown files with YAML frontmatter and provides
lookup by rule ID, language, and domain.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

DEFAULT_CODEGUARD_DIR = os.path.join(os.path.dirname(__file__), "config", "codeguard")


class CodeGuardRule:
    """A single CodeGuard security rule."""

    def __init__(self, rule_id: str, description: str,
                 languages: Optional[List[str]] = None,
                 body: str = "", file_path: str = ""):
        self.rule_id = rule_id
        self.description = description
        self.languages = [lang.lower() for lang in (languages or [])]
        self.body = body
        self.file_path = file_path
        self._domain = self._extract_domain()

    @property
    def domain(self) -> str:
        return self._domain

    def _extract_domain(self) -> str:
        """Extract the domain name from the rule ID."""
        # e.g. "codeguard-0-input-validation-injection" → "input-validation-injection"
        parts = self.rule_id.split("-", 2)
        return parts[2] if len(parts) > 2 else self.rule_id

    def applies_to_language(self, language: str) -> bool:
        """Check if this rule applies to a given language."""
        if not self.languages:
            return True  # No language restriction = applies to all
        return language.lower() in self.languages

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "domain": self.domain,
            "languages": self.languages,
        }

    def to_prompt_text(self) -> str:
        """Format for inclusion in an LLM prompt."""
        return f"- CodeGuard [{self.rule_id}]: {self.description}"

    def get_relevant_body(self, max_chars: int = 2000) -> str:
        """Get a truncated version of the rule body for prompt context."""
        if len(self.body) <= max_chars:
            return self.body
        return self.body[:max_chars] + "\n... (truncated)"

    def __repr__(self) -> str:
        return f"CodeGuardRule({self.rule_id})"


def _parse_frontmatter(content: str) -> tuple:
    """Parse YAML frontmatter and body from markdown content.

    Returns (metadata_dict, body_text).
    """
    if not content.startswith("---"):
        return {}, content

    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, content

    frontmatter = parts[1].strip()
    body = parts[2].strip()

    metadata: Dict[str, Any] = {}
    current_key = None
    current_list: Optional[List[str]] = None

    for line in frontmatter.split("\n"):
        line = line.strip()
        if not line:
            continue

        # List item
        if line.startswith("- ") and current_key:
            if current_list is None:
                current_list = []
                metadata[current_key] = current_list
            current_list.append(line[2:].strip())
            continue

        # Key: value
        match = re.match(r"^(\w+):\s*(.*)", line)
        if match:
            current_key = match.group(1)
            value = match.group(2).strip()
            current_list = None
            if value:
                metadata[current_key] = value
            # If no value, might be followed by a list
            continue

    return metadata, body


class CodeGuardLoader:
    """
    Loads and indexes CodeGuard rules for rule-guided scanning.

    Parses markdown files with YAML frontmatter from a directory.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self._rules_dir = rules_dir or DEFAULT_CODEGUARD_DIR
        self._rules: Dict[str, CodeGuardRule] = {}
        self._by_language: Dict[str, List[str]] = {}
        self._by_domain: Dict[str, str] = {}
        self._loaded = False

    def load(self) -> int:
        """Load CodeGuard rules from markdown files. Returns count loaded."""
        if not os.path.isdir(self._rules_dir):
            logger.error("CodeGuard directory not found: %s", self._rules_dir)
            return 0

        count = 0
        for filename in sorted(os.listdir(self._rules_dir)):
            if not filename.endswith(".md"):
                continue

            file_path = os.path.join(self._rules_dir, filename)
            try:
                with open(file_path, "r") as f:
                    content = f.read()
            except OSError as e:
                logger.warning("Cannot read %s: %s", file_path, e)
                continue

            metadata, body = _parse_frontmatter(content)

            # Extract rule_id from frontmatter or body
            rule_id = None
            for line in body.split("\n"):
                if line.startswith("rule_id:"):
                    rule_id = line.split(":", 1)[1].strip()
                    break
            if not rule_id:
                rule_id = filename.replace(".md", "")

            description = metadata.get("description", "")
            languages = metadata.get("languages", [])
            if isinstance(languages, str):
                languages = [languages]

            rule = CodeGuardRule(
                rule_id=rule_id,
                description=description,
                languages=languages,
                body=body,
                file_path=file_path,
            )
            self._rules[rule.rule_id] = rule
            self._by_domain[rule.domain] = rule.rule_id

            # Index by language
            for lang in rule.languages:
                if lang not in self._by_language:
                    self._by_language[lang] = []
                self._by_language[lang].append(rule.rule_id)

            count += 1

        self._loaded = count > 0
        logger.info("CodeGuard loaded: %d rules across %d languages",
                     count, len(self._by_language))
        return count

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def get(self, rule_id: str) -> Optional[CodeGuardRule]:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_by_domain(self, domain: str) -> Optional[CodeGuardRule]:
        """Get a rule by domain name (e.g. 'input-validation-injection')."""
        rule_id = self._by_domain.get(domain)
        if rule_id:
            return self._rules.get(rule_id)
        return None

    def get_for_language(self, language: str) -> List[CodeGuardRule]:
        """Get all rules applicable to a programming language."""
        lang = language.lower()
        rule_ids = self._by_language.get(lang, [])
        result = [self._rules[rid] for rid in rule_ids if rid in self._rules]
        # Also include rules with no language restriction
        for rule in self._rules.values():
            if not rule.languages and rule not in result:
                result.append(rule)
        return result

    def get_all(self) -> List[CodeGuardRule]:
        """Get all loaded rules."""
        return list(self._rules.values())

    def get_all_ids(self) -> Set[str]:
        """Get all rule IDs."""
        return set(self._rules.keys())

    def format_for_prompt(self, rule_ids: List[str], max_body_chars: int = 500) -> str:
        """Format a list of rule IDs for inclusion in an LLM prompt."""
        lines = []
        for rid in rule_ids:
            rule = self._rules.get(rid)
            if rule:
                lines.append(rule.to_prompt_text())
                if max_body_chars > 0:
                    body_excerpt = rule.get_relevant_body(max_body_chars)
                    # Extract just key bullet points
                    key_lines = [l for l in body_excerpt.split("\n")
                                 if l.strip().startswith(("- ", "* ", "1.", "2.", "3."))
                                 and len(l.strip()) > 10][:5]
                    if key_lines:
                        lines.extend(["  " + l.strip() for l in key_lines])
        return "\n".join(lines)

    def get_stats(self) -> Dict[str, Any]:
        """Get loader statistics."""
        return {
            "total_rules": len(self._rules),
            "languages": sorted(self._by_language.keys()),
            "domains": sorted(self._by_domain.keys()),
            "loaded": self._loaded,
        }
