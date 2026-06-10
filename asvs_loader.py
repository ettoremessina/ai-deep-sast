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
ASVS Loader — parse ASVS 5.0.0 JSON into matchable security requirements.

Loads structured ASVS requirements and provides lookup by:
- Requirement ID (e.g. "1.2.4")
- Chapter (e.g. "V1")
- CWE mapping (e.g. "CWE-89")
- Keyword search
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

DEFAULT_ASVS_PATH = os.path.join(os.path.dirname(__file__), "config", "asvs", "asvs_5.0.0.json")


class ASVSRequirement:
    """A single ASVS requirement."""

    def __init__(self, req_id: str, chapter: str, chapter_name: str,
                 description: str, level: int,
                 cwe: Optional[List[str]] = None,
                 keywords: Optional[List[str]] = None):
        self.id = req_id
        self.chapter = chapter
        self.chapter_name = chapter_name
        self.description = description
        self.level = level
        self.cwe = cwe or []
        self.keywords = [k.lower() for k in (keywords or [])]

    @property
    def full_id(self) -> str:
        return f"v5.0.0-{self.id}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "full_id": self.full_id,
            "chapter": self.chapter,
            "chapter_name": self.chapter_name,
            "description": self.description,
            "level": self.level,
            "cwe": self.cwe,
            "keywords": self.keywords,
        }

    def to_prompt_text(self) -> str:
        """Format for inclusion in an LLM prompt."""
        cwe_str = ", ".join(self.cwe) if self.cwe else "N/A"
        return f"- {self.full_id}: {self.description} ({cwe_str})"

    def __repr__(self) -> str:
        return f"ASVSRequirement({self.full_id})"


class ASVSLoader:
    """
    Loads and indexes ASVS 5.0.0 requirements for rule-guided scanning.

    Provides fast lookups by ID, chapter, CWE, and keyword.
    """

    def __init__(self, path: Optional[str] = None):
        self._path = path or DEFAULT_ASVS_PATH
        self._requirements: Dict[str, ASVSRequirement] = {}
        self._by_chapter: Dict[str, List[str]] = {}
        self._by_cwe: Dict[str, List[str]] = {}
        self._loaded = False

    def load(self) -> int:
        """Load ASVS requirements from JSON. Returns count loaded."""
        if not os.path.exists(self._path):
            logger.error("ASVS file not found: %s", self._path)
            return 0

        try:
            with open(self._path, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load ASVS: %s", e)
            return 0

        for req_data in data.get("requirements", []):
            req = ASVSRequirement(
                req_id=req_data["id"],
                chapter=req_data.get("chapter", ""),
                chapter_name=req_data.get("chapter_name", ""),
                description=req_data.get("description", ""),
                level=req_data.get("level", 1),
                cwe=req_data.get("cwe", []),
                keywords=req_data.get("keywords", []),
            )
            self._requirements[req.id] = req

            # Index by chapter
            ch = req.chapter
            if ch not in self._by_chapter:
                self._by_chapter[ch] = []
            self._by_chapter[ch].append(req.id)

            # Index by CWE
            for cwe in req.cwe:
                if cwe not in self._by_cwe:
                    self._by_cwe[cwe] = []
                self._by_cwe[cwe].append(req.id)

        self._loaded = True
        logger.info("ASVS loaded: %d requirements across %d chapters",
                     len(self._requirements), len(self._by_chapter))
        return len(self._requirements)

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def get(self, req_id: str) -> Optional[ASVSRequirement]:
        """Get a requirement by ID (e.g. '1.2.4')."""
        return self._requirements.get(req_id)

    def get_by_chapter(self, chapter: str) -> List[ASVSRequirement]:
        """Get all requirements for a chapter (e.g. 'V1')."""
        ids = self._by_chapter.get(chapter, [])
        return [self._requirements[rid] for rid in ids]

    def get_by_cwe(self, cwe: str) -> List[ASVSRequirement]:
        """Get requirements mapped to a CWE (e.g. 'CWE-89')."""
        ids = self._by_cwe.get(cwe, [])
        return [self._requirements[rid] for rid in ids]

    def search_keywords(self, query: str) -> List[ASVSRequirement]:
        """Find requirements matching a keyword query."""
        q = query.lower()
        return [req for req in self._requirements.values()
                if any(q in kw for kw in req.keywords)
                or q in req.description.lower()]

    def get_all(self) -> List[ASVSRequirement]:
        """Get all loaded requirements."""
        return list(self._requirements.values())

    def get_all_ids(self) -> Set[str]:
        """Get all requirement IDs."""
        return set(self._requirements.keys())

    def format_for_prompt(self, req_ids: List[str]) -> str:
        """Format a list of requirement IDs for inclusion in an LLM prompt."""
        lines = []
        for rid in req_ids:
            req = self._requirements.get(rid)
            if req:
                lines.append(req.to_prompt_text())
        return "\n".join(lines)

    def get_stats(self) -> Dict[str, Any]:
        """Get loader statistics."""
        return {
            "total_requirements": len(self._requirements),
            "chapters": len(self._by_chapter),
            "cwe_mappings": len(self._by_cwe),
            "loaded": self._loaded,
        }
