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
Deep scan coverage tracker.

Tracks evaluation completeness and provides the "done" signal (§5.7):
- Derives coverage checklist from the index (FR-067)
- Maps goals to components (FR-068)
- Closes items when evidence exists (FR-069)
- Signals complete when all items closed (FR-071)

Constitution alignment:
  VI. Coverage Before Yield — auto-stop requires BOTH coverage-complete
      AND yield-below-threshold
"""

import logging
from typing import Any, Dict, List, Optional

from finding_store import FindingStore
from indexer import CodeIndex

logger = logging.getLogger(__name__)


class CoverageGuide:
    """
    Deep scan coverage tracker.

    Generates a checklist of what must be evaluated, tracks progress,
    and signals when evaluation is complete.
    """

    def __init__(self, index: CodeIndex, finding_store: FindingStore):
        self.index = index
        self.store = finding_store

    def generate_checklist(self, goals: Optional[List[str]] = None) -> List[str]:
        """
        Generate a coverage checklist from the index (FR-067).

        Each file with functions gets a checklist item.
        Custom goals can be added on top.

        Returns list of coverage item IDs.
        """
        item_ids: List[str] = []
        stats = self.index.get_stats()

        if stats["total_functions"] == 0:
            logger.warning("Index is empty, no coverage checklist generated")
            return item_ids

        # One item per file with functions
        all_funcs = self.index.get_all_functions()
        files_seen = set()
        for func in all_funcs:
            fp = func.get("file_path", "")
            if fp and fp not in files_seen:
                files_seen.add(fp)
                func_count = len(self.index.list_functions_in_file(fp))
                item_id = self.store.add_coverage_item(
                    component=fp,
                    goal=f"Evaluate {func_count} function(s) for security vulnerabilities",
                    bar=f"Rule-based + exploratory detection completed on all {func_count} function(s)",
                )
                item_ids.append(item_id)

        # Add custom goals
        if goals:
            for goal in goals:
                item_id = self.store.add_coverage_item(
                    component="custom",
                    goal=goal,
                    bar="Operator confirms completion",
                )
                item_ids.append(item_id)

        logger.info("Coverage checklist: %d items (%d files + %d custom goals)",
                     len(item_ids), len(files_seen), len(goals or []))
        return item_ids

    def mark_file_complete(self, file_path: str, evidence: str) -> bool:
        """
        Mark a file's coverage item as complete with evidence (FR-069).

        Evidence should describe what was done (e.g., "rule-based + exploratory,
        2 candidates found, 1 true-positive, 1 false-positive").
        """
        status = self.store.get_coverage_status()
        for item in status.get("items", []):
            if item["component"] == file_path and item["status"] == "open":
                return self.store.close_coverage_item(item["id"], evidence)
        logger.warning("No open coverage item for %s", file_path)
        return False

    def is_complete(self) -> bool:
        """Check if all coverage items are closed (FR-071)."""
        return self.store.is_coverage_complete()

    def should_stop(self, yield_below_threshold: bool = False) -> bool:
        """
        Determine if evaluation should stop (Constitution VI).

        Auto-stop requires BOTH:
        1. Coverage is complete (all checklist items closed)
        2. Yield is below threshold (no new findings in recent iterations)
        """
        if not self.is_complete():
            return False
        if not yield_below_threshold:
            return False
        return True

    def get_progress(self) -> Dict[str, Any]:
        """Get coverage progress as a summary."""
        status = self.store.get_coverage_status()
        return {
            "total": status["total"],
            "closed": status["closed"],
            "open": status["open"],
            "complete": status["complete"],
            "percent": round(status["closed"] / status["total"] * 100, 1) if status["total"] > 0 else 0,
        }
