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
Vite environment-variable analysis.

Vite inlines every VITE_-prefixed variable into the client bundle at build time,
so its value ships to every visitor. That is a property of the build, not a
judgement about the value, which is why this runs as a rule and never reaches
the LLM: it is faster, free, and cannot miss one.

Values are never returned, logged, or reported — only key names and locations.
"""

import glob
import logging
import os
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")

# Names suggesting the value is meant to stay private. Exposure is certain either
# way; this only orders the findings.
_SENSITIVE_NAME = re.compile(
    r"(?i)(secret|password|passwd|token|api_?key|licen[cs]e|credential|private)"
)


def parse_env_file(path: str) -> List[str]:
    """Return the key names defined in a .env file, in order. Never the values."""
    keys: List[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.lstrip().startswith("#"):
                    continue
                match = _ENV_LINE.match(line)
                if match:
                    keys.append(match.group(1))
    except OSError as e:
        logger.warning("Cannot read env file %s: %s", path, e)
    return keys


def scan_vite_env(target_path: str,
                  source_reads: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """
    Report every VITE_ key defined under target_path as client-exposed.

    source_reads maps a variable name to the files reading it via
    import.meta.env, used to name the use sites in each finding.
    """
    if not os.path.isdir(target_path):
        return []

    by_key: Dict[str, List[str]] = {}
    for path in sorted(glob.glob(os.path.join(target_path, ".env*"))):
        for key in parse_env_file(path):
            if key.startswith("VITE_"):
                by_key.setdefault(key, []).append(os.path.basename(path))

    findings: List[Dict[str, Any]] = []
    for key, files in sorted(by_key.items()):
        sites = source_reads.get(key, [])
        sensitive = bool(_SENSITIVE_NAME.search(key))
        description = (
            "%s is inlined into the client bundle by Vite, so its value is "
            "readable by anyone who loads the application. Defined in: %s."
            % (key, ", ".join(sorted(set(files))))
        )
        description += (
            " Read at: %s." % ", ".join(sorted(set(sites))) if sites
            else " No import.meta.env read of this key was found in the indexed"
                 " sources; it may be unused."
        )
        if sensitive:
            description += (
                " The name suggests a value that is not meant to be public;"
                " move it behind a server-side endpoint rather than shipping it."
            )
        findings.append({
            "key": key,
            "files": sorted(set(files)),
            "use_sites": sorted(set(sites)),
            "severity_tier": "ERROR" if sensitive else "INFO",
            "description": description,
        })

    if findings:
        logger.info("Vite env: %d VITE_ keys exposed in the client bundle",
                    len(findings))
    return findings
