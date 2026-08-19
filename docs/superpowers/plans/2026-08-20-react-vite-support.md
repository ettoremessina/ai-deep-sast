# React + Vite Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a brute-force deep scan see a React + Vite project's real security surface — config files, `.env` variables, and every function — while costing less than it does today.

**Architecture:** All work happens inside the existing brute-force path. The indexer stops losing same-named functions, skips trivial ones, and emits whole-file units for config files that contain no functions. A deterministic `.env` analyser produces findings without calling the LLM. The brute-force prompts gain React/Vite vulnerability classes.

**Tech Stack:** Python 3.11, tree-sitter (`tree_sitter_typescript`), pytest, SQLite via `finding_store.py`.

## Global Constraints

- Work on branch `fix/index-modern-language-idioms`. Do not create a new branch.
- Spec: `docs/superpowers/specs/2026-08-20-react-vite-support-design.md`. Its measured numbers are the acceptance criteria.
- Run the suite with the venv's bin on PATH — `tests/test_rules.py` shells out to the `semgrep` executable:
  `PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/ -q`
- Baseline before starting: **291 tests pass**. Never commit with fewer passing.
- Tests are written before implementation, and must be seen to fail first.
- No new scan mode, no work on guided/Semgrep modes, no Vue/Svelte/Angular support.
- `.env` values are never written to findings, logs, or reports — key names only.
- Every new file-reading path degrades to a logged warning, never an exception: these run inside scans lasting hours.
- Follow the existing style: lazy `logger.warning("...%s", x)` formatting, type hints, Apache-2.0 header on new files.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `indexer.py` | Key uniqueness, honest counts, trivial-function filter, whole-file units, entity-tolerant parse warning | Modify |
| `vite_env.py` | Parse `.env*` files, cross-reference `import.meta.env` reads, emit findings. New module: the logic is self-contained and does not belong in the tree-sitter indexer. | Create |
| `detector.py` | React/Vite vulnerability classes in the two brute-force prompts | Modify |
| `deepscan.py` | `--min-function-lines` flag; run the `.env` analyser in the brute-force pipeline | Modify |
| `tests/test_indexer.py` | Key uniqueness, trivial filter, whole-file units, parse warning | Modify |
| `tests/test_vite_env.py` | `.env` parsing, cross-referencing, value redaction | Create |

---

## Task 1: Stop losing same-named functions

Today `FunctionInfo.key` is `file_path:qualified_name`. Two functions named
`renderCell` in one file produce the same key, and `build()` stores functions in
a dict keyed by it, so the second silently replaces the first. On Chrono_Web this
loses 308 of 1839 functions; `src/pages/ComponentSearch.tsx` parses 64 and indexes 32.

**Files:**
- Modify: `indexer.py:228-230` (`FunctionInfo.key`)
- Modify: `indexer.py:597` (`stats["functions_found"]`)
- Test: `tests/test_indexer.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `FunctionInfo.key` → `f"{file_path}:{qualified_name}:{start_line}"`. Task 3 and Task 4 rely on keys being unique per function.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_indexer.py`:

```python
def test_same_named_functions_in_one_file_all_indexed(tmp_path):
    """Two callbacks with the same name must not overwrite each other."""
    f = tmp_path / "grid.tsx"
    f.write_text(
        "export const getColumns = () => [\n"
        "  { renderCell: (p) => <span>{p.a}</span> },\n"
        "  { renderCell: (p) => <span>{p.b}</span> },\n"
        "];\n"
    )
    idx = CodeIndex()
    stats = idx.build(str(f))
    names = [fn["name"] for fn in idx.get_all_functions()]
    assert names.count("renderCell") == 2
    assert stats["functions_found"] == len(idx.get_all_functions())


def test_key_includes_start_line():
    a = FunctionInfo("f", "a.ts", 1, 2, "body", "typescript")
    b = FunctionInfo("f", "a.ts", 10, 11, "body", "typescript")
    assert a.key != b.key
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_indexer.py -k "same_named or start_line" -v
```

Expected: `test_key_includes_start_line` FAILS with `assert 'a.ts:f' != 'a.ts:f'`; `test_same_named_functions_in_one_file_all_indexed` FAILS with `assert 1 == 2`.

- [ ] **Step 3: Make the key unique**

Replace `indexer.py:228-230`:

```python
    @property
    def key(self) -> str:
        # start_line disambiguates same-named functions in one file: React files
        # routinely define many callbacks called renderCell, and without it each
        # overwrites the previous one in the index dict.
        return f"{self.file_path}:{self.qualified_name}:{self.start_line}"
```

- [ ] **Step 4: Report the count that survives indexing**

At `indexer.py:597`, replace `stats["functions_found"] += len(functions)` with:

```python
                # Count what is retrievable, not what was parsed: anything the
                # key collapses would otherwise be reported as analysed.
                stats["functions_found"] += len({func.key for func in functions})
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_indexer.py -k "same_named or start_line" -v
```

Expected: PASS.

- [ ] **Step 6: Run the full suite — this changes a widely used key**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/ -q
```

Expected: 293 passed. If `test_finding_store.py` or `test_detector.py` fail, the key format is reaching fingerprints; stop and report rather than adjusting the test to match.

- [ ] **Step 7: Verify against the real project**

```bash
.venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from indexer import CodeIndex
idx = CodeIndex(); st = idx.build('/Users/ettore/Temp/Chrono_Web')
print('functions_found:', st['functions_found'], '| retrievable:', len(idx.get_all_functions()))
"
```

Expected: both numbers **1839**, equal to each other.

- [ ] **Step 8: Check resume compatibility**

Fingerprints in an existing `deepscan.db` were computed under the old key. Confirm whether `finding_store.compute_fingerprint` consumes `FunctionInfo.key`:

```bash
grep -n "def compute_fingerprint" -A 12 finding_store.py
```

If it takes `file_path` and `function_name` (not `key`), fingerprints are unaffected — note that in the commit message. If it consumes `key`, stop: resuming an existing scan would re-analyse everything and duplicate findings, and that needs a decision before proceeding.

- [ ] **Step 9: Commit**

```bash
git add indexer.py tests/test_indexer.py
git commit -m "fix(indexer): stop same-named functions overwriting each other

FunctionInfo.key omitted the start line, so two functions with the same
qualified name in one file collapsed to a single index entry. React files hit
this constantly: ComponentSearch.tsx parses 64 functions and indexed 32,
because renderCell and renderHeader each occur 16 times.

308 of 1839 functions (17%) were lost on a real project, and functions_found
counted before the collapse, so the scan reported analysing code it never saw."
```

---

## Task 2: Skip trivial functions

46% of parsed functions on Chrono_Web are 1–3 lines — `map`/`filter` predicates
and MUI render callbacks like `x => x.compSubTypeAttValId`. Each costs a full LLM
call (~36 s) and carries no security signal.

**Files:**
- Modify: `indexer.py` (`CodeIndex.__init__`, `build`)
- Modify: `deepscan.py` (CLI flag, orchestrator wiring)
- Test: `tests/test_indexer.py`

**Interfaces:**
- Consumes: `FunctionInfo.key` from Task 1.
- Produces: `CodeIndex(min_function_lines: int = 4)`; `stats["functions_skipped_trivial"]`; `deepscan.py --min-function-lines N`.

- [ ] **Step 1: Write the failing test**

```python
def test_trivial_functions_skipped_by_default(tmp_path):
    f = tmp_path / "cb.ts"
    f.write_text(
        "export const pick = (x) => x.id;\n"
        "export function real(items) {\n"
        "    const out = [];\n"
        "    for (const i of items) {\n"
        "        out.push(i.id);\n"
        "    }\n"
        "    return out;\n"
        "}\n"
    )
    idx = CodeIndex()
    stats = idx.build(str(f))
    names = [fn["name"] for fn in idx.get_all_functions()]
    assert names == ["real"]
    assert stats["functions_skipped_trivial"] == 1


def test_threshold_can_be_lowered(tmp_path):
    f = tmp_path / "cb.ts"
    f.write_text("export const pick = (x) => x.id;\n")
    idx = CodeIndex(min_function_lines=1)
    idx.build(str(f))
    assert [fn["name"] for fn in idx.get_all_functions()] == ["pick"]
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_indexer.py -k "trivial or threshold" -v
```

Expected: FAIL — `CodeIndex()` takes no `min_function_lines`, and `functions_skipped_trivial` is not in stats.

- [ ] **Step 3: Add the threshold to CodeIndex**

In `CodeIndex.__init__`, add the parameter and store it. Above the class, add the constant:

```python
# Bodies at or below this many non-blank lines are callbacks and predicates
# (`x => x.id`), not analysable units. Overridable via --min-function-lines.
DEFAULT_MIN_FUNCTION_LINES = 4
```

```python
    def __init__(self, ..., min_function_lines: int = DEFAULT_MIN_FUNCTION_LINES):
        ...
        self.min_function_lines = min_function_lines
```

- [ ] **Step 4: Filter in build() and count the skips**

Add `"functions_skipped_trivial": 0` to the `stats` dict at `indexer.py:559`. Then, in the loop at `indexer.py:585`, replace the storing block's first line so filtering happens before storage:

```python
                for func in functions:
                    if _body_line_count(func.body) < self.min_function_lines:
                        stats["functions_skipped_trivial"] += 1
                        continue
                    self._functions[func.key] = func
                    self._by_name[func.name].append(func.key)
                    self._by_file[file_path].append(func.key)
```

Note the counter increments before `continue`, and `functions_found` must count only stored functions — replace the Task 1 line with:

```python
                stats["functions_found"] = len(self._functions)
```

Add the helper near `_get_language_for_file`:

```python
def _body_line_count(body: str) -> int:
    """Non-blank lines in a function body."""
    return len([line for line in (body or "").splitlines() if line.strip()])
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_indexer.py -k "trivial or threshold" -v
```

Expected: PASS.

- [ ] **Step 6: Report the skips in the scan log**

In `indexer.py:610`, extend the summary so a 46% reduction is visible rather than silent:

```python
        logger.info("Index built: %d files, %d functions, %d calls (%d trivial skipped)",
                     stats["files_parsed"], stats["functions_found"],
                     stats["calls_found"], stats["functions_skipped_trivial"])
```

- [ ] **Step 7: Wire the CLI flag**

In `deepscan.py`, after the `--max-tokens` argument, add:

```python
    parser.add_argument("--min-function-lines", type=int, default=None,
                        help="Minimum non-blank body lines for a function to be analysed "
                             "(default: 4). One-line callbacks such as `x => x.id` carry no "
                             "security signal but cost a full LLM call each. Use 1 to analyse "
                             "everything.")
```

Add `min_function_lines: Optional[int] = None` to `Orchestrator.__init__`, store it as `self.min_function_lines`, pass `min_function_lines=args.min_function_lines` where the orchestrator is constructed, and in the method that builds the index pass it through:

```python
        kwargs = {}
        if self.min_function_lines:
            kwargs["min_function_lines"] = self.min_function_lines
        self.index = CodeIndex(**kwargs)
```

Locate that construction first:

```bash
grep -n "CodeIndex(" deepscan.py
```

- [ ] **Step 8: Verify the flag end to end**

```bash
.venv/bin/python deepscan.py --help | grep -A 4 "min-function-lines"
.venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from indexer import CodeIndex
for n in (4, 1):
    idx = CodeIndex(min_function_lines=n)
    st = idx.build('/Users/ettore/Temp/Chrono_Web')
    print('min_function_lines=%d -> %d unita, %d saltate' % (n, st['functions_found'], st['functions_skipped_trivial']))
"
```

Expected: `min_function_lines=4` → **993** units, 846 skipped. `min_function_lines=1` → 1839 units, 0 skipped.

- [ ] **Step 9: Run the full suite and commit**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/ -q
git add indexer.py deepscan.py tests/test_indexer.py
git commit -m "feat(indexer): skip trivial function bodies

46% of the functions parsed from a real React project are 1-3 line callbacks
and predicates (x => x.id, MUI renderCell) that cost a full LLM call each and
carry no security signal. Skipping them takes that project from 1839 units to
993 — below the 1531 it analysed before same-named functions stopped being
dropped, while now analysing strictly more real code.

The threshold is a flag, not a constant, and skipped functions are counted in
the scan summary: a silent 46% reduction would be indistinguishable from a bug."
```

---

## Task 3: Analysable units from config files with no functions

`src/configs/keycloak.ts` (full OIDC config), `src/configVariables.ts`
(8 `import.meta.env` reads) and `src/main.tsx` (auth provider wiring) contain no
function declarations, so today they reach nothing. Most of the other 118
function-less files are barrel re-exports with nothing to analyse.

**Files:**
- Modify: `indexer.py` (`build`, plus two new module-level helpers)
- Test: `tests/test_indexer.py`

**Interfaces:**
- Consumes: `_body_line_count` and the stats dict from Task 2.
- Produces: units whose `name` is `"(file)"` and whose `body` is the whole file text; `stats["whole_file_units"]`.

- [ ] **Step 1: Write the failing test**

```python
CONFIG_FILE = """\
const configVariables = {
    backendBaseUrl: import.meta.env.VITE_BACKEND_URL as string,
};
export default configVariables;
"""

# Contains "Auth", which matches the auth signal. Only the re-export check keeps
# it out — which is exactly what this fixture is here to exercise.
BARREL_FILE = """\
export * from './AuthenticatedLayout';
export * from './PageLayout';
"""


def test_config_file_without_functions_becomes_a_unit(tmp_path):
    (tmp_path / "configVariables.ts").write_text(CONFIG_FILE)
    idx = CodeIndex()
    stats = idx.build(str(tmp_path))
    units = idx.get_all_functions()
    assert len(units) == 1
    assert units[0]["name"] == "(file)"
    assert "VITE_BACKEND_URL" in units[0]["body"]
    assert stats["whole_file_units"] == 1


def test_barrel_file_is_not_a_unit(tmp_path):
    (tmp_path / "index.ts").write_text(BARREL_FILE)
    idx = CodeIndex()
    stats = idx.build(str(tmp_path))
    assert idx.get_all_functions() == []
    assert stats["whole_file_units"] == 0


def test_oversized_config_file_is_skipped_not_truncated(tmp_path):
    big = tmp_path / "huge.ts"
    big.write_text("const c = { url: 'https://x' };\n" + ("// filler\n" * 20000))
    idx = CodeIndex()
    stats = idx.build(str(big))
    assert idx.get_all_functions() == []
    assert stats["whole_file_units"] == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_indexer.py -k "config_file or barrel or oversized" -v
```

Expected: FAIL — `whole_file_units` missing from stats, no units produced.

- [ ] **Step 3: Add the selection helpers**

Add near `_get_language_for_file` in `indexer.py`:

```python
# A file with no functions is worth analysing when it configures something. The
# signal list is deliberately broad: a false positive costs one LLM call, a false
# negative is a blind spot in auth or configuration analysis.
_CONFIG_SIGNALS = (
    re.compile(r"import\.meta\.env|process\.env"),
    re.compile(r"https?://"),
    re.compile(r"export\s+(default\s+)?(const|var|let)\s+\w+\s*(:[^=]+)?=\s*\{"),
    re.compile(r"localStorage|sessionStorage|document\.cookie"),
    re.compile(r"(?i)\b(token|secret|apikey|api_key|credential|password)\b"),
    re.compile(r"(?i)(auth|oidc|keycloak|oauth|jwt|login|permission|role)"),
    re.compile(r"window\.(location|history|open)|document\.(write|getElementById)"),
    re.compile(r"defineConfig|createRoot|configureStore|new\s+[A-Z]\w*Client\s*\("),
)

# Lines that carry no behaviour: a file made only of these is a barrel re-export.
_REEXPORT_ONLY = re.compile(
    r"^\s*(//.*|/\*.*|\*.*|import\s.*|export\s+\*.*|"
    r"export\s+\{[^}]*\}\s*(from\s+.*)?;?|)$"
)

# Whole-file units are sent to the LLM in one prompt; past this they crowd out
# the answer, so they are reported as skipped rather than silently truncated.
MAX_WHOLE_FILE_CHARS = 20000


def _is_analysable_config(source: str) -> bool:
    """True when a function-less file configures something worth analysing."""
    if all(_REEXPORT_ONLY.match(line) for line in source.splitlines()):
        return False
    return any(rx.search(source) for rx in _CONFIG_SIGNALS)
```

`indexer.py` does not import `re` today. Add it to the stdlib import block at
`indexer.py:33-36`, keeping alphabetical order:

```python
import hashlib
import json
import logging
import os
import re
```

- [ ] **Step 4: Emit the unit in build()**

`indexer.py:578` currently skips any recognised file that yielded no functions.
Replace that block:

```python
                if not functions and _get_language_for_file(file_path):
                    unit = self._whole_file_unit(file_path)
                    if unit is None:
                        stats["files_skipped"] += 1
                        continue
                    self._remove_file(file_path)
                    self._functions[unit.key] = unit
                    self._by_name[unit.name].append(unit.key)
                    self._by_file[file_path].append(unit.key)
                    self._file_hashes[file_path] = content_hash
                    stats["files_parsed"] += 1
                    stats["whole_file_units"] += 1
                    stats["functions_found"] = len(self._functions)
                    continue
```

Add `"whole_file_units": 0` to the stats dict, and the method to `CodeIndex`:

```python
    def _whole_file_unit(self, file_path: str) -> Optional[FunctionInfo]:
        """A function-less config file as a single analysable unit, or None."""
        try:
            with open(file_path, encoding="utf-8", errors="replace") as handle:
                source = handle.read()
        except OSError as e:
            logger.warning("Cannot read %s for config analysis: %s", file_path, e)
            return None

        if len(source) > MAX_WHOLE_FILE_CHARS:
            logger.warning("Config file %s is %d chars (limit %d) - not analysed",
                           file_path, len(source), MAX_WHOLE_FILE_CHARS)
            return None

        if not _is_analysable_config(source):
            return None

        return FunctionInfo(
            name="(file)", file_path=file_path, start_line=1,
            end_line=len(source.splitlines()) or 1, body=source,
            language=_get_language_for_file(file_path) or "",
        )
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_indexer.py -k "config_file or barrel or oversized" -v
```

Expected: PASS.

- [ ] **Step 6: Verify the selection against the real project**

```bash
.venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from indexer import CodeIndex
idx = CodeIndex(); st = idx.build('/Users/ettore/Temp/Chrono_Web')
units = [f for f in idx.get_all_functions() if f['name'] == '(file)']
print('whole-file units:', st['whole_file_units'])
for u in sorted(units, key=lambda x: x['file_path']):
    print('  ', u['file_path'].replace('/Users/ettore/Temp/Chrono_Web/', ''))
"
```

Expected: **9 units**, and the list must include `src/configVariables.ts`,
`src/configs/keycloak.ts` and `src/main.tsx`. If any of those three is absent the
signal list is too narrow — widen it and re-run rather than accepting the result.

- [ ] **Step 7: Run the full suite and commit**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/ -q
git add indexer.py tests/test_indexer.py
git commit -m "feat(indexer): analyse config files that declare no functions

The unit of analysis was the function, so a file without one contributed
nothing: on a real React project that hid the whole OIDC configuration, the
eight import.meta.env reads, and the auth provider wiring in main.tsx.

Files with no functions are now emitted as a single whole-file unit when their
content signals configuration, and rejected when they are barrel re-exports.
That selects 9 of 121 such files on the reference project."
```

---

## Task 4: Deterministic `.env` analysis

Every `VITE_`-prefixed variable is inlined into the client bundle by Vite. That
is a fact, not a judgement, so it needs no LLM. Chrono_Web has 41 such keys
across 8 files, including a commercial licence key and a full Keycloak config.

**Files:**
- Create: `vite_env.py`
- Create: `tests/test_vite_env.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `scan_vite_env(target_path: str, source_reads: Dict[str, List[str]]) -> List[Dict[str, Any]]`, where `source_reads` maps a variable name to the files reading it. Each returned dict has keys `key`, `files`, `use_sites`, `severity_tier`, `description`. Task 5 consumes this.

- [ ] **Step 1: Write the failing test**

Create `tests/test_vite_env.py` with the Apache-2.0 header copied from
`tests/test_indexer.py`, then:

```python
"""Tests for the Vite environment-variable analyser."""

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
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_vite_env.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'vite_env'`.

- [ ] **Step 3: Write the module**

Create `vite_env.py` with the Apache-2.0 header copied from `indexer.py`, then:

```python
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
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_vite_env.py -v
```

Expected: 8 passed.

- [ ] **Step 5: Verify against the real project**

```bash
.venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from vite_env import scan_vite_env
fs = scan_vite_env('/Users/ettore/Temp/Chrono_Web', {})
print('chiavi VITE_ trovate:', len(fs))
for f in fs:
    print('  %-9s %-38s in %d file' % (f['severity_tier'], f['key'], len(f['files'])))
"
```

Expected: **6 distinct keys** (41 definitions collapsing across 8 files), with
`VITE_REACT_APP_MUI_X_LICENSE_KEY` ranked `ERROR`. No value appears in the output.

- [ ] **Step 6: Commit**

```bash
git add vite_env.py tests/test_vite_env.py
git commit -m "feat: report Vite env variables exposed in the client bundle

Vite inlines every VITE_-prefixed variable into the bundle, so its value ships
to every visitor. The existing secrets rules cannot express this: they match
suspicious names, and VITE_KEYCLOAK_CLIENT_ID contains none while still being
public.

This runs as a rule rather than through the LLM — the exposure is a property of
the build, so a rule decides it instantly, for free, and cannot miss one. Key
names and locations are reported; values never leave the file."
```

---

## Task 5: Run the `.env` analyser in the brute-force pipeline

Task 4 produces findings that nothing yet stores. This wires it in and supplies
the `import.meta.env` cross-reference.

**Files:**
- Modify: `deepscan.py` (`_run_detection`)
- Modify: `indexer.py` (collect `import.meta.env` reads)
- Test: `tests/test_indexer.py`

**Interfaces:**
- Consumes: `scan_vite_env` from Task 4; `FindingStore.add_finding` (`file_path`, `vulnerability_class`, `description`, `detection_technique`, `severity_tier`, `cwe`, `metadata`).
- Produces: findings with `detection_technique="vite-env"` and `cwe="CWE-200"`.

- [ ] **Step 1: Write the failing test**

```python
def test_import_meta_env_reads_are_collected(tmp_path):
    (tmp_path / "config.ts").write_text(
        "const c = {\n"
        "    a: import.meta.env.VITE_API_URL as string,\n"
        "    b: import.meta.env.VITE_CLIENT_ID as string,\n"
        "};\n"
        "export default c;\n"
    )
    idx = CodeIndex()
    idx.build(str(tmp_path))
    reads = idx.get_env_reads()
    assert sorted(reads) == ["VITE_API_URL", "VITE_CLIENT_ID"]
    assert reads["VITE_API_URL"] == [str(tmp_path / "config.ts")]
```

- [ ] **Step 2: Run it to verify it fails**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_indexer.py -k "import_meta_env" -v
```

Expected: FAIL — `CodeIndex` has no attribute `get_env_reads`.

- [ ] **Step 3: Collect the reads**

In `indexer.py`, add the pattern next to `_CONFIG_SIGNALS`:

```python
_ENV_READ = re.compile(r"import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)")
```

In `CodeIndex.__init__` add `self._env_reads: Dict[str, List[str]] = {}`. In
`build()`, inside the per-file `try` immediately after `content_hash` is computed,
record the reads for source files:

```python
                if _get_language_for_file(file_path):
                    self._record_env_reads(file_path)
```

Add the two methods to `CodeIndex`:

```python
    def _record_env_reads(self, file_path: str) -> None:
        """Note which import.meta.env variables this file reads."""
        try:
            with open(file_path, encoding="utf-8", errors="replace") as handle:
                source = handle.read()
        except OSError:
            return  # unreadable files are already reported by the parser
        for name in set(_ENV_READ.findall(source)):
            self._env_reads.setdefault(name, []).append(file_path)

    def get_env_reads(self) -> Dict[str, List[str]]:
        """Map each import.meta.env variable to the files reading it."""
        return {k: sorted(set(v)) for k, v in self._env_reads.items()}
```

- [ ] **Step 4: Run it to verify it passes**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_indexer.py -k "import_meta_env" -v
```

Expected: PASS.

- [ ] **Step 5: Store the findings during detection**

In `deepscan.py`, add `from vite_env import scan_vite_env` to the imports. In
`_run_detection`, before the mode dispatch (`if self.guided and ...`), add:

```python
        stats["vite_env"] = self._run_vite_env()
```

and add the method to `Orchestrator`:

```python
    def _run_vite_env(self) -> Dict[str, Any]:
        """Report Vite env variables inlined into the client bundle."""
        result = {"keys_found": 0, "candidates_created": 0}
        findings = scan_vite_env(self.target, self.index.get_env_reads())
        result["keys_found"] = len(findings)

        for finding in findings:
            fid = self.store.add_finding(
                file_path=finding["files"][0],
                vulnerability_class="client-exposed-env-variable",
                description=finding["description"],
                detection_technique="vite-env",
                severity_tier=finding["severity_tier"],
                cwe="CWE-200",
                metadata={"key": finding["key"], "files": finding["files"],
                          "use_sites": finding["use_sites"]},
            )
            if fid:
                result["candidates_created"] += 1

        if findings:
            logger.info("Vite env: %d exposed keys, %d candidates",
                        result["keys_found"], result["candidates_created"])
        return result
```

- [ ] **Step 6: Verify nothing raises when there are no env files**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/ -q
```

Expected: all pass. `tests/test_orchestrator.py` exercises targets with no `.env`;
if it fails, `_run_vite_env` is not degrading silently as it must.

- [ ] **Step 7: Confirm no value reaches the store**

```bash
.venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from indexer import CodeIndex
from vite_env import scan_vite_env
idx = CodeIndex(); idx.build('/Users/ettore/Temp/Chrono_Web')
fs = scan_vite_env('/Users/ettore/Temp/Chrono_Web', idx.get_env_reads())
import re
for f in fs:
    print('%-9s %-38s letta in %d file' % (f['severity_tier'], f['key'], len(f['use_sites'])))
vals = [l.split('=',1)[1].strip() for l in open('/Users/ettore/Temp/Chrono_Web/.env') if '=' in l]
blob = repr(fs)
leaked = [v for v in vals if v and v in blob]
print('VALORI TRAPELATI:', leaked or 'nessuno')
"
```

Expected: use sites populated from `configVariables.ts`, and **`VALORI TRAPELATI: nessuno`**. If any value appears, stop and fix before committing.

- [ ] **Step 8: Commit**

```bash
git add deepscan.py indexer.py tests/test_indexer.py
git commit -m "feat(deepscan): store Vite env exposure findings in brute force

Wires the env analyser into the detection phase and cross-references each key
with the files reading it through import.meta.env, so a finding names both the
variable and where it is used rather than just listing a file."
```

---

## Task 6: React and Vite knowledge in the brute-force prompts

`rule_matcher` is only built under `--guided`, so rules never reach a brute-force
scan. The knowledge has to live in the prompts the brute-force path actually uses.

**Files:**
- Modify: `detector.py:48-63` (`RULE_BASED_SYSTEM_PROMPT`)
- Modify: `detector.py:107-132` (`EXPLORATORY_SYSTEM_PROMPT`)
- Test: `tests/test_detector.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: no new symbols; prompt text only.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_detector.py`:

```python
class TestFrontendPromptCoverage:
    """The brute-force prompts must name the React/Vite classes we scan for."""

    @pytest.mark.parametrize("needle", [
        "dangerouslySetInnerHTML",
        "javascript:",
        "localStorage",
        "import.meta.env",
    ])
    def test_rule_based_prompt_mentions(self, needle):
        assert needle in RULE_BASED_SYSTEM_PROMPT

    def test_exploratory_prompt_mentions_client_side_authorisation(self):
        assert "client-side" in EXPLORATORY_SYSTEM_PROMPT.lower()
```

- [ ] **Step 2: Run it to verify it fails**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_detector.py -k "Frontend" -v
```

Expected: 5 FAIL — none of those strings appear yet.

- [ ] **Step 3: Extend the rule-based prompt**

In `detector.py`, insert before the `If no vulnerabilities are found` line of
`RULE_BASED_SYSTEM_PROMPT`:

```
When the code is a browser front end, also consider:
- dangerouslySetInnerHTML, innerHTML or document.write reached by non-constant input
- javascript: or data: URLs flowing into href, src or window.open
- tokens, credentials or personal data written to localStorage or sessionStorage
- secrets read from import.meta.env: every VITE_-prefixed variable is inlined into \
the client bundle and is readable by any visitor
- authorisation decided only in the browser, with no server-side check
- postMessage handlers that do not verify event.origin
```

- [ ] **Step 4: Extend the exploratory prompt**

In `EXPLORATORY_SYSTEM_PROMPT`, add to the list of design-level flaws:

```
- Client-side-only authorisation: route guards or UI gating with no server check
- Trust placed in build-time configuration that ships to the browser
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_detector.py -k "Frontend" -v
```

Expected: 5 passed. Add `RULE_BASED_SYSTEM_PROMPT` to the imports in
`tests/test_detector.py` if the run fails on `NameError`.

- [ ] **Step 6: Check the prompt has not bloated**

```bash
.venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from detector import RULE_BASED_SYSTEM_PROMPT as R, EXPLORATORY_SYSTEM_PROMPT as E
print('rule-based : %d char (~%d token)' % (len(R), len(R)//4))
print('exploratory: %d char (~%d token)' % (len(E), len(E)//4))
"
```

Expected: both under 2000 characters. The prompt is sent on every one of ~1000
calls; if either is larger, cut the least specific lines rather than accepting it.

- [ ] **Step 7: Run the full suite and commit**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/ -q
git add detector.py tests/test_detector.py
git commit -m "feat(detector): teach the brute-force prompts React and Vite risks

rule_matcher is only constructed under --guided, so rules never reach a
brute-force scan and the CodeGuard client-side guidance sat unused. The
vulnerability classes specific to this stack now live in the two prompts the
brute-force path actually sends."
```

---

## Task 7: Stop the false partial-parse warning

HTML entities (`&sup2;`) inside JSX make the tsx grammar report a syntax error.
The scan then declares "coverage is incomplete" although every function was
indexed — verified on `src/utils/uiUtils.tsx`, 6 of 6 found. A false warning
teaches users to distrust accurate reports.

**Files:**
- Modify: `indexer.py:295-297` (the `has_error` branch in `parse_file`)
- Test: `tests/test_indexer.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: no new symbols.

- [ ] **Step 1: Write the failing test**

```python
def test_html_entity_in_jsx_is_not_a_partial_parse(tmp_path):
    f = tmp_path / "label.tsx"
    f.write_text(
        "export function AreaLabel() {\n"
        "    return <>Area (mm&sup2;)</>;\n"
        "}\n"
    )
    idx = CodeIndex()
    stats = idx.build(str(f))
    assert [fn["name"] for fn in idx.get_all_functions()] == ["AreaLabel"]
    assert stats["files_with_syntax_errors"] == 0


def test_genuinely_broken_file_still_reports(tmp_path):
    f = tmp_path / "broken.tsx"
    f.write_text("export function A() { return <div>; }\nfunction (((\n")
    idx = CodeIndex()
    stats = idx.build(str(f))
    assert stats["files_with_syntax_errors"] == 1
```

- [ ] **Step 2: Run them to verify the first fails**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_indexer.py -k "html_entity or genuinely_broken" -v
```

Expected: `test_html_entity_in_jsx_is_not_a_partial_parse` FAILS with
`assert 1 == 0`; `test_genuinely_broken_file_still_reports` passes already.

- [ ] **Step 3: Ignore entity-only errors**

Add next to `_ENV_READ` in `indexer.py`:

```python
# tree-sitter's tsx grammar flags HTML entities in JSX text as errors. They are
# valid JSX, and the surrounding functions parse fine, so treating them as a
# partial parse marks complete coverage as incomplete.
_HTML_ENTITY = re.compile(r"^&(#[0-9]+|#x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*);?$")
```

Replace the `has_error` branch at `indexer.py:295-296`:

```python
        if tree.root_node.has_error:
            first_error = self._first_error_node(tree.root_node)
            if not self._is_html_entity_error(first_error, source):
                self._record_syntax_error(file_path, tree.root_node, lang_name)
```

`_record_syntax_error` recomputes the first error node itself; leave it unchanged.
Add the helper to the same class:

```python
    @staticmethod
    def _is_html_entity_error(error_node, source: bytes) -> bool:
        """True when the only parse error is an HTML entity in JSX text."""
        if error_node is None:
            return False
        text = source[error_node.start_byte:error_node.end_byte].decode(
            "utf-8", errors="replace").strip()
        return bool(_HTML_ENTITY.match(text))
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/test_indexer.py -k "html_entity or genuinely_broken" -v
```

Expected: both PASS. If the first still fails, print the error node's text to see
what tree-sitter actually flagged — the entity may be reported together with
surrounding text, in which case match on the node containing an entity rather
than equalling one, and say so in the comment.

- [ ] **Step 5: Verify on the real file**

```bash
.venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from indexer import CodeIndex
idx = CodeIndex()
st = idx.build('/Users/ettore/Temp/Chrono_Web/src/utils/uiUtils.tsx')
print('funzioni:', st['functions_found'], '| file con errori:', st['files_with_syntax_errors'])
"
```

Expected: `funzioni: 6 | file con errori: 0`.

- [ ] **Step 6: Run the full suite and commit**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/ -q
git add indexer.py tests/test_indexer.py
git commit -m "fix(indexer): do not report HTML entities as a partial parse

The tsx grammar flags entities such as &sup2; in JSX text as syntax errors, so
a file whose functions all parsed was reported as incompletely covered —
verified on uiUtils.tsx, where all 6 of 6 functions were indexed. Genuinely
truncated files still report."
```

---

## Task 8: Verify the whole against the reference project

Each task checked its own change. This confirms they compose, and that the
spec's acceptance numbers hold together.

**Files:**
- Modify: `docs/superpowers/specs/2026-08-20-react-vite-support-design.md` (record measured results)

- [ ] **Step 1: Run the full suite one final time**

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/ -q
```

Expected: all pass, no fewer than the 291 baseline plus the tests added here.

- [ ] **Step 2: Measure the composed result**

```bash
.venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from indexer import CodeIndex
from vite_env import scan_vite_env
idx = CodeIndex(); st = idx.build('/Users/ettore/Temp/Chrono_Web')
units = idx.get_all_functions()
whole = [u for u in units if u['name'] == '(file)']
env = scan_vite_env('/Users/ettore/Temp/Chrono_Web', idx.get_env_reads())
print('unita analizzate      :', st['functions_found'], '(atteso 993 + 9 = 1002)')
print('funzioni banali saltate:', st['functions_skipped_trivial'], '(atteso 846)')
print('unita da file interi   :', len(whole), '(atteso 9)')
print('chiavi VITE_ esposte   :', len(env), '(attese 6)')
print('file con errori parse  :', st['files_with_syntax_errors'], '(atteso 0)')
"
```

- [ ] **Step 3: Record the measured results in the spec**

Append a `## Measured after implementation` section to the spec with the numbers
from Step 2 beside the predictions. Where a number differs from the prediction,
write why — the spec is the record of what this work actually achieved, and an
unexplained gap is a finding, not a rounding error.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-08-20-react-vite-support-design.md
git commit -m "docs: record measured results of React + Vite support"
```

- [ ] **Step 5: Report to the user before any real scan**

A scan of Chrono_Web is a multi-hour commitment. Present the measured numbers and
let the user decide whether to launch it, rather than starting one.

---

## Notes for the implementer

**Order matters.** Task 1 must land before Task 2: the trivial filter counts
functions, and until keys are unique the counts are wrong. Task 4 must land
before Task 5, which imports it. Tasks 6 and 7 are independent and may be done
in any order.

**Do not adjust a failing test to match the code.** Two places call this out
explicitly (Task 1 Step 6, Task 5 Step 6) because both would look like trivial
test breakage while signalling something real: fingerprint format changes, and
a path that raises where it must warn.

**The reference project is `/Users/ettore/Temp/Chrono_Web`.** Every task verifies
against it. If it is unavailable, say so and stop rather than skipping the
verification steps — the spec's numbers are the acceptance criteria and cannot be
confirmed any other way.
