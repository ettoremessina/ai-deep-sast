# React + Vite support for brute-force deep scan

**Date:** 2026-08-20
**Status:** approved, ready for implementation planning
**Branch:** `fix/index-modern-language-idioms`

## Problem

Running a deep scan over a real React + Vite codebase leaves most of its security
surface unexamined, and costs more than the results justify.

All measurements below come from `/Users/ettore/Temp/Chrono_Web` (190 `.ts`,
86 `.tsx`, 8 `.env` files), taken before any change.

### What already works

Arrow-function components and JSX/TSX parse correctly. A probe covering six
declaration forms — arrow component assigned to `const`, plain `function`, inline
exported arrow, `async` arrow, typed `React.FC<Props>` with JSX, and a class
method — indexed all six with no syntax errors. Commit `34984c5` fixed this
earlier; no further work is needed there.

On the real project the indexer finds **1531 functions across 156 files**.

### What does not work

**1. Everything that is not a function is invisible.** The unit of analysis is
the function, so a file containing no function declarations contributes nothing.
121 source files are in this state. Among them:

| file | content | today |
|---|---|---|
| `src/configVariables.ts` | 8 `import.meta.env.VITE_*` reads | invisible |
| `src/configs/keycloak.ts` | full OIDC config: authority, client_id, redirect URIs | invisible |
| `src/main.tsx` | `AuthProvider` wiring, `onSigninCallback` manipulating `window.history` | invisible |

Most of the remaining 121 are barrel files (`export * from …`) with nothing to
analyse. The distinction matters: a filter that admits all 121 adds ~100 useless
LLM calls.

**2. `.env` files are not scanned at all.** `.env` is not a recognised extension,
so the deep scan never reads it. The existing Semgrep secrets path does cover
`*.env`, but `_run_semgrep()` is only called under
`--guided --guide-rules semgrep` ([deepscan.py:294](../../../deepscan.py)); in
brute force it never runs.

That path would also be the wrong tool. Its rules match suspicious *names*
(`password`, `secret`, `credential`). The Vite risk does not depend on the name:
**any** `VITE_*` variable is inlined into the client bundle at build time.
`VITE_KEYCLOAK_CLIENT_ID` contains no suspicious word and is still public.
Chrono_Web has 41 such keys across 8 environment files — including
`VITE_REACT_APP_MUI_X_LICENSE_KEY`, a commercial licence key, and the complete
Keycloak configuration for named customer environments.

**3. Rules never run in brute force.** `rule_matcher` is only constructed when
`--guided` is set ([deepscan.py:284](../../../deepscan.py)). Adding React rules to
`_match_language_rules` would have no effect on a brute-force scan. React and
Vite knowledge has to reach the brute-force prompts instead.

**4. Scanning cost is prohibitive.** 1531 functions is 3.5× Chrono_Server, which
took 12h53m end to end. Extrapolating the rates measured on that run
(36 s/function, 80 s/exploratory batch, 43.5 s/triage candidate) gives roughly
42 hours — 15 h rule-based, 7 h exploratory, 20 h triage. 39.3% of the functions
are 1–3 lines — `map`/`filter` predicates and
MUI render callbacks such as `x => x.compSubTypeAttValId` — carrying no security
signal but consuming a full LLM call each.

**5. The index silently drops functions.** `FunctionInfo.key` is
`f"{file_path}:{qualified_name}"` with no line number
([indexer.py:229](../../../indexer.py)), and `build()` stores functions in a dict
keyed by it ([indexer.py:586](../../../indexer.py)). Same-named functions in one
file overwrite each other. `functions_found` counts before this collapse, which
is why it reports 1839 while only 1531 are retrievable.

On Chrono_Web **308 functions (17%) are lost**. The worst case,
`src/pages/ComponentSearch.tsx`, parses 64 functions and indexes 32 — half the
file — because `getColumns.renderCell` and `getColumns.renderHeader` each occur
16 times. This is not React-specific: the C# scan indexed 443 functions and
processed 429.

**6. A false partial-parse warning.** HTML entities (`&sup2;`) inside JSX make
the tsx grammar report a syntax error, so the scan declares "coverage is
incomplete" while every function in the file was in fact indexed — verified on
`src/utils/uiUtils.tsx`, 6 of 6 found.

## Non-goals

- Guided, Semgrep-guided, and ASVS/CodeGuard modes. The user works exclusively in
  brute force; work targeting other modes would not be used.
- A new scan mode. Selection happens inside the existing brute-force path.
- Vue, Svelte, Angular. React + Vite only.
- Reproducing Vite's bundler resolution. Determining whether a variable is
  *reachable* in the shipped bundle is out of scope; the `VITE_` prefix is the
  criterion.

## Design

### A. Analysable units from files with no functions

When a recognised source file yields no functions, the indexer decides by
**content** whether the file is worth analysing, and if so emits the whole file
as a single unit.

Selection requires at least one signal and rejects pure re-export files. Signal
families: environment access (`import.meta.env`, `process.env`); exported object
literals; URLs; browser storage (`localStorage`, `sessionStorage`,
`document.cookie`); secret-ish identifiers; authentication vocabulary (`auth`,
`oidc`, `keycloak`, `oauth`, `jwt`, `role`, `permission`); browser navigation
(`window.location`, `window.history`); and configuration constructors
(`defineConfig`, `createRoot`, `configureStore`).

Measured on Chrono_Web: **9 of 121 files selected**, 13 rejected as pure
re-exports, 99 as signal-free.

**The signal list is the tunable part of this design.** A narrower list tested
during design selected only 4 files and missed `main.tsx`, whose auth-provider
wiring is exactly the kind of code this feature exists to reach. A wider list
also admits type-only files (`types/TUser.ts`, `widgets/WidgetProps.tsx`) that
have no runtime behaviour.

Resolve that trade-off toward **recall**: while the selected set stays in the
tens of files, a false positive costs one LLM call (~40 s) and a false negative
costs a blind spot in authentication analysis. Revisit only if the selected set
grows into the hundreds on some project.

Whole-file units must carry a size ceiling. A file above the ceiling is reported
as skipped, with its size, rather than silently truncated or sent whole.

### B. Deterministic `.env` analysis

Whether a `VITE_*` variable reaches the client bundle is a fact about Vite, not a
judgement, so it needs no LLM: a rule decides it in milliseconds with perfect
recall and zero tokens.

For each `.env*` file, parse `KEY=VALUE` pairs and report every `VITE_`-prefixed
key as client-exposed. Cross-reference the keys against `import.meta.env.<KEY>`
reads found in the indexed sources, so each finding names both the variable and
its use sites. Keys defined but never read, and keys read but never defined, are
worth reporting as separate lower-severity observations.

**Values are never emitted into findings, logs, or reports** — only key names,
file names, and use sites. The existing redaction path covers text sent to the
LLM; this path produces findings directly and must not leak values into the
report or the DefectDojo export.

Severity should reflect what the key name suggests (a licence key or client
secret ranks above an API base URL) while every `VITE_` key is at minimum an
informational finding, because exposure is certain.

### C. React and Vite knowledge in the brute-force prompts

Extend `RULE_BASED_SYSTEM_PROMPT` and `EXPLORATORY_SYSTEM_PROMPT`
([detector.py:48](../../../detector.py), [detector.py:107](../../../detector.py))
with the vulnerability classes specific to this stack: `dangerouslySetInnerHTML`
with non-constant input; `javascript:` URLs reaching `href`/`src`; tokens or
credentials in `localStorage`/`sessionStorage`; secrets read from
`import.meta.env` in client code; client-side-only authorisation; unsafe
`postMessage` handling; and `eval`-equivalents.

Prompt growth costs output tokens on every call, so additions must be specific
enough to change the model's behaviour. Keep the additions proportionate and
verify the effect against the same target before and after.

`config/codeguard/codeguard-0-client-side-web-security.md` already carries
relevant guidance and is currently unreachable in brute force; it is the natural
source for this material.

### D. Skipping trivial functions

Exclude functions whose body is 1–3 non-blank lines from LLM analysis. On
Chrono_Web 846 of the 1839 parsed functions (46%) fall below it, leaving 993,
and the filter removes noise along with cost.

The threshold must be a named constant, overridable from the CLI, so a project
where it proves wrong can adjust it without a code change. Skipped functions must
be counted and reported in the scan summary — a silent 39% reduction in analysed
code would be indistinguishable from a bug.

### E. Stop losing functions to key collisions

Make the index key unique per function by including its start line, so
same-named functions in one file no longer overwrite each other, and make
`functions_found` report what is actually retrievable.

This is a correctness fix that outranks everything else here: today the scanner
reports success while never analysing 17% of the code, and nothing in the output
reveals it.

It interacts with section D, and favourably. Fixing collisions alone raises
Chrono_Web from 1531 to 1839 units. But 46% of all parsed functions are 1–3 lines
— the recovered ones are overwhelmingly one-line `renderCell` callbacks — so with
the trivial filter applied the total lands at **993 units: fewer than the 1531
analysed today, with nothing silently dropped**.

Callers, callees, and fingerprints derive from these keys, so changing the key
format affects call-graph lookups and finding identity. Existing scan databases
carry fingerprints computed the old way; resume behaviour against an existing
`deepscan.db` must be checked, not assumed.

### F. Correct the false partial-parse warning

The warning must not fire when every function in the file was recovered. HTML
entities inside JSX are valid input, and a false "coverage is incomplete"
teaches users to distrust accurate reports.

## Error handling

Every new path runs inside scans lasting many hours, so none of them may raise
into the scan loop. An unreadable or malformed `.env`, a file exceeding the size
ceiling, and an undecodable source file each produce a warning naming the file
and are skipped. Absence of `.env` files, or a project with no config-only files,
is normal and silent.

Selection and skip counts belong in the summary: files selected as whole-file
units, files rejected, functions skipped as trivial, `.env` files parsed. These
numbers are how a user distinguishes "nothing to report" from "silently did
nothing".

## Testing

Tests are written before implementation, following the existing suite's
conventions (`tests/`, pytest, mocked LLM).

Unit coverage: content heuristic selects config-like files and rejects pure
re-exports; `.env` parsing extracts `VITE_` keys and never surfaces values;
cross-referencing links keys to use sites and flags unused and undefined keys;
the trivial-function threshold excludes 1–3 line bodies and respects its
override; HTML entities in JSX produce no partial-parse warning while genuinely
truncated files still do; oversized and unreadable files are skipped with a
warning rather than an exception.

Integration coverage: an indexed fixture project resembling Chrono_Web's shape
(barrel files, a config file reading `import.meta.env`, an auth config, trivial
callbacks) yields exactly the expected units.

Beyond the suite, each change is measured against Chrono_Web itself, comparing
against the figures recorded in this document. Those numbers are the acceptance
criteria: 9 of 121 files selected, 41 `VITE_` keys found across 8 files, 1531
1839 functions reduced to 993 with none lost to key collisions, and no
partial-parse warning on `uiUtils.tsx`.

## Consequences

Analysed units go from 1531 today — with 308 silently dropped — to 993 with
nothing lost, plus roughly 9 whole-file units, cutting estimated scan time by
about 15 hours while increasing what is actually examined. Authentication configuration and
environment-variable surface become visible for the first time. `.env` findings
arrive with no token cost.

The trivial-function filter means some code is no longer analysed. This is a
deliberate trade, justified by the sampled content of those functions, and it is
reversible through the threshold override.

## Granularity of `.env` findings

One finding per `VITE_` key, not one per file.

The deciding factor is triage, not report volume: the correct verdict differs per
key. `VITE_API_URL` is legitimately public and a reviewer will accept it;
`VITE_REACT_APP_MUI_X_LICENSE_KEY` is not. Per-file findings would force one
verdict onto both, and would stay open until every key in the file was addressed.
Per-key findings carry stable fingerprints, so DefectDojo tracks and closes them
individually.

Keys repeated across the 8 environment files are the same finding at different
sites, not 8 findings; the fingerprint must reflect the key, with the files
listed as evidence.

## Measured after implementation

All seven tasks landed and were reviewed individually. This section is Task 8:
composing them and measuring the result against `/Users/ettore/Temp/Chrono_Web`,
the same reference project used throughout design. Full suite:
`326 passed` (`PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest tests/ -q`).

| metric | predicted | measured | match |
|---|---|---|---|
| regular (non-whole-file) units | 993 | 993 | exact |
| whole-file units | 9 | 10 | differs — explained below |
| total units analysed | 993 + 9 = 1002 | 993 + 10 = 1003 | differs — same causes |
| trivial functions skipped | 846 | 846 | exact |
| distinct `VITE_` keys exposed | 6 | 6 | exact |
| files with syntax errors | 0 | 0 | exact |
| units skipped inside one run | not predicted | 0 | see "What the whole-branch review caught" |

The whole-file count moved twice: down from the predicted 9 to 8 when a barrel
file was correctly rejected, then up to 10 when the final review found two more
files that had been reaching nothing. Both movements are explained below, and
both are the selection working better rather than differently.

### Why whole-file units are 8, not 9

Known before this task, recorded here for the permanent record. One of the nine
files the content heuristic selected during Task 3 development was
`src/components/index.ts`, a pure barrel file (`export * from …`). It was
admitted by a bug in the controller's own design-time prototype of the
selection heuristic, not by the heuristic actually shipped in `indexer.py`.
The shipped heuristic rejects pure re-export files by design (see section A
above, "13 rejected as pure re-exports"), so `index.ts` is correctly excluded
now. The 993 + 9 = 1002 figure in the brief and in "Testing" above is stale by
exactly this one file; 993 + 8 = 1001 is the correct composed total, and every
component number (993 regular units, 846 trivial skips) matches its
prediction exactly. This is not a regression — it is the selection heuristic
working as designed against a case the earlier prototype got wrong.

### The 1531 → 1839 → 993 story, remeasured

Three numbers describe the same codebase under three states of the code. The
first is the documented pre-implementation baseline; the other two were
reproduced live against the current `main`-branch code for this task, by
toggling only `min_function_lines` (Task 2's flag) since the key-collision fix
(Task 1) is now permanently in effect:

1. **1531** — what the original scanner (key collisions present, no whole-file
   units, no trivial filter) actually retained. `functions_found` reported 1839
   even then, but 308 of those (17%) were silently overwritten in the
   `self._functions` dict because same-named functions in one file shared a key
   with no line number. Only 1531 were ever sent to the LLM. This number is
   carried forward from the pre-implementation measurement recorded at the top
   of this document; reproducing it exactly would require reverting the Task 1
   fix, which is out of scope for a composed-result check.
2. **1839** — collisions fixed (Task 1), trivial filter disabled
   (`CodeIndex(min_function_lines=1)`), reference target rebuilt. Measured
   directly for this task: `functions_found = 1847`, of which 8 are whole-file
   units, leaving **1839** regular functions — an exact match to the design's
   prediction, and now independently confirmed rather than only asserted.
   Every one of these is now genuinely indexed and retrievable; nothing is lost
   to key collisions.
3. **993** — collisions fixed and the trivial filter applied at its default
   threshold (4 non-blank body lines). Measured directly: `functions_found =
   1001`, of which 8 are whole-file units, leaving **993** regular functions —
   again an exact match. `1839 - 993 = 846`, the exact count of functions
   skipped as trivial, so the arithmetic is internally consistent as well as
   matching the prediction.

Net effect: the scanner goes from silently analysing 1531 functions (with 308
dropped and no sign of it) to deliberately analysing 993 regular functions plus
8 whole-file units (1001 total) — fewer LLM calls than even the broken
baseline, while every one of the 1839 functions that genuinely exist is now
accounted for (either analysed or explicitly, countably skipped as trivial).
Coverage strictly increased; cost still went down.

### `VITE_` key count: 41 occurrences vs. 6 distinct keys

The design's "Chrono_Web has 41 such keys across 8 environment files" (Problem,
point 2) and the Testing section's "41 `VITE_` keys found across 8 files" count
*occurrences* — a key repeated in multiple `.env*` files counts once per file.
The Task 8 measurement counts *distinct key names*, matching the "Granularity
of `.env` findings" design decision that one finding is emitted per key, not
per file or per occurrence (section above, "the fingerprint must reflect the
key, with the files listed as evidence"). The two counts are consistent, not
contradictory: 5 of the 6 distinct keys
(`VITE_KEYCLOAK_CLIENT_ID`, `VITE_KEYCLOAK_DEFAULT_REALM`,
`VITE_KEYCLOAK_DEFAULT_URL`, `VITE_KEYCLOAK_REDIRECT_URL`,
`VITE_REACT_APP_BACKEND_BASE_URL`) are defined in all 8 environment files
(5 × 8 = 40 occurrences), and the sixth (`VITE_REACT_APP_MUI_X_LICENSE_KEY`)
appears only in `.env` (1 occurrence) — 40 + 1 = 41, matching the original
occurrence count exactly. `scan_vite_env` correctly deduplicates by key,
producing 6 findings as designed.

### Unaffected-target sanity check

A scan target with no `.env` files and no React/Vite code should be unaffected
by all seven changes. Built the index over this repository's own `samples/`
directory (`SampleVuln.java`, `sample_vuln.py`, plus non-code fixtures
`sample_secrets.env`, `sample_jdbc.properties`, `sample_app.conf` that the
indexer does not treat as source): `files_parsed: 2, functions_found: 14,
functions_skipped_trivial: 0, whole_file_units: 0, files_with_syntax_errors:
0`, `scan_vite_env` returned 0 findings (the sample `.env` file has no
`VITE_`-prefixed keys — it exists to exercise the Semgrep secrets rules, not
this feature), and no warnings were logged during the build. No whole-file
units, no env findings, no new warnings — the new machinery is silent on a
target it has no business touching.

### CLI surface

`deepscan.py --help` lists both new flags: `--min-function-lines` (default 4,
Task 2) and `--max-tokens` (pre-existing, unrelated to this work but confirmed
still present alongside the new flag).

### Summary

Every measured number matches its prediction exactly once the known Task 3
barrel-file correction (9 → 8 whole-file units, hence 1002 → 1001 total) is
applied. No unexplained gaps were found. The seven tasks compose correctly:
Task 1's unique keys make Task 2's trivial count meaningful, Task 4's rule
feeds Task 5's pipeline wiring and produces exactly the deduplicated finding
count the design called for, and Task 7's fix leaves `files_with_syntax_errors`
at 0 on a target that exercises the HTML-entity case. The full test suite
passes at 326, up from the 291 baseline named in the task brief plus the tests
added across all seven tasks.

## What the whole-branch review caught

Each task was reviewed on its own and passed. Reviewing the seven together found
one defect that no task-scoped review could have seen, and it was the most
consequential of the whole effort.

**Section E's fix never reached the LLM.** Making `FunctionInfo.key` unique did
stop the index dropping functions — 1531 became 1839. But the detector decides
what to analyse with `is_function_processed(file_path, qualified_name)`, and
`compute_fingerprint` hashes the same pair. Neither can tell two functions named
`renderCell` apart. The loss had moved out of the index and into the detector,
where it was counted as `resumed_skipped` — a statistic whose name suggests
nothing is wrong.

Measured before the fix: 30 `(file, qualified_name)` pairs held 2–8 units each,
and **60 of 1001 units were skipped inside a single run**, concentrated in the
functions most worth reading — `fetchMyAPI` six times across report and timesheet
pages, `Topbar.action` eight times. A test case with two `renderCell` functions,
the second containing `dangerouslySetInnerHTML={{__html: p.z}}`, produced two LLM
calls instead of three and never sent the XSS.

The fix carries a per-function discriminator through the processed-marker and the
fingerprint, using an **occurrence index** rather than the start line. That choice
keeps markers and fingerprints byte-identical for uniquely-named functions, which
are the overwhelming majority: inserting lines above a function changes its start
line but not its occurrence index, so a stored scan does not re-fingerprint its
whole corpus after an unrelated edit.

Two related defects came out of the same review. `get_function_body` returned the
first of N same-named functions, which was harmless while duplicates were never
analysed and would have become a wrong triage verdict once they were — so it had
to land in the same commit. And the whole-file gate ran *before* the trivial
filter, so a config file whose only function was a one-line arrow got no coverage
at all while still counting as parsed. Fixing that is what took whole-file units
from 8 to 10: `src/utils/axiosHeaders.ts`, which sets the `Authorization: Bearer`
header, and `src/services/userService.ts`, which reads and writes an access token
in `localStorage`. Both had been reaching nothing. The selection heuristic itself
was not touched — only when it is consulted.

Final state: **354 tests**, `resumed_skipped` 0, and 1003 of 1003 units reaching
the analysis.

### Known limits, recorded deliberately

Resuming against a `deepscan.db` written before this work does not re-analyse
everything, but it can add duplicate findings for functions whose names repeat in
one file, and the first occurrence of each such group stays skipped by its stale
marker. The store now stamps a format version and warns on open. Deleting the
store is the clean remedy.

Because the discriminator is positional, inserting a new same-named function
*above* an existing one transfers the old one's identity — and any verdict already
recorded against it — to the new code. This is a narrower instance of the
name-based identity the finding store already used, not something this work
introduced, but it is a real limit on triage correctness across scans.

On the `--guided --guide-rules semgrep` path, a Semgrep hit inside a second or
later same-named function now yields no function body rather than the wrong one.
That path is an explicit non-goal here and the change measures zero impact on the
reference project, but it is a regression in kind and worth a one-line follow-up.
