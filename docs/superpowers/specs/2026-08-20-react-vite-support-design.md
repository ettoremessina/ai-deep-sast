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

**5. Two reporting defects.** A partial-parse warning fires on HTML entities
(`&sup2;`) inside JSX, declaring "coverage is incomplete" while in fact every
function in the file is indexed — verified on `src/utils/uiUtils.tsx`, all 6 of 6
found. Separately, the index reports `functions_found=1839` while
`get_all_functions()` returns 1531; the 308-function gap is unexplained.

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
Chrono_Web this drops 602 of 1531 units (39.3%), leaving 929, and removes noise
along with cost.

The threshold must be a named constant, overridable from the CLI, so a project
where it proves wrong can adjust it without a code change. Skipped functions must
be counted and reported in the scan summary — a silent 39% reduction in analysed
code would be indistinguishable from a bug.

### E. Two corrections

The partial-parse warning must not fire when every function in the file was
recovered; HTML entities inside JSX are valid input, and a false "coverage is
incomplete" teaches users to distrust accurate reports.

The `functions_found` / `get_all_functions()` discrepancy must be explained
before anything is changed. It is a measurement question, not a fix: if 1839 is
the honest count, retrieval is losing functions; if 1531 is, the reported
statistic is wrong. Determine which before touching either.

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
functions reduced to 929, and no partial-parse warning on `uiUtils.tsx`.

## Consequences

Analysed units drop from 1531 to 929 functions plus roughly 9 whole-file units,
cutting estimated scan time by about 14 hours. Authentication configuration and
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
