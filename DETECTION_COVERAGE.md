# Detection Coverage

This document describes the vulnerability detection capabilities, rule sources, and known
limitations of the AI Deep SAST.

## Rule Sources

The scanner chains multiple Semgrep rule packs and custom rules:

| Rule Source | Type | Description |
|---|---|---|
| `p/default` | Semgrep Registry | Broad recommended ruleset (~600+ rules). Includes OWASP Top 10, CWE Top 25, language-specific, and audit rules |
| `p/secrets` | Semgrep Registry | Known vendor secret/credential patterns (AWS keys, GitHub PATs, Slack tokens, etc.) |
| `config/custom-secrets.yaml` | Custom (this project) | 6 rules for hardcoded credentials in config files (.properties, .env, .yaml) and source code (Java, Python) |
| `config/custom-zipslip.yaml` | Custom (this project) | 2 taint rules for Zip Slip path traversal (CWE-22) in Java and Python |
| `config/custom-ai-risks.yaml` | Custom (this project) | 3 rules for AI/ML-specific risks (unsafe pickle/torch load, trust_remote_code) |
| `p/ai-best-practices` | Semgrep Registry | 27 rules for AI/ML best practices (optional, included by default) |

## Custom Rule Details

### Hardcoded Secret Detection (`config/custom-secrets.yaml`)

| Rule ID | Language | What it detects |
|---|---|---|
| `hardcoded-password-properties` | Config files | `password=`, `secret=`, `credential=` in .properties/.env/.conf/.yaml |
| `hardcoded-redis-password` | Config files | Redis-specific password patterns |
| `hardcoded-api-key-properties` | Config files | API key and token assignments |
| `hardcoded-jdbc-connection-string` | Config files | JDBC URLs with hardcoded IPs |
| `hardcoded-secret-python` | Python | `PASSWORD`, `SECRET`, `API_KEY` variable assignments |
| `hardcoded-secret-java` | Java | Same patterns in Java source |

**False-positive exclusions:**
- Spring Boot `${VAR}` placeholders
- Helm/Vault `{{ }}` templates
- Commented-out lines
- Values shorter than 4 characters
- File paths

### Zip Slip Detection (`config/custom-zipslip.yaml`)

| Rule ID | Language | What it detects |
|---|---|---|
| `zipslip-java` | Java | `ZipEntry.getName()` / `JarEntry.getName()` flowing into file I/O without path validation |
| `zipslip-python` | Python | `ZipInfo.filename` / `TarInfo.name` flowing into `open()` without path validation |

**How it works:**

These rules use Semgrep's **taint analysis mode** to track data flow from archive entry names
(taint sources) to file system operations (taint sinks). If the data passes through a known
sanitizer (e.g., `getCanonicalPath()` in Java, `os.path.realpath()` in Python), the finding
is suppressed.

**Recognised sanitizers:**

| Language | Sanitizer |
|---|---|
| Java | `File.getCanonicalPath()`, `Path.normalize()`, `File.toPath().normalize()` |
| Python | `os.path.realpath()`, `os.path.abspath()`, `Path.resolve()` |

### AI/ML Risk Detection (`config/custom-ai-risks.yaml`)

| Rule ID | Language | What it detects |
|---|---|---|
| `ai-unsafe-torch-load` | Python | `torch.load()` without `weights_only=True` |
| `ai-unsafe-pickle-load` | Python | `pickle.load()` / `pickle.loads()` on untrusted data |
| `ai-trust-remote-code` | Python | `trust_remote_code=True` in HuggingFace model loading |

## Analysis Pipeline

Each finding goes through up to three analysis stages:

1. **Semgrep** — static analysis with all configured rules
2. **SecureBERT 2.0** (optional) — ML-based vulnerability classifier that filters false positives
3. **Foundation-Sec-8B** — LLM-powered deep analysis with remediation guidance

Findings matching `skip_llm_rules` prefixes (default: `config.`) bypass LLM analysis and use
Semgrep metadata directly, since these deterministic rules already provide CWE/OWASP mappings.

## Vulnerability Classes Covered

| Vulnerability Class | CWE | Detection Source | Confidence |
|---|---|---|---|
| SQL Injection | CWE-89 | `p/default` | High |
| OS Command Injection | CWE-78 | `p/default` | High |
| Path Traversal | CWE-22 | `p/default` + `custom-zipslip.yaml` | High |
| Zip Slip | CWE-22 | `custom-zipslip.yaml` (taint) | High |
| XSS (Cross-Site Scripting) | CWE-79 | `p/default` | High |
| SSRF | CWE-918 | `p/default` | High |
| XXE (XML External Entity) | CWE-611 | `p/default` | High |
| Insecure Deserialization | CWE-502 | `p/default` + `custom-ai-risks.yaml` | High |
| Hardcoded Credentials | CWE-798 | `p/secrets` + `custom-secrets.yaml` | High |
| Weak Cryptography | CWE-327 | `p/default` | Medium |
| Unsafe Reflection | CWE-470 | `p/default` | Medium |
| Debug Mode Enabled | CWE-489 | `p/default` | Medium |
| Weak Random | CWE-330 | `p/default` | Medium |
| AI/ML Unsafe Model Loading | — | `custom-ai-risks.yaml` | High |
| AI/ML Remote Code Trust | — | `custom-ai-risks.yaml` | High |

## Known Limitations

### Semgrep OSS Taint Analysis

The scanner uses Semgrep Community Edition (OSS), which has the following taint analysis
constraints:

| Capability | Supported | Notes |
|---|---|---|
| Single-function taint tracking | ✅ Yes | Source and sink must be in the same method/function |
| Cross-function taint tracking | ❌ No | Requires Semgrep Pro (paid) |
| Cross-file taint tracking | ❌ No | Requires Semgrep Pro (paid) |
| Sanitizer recognition | ✅ Yes | Within the same function scope |
| Constant propagation | ✅ Yes | Cross-function supported in OSS |

**Impact:** If a tainted value (e.g., `entry.getName()`) is passed to a helper function that
constructs the file path, the taint is lost at the function boundary and the vulnerability
will not be detected. This is the primary source of false negatives.

### Custom Rule Scope

| Rule | False Positives | False Negatives |
|---|---|---|
| Zip Slip (Java) | Low — may flag code using internal safe wrapper libraries | Misses cross-function zip extraction patterns |
| Zip Slip (Python) | Low — `$ENTRY.name` is broad, may match non-archive objects | Misses cross-function patterns |
| Hardcoded Secrets | Low — excludes placeholders, templates, short values | May miss obfuscated or encoded credentials |
| AI/ML Risks | Very low — pattern-based, specific APIs | Only covers PyTorch, pickle, HuggingFace |

### Language Coverage

Custom rules currently cover:

| Language | Secret Detection | Zip Slip | AI/ML Risks |
|---|---|---|---|
| Java | ✅ | ✅ | — |
| Python | ✅ | ✅ | ✅ |
| Config files | ✅ | — | — |
| C#/.NET | — | — | — |
| Go | — | — | — |
| JavaScript | — | — | — |

`p/default` provides broad language coverage for all Semgrep-supported languages (~30+).
Custom rules can be extended for additional languages as needed.

### Deep Scan Language Coverage

The deep scan builds a tree-sitter index before handing functions to the LLM, so its coverage
depends on what the index can extract:

| Construct | Indexed | Notes |
|---|---|---|
| Named functions and methods | Yes | All languages in `_LANGUAGE_MAP` |
| `.jsx` / `.tsx` (JSX syntax) | Yes | `.tsx` uses the dedicated TSX grammar |
| Bound arrow functions / function expressions | Yes | `const Foo = () => {}`, `const h = useCallback(() => {}, [])`, `memo(() => {})`, `obj.h = function () {}` — named after their binding and qualified by the enclosing function or class |
| C# top-level statements | Yes | `.NET 6+` `Program.cs` with no `Main`: indexed as one synthetic `<top-level>` function, which is where ASP.NET wires up authentication, CORS and endpoints. Files with an explicit `Main` are unaffected |
| Declarations with no body | No | C#/Java interface members, `abstract`, `partial` and `extern` declarations are signatures with no implementation, so they are skipped: there is nothing to analyse and each one would cost an LLM call. Expression-bodied members (`=> expr`) are kept. Controlled by `_BODYLESS_DECLARATION_LANGUAGES` in `indexer.py` |
| Module-level code in other languages | No | Python/JS statements outside any function are not indexed; extend `_TOP_LEVEL_STATEMENT_TYPES` in `indexer.py` to cover them |
| Anonymous inline callbacks | No | `onClick={() => ...}`, `arr.map(x => ...)`, `useEffect(() => ...)` — analysed as part of the enclosing function's body |
| Partially parseable files | Partially | Counted in `files_with_syntax_errors` and logged as a warning; functions after the syntax error may be missing |

Rule guidance for JS/TS (`rule_matcher.py`) is currently oriented towards server-side Node
patterns (`req.body`, `child_process`, `fs.*`). React-specific client-side patterns
(token storage in `localStorage`, `postMessage` without origin checks, `target="_blank"`
without `noopener`, prototype pollution) are not yet mapped to ASVS/CodeGuard rules and rely
on `p/default` plus the LLM's own judgement.

## Extending Detection

### Adding a new custom rule

1. Create or edit a YAML file in `config/`
2. Follow the [Semgrep rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax)
3. Add test fixtures in `tests/fixtures/`
4. Add tests in `tests/test_rules.py`
5. Wire the config file into `semgrep_config` in `scanner_config.yaml` and `aideepsast.py`

### Enabling Semgrep Pro

If cross-function or cross-file taint analysis is needed:

1. Obtain a Semgrep Pro license
2. Run with `semgrep login` to authenticate
3. The existing taint rules will automatically benefit from deeper analysis

## Test Coverage

All custom rules are validated by automated tests:

| Test Class | Rules Tested | Tests |
|---|---|---|
| `TestPropertiesRules` | Config file secrets | 4 detection + 3 false-positive exclusion |
| `TestYamlRules` | YAML secrets | 2 tests |
| `TestEnvRules` | .env secrets | 2 tests |
| `TestJavaRules` | Java source secrets | 1 test |
| `TestPythonRules` | Python source secrets | 3 tests |
| `TestJavaZipSlip` | Java Zip Slip taint | 2 detection + 1 false-positive + 1 count |
| `TestPythonZipSlip` | Python Zip Slip taint | 2 detection + 1 false-positive + 1 count |
