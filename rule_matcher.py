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
Rule Matcher — maps function context to relevant ASVS + CodeGuard rules.

Analyses function metadata (name, body, API calls) from the tree-sitter index
and determines which security rules are relevant. Only functions with matched
rules are sent to Opus for deep analysis.

This is the key component for reducing LLM calls from brute-force to targeted.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from asvs_loader import ASVSLoader
from codeguard_loader import CodeGuardLoader

logger = logging.getLogger(__name__)

# --- API-to-Rule Mapping Tables ---
# Each entry is (compiled_regex, rule_ids).  Regexes use word-boundaries
# (\b) or call-site patterns (e.g. \.method\() to avoid false substring
# matches on ubiquitous tokens like "exec", "Logger", or "URL".

_re = re.compile  # shorthand

# Java/general API calls → ASVS requirement IDs
API_TO_ASVS: List[Tuple[re.Pattern, List[str]]] = [
    # SQL / Database — specific class/method names
    (_re(r"\bPreparedStatement\b"), ["1.2.4"]),
    (_re(r"\bcreateQuery\b|\bcreateNativeQuery\b|\bcreateSQLQuery\b"), ["1.2.4"]),
    (_re(r"\bexecuteQuery\b|\bexecuteUpdate\b"), ["1.2.4"]),
    (_re(r"\bJdbcTemplate\b|\bNamedParameterJdbcTemplate\b"), ["1.2.4"]),

    # OS Command Injection — require call-site context
    (_re(r"Runtime\.getRuntime\(\)\.exec\("), ["1.2.5"]),
    (_re(r"\bProcessBuilder\b"), ["1.2.5"]),
    (_re(r"\bsubprocess\."), ["1.2.5"]),

    # XSS / Output encoding
    (_re(r"\binnerHTML\b|document\.write\(|dangerouslySetInnerHTML"), ["1.2.1"]),

    # LDAP
    (_re(r"\bDirContext\b|\bInitialDirContext\b|\bLdapContext\b"), ["1.2.6"]),

    # Deserialization
    (_re(r"\bObjectInputStream\b|\bXMLDecoder\b"), ["1.5.1"]),
    (_re(r"\.readObject\(|\breadValue\("), ["1.5.1"]),
    (_re(r"\bpickle\.(load|loads)\b"), ["1.5.1"]),
    (_re(r"\byaml\.(load|unsafe_load)\("), ["1.5.1"]),

    # Eval / Code injection — require call parens to avoid comments
    (_re(r"\beval\s*\("), ["1.3.2"]),
    (_re(r"\bScriptEngine\b|\bSpelExpressionParser\b"), ["1.3.2"]),

    # Input handling — specific servlet/Spring types
    (_re(r"\bHttpServletRequest\b"), ["2.1.1"]),
    (_re(r"\bgetParameter\(|\bgetQueryString\(|\bgetRequestURI\("), ["2.1.1"]),
    (_re(r"@RequestParam\b|@RequestBody\b|@PathVariable\b"), ["2.1.1"]),

    # File handling / Path traversal — specific I/O classes
    (_re(r"\bFileOutputStream\b|\bFileWriter\b"), ["5.2.1", "5.2.2"]),
    (_re(r"\bFileInputStream\b"), ["5.2.1"]),
    (_re(r"\bZipEntry\b|\bJarEntry\b|\bZipInputStream\b"), ["5.2.1"]),
    (_re(r"\bMultipartFile\b"), ["5.1.1"]),

    # Authentication — specific encoder/digest classes
    (_re(r"\bPasswordEncoder\b|\bBCryptPasswordEncoder\b"), ["6.1.1"]),
    (_re(r"\bMessageDigest\b|\bDigestUtils\b"), ["6.1.1", "11.1.1"]),

    # Session
    (_re(r"\bHttpSession\b"), ["7.1.1", "7.2.1"]),
    (_re(r"\bnew\s+Cookie\("), ["7.3.1"]),

    # JWT / Tokens
    (_re(r"\bJwts\b|\bJwtParser\b|\bjsonwebtoken\b"), ["9.1.1"]),

    # Cryptography — specific classes, not generic words
    (_re(r"\bCipher\.getInstance\("), ["11.1.1"]),
    (_re(r"\bSecretKeySpec\b|\bKeyGenerator\b"), ["11.1.2"]),
    (_re(r"\bnew\s+Random\("), ["11.2.1"]),
    (_re(r"\bMath\.random\("), ["11.2.1"]),

    # TLS / SSL
    (_re(r"\bSSLContext\b"), ["12.1.1", "12.1.2"]),
    (_re(r"\bTrustManager\b|\bHostnameVerifier\b|\bX509TrustManager\b"), ["12.1.2"]),

    # Error handling — only stack trace exposure, not generic catch
    (_re(r"\.printStackTrace\("), ["13.1.1"]),

    # URL / Redirect — specific redirect calls, not generic "URL"
    (_re(r"\.sendRedirect\("), ["1.2.2"]),

    # XML
    (_re(r"\bDocumentBuilderFactory\b|\bSAXParserFactory\b"), ["1.2.7"]),
    (_re(r"\bXMLReader\b|\bTransformerFactory\b"), ["1.2.7"]),

    # --- Python ---
    (_re(r"\bsubprocess\.(run|call|Popen|check_output)\("), ["1.2.5"]),
    (_re(r"\bos\.(system|popen|exec[lv]?p?)\("), ["1.2.5"]),
    (_re(r"\bflask\.request\b|\brequest\.(args|form|json|data|files)\b"), ["2.1.1"]),
    (_re(r"\bdjango\.db\b|\bcursor\.execute\("), ["1.2.4"]),
    (_re(r"\bSQLAlchemy\b|\btext\s*\("), ["1.2.4"]),
    (_re(r"\bhashlib\.(md5|sha1)\("), ["11.1.1"]),
    (_re(r"\bopen\s*\("), ["5.2.1"]),
    (_re(r"\blxml\.etree\b|\bxml\.etree\.ElementTree\b"), ["1.2.7"]),
    (_re(r"\bmake_response\(|\bredirect\("), ["1.2.2"]),
    (_re(r"\b@login_required\b|\b@requires_auth\b"), ["6.1.1"]),
    (_re(r"\bjinja2\.Template\b|\brender_template_string\("), ["1.2.1"]),

    # --- Go ---
    (_re(r"\bexec\.Command\("), ["1.2.5"]),
    (_re(r"\bsql\.Open\(|\bdb\.Query\(|\bdb\.Exec\("), ["1.2.4"]),
    (_re(r"\bhttp\.HandleFunc\(|\br\.FormValue\(|\br\.URL\.Query\("), ["2.1.1"]),
    (_re(r"\bcrypto/md5\b|\bcrypto/sha1\b|\bcrypto/des\b"), ["11.1.1"]),
    (_re(r"\bos\.Open\(|\bos\.Create\(|\bioutil\.ReadFile\("), ["5.2.1"]),
    (_re(r"\bxml\.NewDecoder\(|\bxml\.Unmarshal\("), ["1.2.7"]),
    (_re(r"\bhttp\.Redirect\("), ["1.2.2"]),
    (_re(r"\btls\.Config\b"), ["12.1.1", "12.1.2"]),
    (_re(r"\btemplate\.HTML\("), ["1.2.1"]),

    # --- C# / .NET ---
    (_re(r"\bSqlCommand\b|\bSqlDataAdapter\b"), ["1.2.4"]),
    (_re(r"\bProcess\.Start\("), ["1.2.5"]),
    (_re(r"\bHttpContext\b|\bRequest\.QueryString\b|\bRequest\.Form\b"), ["2.1.1"]),
    (_re(r"\bBinaryFormatter\b|\bXmlSerializer\b"), ["1.5.1"]),
    (_re(r"\bMD5\.Create\(|\bSHA1\.Create\("), ["11.1.1"]),
    (_re(r"\bFile\.Open\(|\bStreamWriter\b|\bStreamReader\b"), ["5.2.1"]),
    (_re(r"\bXmlDocument\b|\bXmlTextReader\b"), ["1.2.7"]),
    (_re(r"\bResponse\.Redirect\("), ["1.2.2"]),
    (_re(r"\b\[Authorize\]|\b\[AllowAnonymous\]"), ["6.1.1"]),

    # --- PHP ---
    (_re(r"\b(mysql_query|mysqli_query|pg_query)\s*\("), ["1.2.4"]),
    (_re(r"\b(shell_exec|passthru|system|popen|proc_open)\s*\("), ["1.2.5"]),
    (_re(r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b"), ["2.1.1"]),
    (_re(r"\b(unserialize|json_decode)\s*\("), ["1.5.1"]),
    (_re(r"\bmd5\s*\(|\bsha1\s*\("), ["11.1.1"]),
    (_re(r"\b(fopen|file_put_contents|move_uploaded_file)\s*\("), ["5.2.1"]),
    (_re(r"\bheader\s*\(\s*['\"]Location"), ["1.2.2"]),
    (_re(r"\bsimplexml_load_string\(|\bDOMDocument\b"), ["1.2.7"]),

    # --- Ruby ---
    (_re(r"\bsystem\s*\(|\b`[^`]+`|\bIO\.popen\("), ["1.2.5"]),
    (_re(r"\bActiveRecord\b|\bfind_by_sql\(|\bwhere\(\.\*raw"), ["1.2.4"]),
    (_re(r"\bparams\[|\brequest\.(params|body|query_parameters)\b"), ["2.1.1"]),
    (_re(r"\bMarshal\.load\(|\bYAML\.load\("), ["1.5.1"]),
    (_re(r"\bDigest::MD5\b|\bDigest::SHA1\b"), ["11.1.1"]),
    (_re(r"\bredirect_to\b"), ["1.2.2"]),

    # --- Kotlin ---
    (_re(r"\bRuntime\.getRuntime\(\)\.exec\("), ["1.2.5"]),
    (_re(r"\bNamedParameterJdbcTemplate\b|\bjdbcTemplate\b"), ["1.2.4"]),

    # --- Scala ---
    (_re(r"\bslick\.jdbc\b|\bsql\"\"\"|\.as\[\w+\]"), ["1.2.4"]),
    (_re(r"\bProcess\(|\bsys\.process\b|\b\"[^\"]+\"\.!"), ["1.2.5"]),
    (_re(r"\bAction\s*\{|\brequest\.body\b|\brequest\.queryString\b"), ["2.1.1"]),
    (_re(r"\bRedirect\("), ["1.2.2"]),
    (_re(r"\bXML\.load\(|\bscala\.xml\b"), ["1.2.7"]),
    (_re(r"\bSource\.fromFile\("), ["5.2.1"]),

    # --- Swift ---
    (_re(r"\bURLSession\b|\bURLRequest\b"), ["2.1.1"]),
    (_re(r"\bSecKeyEncrypt\b|\bCCCrypt\b"), ["11.1.1"]),
    (_re(r"\bProcess\(\)|\bNSTask\b"), ["1.2.5"]),
    (_re(r"\bFileManager\b\.\w+\("), ["5.2.1"]),

    # --- Rust ---
    (_re(r"\bCommand::new\("), ["1.2.5"]),
    (_re(r"\bunsafe\s*\{"), ["1.3.2"]),
    (_re(r"\bsqlx::|\bdiesel::"), ["1.2.4"]),
    (_re(r"\bstd::fs::(read|write|File::open)"), ["5.2.1"]),

    # --- JavaScript / TypeScript ---
    (_re(r"\bchild_process\b|\bexecSync\(|\bspawnSync\("), ["1.2.5"]),
    (_re(r"\breq\.(body|params|query|headers)\b"), ["2.1.1"]),
    (_re(r"\bres\.redirect\("), ["1.2.2"]),
    (_re(r"\bfs\.(readFile|writeFile|createReadStream)\("), ["5.2.1"]),
    (_re(r"\bcrypto\.createCipher\(|\bcrypto\.createHash\("), ["11.1.1"]),
    (_re(r"\bDOMParser\b|\bparseFromString\("), ["1.2.7"]),
    (_re(r"\bexpress\.Router\(|\bapp\.(get|post|put|delete)\("), ["2.1.1"]),

    # --- Bash ---
    (_re(r"\beval\s|\bcurl\s|\bwget\s"), ["1.2.5"]),
    (_re(r"\bsource\s|\b\. /"), ["1.3.2"]),
]

# API calls → CodeGuard rule IDs
API_TO_CODEGUARD: List[Tuple[re.Pattern, List[str]]] = [
    # Input validation — specific injection-relevant APIs
    (_re(r"\bgetParameter\(|\bgetHeader\("), ["codeguard-0-input-validation-injection"]),
    (_re(r"@RequestParam\b"), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bProcessBuilder\b|\bsubprocess\."), ["codeguard-0-input-validation-injection"]),
    (_re(r"\beval\s*\("), ["codeguard-0-input-validation-injection"]),

    # File handling — specific I/O classes
    (_re(r"\bFileOutputStream\b|\bFileInputStream\b"), ["codeguard-0-file-handling-and-uploads"]),
    (_re(r"\bZipEntry\b|\bMultipartFile\b"), ["codeguard-0-file-handling-and-uploads"]),

    # Authentication — specific auth classes
    (_re(r"\bPasswordEncoder\b|\bBCryptPasswordEncoder\b"), ["codeguard-0-authentication-mfa"]),
    (_re(r"\bAuthenticationManager\b"), ["codeguard-0-authentication-mfa"]),

    # Authorization — annotation/class patterns
    (_re(r"@PreAuthorize\b|@Secured\b|@RolesAllowed\b"), ["codeguard-0-authorization-access-control"]),
    (_re(r"\bAccessDecisionManager\b"), ["codeguard-0-authorization-access-control"]),

    # Session / Cookies — specific types
    (_re(r"\bHttpSession\b"), ["codeguard-0-session-management-and-cookies"]),
    (_re(r"\bnew\s+Cookie\("), ["codeguard-0-session-management-and-cookies"]),

    # Serialization / XML — specific dangerous classes
    (_re(r"\bObjectInputStream\b|\bXMLDecoder\b"), ["codeguard-0-xml-and-serialization"]),
    (_re(r"\bDocumentBuilderFactory\b|\bSAXParserFactory\b"), ["codeguard-0-xml-and-serialization"]),
    (_re(r"\bpickle\.(load|loads)\b"), ["codeguard-0-xml-and-serialization"]),

    # Crypto — specific classes, not generic words
    (_re(r"\bCipher\.getInstance\("), ["codeguard-1-crypto-algorithms"]),
    (_re(r"\bMessageDigest\b|\bSecretKeySpec\b"), ["codeguard-1-crypto-algorithms"]),
    (_re(r"\bnew\s+Random\("), ["codeguard-1-crypto-algorithms"]),

    # Certificates / TLS
    (_re(r"\bTrustManager\b|\bHostnameVerifier\b|\bX509TrustManager\b"), ["codeguard-1-digital-certificates"]),
    (_re(r"\bSSLContext\b"), ["codeguard-1-digital-certificates"]),

    # Hardcoded credentials — assignment patterns, not just substring
    (_re(r'(?:password|passwd|secret|api_key|apiKey)\s*=\s*["\']'), ["codeguard-1-hardcoded-credentials"]),
    (_re(r'"(?:password|secret|api[_-]?key)"\s*:\s*"'), ["codeguard-1-hardcoded-credentials"]),

    # Data storage — specific JDBC classes
    (_re(r"\bPreparedStatement\b|\bJdbcTemplate\b"), ["codeguard-0-data-storage"]),

    # API / Web services — specific HTTP client classes
    (_re(r"\bRestTemplate\b|\bWebClient\b|\bHttpClient\b"), ["codeguard-0-api-web-services"]),

    # C unsafe functions — require call parens
    (_re(r"\b(strcpy|strcat|sprintf|gets|scanf|memcpy)\s*\("), ["codeguard-0-safe-c-functions"]),

    # Cloud / K8s
    (_re(r"\bKubernetesClient\b"), ["codeguard-0-cloud-orchestration-kubernetes"]),

    # --- Python ---
    (_re(r"\bsubprocess\.(run|call|Popen|check_output)\("), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bos\.(system|popen|exec[lv]?p?)\("), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bflask\.request\b|\brequest\.(args|form|json|files)\b"), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bhashlib\.(md5|sha1)\("), ["codeguard-1-crypto-algorithms"]),
    (_re(r"\bopen\s*\("), ["codeguard-0-file-handling-and-uploads"]),
    (_re(r"\blxml\.etree\b|\bxml\.etree\b"), ["codeguard-0-xml-and-serialization"]),
    (_re(r"\b@login_required\b"), ["codeguard-0-authentication-mfa"]),

    # --- Go ---
    (_re(r"\bexec\.Command\("), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bsql\.Open\(|\bdb\.Query\(|\bdb\.Exec\("), ["codeguard-0-data-storage"]),
    (_re(r"\br\.FormValue\(|\br\.URL\.Query\("), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bcrypto/md5\b|\bcrypto/des\b"), ["codeguard-1-crypto-algorithms"]),
    (_re(r"\btls\.Config\b"), ["codeguard-1-digital-certificates"]),
    (_re(r"\bos\.Open\(|\bos\.Create\("), ["codeguard-0-file-handling-and-uploads"]),

    # --- C# / .NET ---
    (_re(r"\bSqlCommand\b|\bSqlDataAdapter\b"), ["codeguard-0-data-storage"]),
    (_re(r"\bProcess\.Start\("), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bRequest\.QueryString\b|\bRequest\.Form\b"), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bBinaryFormatter\b"), ["codeguard-0-xml-and-serialization"]),
    (_re(r"\bMD5\.Create\(|\bSHA1\.Create\("), ["codeguard-1-crypto-algorithms"]),
    (_re(r"\bFile\.Open\(|\bStreamWriter\b"), ["codeguard-0-file-handling-and-uploads"]),
    (_re(r"\b\[Authorize\]"), ["codeguard-0-authorization-access-control"]),

    # --- PHP ---
    (_re(r"\b(mysql_query|mysqli_query|pg_query)\s*\("), ["codeguard-0-data-storage"]),
    (_re(r"\b(shell_exec|passthru|system|popen)\s*\("), ["codeguard-0-input-validation-injection"]),
    (_re(r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b"), ["codeguard-0-input-validation-injection"]),
    (_re(r"\b(unserialize)\s*\("), ["codeguard-0-xml-and-serialization"]),
    (_re(r"\bmd5\s*\(|\bsha1\s*\("), ["codeguard-1-crypto-algorithms"]),
    (_re(r"\b(fopen|file_put_contents|move_uploaded_file)\s*\("), ["codeguard-0-file-handling-and-uploads"]),

    # --- Ruby ---
    (_re(r"\bsystem\s*\(|\bIO\.popen\("), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bfind_by_sql\("), ["codeguard-0-data-storage"]),
    (_re(r"\bparams\["), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bMarshal\.load\("), ["codeguard-0-xml-and-serialization"]),
    (_re(r"\bDigest::MD5\b"), ["codeguard-1-crypto-algorithms"]),

    # --- JavaScript / TypeScript ---
    (_re(r"\bchild_process\b|\bexecSync\("), ["codeguard-0-input-validation-injection"]),
    (_re(r"\breq\.(body|params|query|headers)\b"), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bfs\.(readFile|writeFile|createReadStream)\("), ["codeguard-0-file-handling-and-uploads"]),
    (_re(r"\bcrypto\.createCipher\(|\bcrypto\.createHash\("), ["codeguard-1-crypto-algorithms"]),

    # --- Scala ---
    (_re(r"\bslick\.jdbc\b|\bsql\"\"\""), ["codeguard-0-data-storage"]),
    (_re(r"\bProcess\(|\bsys\.process\b"), ["codeguard-0-input-validation-injection"]),
    (_re(r"\brequest\.body\b|\brequest\.queryString\b"), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bXML\.load\("), ["codeguard-0-xml-and-serialization"]),
    (_re(r"\bSource\.fromFile\("), ["codeguard-0-file-handling-and-uploads"]),

    # --- Rust ---
    (_re(r"\bCommand::new\("), ["codeguard-0-input-validation-injection"]),
    (_re(r"\bunsafe\s*\{"), ["codeguard-0-safe-c-functions"]),
    (_re(r"\bsqlx::|\bdiesel::"), ["codeguard-0-data-storage"]),

    # --- Bash ---
    (_re(r"\beval\s|\bcurl\s|\bwget\s"), ["codeguard-0-input-validation-injection"]),
]

# Function name patterns → rule IDs (ASVS + CodeGuard combined)
# ONLY patterns that strongly indicate security-relevant logic.
# Removed: error/exception, log/logger/trace, api/handler (too generic).
NAME_PATTERNS: List[Tuple[re.Pattern, List[str], List[str]]] = [
    # (pattern, asvs_ids, codeguard_ids)
    (re.compile(r"(?i)(?:^|[_.])(?:auth|login|signIn|verifyUser|verifyCredentials|verifyToken)"),
     ["6.1.1", "6.2.1", "6.3.1"], ["codeguard-0-authentication-mfa"]),

    (re.compile(r"(?i)(?:^|[_.])(?:password|credential|apiKey|api_key)"),
     ["6.1.1", "14.2.1"], ["codeguard-1-hardcoded-credentials"]),

    (re.compile(r"(?i)(?:^|[_.])(?:encrypt|decrypt|hash|cipher|digest|hmac)"),
     ["11.1.1", "11.1.2"], ["codeguard-1-crypto-algorithms"]),

    (re.compile(r"(?i)(?:^|[_.])(?:upload|download|extractZip|unzip)"),
     ["5.1.1", "5.2.1", "5.2.2"], ["codeguard-0-file-handling-and-uploads"]),

    (re.compile(r"(?i)(?:^|[_.])(?:executeQuery|executeUpdate|sqlQuery|runQuery|jdbcQuery)"),
     ["1.2.4"], ["codeguard-0-input-validation-injection", "codeguard-0-data-storage"]),

    (re.compile(r"(?i)(?:^|[_.])(?:session|cookie|jwt)"),
     ["7.1.1", "7.2.1", "7.3.1", "9.1.1"], ["codeguard-0-session-management-and-cookies"]),

    (re.compile(r"(?i)(?:^|[_.])(?:deseriali|unmarshal|readObject|fromJson)"),
     ["1.5.1"], ["codeguard-0-xml-and-serialization"]),

    (re.compile(r"(?i)(?:^|[_.])(?:execCommand|runCommand|shellExec|popen|spawnProcess)"),
     ["1.2.5"], ["codeguard-0-input-validation-injection"]),

    (re.compile(r"(?i)(?:^|[_.])(?:redirect|sendRedirect)"),
     ["1.2.2"], ["codeguard-0-client-side-web-security"]),

    (re.compile(r"(?i)(?:^|[_.])(?:sanitiz|escapeHtml|encodeUrl)"),
     ["1.2.1", "1.3.1"], ["codeguard-0-input-validation-injection"]),

    (re.compile(r"(?i)(?:^|[_.])(?:ssl|tls|certificate)"),
     ["12.1.1", "12.1.2"], ["codeguard-1-digital-certificates"]),

    (re.compile(r"(?i)(?:^|[_.])(?:authorize|checkPermission|checkRole|isAllowed)"),
     ["8.1.1", "8.1.2"], ["codeguard-0-authorization-access-control"]),

    (re.compile(r"(?i)(?:^|[_.])(?:parseXml|xpathQuery|xsltTransform)"),
     ["1.2.7"], ["codeguard-0-xml-and-serialization"]),

    (re.compile(r"(?i)(?:^|[_.])(?:ldapSearch|ldapQuery|ldapBind)"),
     ["1.2.6"], ["codeguard-0-input-validation-injection"]),
]


class MatchResult:
    """Result of matching a function against security rules."""

    def __init__(self):
        self.asvs_ids: Set[str] = set()
        self.codeguard_ids: Set[str] = set()
        self.match_reasons: List[str] = []

    @property
    def has_matches(self) -> bool:
        return bool(self.asvs_ids or self.codeguard_ids)

    @property
    def total_rules(self) -> int:
        return len(self.asvs_ids) + len(self.codeguard_ids)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asvs_ids": sorted(self.asvs_ids),
            "codeguard_ids": sorted(self.codeguard_ids),
            "match_reasons": self.match_reasons,
            "total_rules": self.total_rules,
        }


class RuleMatcher:
    """
    Maps function context to relevant security rules.

    Analyses function name, body, and API usage to determine which
    ASVS requirements and CodeGuard rules are relevant.
    """

    def __init__(self, asvs: Optional[ASVSLoader] = None,
                 codeguard: Optional[CodeGuardLoader] = None):
        self.asvs = asvs
        self.codeguard = codeguard
        self._stats = {"functions_checked": 0, "functions_matched": 0,
                       "functions_skipped": 0}

    def match_function(self, func: Dict[str, Any]) -> MatchResult:
        """
        Match a function against all security rules.

        Args:
            func: Function dict from the indexer with keys:
                  name, qualified_name, file_path, body, language, etc.

        Returns:
            MatchResult with matched ASVS and CodeGuard rule IDs.
        """
        result = MatchResult()
        self._stats["functions_checked"] += 1

        func_name = func.get("qualified_name") or func.get("name", "")
        body = func.get("body", "")
        language = func.get("language", "")

        # 1. Match by API calls in function body
        self._match_api_calls(body, result)

        # 2. Match by function name patterns
        self._match_name_patterns(func_name, result)

        # 3. Language-specific CodeGuard rules
        if self.codeguard and self.codeguard.is_loaded:
            self._match_language_rules(language, body, result)

        if result.has_matches:
            self._stats["functions_matched"] += 1
        else:
            self._stats["functions_skipped"] += 1

        return result

    def _match_api_calls(self, body: str, result: MatchResult) -> None:
        """Check function body for security-relevant API calls using regex."""
        if self.asvs:
            for pattern, asvs_ids in API_TO_ASVS:
                if pattern.search(body):
                    for aid in asvs_ids:
                        result.asvs_ids.add(aid)
                    result.match_reasons.append(f"API: {pattern.pattern}")

        if self.codeguard:
            for pattern, cg_ids in API_TO_CODEGUARD:
                if pattern.search(body):
                    for cid in cg_ids:
                        result.codeguard_ids.add(cid)

    def _match_name_patterns(self, func_name: str, result: MatchResult) -> None:
        """Check function name against security-relevant patterns."""
        for pattern, asvs_ids, cg_ids in NAME_PATTERNS:
            if pattern.search(func_name):
                if self.asvs:
                    for aid in asvs_ids:
                        result.asvs_ids.add(aid)
                if self.codeguard:
                    for cid in cg_ids:
                        result.codeguard_ids.add(cid)
                result.match_reasons.append(f"Name: {pattern.pattern}")

    def _match_language_rules(self, language: str, body: str,
                               result: MatchResult) -> None:
        """Add language-specific CodeGuard rules based on code patterns."""
        if not language:
            return

        # C-specific unsafe function detection
        if language in ("c", "cpp"):
            c_unsafe = ["strcpy", "strcat", "sprintf", "vsprintf", "gets",
                        "scanf", "sscanf", "fscanf", "strncpy", "strncat",
                        "memcpy", "memmove", "alloca"]
            for fn in c_unsafe:
                if fn + "(" in body:
                    result.codeguard_ids.add("codeguard-0-safe-c-functions")
                    result.match_reasons.append(f"C-unsafe: {fn}")
                    break

    def build_guided_prompt(self, result: MatchResult) -> str:
        """
        Build a rule-guided prompt section from match results.

        This replaces the open-ended "analyse for vulnerabilities" prompt
        with specific rules to check against.
        """
        sections = []

        if result.asvs_ids and self.asvs and self.asvs.is_loaded:
            sections.append("ASVS Requirements to check:")
            sections.append(self.asvs.format_for_prompt(sorted(result.asvs_ids)))

        if result.codeguard_ids and self.codeguard and self.codeguard.is_loaded:
            sections.append("\nCodeGuard Guidelines to check:")
            sections.append(self.codeguard.format_for_prompt(
                sorted(result.codeguard_ids), max_body_chars=300))

        if not sections:
            return ""

        prompt = "\n".join(sections)
        prompt += "\n\nFor each violated requirement, provide:"
        prompt += "\n1. Which requirement is violated (ID)"
        prompt += "\n2. The specific code that violates it"
        prompt += "\n3. Why it's a violation (evidence)"
        prompt += "\n4. CWE classification"
        prompt += "\n5. Remediation guidance"

        return prompt

    def get_stats(self) -> Dict[str, Any]:
        """Get matcher statistics."""
        return dict(self._stats)

    def reset_stats(self) -> None:
        """Reset statistics counters."""
        self._stats = {"functions_checked": 0, "functions_matched": 0,
                       "functions_skipped": 0}
