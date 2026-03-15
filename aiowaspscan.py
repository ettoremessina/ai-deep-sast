#!/usr/bin/env python3

import os
import sys
import json
import yaml
import argparse
import logging
import tempfile
import platform
import subprocess
from datetime import datetime, timezone


def utc_now_iso():
    """Return current UTC time as ISO 8601 string with Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def setup_logging(log_level="INFO", log_file=None):
    """Configure logging for console and optional file output."""
    log_format = '%(asctime)s [%(levelname)s] %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format=log_format,
        datefmt=date_format,
        handlers=handlers
    )
    return logging.getLogger(__name__)



def load_config(config_path):
    """Load configuration from a YAML file."""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as e:
        print(f"Error parsing config file: {e}")
        return {}


def parse_arguments():
    """Parse command-line arguments for CI/CD flexibility."""
    parser = argparse.ArgumentParser(
        description="AI-Powered OWASP Top 10 Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 aiowaspscan.py --target ./src
  python3 aiowaspscan.py --target app.py --severity-threshold ERROR
  python3 aiowaspscan.py --config config/scanner_config.yaml
  python3 aiowaspscan.py --target ./src --skip-llm
        """
    )
    parser.add_argument(
        '--target', type=str, default=None,
        help='Target file or directory to scan (default: current directory)'
    )
    parser.add_argument(
        '--hf-repo', type=str, default=None,
        help='Hugging Face repo for the GGUF model (default: fdtn-ai/Foundation-Sec-8B-Q8_0-GGUF)'
    )
    parser.add_argument(
        '--hf-file', type=str, default=None,
        help='GGUF model file name (default: foundation-sec-8b-q8_0.gguf)'
    )
    parser.add_argument(
        '--ctx-size', type=int, default=None,
        help='Context window size for the model (default: 4096)'
    )
    parser.add_argument(
        '--n-gpu-layers', type=int, default=None,
        help='Number of layers to offload to GPU. -1 for all (default: -1)'
    )
    parser.add_argument(
        '--threads', type=int, default=None,
        help='Number of CPU threads for inference (default: auto-detect)'
    )
    parser.add_argument(
        '--max-tokens', type=int, default=None,
        help='Maximum tokens for LLM generation (default: 2048)'
    )
    parser.add_argument(
        '--temperature', type=float, default=None,
        help='Temperature for LLM generation (default: 0.1)'
    )
    parser.add_argument(
        '--output-dir', type=str, default=None,
        help='Directory to store reports (default: security-reports)'
    )
    parser.add_argument(
        '--severity-threshold', type=str,
        choices=['INFO', 'WARNING', 'ERROR'], default=None,
        help='Minimum severity to fail the build (default: WARNING)'
    )
    parser.add_argument(
        '--llm-timeout', type=int, default=None,
        help='Timeout in seconds for each LLM call (default: 300)'
    )
    parser.add_argument(
        '--semgrep-config', type=str, default=None,
        help='Semgrep ruleset config (default: p/owasp-top-ten)'
    )
    parser.add_argument(
        '--semgrep-timeout', type=int, default=None,
        help='Timeout in seconds for Semgrep scan (default: 300)'
    )
    parser.add_argument(
        '--config', type=str, default=None,
        help='Path to YAML configuration file'
    )
    parser.add_argument(
        '--log-level', type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default=None,
        help='Logging level (default: INFO)'
    )
    parser.add_argument(
        '--log-file', type=str, default=None,
        help='Path to log file (default: None, console only)'
    )
    parser.add_argument(
        '--skip-llm', action='store_true', default=False,
        help='Skip LLM analysis (only run Semgrep scan)'
    )
    return parser.parse_args()


def detect_cpu_threads():
    """Detect optimal number of CPU threads."""
    try:
        if platform.system() == 'Darwin':
            result = subprocess.run(
                ['sysctl', '-n', 'hw.perflevel0.logicalcpu'],
                capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip())
        return os.cpu_count() or 4
    except Exception:
        return 4


def merge_configuration(args):
    """
    Merge configuration from YAML file, CLI arguments,
    and environment variables. Priority: CLI > ENV > YAML > Defaults.
    """
    defaults = {
        'target': '.',
        'hf_repo': 'fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF',
        'hf_file': 'foundation-sec-8b-instruct-q8_0.gguf',
        'ctx_size': 4096,
        'n_gpu_layers': -1,
        'threads': detect_cpu_threads(),
        'max_tokens': 2048,
        'temperature': 0.1,
        'output_dir': 'security-reports',
        'severity_threshold': 'WARNING',
        'llm_timeout': 300,
        'semgrep_config': 'p/owasp-top-ten',
        'semgrep_timeout': 300,
        'log_level': 'INFO',
        'log_file': None,
        'skip_llm': False
    }

    # Load YAML config if provided
    yaml_config = {}
    if args.config:
        yaml_config = load_config(args.config)

    # Environment variable overrides
    env_config = {}
    env_str_mappings = {
        'target': 'SCANNER_TARGET',
        'hf_repo': 'SCANNER_HF_REPO',
        'hf_file': 'SCANNER_HF_FILE',
        'output_dir': 'SCANNER_OUTPUT_DIR',
        'severity_threshold': 'SCANNER_SEVERITY_THRESHOLD',
        'semgrep_config': 'SCANNER_SEMGREP_CONFIG',
        'log_level': 'SCANNER_LOG_LEVEL',
        'log_file': 'SCANNER_LOG_FILE',
    }
    for key, env_var in env_str_mappings.items():
        val = os.environ.get(env_var)
        if val is not None:
            env_config[key] = val

    env_int_mappings = {
        'ctx_size': 'SCANNER_CTX_SIZE',
        'n_gpu_layers': 'SCANNER_N_GPU_LAYERS',
        'threads': 'SCANNER_THREADS',
        'max_tokens': 'SCANNER_MAX_TOKENS',
        'llm_timeout': 'SCANNER_LLM_TIMEOUT',
        'semgrep_timeout': 'SCANNER_SEMGREP_TIMEOUT',
    }
    for key, env_var in env_int_mappings.items():
        val = os.environ.get(env_var)
        if val is not None:
            try:
                env_config[key] = int(val)
            except ValueError:
                pass

    temp_env = os.environ.get('SCANNER_TEMPERATURE')
    if temp_env is not None:
        try:
            env_config['temperature'] = float(temp_env)
        except ValueError:
            pass

    skip_llm_env = os.environ.get('SCANNER_SKIP_LLM')
    if skip_llm_env is not None:
        env_config['skip_llm'] = skip_llm_env.lower() in ('true', '1', 'yes')

    # CLI argument overrides
    cli_config = {}
    cli_mappings = {
        'target': args.target,
        'hf_repo': args.hf_repo,
        'hf_file': args.hf_file,
        'ctx_size': args.ctx_size,
        'n_gpu_layers': args.n_gpu_layers,
        'threads': args.threads,
        'max_tokens': args.max_tokens,
        'temperature': args.temperature,
        'output_dir': args.output_dir,
        'severity_threshold': args.severity_threshold,
        'llm_timeout': args.llm_timeout,
        'semgrep_config': args.semgrep_config,
        'semgrep_timeout': args.semgrep_timeout,
        'log_level': args.log_level,
        'log_file': args.log_file,
    }
    for key, val in cli_mappings.items():
        if val is not None:
            cli_config[key] = val

    if args.skip_llm:
        cli_config['skip_llm'] = True

    # Merge: CLI > ENV > YAML > Defaults
    final_config = {}
    for key in defaults:
        if key in cli_config:
            final_config[key] = cli_config[key]
        elif key in env_config:
            final_config[key] = env_config[key]
        elif key in yaml_config:
            final_config[key] = yaml_config[key]
        else:
            final_config[key] = defaults[key]

    return final_config


def get_system_memory_gb():
    """Get total system memory in GB."""
    try:
        if platform.system() == 'Darwin':
            result = subprocess.run(
                ['sysctl', '-n', 'hw.memsize'],
                capture_output=True, text=True
            )
            return int(result.stdout.strip()) / (1024 ** 3)
    except Exception:
        pass
    return 0


def validate_environment(target, skip_llm, config, logger):
    """Validate that all required tools and targets exist."""
    logger.info("Validating environment...")

    # System info
    logger.info(f"Platform: {platform.system()} {platform.machine()}")
    mem_gb = get_system_memory_gb()
    if mem_gb > 0:
        logger.info(f"System memory: {mem_gb:.1f} GB")

    # Check target exists
    if not os.path.exists(target):
        logger.error(f"Target '{target}' not found.")
        sys.exit(2)
    logger.info(f"Target '{target}' found.")

    # Check Semgrep is installed
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True, text=True, timeout=15
        )
        logger.info(f"Semgrep version: {result.stdout.strip()}")
    except FileNotFoundError:
        logger.error("Semgrep is not installed or not in PATH.")
        logger.error("Install with: pip install semgrep")
        sys.exit(2)
    except subprocess.TimeoutExpired:
        logger.error("Semgrep version check timed out.")
        sys.exit(2)

    # Check llama-cli is installed (only if LLM analysis is enabled)
    if not skip_llm:
        try:
            result = subprocess.run(
                ["llama-cli", "--version"],
                capture_output=True, text=True, timeout=15
            )
            logger.info(f"llama-cli version: {result.stdout.strip()}")
        except FileNotFoundError:
            logger.error("llama-cli is not installed or not in PATH.")
            logger.error("Install llama.cpp: brew install llama.cpp")
            logger.error("Or use --skip-llm to run without LLM analysis.")
            sys.exit(2)
        except subprocess.TimeoutExpired:
            logger.error("llama-cli version check timed out.")
            sys.exit(2)

        # Memory check
        if mem_gb > 0 and mem_gb < 12:
            logger.warning(
                f"System has {mem_gb:.1f} GB memory. "
                f"The Q8_0 model requires ~8-9 GB. "
                f"Performance may be degraded. Consider using a Q4 model."
            )

        logger.info(f"Model: {config['hf_repo']} / {config['hf_file']}")
        logger.info(f"Context size: {config['ctx_size']}")
        logger.info(f"GPU layers: {config['n_gpu_layers']}")
        logger.info(f"CPU threads: {config['threads']}")
    else:
        logger.info("LLM analysis is disabled. Skipping llama-cli check.")

    logger.info("Environment validation passed.")


def run_semgrep_scan(target, config, output_dir, timeout, logger):
    """Run Semgrep OWASP Top 10 scan and return results."""
    semgrep_output = os.path.join(output_dir, 'semgrep_report.json')
    logger.info(f"Running Semgrep scan on '{target}' with config '{config}'...")

    try:
        result = subprocess.run(
            [
                "semgrep",
                f"--config={config}",
                "--json",
                f"--output={semgrep_output}",
                target
            ],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode > 1:
            logger.error(f"Semgrep scan failed with exit code {result.returncode}")
            logger.error(f"Stderr: {result.stderr}")
            sys.exit(2)

        if result.returncode == 1:
            logger.info("Semgrep completed with findings (exit code 1).")
        else:
            logger.info("Semgrep completed with no findings (exit code 0).")

    except FileNotFoundError:
        logger.error("Semgrep executable not found.")
        sys.exit(2)
    except subprocess.TimeoutExpired:
        logger.error(f"Semgrep scan timed out after {timeout} seconds.")
        sys.exit(2)

    # Load results
    try:
        with open(semgrep_output) as f:
            data = json.load(f)

        findings_count = len(data.get('results', []))
        errors_count = len(data.get('errors', []))
        logger.info(f"Semgrep results: {findings_count} finding(s), {errors_count} error(s).")

        for finding in data.get('results', []):
            rule_id = finding.get('check_id', 'unknown')
            severity = finding.get('extra', {}).get('severity', 'UNKNOWN')
            file_path = finding.get('path', 'unknown')
            line = finding.get('start', {}).get('line', '?')
            logger.debug(f"  Found: [{severity}] {rule_id} at {file_path}:{line}")

        for error in data.get('errors', []):
            logger.warning(f"Semgrep error: {error.get('message', 'Unknown error')}")

        return data

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Semgrep JSON output: {e}")
        sys.exit(2)
    except FileNotFoundError:
        logger.error(f"Semgrep output file not found at '{semgrep_output}'.")
        sys.exit(2)


def build_prompt(code_snippet, semgrep_finding, rule_id):
    """
    Build the LLM prompt for a given finding.
    Optimised for Cisco Foundation-Sec-8B-Instruct model.
    """
    return f"""You are a cybersecurity expert performing a secure code review.
Your task is to analyze a vulnerability detected by Semgrep and map it to the OWASP Top 10 (2021) framework.

**Rule ID:** {rule_id}
**Semgrep Finding:** {semgrep_finding}

**Code Snippet:**

{code_snippet}

Provide your analysis in the following structured format:

1. **OWASP Category**: Identify the specific OWASP Top 10 (2021) category (e.g., A01:2021 - Broken Access Control). If multiple categories apply, list all.
2. **CWE Mapping**: Identify the relevant CWE (Common Weakness Enumeration) ID(s).
3. **CVSS Estimate**: Provide an estimated CVSS v3.1 base score and vector string.
4. **Severity**: Rate as one of: INFO, WARNING, ERROR.
5. **Attack Vector**: Describe the specific attack scenario. Include example payloads where applicable.
6. **Impact**: Describe the potential business and technical impact if exploited, including data confidentiality, integrity, and availability.
7. **Remediation**: Provide a specific, secure code fix. Show the corrected code.
8. **Defence in Depth**: Suggest additional security controls beyond the code fix (e.g., WAF rules, input validation layers, security headers).
9. **References**: List relevant CWE IDs, OWASP links, and Cisco security advisories if applicable."""


def ask_llm(code_snippet, semgrep_finding, rule_id, config, logger):
    """
    Query Cisco Foundation-Sec-8B via llama-cli with GGUF model.
    Uses a temporary file for the prompt to avoid
    exposing code in shell history or process logs.

    Command:
    llama-cli --hf-repo fdtn-ai/Foundation-Sec-8B-Q8_0-GGUF \
              --hf-file foundation-sec-8b-q8_0.gguf \
              -p "<prompt>"
    """
    prompt = build_prompt(code_snippet, semgrep_finding, rule_id)
    tmp_path = None

    logger.debug("=" * 70)
    logger.debug("LLM PROMPT (Foundation-Sec-8B via llama-cli)")
    logger.debug("=" * 70)
    logger.debug(prompt)
    logger.debug("=" * 70)

    try:
        # Write prompt to temporary file for security
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.txt', delete=False, prefix='owasp_prompt_'
        ) as tmp:
            tmp.write(prompt)
            tmp_path = tmp.name

        logger.debug(f"Prompt written to temporary file: {tmp_path}")

        # Read prompt back for -p flag
        with open(tmp_path, 'r') as f:
            prompt_content = f.read()

        # Build llama-cli command
        cmd = [
            "llama-cli",
            "--hf-repo", config['hf_repo'],
            "--hf-file", config['hf_file'],
            "-c", str(config['ctx_size']),
            "-ngl", str(config['n_gpu_layers']),
            "-t", str(config['threads']),
            "--temp", str(config['temperature']),
            "-n", str(config['max_tokens']),
            "--no-display-prompt",
            "-p", prompt_content
        ]

        logger.debug(
            f"Executing: llama-cli --hf-repo {config['hf_repo']} "
            f"--hf-file {config['hf_file']} "
            f"-c {config['ctx_size']} -ngl {config['n_gpu_layers']} "
            f"-t {config['threads']} -p <prompt>"
        )

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config['llm_timeout']
        )

        if result.returncode != 0:
            logger.warning(
                f"llama-cli returned exit code {result.returncode}. "
                f"Stderr: {result.stderr.strip()[:500]}"
            )
            return {
                "status": "error",
                "message": "LLM analysis failed. Manual review required.",
                "raw_output": result.stderr.strip()[:500]
            }

        output = result.stdout.strip()
        if not output:
            logger.warning("llama-cli returned empty output.")
            return {
                "status": "empty",
                "message": "LLM returned empty response. Manual review required.",
                "raw_output": ""
            }

        return {
            "status": "success",
            "message": output,
            "raw_output": output
        }

    except subprocess.TimeoutExpired:
        logger.warning(
            f"llama-cli timed out after {config['llm_timeout']} seconds."
        )
        return {
            "status": "timeout",
            "message": f"LLM analysis timed out after {config['llm_timeout']}s. Manual review required.",
            "raw_output": ""
        }
    except FileNotFoundError:
        logger.error("llama-cli executable not found.")
        return {
            "status": "error",
            "message": "llama-cli not found. Manual review required.",
            "raw_output": ""
        }
    except Exception as e:
        logger.warning(f"llama-cli call failed: {e}")
        return {
            "status": "error",
            "message": f"LLM analysis error: {str(e)}. Manual review required.",
            "raw_output": ""
        }
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
            logger.debug(f"Temporary prompt file cleaned up: {tmp_path}")


def extract_code_snippet(file_path, start_line, end_line, context_lines=3, logger=None):
    """
    Extract the relevant code snippet from the file.
    Adds context lines above and below for better analysis.
    """
    try:
        with open(file_path) as f:
            lines = f.readlines()

        total_lines = len(lines)
        ctx_start = max(0, start_line - 1 - context_lines)
        ctx_end = min(total_lines, end_line + context_lines)

        snippet_lines = []
        for i in range(ctx_start, ctx_end):
            marker = ">>>" if start_line - 1 <= i < end_line else "   "
            snippet_lines.append(f"{marker} {i+1:4d} | {lines[i].rstrip()}")

        return '\n'.join(snippet_lines)

    except FileNotFoundError:
        if logger:
            logger.warning(f"File not found: {file_path}")
        return "Code snippet unavailable: file not found."
    except IndexError:
        if logger:
            logger.warning(f"Line range out of bounds in {file_path}")
        return "Code snippet unavailable: line range out of bounds."
    except Exception as e:
        if logger:
            logger.warning(f"Error reading {file_path}: {e}")
        return f"Code snippet unavailable: {str(e)}"


def process_single_finding(finding, config, logger):
    """Process a single Semgrep finding."""
    file_path = finding['path']
    start = finding['start']['line']
    end = finding['end']['line']
    message = finding['extra']['message']
    rule_id = finding.get('check_id', 'unknown')
    severity = finding['extra'].get('severity', 'WARNING').upper()
    metadata = finding['extra'].get('metadata', {})

    code_snippet = extract_code_snippet(
        file_path, start, end, context_lines=3, logger=logger
    )

    logger.info(f"Analyzing [{severity}] '{rule_id}' at {file_path}:{start}-{end} ...")
    ai_result = ask_llm(code_snippet, message, rule_id, config, logger)

    return {
        "file": file_path,
        "start_line": start,
        "end_line": end,
        "lines": f"{start}-{end}",
        "rule_id": rule_id,
        "severity": severity,
        "semgrep_message": message,
        "code_snippet": code_snippet,
        "ai_analysis": ai_result,
        "metadata": {
            "cwe": metadata.get('cwe', []),
            "owasp": metadata.get('owasp', []),
            "confidence": metadata.get('confidence', 'UNKNOWN'),
            "references": metadata.get('references', [])
        },
        "timestamp": utc_now_iso()
    }


def process_findings(data, config, skip_llm, logger):
    """Analyze each Semgrep finding using llama-cli."""
    findings = data.get('results', [])
    if not findings:
        logger.info("No findings to process.")
        return []

    report = []

    if skip_llm:
        logger.info(f"Processing {len(findings)} finding(s) without LLM analysis...")
        for finding in findings:
            file_path = finding['path']
            start = finding['start']['line']
            end = finding['end']['line']
            message = finding['extra']['message']
            rule_id = finding.get('check_id', 'unknown')
            severity = finding['extra'].get('severity', 'WARNING').upper()
            metadata = finding['extra'].get('metadata', {})

            code_snippet = extract_code_snippet(
                file_path, start, end, context_lines=3, logger=logger
            )

            report.append({
                "file": file_path,
                "start_line": start,
                "end_line": end,
                "lines": f"{start}-{end}",
                "rule_id": rule_id,
                "severity": severity,
                "semgrep_message": message,
                "code_snippet": code_snippet,
                "ai_analysis": {
                    "status": "skipped",
                    "message": "LLM analysis was skipped.",
                    "raw_output": ""
                },
                "metadata": {
                    "cwe": metadata.get('cwe', []),
                    "owasp": metadata.get('owasp', []),
                    "confidence": metadata.get('confidence', 'UNKNOWN'),
                    "references": metadata.get('references', [])
                },
                "timestamp": utc_now_iso()
            })
        logger.info(f"Processed {len(report)} finding(s) without LLM.")
        return report

    # Sequential processing — each call invokes llama-cli
    # Note: llama-cli loads the model per invocation. On Mac with Metal,
    # the GGUF model loads quickly (~2-5 seconds) and infers efficiently.
    logger.info(
        f"Processing {len(findings)} finding(s) with "
        f"Foundation-Sec-8B via llama-cli..."
    )
    logger.info(
        f"Model: {config['hf_repo']} / {config['hf_file']}"
    )
    logger.info(
        f"Estimated time: ~{len(findings) * 30}-{len(findings) * 120} seconds "
        f"(depends on hardware)"
    )

    for i, finding in enumerate(findings, 1):
        logger.info(f"Processing finding {i}/{len(findings)}...")
        try:
            result = process_single_finding(finding, config, logger)
            report.append(result)
            logger.info(
                f"Finding {i}/{len(findings)} complete. "
                f"Status: {result['ai_analysis']['status']}"
            )
        except Exception as e:
            rule_id = finding.get('check_id', 'unknown')
            logger.error(f"Error processing finding '{rule_id}': {e}")
            report.append({
                "file": finding.get('path', 'unknown'),
                "start_line": finding.get('start', {}).get('line', 0),
                "end_line": finding.get('end', {}).get('line', 0),
                "lines": "unknown",
                "rule_id": rule_id,
                "severity": finding.get('extra', {}).get('severity', 'WARNING'),
                "semgrep_message": finding.get('extra', {}).get('message', ''),
                "code_snippet": "Unavailable due to processing error.",
                "ai_analysis": {
                    "status": "error",
                    "message": f"Processing error: {str(e)}",
                    "raw_output": ""
                },
                "metadata": {},
                "timestamp": utc_now_iso()
            })

    # Sort by severity then by file
    severity_order = {'ERROR': 0, 'WARNING': 1, 'INFO': 2}
    report.sort(key=lambda x: (
        severity_order.get(x.get('severity', 'INFO'), 99),
        x.get('file', ''),
        x.get('start_line', 0)
    ))

    logger.info(f"Completed analysis of {len(report)} finding(s).")
    return report


def generate_summary(report):
    """Generate a summary of findings by severity."""
    summary = {'ERROR': 0, 'WARNING': 0, 'INFO': 0}
    for entry in report:
        sev = entry.get('severity', 'INFO')
        summary[sev] = summary.get(sev, 0) + 1
    return summary


def generate_markdown_report(report, output_dir, config, logger):
    """Generate a detailed Markdown report."""
    md_path = os.path.join(output_dir, 'owasp_ai_report.md')
    summary = generate_summary(report)

    with open(md_path, 'w') as f:
        f.write("# 🛡️ AI-Powered OWASP Top 10 Security Report\n\n")
        f.write(f"**Generated:** {utc_now_iso()} UTC\n\n")
        f.write(f"**Target:** `{config.get('target', 'N/A')}`\n\n")
        f.write(f"**Semgrep Config:** `{config.get('semgrep_config', 'N/A')}`\n\n")
        f.write(f"**LLM Model:** `{config.get('hf_repo', 'N/A')} / {config.get('hf_file', 'N/A')}`\n\n")
        f.write(f"**Severity Threshold:** `{config.get('severity_threshold', 'N/A')}`\n\n")

        f.write("## Summary\n\n")
        f.write("| Severity | Count |\n")
        f.write("|----------|-------|\n")
        f.write(f"| 🔴 ERROR   | {summary.get('ERROR', 0)} |\n")
        f.write(f"| 🟡 WARNING | {summary.get('WARNING', 0)} |\n")
        f.write(f"| 🔵 INFO    | {summary.get('INFO', 0)} |\n")
        f.write(f"| **Total**  | **{len(report)}** |\n\n")
        f.write("---\n\n")

        if not report:
            f.write("✅ **No security findings detected.**\n")
            logger.info(f"Markdown report written to '{md_path}'.")
            return md_path

        f.write("## Table of Contents\n\n")
        for i, entry in enumerate(report, 1):
            severity_icon = {'ERROR': '🔴', 'WARNING': '🟡', 'INFO': '🔵'}
            icon = severity_icon.get(entry['severity'], '⚪')
            f.write(
                f"{i}. {icon} [{entry['rule_id']}]"
                f"(#finding-{i}) - "
                f"`{entry['file']}:{entry['lines']}`\n"
            )
        f.write("\n---\n\n")

        f.write("## Detailed Findings\n\n")
        for i, entry in enumerate(report, 1):
            severity_icon = {'ERROR': '🔴', 'WARNING': '🟡', 'INFO': '🔵'}
            icon = severity_icon.get(entry['severity'], '⚪')

            f.write(f"### Finding {i} {icon} {entry['rule_id']}\n\n")
            f.write("| Property | Value |\n")
            f.write("|----------|-------|\n")
            f.write(f"| **File** | `{entry['file']}` |\n")
            f.write(f"| **Lines** | {entry['lines']} |\n")
            f.write(f"| **Severity** | {entry['severity']} |\n")
            f.write(f"| **Confidence** | {entry.get('metadata', {}).get('confidence', 'N/A')} |\n")

            cwe_list = entry.get('metadata', {}).get('cwe', [])
            owasp_list = entry.get('metadata', {}).get('owasp', [])
            if cwe_list:
                f.write(f"| **CWE** | {', '.join(cwe_list)} |\n")
            if owasp_list:
                f.write(f"| **OWASP** | {', '.join(owasp_list)} |\n")

            f.write(f"| **Timestamp** | {entry['timestamp']} |\n\n")

            f.write(f"#### Semgrep Finding\n\n{entry['semgrep_message']}\n\n")
            f.write(f"#### Code Snippet\n\n```\n{entry['code_snippet']}\n```\n\n")

            ai = entry.get('ai_analysis', {})
            if isinstance(ai, dict):
                status = ai.get('status', 'unknown')
                if status == 'success':
                    f.write(f"#### 🤖 AI Analysis (Foundation-Sec-8B)\n\n{ai['message']}\n\n")
                elif status == 'skipped':
                    f.write("#### 🤖 AI Analysis\n\n*LLM analysis was skipped.*\n\n")
                else:
                    f.write(
                        f"#### 🤖 AI Analysis\n\n"
                        f"⚠️ *{ai.get('message', 'Analysis unavailable.')}*\n\n"
                    )
            else:
                f.write(f"#### 🤖 AI Analysis\n\n{ai}\n\n")

            refs = entry.get('metadata', {}).get('references', [])
            if refs:
                f.write("#### References\n\n")
                for ref in refs:
                    f.write(f"- {ref}\n")
                f.write("\n")

            f.write("---\n\n")

    logger.info(f"Markdown report written to '{md_path}'.")
    return md_path


def generate_json_report(report, output_dir, config, logger):
    """Generate a JSON report for machine consumption."""
    json_path = os.path.join(output_dir, 'owasp_ai_report.json')
    summary = generate_summary(report)

    json_output = {
        "report_metadata": {
            "tool": "aiowaspscan",
            "version": "2.0.0",
            "generated_at": utc_now_iso(),
            "target": config.get('target', 'N/A'),
            "semgrep_config": config.get('semgrep_config', 'N/A'),
            "llm_model": f"{config.get('hf_repo', 'N/A')} / {config.get('hf_file', 'N/A')}",
            "severity_threshold": config.get('severity_threshold', 'N/A'),
            "llm_enabled": not config.get('skip_llm', False)
        },
        "summary": {
            "total_findings": len(report),
            "by_severity": summary
        },
        "findings": report
    }

    with open(json_path, 'w') as f:
        json.dump(json_output, f, indent=2, default=str)

    logger.info(f"JSON report written to '{json_path}'.")
    return json_path


def generate_junit_report(report, output_dir, logger):
    """Generate a JUnit XML report for Jenkins integration."""
    junit_path = os.path.join(output_dir, 'owasp_junit_report.xml')

    test_cases = []
    for entry in report:
        name = f"{entry['rule_id']} in {entry['file']}:{entry['lines']}"
        classname = entry['file'].replace('/', '.').replace('\\', '.')

        # Escape XML special characters
        safe_message = (
            entry['semgrep_message'][:200]
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
        )
        safe_full_message = (
            entry['semgrep_message']
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
        )

        if entry['severity'] in ['ERROR', 'WARNING']:
            test_cases.append(
                f'    <testcase name="{name}" classname="{classname}">\n'
                f'      <failure message="{safe_message}">'
                f'{safe_full_message}</failure>\n'
                f'    </testcase>'
            )
        else:
            test_cases.append(
                f'    <testcase name="{name}" classname="{classname}" />'
            )

    failures = sum(1 for e in report if e['severity'] in ['ERROR', 'WARNING'])

    xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="OWASP-AI-Security-Scan" tests="{len(report)}" failures="{failures}" timestamp="{utc_now_iso()}">
{chr(10).join(test_cases)}
</testsuite>"""

    with open(junit_path, 'w') as f:
        f.write(xml_content)

    logger.info(f"JUnit report written to '{junit_path}'.")
    return junit_path


def evaluate_quality_gate(report, threshold, logger):
    """
    Evaluate findings against the severity threshold.
    Exit 0 = Pass, Exit 1 = Fail.
    """
    severity_levels = {'INFO': 0, 'WARNING': 1, 'ERROR': 2}
    threshold_level = severity_levels.get(threshold.upper(), 1)

    violations = []
    for entry in report:
        entry_severity = entry.get('severity', 'WARNING')
        if isinstance(entry_severity, str):
            entry_severity = entry_severity.upper()
        entry_level = severity_levels.get(entry_severity, 1)
        if entry_level >= threshold_level:
            violations.append(entry)

    logger.info("=" * 50)
    logger.info("QUALITY GATE EVALUATION")
    logger.info("=" * 50)
    logger.info(f"Threshold:        {threshold}")
    logger.info(f"Threshold Level:  {threshold_level}")
    logger.info(f"Total Findings:   {len(report)}")
    logger.info(f"Violations:       {len(violations)}")

    for entry in report:
        entry_severity = entry.get('severity', 'UNKNOWN')
        entry_level = severity_levels.get(
            entry_severity.upper() if isinstance(entry_severity, str) else 'WARNING', -1
        )
        status = "❌ VIOLATION" if entry_level >= threshold_level else "✅ PASS"
        logger.info(
            f"  {status} [{entry_severity}] (level {entry_level}) "
            f"{entry.get('rule_id', 'unknown')} in "
            f"{entry.get('file', 'unknown')}:{entry.get('lines', '?')}"
        )

    if violations:
        logger.warning(
            f"Quality gate FAILED: {len(violations)} finding(s) "
            f"at or above '{threshold}' severity."
        )
        return 1
    else:
        logger.info("✅ Quality gate PASSED: No findings above threshold.")
        return 0


def main():
    """Main execution flow."""
    args = parse_arguments()
    config = merge_configuration(args)

    logger = setup_logging(
        log_level=config['log_level'],
        log_file=config['log_file']
    )

    logger.info("=" * 60)
    logger.info("   AI-Powered OWASP Top 10 Security Scanner v2.0.0")
    logger.info("   Model: Cisco Foundation-Sec-8B (GGUF via llama-cli)")
    logger.info("=" * 60)
    logger.info(f"  Target:             {config['target']}")
    logger.info(f"  HF Repo:            {config['hf_repo']}")
    logger.info(f"  HF File:            {config['hf_file']}")
    logger.info(f"  Context Size:       {config['ctx_size']}")
    logger.info(f"  GPU Layers:         {config['n_gpu_layers']}")
    logger.info(f"  CPU Threads:        {config['threads']}")
    logger.info(f"  Max Tokens:         {config['max_tokens']}")
    logger.info(f"  Temperature:        {config['temperature']}")
    logger.info(f"  Output Directory:   {config['output_dir']}")
    logger.info(f"  Severity Threshold: {config['severity_threshold']}")
    logger.info(f"  LLM Timeout:        {config['llm_timeout']}s")
    logger.info(f"  Semgrep Config:     {config['semgrep_config']}")
    logger.info(f"  Semgrep Timeout:    {config['semgrep_timeout']}s")
    logger.info(f"  LLM Enabled:        {not config['skip_llm']}")
    logger.info(f"  Log Level:          {config['log_level']}")
    logger.info("=" * 60)

    os.makedirs(config['output_dir'], exist_ok=True)

    # Step 1: Validate environment
    validate_environment(config['target'], config['skip_llm'], config, logger)

    # Step 2: Run Semgrep scan
    semgrep_data = run_semgrep_scan(
        target=config['target'],
        config=config['semgrep_config'],
        output_dir=config['output_dir'],
        timeout=config['semgrep_timeout'],
        logger=logger
    )

    # Step 3: Check if there are findings
    if not semgrep_data.get('results'):
        logger.info("No findings detected by Semgrep. Pipeline passes.")
        generate_markdown_report([], config['output_dir'], config, logger)
        generate_json_report([], config['output_dir'], config, logger)
        generate_junit_report([], config['output_dir'], logger)
        sys.exit(0)

    # Step 4: Process findings
    report = process_findings(
        data=semgrep_data,
        config=config,
        skip_llm=config['skip_llm'],
        logger=logger
    )

    # Step 5: Generate reports
    generate_markdown_report(report, config['output_dir'], config, logger)
    generate_json_report(report, config['output_dir'], config, logger)
    generate_junit_report(report, config['output_dir'], logger)

    # Step 6: Quality gate
    exit_code = evaluate_quality_gate(
        report, config['severity_threshold'], logger
    )

    logger.info("=" * 60)
    logger.info(f"  Scan complete. Reports saved to '{config['output_dir']}'")
    logger.info(f"  Exit code: {exit_code}")
    logger.info("=" * 60)

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
