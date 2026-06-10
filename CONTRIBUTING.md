# How to Contribute

Thanks for your interest in contributing to `AI Deep SAST`!
Here are a few general guidelines on contributing and reporting bugs that we ask
you to review. Following these guidelines helps to communicate that you respect
the time of the contributors managing and developing this open source project.
In return, they should reciprocate that respect in addressing your issue,
assessing changes, and helping you finalize your pull requests. In that spirit
of mutual respect, we endeavor to review incoming issues and pull requests
within 10 days, and will close any lingering issues or pull requests after 60
days of inactivity.

Please note that all of your interactions in the project are subject to our
[Code of Conduct](/CODE_OF_CONDUCT.md). This includes creation of issues or pull
requests, commenting on issues or pull requests, and extends to all interactions
in any real-time space e.g., Slack, Discord, etc.

## Reporting Issues

Before reporting a new issue, please ensure that the issue was not already
reported or fixed by searching through our
[issues list](https://github.com/cisco-open/ai-deep-sast/issues).

When creating a new issue, please be sure to include a **title and clear
description**, as much relevant information as possible, and, if possible, a
test case.

**If you discover a security bug, please do not report it through GitHub.
Instead, please see security procedures in [SECURITY.md](/SECURITY.md).**

## Sending Pull Requests

Before sending a new pull request, take a look at existing pull requests and
issues to see if the proposed change or fix has been discussed in the past, or
if the change was already implemented but not yet released.

We expect new pull requests to include tests for any affected behavior, and, as
we follow semantic versioning, we may reserve breaking changes until the next
major version release.

1. Fork the repository.
2. Create a feature branch from `main`.
3. Make your changes — follow the existing code style.
4. Add or update tests for any new functionality.
5. Run the test suite and ensure all tests pass.
6. Submit a pull request with a clear description of the changes.

## Development Setup

```bash
# Clone and set up
git clone https://github.com/cisco-open/ai-deep-sast.git
cd ai-deep-sast
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run tests
python3 -m pytest tests/ -v
```

### Running a Test Scan

```bash
# Semgrep only (no LLM required)
python3 aideepsast.py --target samples/sample_vuln.py --skip-llm
```

## Coding Standards

- Follow existing code style and conventions.
- Add docstrings to new functions.
- Keep changes focused — one feature or fix per PR.
- Do not commit generated reports, logs, or model files.

## Tests

- All PRs must pass the existing test suite.
- Add tests for new features or bug fixes.
- Run: `python3 -m pytest tests/ -v`

## Other Ways to Contribute

We welcome anyone that wants to contribute to triage and reply to open issues
to help troubleshoot and fix existing bugs. Here is what you can do:

- Help ensure that existing issues follow the recommendations from the
  _[Reporting Issues](#reporting-issues)_ section, providing feedback to the
  issue's author on what might be missing.
- Review existing pull requests, and test patches against real existing
  applications that use the scanner.
- Write a test, or add a missing test case to an existing test.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE).
