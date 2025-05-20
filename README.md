# LiteStar Code Analysis Framework

A static analysis tool built to detect code smells, security vulnerabilities, sensitive data leaks, outdated dependencies, and misconfigurations in Python projects using the [LiteStar](https://docs.litestar.dev) framework.

## Features

- Detects common code smells (long functions, deep nesting, etc.)
- Static security analysis based on OWASP Top 10
- Taint analysis for user input in dangerous sinks
- Sensitive data exposure (hardcoded secrets, AWS keys, etc.)
- Checks for missing route guards in LiteStar apps
- Dependency vulnerability scan via `pip-audit`
- Outputs a clean markdown report of findings

## Usage

```bash
python main.py /path/to/litestar/project
```

A `litestar_analysis_report.md` will be generated after scanning.

## Requirements

- Python 3.8+
- Optional: `pip install pip-audit colorama`

## Author

Created by **w01f**
