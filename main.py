from analyzers import code_smell, security, sensitive_data, version_checker, litestar_checks, middleware_check
from report_generator import generate_report
import os
import argparse
import sys

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

def print_section(title, issues):
    print(f"\n{BOLD}{YELLOW}=== {title} ==={RESET}")
    if not issues:
        print(f"{GREEN}✓ No issues found.{RESET}")
    else:
        for issue in issues:
            if isinstance(issue, dict):
                file = issue.get("file", "unknown")
                line = issue.get("line", "-")
                desc = issue.get("issue", "Unspecified issue")
                suggestion = issue.get("suggestion", "-")
                code = issue.get("code", "")
                print(f"{RED}✗ {file}:{line} - {desc}{RESET}")
                print(f"    Suggestion: {suggestion}")
                if code:
                    print(f"    Code: {code}")
            else:
                print(f"{RED}✗ {issue}{RESET}")

def scan_project(path: str):
    print(f"{BOLD}Scanning project -> {path}{RESET}")

    results = {
        "Code Smells": code_smell.analyze(path),
        "Security Issues": security.analyze(path),
        "Sensitive Data": sensitive_data.analyze(path),
        "Version Issues": version_checker.analyze(path),
        "LiteStar Checks": litestar_checks.analyze(path),
        "Middleware Issues": middleware_check.analyze(path),
    }

    total_issues = 0
    for title, issues in results.items():
        print_section(title, issues)
        total_issues += len(issues)

    print(f"\n{BOLD}{YELLOW}=== FINAL REPORT ==={RESET}")
    for title, issues in results.items():
        count = len(issues)
        color = RED if count > 0 else GREEN
        print(f"{color}{title:<25}: {count} issue(s) found{RESET}")

    print(f"\n{BOLD}Total Issues Found -> {total_issues}{RESET}")
    if total_issues == 0:
        print(f"{GREEN}✓ Your codebase is clean. Great job!{RESET}")
    else:
        print(f"{RED}✗ Please review and fix the reported issues above.{RESET}")
    generate_report(results, path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LiteStar Code Analysis Framework")
    parser.add_argument("project_path", help="Path to your LiteStar project")
    args = parser.parse_args()

    if not os.path.exists(args.project_path):
        print(f"{RED}✗ Path does not exist: {args.project_path}{RESET}")
        sys.exit(1)
    scan_project(args.project_path)