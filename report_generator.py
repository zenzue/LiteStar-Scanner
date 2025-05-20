import os

def generate_report(results: dict, project_path: str, output_path="litestar_analysis_report.md"):
    project_title = os.path.basename(os.path.abspath(project_path)) or "Project"

    lines = []
    lines.append(f"# LiteStar Code Analysis Report - {project_title}\n")

    for category, issues in results.items():
        lines.append(f"## {category}\n")

        if not issues:
            lines.append("_No issues found._\n")
            continue

        for issue in issues:
            if isinstance(issue, dict):
                file = issue.get("file", "unknown")
                line = issue.get("line", "-")
                desc = issue.get("issue", "Unspecified issue")
                suggestion = issue.get("suggestion", "-")
                code = issue.get("code", "")
                lines.append(f"- **File**: `{file}:{line}`\n  - **Issue**: {desc}\n  - **Suggestion**: {suggestion}")
                if code:
                    lines.append(f"  - **Code**:\n    ```python\n    {code}\n    ```")
            else:
                lines.append(f"- {issue}")
        lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\nMarkdown report generated: {output_path}")