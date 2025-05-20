import subprocess
import json
from typing import List
from pydantic import BaseModel

class PackageIssue(BaseModel):
    file: str = "dependencies"
    line: int = 0
    issue: str
    suggestion: str
    code: str = ""

def analyze(_path: str) -> List[dict]:
    try:
        result = subprocess.run(
            ["pip-audit", "--format", "json"],
            capture_output=True,
            text=True,
            check=False
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if not stdout:
            return [{
                "file": "dependencies",
                "line": 0,
                "issue": "No output from pip-audit",
                "suggestion": "Ensure your environment has dependencies installed",
                "code": ""
            }]

        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            return [{
                "file": "dependencies",
                "line": 0,
                "issue": "Invalid JSON from pip-audit",
                "suggestion": stderr or "Try running pip-audit manually for more details",
                "code": ""
            }]

        if not isinstance(parsed, list):
            return [{
                "file": "dependencies",
                "line": 0,
                "issue": "Unexpected format from pip-audit",
                "suggestion": stderr or "Try running pip-audit manually for more details",
                "code": ""
            }]

        issues = []
        for entry in parsed:
            if not isinstance(entry, dict):
                continue

            package = entry.get("name")
            version = entry.get("version")
            for vuln in entry.get("vulns", []):
                issues.append(PackageIssue(
                    issue=f"{package}=={version} - {vuln.get('id', 'UNKNOWN')}",
                    suggestion=vuln.get("description", "").split("\n")[0],
                ).dict())

        return issues

    except FileNotFoundError:
        return [{
            "file": "dependencies",
            "line": 0,
            "issue": "pip-audit not installed",
            "suggestion": "Install it with: pip install pip-audit",
            "code": ""
        }]
    except Exception as e:
        return [{
            "file": "dependencies",
            "line": 0,
            "issue": "pip-audit failed",
            "suggestion": str(e),
            "code": ""
        }]
