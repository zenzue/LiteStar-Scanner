import subprocess
import json
from typing import List, Union
from pydantic import BaseModel

class PackageIssue(BaseModel):
    file: str = "requirements"
    line: int = 0
    issue: str
    suggestion: str
    code: str = ""

def analyze(_path: str) -> List[Union[dict, str]]:
    try:
        output = subprocess.check_output(["pip-audit", "--format", "json"], text=True)
        parsed = json.loads(output)

        issues = []
        for entry in parsed:
            package = entry.get("name")
            version = entry.get("version")
            vulnerabilities = entry.get("vulns", [])

            for vuln in vulnerabilities:
                vuln_id = vuln.get("id", "UNKNOWN")
                desc = vuln.get("description", "").strip().split("\n")[0]
                issues.append(PackageIssue(
                    issue=f"{package}=={version} has vulnerability: {vuln_id}",
                    suggestion=desc[:180] + ("..." if len(desc) > 180 else ""),
                ).dict())
        return issues

    except FileNotFoundError:
        return [{"file": "dependencies", "line": 0, "issue": "pip-audit not installed", "suggestion": "Install it using: pip install pip-audit", "code": ""}]
    except subprocess.CalledProcessError as e:
        return [{"file": "dependencies", "line": 0, "issue": "Failed to run pip-audit", "suggestion": str(e), "code": ""}]
    except Exception as e:
        return [{"file": "dependencies", "line": 0, "issue": "Unknown error during audit", "suggestion": str(e), "code": ""}]