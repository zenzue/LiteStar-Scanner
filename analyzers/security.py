import re
import os
import json

def analyze(path):
    insecure_patterns = [
        (r"\beval\(", "Use of eval() is dangerous", "Avoid eval()"),
        (r"\bexec\(", "Use of exec() can lead to code injection", "Avoid exec()"),
        (r"pickle\.load", "Insecure deserialization with pickle", "Use json or safer method"),
        (r"marshal\.loads", "Insecure deserialization with marshal", "Avoid using marshal"),
        (r"yaml\.load\s*\(", "Unsafe YAML loading (use yaml.safe_load)", "Use yaml.safe_load()"),
        (r"os\.system\(", "Command execution without input sanitization", "Use subprocess and sanitize inputs"),
        (r"subprocess\.(Popen|call|run)\(", "Shell execution without validation", "Avoid shell=True"),
        (r"open\s*\(.*['\"]w[bt]?['\"]\)", "File writing risk — potential path traversal", "Validate file paths"),
        (r"(token|secret|key)[\s:=]+[\"'][a-zA-Z0-9_\-]{16,}[\"']", "Hardcoded token or secret", "Use environment variables"),
        (r"app\.debug\s*=\s*True", "Debug mode enabled — exposes internals", "Disable debug in production"),
        (r"\.trust_host_header\s*=\s*True", "Untrusted Host header allowed", "Set trust_host_header=False"),
        (r"(?:request|query)_params.*\[.*\]", "Potential unsanitized user input (XSS/SQLi risk)", "Sanitize input"),
        (r"SELECT\s+.*\s+FROM\s+.*\+.*", "SQL query built using string concatenation (SQLi risk)", "Use parameterized queries"),
        (r"redirect\s*\(\s*request\.args\.get\(", "Open redirect from unvalidated user input", "Validate redirect URLs"),
        (r"(requests\.get|urlopen|aiohttp)\s*\(\s*request\.", "SSRF via user-controlled URL", "Avoid using user input in URLs"),
        (r"Response\(\s*request\.args\.get\(", "Reflected input in response (XSS risk)", "Escape output"),
        (r"response\.set_cookie\(.*httponly=False", "Cookies missing HttpOnly flag", "Set HttpOnly=True"),
        (r"response\.set_cookie\(.*secure=False", "Cookies missing Secure flag", "Set Secure=True"),
        (r"(AllowAllCORSConfig|allow_origins\s*=\s*\[?[\"']\*+)", "CORS allows any origin — security risk", "Restrict origins"),
        (r"(csrf_protect\s*=\s*False|csrf_exempt)", "CSRF protection disabled or bypassed", "Enable CSRF protection"),
        (r"(ldap3|ldap).*(search|bind|filter).*\+.*", "Potential LDAP injection (user input used in query)", "Escape LDAP input"),
        (r"Response\(\s*.*[<>&]", "Possible HTML injection — ensure proper escaping", "Use html.escape()"),
        (r"@get\(.*\)", "Route handler — check for missing guards/auth", "Add guards=[]"),
        (r"(auth_required\s*=\s*False)", "Route explicitly disables auth", "Enforce authentication"),
        (r"(user\.is_admin\s*==\s*True)", "Hardcoded privilege check — consider RBAC", "Use role-based access"),
    ]

    taint_sources = [
        r"request\.args\.get",
        r"request\.json",
        r"request\.query_params",
        r"request\.path_params",
        r"request\.headers\.get",
        r"request\.cookies\.get",
    ]

    taint_sinks = [
        r"eval",
        r"exec",
        r"os\.system",
        r"subprocess\.(Popen|call|run)"
    ]

    insecure_routes = [
        r"@get\(",
        r"@post\(",
        r"@put\(",
        r"@delete\(",
        r"@patch\("
    ]

    issues = []

    for root, _, files in os.walk(path):
        for file in files:
            if not file.endswith(".py"):
                continue
            full_path = os.path.join(root, file)
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
                for pattern, message, suggestion in insecure_patterns:
                    for match in re.finditer(pattern, content):
                        line = content[:match.start()].count('\n') + 1
                        issues.append({
                            "file": file,
                            "line": line,
                            "issue": message,
                            "suggestion": suggestion,
                            "code": lines[line - 1].strip()
                        })
                for source in taint_sources:
                    for sink in taint_sinks:
                        pattern = rf"{sink}\(.*{source}"
                        for match in re.finditer(pattern, content):
                            line = content[:match.start()].count('\n') + 1
                            issues.append({
                                "file": file,
                                "line": line,
                                "issue": f"Tainted input from {source} used in {sink}",
                                "suggestion": "Sanitize input before use",
                                "code": lines[line - 1].strip()
                            })
                for route in insecure_routes:
                    for match in re.finditer(route, content):
                        snippet = content[match.end():match.end() + 100]
                        if "guards=" not in snippet:
                            line = content[:match.start()].count('\n') + 1
                            issues.append({
                                "file": file,
                                "line": line,
                                "issue": f"LiteStar route {route.strip('@(')} missing guards",
                                "suggestion": "Add guards=[]",
                                "code": lines[line - 1].strip()
                            })
    return issues