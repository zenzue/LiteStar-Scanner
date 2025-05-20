import re
import os

def analyze(path):
    sensitive_patterns = [
        (r"(?i)(password\s*=\s*['\"].{4,}['\"])", "Hardcoded password"),
        (r"(?i)(secret(_key)?\s*=\s*['\"].{8,}['\"])", "Hardcoded secret key"),
        (r"(api[_-]?key\s*=\s*['\"].{10,}['\"])", "Hardcoded API key"),
        (r"(AWS_ACCESS_KEY_ID\s*=\s*['\"]?AKIA[0-9A-Z]{16}['\"]?)", "Hardcoded AWS Access Key"),
        (r"(AWS_SECRET_ACCESS_KEY\s*=\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?)", "Hardcoded AWS Secret Key"),
        (r"(?i)(jwt|access_token)\s*=\s*['\"].{20,}\.[\w-]+\.[\w-]+['\"]", "Hardcoded JWT token"),
        (r"(slack[_-]token\s*=\s*['\"]?xox[baprs]-[0-9a-zA-Z]{10,}['\"]?)", "Hardcoded Slack token"),
        (r"(firebase[_-]?key\s*=\s*['\"][A-Za-z0-9_\-]{20,}['\"])", "Hardcoded Firebase API Key"),
        (r"(?i)(oauth[_-]token\s*=\s*['\"].{15,}['\"])", "Hardcoded OAuth token"),
        (r"(private[_-]?key\s*=\s*['\"]?-----BEGIN(?: RSA)? PRIVATE KEY-----)", "Hardcoded Private Key block"),
        (r"(client[_-]?secret\s*=\s*['\"].{10,}['\"])", "Hardcoded Client Secret"),
        (r"(gcp[_-]?service[_-]?account[_-]?key\s*=\s*['\"]{.+}['\"])", "GCP service account key in string"),
    ]

    issues = []

    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(".py") or file.endswith(".env") or file.endswith(".json"):
                full_path = os.path.join(root, file)
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    for pattern, message in sensitive_patterns:
                        for match in re.finditer(pattern, content):
                            line_num = content[:match.start()].count("\n") + 1
                            issues.append(f"{file}:{line_num} - {message}: {match.group(0).strip()}")
    return issues