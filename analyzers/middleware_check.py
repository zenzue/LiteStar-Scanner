import os
import re

def analyze(path):
    issues = []
    middleware_patterns = [
        (r"(Middleware|DefineMiddleware)\s*\(", "Possible custom middleware"),
        (r"before_send\s*=\s*", "Use of 'before_send' function (may modify headers/body)"),
        (r"after_request\s*=\s*", "Use of 'after_request' hook (review its logic)"),
        (r"exception_handlers\s*=\s*{[^}]*Exception:.*?lambda", "Exception handler suppressing all exceptions"),
    ]
    
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    for pattern, message in middleware_patterns:
                        for match in re.finditer(pattern, content):
                            snippet = content[match.start():match.end()]
                            issues.append(f"{file}:{match.start()} - {message}: `{snippet}`")
    return issues