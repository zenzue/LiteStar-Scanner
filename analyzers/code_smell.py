import ast
import os

def analyze(path, max_function_lines=50, max_args=5, max_locals=15, max_nesting=3):
    issues = []

    for root, _, files in os.walk(path):
        for file in files:
            if not file.endswith(".py"):
                continue

            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()
                tree = ast.parse(code, filename=file)
            except Exception as e:
                issues.append({
                    "file": file,
                    "line": 0,
                    "issue": "Parse error",
                    "suggestion": str(e),
                    "code": ""
                })
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_name = node.name
                    func_len = len(node.body)
                    arg_count = len(node.args.args)
                    local_vars = sum(1 for n in ast.walk(node) if isinstance(n, ast.Assign))

                    if func_len > max_function_lines:
                        issues.append({
                            "file": file,
                            "line": node.lineno,
                            "issue": f"Function '{func_name}' is too long ({func_len} lines)",
                            "suggestion": "Break the function into smaller parts",
                            "code": f"def {func_name}(...):"
                        })

                    if arg_count > max_args:
                        issues.append({
                            "file": file,
                            "line": node.lineno,
                            "issue": f"Function '{func_name}' has too many arguments ({arg_count})",
                            "suggestion": "Reduce argument count or use a config object",
                            "code": f"def {func_name}(...):"
                        })

                    if local_vars > max_locals:
                        issues.append({
                            "file": file,
                            "line": node.lineno,
                            "issue": f"Function '{func_name}' has too many local variables ({local_vars})",
                            "suggestion": "Reduce variable count or split logic",
                            "code": f"def {func_name}(...):"
                        })

                    nesting = max_nesting_level(node)
                    if nesting > max_nesting:
                        issues.append({
                            "file": file,
                            "line": node.lineno,
                            "issue": f"Function '{func_name}' has deep nesting (level {nesting})",
                            "suggestion": "Refactor nested logic or use early returns",
                            "code": f"def {func_name}(...):"
                        })

    return issues

def max_nesting_level(node, level=0):
    max_level = level
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
            child_level = max_nesting_level(child, level + 1)
            if child_level > max_level:
                max_level = child_level
        else:
            child_level = max_nesting_level(child, level)
            if child_level > max_level:
                max_level = child_level
    return max_level