import ast
import os

def is_route_decorator(decorator):
    try:
        if isinstance(decorator, ast.Call):
            func = decorator.func
        else:
            func = decorator

        if isinstance(func, ast.Attribute):
            return func.attr in {"get", "post", "put", "patch", "delete", "route"}
        elif isinstance(func, ast.Name):
            return func.id in {"get", "post", "put", "patch", "delete", "route"}
    except Exception:
        return False
    return False

def analyze(path):
    issues = []

    for root, _, files in os.walk(path):
        for file in files:
            if not file.endswith(".py"):
                continue

            full_path = os.path.join(root, file)
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                try:
                    tree = ast.parse(f.read(), filename=file)
                except SyntaxError as e:
                    issues.append(f"{file}:{e.lineno} - Syntax error, skipping file")
                    continue

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        has_route = any(is_route_decorator(d) for d in node.decorator_list)
                        if has_route:
                            has_guard_kwarg = any(
                                isinstance(kw, ast.keyword) and kw.arg == "guards"
                                for d in node.decorator_list
                                if isinstance(d, ast.Call)
                                for kw in d.keywords
                            )
                            if not has_guard_kwarg:
                                issues.append(f"{file}:{node.lineno} - Route '{node.name}' may be unprotected (no guards=)")
                    
                    elif isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name) and node.func.id == "DefineMiddleware":
                            issues.append(f"{file}:{node.lineno} - Middleware definition found (review logic)")

                        if isinstance(node.func, ast.Name) and node.func.id in {"before_send", "after_request"}:
                            issues.append(f"{file}:{node.lineno} - Hook '{node.func.id}' used (review security implications)")

    return issues